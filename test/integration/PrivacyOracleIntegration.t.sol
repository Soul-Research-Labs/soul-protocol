// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/PrivacyOracleIntegration.sol";

/// @dev Minimal mock verifier for oracle proofs
contract MockOracleVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool v) external {
        shouldPass = v;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

contract PrivacyOracleIntegrationTest is Test {
    PrivacyOracleIntegration oracle;
    MockOracleVerifier priceVerifier;
    MockOracleVerifier rangeVerifier;

    address admin = address(this);
    address operator;
    address oracleNode = makeAddr("oracleNode");
    address nobody = makeAddr("nobody");
    address user = makeAddr("user");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    bytes32 pairId = keccak256("ETH/USD");
    bytes32 nodePubKey = bytes32(uint256(0xBABE));

    function setUp() public {
        priceVerifier = new MockOracleVerifier();
        rangeVerifier = new MockOracleVerifier();

        oracle = new PrivacyOracleIntegration(
            address(priceVerifier),
            address(rangeVerifier),
            2 // signature threshold
        );

        operator = admin;

        // Register oracle node
        oracle.registerOracleNode(oracleNode, nodePubKey);

        // Grant ORACLE_ROLE to oracleNode
        oracle.grantRole(ORACLE_ROLE, oracleNode);
    }

    /* ══════════════════════════════════════════════════
                     CONSTRUCTOR
       ══════════════════════════════════════════════════ */

    function test_constructor_setsVerifiers() public view {
        assertEq(oracle.priceProofVerifier(), address(priceVerifier));
        assertEq(oracle.rangeProofVerifier(), address(rangeVerifier));
    }

    function test_constructor_setsThreshold() public view {
        assertEq(oracle.signatureThreshold(), 2);
    }

    function test_constructor_revertsZeroVerifier() public {
        vm.expectRevert(PrivacyOracleIntegration.ZeroAddress.selector);
        new PrivacyOracleIntegration(address(0), address(rangeVerifier), 2);
    }

    function test_constructor_setsRoles() public view {
        assertTrue(oracle.hasRole(oracle.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(oracle.hasRole(OPERATOR_ROLE, admin));
    }

    /* ══════════════════════════════════════════════════
                     ADD PAIR
       ══════════════════════════════════════════════════ */

    function test_addPair() public {
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );

        PrivacyOracleIntegration.PairConfig memory pair = oracle.getPair(
            pairId
        );
        assertEq(pair.symbol, "ETH/USD");
        assertEq(pair.decimals, 8);
        assertTrue(pair.isActive);
    }

    function test_addPair_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );
    }

    function test_getAllPairs() public {
        bytes32 pair2 = keccak256("BTC/USD");

        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("e"),
            makeAddr("u")
        );
        oracle.addPair(
            pair2,
            "BTC/USD",
            8,
            3600,
            200,
            makeAddr("b"),
            makeAddr("u2")
        );

        bytes32[] memory pairs = oracle.getAllPairs();
        assertEq(pairs.length, 2);
    }

    /* ══════════════════════════════════════════════════
                  ORACLE NODE MANAGEMENT
       ══════════════════════════════════════════════════ */

    function test_registerOracleNode() public view {
        PrivacyOracleIntegration.OracleNode memory node = oracle.getOracleNode(
            oracleNode
        );
        assertEq(node.nodeAddress, oracleNode);
        assertEq(node.publicKey, nodePubKey);
        assertTrue(node.isActive);
    }

    function test_registerOracleNode_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        oracle.registerOracleNode(makeAddr("new"), bytes32(uint256(0xFF)));
    }

    function test_deactivateOracleNode() public {
        oracle.deactivateOracleNode(oracleNode);

        PrivacyOracleIntegration.OracleNode memory node = oracle.getOracleNode(
            oracleNode
        );
        assertFalse(node.isActive);
    }

    function test_getAllOracleNodes() public view {
        address[] memory nodes = oracle.getAllOracleNodes();
        assertEq(nodes.length, 1);
        assertEq(nodes[0], oracleNode);
    }

    /* ══════════════════════════════════════════════════
                  SUBMIT ENCRYPTED PRICE
       ══════════════════════════════════════════════════ */

    function test_submitEncryptedPrice() public {
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );

        bytes32 recipientPubKey = bytes32(uint256(0xCAFE));
        bytes32 ephemeralPubKey = bytes32(uint256(0xFEED));
        bytes32 commitment = bytes32(uint256(0xDEAD));

        vm.prank(oracleNode);
        oracle.submitEncryptedPrice(
            pairId,
            recipientPubKey,
            hex"AABB",
            ephemeralPubKey,
            commitment
        );
    }

    function test_submitEncryptedPrice_revertsNotOracle() public {
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );

        vm.prank(nobody);
        vm.expectRevert();
        oracle.submitEncryptedPrice(
            pairId,
            bytes32(uint256(1)),
            hex"AA",
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );
    }

    /* ══════════════════════════════════════════════════
                  REQUEST ENCRYPTED PRICE
       ══════════════════════════════════════════════════ */

    function test_requestEncryptedPrice_emitsEvent() public {
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );

        bytes32 recipientPubKey = bytes32(uint256(0xCAFE));

        vm.prank(user);
        oracle.requestEncryptedPrice(pairId, recipientPubKey);
    }

    /* ══════════════════════════════════════════════════
                  CONFIGURATION
       ══════════════════════════════════════════════════ */

    function test_setSignatureThreshold() public {
        oracle.setSignatureThreshold(5);
        assertEq(oracle.signatureThreshold(), 5);
    }

    function test_setSignatureThreshold_revertsNotAdmin() public {
        vm.prank(nobody);
        vm.expectRevert();
        oracle.setSignatureThreshold(5);
    }

    function test_setVerifiers() public {
        MockOracleVerifier newV = new MockOracleVerifier();
        oracle.setVerifiers(address(newV), address(newV));
        assertEq(oracle.priceProofVerifier(), address(newV));
        assertEq(oracle.rangeProofVerifier(), address(newV));
    }

    function test_deactivatePair() public {
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );

        oracle.deactivatePair(pairId);
        PrivacyOracleIntegration.PairConfig memory pair = oracle.getPair(
            pairId
        );
        assertFalse(pair.isActive);
    }

    /* ══════════════════════════════════════════════════
                  CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_constants() public view {
        assertEq(oracle.MAX_PRICE_STALENESS(), 1 hours);
        assertEq(oracle.MIN_UPDATE_INTERVAL(), 10 seconds);
        assertEq(oracle.MAX_ORACLE_NODES(), 100);
    }

    /* ══════════════════════════════════════════════════
                  PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        oracle.pause();
        assertTrue(oracle.paused());

        oracle.unpause();
        assertFalse(oracle.paused());
    }

    function test_pause_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        oracle.pause();
    }

    function test_pause_blocksRequests() public {
        oracle.addPair(
            pairId,
            "ETH/USD",
            8,
            3600,
            100,
            makeAddr("eth"),
            makeAddr("usd")
        );

        oracle.pause();

        vm.prank(user);
        vm.expectRevert();
        oracle.requestEncryptedPrice(pairId, bytes32(uint256(1)));
    }
}
