// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/PrivacyPoolIntegration.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/// @dev Always-passing mock verifier
contract MockPoolVerifier is IProofVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool v) external {
        shouldPass = v;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return shouldPass;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view override returns (bool) {
        return shouldPass;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view override returns (bool) {
        return shouldPass;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 1;
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

contract PrivacyPoolIntegrationTest is Test {
    PrivacyPoolIntegration pool;
    MockPoolVerifier rangeVerifier;
    MockPoolVerifier withdrawVerifier;
    MockPoolVerifier swapVerifier;

    address admin = address(this);
    address operator;
    address user = makeAddr("user");
    address nobody = makeAddr("nobody");
    address relayer = makeAddr("relayer");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        rangeVerifier = new MockPoolVerifier();
        withdrawVerifier = new MockPoolVerifier();
        swapVerifier = new MockPoolVerifier();

        pool = new PrivacyPoolIntegration(
            address(rangeVerifier),
            address(withdrawVerifier),
            address(swapVerifier)
        );

        operator = admin; // admin gets OPERATOR_ROLE in constructor
    }

    /* ══════════════════════════════════════════════════
                     CONSTRUCTOR
       ══════════════════════════════════════════════════ */

    function test_constructor_setsVerifiers() public view {
        assertEq(pool.rangeProofVerifier(), address(rangeVerifier));
        assertEq(pool.withdrawProofVerifier(), address(withdrawVerifier));
        assertEq(pool.swapProofVerifier(), address(swapVerifier));
    }

    function test_constructor_revertsZeroVerifier() public {
        vm.expectRevert(PrivacyPoolIntegration.ZeroAddress.selector);
        new PrivacyPoolIntegration(
            address(0),
            address(withdrawVerifier),
            address(swapVerifier)
        );
    }

    function test_constructor_setsRoles() public view {
        assertTrue(pool.hasRole(pool.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pool.hasRole(OPERATOR_ROLE, admin));
    }

    /* ══════════════════════════════════════════════════
                    ADD POOL TOKEN
       ══════════════════════════════════════════════════ */

    function test_addPoolToken() public {
        address token = makeAddr("token");
        pool.addPoolToken(token, 100 ether, 50 ether, 100);

        PrivacyPoolIntegration.PoolToken memory pt = pool.getPoolToken(token);
        assertTrue(pt.isActive);
        assertEq(pt.maxDeposit, 100 ether);
        assertEq(pt.maxWithdraw, 50 ether);
        assertEq(pt.fee, 100);
    }

    function test_addPoolToken_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        pool.addPoolToken(makeAddr("token"), 100 ether, 50 ether, 100);
    }

    /* ══════════════════════════════════════════════════
                  UPDATE VERIFIERS
       ══════════════════════════════════════════════════ */

    function test_updateVerifiers() public {
        MockPoolVerifier newV = new MockPoolVerifier();
        pool.updateVerifiers(address(newV), address(newV), address(newV));
        assertEq(pool.rangeProofVerifier(), address(newV));
        assertEq(pool.withdrawProofVerifier(), address(newV));
        assertEq(pool.swapProofVerifier(), address(newV));
    }

    function test_updateVerifiers_revertsNotAdmin() public {
        vm.prank(nobody);
        vm.expectRevert();
        pool.updateVerifiers(makeAddr("a"), makeAddr("b"), makeAddr("c"));
    }

    /* ══════════════════════════════════════════════════
                   VIEW FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_commitmentExists_false() public view {
        assertFalse(pool.commitmentExists(bytes32(uint256(1))));
    }

    function test_isNullifierSpent_false() public view {
        assertFalse(pool.isNullifierSpent(bytes32(uint256(1))));
    }

    function test_getCommitmentCount_zero() public view {
        assertEq(pool.getCommitmentCount(), 0);
    }

    function test_getSupportedTokens_empty() public view {
        address[] memory tokens = pool.getSupportedTokens();
        assertEq(tokens.length, 0);
    }

    function test_getSupportedTokens_afterAdd() public {
        pool.addPoolToken(makeAddr("tokenA"), 100 ether, 50 ether, 0);
        pool.addPoolToken(makeAddr("tokenB"), 200 ether, 100 ether, 0);

        address[] memory tokens = pool.getSupportedTokens();
        assertEq(tokens.length, 2);
    }

    /* ══════════════════════════════════════════════════
                  CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_constants() public view {
        assertEq(pool.MERKLE_TREE_DEPTH(), 20);
        assertEq(pool.MAX_COMMITMENTS(), 1_048_576);
        assertEq(pool.RANGE_PROOF_BITS(), 64);
    }

    /* ══════════════════════════════════════════════════
                  PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        pool.pause();
        assertTrue(pool.paused());

        pool.unpause();
        assertFalse(pool.paused());
    }

    function test_pause_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        pool.pause();
    }

    /* ══════════════════════════════════════════════════
                   RECEIVE ETH
       ══════════════════════════════════════════════════ */

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool sent, ) = address(pool).call{value: 0.5 ether}("");
        assertTrue(sent);
        assertEq(address(pool).balance, 0.5 ether);
    }
}
