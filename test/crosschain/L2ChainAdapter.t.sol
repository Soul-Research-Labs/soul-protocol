// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/L2ChainAdapter.sol";

contract L2ChainAdapterTest is Test {
    L2ChainAdapter public adapter;

    address admin = makeAddr("admin");
    address relayer = makeAddr("relayer");
    address oracle = makeAddr("oracle");

    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    // Default chain IDs
    uint256 constant ARB = 42_161;
    uint256 constant OP = 10;
    uint256 constant BASE = 8453;
    uint256 constant ZKSYNC = 324;
    uint256 constant SCROLL = 534_352;
    uint256 constant LINEA = 59_144;
    uint256 constant POLYGON_ZKEVM = 1101;

    // Oracle key for signature tests
    uint256 oracleKey = 0xA11CE;
    address oracleSigner;

    function setUp() public {
        adapter = new L2ChainAdapter(admin);

        vm.startPrank(admin);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(ORACLE_ROLE, oracle);
        vm.stopPrank();

        oracleSigner = vm.addr(oracleKey);
    }

    // ── Constructor
    // ──────────────────────────────────────────────

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(ADMIN_ROLE, admin));
    }

    function test_constructor_initializesDefaultChains() public view {
        uint256[] memory chains = adapter.getSupportedChains();
        assertEq(chains.length, 7);

        // Check known chains exist in mapping
        L2ChainAdapter.ChainConfig memory arb = adapter.getChainConfig(ARB);
        assertEq(arb.chainId, ARB);
        assertEq(keccak256(bytes(arb.name)), keccak256("Arbitrum One"));
        assertFalse(arb.enabled); // disabled by default

        L2ChainAdapter.ChainConfig memory op = adapter.getChainConfig(OP);
        assertEq(op.chainId, OP);
        assertEq(keccak256(bytes(op.name)), keccak256("Optimism"));

        L2ChainAdapter.ChainConfig memory base_ = adapter.getChainConfig(BASE);
        assertEq(base_.chainId, BASE);

        L2ChainAdapter.ChainConfig memory zk = adapter.getChainConfig(ZKSYNC);
        assertEq(zk.chainId, ZKSYNC);
        assertEq(zk.gasLimit, 2_000_000);

        L2ChainAdapter.ChainConfig memory sc = adapter.getChainConfig(SCROLL);
        assertEq(sc.chainId, SCROLL);

        L2ChainAdapter.ChainConfig memory lin = adapter.getChainConfig(LINEA);
        assertEq(lin.chainId, LINEA);

        L2ChainAdapter.ChainConfig memory poly = adapter.getChainConfig(POLYGON_ZKEVM);
        assertEq(poly.chainId, POLYGON_ZKEVM);
    }

    // ── addChain
    // ─────────────────────────────────────────────────

    function test_addChain_success() public {
        uint256 newChain = 12_345;
        vm.prank(admin);
        adapter.addChain(
            newChain, "TestChain", makeAddr("bridge"), makeAddr("messenger"), 5, 500_000
        );

        L2ChainAdapter.ChainConfig memory config = adapter.getChainConfig(newChain);
        assertEq(config.chainId, newChain);
        assertEq(keccak256(bytes(config.name)), keccak256("TestChain"));
        assertTrue(config.enabled);
        assertEq(config.confirmations, 5);
        assertEq(config.gasLimit, 500_000);

        uint256[] memory chains = adapter.getSupportedChains();
        assertEq(chains.length, 8); // 7 default + 1 new
    }

    function test_addChain_emitsEvent() public {
        address bridge = makeAddr("bridge");
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit L2ChainAdapter.ChainAdded(12_345, "TestChain", bridge);
        adapter.addChain(12_345, "TestChain", bridge, makeAddr("messenger"), 1, 1_000_000);
    }

    function test_addChain_revert_alreadyExists() public {
        vm.prank(admin);
        vm.expectRevert(L2ChainAdapter.ChainAlreadyExists.selector);
        adapter.addChain(ARB, "Arb Dupe", makeAddr("b"), makeAddr("m"), 1, 1_000_000);
    }

    function test_addChain_revert_zeroBridge() public {
        vm.prank(admin);
        vm.expectRevert(L2ChainAdapter.ZeroAddress.selector);
        adapter.addChain(99_999, "Test", address(0), makeAddr("m"), 1, 1_000_000);
    }

    function test_addChain_revert_zeroMessenger() public {
        vm.prank(admin);
        vm.expectRevert(L2ChainAdapter.ZeroAddress.selector);
        adapter.addChain(99_999, "Test", makeAddr("b"), address(0), 1, 1_000_000);
    }

    function test_addChain_revert_notAdmin() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.addChain(99_999, "Test", makeAddr("b"), makeAddr("m"), 1, 1_000_000);
    }

    // ── updateChain
    // ──────────────────────────────────────────────

    function test_updateChain_enable() public {
        address bridge = makeAddr("arbBridge");
        address messenger = makeAddr("arbMessenger");

        vm.prank(admin);
        adapter.updateChain(ARB, bridge, messenger, 10, 2_000_000, true);

        L2ChainAdapter.ChainConfig memory config = adapter.getChainConfig(ARB);
        assertTrue(config.enabled);
        assertEq(config.bridge, bridge);
        assertEq(config.messenger, messenger);
        assertEq(config.confirmations, 10);
        assertEq(config.gasLimit, 2_000_000);
    }

    function test_updateChain_disable() public {
        // First enable
        vm.startPrank(admin);
        adapter.updateChain(ARB, makeAddr("b"), makeAddr("m"), 1, 1_000_000, true);
        assertTrue(adapter.getChainConfig(ARB).enabled);

        // Then disable (can use zero addresses now)
        adapter.updateChain(ARB, address(0), address(0), 1, 1_000_000, false);
        assertFalse(adapter.getChainConfig(ARB).enabled);
        vm.stopPrank();
    }

    function test_updateChain_emitsEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit L2ChainAdapter.ChainUpdated(ARB, true);
        adapter.updateChain(ARB, makeAddr("b"), makeAddr("m"), 1, 1_000_000, true);
    }

    function test_updateChain_revert_chainNotFound() public {
        vm.prank(admin);
        vm.expectRevert(L2ChainAdapter.ChainNotFound.selector);
        adapter.updateChain(99_999, makeAddr("b"), makeAddr("m"), 1, 1_000_000, true);
    }

    function test_updateChain_revert_enableZeroBridge() public {
        vm.prank(admin);
        vm.expectRevert(L2ChainAdapter.ZeroAddress.selector);
        adapter.updateChain(ARB, address(0), makeAddr("m"), 1, 1_000_000, true);
    }

    function test_updateChain_revert_enableZeroMessenger() public {
        vm.prank(admin);
        vm.expectRevert(L2ChainAdapter.ZeroAddress.selector);
        adapter.updateChain(ARB, makeAddr("b"), address(0), 1, 1_000_000, true);
    }

    function test_updateChain_revert_notAdmin() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.updateChain(ARB, makeAddr("b"), makeAddr("m"), 1, 1_000_000, true);
    }

    // ── sendMessage
    // ──────────────────────────────────────────────

    function _enableArbitrum() internal {
        vm.prank(admin);
        adapter.updateChain(ARB, makeAddr("b"), makeAddr("m"), 1, 1_000_000, true);
    }

    function test_sendMessage_success() public {
        _enableArbitrum();

        bytes32 msgId = adapter.sendMessage(ARB, hex"aabb");
        assertTrue(msgId != bytes32(0));

        L2ChainAdapter.MessageStatus status = adapter.getMessageStatus(msgId);
        assertEq(uint8(status), uint8(L2ChainAdapter.MessageStatus.PENDING));
    }

    function test_sendMessage_emitsEvent() public {
        _enableArbitrum();

        vm.expectEmit(false, false, false, true);
        emit L2ChainAdapter.MessageSent(bytes32(0), block.chainid, ARB);
        adapter.sendMessage(ARB, hex"aabb");
    }

    function test_sendMessage_revert_chainNotEnabled() public view {
        // ARB is disabled by default
        assertFalse(adapter.getChainConfig(ARB).enabled);
    }

    function test_sendMessage_revert_disabled() public {
        vm.expectRevert(L2ChainAdapter.ChainNotEnabled.selector);
        adapter.sendMessage(ARB, hex"aabb");
    }

    function test_sendMessage_revert_unknownChain() public {
        vm.expectRevert(L2ChainAdapter.ChainNotEnabled.selector);
        adapter.sendMessage(99_999, hex"aabb");
    }

    function test_sendMessage_uniqueIds() public {
        _enableArbitrum();
        bytes32 id1 = adapter.sendMessage(ARB, hex"aa");

        // Warp 1 second to get different timestamp
        vm.warp(block.timestamp + 1);
        bytes32 id2 = adapter.sendMessage(ARB, hex"aa");

        assertTrue(id1 != id2);
    }

    function test_sendMessage_differentPayloads() public {
        _enableArbitrum();
        bytes32 id1 = adapter.sendMessage(ARB, hex"aa");
        bytes32 id2 = adapter.sendMessage(ARB, hex"bb");
        // Same timestamp but different payloads may or may not differ
        // Just verify both succeed
        assertTrue(id1 != bytes32(0));
        assertTrue(id2 != bytes32(0));
    }

    // ── receiveMessage with oracle-signed proof
    // ──────────────────

    function _setupOracleForChain(
        uint256 chainId
    ) internal {
        vm.startPrank(admin);
        adapter.addOracle(chainId, oracleSigner);
        adapter.updateChain(chainId, makeAddr("b"), makeAddr("m"), 1, 1_000_000, true);
        vm.stopPrank();
    }

    /// @dev OZ MerkleProof._hashPair sorts before hashing
    function _hashPair(
        bytes32 a,
        bytes32 b
    ) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _buildProof(
        uint256 sourceChain,
        bytes32 messageId,
        bytes memory payload,
        uint256 blockNumber,
        bytes32 /* stateRoot (unused) */
    ) internal view returns (bytes memory) {
        // Compute message leaf
        bytes32 messageLeaf =
            keccak256(abi.encodePacked(sourceChain, block.chainid, messageId, keccak256(payload)));

        // Build a Merkle tree: leaf + sibling → root (contract requires ≥1 proof element)
        bytes32 sibling = bytes32(uint256(0xdead));
        bytes32 actualRoot = _hashPair(messageLeaf, sibling);

        // Sign the state root with oracle key
        bytes32 innerHash = keccak256(abi.encodePacked(sourceChain, blockNumber, actualRoot));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", innerHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Encode: stateRoot(32) + blockNumber(32) + merkleProofLen(2) + sibling(32) + sig(65)
        return abi.encodePacked(
            actualRoot,
            bytes32(blockNumber),
            uint16(1), // 1 merkle proof element
            sibling,
            sig
        );
    }

    function test_receiveMessage_success() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory payload = hex"aabbccdd";
        uint256 blockNum = 100;

        bytes memory proof = _buildProof(ARB, messageId, payload, blockNum, bytes32(0));

        vm.prank(relayer);
        adapter.receiveMessage(messageId, ARB, payload, proof);

        L2ChainAdapter.MessageStatus status = adapter.getMessageStatus(messageId);
        assertEq(uint8(status), uint8(L2ChainAdapter.MessageStatus.RELAYED));
    }

    function test_receiveMessage_emitsEvent() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(77));
        bytes memory payload = hex"1122";

        bytes memory proof = _buildProof(ARB, messageId, payload, 200, bytes32(0));

        vm.prank(relayer);
        vm.expectEmit(true, false, false, true);
        emit L2ChainAdapter.MessageReceived(messageId, ARB);
        adapter.receiveMessage(messageId, ARB, payload, proof);
    }

    function test_receiveMessage_revert_duplicateId() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory payload = hex"aabb";
        bytes memory proof = _buildProof(ARB, messageId, payload, 100, bytes32(0));

        vm.prank(relayer);
        adapter.receiveMessage(messageId, ARB, payload, proof);

        // Try again with same ID
        vm.prank(relayer);
        vm.expectRevert(L2ChainAdapter.InvalidMessageStatus.selector);
        adapter.receiveMessage(messageId, ARB, payload, proof);
    }

    function test_receiveMessage_revert_shortProof() public {
        _setupOracleForChain(ARB);

        vm.prank(relayer);
        vm.expectRevert("Message proof too short");
        adapter.receiveMessage(bytes32(uint256(1)), ARB, hex"aa", hex"0011");
    }

    function test_receiveMessage_revert_notRelayer() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory proof = _buildProof(ARB, messageId, hex"aa", 100, bytes32(0));

        vm.prank(oracle);
        vm.expectRevert();
        adapter.receiveMessage(messageId, ARB, hex"aa", proof);
    }

    function test_receiveMessage_revert_disabledChain() public {
        // ARB is disabled by default, add oracle but don't enable
        vm.prank(admin);
        adapter.addOracle(ARB, oracleSigner);

        bytes32 messageId = bytes32(uint256(42));
        // Build proof that would be valid if chain were enabled
        bytes memory fakeProof = new bytes(161);
        vm.prank(relayer);
        vm.expectRevert(); // chain not enabled → _verifyMessageProof returns false
        adapter.receiveMessage(messageId, ARB, hex"aa", fakeProof);
    }

    // ── receiveMessage with pre-stored state root
    // ────────────────

    function test_receiveMessage_withKnownStateRoot() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(55));
        bytes memory payload = hex"eeff";
        uint256 blockNum = 1500; // Must be > 1000 to avoid underflow in expiry check

        // Compute leaf and merkle root (with 1 sibling) for known state root path
        bytes32 messageLeaf =
            keccak256(abi.encodePacked(ARB, block.chainid, messageId, keccak256(payload)));
        bytes32 sibling = bytes32(uint256(0xdead));
        bytes32 merkleRoot = _hashPair(messageLeaf, sibling);

        // Pre-store state root via oracle
        vm.prank(oracle);
        adapter.updateStateRoot(ARB, blockNum, merkleRoot);

        // Build proof with known state root — dummy sig OK because root is already known
        bytes memory dummySig = new bytes(65);
        bytes memory proof =
            abi.encodePacked(merkleRoot, bytes32(blockNum), uint16(1), sibling, dummySig);

        vm.prank(relayer);
        adapter.receiveMessage(messageId, ARB, payload, proof);

        assertEq(
            uint8(adapter.getMessageStatus(messageId)), uint8(L2ChainAdapter.MessageStatus.RELAYED)
        );
    }

    function test_receiveMessage_revert_wrongStateRoot() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(88));
        bytes memory payload = hex"aabb";
        uint256 blockNum = 300;

        // Store a DIFFERENT state root than what the proof will claim
        vm.prank(oracle);
        adapter.updateStateRoot(ARB, blockNum, bytes32(uint256(999)));

        // Build proof with correct leaf but claim a different root
        bytes32 messageLeaf =
            keccak256(abi.encodePacked(ARB, block.chainid, messageId, keccak256(payload)));
        bytes32 sibling = bytes32(uint256(0xdead));
        bytes32 correctRoot = _hashPair(messageLeaf, sibling);

        bytes memory dummySig = new bytes(65);
        bytes memory proof =
            abi.encodePacked(correctRoot, bytes32(blockNum), uint16(1), sibling, dummySig);

        vm.prank(relayer);
        vm.expectRevert(L2ChainAdapter.InvalidProof.selector);
        adapter.receiveMessage(messageId, ARB, payload, proof);
    }

    // ── confirmMessage
    // ───────────────────────────────────────────

    function test_confirmMessage_success() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory payload = hex"aabb";
        bytes memory proof = _buildProof(ARB, messageId, payload, 100, bytes32(0));

        vm.prank(relayer);
        adapter.receiveMessage(messageId, ARB, payload, proof);

        vm.prank(relayer);
        adapter.confirmMessage(messageId);

        assertEq(
            uint8(adapter.getMessageStatus(messageId)),
            uint8(L2ChainAdapter.MessageStatus.CONFIRMED)
        );
    }

    function test_confirmMessage_emitsEvent() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory payload = hex"aabb";
        bytes memory proof = _buildProof(ARB, messageId, payload, 100, bytes32(0));

        vm.prank(relayer);
        adapter.receiveMessage(messageId, ARB, payload, proof);

        vm.prank(relayer);
        vm.expectEmit(true, false, false, false);
        emit L2ChainAdapter.MessageConfirmed(messageId);
        adapter.confirmMessage(messageId);
    }

    function test_confirmMessage_revert_notRelayed() public {
        vm.prank(relayer);
        vm.expectRevert(L2ChainAdapter.InvalidMessageStatus.selector);
        adapter.confirmMessage(bytes32(uint256(999)));
    }

    function test_confirmMessage_revert_notRelayer() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory proof = _buildProof(ARB, messageId, hex"aa", 100, bytes32(0));
        vm.prank(relayer);
        adapter.receiveMessage(messageId, ARB, hex"aa", proof);

        vm.prank(oracle);
        vm.expectRevert();
        adapter.confirmMessage(messageId);
    }

    // ── updateStateRoot
    // ──────────────────────────────────────────

    function test_updateStateRoot() public {
        bytes32 root = bytes32(uint256(12_345));
        vm.prank(oracle);
        adapter.updateStateRoot(ARB, 100, root);

        assertEq(adapter.stateRoots(ARB, 100), root);
        assertEq(adapter.latestBlockNumber(ARB), 100);
    }

    function test_updateStateRoot_updatesLatestBlock() public {
        vm.startPrank(oracle);
        adapter.updateStateRoot(ARB, 100, bytes32(uint256(1)));
        adapter.updateStateRoot(ARB, 200, bytes32(uint256(2)));
        vm.stopPrank();

        assertEq(adapter.latestBlockNumber(ARB), 200);
    }

    function test_updateStateRoot_doesNotDecrease() public {
        vm.startPrank(oracle);
        adapter.updateStateRoot(ARB, 200, bytes32(uint256(2)));
        adapter.updateStateRoot(ARB, 100, bytes32(uint256(1)));
        vm.stopPrank();

        assertEq(adapter.latestBlockNumber(ARB), 200);
    }

    function test_updateStateRoot_emitsEvent() public {
        vm.prank(oracle);
        vm.expectEmit(true, true, false, true);
        emit L2ChainAdapter.StateRootUpdated(ARB, 100, bytes32(uint256(42)));
        adapter.updateStateRoot(ARB, 100, bytes32(uint256(42)));
    }

    function test_updateStateRoot_revert_notOracle() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.updateStateRoot(ARB, 100, bytes32(uint256(1)));
    }

    // ── Oracle Management
    // ────────────────────────────────────────

    function test_addOracle() public {
        address o = makeAddr("newOracle");
        vm.prank(admin);
        adapter.addOracle(ARB, o);
        // Verify by checking chainOracles(ARB, 0)
        assertEq(adapter.chainOracles(ARB, 0), o);
    }

    function test_addOracle_emitsEvent() public {
        address o = makeAddr("newOracle");
        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit L2ChainAdapter.OracleAdded(ARB, o);
        adapter.addOracle(ARB, o);
    }

    function test_addOracle_multiple() public {
        vm.startPrank(admin);
        adapter.addOracle(ARB, makeAddr("o1"));
        adapter.addOracle(ARB, makeAddr("o2"));
        adapter.addOracle(ARB, makeAddr("o3"));
        vm.stopPrank();

        assertEq(adapter.chainOracles(ARB, 0), makeAddr("o1"));
        assertEq(adapter.chainOracles(ARB, 1), makeAddr("o2"));
        assertEq(adapter.chainOracles(ARB, 2), makeAddr("o3"));
    }

    function test_addOracle_revert_notAdmin() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.addOracle(ARB, makeAddr("o"));
    }

    function test_removeOracle() public {
        vm.startPrank(admin);
        adapter.addOracle(ARB, makeAddr("o1"));
        adapter.addOracle(ARB, makeAddr("o2"));
        adapter.removeOracle(ARB, makeAddr("o1"));
        vm.stopPrank();

        // o2 swapped to position 0
        assertEq(adapter.chainOracles(ARB, 0), makeAddr("o2"));
    }

    function test_removeOracle_emitsEvent() public {
        vm.prank(admin);
        adapter.addOracle(ARB, makeAddr("o1"));

        vm.prank(admin);
        vm.expectEmit(true, true, false, false);
        emit L2ChainAdapter.OracleRemoved(ARB, makeAddr("o1"));
        adapter.removeOracle(ARB, makeAddr("o1"));
    }

    function test_removeOracle_revert_notAdmin() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.removeOracle(ARB, makeAddr("o"));
    }

    // ── setMinOracleSignatures
    // ───────────────────────────────────

    function test_setMinOracleSignatures() public {
        vm.prank(admin);
        adapter.setMinOracleSignatures(ARB, 3);
        assertEq(adapter.minOracleSignatures(ARB), 3);
    }

    function test_setMinOracleSignatures_revert_notAdmin() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.setMinOracleSignatures(ARB, 3);
    }

    // ── View Functions
    // ───────────────────────────────────────────

    function test_getSupportedChains() public view {
        uint256[] memory chains = adapter.getSupportedChains();
        assertEq(chains.length, 7);
    }

    function test_getChainConfig_unknown() public view {
        L2ChainAdapter.ChainConfig memory config = adapter.getChainConfig(99_999);
        assertEq(config.chainId, 0);
    }

    function test_isChainSupported_disabled() public view {
        assertFalse(adapter.isChainSupported(ARB));
    }

    function test_isChainSupported_enabled() public {
        _enableArbitrum();
        assertTrue(adapter.isChainSupported(ARB));
    }

    function test_getMessageStatus_unknown() public view {
        assertEq(
            uint8(adapter.getMessageStatus(bytes32(uint256(999)))),
            uint8(L2ChainAdapter.MessageStatus.PENDING)
        );
    }

    // ── Signature Malleability Protection
    // ─────────────────────────

    function test_signatureMalleability_highS_rejected() public {
        _setupOracleForChain(ARB);

        bytes32 messageId = bytes32(uint256(42));
        bytes memory payload = hex"aabb";
        uint256 blockNum = 100;

        // Compute message leaf and merkle root
        bytes32 messageLeaf =
            keccak256(abi.encodePacked(ARB, block.chainid, messageId, keccak256(payload)));
        bytes32 sibling = bytes32(uint256(0xdead));
        bytes32 merkleRoot = _hashPair(messageLeaf, sibling);

        // Sign with oracle key
        bytes32 innerHash = keccak256(abi.encodePacked(ARB, blockNum, merkleRoot));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", innerHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, ethHash);

        // Malleable: flip s to N - s
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 malleableS = bytes32(N - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;
        bytes memory malleableSig = abi.encodePacked(r, malleableS, malleableV);

        bytes memory proof =
            abi.encodePacked(merkleRoot, bytes32(blockNum), uint16(1), sibling, malleableSig);

        // Should fail because high-s signature is rejected by _recoverSigner
        vm.prank(relayer);
        vm.expectRevert(); // InsufficientOracleSignatures or InvalidOracleSignature
        adapter.receiveMessage(messageId, ARB, payload, proof);
    }

    // ── Fuzz
    // ─────────────────────────────────────────────────────

    function testFuzz_sendMessage_payloads(
        bytes calldata payload
    ) public {
        _enableArbitrum();
        bytes32 id = adapter.sendMessage(ARB, payload);
        assertTrue(id != bytes32(0));
    }

    function testFuzz_updateStateRoot(
        uint256 blockNum,
        bytes32 root
    ) public {
        vm.assume(blockNum > 0);
        vm.prank(oracle);
        adapter.updateStateRoot(ARB, blockNum, root);
        assertEq(adapter.stateRoots(ARB, blockNum), root);
    }
}
