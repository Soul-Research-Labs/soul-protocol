// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ZaseonCrossChainRelay.sol";

/// @dev Mock bridge adapter that succeeds
contract MockRelayAdapter {
    bool public called;
    bytes public lastPayload;

    function sendMessage(
        uint32,
        bytes calldata payload,
        bytes calldata
    ) external payable {
        called = true;
        lastPayload = payload;
    }

    function dispatch(
        uint32,
        bytes32,
        bytes calldata payload
    ) external payable returns (bytes32) {
        called = true;
        lastPayload = payload;
        return keccak256(payload);
    }

    /// @dev Accept any call with unknown selector (e.g. tuple-typed sendMessage)
    fallback() external payable {
        called = true;
    }

    receive() external payable {}
}

/// @dev Mock ProofHub that records submissions
contract MockProofHub {
    bool public submitted;
    bytes32 public lastCommitment;

    function submitProofInstant(
        bytes calldata,
        bytes calldata,
        bytes32 commitment,
        uint64,
        uint64,
        bytes32
    ) external {
        submitted = true;
        lastCommitment = commitment;
    }
}

/// @dev Bridge adapter that always fails
contract FailingRelayAdapter {
    fallback() external payable {
        revert("bridge fail");
    }
}

contract ZaseonCrossChainRelayTest is Test {
    ZaseonCrossChainRelay public relay;
    MockRelayAdapter public relayAdapter;
    MockProofHub public proofHub;

    address admin;
    address relayer = makeAddr("relayer");
    address bridgeRole = makeAddr("bridgeRole");
    address operatorAddr = makeAddr("operator");

    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant RELAY_ROLE = keccak256("RELAY_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    uint256 constant DEST_CHAIN = 42_161; // Arbitrum

    function setUp() public {
        admin = address(this);
        proofHub = new MockProofHub();
        relayAdapter = new MockRelayAdapter();

        relay = new ZaseonCrossChainRelay(
            address(proofHub),
            ZaseonCrossChainRelay.BridgeType.LAYERZERO
        );

        relay.grantRole(RELAYER_ROLE, relayer);
        relay.grantRole(RELAY_ROLE, bridgeRole);
        relay.grantRole(OPERATOR_ROLE, operatorAddr);

        // Configure destination chain
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: address(proofHub),
                relayAdapter: address(relayAdapter),
                bridgeChainId: 30_110,
                active: true
            });
        relay.configureChain(DEST_CHAIN, config);
    }

    // ── Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsState() public view {
        assertEq(relay.proofHub(), address(proofHub));
        assertEq(
            uint8(relay.bridgeType()),
            uint8(ZaseonCrossChainRelay.BridgeType.LAYERZERO)
        );
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(relay.hasRole(relay.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(relay.hasRole(RELAYER_ROLE, admin));
        assertTrue(relay.hasRole(OPERATOR_ROLE, admin));
    }

    function test_constructor_revert_zeroProofHub() public {
        vm.expectRevert(ZaseonCrossChainRelay.ZeroAddress.selector);
        new ZaseonCrossChainRelay(
            address(0),
            ZaseonCrossChainRelay.BridgeType.LAYERZERO
        );
    }

    function test_constructor_hyperlaneType() public {
        ZaseonCrossChainRelay r2 = new ZaseonCrossChainRelay(
            address(proofHub),
            ZaseonCrossChainRelay.BridgeType.HYPERLANE
        );
        assertEq(
            uint8(r2.bridgeType()),
            uint8(ZaseonCrossChainRelay.BridgeType.HYPERLANE)
        );
    }

    // ── configureChain
    // ───────────────────────────────────────────

    function test_configureChain_addsToSupported() public view {
        uint256[] memory chains = relay.getSupportedChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], DEST_CHAIN);
        assertTrue(relay.isChainSupported(DEST_CHAIN));
    }

    function test_configureChain_storesConfig() public view {
        (
            address hub,
            address adapter_,
            uint32 bridgeChainId,
            bool active
        ) = relay.chainConfigs(DEST_CHAIN);
        assertEq(hub, address(proofHub));
        assertEq(adapter_, address(relayAdapter));
        assertEq(bridgeChainId, 30_110);
        assertTrue(active);
    }

    function test_configureChain_emitsEvent() public {
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: makeAddr("hub2"),
                relayAdapter: makeAddr("adapter2"),
                bridgeChainId: 99,
                active: true
            });

        vm.prank(operatorAddr);
        vm.expectEmit(true, false, false, true);
        emit ZaseonCrossChainRelay.ChainConfigured(
            10,
            makeAddr("hub2"),
            makeAddr("adapter2"),
            99
        );
        relay.configureChain(10, config);
    }

    function test_configureChain_revert_zeroProofHub() public {
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: address(0),
                relayAdapter: makeAddr("a"),
                bridgeChainId: 1,
                active: true
            });
        vm.prank(operatorAddr);
        vm.expectRevert(ZaseonCrossChainRelay.InvalidProofHub.selector);
        relay.configureChain(999, config);
    }

    function test_configureChain_revert_zeroRelayAdapter() public {
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: makeAddr("h"),
                relayAdapter: address(0),
                bridgeChainId: 1,
                active: true
            });
        vm.prank(operatorAddr);
        vm.expectRevert(ZaseonCrossChainRelay.InvalidRelayAdapter.selector);
        relay.configureChain(999, config);
    }

    function test_configureChain_revert_notOperator() public {
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: makeAddr("h"),
                relayAdapter: makeAddr("a"),
                bridgeChainId: 1,
                active: true
            });
        vm.prank(relayer);
        vm.expectRevert();
        relay.configureChain(999, config);
    }

    function test_configureChain_updateExisting() public {
        // Re-configure DEST_CHAIN → should NOT add duplicate to supportedChains
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: makeAddr("hub3"),
                relayAdapter: makeAddr("adapter3"),
                bridgeChainId: 55,
                active: true
            });
        relay.configureChain(DEST_CHAIN, config);

        uint256[] memory chains = relay.getSupportedChains();
        assertEq(chains.length, 1); // no duplicate push
        (address hub, , , ) = relay.chainConfigs(DEST_CHAIN);
        assertEq(hub, makeAddr("hub3"));
    }

    // ── relayProof
    // ───────────────────────────────────────────────

    function test_relayProof_success() public {
        bytes memory proof = hex"aabbccdd";
        bytes memory pubInputs = hex"1122";
        bytes32 commitment = bytes32(uint256(42));
        bytes32 proofType = bytes32("groth16");

        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bytes32 messageId = relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            proof,
            pubInputs,
            commitment,
            uint64(DEST_CHAIN),
            proofType
        );

        assertTrue(messageId != bytes32(0));
        assertTrue(relayAdapter.called());
        assertEq(relay.relayNonce(), 1);
    }

    function test_relayProof_emitsEvent() public {
        bytes32 proofId = bytes32(uint256(7));
        bytes memory proof = hex"aa";
        bytes memory pubInputs = hex"bb";
        bytes32 commitment = bytes32(uint256(99));

        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectEmit(true, false, false, false);
        emit ZaseonCrossChainRelay.ProofRelayed(
            proofId,
            0,
            0,
            commitment,
            bytes32(0)
        );
        relay.relayProof{value: 0.01 ether}(
            proofId,
            proof,
            pubInputs,
            commitment,
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    function test_relayProof_storesRelayedProof() public {
        bytes32 proofId = bytes32(uint256(5));
        bytes memory proof = hex"aabb";
        bytes memory pubInputs = hex"ccdd";
        bytes32 commitment = bytes32(uint256(77));

        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bytes32 messageId = relay.relayProof{value: 0.01 ether}(
            proofId,
            proof,
            pubInputs,
            commitment,
            uint64(DEST_CHAIN),
            bytes32("plonk")
        );

        (
            bytes32 storedProofId,
            ,
            ,
            bytes32 storedCommitment,
            uint64 srcChain,
            uint64 dstChain,
            bytes32 storedProofType,
            uint256 ts,
            bool processed
        ) = relay.relayedProofs(messageId);

        assertEq(storedProofId, proofId);
        assertEq(storedCommitment, commitment);
        assertEq(srcChain, uint64(block.chainid));
        assertEq(dstChain, uint64(DEST_CHAIN));
        assertEq(storedProofType, bytes32("plonk"));
        assertTrue(ts > 0);
        assertFalse(processed);
    }

    function test_relayProof_revert_proofTooLarge() public {
        bytes memory bigProof = new bytes(32_769);
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZaseonCrossChainRelay.ProofTooLarge.selector,
                32_769
            )
        );
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            bigProof,
            hex"aa",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    function test_relayProof_revert_publicInputsTooLarge() public {
        bytes memory bigPub = new bytes(8193);
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZaseonCrossChainRelay.PublicInputsTooLarge.selector,
                8193
            )
        );
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            hex"aa",
            bigPub,
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    function test_relayProof_revert_chainNotSupported() public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZaseonCrossChainRelay.ChainNotSupported.selector,
                999
            )
        );
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            hex"aa",
            hex"bb",
            bytes32(0),
            999,
            bytes32(0)
        );
    }

    function test_relayProof_revert_notRelayer() public {
        vm.deal(operatorAddr, 1 ether);
        vm.prank(operatorAddr);
        vm.expectRevert();
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    function test_relayProof_revert_whenPaused() public {
        relay.pause();
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert();
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    function test_relayProof_incrementsNonce() public {
        vm.deal(relayer, 10 ether);
        vm.startPrank(relayer);
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        relay.relayProof{value: 0.01 ether}(
            bytes32(uint256(2)),
            hex"cc",
            hex"dd",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        vm.stopPrank();
        assertEq(relay.relayNonce(), 2);
    }

    // ── selfRelayProof
    // ───────────────────────────────────────────────

    function test_selfRelayProof_success() public {
        address randomUser = makeAddr("randomUser");
        bytes memory proof = hex"aabbccdd";
        bytes memory pubInputs = hex"1122";
        bytes32 commitment = bytes32(uint256(999));
        bytes32 proofType = bytes32("halo2");

        vm.deal(randomUser, 1 ether);
        vm.prank(randomUser);
        
        // Should succeed WITHOUT RELAYER_ROLE
        bytes32 messageId = relay.selfRelayProof{value: 0.01 ether}(
            bytes32(uint256(100)),
            proof,
            pubInputs,
            commitment,
            uint64(DEST_CHAIN),
            proofType
        );

        assertTrue(messageId != bytes32(0));
        assertTrue(relayAdapter.called());
        // Check event emission? Already covered by relayProof tests mostly, but good to know it works.
    }

    // ── relayProof via Hyperlane
    // ──────────────────────────────────

    function test_relayProof_hyperlane() public {
        ZaseonCrossChainRelay hypRelay = new ZaseonCrossChainRelay(
            address(proofHub),
            ZaseonCrossChainRelay.BridgeType.HYPERLANE
        );
        hypRelay.grantRole(RELAYER_ROLE, relayer);
        hypRelay.grantRole(OPERATOR_ROLE, address(this));

        MockRelayAdapter hypAdapter = new MockRelayAdapter();
        ZaseonCrossChainRelay.ChainConfig memory config = ZaseonCrossChainRelay
            .ChainConfig({
                proofHub: address(proofHub),
                relayAdapter: address(hypAdapter),
                bridgeChainId: 30_110,
                active: true
            });
        hypRelay.configureChain(DEST_CHAIN, config);

        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bytes32 msgId = hypRelay.relayProof{value: 0.01 ether}(
            bytes32(uint256(1)),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        assertTrue(msgId != bytes32(0));
        assertTrue(hypAdapter.called());
    }

    // ── receiveRelayedProof
    // ──────────────────────────────────────

    function test_receiveRelayedProof_success() public {
        bytes32 proofId = bytes32(uint256(42));
        bytes memory payload = abi.encode(
            uint8(1), // MSG_PROOF_RELAY
            proofId,
            hex"aabb",
            hex"ccdd",
            bytes32(uint256(99)),
            uint64(10), // srcChainId = Optimism
            bytes32("groth16")
        );

        vm.prank(bridgeRole);
        relay.receiveRelayedProof(10, payload);

        assertTrue(proofHub.submitted());
        assertEq(proofHub.lastCommitment(), bytes32(uint256(99)));
    }

    function test_receiveRelayedProof_emitsEvent() public {
        bytes32 proofId = bytes32(uint256(42));
        bytes memory payload = abi.encode(
            uint8(1),
            proofId,
            hex"aa",
            hex"bb",
            bytes32(uint256(77)),
            uint64(10),
            bytes32("plonk")
        );

        vm.prank(bridgeRole);
        vm.expectEmit(true, false, false, false);
        emit ZaseonCrossChainRelay.ProofReceived(
            proofId,
            10,
            bytes32(uint256(77)),
            true
        );
        relay.receiveRelayedProof(10, payload);
    }

    function test_receiveRelayedProof_revert_invalidMessage() public {
        bytes memory payload = abi.encode(
            uint8(2), // MSG_NULLIFIER_SYNC — not handled
            bytes32(uint256(1)),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(10),
            bytes32(0)
        );

        vm.prank(bridgeRole);
        vm.expectRevert(ZaseonCrossChainRelay.InvalidMessage.selector);
        relay.receiveRelayedProof(10, payload);
    }

    function test_receiveRelayedProof_revert_alreadyProcessed() public {
        bytes32 proofId = bytes32(uint256(42));
        bytes memory payload = abi.encode(
            uint8(1),
            proofId,
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(10),
            bytes32(0)
        );

        vm.prank(bridgeRole);
        relay.receiveRelayedProof(10, payload);

        vm.prank(bridgeRole);
        vm.expectRevert(); // AlreadyProcessed
        relay.receiveRelayedProof(10, payload);
    }

    function test_receiveRelayedProof_revert_notBridgeRole() public {
        bytes memory payload = abi.encode(
            uint8(1),
            bytes32(0),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(10),
            bytes32(0)
        );
        vm.prank(relayer);
        vm.expectRevert();
        relay.receiveRelayedProof(10, payload);
    }

    function test_receiveRelayedProof_revert_whenPaused() public {
        relay.pause();
        bytes memory payload = abi.encode(
            uint8(1),
            bytes32(0),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(10),
            bytes32(0)
        );
        vm.prank(bridgeRole);
        vm.expectRevert();
        relay.receiveRelayedProof(10, payload);
    }

    // ── View Functions
    // ───────────────────────────────────────────

    function test_getSupportedChains() public view {
        uint256[] memory chains = relay.getSupportedChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], DEST_CHAIN);
    }

    function test_isChainSupported_true() public view {
        assertTrue(relay.isChainSupported(DEST_CHAIN));
    }

    function test_isChainSupported_false() public view {
        assertFalse(relay.isChainSupported(999));
    }

    // ── Admin
    // ────────────────────────────────────────────────────

    function test_pause() public {
        relay.pause(); // admin=address(this) has OPERATOR_ROLE
        assertTrue(relay.paused());
    }

    function test_unpause() public {
        relay.pause();
        relay.unpause();
        assertFalse(relay.paused());
    }

    function test_updateProofHub() public {
        address newHub = makeAddr("newHub");
        relay.updateProofHub(newHub);
        assertEq(relay.proofHub(), newHub);
    }

    function test_updateProofHub_revert_zeroAddress() public {
        vm.expectRevert(ZaseonCrossChainRelay.ZeroAddress.selector);
        relay.updateProofHub(address(0));
    }

    function test_updateProofHub_revert_notAdmin() public {
        vm.prank(relayer);
        vm.expectRevert();
        relay.updateProofHub(makeAddr("h"));
    }

    // ── Constants
    // ────────────────────────────────────────────────

    function test_messageTypeConstants() public view {
        assertEq(relay.MSG_PROOF_RELAY(), 1);
        assertEq(relay.MSG_NULLIFIER_SYNC(), 2);
        assertEq(relay.MSG_LOCK_NOTIFICATION(), 3);
    }

    function test_sizeConstants() public view {
        assertEq(relay.MAX_PROOF_SIZE(), 32_768);
        assertEq(relay.MAX_PUBLIC_INPUTS_SIZE(), 8192);
    }

    // ── Fuzz
    // ─────────────────────────────────────────────────────

    function testFuzz_relayProof_differentProofIds(bytes32 proofId) public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bytes32 msgId = relay.relayProof{value: 0.01 ether}(
            proofId,
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        assertTrue(msgId != bytes32(0));
    }
}
