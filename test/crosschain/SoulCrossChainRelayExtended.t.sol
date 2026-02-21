// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SoulCrossChainRelay.sol";

/// @dev Mock bridge adapter that succeeds
contract MockBridgeAdapterExt {
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

    fallback() external payable {
        called = true;
    }

    receive() external payable {}
}

/// @dev Mock ProofHub that records submissions
contract MockProofHubExt {
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

/// @dev Bridge adapter that always reverts
contract FailingBridgeAdapterExt {
    fallback() external payable {
        revert("bridge fail");
    }
}

/**
 * @title SoulCrossChainRelayExtendedTest
 * @notice Extended tests covering relayBatch, selfRelayProof edge cases,
 *         failing bridge adapter scenarios, and additional fuzz tests.
 *         Supplements the existing SoulCrossChainRelayTest.
 */
contract SoulCrossChainRelayExtendedTest is Test {
    SoulCrossChainRelay public relay;
    MockBridgeAdapterExt public bridgeAdapter;
    MockProofHubExt public proofHub;
    FailingBridgeAdapterExt public failingBridge;

    address admin;
    address relayer = makeAddr("relayer");
    address bridgeRole = makeAddr("bridgeRole");
    address operatorAddr = makeAddr("operator");

    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    uint256 constant DEST_CHAIN = 42_161; // Arbitrum
    uint256 constant BASE_CHAIN = 8453;

    function setUp() public {
        admin = address(this);
        proofHub = new MockProofHubExt();
        bridgeAdapter = new MockBridgeAdapterExt();
        failingBridge = new FailingBridgeAdapterExt();

        relay = new SoulCrossChainRelay(
            address(proofHub),
            SoulCrossChainRelay.BridgeType.LAYERZERO
        );

        relay.grantRole(RELAYER_ROLE, relayer);
        relay.grantRole(BRIDGE_ROLE, bridgeRole);
        relay.grantRole(OPERATOR_ROLE, operatorAddr);

        // Configure destination chain
        SoulCrossChainRelay.ChainConfig memory config = SoulCrossChainRelay
            .ChainConfig({
                proofHub: address(proofHub),
                bridgeAdapter: address(bridgeAdapter),
                bridgeChainId: 30_110,
                active: true
            });

        vm.prank(operatorAddr);
        relay.configureChain(DEST_CHAIN, config);
    }

    // =========================================================================
    // relayBatch TESTS — previously untested
    // =========================================================================

    function test_relayBatch_success() public {
        bytes[] memory payloads = new bytes[](3);
        payloads[0] = abi.encode(
            uint8(1),
            keccak256("proof1"),
            hex"aa",
            hex"bb",
            bytes32(uint256(1)),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        payloads[1] = abi.encode(
            uint8(1),
            keccak256("proof2"),
            hex"cc",
            hex"dd",
            bytes32(uint256(2)),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        payloads[2] = abi.encode(
            uint8(1),
            keccak256("proof3"),
            hex"ee",
            hex"ff",
            bytes32(uint256(3)),
            uint64(DEST_CHAIN),
            bytes32(0)
        );

        vm.deal(address(this), 1 ether);
        bytes32 messageId = relay.relayBatch{value: 0.01 ether}(
            uint64(DEST_CHAIN),
            payloads
        );

        assertTrue(messageId != bytes32(0), "Message ID should be non-zero");
        assertTrue(bridgeAdapter.called(), "Bridge adapter should be called");
    }

    function test_relayBatch_emitsProofRelayed() public {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = hex"aabb";

        vm.deal(address(this), 1 ether);

        vm.expectEmit(false, false, false, false);
        emit SoulCrossChainRelay.ProofRelayed(
            bytes32(0),
            uint64(block.chainid),
            uint64(DEST_CHAIN),
            bytes32(0),
            bytes32(0) // Don't check exact messageId
        );

        relay.relayBatch{value: 0.01 ether}(uint64(DEST_CHAIN), payloads);
    }

    function test_relayBatch_incrementsNonce() public {
        uint256 nonceBefore = relay.relayNonce();

        bytes[] memory payloads = new bytes[](1);
        payloads[0] = hex"aa";

        vm.deal(address(this), 1 ether);
        relay.relayBatch{value: 0.01 ether}(uint64(DEST_CHAIN), payloads);

        assertEq(relay.relayNonce(), nonceBefore + 1, "Nonce should increment");
    }

    function test_relayBatch_revert_chainNotSupported() public {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = hex"aa";

        vm.expectRevert(
            abi.encodeWithSelector(
                SoulCrossChainRelay.ChainNotSupported.selector,
                uint256(99999)
            )
        );
        relay.relayBatch(uint64(99999), payloads);
    }

    function test_relayBatch_revert_whenPaused() public {
        vm.prank(operatorAddr);
        relay.pause();

        bytes[] memory payloads = new bytes[](1);
        payloads[0] = hex"aa";

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        relay.relayBatch(uint64(DEST_CHAIN), payloads);
    }

    function test_relayBatch_emptyPayloads() public {
        bytes[] memory payloads = new bytes[](0);

        vm.deal(address(this), 1 ether);
        // Empty batch should still succeed (relay semantics don't enforce min size)
        bytes32 messageId = relay.relayBatch{value: 0.01 ether}(
            uint64(DEST_CHAIN),
            payloads
        );
        assertTrue(messageId != bytes32(0));
    }

    function test_relayBatch_uniqueMessageIds() public {
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = hex"aa";

        vm.deal(address(this), 2 ether);

        bytes32 id1 = relay.relayBatch{value: 0.01 ether}(
            uint64(DEST_CHAIN),
            payloads
        );
        bytes32 id2 = relay.relayBatch{value: 0.01 ether}(
            uint64(DEST_CHAIN),
            payloads
        );

        assertTrue(id1 != id2, "Batch message IDs must be unique");
    }

    // =========================================================================
    // selfRelayProof EDGE CASES — previously sparse
    // =========================================================================

    function test_selfRelayProof_revert_whenPaused() public {
        vm.prank(operatorAddr);
        relay.pause();

        vm.prank(makeAddr("anyone"));
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        relay.selfRelayProof(
            keccak256("p"),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    function test_selfRelayProof_revert_chainNotSupported() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulCrossChainRelay.ChainNotSupported.selector,
                uint256(99999)
            )
        );
        relay.selfRelayProof(
            keccak256("p"),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(99999),
            bytes32(0)
        );
    }

    function test_selfRelayProof_revert_proofTooLarge() public {
        // MAX_PROOF_SIZE = 32768
        bytes memory largeProof = new bytes(32769);
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulCrossChainRelay.ProofTooLarge.selector,
                uint256(32769)
            )
        );
        relay.selfRelayProof(
            keccak256("p"),
            largeProof,
            hex"bb",
            bytes32(0),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
    }

    // =========================================================================
    // FAILING BRIDGE ADAPTER — previously unused
    // =========================================================================

    function test_relayProof_revert_failingBridge() public {
        // Configure a chain with a failing bridge adapter
        SoulCrossChainRelay.ChainConfig memory failConfig = SoulCrossChainRelay
            .ChainConfig({
                proofHub: address(proofHub),
                bridgeAdapter: address(failingBridge),
                bridgeChainId: 30_111,
                active: true
            });

        vm.prank(operatorAddr);
        relay.configureChain(BASE_CHAIN, failConfig);

        vm.deal(relayer, 1 ether);
        vm.prank(relayer);

        vm.expectRevert();
        relay.relayProof{value: 0.01 ether}(
            keccak256("p"),
            hex"aa",
            hex"bb",
            bytes32(0),
            uint64(BASE_CHAIN),
            bytes32(0)
        );
    }

    function test_relayBatch_revert_failingBridge() public {
        SoulCrossChainRelay.ChainConfig memory failConfig = SoulCrossChainRelay
            .ChainConfig({
                proofHub: address(proofHub),
                bridgeAdapter: address(failingBridge),
                bridgeChainId: 30_111,
                active: true
            });

        vm.prank(operatorAddr);
        relay.configureChain(BASE_CHAIN, failConfig);

        bytes[] memory payloads = new bytes[](1);
        payloads[0] = hex"aa";

        vm.deal(address(this), 1 ether);
        vm.expectRevert();
        relay.relayBatch{value: 0.01 ether}(uint64(BASE_CHAIN), payloads);
    }

    // =========================================================================
    // FUZZ TESTS — additional coverage
    // =========================================================================

    function testFuzz_relayBatch_multipleBatchSizes(uint8 count) public {
        count = uint8(bound(count, 1, 20));

        bytes[] memory payloads = new bytes[](count);
        for (uint8 i = 0; i < count; i++) {
            payloads[i] = abi.encode(
                uint8(1),
                keccak256(abi.encodePacked("proof", i)),
                hex"deadbeef",
                hex"aabb",
                bytes32(uint256(i)),
                uint64(DEST_CHAIN),
                bytes32(0)
            );
        }

        vm.deal(address(this), 1 ether);
        bytes32 messageId = relay.relayBatch{value: 0.01 ether}(
            uint64(DEST_CHAIN),
            payloads
        );
        assertTrue(messageId != bytes32(0));
    }

    function testFuzz_relayProof_variableProofSizes(uint16 proofSize) public {
        proofSize = uint16(bound(proofSize, 1, 32_768));
        bytes memory proof = new bytes(proofSize);

        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bytes32 id = relay.relayProof{value: 0.01 ether}(
            keccak256("test"),
            proof,
            hex"aabb",
            bytes32(uint256(42)),
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        assertTrue(id != bytes32(0));
    }

    function testFuzz_relayProof_variableCommitments(
        bytes32 commitment
    ) public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        bytes32 id = relay.relayProof{value: 0.01 ether}(
            keccak256("test"),
            hex"deadbeef",
            hex"aabb",
            commitment,
            uint64(DEST_CHAIN),
            bytes32(0)
        );
        assertTrue(id != bytes32(0));
    }
}
