// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SoulCrossChainRelay.sol";
import "../../contracts/crosschain/CrossChainNullifierSync.sol";

/**
 * @title CrossChainIntegrationTest
 * @notice Integration tests for Phase 2: Cross-Chain Proof Relay.
 *         Tests the full flow: relay configuration, proof dispatch,
 *         proof receipt, nullifier sync batch/flush.
 *
 *         These tests use local fork simulation — real bridges require
 *         deployed LayerZero/Hyperlane endpoints on testnets.
 */
contract CrossChainIntegrationTest is Test {
    SoulCrossChainRelay public relaySource;
    SoulCrossChainRelay public relayDest;
    CrossChainNullifierSync public nullifierSync;

    // Mock addresses for bridge and proof hub
    address public mockProofHub = makeAddr("proofHub");
    address public mockBridgeAdapter = makeAddr("bridgeAdapter");
    address public mockNullifierRegistry = makeAddr("nullifierRegistry");

    uint256 constant ARBITRUM_CHAIN_ID = 421614;
    uint256 constant BASE_CHAIN_ID = 84532;
    uint32 constant ARBITRUM_LZ_EID = 40231;
    uint32 constant BASE_LZ_EID = 40245;

    function setUp() public {
        // Deploy source relay (simulating Arbitrum)
        relaySource = new SoulCrossChainRelay(
            mockProofHub,
            SoulCrossChainRelay.BridgeType.LAYERZERO
        );

        // Deploy destination relay (simulating Base)
        relayDest = new SoulCrossChainRelay(
            mockProofHub,
            SoulCrossChainRelay.BridgeType.LAYERZERO
        );

        // Deploy nullifier sync
        nullifierSync = new CrossChainNullifierSync(mockNullifierRegistry);

        // Configure source → destination chain
        relaySource.configureChain(
            BASE_CHAIN_ID,
            SoulCrossChainRelay.ChainConfig({
                proofHub: mockProofHub,
                bridgeAdapter: mockBridgeAdapter,
                bridgeChainId: BASE_LZ_EID,
                active: true
            })
        );

        // Configure destination → source
        relayDest.configureChain(
            ARBITRUM_CHAIN_ID,
            SoulCrossChainRelay.ChainConfig({
                proofHub: mockProofHub,
                bridgeAdapter: mockBridgeAdapter,
                bridgeChainId: ARBITRUM_LZ_EID,
                active: true
            })
        );

        // Grant BRIDGE_ROLE on dest relay for incoming messages
        relayDest.grantRole(relayDest.BRIDGE_ROLE(), address(this));

        // Configure nullifier sync target
        nullifierSync.configureSyncTarget(
            BASE_CHAIN_ID,
            CrossChainNullifierSync.SyncTarget({
                nullifierRegistry: mockNullifierRegistry,
                relay: address(relaySource),
                chainId: BASE_CHAIN_ID,
                active: true
            })
        );
    }

    // ═══════════════════════════════════════════════
    //  SoulCrossChainRelay Tests
    // ═══════════════════════════════════════════════

    function test_relayDeployed() public view {
        assertTrue(
            address(relaySource) != address(0),
            "Source relay not deployed"
        );
        assertTrue(address(relayDest) != address(0), "Dest relay not deployed");
    }

    function test_chainConfigured() public view {
        assertTrue(
            relaySource.isChainSupported(BASE_CHAIN_ID),
            "Base not supported on source"
        );
        assertTrue(
            relayDest.isChainSupported(ARBITRUM_CHAIN_ID),
            "Arbitrum not supported on dest"
        );
    }

    function test_getSupportedChains() public view {
        uint256[] memory chains = relaySource.getSupportedChains();
        assertEq(chains.length, 1, "Should have 1 supported chain");
        assertEq(chains[0], BASE_CHAIN_ID, "Should be Base");
    }

    function test_relayProof() public {
        bytes32 proofId = keccak256("test_proof_1");
        bytes memory proof = hex"deadbeef";
        bytes memory publicInputs = hex"cafebabe";
        bytes32 commitment = keccak256("commitment_1");
        bytes32 proofType = keccak256("state_transfer");

        // MockBridgeAdapter won't actually process, but relayProof should succeed
        // (the low-level call to bridgeAdapter will fail silently since it's an EOA)
        // Only check indexed topic (proofId), skip non-indexed data matching
        vm.expectEmit(true, false, false, false);
        emit SoulCrossChainRelay.ProofRelayed(
            proofId,
            uint64(block.chainid),
            uint64(BASE_CHAIN_ID),
            commitment,
            bytes32(0) // messageId is unpredictable
        );

        bytes32 messageId = relaySource.relayProof(
            proofId,
            proof,
            publicInputs,
            commitment,
            uint64(BASE_CHAIN_ID),
            proofType
        );

        assertTrue(messageId != bytes32(0), "Message ID should be non-zero");
    }

    function test_relayProofToUnsupportedChainReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulCrossChainRelay.ChainNotSupported.selector,
                999
            )
        );
        relaySource.relayProof(
            keccak256("p"),
            hex"aa",
            hex"bb",
            keccak256("c"),
            uint64(999),
            keccak256("t")
        );
    }

    function test_relayOversizedProofReverts() public {
        bytes memory bigProof = new bytes(33_000); // > MAX_PROOF_SIZE
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulCrossChainRelay.ProofTooLarge.selector,
                33_000
            )
        );
        relaySource.relayProof(
            keccak256("p"),
            bigProof,
            hex"bb",
            keccak256("c"),
            uint64(BASE_CHAIN_ID),
            keccak256("t")
        );
    }

    function test_receiveRelayedProof() public {
        bytes32 proofId = keccak256("incoming_proof");
        bytes memory proof = hex"1234";
        bytes memory publicInputs = hex"5678";
        bytes32 commitment = keccak256("incoming_commitment");
        bytes32 proofType = keccak256("state_transfer");

        // Encode as MSG_PROOF_RELAY
        bytes memory payload = abi.encode(
            uint8(1), // MSG_PROOF_RELAY
            proofId,
            proof,
            publicInputs,
            commitment,
            uint64(ARBITRUM_CHAIN_ID),
            proofType
        );

        // Only check indexed proofId — submitted may be true since
        // proofHub.call to a mock EOA returns success
        vm.expectEmit(true, false, false, false);
        emit SoulCrossChainRelay.ProofReceived(
            proofId,
            uint64(ARBITRUM_CHAIN_ID),
            commitment,
            true
        );

        relayDest.receiveRelayedProof(ARBITRUM_CHAIN_ID, payload);
    }

    function test_duplicateReceiveReverts() public {
        bytes32 proofId = keccak256("dup_proof");
        bytes memory payload = abi.encode(
            uint8(1),
            proofId,
            hex"aa",
            hex"bb",
            keccak256("c"),
            uint64(ARBITRUM_CHAIN_ID),
            keccak256("t")
        );

        // First call succeeds
        relayDest.receiveRelayedProof(ARBITRUM_CHAIN_ID, payload);

        // Second call with same proof should revert
        vm.expectRevert(); // AlreadyProcessed
        relayDest.receiveRelayedProof(ARBITRUM_CHAIN_ID, payload);
    }

    function test_unauthorizedRelayReverts() public {
        address nobody = makeAddr("nobody");
        vm.prank(nobody);
        vm.expectRevert(); // AccessControl error
        relaySource.relayProof(
            keccak256("p"),
            hex"aa",
            hex"bb",
            keccak256("c"),
            uint64(BASE_CHAIN_ID),
            keccak256("t")
        );
    }

    function test_pauseRelay() public {
        relaySource.pause();
        vm.expectRevert(); // Pausable: paused
        relaySource.relayProof(
            keccak256("p"),
            hex"aa",
            hex"bb",
            keccak256("c"),
            uint64(BASE_CHAIN_ID),
            keccak256("t")
        );

        relaySource.unpause();
        // Should work after unpause
        relaySource.relayProof(
            keccak256("p2"),
            hex"aa",
            hex"bb",
            keccak256("c2"),
            uint64(BASE_CHAIN_ID),
            keccak256("t")
        );
    }

    // ═══════════════════════════════════════════════
    //  CrossChainNullifierSync Tests
    // ═══════════════════════════════════════════════

    function test_nullifierSyncDeployed() public view {
        assertTrue(address(nullifierSync) != address(0), "Sync not deployed");
    }

    function test_queueNullifier() public {
        bytes32 nullifier = keccak256("nullifier_1");
        bytes32 commitment = keccak256("commitment_1");

        vm.expectEmit(true, false, false, true);
        emit CrossChainNullifierSync.NullifierQueued(nullifier, commitment);

        nullifierSync.queueNullifier(nullifier, commitment);
        assertEq(nullifierSync.getPendingCount(), 1, "Should have 1 pending");
    }

    function test_queueNullifierBatch() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("nullifier", i));
            commitments[i] = keccak256(abi.encodePacked("commitment", i));
        }

        nullifierSync.queueNullifierBatch(nullifiers, commitments);
        assertEq(nullifierSync.getPendingCount(), 3, "Should have 3 pending");
    }

    function test_batchSizeLimitEnforced() public {
        bytes32[] memory nullifiers = new bytes32[](21); // > MAX_BATCH_SIZE
        bytes32[] memory commitments = new bytes32[](21);

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainNullifierSync.BatchTooLarge.selector,
                21
            )
        );
        nullifierSync.queueNullifierBatch(nullifiers, commitments);
    }

    function test_arrayLengthMismatchReverts() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](2);

        vm.expectRevert(CrossChainNullifierSync.ArrayLengthMismatch.selector);
        nullifierSync.queueNullifierBatch(nullifiers, commitments);
    }

    function test_flushEmptyBatchReverts() public {
        vm.expectRevert(CrossChainNullifierSync.NoPendingNullifiers.selector);
        nullifierSync.flushToChain(BASE_CHAIN_ID);
    }

    function test_flushToUnconfiguredChainReverts() public {
        nullifierSync.queueNullifier(keccak256("n"), keccak256("c"));

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainNullifierSync.TargetNotConfigured.selector,
                999
            )
        );
        nullifierSync.flushToChain(999);
    }

    function test_receiveNullifierBatch() public {
        // Grant BRIDGE_ROLE
        nullifierSync.grantRole(nullifierSync.BRIDGE_ROLE(), address(this));

        bytes32[] memory nullifiers = new bytes32[](2);
        bytes32[] memory commitments = new bytes32[](2);
        nullifiers[0] = keccak256("remote_null_1");
        nullifiers[1] = keccak256("remote_null_2");
        commitments[0] = keccak256("remote_commit_1");
        commitments[1] = keccak256("remote_commit_2");

        vm.expectEmit(true, false, false, true);
        emit CrossChainNullifierSync.NullifierBatchReceived(
            ARBITRUM_CHAIN_ID,
            2,
            keccak256("source_root")
        );

        nullifierSync.receiveNullifierBatch(
            ARBITRUM_CHAIN_ID,
            nullifiers,
            commitments,
            keccak256("source_root")
        );

        assertEq(
            nullifierSync.inboundSyncCount(ARBITRUM_CHAIN_ID),
            2,
            "Should track 2 inbound"
        );
    }

    function test_receiveEmptyBatchReverts() public {
        nullifierSync.grantRole(nullifierSync.BRIDGE_ROLE(), address(this));

        bytes32[] memory empty = new bytes32[](0);

        vm.expectRevert(CrossChainNullifierSync.EmptyBatch.selector);
        nullifierSync.receiveNullifierBatch(
            ARBITRUM_CHAIN_ID,
            empty,
            empty,
            bytes32(0)
        );
    }

    function test_syncTargetConfiguration() public view {
        uint256[] memory targets = nullifierSync.getTargetChains();
        assertEq(targets.length, 1, "Should have 1 target");
        assertEq(targets[0], BASE_CHAIN_ID, "Should be Base");
    }
}
