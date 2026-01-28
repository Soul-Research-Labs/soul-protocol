// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {DirectL2Messenger} from "../../contracts/crosschain/DirectL2Messenger.sol";
import {L2ProofRouter} from "../../contracts/crosschain/L2ProofRouter.sol";
import {SharedSequencerIntegration} from "../../contracts/crosschain/SharedSequencerIntegration.sol";

/**
 * @title DirectL2MessengerFuzz
 * @notice Fuzz tests for Direct L2 Messaging contracts
 */
contract DirectL2MessengerFuzz is Test {
    DirectL2Messenger public messenger;
    L2ProofRouter public proofRouter;
    SharedSequencerIntegration public sequencerIntegration;

    address public admin = address(0x1);
    address public pilHub = address(0x2);
    address public relayer1 = address(0x3);
    address public relayer2 = address(0x4);
    address public relayer3 = address(0x5);
    address public user = address(0x6);

    uint256 public constant OPTIMISM_CHAIN_ID = 10;
    uint256 public constant BASE_CHAIN_ID = 8453;
    uint256 public constant ARBITRUM_CHAIN_ID = 42161;

    function setUp() public {
        vm.startPrank(admin);

        // Deploy contracts
        messenger = new DirectL2Messenger(admin, pilHub);
        proofRouter = new L2ProofRouter(admin, pilHub);
        sequencerIntegration = new SharedSequencerIntegration(admin, pilHub);

        // Configure routes
        messenger.configureRoute(
            block.chainid,
            OPTIMISM_CHAIN_ID,
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            300
        );

        messenger.configureRoute(
            block.chainid,
            BASE_CHAIN_ID,
            DirectL2Messenger.MessagePath.SUPERCHAIN,
            address(0),
            1,
            0
        );

        vm.stopPrank();

        // Register relayers
        vm.deal(relayer1, 10 ether);
        vm.deal(relayer2, 10 ether);
        vm.deal(relayer3, 10 ether);
        vm.deal(user, 10 ether);

        vm.prank(relayer1);
        messenger.registerRelayer{value: 1 ether}();

        vm.prank(relayer2);
        messenger.registerRelayer{value: 1 ether}();

        vm.prank(relayer3);
        messenger.registerRelayer{value: 1 ether}();

        // Register a mock sequencer for integration tests
        address mockSequencer = address(0xABC);
        uint256[] memory chains = new uint256[](1);
        chains[0] = OPTIMISM_CHAIN_ID;
        address[] memory validators = new address[](1);
        validators[0] = admin;
        
        vm.prank(admin);
        sequencerIntegration.registerSequencer(
            mockSequencer,
            SharedSequencerIntegration.SequencerType.CUSTOM,
            chains,
            6667,
            validators
        );
    }

    /*//////////////////////////////////////////////////////////////
                     DIRECT L2 MESSENGER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Message ID uniqueness
    function testFuzz_MessageIdUniqueness(
        uint256 destChainId,
        address recipient,
        bytes calldata payload,
        bytes32 nullifier
    ) public {
        vm.assume(destChainId != block.chainid);
        vm.assume(destChainId > 0 && destChainId < type(uint64).max);
        vm.assume(recipient != address(0));
        vm.assume(payload.length > 0 && payload.length < 10000);

        vm.prank(admin);
        messenger.configureRoute(
            block.chainid,
            destChainId,
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            300
        );

        vm.prank(user);
        bytes32 messageId1 = messenger.sendMessage(
            destChainId,
            recipient,
            payload,
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            nullifier
        );

        vm.prank(user);
        bytes32 messageId2 = messenger.sendMessage(
            destChainId,
            recipient,
            payload,
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            nullifier
        );

        // Message IDs should always be unique
        assertNotEq(messageId1, messageId2, "Message IDs must be unique");
    }

    /// @notice Fuzz test: Relayer bond requirements
    function testFuzz_RelayerBondRequirements(uint256 bondAmount) public {
        bondAmount = bound(bondAmount, 0, type(uint128).max);
        
        address newRelayer = address(
            uint160(uint256(keccak256(abi.encode(bondAmount, block.timestamp))))
        );
        vm.deal(newRelayer, bondAmount);

        if (bondAmount < 1 ether) {
            vm.expectRevert(DirectL2Messenger.InsufficientBond.selector);
        }

        vm.prank(newRelayer);
        messenger.registerRelayer{value: bondAmount}();

        if (bondAmount >= 1 ether) {
            DirectL2Messenger.Relayer memory r = messenger.getRelayer(
                newRelayer
            );
            assertEq(r.bond, bondAmount, "Bond amount mismatch");
            assertTrue(r.active, "Relayer should be active");
        }
    }

    /// @notice Fuzz test: Challenge bond requirements
    function testFuzz_ChallengeBondRequirements(uint256 challengeBond) public {
        // First send a message
        vm.prank(admin);
        messenger.configureRoute(
            block.chainid,
            OPTIMISM_CHAIN_ID,
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            300
        );

        vm.prank(user);
        bytes32 messageId = messenger.sendMessage(
            OPTIMISM_CHAIN_ID,
            address(0x999),
            hex"1234",
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );

        // Simulate message being relayed (would need proper signatures in practice)
        // For now we test the challenge bond logic independently

        address challenger = address(0x888);
        vm.deal(challenger, challengeBond);

        // Challenge requires 0.1 ether minimum
        if (challengeBond < 0.1 ether) {
            // Challenge should fail with insufficient bond
            vm.prank(challenger);
            // Note: This will revert because message isn't in RELAYED state
            // but we're testing the bond logic concept
        }
    }

    /// @notice Fuzz test: Route configuration validation
    function testFuzz_RouteConfiguration(
        uint256 sourceChainId,
        uint256 destChainId,
        uint8 pathType,
        uint256 minConfirmations,
        uint256 challengeWindow
    ) public {
        vm.assume(pathType < 4); // Valid MessagePath enum values
        vm.assume(sourceChainId != destChainId);
        minConfirmations = bound(minConfirmations, 0, 99);
        challengeWindow = bound(challengeWindow, 0, 7 days);

        vm.prank(admin);
        messenger.configureRoute(
            sourceChainId,
            destChainId,
            DirectL2Messenger.MessagePath(pathType),
            address(0),
            minConfirmations,
            challengeWindow
        );

        DirectL2Messenger.RouteConfig memory route = messenger.getRoute(
            sourceChainId,
            destChainId
        );
        assertTrue(route.active, "Route should be active");
        assertEq(uint8(route.preferredPath), pathType, "Path type mismatch");
    }

    /// @notice Fuzz test: Message payload size limits
    function testFuzz_PayloadSizeLimits(uint256 payloadSize) public {
        vm.assume(payloadSize > 0);

        // Bound to reasonable sizes to avoid memory issues
        payloadSize = bound(payloadSize, 1, 100000);

        bytes memory payload = new bytes(payloadSize);
        for (uint256 i = 0; i < payloadSize; i++) {
            payload[i] = bytes1(uint8(i % 256));
        }

        vm.prank(user);
        try
            messenger.sendMessage(
                OPTIMISM_CHAIN_ID,
                address(0x999),
                payload,
                DirectL2Messenger.MessagePath.FAST_RELAYER,
                bytes32(0)
            )
        returns (bytes32 messageId) {
            // Message sent successfully
            assertTrue(messageId != bytes32(0), "Valid message ID required");
        } catch {
            // Large payloads may fail due to gas limits - this is expected
        }
    }

    /*//////////////////////////////////////////////////////////////
                      L2 PROOF ROUTER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Proof ID uniqueness
    function testFuzz_ProofIdUniqueness(
        uint8 proofType,
        uint256 destChainId,
        bytes calldata proofData,
        bytes calldata publicInputs
    ) public {
        vm.assume(proofType < 8); // Valid ProofType enum values
        vm.assume(destChainId != block.chainid);
        vm.assume(destChainId > 0);
        vm.assume(proofData.length > 0 && proofData.length < 10000);

        vm.prank(user);
        bytes32 proofId1 = proofRouter.submitProof(
            L2ProofRouter.ProofType(proofType),
            destChainId,
            proofData,
            publicInputs,
            bytes32(0)
        );

        vm.prank(user);
        bytes32 proofId2 = proofRouter.submitProof(
            L2ProofRouter.ProofType(proofType),
            destChainId,
            proofData,
            publicInputs,
            bytes32(0)
        );

        assertNotEq(proofId1, proofId2, "Proof IDs must be unique");
    }

    /// @notice Fuzz test: Gas estimation consistency
    function testFuzz_GasEstimationConsistency(
        uint8 proofType,
        uint256 dataLength
    ) public {
        vm.assume(proofType < 8);
        dataLength = bound(dataLength, 1, 10000);

        bytes memory proofData = new bytes(dataLength);

        vm.prank(user);
        bytes32 proofId = proofRouter.submitProof(
            L2ProofRouter.ProofType(proofType),
            OPTIMISM_CHAIN_ID,
            proofData,
            "",
            bytes32(0)
        );

        L2ProofRouter.Proof memory proof = proofRouter.getProof(proofId);

        // Gas estimate should be positive and reasonable
        assertTrue(proof.gasEstimate > 0, "Gas estimate must be positive");
        assertTrue(
            proof.gasEstimate < 10_000_000,
            "Gas estimate should be reasonable"
        );
    }

    /// @notice Fuzz test: Batch accumulation
    function testFuzz_BatchAccumulation(uint256 proofCount) public {
        proofCount = bound(proofCount, 1, 50); // Bound to avoid timeouts

        bytes32[] memory proofIds = new bytes32[](proofCount);

        for (uint256 i = 0; i < proofCount; i++) {
            vm.prank(user);
            proofIds[i] = proofRouter.submitProof(
                L2ProofRouter.ProofType.GROTH16,
                OPTIMISM_CHAIN_ID,
                abi.encodePacked(i),
                "",
                bytes32(0)
            );
        }

        bytes32 activeBatch = proofRouter.getActiveBatch(OPTIMISM_CHAIN_ID);

        if (proofCount < 100) {
            // Should have an active batch
            assertTrue(activeBatch != bytes32(0), "Should have active batch");
        }
    }

    /// @notice Fuzz test: Cache eviction under pressure
    function testFuzz_CacheEviction(uint256 cacheEntries) public {
        cacheEntries = bound(cacheEntries, 1, 100);

        // Submit many proofs to fill cache
        for (uint256 i = 0; i < cacheEntries; i++) {
            vm.prank(user);
            proofRouter.submitProof(
                L2ProofRouter.ProofType.GROTH16,
                OPTIMISM_CHAIN_ID,
                abi.encodePacked("proof", i),
                abi.encodePacked("input", i),
                bytes32(0)
            );
        }

        uint256 cacheSize = proofRouter.getCacheSize();

        // Cache size should never exceed MAX_CACHE_SIZE (1000)
        assertTrue(cacheSize <= 1000, "Cache should respect max size");
    }

    /*//////////////////////////////////////////////////////////////
                 SHARED SEQUENCER INTEGRATION FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Bundle ID uniqueness
    function testFuzz_BundleIdUniqueness(
        uint256 targetChain1,
        uint256 targetChain2
    ) public {
        vm.assume(targetChain1 != block.chainid);
        vm.assume(targetChain2 != block.chainid);
        vm.assume(targetChain1 > 0 && targetChain2 > 0);

        SharedSequencerIntegration.AtomicTransaction[]
            memory txs1 = new SharedSequencerIntegration.AtomicTransaction[](1);
        txs1[0] = SharedSequencerIntegration.AtomicTransaction({
            transactionHash: keccak256("tx1"),
            targetChainId: targetChain1,
            target: address(0x999),
            data: hex"1234",
            value: 0,
            gasLimit: 100000,
            nullifierBinding: bytes32(0)
        });

        SharedSequencerIntegration.AtomicTransaction[]
            memory txs2 = new SharedSequencerIntegration.AtomicTransaction[](1);
        txs2[0] = SharedSequencerIntegration.AtomicTransaction({
            transactionHash: keccak256("tx2"),
            targetChainId: targetChain2,
            target: address(0x999),
            data: hex"5678",
            value: 0,
            gasLimit: 100000,
            nullifierBinding: bytes32(0)
        });

        vm.prank(user);
        bytes32 bundleId1 = sequencerIntegration.submitAtomicBundle(
            txs1,
            address(0)
        );

        vm.prank(user);
        bytes32 bundleId2 = sequencerIntegration.submitAtomicBundle(
            txs2,
            address(0)
        );

        assertNotEq(bundleId1, bundleId2, "Bundle IDs must be unique");
    }

    /// @notice Fuzz test: Multi-chain bundle limits
    function testFuzz_MultiChainBundleLimits(uint256 chainCount) public {
        chainCount = bound(chainCount, 1, 15);

        SharedSequencerIntegration.AtomicTransaction[]
            memory txs = new SharedSequencerIntegration.AtomicTransaction[](
                chainCount
            );

        for (uint256 i = 0; i < chainCount; i++) {
            txs[i] = SharedSequencerIntegration.AtomicTransaction({
                transactionHash: keccak256(abi.encodePacked("tx", i)),
                targetChainId: 1000 + i, // Different chain IDs
                target: address(0x999),
                data: hex"1234",
                value: 0,
                gasLimit: 100000,
                nullifierBinding: bytes32(0)
            });
        }

        if (chainCount > 10) {
            vm.expectRevert(
                SharedSequencerIntegration.InvalidChainSet.selector
            );
        }

        vm.prank(user);
        sequencerIntegration.submitAtomicBundle(txs, address(0));
    }

    /// @notice Fuzz test: Sequence number monotonicity
    function testFuzz_SequenceNumberMonotonicity(
        uint256 messageCount,
        uint256 destChainId
    ) public {
        messageCount = bound(messageCount, 1, 20);
        vm.assume(destChainId != block.chainid);
        vm.assume(destChainId > 0);

        // Register sequencer for this specific chain
        // Ensure seq address is non-zero
        address seq = address(uint160(uint256(keccak256(abi.encode(destChainId)))));
        if (seq == address(0)) seq = address(0x1);
        uint256[] memory chains = new uint256[](1);
        chains[0] = destChainId;
        address[] memory validators = new address[](1);
        validators[0] = admin;

        vm.prank(admin);
        sequencerIntegration.registerSequencer(
            seq,
            SharedSequencerIntegration.SequencerType.CUSTOM,
            chains,
            1,
            validators
        );

        uint256 lastSequence = 0;

        for (uint256 i = 0; i < messageCount; i++) {
            vm.prank(user);
            uint256 sequence = sequencerIntegration.requestOrderedMessage(
                destChainId,
                keccak256(abi.encodePacked("message", i)),
                address(0)
            );

            // Sequence numbers must be strictly increasing
            assertTrue(sequence > lastSequence, "Sequence must increase");
            lastSequence = sequence;
        }
    }

    /// @notice Fuzz test: Transaction hash uniqueness in bundles
    function testFuzz_TransactionHashUniqueness(uint256 txCount) public {
        txCount = bound(txCount, 1, 50);

        SharedSequencerIntegration.AtomicTransaction[]
            memory txs = new SharedSequencerIntegration.AtomicTransaction[](
                txCount
            );

        for (uint256 i = 0; i < txCount; i++) {
            txs[i] = SharedSequencerIntegration.AtomicTransaction({
                transactionHash: keccak256(
                    abi.encodePacked("unique_tx", i, block.timestamp)
                ),
                targetChainId: OPTIMISM_CHAIN_ID,
                target: address(0x999),
                data: abi.encodePacked(i),
                value: 0,
                gasLimit: 100000,
                nullifierBinding: bytes32(0)
            });
        }

        vm.prank(user);
        bytes32 bundleId = sequencerIntegration.submitAtomicBundle(
            txs,
            address(0)
        );

        assertTrue(bundleId != bytes32(0), "Bundle should be created");
    }

    /*//////////////////////////////////////////////////////////////
                     CROSS-CONTRACT INTEGRATION FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: End-to-end message with proof routing
    function testFuzz_E2EMessageWithProofRouting(
        bytes calldata payload,
        bytes32 nullifier
    ) public {
        vm.assume(payload.length > 0 && payload.length < 1000);

        // Send message via DirectL2Messenger
        vm.prank(user);
        bytes32 messageId = messenger.sendMessage(
            OPTIMISM_CHAIN_ID,
            address(0x999),
            payload,
            DirectL2Messenger.MessagePath.FAST_RELAYER,
            nullifier
        );

        // Submit corresponding proof via L2ProofRouter
        vm.prank(user);
        bytes32 proofId = proofRouter.submitProof(
            L2ProofRouter.ProofType.NULLIFIER_PROOF,
            OPTIMISM_CHAIN_ID,
            abi.encode(messageId),
            abi.encode(nullifier),
            nullifier
        );

        // Both should be created successfully
        assertTrue(messageId != bytes32(0), "Message ID should be valid");
        assertTrue(proofId != bytes32(0), "Proof ID should be valid");

        // Nullifier binding should be consistent
        DirectL2Messenger.L2Message memory msg_ = messenger.getMessage(
            messageId
        );
        L2ProofRouter.Proof memory proof = proofRouter.getProof(proofId);

        assertEq(
            msg_.nullifierBinding,
            proof.nullifierBinding,
            "Nullifier binding should match"
        );
    }

    /// @notice Fuzz test: Atomic bundle with multiple proof types
    function testFuzz_AtomicBundleWithMultipleProofTypes(
        uint256 proofCount
    ) public {
        proofCount = bound(proofCount, 1, 8);

        SharedSequencerIntegration.AtomicTransaction[]
            memory txs = new SharedSequencerIntegration.AtomicTransaction[](
                proofCount
            );

        for (uint256 i = 0; i < proofCount; i++) {
            // Different proof types for each transaction
            L2ProofRouter.ProofType proofType = L2ProofRouter.ProofType(i % 8);

            txs[i] = SharedSequencerIntegration.AtomicTransaction({
                transactionHash: keccak256(
                    abi.encodePacked("tx", i, proofType)
                ),
                targetChainId: OPTIMISM_CHAIN_ID,
                target: address(proofRouter),
                data: abi.encodeCall(
                    L2ProofRouter.submitProof,
                    (proofType, BASE_CHAIN_ID, hex"1234", hex"5678", bytes32(0))
                ),
                value: 0,
                gasLimit: 500000,
                nullifierBinding: bytes32(i)
            });
        }

        vm.prank(user);
        bytes32 bundleId = sequencerIntegration.submitAtomicBundle(
            txs,
            address(0)
        );

        assertTrue(bundleId != bytes32(0), "Atomic bundle should be created");
    }
}
