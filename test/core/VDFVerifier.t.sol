// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {VDFVerifier} from "../../contracts/core/VDFVerifier.sol";

/**
 * @title VDFVerifierTest
 * @notice Foundry tests for VDF verification and randomness beacon
 */
contract VDFVerifierTest is Test {
    VDFVerifier public vdf;
    
    address owner = address(this);
    address relayer1 = address(0x1);
    address relayer2 = address(0x2);
    address relayer3 = address(0x3);
    
    // Test RSA modulus (small for testing)
    uint256 constant TEST_MODULUS = 3233; // 61 * 53
    
    // Production-like modulus
    uint256 constant LARGE_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function setUp() public {
        vdf = new VDFVerifier(TEST_MODULUS);
        
        // Fund relayers
        vm.deal(relayer1, 10 ether);
        vm.deal(relayer2, 10 ether);
        vm.deal(relayer3, 10 ether);
    }

    // ============================================================================
    // ADMIN TESTS
    // ============================================================================
    
    function test_Constructor() public view {
        assertEq(vdf.owner(), owner);
        assertEq(vdf.rsaModulus(), TEST_MODULUS);
    }
    
    function test_SetRSAModulus() public {
        uint256 newModulus = 9999;
        vdf.setRSAModulus(newModulus);
        assertEq(vdf.rsaModulus(), newModulus);
    }
    
    function test_SetRSAModulus_OnlyOwner() public {
        vm.prank(relayer1);
        vm.expectRevert();
        vdf.setRSAModulus(9999);
    }
    
    function test_PauseUnpause() public {
        assertFalse(vdf.paused());
        
        vdf.pause();
        assertTrue(vdf.paused());
        
        vdf.unpause();
        assertFalse(vdf.paused());
    }

    // ============================================================================
    // INPUT HASH TESTS
    // ============================================================================
    
    function test_ComputeInputHash() public view {
        VDFVerifier.VDFInput memory input = VDFVerifier.VDFInput({
            seed: bytes32(uint256(12345)),
            iterations: 1000000,
            modulus: TEST_MODULUS
        });
        
        bytes32 hash = vdf.computeInputHash(input);
        assertNotEq(hash, bytes32(0));
        
        // Same input should produce same hash
        bytes32 hash2 = vdf.computeInputHash(input);
        assertEq(hash, hash2);
    }
    
    function test_ComputeInputHash_DifferentInputs() public view {
        VDFVerifier.VDFInput memory input1 = VDFVerifier.VDFInput({
            seed: bytes32(uint256(12345)),
            iterations: 1000000,
            modulus: TEST_MODULUS
        });
        
        VDFVerifier.VDFInput memory input2 = VDFVerifier.VDFInput({
            seed: bytes32(uint256(12346)), // Different seed
            iterations: 1000000,
            modulus: TEST_MODULUS
        });
        
        bytes32 hash1 = vdf.computeInputHash(input1);
        bytes32 hash2 = vdf.computeInputHash(input2);
        
        assertNotEq(hash1, hash2);
    }

    // ============================================================================
    // RELAYER TESTS
    // ============================================================================
    
    function test_RegisterRelayer() public {
        vm.prank(relayer1);
        vdf.registerRelayer{value: 2 ether}();
        
        assertEq(vdf.relayerStakes(relayer1), 2 ether);
        assertEq(vdf.totalRelayerStake(), 2 ether);
        assertEq(vdf.getRelayerCount(), 1);
    }
    
    function test_RegisterRelayer_MultipleRelayers() public {
        vm.prank(relayer1);
        vdf.registerRelayer{value: 2 ether}();
        
        vm.prank(relayer2);
        vdf.registerRelayer{value: 3 ether}();
        
        vm.prank(relayer3);
        vdf.registerRelayer{value: 5 ether}();
        
        assertEq(vdf.getRelayerCount(), 3);
        assertEq(vdf.totalRelayerStake(), 10 ether);
    }
    
    function test_RegisterRelayer_IncrementalStake() public {
        vm.startPrank(relayer1);
        vdf.registerRelayer{value: 1 ether}();
        assertEq(vdf.relayerStakes(relayer1), 1 ether);
        
        vdf.registerRelayer{value: 2 ether}();
        assertEq(vdf.relayerStakes(relayer1), 3 ether);
        vm.stopPrank();
        
        // Should still only have one relayer
        assertEq(vdf.getRelayerCount(), 1);
    }
    
    function test_RegisterRelayer_RevertIfInsufficientStake() public {
        vm.prank(relayer1);
        vm.expectRevert(VDFVerifier.InsufficientStake.selector);
        vdf.registerRelayer{value: 0.5 ether}();
    }
    
    function test_UnregisterRelayer() public {
        vm.prank(relayer1);
        vdf.registerRelayer{value: 2 ether}();
        
        uint256 balanceBefore = relayer1.balance;
        
        vm.prank(relayer1);
        vdf.unregisterRelayer();
        
        assertEq(vdf.relayerStakes(relayer1), 0);
        assertEq(vdf.totalRelayerStake(), 0);
        assertEq(vdf.getRelayerCount(), 0);
        assertEq(relayer1.balance, balanceBefore + 2 ether);
    }
    
    function test_UnregisterRelayer_RevertIfNotRegistered() public {
        vm.prank(relayer1);
        vm.expectRevert(VDFVerifier.RelayerNotRegistered.selector);
        vdf.unregisterRelayer();
    }
    
    function test_GetRelayers() public {
        vm.prank(relayer1);
        vdf.registerRelayer{value: 1 ether}();
        
        vm.prank(relayer2);
        vdf.registerRelayer{value: 2 ether}();
        
        address[] memory relayers = vdf.getRelayers();
        assertEq(relayers.length, 2);
        assertEq(relayers[0], relayer1);
        assertEq(relayers[1], relayer2);
    }

    // ============================================================================
    // BEACON TESTS
    // ============================================================================
    
    function test_PublishBeacon() public {
        uint64 blockNum = 12345;
        bytes32 blockHash = bytes32(uint256(0xabcdef));
        uint256 vdfOutput = 123456789;
        bytes32 proofCommitment = bytes32(uint256(0x123));
        
        vdf.publishBeacon(blockNum, blockHash, vdfOutput, proofCommitment);
        
        VDFVerifier.RandomnessBeacon memory beacon = vdf.getBeacon(
            uint64(block.chainid),
            blockNum
        );
        
        assertEq(beacon.chainId, uint64(block.chainid));
        assertEq(beacon.blockNumber, blockNum);
        assertEq(beacon.blockHash, blockHash);
        assertEq(beacon.vdfOutput, vdfOutput);
        assertNotEq(beacon.commitment, bytes32(0));
    }
    
    function test_GetBeaconRandomness() public {
        uint64 blockNum = 12345;
        bytes32 blockHash = bytes32(uint256(0xabcdef));
        uint256 vdfOutput = 123456789;
        
        vdf.publishBeacon(blockNum, blockHash, vdfOutput, bytes32(0));
        
        uint256 random1 = vdf.getBeaconRandomness(
            uint64(block.chainid),
            blockNum,
            bytes32(uint256(1)), // purpose
            0 // index
        );
        
        uint256 random2 = vdf.getBeaconRandomness(
            uint64(block.chainid),
            blockNum,
            bytes32(uint256(1)),
            1 // different index
        );
        
        // Different indices should produce different randomness
        assertNotEq(random1, random2);
    }
    
    function test_GetBeaconRandomness_DifferentPurpose() public {
        uint64 blockNum = 12345;
        bytes32 blockHash = bytes32(uint256(0xabcdef));
        uint256 vdfOutput = 123456789;
        
        vdf.publishBeacon(blockNum, blockHash, vdfOutput, bytes32(0));
        
        uint256 random1 = vdf.getBeaconRandomness(
            uint64(block.chainid),
            blockNum,
            bytes32(uint256(1)), // purpose 1
            0
        );
        
        uint256 random2 = vdf.getBeaconRandomness(
            uint64(block.chainid),
            blockNum,
            bytes32(uint256(2)), // purpose 2
            0
        );
        
        // Different purposes should produce different randomness
        assertNotEq(random1, random2);
    }
    
    function test_GetBeaconRandomness_RevertIfExpired() public {
        uint64 blockNum = 12345;
        bytes32 blockHash = bytes32(uint256(0xabcdef));
        uint256 vdfOutput = 123456789;
        
        vdf.publishBeacon(blockNum, blockHash, vdfOutput, bytes32(0));
        
        // Warp past validity period
        vm.warp(block.timestamp + 3601);
        
        vm.expectRevert(VDFVerifier.BeaconExpired.selector);
        vdf.getBeaconRandomness(
            uint64(block.chainid),
            blockNum,
            bytes32(uint256(1)),
            0
        );
    }
    
    function test_GetBeaconRandomness_RevertIfNotPublished() public {
        vm.expectRevert(VDFVerifier.InvalidProof.selector);
        vdf.getBeaconRandomness(
            uint64(block.chainid),
            99999, // Non-existent block
            bytes32(uint256(1)),
            0
        );
    }

    // ============================================================================
    // RELAYER SELECTION TESTS
    // ============================================================================
    
    function test_SelectRelayer() public {
        // Register relayers with different stakes
        vm.prank(relayer1);
        vdf.registerRelayer{value: 1 ether}();
        
        vm.prank(relayer2);
        vdf.registerRelayer{value: 4 ether}();
        
        vm.prank(relayer3);
        vdf.registerRelayer{value: 5 ether}();
        
        // Publish beacon to enable selection
        vdf.publishBeacon(12345, bytes32(uint256(0xabcd)), 123456, bytes32(0));
        
        VDFVerifier.RelayerSelection memory selection = vdf.selectRelayer(0);
        
        // Selection should be one of the registered relayers
        assertTrue(
            selection.relayer == relayer1 ||
            selection.relayer == relayer2 ||
            selection.relayer == relayer3
        );
        assertTrue(selection.stake > 0);
        assertEq(selection.round, 0);
    }
    
    function test_SelectRelayer_DifferentRounds() public {
        vm.prank(relayer1);
        vdf.registerRelayer{value: 5 ether}();
        
        vm.prank(relayer2);
        vdf.registerRelayer{value: 5 ether}();
        
        vdf.publishBeacon(12345, bytes32(uint256(0xabcd)), 123456, bytes32(0));
        
        // Try multiple rounds - selection should vary
        VDFVerifier.RelayerSelection memory sel0 = vdf.selectRelayer(0);
        VDFVerifier.RelayerSelection memory sel1 = vdf.selectRelayer(1);
        VDFVerifier.RelayerSelection memory sel2 = vdf.selectRelayer(2);
        
        // All should have valid relayers (might be same due to randomness)
        assertTrue(sel0.relayer == relayer1 || sel0.relayer == relayer2);
        assertTrue(sel1.relayer == relayer1 || sel1.relayer == relayer2);
        assertTrue(sel2.relayer == relayer1 || sel2.relayer == relayer2);
    }
    
    function test_SelectRelayer_RevertIfNoRelayers() public {
        vdf.publishBeacon(12345, bytes32(uint256(0xabcd)), 123456, bytes32(0));
        
        vm.expectRevert(VDFVerifier.RelayerNotRegistered.selector);
        vdf.selectRelayer(0);
    }
    
    function test_SelectRelayer_RevertIfNoBeacon() public {
        vm.prank(relayer1);
        vdf.registerRelayer{value: 1 ether}();
        
        vm.expectRevert(VDFVerifier.InvalidProof.selector);
        vdf.selectRelayer(0);
    }

    // ============================================================================
    // CROSS-CHAIN SYNC TESTS
    // ============================================================================
    
    function test_VerifyCrossChainSync() public {
        // Publish local beacon first
        vdf.publishBeacon(12345, bytes32(uint256(0xabcd)), 123456, bytes32(0));
        
        bytes32 syncId = bytes32(uint256(1));
        bytes32 remoteCommitment = bytes32(uint256(0x1234));
        uint64 remoteChainId = 10; // Optimism
        
        // Create Merkle proof (single element = root)
        bytes32[] memory merkleProof = new bytes32[](0);
        bytes32 merkleRoot = remoteCommitment; // Single leaf = root
        
        vdf.verifyCrossChainSync(
            syncId,
            remoteCommitment,
            remoteChainId,
            merkleProof,
            merkleRoot
        );
        
        // Verify by checking the verified state
        (
            bytes32 localCommit,
            bytes32 remoteCommit,
            uint64 chainId,
            bytes32 root,
            bool verified
        ) = vdf.crossChainSyncs(syncId);
        
        assertTrue(verified);
        assertEq(chainId, remoteChainId);
        assertEq(remoteCommit, remoteCommitment);
    }
    
    function test_VerifyCrossChainSync_RevertIfAlreadyVerified() public {
        vdf.publishBeacon(12345, bytes32(uint256(0xabcd)), 123456, bytes32(0));
        
        bytes32 syncId = bytes32(uint256(1));
        bytes32 remoteCommitment = bytes32(uint256(0x1234));
        bytes32[] memory merkleProof = new bytes32[](0);
        
        vdf.verifyCrossChainSync(
            syncId,
            remoteCommitment,
            10,
            merkleProof,
            remoteCommitment
        );
        
        vm.expectRevert(VDFVerifier.SyncAlreadyVerified.selector);
        vdf.verifyCrossChainSync(
            syncId,
            remoteCommitment,
            10,
            merkleProof,
            remoteCommitment
        );
    }
    
    function test_VerifyCrossChainSync_RevertIfInvalidProof() public {
        vdf.publishBeacon(12345, bytes32(uint256(0xabcd)), 123456, bytes32(0));
        
        bytes32 syncId = bytes32(uint256(1));
        bytes32 remoteCommitment = bytes32(uint256(0x1234));
        bytes32[] memory merkleProof = new bytes32[](0);
        bytes32 wrongRoot = bytes32(uint256(0x9999)); // Wrong root
        
        vm.expectRevert(VDFVerifier.InvalidMerkleProof.selector);
        vdf.verifyCrossChainSync(
            syncId,
            remoteCommitment,
            10,
            merkleProof,
            wrongRoot
        );
    }

    // ============================================================================
    // FUZZ TESTS
    // ============================================================================
    
    function testFuzz_ComputeInputHash(
        bytes32 seed,
        uint256 iterations,
        uint256 modulus
    ) public view {
        VDFVerifier.VDFInput memory input = VDFVerifier.VDFInput({
            seed: seed,
            iterations: iterations,
            modulus: modulus
        });
        
        bytes32 hash = vdf.computeInputHash(input);
        
        // Hash should be deterministic
        bytes32 hash2 = vdf.computeInputHash(input);
        assertEq(hash, hash2);
    }
    
    function testFuzz_RelayerStake(uint256 stake) public {
        stake = bound(stake, 1 ether, 100 ether);
        
        vm.deal(relayer1, stake);
        vm.prank(relayer1);
        vdf.registerRelayer{value: stake}();
        
        assertEq(vdf.relayerStakes(relayer1), stake);
        assertEq(vdf.totalRelayerStake(), stake);
    }

    // ============================================================================
    // INTEGRATION TESTS
    // ============================================================================
    
    function test_FullRelayerSelectionFlow() public {
        // 1. Register multiple relayers
        vm.prank(relayer1);
        vdf.registerRelayer{value: 2 ether}();
        
        vm.prank(relayer2);
        vdf.registerRelayer{value: 3 ether}();
        
        vm.prank(relayer3);
        vdf.registerRelayer{value: 5 ether}();
        
        // 2. Publish beacon
        vdf.publishBeacon(
            uint64(block.number),
            blockhash(block.number - 1),
            12345678,
            bytes32(0)
        );
        
        // 3. Select relayers for multiple rounds
        uint256[3] memory selections;
        for (uint256 i = 0; i < 100; i++) {
            VDFVerifier.RelayerSelection memory sel = vdf.selectRelayer(i);
            
            if (sel.relayer == relayer1) selections[0]++;
            else if (sel.relayer == relayer2) selections[1]++;
            else if (sel.relayer == relayer3) selections[2]++;
        }
        
        // All relayers should be selected at least once (probabilistic)
        // Higher staked relayers should be selected more often
        console2.log("Relayer1 (2 ETH):", selections[0]);
        console2.log("Relayer2 (3 ETH):", selections[1]);
        console2.log("Relayer3 (5 ETH):", selections[2]);
    }
    
    function test_BeaconConsistencyAcrossBlocks() public {
        // Publish beacons for consecutive blocks
        for (uint64 i = 1; i <= 5; i++) {
            vdf.publishBeacon(
                i,
                bytes32(uint256(i * 1000)),
                i * 123456,
                bytes32(0)
            );
        }
        
        // Each beacon should have unique commitment
        VDFVerifier.RandomnessBeacon memory b1 = vdf.getBeacon(uint64(block.chainid), 1);
        VDFVerifier.RandomnessBeacon memory b2 = vdf.getBeacon(uint64(block.chainid), 2);
        VDFVerifier.RandomnessBeacon memory b3 = vdf.getBeacon(uint64(block.chainid), 3);
        
        assertNotEq(b1.commitment, b2.commitment);
        assertNotEq(b2.commitment, b3.commitment);
        assertNotEq(b1.commitment, b3.commitment);
    }
}
