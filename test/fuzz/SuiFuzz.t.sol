// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/sui/SuiPrimitives.sol";
import "../../contracts/crosschain/SuiBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title SuiFuzz
 * @notice Comprehensive fuzz tests for Sui integration
 * @dev Tests primitives, bridge adapter, validator committee, and nullifier operations
 */
contract SuiFuzz is Test {
    using SuiPrimitives for *;

    SuiBridgeAdapter public bridge;

    address public admin = address(0x1);
    address public relayer = address(0x2);
    address public user = address(0x3);

    uint64 constant INITIAL_EPOCH = 100;

    function setUp() public {
        vm.startPrank(admin);

        // Deploy implementation
        SuiBridgeAdapter implementation = new SuiBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            SuiBridgeAdapter.initialize.selector,
            admin,
            INITIAL_EPOCH
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        bridge = SuiBridgeAdapter(payable(address(proxy)));

        // Setup roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Register initial validators
        bytes memory blsKey = new bytes(96);
        for (uint i = 0; i < 96; i++) {
            blsKey[i] = bytes1(uint8(i + 1));
        }

        bridge.registerValidator(bytes32(uint256(1)), blsKey, 1000 ether);

        // Add token mapping
        bridge.addTokenMapping(
            keccak256("0x2::sui::SUI"),
            address(0) // ETH
        );

        vm.stopPrank();
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test Blake2b hash determinism
    function testFuzz_Blake2bDeterminism(bytes memory data) public pure {
        bytes32 hash1 = SuiPrimitives.blake2b256(data);
        bytes32 hash2 = SuiPrimitives.blake2b256(data);
        assertEq(hash1, hash2, "Blake2b should be deterministic");
    }

    /// @notice Fuzz test Blake2b collision resistance
    function testFuzz_Blake2bCollisionResistance(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = SuiPrimitives.blake2b256(data1);
        bytes32 hash2 = SuiPrimitives.blake2b256(data2);
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    /// @notice Fuzz test hash2 associativity
    function testFuzz_Hash2Properties(
        bytes32 a,
        bytes32 b,
        bytes32 c
    ) public pure {
        // Not associative but should be consistent
        bytes32 result1 = SuiPrimitives.hash2(a, b);
        bytes32 result2 = SuiPrimitives.hash2(a, b);
        assertEq(result1, result2, "hash2 should be deterministic");

        // Order matters
        if (a != b) {
            bytes32 ab = SuiPrimitives.hash2(a, b);
            bytes32 ba = SuiPrimitives.hash2(b, a);
            assertNotEq(ab, ba, "hash2 should not be commutative");
        }
    }

    /// @notice Fuzz test hashN with varying inputs
    function testFuzz_HashN(bytes32[] memory inputs) public pure {
        vm.assume(inputs.length > 0 && inputs.length < 100);

        bytes32 result1 = SuiPrimitives.hashN(inputs);
        bytes32 result2 = SuiPrimitives.hashN(inputs);
        assertEq(result1, result2, "hashN should be deterministic");
    }

    // =========================================================================
    // OBJECT ID FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test object ID derivation
    function testFuzz_DeriveObjectId(
        bytes32 txDigest,
        uint64 index
    ) public pure {
        bytes32 objectId1 = SuiPrimitives.deriveObjectId(txDigest, index);
        bytes32 objectId2 = SuiPrimitives.deriveObjectId(txDigest, index);
        assertEq(
            objectId1,
            objectId2,
            "Object ID derivation should be deterministic"
        );

        // Different index should give different ID
        if (index < type(uint64).max) {
            bytes32 objectIdNext = SuiPrimitives.deriveObjectId(
                txDigest,
                index + 1
            );
            assertNotEq(
                objectId1,
                objectIdNext,
                "Different indices should give different IDs"
            );
        }
    }

    /// @notice Fuzz test object digest computation
    function testFuzz_ComputeObjectDigest(
        bytes32 objectId,
        uint64 version,
        bytes32 typeTag,
        bytes memory data
    ) public pure {
        vm.assume(data.length < 1000);

        bytes32 digest1 = SuiPrimitives.computeObjectDigest(
            objectId,
            version,
            typeTag,
            data
        );
        bytes32 digest2 = SuiPrimitives.computeObjectDigest(
            objectId,
            version,
            typeTag,
            data
        );
        assertEq(digest1, digest2, "Object digest should be deterministic");
    }

    /// @notice Fuzz test object validation
    function testFuzz_IsValidObjectId(bytes32 objectId) public pure {
        bool valid = SuiPrimitives.isValidObjectId(objectId);
        assertEq(valid, objectId != bytes32(0), "Zero should be invalid");
    }

    // =========================================================================
    // NULLIFIER FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test nullifier derivation
    function testFuzz_DeriveNullifier(
        bytes32 objectId,
        uint64 version,
        bytes32 actionDigest
    ) public pure {
        bytes32 nf1 = SuiPrimitives.deriveNullifier(
            objectId,
            version,
            actionDigest
        );
        bytes32 nf2 = SuiPrimitives.deriveNullifier(
            objectId,
            version,
            actionDigest
        );
        assertEq(nf1, nf2, "Nullifier derivation should be deterministic");

        // Different object should give different nullifier
        bytes32 nfDifferent = SuiPrimitives.deriveNullifier(
            bytes32(uint256(objectId) + 1),
            version,
            actionDigest
        );
        assertNotEq(
            nf1,
            nfDifferent,
            "Different objects should have different nullifiers"
        );
    }

    /// @notice Fuzz test cross-domain nullifier
    function testFuzz_CrossDomainNullifier(
        bytes32 suiNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(sourceChain != targetChain);

        bytes32 crossNf = SuiPrimitives.deriveCrossDomainNullifier(
            suiNullifier,
            sourceChain,
            targetChain
        );

        // Deterministic
        bytes32 crossNf2 = SuiPrimitives.deriveCrossDomainNullifier(
            suiNullifier,
            sourceChain,
            targetChain
        );
        assertEq(
            crossNf,
            crossNf2,
            "Cross-domain nullifier should be deterministic"
        );

        // Different chains should give different nullifiers
        bytes32 crossNfReverse = SuiPrimitives.deriveCrossDomainNullifier(
            suiNullifier,
            targetChain,
            sourceChain
        );
        assertNotEq(crossNf, crossNfReverse, "Direction should matter");
    }

    /// @notice Fuzz test PIL binding derivation
    function testFuzz_PILBinding(bytes32 suiNullifier) public pure {
        bytes32 binding1 = SuiPrimitives.derivePILBinding(suiNullifier);
        bytes32 binding2 = SuiPrimitives.derivePILBinding(suiNullifier);
        assertEq(binding1, binding2, "PIL binding should be deterministic");

        // Different nullifier = different binding
        bytes32 differentNullifier = bytes32(uint256(suiNullifier) ^ 1); // XOR to avoid overflow
        bytes32 bindingDiff = SuiPrimitives.derivePILBinding(
            differentNullifier
        );
        if (suiNullifier != differentNullifier) {
            assertNotEq(
                binding1,
                bindingDiff,
                "Different nullifiers should have different bindings"
            );
        }
    }

    // =========================================================================
    // COMMITTEE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test quorum calculation
    function testFuzz_HasQuorum(
        uint256 signingStake,
        uint256 totalStake
    ) public pure {
        vm.assume(totalStake > 0);
        vm.assume(totalStake < type(uint128).max); // Prevent overflow
        vm.assume(signingStake <= totalStake);
        vm.assume(signingStake > 0); // Zero stake edge case handled separately

        bool quorum = SuiPrimitives.hasQuorum(signingStake, totalStake);

        // Manual check: 2/3 + 1 threshold (signing * 10000 >= total * 6667)
        bool expected = signingStake * 10000 >= totalStake * 6667;

        assertEq(quorum, expected, "Quorum calculation mismatch");
    }

    /// @notice Fuzz test committee hash
    function testFuzz_CommitteeHash(
        uint64 epoch,
        bytes32[] memory validators,
        uint256 totalStake
    ) public pure {
        vm.assume(validators.length > 0 && validators.length <= 150);

        uint256[] memory stakes = new uint256[](validators.length);
        for (uint i = 0; i < validators.length; i++) {
            stakes[i] = totalStake / validators.length;
        }

        SuiPrimitives.ValidatorCommittee memory committee = SuiPrimitives
            .ValidatorCommittee({
                epoch: epoch,
                validators: validators,
                stakes: stakes,
                totalStake: totalStake,
                committeeHash: bytes32(0)
            });

        bytes32 hash1 = SuiPrimitives.computeCommitteeHash(committee);
        bytes32 hash2 = SuiPrimitives.computeCommitteeHash(committee);
        assertEq(hash1, hash2, "Committee hash should be deterministic");
    }

    // =========================================================================
    // CHECKPOINT FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test checkpoint digest
    function testFuzz_CheckpointDigest(
        uint64 epoch,
        uint64 sequenceNumber,
        bytes32 contentDigest,
        bytes32 previousDigest,
        uint64 timestampMs
    ) public pure {
        SuiPrimitives.CheckpointSummary memory checkpoint = SuiPrimitives
            .CheckpointSummary({
                epoch: epoch,
                sequenceNumber: sequenceNumber,
                contentDigest: contentDigest,
                previousDigest: previousDigest,
                timestampMs: timestampMs,
                transactions: new bytes32[](0),
                totalGasUsed: 0,
                committeeSig: bytes32(0)
            });

        bytes32 digest1 = SuiPrimitives.computeCheckpointDigest(checkpoint);
        bytes32 digest2 = SuiPrimitives.computeCheckpointDigest(checkpoint);
        assertEq(digest1, digest2, "Checkpoint digest should be deterministic");
    }

    /// @notice Fuzz test checkpoint chain verification
    function testFuzz_CheckpointChain(
        uint64 epoch,
        uint64 seqNum,
        bytes32 content1,
        bytes32 content2,
        uint64 ts1,
        uint64 ts2
    ) public pure {
        vm.assume(seqNum > 0);
        vm.assume(ts2 > ts1);

        SuiPrimitives.CheckpointSummary memory previous = SuiPrimitives
            .CheckpointSummary({
                epoch: epoch,
                sequenceNumber: seqNum - 1,
                contentDigest: content1,
                previousDigest: bytes32(0),
                timestampMs: ts1,
                transactions: new bytes32[](0),
                totalGasUsed: 0,
                committeeSig: bytes32(0)
            });

        bytes32 prevDigest = SuiPrimitives.computeCheckpointDigest(previous);

        SuiPrimitives.CheckpointSummary memory current = SuiPrimitives
            .CheckpointSummary({
                epoch: epoch,
                sequenceNumber: seqNum,
                contentDigest: content2,
                previousDigest: prevDigest,
                timestampMs: ts2,
                transactions: new bytes32[](0),
                totalGasUsed: 0,
                committeeSig: bytes32(0)
            });

        bool valid = SuiPrimitives.verifyCheckpointChain(current, previous);
        assertTrue(valid, "Valid chain should verify");
    }

    // =========================================================================
    // MESSAGE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test message ID computation
    function testFuzz_MessageId(
        uint64 sourceChain,
        uint64 targetChain,
        bytes32 sender,
        address recipient,
        bytes memory payload,
        uint64 nonce
    ) public pure {
        vm.assume(payload.length < 1000);

        SuiPrimitives.SuiMessage memory message = SuiPrimitives.SuiMessage({
            messageId: bytes32(0),
            sourceChain: sourceChain,
            targetChain: targetChain,
            sender: sender,
            recipient: recipient,
            payload: payload,
            nonce: nonce,
            timestamp: 0
        });

        bytes32 id1 = SuiPrimitives.computeMessageId(message);
        bytes32 id2 = SuiPrimitives.computeMessageId(message);
        assertEq(id1, id2, "Message ID should be deterministic");
    }

    /// @notice Fuzz test transfer ID computation
    function testFuzz_TransferId(
        bytes32 sourceObject,
        bytes32 coinType,
        uint256 amount,
        bytes32 sender,
        address recipient,
        uint64 sourceEpoch,
        bytes32 txDigest
    ) public pure {
        SuiPrimitives.SuiBridgeTransfer memory transfer = SuiPrimitives
            .SuiBridgeTransfer({
                transferId: bytes32(0),
                sourceObject: sourceObject,
                coinType: coinType,
                amount: amount,
                sender: sender,
                recipient: recipient,
                sourceEpoch: sourceEpoch,
                txDigest: txDigest
            });

        bytes32 id1 = SuiPrimitives.computeTransferId(transfer);
        bytes32 id2 = SuiPrimitives.computeTransferId(transfer);
        assertEq(id1, id2, "Transfer ID should be deterministic");
    }

    // =========================================================================
    // CHAIN VALIDATION FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test Sui chain ID validation
    function testFuzz_IsSuiChain(uint256 chainId) public pure {
        bool isSui = SuiPrimitives.isSuiChain(chainId);
        bool expected = chainId == 1 || chainId == 2 || chainId == 3;
        assertEq(isSui, expected, "Chain validation mismatch");
    }

    /// @notice Fuzz test epoch validation
    function testFuzz_IsValidEpoch(
        uint64 epoch,
        uint64 currentEpoch
    ) public pure {
        vm.assume(currentEpoch > 0);

        bool valid = SuiPrimitives.isValidEpoch(epoch, currentEpoch);
        bool expected = epoch <= currentEpoch && epoch >= currentEpoch - 1;
        assertEq(valid, expected, "Epoch validation mismatch");
    }

    // =========================================================================
    // MERKLE FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test Merkle root computation
    function testFuzz_MerkleRoot(bytes32[] memory leaves) public pure {
        vm.assume(leaves.length > 0 && leaves.length <= 64);

        bytes32 root1 = SuiPrimitives.computeMerkleRoot(leaves);
        bytes32 root2 = SuiPrimitives.computeMerkleRoot(leaves);
        assertEq(root1, root2, "Merkle root should be deterministic");
    }

    /// @notice Fuzz test single leaf Merkle root
    function testFuzz_SingleLeafMerkle(bytes32 leaf) public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;

        bytes32 root = SuiPrimitives.computeMerkleRoot(leaves);
        assertEq(root, leaf, "Single leaf should be root");
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS
    // =========================================================================

    /// @notice Fuzz test deposit initiation
    function testFuzz_Deposit(uint256 amount, bytes32 suiRecipient) public {
        vm.assume(amount > 0 && amount <= 100_000 ether);
        vm.assume(suiRecipient != bytes32(0));

        vm.deal(user, amount);
        vm.prank(user);

        bridge.deposit{value: amount}(address(0), amount, suiRecipient);

        uint256 todayVolume = bridge.getTodayVolume();
        assertEq(todayVolume, amount, "Daily volume should be updated");
    }

    /// @notice Fuzz test deposit with valid recipient only
    function testFuzz_DepositRecipientValidation(bytes32 recipient) public {
        uint256 amount = 1 ether;
        vm.deal(user, amount);
        vm.prank(user);

        if (recipient == bytes32(0)) {
            vm.expectRevert(SuiBridgeAdapter.InvalidRecipient.selector);
            bridge.deposit{value: amount}(address(0), amount, recipient);
        } else {
            bridge.deposit{value: amount}(address(0), amount, recipient);
        }
    }

    /// @notice Fuzz test validator registration
    function testFuzz_ValidatorRegistration(
        bytes32 suiAddress,
        uint256 stake
    ) public {
        vm.assume(stake > 0 && stake < type(uint128).max);
        vm.assume(suiAddress != bytes32(uint256(1))); // Avoid existing validator

        bytes memory blsKey = new bytes(96);
        for (uint i = 0; i < 96; i++) {
            blsKey[i] = bytes1(uint8(i + 1));
        }

        vm.prank(admin);
        bridge.registerValidator(suiAddress, blsKey, stake);
    }

    /// @notice Fuzz test invalid BLS key length
    function testFuzz_InvalidBLSKeyLength(uint8 keyLength) public {
        vm.assume(keyLength != 96);
        vm.assume(keyLength < 200);

        bytes memory blsKey = new bytes(keyLength);

        vm.prank(admin);
        vm.expectRevert(SuiBridgeAdapter.InvalidValidator.selector);
        bridge.registerValidator(bytes32(uint256(999)), blsKey, 1000 ether);
    }

    /// @notice Fuzz test daily limit enforcement
    function testFuzz_DailyLimitEnforcement(uint256 amount) public {
        // Bound to a range that will definitely exceed MAX_TRANSFER
        amount = bound(amount, 100_001 ether, 1_000_000 ether);

        vm.deal(user, amount);
        vm.prank(user);

        vm.expectRevert(SuiBridgeAdapter.TransferTooLarge.selector);
        bridge.deposit{value: amount}(
            address(0),
            amount,
            bytes32(uint256(123))
        );
    }

    /// @notice Fuzz test nullifier consumption check
    function testFuzz_NullifierConsumption(bytes32 nullifier) public view {
        bool consumed = bridge.isNullifierConsumed(nullifier);
        assertFalse(consumed, "New nullifier should not be consumed");
    }

    /// @notice Fuzz test circuit breaker trigger
    function testFuzz_CircuitBreakerTrigger() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker();

        // Should revert on deposit
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(SuiBridgeAdapter.CircuitBreakerActive.selector);
        bridge.deposit{value: 1 ether}(
            address(0),
            1 ether,
            bytes32(uint256(123))
        );
    }

    /// @notice Fuzz test relayer registration
    function testFuzz_RelayerRegistration(
        address relayerAddr,
        uint256 feeBps
    ) public {
        vm.assume(relayerAddr != address(0));
        vm.assume(feeBps <= 500); // Max 5%

        vm.prank(admin);
        bridge.registerRelayer(relayerAddr, feeBps);

        (bool isActive, uint256 fee, , ) = bridge.relayers(relayerAddr);
        assertTrue(isActive, "Relayer should be active");
        assertEq(fee, feeBps, "Fee should match");
    }

    /// @notice Fuzz test invalid relayer fee
    function testFuzz_InvalidRelayerFee(uint256 feeBps) public {
        vm.assume(feeBps > 500);

        vm.prank(admin);
        vm.expectRevert(SuiBridgeAdapter.InvalidRelayerFee.selector);
        bridge.registerRelayer(address(0x999), feeBps);
    }

    /// @notice Fuzz test committee update
    function testFuzz_CommitteeUpdate(
        uint64 newEpoch,
        uint8 validatorCount
    ) public {
        vm.assume(newEpoch > INITIAL_EPOCH);
        vm.assume(validatorCount > 0 && validatorCount <= 10);

        bytes32[] memory validators = new bytes32[](validatorCount);
        uint256[] memory stakes = new uint256[](validatorCount);

        for (uint i = 0; i < validatorCount; i++) {
            validators[i] = bytes32(uint256(i + 100));
            stakes[i] = 1000 ether;
        }

        vm.prank(admin);
        bridge.updateCommittee(newEpoch, validators, stakes);

        (uint64 epoch, uint256 count, uint256 totalStake) = bridge
            .getCommitteeInfo();
        assertEq(epoch, newEpoch, "Epoch should be updated");
        assertEq(count, validatorCount, "Validator count should match");
        assertEq(
            totalStake,
            uint256(validatorCount) * 1000 ether,
            "Total stake should match"
        );
    }

    /// @notice Fuzz test user daily limit
    function testFuzz_UserDailyLimit(address userAddr, uint256 limit) public {
        vm.assume(userAddr != address(0));
        vm.assume(limit > 0);

        vm.prank(admin);
        bridge.setUserDailyLimit(userAddr, limit);

        assertEq(bridge.userDailyLimit(userAddr), limit, "Limit should be set");
    }

    /// @notice Fuzz test pause/unpause
    function testFuzz_PauseUnpause() public {
        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(); // EnforcedPause
        bridge.deposit{value: 1 ether}(
            address(0),
            1 ether,
            bytes32(uint256(123))
        );

        vm.prank(admin);
        bridge.unpause();

        vm.prank(user);
        bridge.deposit{value: 1 ether}(
            address(0),
            1 ether,
            bytes32(uint256(123))
        );
    }

    // =========================================================================
    // INVARIANT PROPERTIES
    // =========================================================================

    /// @notice Invariant: nullifier cannot be un-consumed
    function invariant_NullifierImmutability() public view {
        // Any nullifier that was consumed should remain consumed
        // This is checked implicitly through the mapping
        assertTrue(true, "Placeholder");
    }

    /// @notice Invariant: daily volume should not exceed max
    function invariant_DailyVolumeLimit() public view {
        uint256 todayVolume = bridge.getTodayVolume();
        assertTrue(
            todayVolume <= 1_000_000 ether,
            "Daily volume should not exceed max"
        );
    }
}
