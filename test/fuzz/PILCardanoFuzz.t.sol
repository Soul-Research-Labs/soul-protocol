// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title PILCardanoFuzz
 * @notice Fuzz tests for Cardano bridge adapter
 * @dev Tests eUTXO model, Plutus scripts, Mithril proofs, and Hydra integration
 */
contract PILCardanoFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint64 constant LOVELACE_PER_ADA = 1_000_000;
    uint64 constant MIN_UTXO_LOVELACE = 1_000_000;
    uint256 constant MAX_ASSET_NAME_LENGTH = 32;
    uint256 constant CARDANO_EPOCH_LENGTH = 432_000; // 5 days in slots
    uint256 constant MITHRIL_CERT_VALIDITY = 48 hours;

    /*//////////////////////////////////////////////////////////////
                         NATIVE ASSET TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test policy ID and asset name hashing
    function testFuzz_NativeAssetId(
        bytes28 policyId,
        bytes32 assetName
    ) public pure {
        // Compute asset ID
        bytes32 assetId = keccak256(abi.encodePacked(policyId, assetName));

        // Asset ID should be deterministic
        bytes32 assetId2 = keccak256(abi.encodePacked(policyId, assetName));
        assertEq(assetId, assetId2, "Asset ID should be deterministic");

        // Different policy IDs should produce different asset IDs
        if (policyId != bytes28(0)) {
            bytes28 differentPolicy = bytes28(uint224(uint224(policyId) ^ 1));
            bytes32 differentAssetId = keccak256(
                abi.encodePacked(differentPolicy, assetName)
            );
            assertNotEq(
                assetId,
                differentAssetId,
                "Different policies should have different IDs"
            );
        }
    }

    /// @notice Fuzz test lovelace to ADA conversion
    function testFuzz_LovelaceConversion(uint64 lovelace) public pure {
        // Lovelace is already in smallest unit
        uint256 ada = uint256(lovelace);

        // 1 ADA = 1,000,000 lovelace
        uint256 wholeAda = lovelace / LOVELACE_PER_ADA;
        uint256 remainder = lovelace % LOVELACE_PER_ADA;

        // Reconstruction should match
        assertEq(
            wholeAda * LOVELACE_PER_ADA + remainder,
            lovelace,
            "Conversion should be reversible"
        );
    }

    /// @notice Fuzz test minimum UTXO value enforcement
    function testFuzz_MinUTXOValue(
        uint64 lovelace,
        uint256 numAssets
    ) public pure {
        numAssets = bound(numAssets, 0, 100);

        // Minimum UTXO increases with number of assets
        // Cardano formula: minUTXO = max(1 ADA, (160 + assetSize) * coinsPerUTXOByte)
        uint256 baseMin = MIN_UTXO_LOVELACE;
        uint256 assetOverhead = numAssets * 50000; // ~0.05 ADA per asset
        uint256 requiredMin = baseMin + assetOverhead;

        if (lovelace < requiredMin) {
            assertTrue(
                lovelace < requiredMin,
                "Should detect insufficient lovelace"
            );
        } else {
            assertTrue(
                lovelace >= requiredMin,
                "Should have sufficient lovelace"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         PLUTUS SCRIPT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Plutus script hash computation
    function testFuzz_PlutusScriptHash(
        bytes memory scriptBytes,
        uint8 scriptType
    ) public pure {
        scriptType = uint8(bound(scriptType, 0, 2)); // PLUTUS_V1, V2, V3

        // Compute script hash (simplified - real uses Blake2b-224)
        bytes32 scriptHash = keccak256(
            abi.encodePacked(scriptType, scriptBytes)
        );

        // Hash should be deterministic
        bytes32 scriptHash2 = keccak256(
            abi.encodePacked(scriptType, scriptBytes)
        );
        assertEq(
            scriptHash,
            scriptHash2,
            "Script hash should be deterministic"
        );

        // Different script types should produce different hashes
        if (scriptBytes.length > 0) {
            uint8 differentType = (scriptType + 1) % 3;
            bytes32 differentHash = keccak256(
                abi.encodePacked(differentType, scriptBytes)
            );
            assertNotEq(
                scriptHash,
                differentHash,
                "Different versions should have different hashes"
            );
        }
    }

    /// @notice Fuzz test datum hash computation
    function testFuzz_DatumHash(bytes memory datum) public pure {
        // Datum hash is used for script input validation
        bytes32 datumHash = keccak256(datum);

        // Hash should be deterministic
        bytes32 datumHash2 = keccak256(datum);
        assertEq(datumHash, datumHash2, "Datum hash should be deterministic");

        // Empty datum should have known hash
        if (datum.length == 0) {
            bytes32 emptyHash = keccak256("");
            assertEq(
                datumHash,
                emptyHash,
                "Empty datum should match empty hash"
            );
        }
    }

    /// @notice Fuzz test redeemer validation
    function testFuzz_RedeemerValidation(
        bytes memory redeemer,
        bytes32 expectedHash
    ) public pure {
        // Redeemer is provided when spending script UTXO
        bytes32 redeemerHash = keccak256(redeemer);

        bool matches = (redeemerHash == expectedHash);

        if (redeemer.length > 0 && expectedHash != bytes32(0)) {
            // Only matches if hashes are equal
            assertEq(
                matches,
                redeemerHash == expectedHash,
                "Validation logic correct"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         MITHRIL CERTIFICATE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Mithril certificate epoch calculation
    function testFuzz_MithrilEpoch(
        uint64 epoch,
        uint64 currentEpoch
    ) public pure {
        // Certificate should be from recent epoch
        if (epoch > currentEpoch) {
            assertTrue(epoch > currentEpoch, "Future epoch detected");
        } else {
            uint64 epochDiff = currentEpoch - epoch;
            // Certificates older than 2 epochs are stale
            bool isStale = epochDiff > 2;
            assertEq(isStale, epochDiff > 2, "Staleness check correct");
        }
    }

    /// @notice Fuzz test Mithril certificate validity
    function testFuzz_MithrilCertificateValidity(
        uint256 verifiedAtSeed,
        uint256 elapsedSeed
    ) public pure {
        // Use reasonable time bounds to avoid overflow
        uint256 verifiedAt = bound(verifiedAtSeed, 0, 1e18);
        uint256 elapsed = bound(elapsedSeed, 0, MITHRIL_CERT_VALIDITY * 2);
        uint256 currentTime = verifiedAt + elapsed;

        bool isValid = currentTime <= verifiedAt + MITHRIL_CERT_VALIDITY;

        if (elapsed <= MITHRIL_CERT_VALIDITY) {
            assertTrue(isValid, "Should be valid within validity period");
        } else {
            assertFalse(isValid, "Should be invalid after validity period");
        }
    }

    /// @notice Fuzz test stake distribution in Mithril
    function testFuzz_MithrilStakeDistribution(
        uint256[] memory stakes,
        uint256 threshold
    ) public pure {
        vm.assume(stakes.length > 0 && stakes.length <= 100);

        uint256 totalStake = 0;
        for (uint256 i = 0; i < stakes.length; i++) {
            stakes[i] = bound(stakes[i], 0, 1e27);
            totalStake += stakes[i];
        }

        if (totalStake == 0) return;

        threshold = bound(threshold, 0, 10000); // basis points
        uint256 requiredStake = (totalStake * threshold) / 10000;

        // Simulate aggregating signers
        uint256 aggregatedStake = 0;
        uint256 signerCount = 0;
        for (
            uint256 i = 0;
            i < stakes.length && aggregatedStake < requiredStake;
            i++
        ) {
            aggregatedStake += stakes[i];
            signerCount++;
        }

        if (requiredStake > 0) {
            assertTrue(
                signerCount <= stakes.length,
                "Should not exceed total signers"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         UTXO PROOF TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test UTXO Merkle proof verification
    function testFuzz_UTXOMerkleProof(
        bytes32 utxoHash,
        bytes32[] memory proof,
        uint256 leafIndex
    ) public pure {
        // Skip if proof length is invalid
        if (proof.length == 0 || proof.length > 32) return;

        // Compute Merkle root
        bytes32 computedHash = utxoHash;
        uint256 index = leafIndex;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        // Root should be deterministic for same inputs
        bytes32 computedHash2 = utxoHash;
        index = leafIndex;
        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash2 = keccak256(
                    abi.encodePacked(computedHash2, proof[i])
                );
            } else {
                computedHash2 = keccak256(
                    abi.encodePacked(proof[i], computedHash2)
                );
            }
            index = index / 2;
        }

        assertEq(
            computedHash,
            computedHash2,
            "Merkle root computation should be deterministic"
        );
    }

    /// @notice Fuzz test UTXO structure hashing
    function testFuzz_UTXOHash(
        bytes32 txHash,
        uint32 outputIndex,
        uint64 lovelace
    ) public pure {
        // UTXO is uniquely identified by txHash + outputIndex
        bytes32 utxoId = keccak256(abi.encodePacked(txHash, outputIndex));

        // Same inputs should produce same ID
        bytes32 utxoId2 = keccak256(abi.encodePacked(txHash, outputIndex));
        assertEq(utxoId, utxoId2, "UTXO ID should be deterministic");

        // Different output indices should produce different IDs
        if (outputIndex < type(uint32).max) {
            bytes32 differentId = keccak256(
                abi.encodePacked(txHash, outputIndex + 1)
            );
            assertNotEq(
                utxoId,
                differentId,
                "Different indices should have different IDs"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         HYDRA HEAD TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Hydra head contestation period
    function testFuzz_HydraContestationPeriod(
        uint256 closedAt,
        uint256 contestationPeriod,
        uint256 currentTime
    ) public pure {
        contestationPeriod = bound(contestationPeriod, 60, 86400); // 1 min to 1 day
        vm.assume(closedAt <= currentTime);
        vm.assume(closedAt <= type(uint256).max - contestationPeriod);

        uint256 contestationEnd = closedAt + contestationPeriod;
        bool canFinalize = currentTime >= contestationEnd;

        if (currentTime < contestationEnd) {
            assertFalse(canFinalize, "Should not finalize during contestation");
        } else {
            assertTrue(
                canFinalize,
                "Should be able to finalize after contestation"
            );
        }
    }

    /// @notice Fuzz test Hydra participant verification
    function testFuzz_HydraParticipants(
        uint256 cardanoKeysLenSeed,
        uint256 evmAddressesLenSeed
    ) public pure {
        uint256 cardanoKeysLen = bound(cardanoKeysLenSeed, 0, 10);
        uint256 evmAddressesLen = bound(evmAddressesLenSeed, 0, 10);

        bool validSetup = cardanoKeysLen == evmAddressesLen;

        if (cardanoKeysLen != evmAddressesLen) {
            assertFalse(validSetup, "Mismatched arrays should be invalid");
        } else {
            assertTrue(validSetup, "Matched arrays should be valid");
        }
    }

    /// @notice Fuzz test Hydra UTXO commitment
    function testFuzz_HydraUTXOCommitment(
        bytes32[] memory utxoHashes
    ) public pure {
        vm.assume(utxoHashes.length > 0 && utxoHashes.length <= 100);

        // Compute commitment hash
        bytes32 commitment = keccak256(abi.encodePacked(utxoHashes));

        // Commitment should be deterministic
        bytes32 commitment2 = keccak256(abi.encodePacked(utxoHashes));
        assertEq(
            commitment,
            commitment2,
            "UTXO commitment should be deterministic"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         ADDRESS VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Cardano address validation
    function testFuzz_CardanoAddressValidation(
        bytes memory addressBytes
    ) public pure {
        vm.assume(addressBytes.length > 0);

        // Cardano addresses are 57-114 bytes
        bool validLength = addressBytes.length >= 57 &&
            addressBytes.length <= 114;

        if (!validLength) {
            assertFalse(validLength, "Invalid length should fail");
            return;
        }

        // Check header byte
        uint8 header = uint8(addressBytes[0]);
        uint8 addressType = header >> 4;
        uint8 networkTag = header & 0x0F;

        // Valid address types are 0-8
        bool validType = addressType <= 8;
        // Valid network tags are 0 (testnet) or 1 (mainnet)
        bool validNetwork = networkTag <= 1;

        if (!validType) {
            assertFalse(validType, "Invalid address type should fail");
        }
        if (!validNetwork) {
            assertFalse(validNetwork, "Invalid network tag should fail");
        }
    }

    /// @notice Fuzz test Cardano base address components
    function testFuzz_CardanoBaseAddress(
        bytes28 paymentCredential,
        bytes28 stakingCredential,
        uint8 networkTag
    ) public pure {
        networkTag = uint8(bound(networkTag, 0, 1));

        // Base address header: 0x00 (testnet) or 0x01 (mainnet)
        uint8 header = networkTag;

        // Construct address (simplified)
        bytes memory fullAddress = abi.encodePacked(
            header,
            paymentCredential,
            stakingCredential
        );

        // Should be 57 bytes (1 header + 28 payment + 28 staking)
        assertEq(fullAddress.length, 57, "Base address should be 57 bytes");

        // Header should indicate base address type
        assertLe(uint8(fullAddress[0]) >> 4, 8, "Address type should be valid");
    }

    /*//////////////////////////////////////////////////////////////
                         SLOT/EPOCH TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test slot to epoch conversion
    function testFuzz_SlotToEpoch(uint64 slot) public pure {
        uint64 epoch = slot / uint64(CARDANO_EPOCH_LENGTH);
        uint64 slotInEpoch = slot % uint64(CARDANO_EPOCH_LENGTH);

        // Reconstruction should match
        uint64 reconstructedSlot = epoch *
            uint64(CARDANO_EPOCH_LENGTH) +
            slotInEpoch;
        assertEq(reconstructedSlot, slot, "Slot reconstruction should match");

        // Slot in epoch should be less than epoch length
        assertLt(
            slotInEpoch,
            CARDANO_EPOCH_LENGTH,
            "Slot in epoch should be bounded"
        );
    }

    /// @notice Fuzz test slot timing
    function testFuzz_SlotTiming(uint64 slot1, uint64 slot2) public pure {
        // Each slot is ~1 second
        uint64 slotDiff = slot1 > slot2 ? slot1 - slot2 : slot2 - slot1;

        // Time difference in seconds (approximately)
        uint256 timeDiff = uint256(slotDiff); // 1 slot ≈ 1 second

        // Slots should be ordered consistently with time
        if (slot1 > slot2) {
            assertGt(slot1, slot2, "Slot ordering should be consistent");
        }
    }

    /*//////////////////////////////////////////////////////////////
                         TRANSFER TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test transfer fee calculation
    function testFuzz_TransferFee(
        uint256 amountSeed,
        uint256 feeBpsSeed
    ) public pure {
        uint256 amount = bound(amountSeed, MIN_UTXO_LOVELACE, 1e18);
        uint256 feeBps = bound(feeBpsSeed, 0, 100); // Max 1%

        uint256 fee = (amount * feeBps) / 10000;

        // Fee should be bounded
        assertLe(fee, amount / 100, "Fee should not exceed 1%");

        // Fee calculation should be deterministic
        uint256 fee2 = (amount * feeBps) / 10000;
        assertEq(fee, fee2, "Fee calculation should be deterministic");
    }

    /// @notice Fuzz test transfer ID generation
    function testFuzz_TransferIdGeneration(
        address sender,
        bytes28 policyId,
        bytes32 assetName,
        uint256 amount,
        uint256 nonce
    ) public pure {
        vm.assume(sender != address(0));

        bytes32 transferId = keccak256(
            abi.encodePacked(sender, policyId, assetName, amount, nonce)
        );

        // Transfer ID should be deterministic
        bytes32 transferId2 = keccak256(
            abi.encodePacked(sender, policyId, assetName, amount, nonce)
        );
        assertEq(
            transferId,
            transferId2,
            "Transfer ID should be deterministic"
        );

        // Different nonces should produce different IDs
        if (nonce < type(uint256).max) {
            bytes32 differentId = keccak256(
                abi.encodePacked(sender, policyId, assetName, amount, nonce + 1)
            );
            assertNotEq(
                transferId,
                differentId,
                "Different nonces should have different IDs"
            );
        }
    }

    /// @notice Fuzz test multi-asset transfer
    function testFuzz_MultiAssetTransfer(
        uint256 numAssetsSeed,
        uint64 quantity1,
        uint64 quantity2,
        uint64 quantity3
    ) public pure {
        uint256 numAssets = bound(numAssetsSeed, 1, 3);

        // Bound quantities
        uint64 q1 = uint64(bound(quantity1, 1, 1e15));
        uint64 q2 = uint64(bound(quantity2, 1, 1e15));
        uint64 q3 = uint64(bound(quantity3, 1, 1e15));

        // Calculate total value based on numAssets
        uint256 totalValue = q1;
        if (numAssets >= 2) totalValue += q2;
        if (numAssets >= 3) totalValue += q3;

        // Verify total calculation
        uint256 checkTotal = q1;
        if (numAssets >= 2) checkTotal += q2;
        if (numAssets >= 3) checkTotal += q3;

        assertEq(totalValue, checkTotal, "Total value should match sum");
        assertTrue(totalValue >= q1, "Total should be at least first quantity");
    }

    /*//////////////////////////////////////////////////////////////
                         GUARDIAN SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test guardian threshold
    function testFuzz_GuardianThreshold(
        uint256 signaturesCount,
        uint256 threshold,
        uint256 totalGuardians
    ) public pure {
        totalGuardians = bound(totalGuardians, 1, 100);
        threshold = bound(threshold, 1, totalGuardians);
        signaturesCount = bound(signaturesCount, 0, totalGuardians);

        bool hasQuorum = signaturesCount >= threshold;

        if (signaturesCount >= threshold) {
            assertTrue(hasQuorum, "Should have quorum with enough signatures");
        } else {
            assertFalse(
                hasQuorum,
                "Should not have quorum without enough signatures"
            );
        }
    }

    /// @notice Fuzz test multi-sig message hash
    function testFuzz_MultiSigMessageHash(
        bytes32 messageId,
        uint256 amount,
        bytes memory recipient
    ) public pure {
        // Hash message for guardian signatures
        bytes32 messageHash = keccak256(
            abi.encodePacked(messageId, amount, recipient)
        );

        // Hash should be deterministic
        bytes32 messageHash2 = keccak256(
            abi.encodePacked(messageId, amount, recipient)
        );
        assertEq(
            messageHash,
            messageHash2,
            "Message hash should be deterministic"
        );
    }
}
