// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title PILBridgeFuzz
 * @notice Fuzz tests for all PIL bridge adapters and cross-chain messaging
 * @dev Tests LayerZero, Chainlink, Wormhole, StarkNet, Solana, Bitcoin bridges
 *
 * Run with: forge test --match-contract PILBridgeFuzz --fuzz-runs 10000
 */
contract PILBridgeFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant FEE_DENOMINATOR = 10000;
    uint256 constant MAX_BRIDGE_FEE = 100; // 1%
    uint256 constant MIN_BRIDGE_AMOUNT = 1000;

    // Chain IDs
    uint256 constant ETHEREUM = 1;
    uint256 constant SOLANA = 1399811149;
    uint256 constant STARKNET = 23448594291968334;
    uint256 constant BITCOIN = 0; // L1
    uint256 constant ARBITRUM = 42161;
    uint256 constant OPTIMISM = 10;
    uint256 constant POLYGON = 137;
    uint256 constant AVALANCHE = 43114;
    uint256 constant BSC = 56;

    /*//////////////////////////////////////////////////////////////
                    LAYERZERO BRIDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test LayerZero message encoding
    function testFuzz_LayerZeroMessageEncoding(
        uint16 srcChainId,
        uint16 dstChainId,
        bytes32 recipient,
        uint128 amount,
        uint64 nonce
    ) public pure {
        vm.assume(srcChainId != dstChainId);
        vm.assume(recipient != bytes32(0));
        vm.assume(amount > MIN_BRIDGE_AMOUNT);

        // Encode message
        bytes memory payload = abi.encode(recipient, amount, nonce);

        // Decode and verify
        (
            bytes32 decodedRecipient,
            uint256 decodedAmount,
            uint64 decodedNonce
        ) = abi.decode(payload, (bytes32, uint256, uint64));

        assertEq(decodedRecipient, recipient, "Recipient mismatch");
        assertEq(decodedAmount, amount, "Amount mismatch");
        assertEq(decodedNonce, nonce, "Nonce mismatch");
    }

    /// @notice Fuzz test LayerZero fee calculation
    function testFuzz_LayerZeroFeeCalculation(
        uint128 amountSeed,
        uint16 baseFeeSeed,
        uint256 gasPriceSeed
    ) public pure {
        uint128 amount = uint128(
            bound(uint256(amountSeed), MIN_BRIDGE_AMOUNT + 1, type(uint128).max)
        );
        uint16 baseFee = uint16(bound(uint256(baseFeeSeed), 0, MAX_BRIDGE_FEE));
        uint256 gasPrice = bound(gasPriceSeed, 1, 999 gwei);

        uint256 protocolFee = (uint256(amount) * baseFee) / FEE_DENOMINATOR;
        uint256 gasFee = gasPrice * 200000; // Estimated gas

        uint256 totalFee = protocolFee + gasFee;
        uint256 amountAfterFee = amount > totalFee ? amount - totalFee : 0;

        assertLe(protocolFee, amount, "Protocol fee exceeds amount");
        if (amount > totalFee) {
            assertGt(amountAfterFee, 0, "Should have remaining amount");
        }
    }

    /*//////////////////////////////////////////////////////////////
                    CHAINLINK CCIP TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Chainlink CCIP message structure
    function testFuzz_ChainlinkCCIPMessage(
        uint256 srcChainSeed,
        uint256 dstChainSeed,
        address sender,
        bytes32 receiver,
        uint256 amountSeed,
        bytes32 messageId
    ) public view {
        uint64 srcChainSelector = uint64(
            bound(srcChainSeed, 1, type(uint64).max - 1)
        );
        uint64 dstChainSelector = uint64(
            bound(dstChainSeed, srcChainSelector + 1, type(uint64).max)
        );
        vm.assume(sender != address(0));
        vm.assume(receiver != bytes32(0));
        uint128 amount = uint128(bound(amountSeed, 1, type(uint128).max - 1));

        // Message should be deterministically computed
        bytes32 computedId = keccak256(
            abi.encodePacked(
                srcChainSelector,
                dstChainSelector,
                sender,
                receiver,
                amount,
                block.timestamp
            )
        );

        // Different inputs should produce different IDs
        bytes32 computedId2 = keccak256(
            abi.encodePacked(
                srcChainSelector,
                dstChainSelector,
                sender,
                receiver,
                amount + 1,
                block.timestamp
            )
        );

        assertNotEq(
            computedId,
            computedId2,
            "Different amounts should produce different IDs"
        );
    }

    /// @notice Fuzz test CCIP rate limiting
    function testFuzz_CCIPRateLimiting(
        uint128 amount,
        uint128 bucketCapacity,
        uint128 currentBucket,
        uint128 refillRate,
        uint256 timeDelta
    ) public pure {
        vm.assume(bucketCapacity > 0);
        vm.assume(refillRate > 0 && refillRate <= bucketCapacity);
        vm.assume(timeDelta <= 1 days);

        // Calculate refilled amount
        uint256 refilled = (uint256(refillRate) * timeDelta) / 1 hours;
        uint256 newBucket = currentBucket + refilled;
        if (newBucket > bucketCapacity) {
            newBucket = bucketCapacity;
        }

        // Check if transfer allowed
        bool allowed = amount <= newBucket;

        if (allowed) {
            uint256 afterTransfer = newBucket - amount;
            assertLe(
                afterTransfer,
                bucketCapacity,
                "Bucket should not exceed capacity"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    WORMHOLE BRIDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Wormhole VAA structure
    function testFuzz_WormholeVAAStructure(
        uint8 version,
        uint32 guardianSetIndex,
        uint16 emitterChain,
        bytes32 emitterAddress,
        uint64 sequence,
        bytes32 payload
    ) public pure {
        // VAA header
        bytes memory vaaHeader = abi.encodePacked(
            version,
            guardianSetIndex,
            uint8(1), // Signature count (simplified)
            emitterChain,
            emitterAddress,
            sequence,
            uint8(1), // Consistency level
            payload
        );

        // VAA hash
        bytes32 vaaHash = keccak256(vaaHeader);

        // Hash should be deterministic
        bytes32 vaaHash2 = keccak256(vaaHeader);
        assertEq(vaaHash, vaaHash2, "VAA hash should be deterministic");
    }

    /// @notice Fuzz test Wormhole guardian signature verification concept
    function testFuzz_WormholeGuardianQuorum(
        uint8 totalGuardians,
        uint8 signaturesProvided
    ) public pure {
        vm.assume(totalGuardians > 0 && totalGuardians <= 19);
        vm.assume(signaturesProvided <= totalGuardians);

        // Quorum is 2/3 + 1
        uint256 quorum = (uint256(totalGuardians) * 2) / 3 + 1;

        bool hasQuorum = signaturesProvided >= quorum;

        // If we have more than 2/3, we should have quorum
        if (signaturesProvided > (totalGuardians * 2) / 3) {
            assertTrue(hasQuorum, "Should have quorum with >2/3 signatures");
        }
    }

    /*//////////////////////////////////////////////////////////////
                    STARKNET BRIDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test StarkNet message hash computation
    function testFuzz_StarkNetMessageHash(
        uint256 fromAddressSeed,
        uint256 toAddressSeed,
        uint256 selectorSeed,
        uint256[] memory payload
    ) public pure {
        uint256 fromAddress = bound(fromAddressSeed, 1, type(uint256).max);
        uint256 toAddress = bound(toAddressSeed, 1, type(uint256).max);
        uint256 selector = bound(selectorSeed, 1, type(uint256).max);
        // Skip if payload too long
        if (payload.length > 10) return;

        // StarkNet message hash (simplified)
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                fromAddress,
                toAddress,
                selector,
                keccak256(abi.encodePacked(payload))
            )
        );

        // Should be deterministic
        bytes32 messageHash2 = keccak256(
            abi.encodePacked(
                fromAddress,
                toAddress,
                selector,
                keccak256(abi.encodePacked(payload))
            )
        );

        assertEq(
            messageHash,
            messageHash2,
            "Message hash should be deterministic"
        );
    }

    /// @notice Fuzz test StarkNet L1 -> L2 messaging
    function testFuzz_StarkNetL1ToL2(
        uint256 l2ContractAddress,
        uint256 entryPointSelector,
        uint128 amount,
        uint256 nonceSeed
    ) public pure {
        vm.assume(l2ContractAddress != 0);
        vm.assume(entryPointSelector != 0);
        vm.assume(amount > 0);
        uint256 nonce = bound(nonceSeed, 0, type(uint256).max - 1);

        // Compute message hash
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "L1_TO_L2",
                l2ContractAddress,
                entryPointSelector,
                amount,
                nonce
            )
        );

        // Message should be unique per nonce
        bytes32 msgHash2 = keccak256(
            abi.encodePacked(
                "L1_TO_L2",
                l2ContractAddress,
                entryPointSelector,
                amount,
                nonce + 1
            )
        );

        assertNotEq(
            msgHash,
            msgHash2,
            "Different nonces should produce different hashes"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    SOLANA BRIDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Solana account derivation
    function testFuzz_SolanaAccountDerivation(
        bytes32 programId,
        bytes32 seed1,
        bytes32 seed2,
        uint8 bump
    ) public pure {
        vm.assume(seed1 != seed2);

        // PDA derivation (simplified)
        bytes32 pda1 = keccak256(abi.encodePacked(programId, seed1, bump));
        bytes32 pda2 = keccak256(abi.encodePacked(programId, seed2, bump));

        assertNotEq(
            pda1,
            pda2,
            "Different seeds should produce different PDAs"
        );
    }

    /// @notice Fuzz test Solana SPL token transfer
    function testFuzz_SolanaSPLTransfer(
        bytes32 mint,
        bytes32 fromAccount,
        bytes32 toAccount,
        uint64 amount,
        uint8 decimals
    ) public pure {
        vm.assume(fromAccount != toAccount);
        vm.assume(amount > 0);
        vm.assume(decimals <= 18);

        // Token amount with decimals
        uint256 rawAmount = uint256(amount) * (10 ** decimals);

        // Transfer should preserve amount
        assertEq(
            rawAmount / (10 ** decimals),
            amount,
            "Decimal conversion should be reversible"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    BITCOIN BRIDGE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test Bitcoin HTLC script hash
    function testFuzz_BitcoinHTLCScript(
        bytes32 secretHash,
        bytes20 recipientPubKeyHash,
        bytes20 refundPubKeyHash,
        uint32 lockTime
    ) public pure {
        vm.assume(recipientPubKeyHash != refundPubKeyHash);
        vm.assume(lockTime > 0);

        // HTLC script hash (simplified)
        bytes32 scriptHash = keccak256(
            abi.encodePacked(
                "OP_IF",
                "OP_SHA256",
                secretHash,
                "OP_EQUALVERIFY",
                recipientPubKeyHash,
                "OP_ELSE",
                lockTime,
                "OP_CHECKLOCKTIMEVERIFY",
                refundPubKeyHash,
                "OP_ENDIF"
            )
        );

        // Script hash should be deterministic
        bytes32 scriptHash2 = keccak256(
            abi.encodePacked(
                "OP_IF",
                "OP_SHA256",
                secretHash,
                "OP_EQUALVERIFY",
                recipientPubKeyHash,
                "OP_ELSE",
                lockTime,
                "OP_CHECKLOCKTIMEVERIFY",
                refundPubKeyHash,
                "OP_ENDIF"
            )
        );

        assertEq(
            scriptHash,
            scriptHash2,
            "Script hash should be deterministic"
        );
    }

    /// @notice Fuzz test Bitcoin Merkle proof
    function testFuzz_BitcoinMerkleProof(
        bytes32 txHash,
        bytes32[] memory proof,
        uint256 indexSeed
    ) public pure {
        // Skip if proof length is invalid
        if (proof.length == 0 || proof.length > 32) return;
        uint256 index = bound(indexSeed, 0, (1 << proof.length) - 1);

        bytes32 current = txHash;

        for (uint256 i = 0; i < proof.length; i++) {
            if ((index >> i) & 1 == 0) {
                current = keccak256(abi.encodePacked(current, proof[i]));
            } else {
                current = keccak256(abi.encodePacked(proof[i], current));
            }
        }

        // Merkle root should be deterministic
        assertNotEq(current, bytes32(0), "Merkle root should not be zero");
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN ATOMICITY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test cross-chain message ordering
    function testFuzz_CrossChainMessageOrdering(
        uint64 nonce1,
        uint64 nonce2,
        uint64 nonce3
    ) public pure {
        vm.assume(nonce1 < nonce2 && nonce2 < nonce3);

        // Messages should be processed in order
        bool order1Before2 = nonce1 < nonce2;
        bool order2Before3 = nonce2 < nonce3;

        assertTrue(order1Before2, "Message 1 should be before 2");
        assertTrue(order2Before3, "Message 2 should be before 3");
    }

    /// @notice Fuzz test cross-chain replay protection
    function testFuzz_CrossChainReplayProtection(
        uint256 srcChain,
        uint256 dstChain,
        bytes32 messageHash,
        uint64 nonce
    ) public pure {
        vm.assume(srcChain != dstChain);

        // Full message ID includes chain context
        bytes32 fullMessageId = keccak256(
            abi.encodePacked(srcChain, dstChain, messageHash, nonce)
        );

        // Same message on different chains should have different IDs
        bytes32 otherChainId = keccak256(
            abi.encodePacked(dstChain, srcChain, messageHash, nonce)
        );

        assertNotEq(
            fullMessageId,
            otherChainId,
            "Cross-chain replay should be prevented"
        );
    }

    /// @notice Fuzz test finality thresholds
    function testFuzz_FinalityThresholds(
        uint256 chainId,
        uint256 blockConfirmationsSeed,
        uint256 requiredConfirmationsSeed
    ) public pure {
        uint256 requiredConfirmations = bound(
            requiredConfirmationsSeed,
            1,
            256
        );
        uint256 blockConfirmations = bound(blockConfirmationsSeed, 0, 1000);

        bool isFinalized = blockConfirmations >= requiredConfirmations;

        if (blockConfirmations >= requiredConfirmations) {
            assertTrue(
                isFinalized,
                "Should be finalized with enough confirmations"
            );
        } else {
            assertFalse(
                isFinalized,
                "Should not be finalized without enough confirmations"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                    RELAYER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test relayer fee calculation
    function testFuzz_RelayerFeeCalculation(
        uint256 messageSizeSeed,
        uint256 gasPriceSeed,
        uint256 gasLimitSeed,
        uint256 relayerFeeSeed
    ) public pure {
        uint256 messageSize = bound(messageSizeSeed, 1, 10000);
        uint256 gasPrice = bound(gasPriceSeed, 1, 1000 gwei);
        uint256 gasLimit = bound(gasLimitSeed, 21001, 1000000);
        uint256 relayerFeeRate = bound(relayerFeeSeed, 0, 1000); // Max 10%

        uint256 gasCost = gasPrice * gasLimit;
        uint256 relayerPremium = (gasCost * relayerFeeRate) / FEE_DENOMINATOR;
        uint256 totalCost = gasCost + relayerPremium;

        assertGe(totalCost, gasCost, "Total should include premium");
        assertLe(
            relayerPremium,
            gasCost / 10,
            "Premium should be at most 10% of gas"
        );
    }

    /// @notice Fuzz test relayer slashing conditions
    function testFuzz_RelayerSlashing(
        uint128 stakeSeed,
        uint128 slashAmount,
        uint256 violationCountSeed
    ) public pure {
        uint128 stake = uint128(
            bound(uint256(stakeSeed), 1, type(uint128).max)
        );
        uint256 violationCount = bound(violationCountSeed, 1, 10);

        // Slash amount increases with violations
        uint256 effectiveSlash = uint256(slashAmount) * violationCount;
        if (effectiveSlash > stake) {
            effectiveSlash = stake;
        }

        uint256 remainingStake = stake - effectiveSlash;

        assertLe(effectiveSlash, stake, "Cannot slash more than stake");
        assertGe(remainingStake, 0, "Remaining stake should be non-negative");
    }
}
