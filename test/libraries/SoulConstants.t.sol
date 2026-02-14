// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/SoulConstants.sol";

contract SoulConstantsTest is Test {
    /* ── Role Hash Verification ─────────────────────── */

    function test_operatorRole_matchesKeccak() public pure {
        assertEq(SoulConstants.OPERATOR_ROLE, keccak256("OPERATOR_ROLE"));
    }

    function test_relayerRole_matchesKeccak() public pure {
        assertEq(SoulConstants.RELAYER_ROLE, keccak256("RELAYER_ROLE"));
    }

    function test_guardianRole_matchesKeccak() public pure {
        assertEq(SoulConstants.GUARDIAN_ROLE, keccak256("GUARDIAN_ROLE"));
    }

    function test_upgraderRole_matchesKeccak() public pure {
        assertEq(SoulConstants.UPGRADER_ROLE, keccak256("UPGRADER_ROLE"));
    }

    function test_announcerRole_matchesKeccak() public pure {
        assertEq(
            SoulConstants.ANNOUNCER_ROLE,
            keccak256("ANNOUNCER_ROLE")
        );
    }

    function test_executorRole_matchesKeccak() public pure {
        assertEq(SoulConstants.EXECUTOR_ROLE, keccak256("EXECUTOR_ROLE"));
    }

    function test_proposerRole_matchesKeccak() public pure {
        assertEq(SoulConstants.PROPOSER_ROLE, keccak256("PROPOSER_ROLE"));
    }

    /* ── Time Constants ─────────────────────────────── */

    function test_timeConstants() public pure {
        assertEq(SoulConstants.HOUR, 3600);
        assertEq(SoulConstants.DAY, 86400);
        assertEq(SoulConstants.WEEK, 604800);
        assertEq(SoulConstants.DEFAULT_CHALLENGE_PERIOD, 1 hours);
        assertEq(SoulConstants.FAST_CHALLENGE_WINDOW, 5 minutes);
        assertEq(SoulConstants.MESSAGE_EXPIRY, 24 hours);
    }

    /* ── Numeric Limits ─────────────────────────────── */

    function test_numericLimits() public pure {
        assertEq(SoulConstants.BASIS_POINTS, 10_000);
        assertEq(SoulConstants.MAX_BATCH_SIZE, 100);
        assertEq(SoulConstants.MAX_SCORE, 100);
    }

    /* ── Cryptographic Constants ────────────────────── */

    function test_secp256k1_order() public pure {
        // Known secp256k1 curve order
        assertEq(
            SoulConstants.SECP256K1_N,
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        );
    }

    function test_secp256k1_nDiv2() public pure {
        assertEq(
            SoulConstants.SECP256K1_N_DIV_2,
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        );
        // Verify it's actually n/2
        assertEq(
            SoulConstants.SECP256K1_N_DIV_2,
            SoulConstants.SECP256K1_N / 2
        );
    }

    /* ── Chain IDs ──────────────────────────────────── */

    function test_chainIds() public pure {
        assertEq(SoulConstants.CHAIN_ETHEREUM, 1);
        assertEq(SoulConstants.CHAIN_ARBITRUM, 42161);
        assertEq(SoulConstants.CHAIN_OPTIMISM, 10);
        assertEq(SoulConstants.CHAIN_BASE, 8453);
        assertEq(SoulConstants.CHAIN_POLYGON_ZKEVM, 1101);
        assertEq(SoulConstants.CHAIN_ZKSYNC, 324);
        assertEq(SoulConstants.CHAIN_SCROLL, 534352);
        assertEq(SoulConstants.CHAIN_LINEA, 59144);
    }

    /* ── Stake Amounts ──────────────────────────────── */

    function test_stakeAmounts() public pure {
        assertEq(SoulConstants.MIN_RELAYER_BOND, 1 ether);
        assertEq(SoulConstants.MIN_RELAYER_STAKE, 0.1 ether);
        assertEq(SoulConstants.MIN_CHALLENGER_STAKE, 0.05 ether);
    }

    /* ── Uniqueness of Role Constants ───────────────── */

    function test_rolesAreUnique() public pure {
        bytes32[13] memory roles = [
            SoulConstants.OPERATOR_ROLE,
            SoulConstants.RELAYER_ROLE,
            SoulConstants.CHALLENGER_ROLE,
            SoulConstants.GUARDIAN_ROLE,
            SoulConstants.MONITOR_ROLE,
            SoulConstants.RECOVERY_ROLE,
            SoulConstants.UPGRADER_ROLE,
            SoulConstants.ANNOUNCER_ROLE,
            SoulConstants.SEQUENCER_ROLE,
            SoulConstants.EMERGENCY_ROLE,
            SoulConstants.VERIFIER_ADMIN_ROLE,
            SoulConstants.EXECUTOR_ROLE,
            SoulConstants.PROPOSER_ROLE
        ];

        for (uint256 i = 0; i < roles.length; i++) {
            for (uint256 j = i + 1; j < roles.length; j++) {
                assertTrue(roles[i] != roles[j], "Duplicate role constants");
            }
        }
    }

    /* ── Domain Separator Uniqueness ────────────────── */

    function test_domainSeparatorsAreUnique() public pure {
        assertTrue(
            SoulConstants.STEALTH_DOMAIN != SoulConstants.NULLIFIER_DOMAIN
        );
        assertTrue(
            SoulConstants.NULLIFIER_DOMAIN != SoulConstants.CROSS_CHAIN_DOMAIN
        );
        assertTrue(
            SoulConstants.STEALTH_DOMAIN != SoulConstants.CROSS_CHAIN_DOMAIN
        );
    }

    /* ── Proof Type Uniqueness ──────────────────────── */

    function test_proofTypesAreUnique() public pure {
        assertTrue(
            SoulConstants.PROOF_TYPE_GROTH16_BLS !=
                SoulConstants.PROOF_TYPE_PLONK
        );
        assertTrue(
            SoulConstants.PROOF_TYPE_PLONK != SoulConstants.PROOF_TYPE_STARK
        );
        assertTrue(
            SoulConstants.PROOF_TYPE_GROTH16_BLS !=
                SoulConstants.PROOF_TYPE_STARK
        );
    }
}
