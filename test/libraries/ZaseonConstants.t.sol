// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/libraries/ZaseonConstants.sol";

contract ZaseonConstantsTest is Test {
    /* ── Role Hash Verification ─────────────────────── */

    function test_operatorRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.OPERATOR_ROLE, keccak256("OPERATOR_ROLE"));
    }

    function test_relayerRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.RELAYER_ROLE, keccak256("RELAYER_ROLE"));
    }

    function test_guardianRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.GUARDIAN_ROLE, keccak256("GUARDIAN_ROLE"));
    }

    function test_upgraderRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.UPGRADER_ROLE, keccak256("UPGRADER_ROLE"));
    }

    function test_announcerRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.ANNOUNCER_ROLE, keccak256("ANNOUNCER_ROLE"));
    }

    function test_executorRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.EXECUTOR_ROLE, keccak256("EXECUTOR_ROLE"));
    }

    function test_proposerRole_matchesKeccak() public pure {
        assertEq(ZaseonConstants.PROPOSER_ROLE, keccak256("PROPOSER_ROLE"));
    }

    /* ── Time Constants ─────────────────────────────── */

    function test_timeConstants() public pure {
        assertEq(ZaseonConstants.HOUR, 3600);
        assertEq(ZaseonConstants.DAY, 86400);
        assertEq(ZaseonConstants.WEEK, 604800);
        assertEq(ZaseonConstants.DEFAULT_CHALLENGE_PERIOD, 1 hours);
        assertEq(ZaseonConstants.FAST_CHALLENGE_WINDOW, 5 minutes);
        assertEq(ZaseonConstants.MESSAGE_EXPIRY, 24 hours);
    }

    /* ── Numeric Limits ─────────────────────────────── */

    function test_numericLimits() public pure {
        assertEq(ZaseonConstants.BASIS_POINTS, 10_000);
        assertEq(ZaseonConstants.MAX_BATCH_SIZE, 100);
        assertEq(ZaseonConstants.MAX_SCORE, 100);
    }

    /* ── Cryptographic Constants ────────────────────── */

    function test_secp256k1_order() public pure {
        // Known secp256k1 curve order
        assertEq(
            ZaseonConstants.SECP256K1_N,
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        );
    }

    function test_secp256k1_nDiv2() public pure {
        assertEq(
            ZaseonConstants.SECP256K1_N_DIV_2,
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        );
        // Verify it's actually n/2
        assertEq(
            ZaseonConstants.SECP256K1_N_DIV_2,
            ZaseonConstants.SECP256K1_N / 2
        );
    }

    /* ── Chain IDs ──────────────────────────────────── */

    function test_chainIds() public pure {
        assertEq(ZaseonConstants.CHAIN_ETHEREUM, 1);
        assertEq(ZaseonConstants.CHAIN_ARBITRUM, 42161);
        assertEq(ZaseonConstants.CHAIN_OPTIMISM, 10);
        assertEq(ZaseonConstants.CHAIN_BASE, 8453);
        assertEq(ZaseonConstants.CHAIN_POLYGON_ZKEVM, 1101);
        assertEq(ZaseonConstants.CHAIN_ZKSYNC, 324);
        assertEq(ZaseonConstants.CHAIN_SCROLL, 534352);
        assertEq(ZaseonConstants.CHAIN_LINEA, 59144);
    }

    /* ── Stake Amounts ──────────────────────────────── */

    function test_stakeAmounts() public pure {
        assertEq(ZaseonConstants.MIN_RELAYER_BOND, 1 ether);
        assertEq(ZaseonConstants.MIN_RELAYER_STAKE, 0.1 ether);
        assertEq(ZaseonConstants.MIN_CHALLENGER_STAKE, 0.05 ether);
    }

    /* ── Uniqueness of Role Constants ───────────────── */

    function test_rolesAreUnique() public pure {
        bytes32[13] memory roles = [
            ZaseonConstants.OPERATOR_ROLE,
            ZaseonConstants.RELAYER_ROLE,
            ZaseonConstants.CHALLENGER_ROLE,
            ZaseonConstants.GUARDIAN_ROLE,
            ZaseonConstants.MONITOR_ROLE,
            ZaseonConstants.RECOVERY_ROLE,
            ZaseonConstants.UPGRADER_ROLE,
            ZaseonConstants.ANNOUNCER_ROLE,
            ZaseonConstants.SEQUENCER_ROLE,
            ZaseonConstants.EMERGENCY_ROLE,
            ZaseonConstants.VERIFIER_ADMIN_ROLE,
            ZaseonConstants.EXECUTOR_ROLE,
            ZaseonConstants.PROPOSER_ROLE
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
            ZaseonConstants.STEALTH_DOMAIN != ZaseonConstants.NULLIFIER_DOMAIN
        );
        assertTrue(
            ZaseonConstants.NULLIFIER_DOMAIN != ZaseonConstants.CROSS_CHAIN_DOMAIN
        );
        assertTrue(
            ZaseonConstants.STEALTH_DOMAIN != ZaseonConstants.CROSS_CHAIN_DOMAIN
        );
    }

    /* ── Proof Type Uniqueness ──────────────────────── */

    function test_proofTypesAreUnique() public pure {
        assertTrue(
            ZaseonConstants.PROOF_TYPE_GROTH16_BLS !=
                ZaseonConstants.PROOF_TYPE_PLONK
        );
        assertTrue(
            ZaseonConstants.PROOF_TYPE_PLONK != ZaseonConstants.PROOF_TYPE_STARK
        );
        assertTrue(
            ZaseonConstants.PROOF_TYPE_GROTH16_BLS !=
                ZaseonConstants.PROOF_TYPE_STARK
        );
    }
}
