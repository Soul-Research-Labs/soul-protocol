// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DenominationLadder
 * @author ZASEON
 * @notice Canonical denomination-tier library enforcing fixed amount tiers across all
 *         privacy-preserving pools (ShieldedPool, CrossChainPrivacyHub, BatchAccumulator,
 *         DelayedClaimVault). Fixed tiers defeat amount-based de-anonymization attacks by
 *         collapsing the amount distribution to a small discrete set.
 *
 * @dev Design:
 *  - Native ladder: {0.01, 0.1, 1, 10, 100} ether (Tornado-style, plus 0.01 for small txs)
 *  - ERC20 ladder: same magnitudes scaled by {1e6, 1e8, 1e18} depending on token decimals
 *  - Exposed as pure functions so callers can enforce tiers at entry and/or validate on-chain
 *  - `isNativeTier` / `isErc20Tier` return bool for cheap guards
 *  - `tierIndex` returns a compact 0..4 index (or 0xff if not a tier) for event emission /
 *    commitment binding
 *
 *  Upstream contracts MUST call {requireNativeTier} or {requireErc20Tier} before accepting
 *  deposits. Encrypting the tier index into commitments (instead of raw amount) further
 *  reduces metadata leakage.
 */
library DenominationLadder {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Sentinel returned by {tierIndex} / {erc20TierIndex} for amounts not on the ladder.
    uint8 internal constant INVALID_TIER = type(uint8).max;

    /// @dev Number of tiers.
    uint8 internal constant TIER_COUNT = 5;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an amount does not match any tier on the ladder.
    error NotADenominationTier(uint256 amount);

    /*//////////////////////////////////////////////////////////////
                             NATIVE LADDER
    //////////////////////////////////////////////////////////////*/

    /// @notice Return the native-asset amount for tier index `i` (0..4).
    /// @dev Tiers: 0=0.01e, 1=0.1e, 2=1e, 3=10e, 4=100e
    function nativeTierAmount(uint8 i) internal pure returns (uint256) {
        if (i == 0) return 0.01 ether;
        if (i == 1) return 0.1 ether;
        if (i == 2) return 1 ether;
        if (i == 3) return 10 ether;
        if (i == 4) return 100 ether;
        revert NotADenominationTier(uint256(i));
    }

    /// @notice Returns tier index for `amount`, or {INVALID_TIER} if not on ladder.
    function tierIndex(uint256 amount) internal pure returns (uint8) {
        // Branchless comparison chain; each tier is distinct so ordering is safe.
        if (amount == 0.01 ether) return 0;
        if (amount == 0.1 ether) return 1;
        if (amount == 1 ether) return 2;
        if (amount == 10 ether) return 3;
        if (amount == 100 ether) return 4;
        return INVALID_TIER;
    }

    /// @notice True if `amount` is a valid native-asset tier.
    function isNativeTier(uint256 amount) internal pure returns (bool) {
        return tierIndex(amount) != INVALID_TIER;
    }

    /// @notice Revert if `amount` is not a valid native tier.
    function requireNativeTier(uint256 amount) internal pure returns (uint8) {
        uint8 idx = tierIndex(amount);
        if (idx == INVALID_TIER) revert NotADenominationTier(amount);
        return idx;
    }

    /*//////////////////////////////////////////////////////////////
                              ERC20 LADDER
    //////////////////////////////////////////////////////////////*/

    /// @notice Return the ERC20 tier amount for tier index `i` given `decimals`.
    /// @dev Ladder is magnitude-only; decimal scaling delegates to the token's own unit.
    ///      Tiers map to: 0=0.01, 1=0.1, 2=1, 3=10, 4=100 (whole-unit equivalents).
    ///
    /// SECURITY (L-2): Tokens with fewer than 2 decimals cannot represent the
    /// 0.01-unit tier without truncating to zero, and tokens with 0 decimals
    /// also cannot represent the 0.1-unit tier. We revert explicitly rather
    /// than silently return a tier amount of zero (which would let callers
    /// appear to "deposit the 0.01 tier" by transferring nothing).
    function erc20TierAmount(
        uint8 i,
        uint8 decimals
    ) internal pure returns (uint256) {
        if (i == 0 && decimals < 2) {
            revert NotADenominationTier(uint256(i));
        }
        if (i == 1 && decimals < 1) {
            revert NotADenominationTier(uint256(i));
        }
        uint256 unit = 10 ** uint256(decimals);
        if (i == 0) return unit / 100; // 0.01
        if (i == 1) return unit / 10; // 0.1
        if (i == 2) return unit; // 1
        if (i == 3) return unit * 10; // 10
        if (i == 4) return unit * 100; // 100
        revert NotADenominationTier(uint256(i));
    }

    /// @notice Returns tier index for ERC20 `amount` at `decimals`, or {INVALID_TIER}.
    function erc20TierIndex(
        uint256 amount,
        uint8 decimals
    ) internal pure returns (uint8) {
        uint256 unit = 10 ** uint256(decimals);
        if (amount == unit / 100) return 0;
        if (amount == unit / 10) return 1;
        if (amount == unit) return 2;
        if (amount == unit * 10) return 3;
        if (amount == unit * 100) return 4;
        return INVALID_TIER;
    }

    /// @notice True if `amount` is a valid ERC20 tier at `decimals`.
    function isErc20Tier(
        uint256 amount,
        uint8 decimals
    ) internal pure returns (bool) {
        return erc20TierIndex(amount, decimals) != INVALID_TIER;
    }

    /// @notice Revert if `amount` is not a valid ERC20 tier at `decimals`.
    function requireErc20Tier(
        uint256 amount,
        uint8 decimals
    ) internal pure returns (uint8) {
        uint8 idx = erc20TierIndex(amount, decimals);
        if (idx == INVALID_TIER) revert NotADenominationTier(amount);
        return idx;
    }
}
