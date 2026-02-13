// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RateLimiter (deprecated)
/// @notice This stub is deprecated. Use contracts/security/BridgeRateLimiter.sol
///         which provides full per-user, per-chain, per-asset, and global
///         rate limiting with sliding windows, admin controls, and emergency pause.
/// @dev Kept only for interface compatibility. Will be removed in v2.
contract RateLimiter {
    /// @notice Always returns true. Not safe for production use.
    /// @dev Migrate callers to BridgeRateLimiter.checkRateLimit().
    function checkRate(
        address /* user */,
        uint256 /* chainId */
    ) external pure returns (bool) {
        return true;
    }
}
