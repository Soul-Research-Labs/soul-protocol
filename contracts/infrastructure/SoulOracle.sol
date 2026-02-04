// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SoulOracle
/// @notice Oracle for price feeds and cross-chain data
contract SoulOracle {
    error NotImplemented();

    // ...oracle logic...

    function setPrice(bytes32 asset, uint256 price) external {
        // ...implementation...
    }

    function getPrice(bytes32 /* asset */) external pure returns (uint256) {
        // ...implementation...
        // SECURITY: Revert instead of returning 0
        revert NotImplemented();
    }
}
