// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// STUB for coverage only
contract BitcoinHTLC is ReentrancyGuard {
    struct Swap {
        bytes32 swapId;
        address sender;
        address recipient;
        uint256 amount;
        bytes32 hashlock;
        uint256 timelock;
        bytes32 preimage;
        bool redeemed;
        bool refunded;
    }

    mapping(bytes32 => Swap) public swaps;
    mapping(address => bytes32[]) public userSwapsAsSender;
    mapping(address => bytes32[]) public userSwapsAsRecipient;
    uint256 public totalSwaps;
    uint256 public totalVolume;
    uint256 public totalRedeemed;
    uint256 public totalRefunded;

    function createSwap(address, bytes32, uint256) external payable returns (bytes32) { return bytes32(0); }
    function redeem(bytes32, bytes32) external {}
    function refund(bytes32) external {}
    function getSwap(bytes32) external view returns (Swap memory) { return swaps[bytes32(0)]; }
    function getUserSwapsAsSender(address) external view returns (bytes32[] memory) { return new bytes32[](0); }
    function getUserSwapsAsRecipient(address) external view returns (bytes32[] memory) { return new bytes32[](0); }
    function isSwapRedeemable(bytes32) external view returns (bool) { return true; }
    function isSwapRefundable(bytes32) external view returns (bool) { return false; }
    function getStats() external view returns (uint256, uint256, uint256, uint256) { return (0, 0, 0, 0); }
    function computeHashlock(bytes32) external pure returns (bytes32) { return bytes32(0); }
}
