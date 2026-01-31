// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
contract MockStarknetMessaging {
    function sendMessageToL2(uint256, uint256, uint256[] calldata) external returns (bytes32) { return bytes32(0); }
    function consumeMessageFromL2(uint256, uint256[] calldata) external returns (bytes32) { return bytes32(0); }
}
