// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockStarknetMessaging {
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32, uint256) {
        return (keccak256(abi.encode(toAddress, selector, payload)), 0);
    }

    function consumeMessageFromL2(
        uint256 fromAddress,
        uint256[] calldata payload
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(fromAddress, payload));
    }
}
