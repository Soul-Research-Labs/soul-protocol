// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
contract ConfidentialStateContainer {
    address public immutable admin;
    address public immutable verifier;
    bool public deprecated;

    constructor(address _verifier) {
        admin = msg.sender;
        verifier = _verifier;
    }

    function setDeprecated(bool _deprecated) external {}
    function registerState(bytes calldata, bytes32, bytes32, bytes calldata, bytes calldata) external {}
    function transferState(bytes32, bytes calldata, bytes32, bytes32, bytes calldata, bytes calldata, address) external {}
}
