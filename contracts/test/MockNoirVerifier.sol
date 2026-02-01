// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockNoirVerifier {
    bool public shouldFail;
    bytes32[] public lastSignals;

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return !shouldFail;
    }
}
