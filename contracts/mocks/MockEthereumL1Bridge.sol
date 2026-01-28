// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../crosschain/EthereumL1Bridge.sol";

/**
 * @title MockEthereumL1Bridge
 * @notice Mock bridge to simulate blob hash return values for testing
 */
contract MockEthereumL1Bridge is EthereumL1Bridge {
    bytes32 public mockBlobHash;
    
    function setMockBlobHash(bytes32 _hash) external {
        mockBlobHash = _hash;
    }
    
    function _getBlobHash(uint256 /* index */) internal view override returns (bytes32) {
        if (mockBlobHash != bytes32(0)) {
            return mockBlobHash;
        }
        return bytes32(0);
    }
}
