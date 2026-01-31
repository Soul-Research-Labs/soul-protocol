// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// STUB for coverage only
contract EthereumL1Bridge is AccessControl, ReentrancyGuard {
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _getBlobHash(uint256) internal view virtual returns (bytes32) { return bytes32(0); }
    function depositETH(uint256, address) external payable {}
    function withdrawETH(uint256, address, bytes32) external {}
}
