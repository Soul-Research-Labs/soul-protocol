// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

// STUB for coverage only
contract Soulv2Orchestrator is Ownable {
    constructor() Ownable(msg.sender) {}
    function coordinate(bytes calldata data) external {}
}
