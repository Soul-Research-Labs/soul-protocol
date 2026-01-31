// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract CrossDomainNullifierAlgebra is AccessControl {
    bytes32 public constant NULLIFIER_REGISTRAR_ROLE = keccak256("NULLIFIER_REGISTRAR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function verifyNullifierAlgebra(bytes calldata) external view returns (bool) { return true; }
    
    function registerNullifier(bytes32, bytes32, bytes32, bytes32) public virtual {}
    
    function pause() external {}
    function unpause() external {}
    function deactivateDomain(bytes32) external {}
    function setEpochDuration(uint64) external {}
}
