// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract CrossDomainNullifierAlgebra is AccessControl {
    bytes32 public constant NULLIFIER_REGISTRAR_ROLE = keccak256("NULLIFIER_REGISTRAR_ROLE");
    function registerNullifier(bytes32, bytes32, bytes32, bytes32) public virtual {}
}

contract CrossDomainNullifierStarknet is CrossDomainNullifierAlgebra {
    bytes32 public latestRoot;
    function registerNullifierFromL1(bytes32, bytes32, bytes32) external {}
    function getMerkleRoot() external view returns (bytes32) { return latestRoot; }
    function getL2Nullifier(bytes32) external pure returns (uint256) { return 0; }
}
