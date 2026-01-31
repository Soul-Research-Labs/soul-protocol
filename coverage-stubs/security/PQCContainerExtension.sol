// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// STUB for coverage only
contract PQCContainerExtension is AccessControl, ReentrancyGuard {
    enum PQCScheme { Dilithium2, Dilithium3, Dilithium5, Kyber512, Kyber768, Kyber1024, SPHINCS_PLUS }

    struct PQCSignature {
        PQCScheme scheme;
        bytes signature;
        bytes32 publicKeyHash;
    }

    mapping(bytes32 => PQCSignature) public extraSignatures;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function attachPQCSignature(bytes32, PQCScheme, bytes calldata, bytes32) external {}
    function verifyPQCSignature(bytes32, bytes32) external view returns (bool) { return true; }
}
