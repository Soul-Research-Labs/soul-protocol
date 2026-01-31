// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// STUB for coverage only
contract DilithiumVerifier is Ownable {
    enum DilithiumLevel {
        Level3,
        Level5
    }

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 expected, uint256 actual);
    error PrecompileCallFailed();
    error InvalidSecurityLevel();
    error ArrayLengthMismatch();

    uint256 public constant DILITHIUM3_PK_SIZE = 1952;
    uint256 public constant DILITHIUM3_SIG_SIZE = 3293;
    uint256 public constant DILITHIUM5_PK_SIZE = 2592;
    uint256 public constant DILITHIUM5_SIG_SIZE = 4595;

    bool public useMockVerification;
    mapping(bytes32 => bool) public mockResults;
    mapping(bytes32 => bool) public trustedKeyHashes;
    uint256 public gasOverride;

    constructor() Ownable(msg.sender) {}

    function verifyDilithium3(bytes32, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function verifyDilithium5(bytes32, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function verify(bytes32, bytes calldata, bytes calldata, DilithiumLevel) external returns (bool) { return true; }
    function batchVerify(bytes32[] calldata, bytes[] calldata, bytes[] calldata, DilithiumLevel[] calldata) external returns (bool) { return true; }

    function setMockMode(bool) external {}
    function setMockResult(bytes32, bytes32, bytes32, bool) external {}
    function addTrustedKey(bytes32) external {}
    function removeTrustedKey(bytes32) external {}
    function setGasOverride(uint256) external {}
    
    function getExpectedSizes(DilithiumLevel) external pure returns (uint256, uint256) { return (0, 0); }
    function isKeyTrusted(bytes calldata) external view returns (bool) { return false; }
    function estimateGas(DilithiumLevel) external pure returns (uint256) { return 0; }
}
