// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// STUB for coverage only
contract SPHINCSPlusVerifier is Ownable {
    enum SPHINCSVariant { SPHINCS_128s, SPHINCS_128f, SPHINCS_256s, SPHINCS_256f }

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 minExpected, uint256 actual);
    error PrecompileCallFailed();
    error UnsupportedVariant();

    uint256 public constant SPHINCS_128S_PK_SIZE = 32;
    uint256 public constant SPHINCS_128S_SIG_SIZE = 7856;
    uint256 public constant SPHINCS_128F_SIG_SIZE = 17088;
    uint256 public constant SPHINCS_256S_PK_SIZE = 64;
    uint256 public constant SPHINCS_256S_SIG_SIZE = 29792;
    uint256 public constant SPHINCS_256F_SIG_SIZE = 49856;

    address public constant SPHINCS_PRECOMSoulE = address(0x0E);
    bool public useMockVerification;
    mapping(bytes32 => bool) public trustedKeyHashes;
    mapping(bytes32 => bool) public preVerified;

    event SPHINCSVerified(bytes32 indexed messageHash, bytes32 indexed publicKeyHash, SPHINCSVariant variant, bool valid);
    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);

    constructor() Ownable(msg.sender) {
        useMockVerification = true;
    }

    function verify(bytes32, bytes calldata, bytes calldata, SPHINCSVariant) external returns (bool) { return true; }
    function verifySPHINCS128s(bytes32, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function verifySPHINCS256s(bytes32, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function setMockMode(bool) external {}
    function addTrustedKey(bytes32) external {}
    function removeTrustedKey(bytes32) external {}
    function addPreVerified(bytes32, bytes32, bytes32) external {}
    function getExpectedSizes(SPHINCSVariant) external pure returns (uint256, uint256) { return (0, 0); }
    function isKeyTrusted(bytes calldata) external view returns (bool) { return false; }
    function estimateGas(SPHINCSVariant) external pure returns (uint256) { return 0; }
}
