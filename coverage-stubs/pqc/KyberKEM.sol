// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// STUB for coverage only
contract KyberKEM is Ownable {
    enum KyberVariant { Kyber512, Kyber768, Kyber1024 }

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidCiphertextSize(uint256 expected, uint256 actual);
    error KeyNotRegistered();
    error KeyAlreadyRegistered();
    error ExchangeNotFound();
    error ExchangeAlreadyCompleted();
    error PrecompileCallFailed();
    error SharedSecretMismatch();

    struct KyberKeyPair {
        bytes32 publicKeyHash;
        KyberVariant variant;
        uint64 registeredAt;
        bool isActive;
    }

    struct Encapsulation {
        bytes ciphertext;
        bytes32 sharedSecretHash;
        KyberVariant variant;
        uint64 timestamp;
    }

    mapping(address => KyberKeyPair) public registeredKeys;
    mapping(bytes32 => Encapsulation) public pendingEncapsulations;
    mapping(bytes32 => bool) public completedExchanges;
    bool public useMockMode;

    constructor() Ownable(msg.sender) {}

    function registerPublicKey(bytes calldata, KyberVariant) external {}
    function revokeKey() external {}
    function encapsulate(address, bytes32) external returns (bytes32, bytes memory, bytes32) { 
        return (bytes32(0), new bytes(0), bytes32(0)); 
    }
    function confirmDecapsulation(bytes32, bytes32) external {}
    function setMockMode(bool) external {}
    
    function getKeyInfo(address owner) external view returns (KyberKeyPair memory) {
        return registeredKeys[owner];
    }
    function getPublicKey(address) external view returns (bytes memory) { return new bytes(0); }
    function getEncapsulation(bytes32 id) external view returns (Encapsulation memory) { return pendingEncapsulations[id]; }
    function isExchangeCompleted(bytes32 id) external view returns (bool) { return completedExchanges[id]; }
    function getSizes(KyberVariant) external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }
}
