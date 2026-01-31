// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract PQCRegistry is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    enum PQCPrimitive { None, Dilithium3, Dilithium5, SPHINCSPlus128s, SPHINCSPlus128f, SPHINCSPlus256s, SPHINCSPlus256f, Kyber512, Kyber768, Kyber1024 }
    enum TransitionPhase { ClassicalOnly, HybridOptional, HybridMandatory, PQPreferred, PQOnly }

    struct AccountPQConfig {
        bytes32 signatureKeyHash;
        bytes32 kemKeyHash;
        uint64 registeredAt;
        PQCPrimitive signatureAlgorithm;
        PQCPrimitive kemAlgorithm;
        bool hybridEnabled;
        bool isActive;
    }

    struct PQCStats {
        uint256 totalAccounts;
        uint256 dilithiumAccounts;
        uint256 sphincsAccounts;
        uint256 kyberAccounts;
        uint256 totalSignatureVerifications;
        uint256 totalKeyEncapsulations;
        uint256 hybridVerifications;
    }

    TransitionPhase public currentPhase;
    mapping(address => AccountPQConfig) public accountConfigs;
    mapping(PQCPrimitive => bool) public supportedPrimitives;
    PQCStats public stats;
    PQCPrimitive public recommendedSignature;
    PQCPrimitive public recommendedKEM;

    event VerifierUpdated(string indexed verifierType, address indexed newAddress);
    event PhaseTransition(TransitionPhase indexed oldPhase, TransitionPhase indexed newPhase);
    event AccountConfigured(address indexed account, PQCPrimitive signatureAlg, PQCPrimitive kemAlg);
    event AccountDeactivated(address indexed account);
    event PrimitiveStatusChanged(PQCPrimitive indexed primitive, bool supported);
    event RecommendationUpdated(PQCPrimitive signature, PQCPrimitive kem);

    error UnsupportedPrimitive(PQCPrimitive primitive);
    error AccountNotConfigured();
    error AccountAlreadyConfigured();
    error PhaseNotAllowed();
    error VerifierNotSet();
    error HybridRequired();
    error InvalidConfiguration();
    error InvalidPhaseTransition();
    error InvalidSignatureLength();

    constructor(address, address, address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function configureAccount(PQCPrimitive s, PQCPrimitive k, bytes32 sh, bytes32 kh, bool h) external {
        accountConfigs[msg.sender] = AccountPQConfig(sh, kh, uint64(block.timestamp), s, k, h, true);
    }
    function updateAccount(PQCPrimitive s, PQCPrimitive k, bytes32 sh, bytes32 kh, bool h) external {
         accountConfigs[msg.sender] = AccountPQConfig(sh, kh, uint64(block.timestamp), s, k, h, true);
    }
    function deactivateAccount() external { accountConfigs[msg.sender].isActive = false; }
    function verifySignature(address, bytes32, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function verifyHybridSignature(address, bytes32, bytes calldata, bytes calldata, bytes calldata) external returns (bool) { return true; }
    function initiateKeyExchange(address) external returns (bytes32, bytes memory) { return (bytes32(0), new bytes(0)); }
    function setDilithiumVerifier(address) external {}
    function setSPHINCSVerifier(address) external {}
    function setKyberKEM(address) external {}
    function transitionPhase(TransitionPhase) external {}
    function setPrimitiveSupport(PQCPrimitive, bool) external {}
    function setRecommendations(PQCPrimitive, PQCPrimitive) external {}
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
    function getAccountConfig(address a) external view returns (AccountPQConfig memory) { return accountConfigs[a]; }
    function isPQCEnabled(address a) external view returns (bool) { return accountConfigs[a].isActive; }
    function getStats() external view returns (PQCStats memory) { return stats; }
    function getRecommendedConfig() external view returns (PQCPrimitive, PQCPrimitive, bool) { return (recommendedSignature, recommendedKEM, true); }
    function allowsClassicalOnly() external view returns (bool) { return true; }
}
