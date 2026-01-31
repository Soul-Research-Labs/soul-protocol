// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// STUB for coverage only
contract PQCProtectedLock is AccessControl, Pausable, ReentrancyGuard {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    uint256 public constant PQC_THRESHOLD_VALUE = 10 ether;
    uint64 public constant PQC_THRESHOLD_DURATION = 30 days;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant UNLOCK_TYPEHASH = keccak256("UnlockAuthorization(bytes32 lockId,address recipient,uint256 nonce,uint256 deadline)");

    address public pqcRegistry;
    address public zkSlocks;
    bool public pqcMandatoryForHighValue;

    enum PQCPrimitive { Dilithium3, Dilithium5, SPHINCS_128s, SPHINCS_256s }

    struct PQCLockConfig { bytes32 pqPublicKeyHash; PQCPrimitive algorithm; bool requireHybrid; bool requirePQOnly; uint64 pqRegisteredAt; uint256 recoveryDelay; }
    mapping(bytes32 => PQCLockConfig) public lockPQCConfigs;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => uint256) public lockValues;
    mapping(bytes32 => uint256) public pendingRecoveries;

    struct UnlockAuth { bytes32 lockId; address recipient; uint256 deadline; bytes classicalSig; bytes pqSignature; bytes pqPublicKey; }

    event PQCConfigured(bytes32 indexed lockId, bytes32 indexed pqPublicKeyHash, PQCPrimitive algorithm, bool requireHybrid);
    event PQCUnlockVerified(bytes32 indexed lockId, address indexed unlocker, bool hybridVerified);
    event EmergencyRecoveryInitiated(bytes32 indexed lockId, address indexed initiator, uint256 executeAfter);
    event EmergencyRecoveryExecuted(bytes32 indexed lockId, address indexed recipient);
    event EmergencyRecoveryCancelled(bytes32 indexed lockId);

    constructor(address _pqcRegistry, address _zkSlocks) {
        pqcRegistry = _pqcRegistry;
        zkSlocks = _zkSlocks;
        DOMAIN_SEPARATOR = keccak256("STUB");
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function configurePQC(bytes32 id, bytes calldata k, PQCPrimitive a, bool h, uint256 d) external {
        lockPQCConfigs[id] = PQCLockConfig(keccak256(k), a, h, false, uint64(block.timestamp), d);
        emit PQCConfigured(id, keccak256(k), a, h);
    }
    function configureNewLockPQC(bytes32 id, uint256 v, bytes calldata k, PQCPrimitive a) external {
        lockValues[id] = v;
        lockPQCConfigs[id] = PQCLockConfig(keccak256(k), a, true, false, uint64(block.timestamp), 7 days);
        emit PQCConfigured(id, keccak256(k), a, true);
    }
    function verifyUnlockAuth(UnlockAuth calldata) public returns (bool) { return true; }
    function executeHybridUnlock(UnlockAuth calldata) external {}
    function initiateRecovery(bytes32 id, bytes calldata, bytes calldata) external {
        pendingRecoveries[id] = block.timestamp + 1 days;
        emit EmergencyRecoveryInitiated(id, msg.sender, block.timestamp + 1 days);
    }
    function executeRecovery(bytes32 id, address r) external {
        delete pendingRecoveries[id];
        emit EmergencyRecoveryExecuted(id, r);
    }
    function cancelRecovery(bytes32 id, bytes calldata) external {
        delete pendingRecoveries[id];
        emit EmergencyRecoveryCancelled(id);
    }
    function hasPQCProtection(bytes32 id) external view returns (bool) { return lockPQCConfigs[id].pqPublicKeyHash != bytes32(0); }
    function getPQCConfig(bytes32 id) external view returns (PQCLockConfig memory) { return lockPQCConfigs[id]; }
    function getNonce(address a) external view returns (uint256) { return nonces[a]; }
    function isRecoveryPending(bytes32 id) external view returns (bool, uint256) { return (pendingRecoveries[id] != 0, pendingRecoveries[id]); }
    function setPQCRegistry(address a) external { pqcRegistry = a; }
    function setPQCMandatory(bool m) external { pqcMandatoryForHighValue = m; }
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
}
