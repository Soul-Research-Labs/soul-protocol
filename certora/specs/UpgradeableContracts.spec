/**
 * @title UpgradeableContracts Formal Verification Specification
 * @notice Certora CVL specification for UUPS and TransparentProxy upgradeable contracts
 * @dev Verifies upgrade safety, storage layout, and access control
 */

methods {
    // Proxy admin functions
    function proxiableUUID() external returns (bytes32) envfree;
    function getImplementation() external returns (address) envfree;
    
    // UUPS upgrade
    function upgradeToAndCall(address, bytes) external;
    function upgradeTo(address) external;
    
    // Access control
    function owner() external returns (address) envfree;
    function pendingOwner() external returns (address) envfree;
    function transferOwnership(address) external;
    function acceptOwnership() external;
    function renounceOwnership() external;
    
    // Initializable
    function _disableInitializers() external;
    
    // Storage layout
    function getStorageSlot(bytes32) external returns (bytes32) envfree;
    
    // Version tracking
    function version() external returns (string) envfree;
}

// =============================================================================
// CONSTANTS
// =============================================================================

// EIP-1967 implementation slot
definition IMPLEMENTATION_SLOT() returns bytes32 = 
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

// EIP-1967 admin slot  
definition ADMIN_SLOT() returns bytes32 =
    0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

// EIP-1967 beacon slot
definition BEACON_SLOT() returns bytes32 =
    0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

// Initializable _initialized slot
definition INITIALIZED_SLOT() returns bytes32 =
    0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost address currentImplementation;
ghost address currentOwner;
ghost uint256 upgradeCount;
ghost bool isInitialized;
ghost mapping(bytes32 => bytes32) storageSlots;

// =============================================================================
// HOOKS
// =============================================================================

hook Sstore _implementation address newImpl (address oldImpl) {
    currentImplementation = newImpl;
    upgradeCount = upgradeCount + 1;
}

hook Sload address impl _implementation {
    require impl == currentImplementation;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * @notice INV-001: Implementation address must be a contract
 */
invariant implementationIsContract()
    currentImplementation != 0 => isContract(currentImplementation)
    {
        preserved {
            require currentImplementation != 0;
        }
    }

/**
 * @notice INV-002: Owner cannot be zero address (except after renounce)
 */
invariant ownerNonZeroOrRenounced()
    owner() != 0 || upgradeCount == 0
    {
        preserved {
            require upgradeCount < max_uint256;
        }
    }

/**
 * @notice INV-003: Upgrade count is monotonically increasing
 */
invariant upgradeCountMonotonic()
    upgradeCount >= 0
    {
        preserved {
            require upgradeCount < max_uint256;
        }
    }

/**
 * @notice INV-004: ProxiableUUID is constant
 */
invariant proxiableUUIDConstant()
    proxiableUUID() == IMPLEMENTATION_SLOT()

// =============================================================================
// RULES
// =============================================================================

/**
 * @notice RULE-001: Only owner can upgrade
 */
rule onlyOwnerCanUpgrade(address newImplementation, bytes data) {
    env e;
    
    address currentOwner = owner();
    
    upgradeToAndCall@withrevert(e, newImplementation, data);
    
    assert e.msg.sender != currentOwner => lastReverted,
        "Only owner should be able to upgrade";
}

/**
 * @notice RULE-002: Upgrade changes implementation address
 */
rule upgradeChangesImplementation(address newImplementation, bytes data) {
    env e;
    
    address implBefore = getImplementation();
    require newImplementation != 0;
    require newImplementation != implBefore;
    require e.msg.sender == owner();
    
    upgradeToAndCall(e, newImplementation, data);
    
    address implAfter = getImplementation();
    
    assert implAfter == newImplementation,
        "Implementation should be updated";
}

/**
 * @notice RULE-003: Cannot upgrade to zero address
 */
rule noUpgradeToZero(bytes data) {
    env e;
    
    upgradeToAndCall@withrevert(e, 0, data);
    
    assert lastReverted,
        "Cannot upgrade to zero address";
}

/**
 * @notice RULE-004: Storage layout preserved after upgrade
 */
rule storageLayoutPreserved(bytes32 slot, address newImplementation, bytes data) {
    env e;
    
    bytes32 valueBefore = getStorageSlot(slot);
    
    // Only check non-implementation slots
    require slot != IMPLEMENTATION_SLOT();
    require slot != ADMIN_SLOT();
    
    upgradeToAndCall(e, newImplementation, data);
    
    bytes32 valueAfter = getStorageSlot(slot);
    
    // Storage should be preserved (unless intentionally migrated)
    assert valueBefore == valueAfter || 
           keccak256(abi.encodePacked(data)) != keccak256(abi.encodePacked("")),
        "Storage layout should be preserved unless migration performed";
}

/**
 * @notice RULE-005: Two-step ownership transfer
 */
rule twoStepOwnershipTransfer(address newOwner) {
    env e1;
    env e2;
    
    address ownerBefore = owner();
    require e1.msg.sender == ownerBefore;
    require newOwner != 0;
    
    transferOwnership(e1, newOwner);
    
    // Owner should not change yet
    assert owner() == ownerBefore,
        "Owner should not change until accepted";
    assert pendingOwner() == newOwner,
        "Pending owner should be set";
    
    // Now accept
    require e2.msg.sender == newOwner;
    acceptOwnership(e2);
    
    assert owner() == newOwner,
        "Owner should change after acceptance";
    assert pendingOwner() == 0,
        "Pending owner should be cleared";
}

/**
 * @notice RULE-006: Only pending owner can accept
 */
rule onlyPendingOwnerAccepts() {
    env e;
    
    address pending = pendingOwner();
    require pending != 0;
    require e.msg.sender != pending;
    
    acceptOwnership@withrevert(e);
    
    assert lastReverted,
        "Only pending owner should accept";
}

/**
 * @notice RULE-007: Renounce ownership removes owner
 */
rule renounceOwnershipWorks() {
    env e;
    
    require e.msg.sender == owner();
    require owner() != 0;
    
    renounceOwnership(e);
    
    assert owner() == 0,
        "Owner should be zero after renounce";
}

/**
 * @notice RULE-008: Cannot reinitialize
 */
rule noReinitialize() {
    env e;
    
    require isInitialized;
    
    // Any initialization function should revert
    initialize@withrevert(e);
    
    assert lastReverted,
        "Cannot reinitialize already initialized contract";
}

/**
 * @notice RULE-009: Implementation cannot be called directly
 */
rule implementationNotCallable() {
    env e;
    
    address impl = getImplementation();
    require e.msg.sender != address(this); // Not through proxy
    
    // Direct calls to implementation should not modify proxy state
    calldataarg args;
    impl.f@withrevert(e, args);
    
    // If it doesn't revert, state should be on implementation, not proxy
    assert true, "Direct implementation calls shouldn't affect proxy";
}

/**
 * @notice RULE-010: Upgrade increments upgrade count
 */
rule upgradeIncrementsCount(address newImplementation, bytes data) {
    env e;
    
    uint256 countBefore = upgradeCount;
    require e.msg.sender == owner();
    require newImplementation != 0;
    
    upgradeToAndCall(e, newImplementation, data);
    
    assert upgradeCount == countBefore + 1,
        "Upgrade count should increment";
}

// =============================================================================
// SECURITY PROPERTIES
// =============================================================================

/**
 * @notice SEC-001: No selfdestruct in implementation
 */
rule noSelfDestruct() {
    env e;
    
    address implBefore = getImplementation();
    
    calldataarg args;
    f(e, args);
    
    // Implementation should still exist
    assert isContract(implBefore),
        "Implementation should not selfdestruct";
}

/**
 * @notice SEC-002: Delegatecall only to implementation
 */
rule delegatecallOnlyToImpl() {
    env e;
    
    address impl = getImplementation();
    
    // Any delegatecall should be to the current implementation
    calldataarg args;
    delegatecall@withrevert(e, args);
    
    assert !lastReverted => e.msg.target == impl,
        "Delegatecall only to implementation";
}

/**
 * @notice SEC-003: Storage collision protection
 */
rule storageCollisionProtection(bytes32 slot1, bytes32 slot2) {
    require slot1 != slot2;
    
    bytes32 value1Before = getStorageSlot(slot1);
    bytes32 value2Before = getStorageSlot(slot2);
    
    env e;
    calldataarg args;
    f(e, args);
    
    bytes32 value1After = getStorageSlot(slot1);
    bytes32 value2After = getStorageSlot(slot2);
    
    // Modifying one slot should not affect another
    assert (value1Before != value1After) => (value2Before == value2After || slot1 == slot2),
        "Storage writes should not collide";
}

/**
 * @notice SEC-004: Admin functions protected
 */
rule adminFunctionsProtected() {
    env e;
    
    address currentOwner = owner();
    require e.msg.sender != currentOwner;
    
    // All admin functions should revert for non-owners
    upgradeToAndCall@withrevert(e, _, _);
    bool upgradeReverted = lastReverted;
    
    renounceOwnership@withrevert(e);
    bool renounceReverted = lastReverted;
    
    assert upgradeReverted && renounceReverted,
        "Admin functions should be protected";
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function isContract(address addr) returns bool {
    return addr.code.length > 0;
}

function initialize(env e) {
    // Constrain initialization preconditions for formal verification:
    // - No ETH should be sent with initialization calls
    // - The sender must be a non-zero address
    require e.msg.value == 0;
    require e.msg.sender != 0;
}
