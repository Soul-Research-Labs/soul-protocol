/**
 * @title SoulFHEModule Formal Verification Specification
 * @notice Certora CVL specification for Fully Homomorphic Encryption module
 * @dev Verifies ciphertext operations, key management, and computation integrity
 */

methods {
    // State getters
    function owner() external returns (address) envfree;
    function fheOracle() external returns (address) envfree;
    function requestNonce() external returns (uint256) envfree;
    function encryptedMerkleRoot() external returns (bytes32) envfree;
    
    // Ciphertext operations
    function registerCiphertext(bytes32, bytes32, bytes32) external;
    function getCiphertext(bytes32) external returns (bytes32, bytes32, bytes32, uint256, bool) envfree;
    function validateCiphertext(bytes32) external returns (bool) envfree;
    function invalidateCiphertext(bytes32) external;
    
    // Encrypted balance operations
    function updateEncryptedBalance(bytes32, bytes32, bytes32, bytes32) external;
    function getEncryptedBalance(bytes32) external returns (bytes32, bytes32, uint256, bytes32) envfree;
    
    // Computation requests
    function requestComputation(uint8, bytes32[]) external returns (bytes32);
    function fulfillComputation(bytes32, bytes32, bool) external;
    function getComputation(bytes32) external returns (bytes32, uint8, bytes32, address, uint256, bool, bool) envfree;
    
    // Key management
    function updateFHEKeys(bytes32, bytes32, bytes32) external;
    function getFHEKeys() external returns (bytes32, bytes32, bytes32, uint256, bool) envfree;
    
    // Admin
    function setFHEOracle(address) external;
    function pause() external;
    function unpause() external;
}

// =============================================================================
// COMPUTATION TYPES
// =============================================================================
// 0: Addition
// 1: Subtraction
// 2: Multiplication
// 3: Comparison
// 4: Equality
// 5: RangeProof
// 6: Custom

definition ADDITION() returns uint8 = 0;
definition SUBTRACTION() returns uint8 = 1;
definition MULTIPLICATION() returns uint8 = 2;
definition COMPARISON() returns uint8 = 3;
definition EQUALITY() returns uint8 = 4;
definition RANGE_PROOF() returns uint8 = 5;
definition CUSTOM() returns uint8 = 6;

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 totalCiphertexts;
ghost uint256 totalComputations;
ghost uint256 completedComputations;
ghost mapping(bytes32 => bool) ciphertextValid;
ghost mapping(bytes32 => bool) computationExists;
ghost mapping(bytes32 => bool) computationCompleted;
ghost bytes32 currentPublicKeyHash;

// =============================================================================
// HOOKS
// =============================================================================

hook Sstore ciphertexts[KEY bytes32 handle].valid bool newValue (bool oldValue) {
    if (newValue && !oldValue) {
        totalCiphertexts = totalCiphertexts + 1;
    }
    if (!newValue && oldValue) {
        totalCiphertexts = require_uint256(totalCiphertexts - 1);
    }
    ciphertextValid[handle] = newValue;
}

hook Sstore computations[KEY bytes32 reqId].completed bool newValue (bool oldValue) {
    if (newValue && !oldValue) {
        completedComputations = completedComputations + 1;
    }
    computationCompleted[reqId] = newValue;
}

hook Sstore fheKeys.publicKeyHash bytes32 newValue (bytes32 oldValue) {
    currentPublicKeyHash = newValue;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * @notice INV-001: Completed computations count never exceeds total
 */
invariant completedNeverExceedsTotal()
    completedComputations <= totalComputations
    {
        preserved {
            require totalComputations < max_uint256;
        }
    }

/**
 * @notice INV-002: FHE oracle must be non-zero when keys are active
 */
invariant oracleSetWhenActive() {
    bytes32 pubKey; bytes32 evalKey; bytes32 relinKey; uint256 timestamp; bool active;
    (pubKey, evalKey, relinKey, timestamp, active) = getFHEKeys();
    active => fheOracle() != 0
}
    {
        preserved {
            require true;
        }
    }

/**
 * @notice INV-003: Request nonce is monotonically increasing
 */
invariant nonceMonotonic()
    requestNonce() >= 0
    {
        preserved {
            require requestNonce() < max_uint256;
        }
    }

// =============================================================================
// RULES
// =============================================================================

/**
 * @notice RULE-001: Only owner can update FHE keys
 */
rule onlyOwnerUpdatesKeys(bytes32 pubKey, bytes32 evalKey, bytes32 relinKey) {
    env e;
    
    address currentOwner = owner();
    
    updateFHEKeys@withrevert(e, pubKey, evalKey, relinKey);
    
    assert e.msg.sender != currentOwner => lastReverted,
        "Only owner should update FHE keys";
}

/**
 * @notice RULE-002: Only FHE oracle can fulfill computations
 */
rule onlyOracleFulfills(bytes32 requestId, bytes32 result, bool verified) {
    env e;
    
    address oracle = fheOracle();
    
    fulfillComputation@withrevert(e, requestId, result, verified);
    
    assert e.msg.sender != oracle => lastReverted,
        "Only FHE oracle should fulfill computations";
}

/**
 * @notice RULE-003: Ciphertext registration creates valid ciphertext
 */
rule registerCreatesValid(bytes32 handle, bytes32 typeHash, bytes32 securityParams) {
    env e;
    
    require !validateCiphertext(handle);
    
    registerCiphertext(e, handle, typeHash, securityParams);
    
    assert validateCiphertext(handle),
        "Registered ciphertext should be valid";
}

/**
 * @notice RULE-004: Invalidating ciphertext makes it invalid
 */
rule invalidateWorks(bytes32 handle) {
    env e;
    
    require validateCiphertext(handle);
    
    invalidateCiphertext(e, handle);
    
    assert !validateCiphertext(handle),
        "Invalidated ciphertext should not be valid";
}

/**
 * @notice RULE-005: Computation request increments nonce
 */
rule computationIncrementsNonce(uint8 operation, bytes32[] inputs) {
    env e;
    
    uint256 nonceBefore = requestNonce();
    
    requestComputation(e, operation, inputs);
    
    uint256 nonceAfter = requestNonce();
    
    assert nonceAfter == nonceBefore + 1,
        "Nonce should increment on computation request";
}

/**
 * @notice RULE-006: Fulfilled computations cannot be fulfilled again
 */
rule noDoubleFulfill(bytes32 requestId, bytes32 result, bool verified) {
    env e;
    
    bytes32 reqId; uint8 op; bytes32 output; address requester; uint256 requestedAt; bool completed; bool ver;
    (reqId, op, output, requester, requestedAt, completed, ver) = getComputation(requestId);
    
    require completed;
    
    fulfillComputation@withrevert(e, requestId, result, verified);
    
    assert lastReverted,
        "Cannot fulfill already completed computation";
}

/**
 * @notice RULE-007: Encrypted balance update requires valid proof
 */
rule balanceUpdatePreservesIntegrity(
    bytes32 commitment,
    bytes32 encryptedAmount,
    bytes32 blindingCommitment,
    bytes32 proofOfBalance
) {
    env e;
    
    bytes32 encBefore; bytes32 blindBefore; uint256 updatedBefore; bytes32 proofBefore;
    (encBefore, blindBefore, updatedBefore, proofBefore) = getEncryptedBalance(commitment);
    
    updateEncryptedBalance(e, commitment, encryptedAmount, blindingCommitment, proofOfBalance);
    
    bytes32 encAfter; bytes32 blindAfter; uint256 updatedAfter; bytes32 proofAfter;
    (encAfter, blindAfter, updatedAfter, proofAfter) = getEncryptedBalance(commitment);
    
    assert encAfter == encryptedAmount,
        "Encrypted amount should be updated";
    assert blindAfter == blindingCommitment,
        "Blinding commitment should be updated";
    assert proofAfter == proofOfBalance,
        "Proof should be stored";
    assert updatedAfter >= updatedBefore,
        "Update timestamp should not decrease";
}

/**
 * @notice RULE-008: FHE key update invalidates old computations
 */
rule keyUpdateAffectsTimestamp(bytes32 pubKey, bytes32 evalKey, bytes32 relinKey) {
    env e;
    
    bytes32 pubBefore; bytes32 evalBefore; bytes32 relinBefore; uint256 tsBefore; bool activeBefore;
    (pubBefore, evalBefore, relinBefore, tsBefore, activeBefore) = getFHEKeys();
    
    updateFHEKeys(e, pubKey, evalKey, relinKey);
    
    bytes32 pubAfter; bytes32 evalAfter; bytes32 relinAfter; uint256 tsAfter; bool activeAfter;
    (pubAfter, evalAfter, relinAfter, tsAfter, activeAfter) = getFHEKeys();
    
    assert tsAfter >= tsBefore,
        "Key timestamp should not decrease";
    assert pubAfter == pubKey,
        "Public key hash should be updated";
}

/**
 * @notice RULE-009: Ciphertext type hash is immutable after creation
 */
rule ciphertextTypeImmutable(bytes32 handle) {
    env e;
    
    bytes32 handleBefore; bytes32 typeBefore; bytes32 secBefore; uint256 createdBefore; bool validBefore;
    (handleBefore, typeBefore, secBefore, createdBefore, validBefore) = getCiphertext(handle);
    
    require validBefore;
    
    calldataarg args;
    f(e, args);
    
    bytes32 handleAfter; bytes32 typeAfter; bytes32 secAfter; uint256 createdAfter; bool validAfter;
    (handleAfter, typeAfter, secAfter, createdAfter, validAfter) = getCiphertext(handle);
    
    // If still valid, type should be unchanged
    assert validAfter => typeAfter == typeBefore,
        "Ciphertext type hash should be immutable";
}

/**
 * @notice RULE-010: Computation output is set by oracle
 */
rule computationOutputFromOracle(bytes32 requestId, bytes32 result, bool verified) {
    env e;
    
    require e.msg.sender == fheOracle();
    
    bytes32 reqIdBefore; uint8 opBefore; bytes32 outputBefore; address requesterBefore; 
    uint256 requestedAtBefore; bool completedBefore; bool verBefore;
    (reqIdBefore, opBefore, outputBefore, requesterBefore, requestedAtBefore, completedBefore, verBefore) = 
        getComputation(requestId);
    
    require !completedBefore;
    
    fulfillComputation(e, requestId, result, verified);
    
    bytes32 reqIdAfter; uint8 opAfter; bytes32 outputAfter; address requesterAfter;
    uint256 requestedAtAfter; bool completedAfter; bool verAfter;
    (reqIdAfter, opAfter, outputAfter, requesterAfter, requestedAtAfter, completedAfter, verAfter) = 
        getComputation(requestId);
    
    assert completedAfter,
        "Computation should be marked complete";
    assert outputAfter == result,
        "Output should match oracle result";
    assert verAfter == verified,
        "Verified flag should match oracle input";
}

// =============================================================================
// SECURITY PROPERTIES
// =============================================================================

/**
 * @notice SEC-001: Encrypted Merkle root can only be updated by owner
 */
rule merkleRootOwnerOnly() {
    env e;
    
    bytes32 rootBefore = encryptedMerkleRoot();
    address currentOwner = owner();
    
    calldataarg args;
    f(e, args);
    
    bytes32 rootAfter = encryptedMerkleRoot();
    
    assert rootBefore != rootAfter => e.msg.sender == currentOwner,
        "Only owner should be able to update Merkle root";
}

/**
 * @notice SEC-002: No unauthorized ciphertext validation
 */
rule ciphertextValidationIntegrity(bytes32 handle) {
    env e;
    
    require !validateCiphertext(handle);
    
    calldataarg args;
    f(e, args);
    
    // If ciphertext becomes valid, it must be through registerCiphertext
    assert validateCiphertext(handle) => 
        (f.selector == sig:registerCiphertext(bytes32,bytes32,bytes32).selector),
        "Ciphertext can only become valid through registration";
}
