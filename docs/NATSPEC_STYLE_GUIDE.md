# Soul Protocol - NatSpec Style Guide

> **Version:** 1.0  
> **Last Updated:** February 1, 2026

---

## Overview

This guide defines the NatSpec documentation standards for Soul Protocol smart contracts. Consistent documentation improves code readability, enables automated doc generation, and helps auditors understand contract behavior.

---

## Required Elements

### Contract-Level Documentation

Every contract MUST include:

```solidity
/**
 * @title ContractName
 * @author Soul Protocol
 * @notice Brief user-facing description of what the contract does
 * @dev Technical implementation notes for developers:
 *      - Architecture decisions
 *      - Integration points
 *      - Key invariants
 * @custom:security-contact security@soul.network
 */
contract ContractName {
    // ...
}
```

### Function Documentation

Every external/public function MUST include:

```solidity
/**
 * @notice What the function does (user-facing, plain English)
 * @dev Technical implementation details:
 *      - Algorithm used
 *      - Gas considerations
 *      - Side effects
 * @param paramName Description of the parameter
 * @param anotherParam Description of another parameter
 * @return returnName Description of what is returned
 * @custom:security Any security considerations or requirements
 */
function doSomething(
    uint256 paramName,
    address anotherParam
) external returns (bytes32 returnName);
```

### Event Documentation

Every event MUST include:

```solidity
/**
 * @notice Emitted when [specific action occurs]
 * @param indexed1 Description of first indexed parameter
 * @param indexed2 Description of second indexed parameter
 * @param data Description of non-indexed data
 */
event ActionOccurred(
    address indexed indexed1,
    bytes32 indexed indexed2,
    uint256 data
);
```

### Error Documentation

Every custom error SHOULD include:

```solidity
/**
 * @notice Thrown when [condition that triggers error]
 * @param actual The actual value that caused the error
 * @param expected The expected value
 */
error InvalidValue(uint256 actual, uint256 expected);
```

### Modifier Documentation

Every modifier MUST include:

```solidity
/**
 * @notice Ensures [condition being checked]
 * @dev Reverts with [ErrorName] if condition not met
 */
modifier onlyAuthorized() {
    // ...
}
```

---

## Examples

### Full Contract Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ZKBoundStateLocks
 * @author Soul Protocol
 * @notice Cross-chain confidential state lock manager using zero-knowledge proofs
 * @dev Core primitive enabling privacy-preserving cross-chain state transfers.
 *      Implements the ZK-SLocks paradigm where state is locked with commitments
 *      and unlocked with ZK proofs of valid state transitions.
 *
 *      Architecture:
 *      - Locks bound to state commitments (not addresses)
 *      - Unlocks require ZK proof of valid transition
 *      - Cross-domain nullifiers prevent replay attacks
 *      - Optimistic dispute resolution for race conditions
 *
 *      Integration:
 *      - Uses CDNA for cross-domain nullifier generation
 *      - Integrates with PC³ for self-authenticating containers
 *      - Compatible with PBP policy enforcement
 *
 * @custom:security-contact security@soul.network
 */
contract ZKBoundStateLocks is AccessControl {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Thrown when attempting to create a lock that already exists
     * @param lockId The ID of the existing lock
     */
    error LockAlreadyExists(bytes32 lockId);

    /**
     * @notice Thrown when lock has expired and cannot be unlocked
     * @param lockId The expired lock's ID
     * @param deadline The expiration timestamp
     */
    error LockExpired(bytes32 lockId, uint256 deadline);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when a new lock is created
     * @param lockId Unique identifier for the lock
     * @param creator Address that created the lock
     * @param commitment State commitment being locked
     * @param deadline Expiration timestamp
     */
    event LockCreated(
        bytes32 indexed lockId,
        address indexed creator,
        bytes32 indexed commitment,
        uint256 deadline
    );

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of lock ID to lock data
    mapping(bytes32 => ZKSLock) public locks;

    /// @notice Registry of used nullifiers (prevents double-spend)
    mapping(bytes32 => bool) public nullifierUsed;

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a new ZK-bound state lock
     * @dev The lock binds a state commitment to a transition predicate.
     *      Only ZK proofs satisfying the predicate can unlock the state.
     *      
     *      Gas: ~50,000 for basic lock, ~80,000 with policy binding
     *      
     *      Emits {LockCreated} on success.
     *
     * @param oldStateCommitment Poseidon hash of the current confidential state
     * @param transitionPredicateHash Hash of the Noir circuit defining valid transitions
     * @param policyHash Hash of disclosure policy (0x0 for no policy)
     * @param unlockDeadline Unix timestamp after which lock expires
     * @return lockId Unique identifier for the created lock
     *
     * @custom:security Caller must be state owner or have OPERATOR_ROLE.
     *                  State commitment must not already be locked.
     */
    function createLock(
        bytes32 oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        uint64 unlockDeadline
    ) external returns (bytes32 lockId) {
        // Implementation
    }

    /**
     * @notice Unlocks a state lock with a valid ZK proof
     * @dev Verifies the ZK proof against the registered verifier,
     *      checks nullifier uniqueness, and executes the state transition.
     *      
     *      Verification flow:
     *      1. Validate proof format and lock existence
     *      2. Verify ZK proof with registered verifier
     *      3. Check nullifier not previously used
     *      4. Mark lock as unlocked and register nullifier
     *      
     *      Gas: ~200,000 - 400,000 depending on proof type
     *
     * @param proof The unlock proof containing ZK proof and metadata
     * @return receipt Unlock receipt with transition details
     *
     * @custom:security Proof verification is trustless - anyone can submit.
     *                  Nullifier prevents replay across all domains.
     */
    function unlock(
        UnlockProof calldata proof
    ) external returns (UnlockReceipt memory receipt) {
        // Implementation
    }
}
```

---

## Documentation Quality Checklist

### Contract Level
- [ ] `@title` matches contract name
- [ ] `@author` is "Soul Protocol"
- [ ] `@notice` explains purpose in plain English
- [ ] `@dev` includes architecture notes
- [ ] `@custom:security-contact` is included

### Function Level
- [ ] `@notice` explains what, not how
- [ ] `@dev` explains implementation details
- [ ] All `@param` documented
- [ ] All `@return` documented
- [ ] Security notes added where applicable

### Event Level
- [ ] `@notice` explains when emitted
- [ ] All parameters documented

---

## Solhint Configuration

Add to `.solhint.json`:

```json
{
  "extends": "solhint:recommended",
  "rules": {
    "natspec-author": "warn",
    "natspec-title": "error",
    "natspec-notice": "error",
    "natspec-dev": "warn",
    "natspec-param": "error",
    "natspec-return": "error"
  }
}
```

---

## Generating Documentation

```bash
# Generate HTML documentation
forge doc --out docs/api

# Serve documentation locally
forge doc --serve --port 4000
```

---

## Common Mistakes to Avoid

### ❌ Don't Do This

```solidity
// Too vague
/// @notice Does something
function doSomething() external;

// Missing parameters
/// @notice Transfers tokens
function transfer(address to, uint256 amount) external;

// Implementation details in @notice
/// @notice Uses assembly to optimize gas by packing storage slots
function optimizedFunction() external;
```

### ✅ Do This

```solidity
/// @notice Executes a cross-chain state transfer
/// @param to Recipient address on destination chain
/// @param amount Amount of tokens to transfer
/// @return transferId Unique identifier for tracking
function transfer(address to, uint256 amount) external returns (bytes32 transferId);
```

---

## Enforcement

1. **Pre-commit Hook**: Runs solhint NatSpec rules
2. **CI Check**: Fails PR if NatSpec coverage < 90%
3. **Code Review**: Documentation quality is reviewed
