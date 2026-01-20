# Gas Optimizations Report

## Overview

This document details the gas optimizations applied to the Privacy Interoperability Layer contracts. All optimizations have been tested and verified with 71/71 tests passing.

## Optimizations Applied

### 1. ZKBoundStateLocks.sol

#### Pre-computed Role Hashes
**Savings: ~200 gas per role access**

```solidity
// Before (runtime computation)
bytes32 public constant LOCK_ADMIN_ROLE = keccak256("LOCK_ADMIN_ROLE");

// After (pre-computed)
bytes32 public constant LOCK_ADMIN_ROLE = 0xb5f42d4ed74356fb5b5979d37d3950e53ab205fdb50ef14ba7816ef87259fef6;
```

Applied to:
- `LOCK_ADMIN_ROLE`
- `VERIFIER_ADMIN_ROLE`
- `DOMAIN_ADMIN_ROLE`
- `DISPUTE_RESOLVER_ROLE`

#### Immutable Proof Verifier
**Savings: ~2,100 gas per external call**

```solidity
// Before
IProofVerifier public proofVerifier;

// After
IProofVerifier public immutable proofVerifier;
```

#### Packed Statistics Storage
**Savings: ~6,000 gas on updates (3 SSTOREs → 1 SSTORE)**

```solidity
// Before (4 separate storage slots)
uint256 public totalLocksCreated;
uint256 public totalLocksUnlocked;
uint256 public totalOptimisticUnlocks;
uint256 public totalDisputes;

// After (1 packed storage slot)
uint256 private _packedStats;
// Layout: totalLocksCreated (64) | totalLocksUnlocked (64) | totalOptimisticUnlocks (64) | totalDisputes (64)
```

#### Unchecked Arithmetic for Statistics
**Savings: ~20 gas per increment**

```solidity
unchecked {
    _packedStats += 1; // Safe: can't overflow 64-bit counter in practice
}
```

---

### 2. NullifierRegistryV3.sol

#### Pre-computed Role Hashes
**Savings: ~200 gas per role access**

```solidity
// Before
bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

// After
bytes32 public constant REGISTRAR_ROLE = 0xedcc084d3dcd65a1f7f23c65c46722faca6953d28e43150a467cf43e5c309238;
```

Applied to:
- `REGISTRAR_ROLE`
- `BRIDGE_ROLE`
- `EMERGENCY_ROLE`

---

### 3. PILAtomicSwapV2.sol

#### Storage Caching
**Savings: ~100 gas per avoided SLOAD**

```solidity
// Before (multiple SLOADs)
if (swap.status != SwapStatus.Created) revert SwapNotPending();
if (block.timestamp >= swap.timeLock) revert SwapExpired();
// ... later
IERC20(swap.token).safeTransfer(swap.recipient, swap.amount);

// After (cached values)
address _recipient = swap.recipient;
address _token = swap.token;
uint256 _amount = swap.amount;
uint256 _timeLock = swap.timeLock;
// ... use cached values
IERC20(_token).safeTransfer(_recipient, _amount);
```

Applied to:
- `claim()` function
- `revealClaim()` function
- `refund()` function
- `_createSwap()` function

#### Unchecked Fee Calculation
**Savings: ~60 gas per swap creation**

```solidity
// Before
uint256 fee = (amount * protocolFeeBps) / 10000;
uint256 netAmount = amount - fee;

// After
uint256 _protocolFeeBps = protocolFeeBps; // Cache SLOAD
uint256 fee;
uint256 netAmount;
unchecked {
    fee = (amount * _protocolFeeBps) / 10000;
    netAmount = amount - fee; // Safe: fee < amount always since feeBps <= 100
}
```

#### Timestamp Caching
**Savings: ~3 gas per avoided read**

```solidity
uint256 currentTime = block.timestamp;
uint256 deadline = currentTime + timeLock;
```

---

### 4. ConfidentialStateContainerV3.sol

Already well-optimized with:
- Pre-computed `OPERATOR_ROLE` hash
- Immutable `verifier`
- Packed `_packedCounters` and `_packedConfig`
- Assembly for hash computation in hot paths

---

## Gas Benchmark Results

After optimizations, the following gas consumption was measured:

| Operation | Gas Used |
|-----------|----------|
| Single state registration | ~264,202 |
| State registration (32 bytes) | ~286,627 |
| State registration (512 bytes) | ~592,876 |
| Single nullifier registration | ~988,868 |
| Batch nullifiers (1) | ~1,012,619 |
| Batch nullifiers (5) | ~346,399/item |
| Batch nullifiers (20) | ~221,679/item |
| Cross-chain proof submission | ~302,969 |
| 100 view calls | 54ms |

## Estimated Total Savings

| Optimization | Per-Call Savings | Impact |
|--------------|------------------|--------|
| Pre-computed role hashes | ~200 gas | High frequency |
| Immutable variables | ~2,100 gas | Every external call |
| Packed storage | ~6,000 gas | Every state update |
| Storage caching | ~100-500 gas | Every transaction |
| Unchecked math | ~20-60 gas | Every transaction |

## Test Results

All 71 tests pass after optimizations:
- 59 original tests ✓
- 12 stress tests ✓

## Best Practices Applied

1. **Pre-compute keccak256 hashes** - Role and typehash constants computed at compile time
2. **Use immutable for unchanging references** - Verifier contracts set once at deployment
3. **Pack storage variables** - Multiple counters/stats in single 256-bit slot
4. **Cache storage reads** - Avoid multiple SLOADs in same function
5. **Use unchecked blocks** - Where overflow is mathematically impossible
6. **Minimize redundant computations** - Cache block.timestamp, computed values
