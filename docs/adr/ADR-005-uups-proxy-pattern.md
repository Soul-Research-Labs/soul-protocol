# ADR-005: UUPS Proxy Pattern for Upgradeable Contracts

## Status

Accepted

## Date

2026-02-28

## Context

ZASEON's core contracts (ShieldedPool, StealthAddressRegistry, CapacityAwareRouter, DynamicRoutingOrchestrator) need upgradeability to fix bugs and add features post-deployment without migrating user state. Key requirements:

1. **Storage preservation**: Upgrades must not corrupt encrypted state or nullifier trees
2. **Minimal gas overhead**: Proxy pattern should add minimal per-call cost
3. **Admin safety**: Upgrade authorization must be multi-sig controlled
4. **Compatibility**: Must work across all 7 target L2s

Evaluated patterns: Transparent Proxy, UUPS (ERC-1822), Diamond (ERC-2535), and Beacon.

## Decision

Use **UUPS (Universal Upgradeable Proxy Standard)** via OpenZeppelin's `UUPSUpgradeable` base contract.

### Rationale

- **Gas savings**: UUPS places upgrade logic in the implementation (not proxy), saving ~2,100 gas per call vs Transparent Proxy which checks admin on every call
- **Simpler proxy**: Proxy contract is minimal (just `delegatecall`), reducing attack surface
- **OZ support**: Well-audited OpenZeppelin 5.x implementation with `_authorizeUpgrade` hook
- **Storage layout**: OpenZeppelin's `StorageSlot` and `Initializable` prevent storage collisions
- **Remove upgrade path**: Can permanently disable upgrades by deploying implementation without `_authorizeUpgrade`

### Rejected alternatives

- **Transparent Proxy**: Higher gas per-call; admin slot management complexity
- **Diamond (ERC-2535)**: Over-engineered for our use case; complex storage management across facets; debugging difficulty
- **Beacon**: Useful for many instances of the same contract; not our pattern

## Consequences

- All upgradeable contracts MUST use `Initializable` instead of constructors
- Storage layout changes require careful gap management (`__gap` arrays)
- `_authorizeUpgrade` restricted to `DEFAULT_ADMIN_ROLE` with timelock
- Upgrade scripts MUST run storage compatibility checks before deploying
- Each upgradeable contract has a corresponding `*Upgradeable.sol` in `contracts/upgradeable/`
