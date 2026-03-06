# ADR-010: ZaseonToken Governance Model

## Status

Accepted

## Date

2026-03-01

## Context

ZASEON governance requires a token model for:

1. **Protocol governance**: Parameter changes, bridge additions, fee updates
2. **Relayer staking**: Economic security for relay network
3. **Fee distribution**: Protocol fee revenue sharing
4. **Emergency actions**: Fast-track proposals for security incidents

Evaluated: pure multisig, token voting (Governor), optimistic governance, conviction voting.

## Decision

Use **OpenZeppelin Governor** with ERC20Votes token and a two-tier timelock system.

### Architecture

- `ZaseonToken`: ERC20Votes with capped supply, no mint function post-deployment
- `ZaseonGovernor`: OZ Governor with configurable thresholds and voting delay
- `ZaseonUpgradeTimelock`: Standard timelock for non-urgent governance actions
- `OperationTimelockModule`: Fast-track module for emergency proposals

### Governance parameters

- **Voting delay**: 1 day (time between proposal and voting start)
- **Voting period**: 5 days
- **Proposal threshold**: 100,000 tokens (prevents spam)
- **Quorum**: 4% of total supply
- **Timelock delay**: 2 days (standard), 6 hours (emergency)

### Two-tier timelock

1. **Standard timelock** (2-day delay): Fee changes, bridge additions, parameter updates
2. **Emergency timelock** (6-hour delay): Pause, circuit breaker, bridge removal. Requires `GUARDIAN_ROLE` co-sign

### Rationale

- **OZ Governor**: Battle-tested, compatible with Tally/Snapshot frontends
- **ERC20Votes**: Delegation support for passive holders
- **Two-tier timelock**: Balances security (fast emergency response) with decentralization (slow parameter changes)
- **Capped supply**: No inflation risk, token economics are predictable

## Consequences

- All protocol parameter changes go through governance
- Emergency actions bypass standard timelock but require guardian approval
- Token delegation enables governance participation without gas costs
- Governance proposals are executable on L1; L2 parameter changes use bridge adapters
- Upgrade proposals require storage compatibility verification before execution
