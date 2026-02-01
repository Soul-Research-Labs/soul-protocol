# Soul Protocol - Governance Contracts

This directory contains governance-related contracts for Soul Protocol.

## Directory Structure

```
governance/
├── SoulMultiSigGovernance.sol   # Multi-signature governance
├── SoulTimelock.sol             # Standard timelock controller
├── SoulUpgradeTimelock.sol      # Upgrade-specific timelock
├── TimelockAdmin.sol            # Timelock administration
└── interfaces/
    ├── ISoulGovernor.sol        # Governor interface
    └── ISoulTimelock.sol        # Timelock interface
```

## Role Hierarchy

```
                    ┌──────────────────┐
                    │  SUPER_ADMIN     │
                    │  (5-of-9 Multisig)│
                    └────────┬─────────┘
                             │
      ┌──────────────────────┼──────────────────────┐
      │                      │                      │
┌─────▼─────┐        ┌───────▼───────┐      ┌───────▼───────┐
│   ADMIN   │        │   GUARDIAN    │      │   OPERATOR    │
│ (3-of-5)  │        │ (2-of-3)      │      │ (2-of-5)      │
│           │        │               │      │               │
│ - Upgrades│        │ - Pause       │      │ - Relay       │
│ - Config  │        │ - Blacklist   │      │ - Process     │
│ - Roles   │        │ - Emergency   │      │ - Maintain    │
└───────────┘        └───────────────┘      └───────────────┘
```

## Separation of Duties

- **Deployer ≠ Admin**: Deployment is one-time, admin is ongoing
- **Admin ≠ Operator**: Configuration vs daily operations
- **Guardian ≠ Admin**: Security response vs management

## Key Features

### Multi-Sig Governance
- Proposal creation with role-based signature requirements
- Time-locked execution for critical operations
- Emergency actions with guardian fast-path

### Timelock Controller
- Configurable delay periods
- Proposal queuing and execution
- Cancellation capabilities

### Upgrade Management
- UUPS upgrade pattern support
- Extended timelock for upgrades
- Multi-sig approval requirements

## Migration Note

These contracts were previously located in `contracts/security/`. They have been
moved here for better organization and clarity between security mechanisms and
governance structures.

## Usage

```solidity
import {SoulMultiSigGovernance} from "./governance/SoulMultiSigGovernance.sol";
import {SoulTimelock} from "./governance/SoulTimelock.sol";
```

## Related Certora Specs

- `certora/specs/SoulGovernor.spec`
- `certora/specs/Timelock.spec`
