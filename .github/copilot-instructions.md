# PIL Project Context

Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

## Tech Stack
- **Solidity 0.8.22** with Foundry + Hardhat
- **ZK Circuits**: Noir (migrated from Circom)
- **Testing**: Foundry fuzz, Echidna, Certora, Halmos
- **L2s**: Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM

## Project Structure
```
contracts/     # Solidity (core, crosschain, privacy, security, pqc)
noir/          # Noir ZK circuits  
test/          # Foundry + Hardhat tests
sdk/           # TypeScript SDK
specs/         # K Framework, TLA+ specs
certora/       # Certora CVL specs
docs/          # Documentation
```

## Key Contracts
- `CrossChainProofHubV3` - Main proof aggregation hub
- `ZKBoundStateLocks` - Cross-chain state locks with ZK unlock
- `PILAtomicSwapV2` - Private atomic swaps
- `UnifiedNullifierManager` - Cross-domain nullifier tracking
- `StealthAddressRegistry` - ERC-5564 stealth addresses

## Development Guidelines
- Follow Solidity style guide
- All new features need fuzz tests
- Security-critical code needs Certora specs
- Use existing patterns from `contracts/interfaces/`

## Commands
```bash
forge build && npx hardhat compile  # Build
forge test -vvv                      # Test (Foundry)
npx hardhat test                     # Test (Hardhat)
```

## Documentation
See `docs/GETTING_STARTED.md` for setup, `docs/INTEGRATION_GUIDE.md` for SDK usage.
