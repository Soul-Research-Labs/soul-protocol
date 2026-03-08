# @zaseon/sdk Changelog

All notable changes to the ZASEON SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-08

### Added

- `UniswapV3AdapterClient` for interacting with Uniswap V3 settlement rebalancing
- Subpath exports: `./bridges`, `./react`, `./cli`, `./compliance`, `./relayer`, `./adapters`
- `ZaseonProtocolClient` — new primary client replacing `ZaseonClient`
- `StealthAddressClient` — ERC-5564 stealth address operations
- `CrossChainLiquidityVaultClient` — LP deposits, withdrawals, settlement swaps
- `DecoyTrafficManager` — cover traffic generation for MAXIMUM privacy tier
- Submission jitter — random delays before transaction broadcast
- Polling jitter — randomized RPC polling intervals
- `NoirProver` — Noir proof generation and verification

### Changed

- Primary entry point is now `ZaseonProtocolClient` (replaces `ZaseonClient`)
- Privacy tier system (STANDARD / ENHANCED / MAXIMUM) controls progressive metadata protection

### Removed

- `sdk/src/client/_deprecated/ZaseonPrivacySDK.ts` (use `ZaseonProtocolClient`)
- `sdk/src/client/ZaseonClient.ts` (superseded by `ZaseonProtocolClient`)

## [1.0.0] - 2026-02-15

### Added

- Initial SDK release
- `ZaseonClient` — protocol interaction client
- Bridge clients for 11 bridge adapters
- ZK proof generation via `NoirProver`
- CLI tool (`zaseon`)
- React hooks (`./react`)
- Compliance module (`./compliance`)
- Relayer module (`./relayer`)
