# Soul Deployment Checklist

## Pre-Deployment Verification

### 1. Code Quality ✅
- [x] All tests pass (`forge test --summary`)
- [x] Gas benchmarks within acceptable limits
- [x] No critical Slither findings unaddressed
- [x] Code coverage >80%

### 2. Security Audit (February 2026) ✅
- [x] Internal security audit completed (44 vulnerabilities fixed)
- [x] Phase 1: 5 Critical, 6 High, 15 Medium resolved
- [x] Phase 2: 2 Critical, 4 High, 6 Medium, 6 Low resolved
- [x] ReentrancyGuard protection added to governance/security
- [x] .transfer() DoS vulnerabilities fixed
- [x] Zero-address validation added
- [x] See [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) for details

### 3. Security Checks ✅
- [x] Attack simulation tests pass (44 tests)
- [x] Stress tests pass (24 tests)
- [x] Fuzz tests pass (116+ tests)
- [x] Invariant tests pass (8 tests)
- [x] Echidna property tests pass (21 tests)
- [x] Total: 544 tests passing

### 4. Pre-Mainnet Security Checklist
- [ ] Call `confirmRoleSeparation()` on ZKBoundStateLocks
- [ ] Call `confirmRoleSeparation()` on CrossChainProofHubV3
- [ ] Verify admin roles distributed to separate addresses
- [ ] Configure timelocks for all admin operations
- [ ] Set up monitoring for critical events
- [ ] Deploy with optimizer enabled (runs: 200)

### 5. Documentation ✅
- [x] README.md up to date
- [x] API documentation complete
- [x] Security model documented
- [x] Upgrade procedures documented

---

## Testnet Deployment

### Phase 1: Sepolia (Ethereum Testnet) ✅ DEPLOYED

**Deployment Date**: January 22, 2026  
**Deployer**: `0xbc5bb932c7696412622b1fe9a09b7fd9509c6913`  
**Chain ID**: 11155111

#### Core Verifiers
| Contract | Address | Verified |
|----------|---------|----------|
| MockProofVerifier | [`0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57`](https://sepolia.etherscan.io/address/0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57) | ✅ |
| Groth16VerifierBN254 | [`0x09cf3f57c213218446aa49d89236247fbe1d08bd`](https://sepolia.etherscan.io/address/0x09cf3f57c213218446aa49d89236247fbe1d08bd) | ✅ |

#### Core Infrastructure
| Contract | Address | Verified |
|----------|---------|----------|
| ConfidentialStateContainerV3 | [`0x5d79991daabf7cd198860a55f3a1f16548687798`](https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798) | ✅ |
| NullifierRegistryV3 | [`0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191`](https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191) | ✅ |
| CrossChainProofHubV3 | [`0x40eaa5de0c6497c8943c967b42799cb092c26adc`](https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc) | ✅ |

#### Application Layer
| Contract | Address | Verified |
|----------|---------|----------|
| SoulAtomicSwapV2 | [`0xdefb9a66dc14a6d247b282555b69da7745b0ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) | ✅ |
| SoulComplianceV2 | [`0x5d41f63f35babed689a63f7e5c9e2943e1f72067`](https://sepolia.etherscan.io/address/0x5d41f63f35babed689a63f7e5c9e2943e1f72067) | ✅ |

#### Soul v2 Primitives
| Contract | Address | Verified |
|----------|---------|----------|
| ProofCarryingContainer (PC³) | [`0x52f8a660ff436c450b5190a84bc2c1a86f1032cc`](https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc) | ✅ |
| PolicyBoundProofs (PBP) | [`0x75e86ee654eae62a93c247e4ab9facf63bc4f328`](https://sepolia.etherscan.io/address/0x75e86ee654eae62a93c247e4ab9facf63bc4f328) | ✅ |
| ExecutionAgnosticStateCommitments (EASC) | [`0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6`](https://sepolia.etherscan.io/address/0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6) | ✅ |
| CrossDomainNullifierAlgebra (CDNA) | [`0x674d0cbfb5bf33981b1656abf6a47cff46430b0c`](https://sepolia.etherscan.io/address/0x674d0cbfb5bf33981b1656abf6a47cff46430b0c) | ✅ |

#### Security
| Contract | Address | Verified |
|----------|---------|----------|
| EmergencyRecovery | [`0x1995dbb199c26afd73a817aaafbccbf28f070ffc`](https://sepolia.etherscan.io/address/0x1995dbb199c26afd73a817aaafbccbf28f070ffc) | ✅ |

#### ZK-Bound State Locks
| Contract | Address | Verified |
|----------|---------|----------|
| ZKBoundStateLocks | [`0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78`](https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78) | ✅ |
| ZKSLockIntegration | [`0x668c1a8197d59b5cf4d3802e209d3784c6f69b29`](https://sepolia.etherscan.io/address/0x668c1a8197d59b5cf4d3802e209d3784c6f69b29) | ✅ |

**Total Contracts Deployed**: 16  
**Total Contracts Verified**: 16 ✅  
**Integration Tests Passed**: 17/17 ✅

#### Integration Test Run (January 22, 2026)
```
✅ MockProofVerifier - Read verification result
✅ Groth16VerifierBN254 - Contract accessible
✅ ConfidentialStateContainerV3 - Read total states
✅ NullifierRegistryV3 - Check nullifier not used
✅ CrossChainProofHubV3 - Contract accessible
✅ SoulAtomicSwapV2 - Contract accessible
✅ SoulComplianceV2 - Contract accessible
✅ ProofCarryingContainer - Contract accessible
✅ PolicyBoundProofs - Contract accessible
✅ ExecutionAgnosticStateCommitments - Contract accessible
✅ CrossDomainNullifierAlgebra - Contract accessible
✅ EmergencyRecovery - Contract accessible
✅ ZKBoundStateLocks - Read stats
✅ ZKBoundStateLocks - Get active locks
✅ ZKSLockIntegration - Contract accessible

All integration tests passed!
```

### Phase 2: Arbitrum Sepolia

```bash
npx hardhat run scripts/deploy-v3.ts --network arbitrumSepolia
```

- [ ] All core contracts deployed
- [ ] Bridge endpoints configured
- [ ] L2 specific optimizations enabled

### Phase 3: Base Sepolia

```bash
npx hardhat run scripts/deploy-v3.ts --network baseSepolia
```

- [ ] All core contracts deployed
- [ ] Cross-chain messaging tested
- [ ] Gas costs verified

### Phase 4: Optimism Sepolia

```bash
npx hardhat run scripts/deploy-v3.ts --network optimismSepolia
```

- [ ] All core contracts deployed
- [ ] L2 specific optimizations enabled
- [ ] Gas costs verified

---

## Integration Testing (Post-Deployment)

### Cross-Chain Tests
- [ ] Proof relay from Sepolia → Arbitrum Sepolia
- [ ] Proof relay from Arbitrum → Base
- [ ] Atomic swap execution
- [ ] Emergency pause/unpause

### Relayer Network
- [ ] Relayer registration
- [ ] Proof submission
- [ ] Staking/slashing mechanics

---

## Mainnet Deployment Checklist

### Pre-Mainnet
- [ ] External audit completed
- [ ] Bug bounty program active
- [ ] Testnet run for 30+ days
- [ ] No critical bugs found

### Governance Setup
- [ ] Multisig deployed (e.g., Gnosis Safe)
- [ ] Timelock configured (48h minimum)
- [ ] Emergency roles assigned
- [ ] Guardian set configured

### Deployment Order
1. [ ] Verifier contracts (no dependencies)
2. [ ] Verifier Registry (depends on verifiers)
3. [ ] Core state containers
4. [ ] Bridge contracts
5. [ ] Governance contracts
6. [ ] Application layer (swaps, compliance)

### Post-Deployment
- [ ] All contract addresses documented
- [ ] Subgraph deployed and indexed
- [ ] Monitoring alerts configured
- [ ] Frontend connected to mainnet

---

## Rollback Procedures

### Emergency Pause
```solidity
// Emergency role can pause immediately
timelockAdmin.schedulePausePC3(salt);
```

### Contract Upgrade
```solidity
// Schedule upgrade with timelock
timelockAdmin.scheduleUpgrade(newImplementation, salt);
// Wait 48 hours...
timelockAdmin.executeUpgrade();
```

---

## Monitoring & Alerting

### Critical Alerts
- [ ] Large withdrawals (>100 ETH)
- [ ] Failed proof verifications (>10/hour)
- [ ] Bridge relay failures
- [ ] Slashing events
- [ ] Emergency actions triggered

### Dashboards
- [ ] Dune Analytics dashboard
- [ ] TheGraph subgraph
- [ ] Internal monitoring stack

---

## Contact & Support

- **Security Issues**: security@soul.network
- **Technical Support**: support@soul.network
- **Bug Bounty**: immunefi.com/bounty/soul

---

*Last Updated: January 22, 2026*
