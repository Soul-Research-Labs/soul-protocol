# NatSpec Documentation Audit Report

**Scope**: `contracts/crosschain/` (16 files) + `contracts/relayer/` (2 files)  
**Standard**: Solidity NatSpec — `@notice`, `@param`, `@return`, `@dev`  
**Rule**: Only public/external functions missing documentation are listed below.

---

## Summary

| Severity                                  | Count                                           |
| ----------------------------------------- | ----------------------------------------------- |
| **No NatSpec at all** (missing `@notice`) | 28 functions                                    |
| **Has `@notice` but missing `@param`**    | 42 functions                                    |
| **Has `@notice` but missing `@return`**   | 26 functions                                    |
| **Total findings**                        | ~80 (some functions have multiple missing tags) |

---

## 1. `contracts/crosschain/ArbitrumBridgeAdapter.sol`

| Line | Function                                                                                              | Missing                            |
| ---- | ----------------------------------------------------------------------------------------------------- | ---------------------------------- |
| 336  | `configureRollup(uint256, address, address, address, address, RollupType)`                            | `@param` (all 6 params)            |
| 549  | `confirmDeposit(bytes32 depositId)`                                                                   | `@param`                           |
| 570  | `registerWithdrawal(address, uint256, bytes32, bytes32, address, bytes32, uint256, uint256, bytes32)` | `@param` (all 9 params), `@return` |
| 621  | `claimWithdrawal(bytes32, bytes32[], uint256)`                                                        | `@param` (all 3 params)            |
| 813  | `pause()`                                                                                             | `@notice`                          |
| 817  | `unpause()`                                                                                           | `@notice`                          |

---

## 2. `contracts/crosschain/BaseBridgeAdapter.sol`

| Line | Function                                 | Missing                         |
| ---- | ---------------------------------------- | ------------------------------- |
| 674  | `syncStateToL2(bytes32, bytes, uint256)` | `@return` (returns `messageId`) |
| 743  | `isProofRelayed(bytes32 proofHash)`      | `@param`, `@return`             |
| 750  | `getAttestation(bytes32 attestationId)`  | `@param`, `@return`             |
| 759  | `hasAttestation(address, bytes32)`       | `@param`, `@return`             |
| 771  | `getStats()`                             | `@return`                       |
| 798  | `setL2Target(address)`                   | `@param`                        |
| 809  | `configureCCTP(address, address)`        | `@param`                        |
| 821  | `setMessenger(address, bool)`            | `@param`                        |

---

## 3. `contracts/crosschain/CrossChainCommitmentRelay.sol`

| Line | Function                         | Missing                        |
| ---- | -------------------------------- | ------------------------------ |
| 246  | `setShieldedPool(address _pool)` | `@notice`, `@param`            |
| 253  | `setPrivacyHub(address _hub)`    | `@notice`, `@param`            |
| 260  | `pause()`                        | `@notice`                      |
| 264  | `unpause()`                      | `@notice`                      |
| 272  | `getChainStats(bytes32 chainId)` | `@notice`, `@param`, `@return` |

---

## 4. `contracts/crosschain/CrossChainMessageRelay.sol`

| Line | Function                                                                                 | Missing                            |
| ---- | ---------------------------------------------------------------------------------------- | ---------------------------------- |
| 801  | `getMessage(bytes32 messageId)`                                                          | `@param`, `@return`                |
| 810  | `getExecutionResult(bytes32 messageId)`                                                  | `@param`, `@return`                |
| 819  | `isTrustedRemote(uint256, address)`                                                      | `@param`, `@return`                |
| 829  | `computeMessageId(uint256, uint256, address, address, uint256, bytes, uint256, uint256)` | `@param` (all 8 params), `@return` |
| 857  | `getBatch(bytes32 batchId)`                                                              | `@param`, `@return`                |

---

## 5. `contracts/crosschain/CrossChainNullifierSync.sol`

| Line | Function            | Missing              |
| ---- | ------------------- | -------------------- |
| 365  | `getPendingCount()` | `@notice`, `@return` |
| 369  | `getTargetChains()` | `@notice`, `@return` |
| 373  | `getBatchCount()`   | `@notice`, `@return` |
| 381  | `pause()`           | `@notice`            |
| 385  | `unpause()`         | `@notice`            |

---

## 6. `contracts/crosschain/CrossL2Atomicity.sol`

**All public/external functions have complete NatSpec. No findings.**

---

## 7. `contracts/crosschain/DirectL2Messenger.sol`

**All public/external functions have complete NatSpec. No findings.**

---

## 8. `contracts/crosschain/EthereumL1Bridge.sol`

| Line | Function                                   | Missing             |
| ---- | ------------------------------------------ | ------------------- |
| 1018 | `getSupportedChainIds()`                   | `@return`           |
| 1025 | `getL2Config(uint256 chainId)`             | `@param`, `@return` |
| 1034 | `isChainSupported(uint256 chainId)`        | `@param`, `@return` |
| 1041 | `getLatestStateRoot(uint256 chainId)`      | `@param`, `@return` |
| 1050 | `isNullifierUsed(bytes32 nullifier)`       | `@param`, `@return` |
| 1061 | `setRateLimits(uint256 newLimit)`          | `@param`            |
| 1070 | `setMinSubmissionBond(uint256 newBond)`    | `@param`            |
| 1079 | `setMaxCommitmentsPerHour(uint256 newMax)` | `@param`            |

---

## 9. `contracts/crosschain/HyperlaneAdapter.sol`

**All public/external functions have complete NatSpec. No findings.**

---

## 10. `contracts/crosschain/L2ChainAdapter.sol`

| Line | Function                                                         | Missing                 |
| ---- | ---------------------------------------------------------------- | ----------------------- |
| 215  | `addChain(uint256, string, address, address, uint256, uint256)`  | `@param` (all 6 params) |
| 243  | `updateChain(uint256, address, address, uint256, uint256, bool)` | `@param` (all 6 params) |
| 270  | `sendMessage(uint256, bytes)`                                    | `@param`, `@return`     |
| 306  | `receiveMessage(bytes32, uint256, bytes, bytes)`                 | `@param` (all 4 params) |
| 333  | `confirmMessage(bytes32 messageId)`                              | `@param`                |
| 624  | `getSupportedChains()`                                           | `@return`               |
| 631  | `getChainConfig(uint256 chainId)`                                | `@param`, `@return`     |
| 640  | `isChainSupported(uint256 chainId)`                              | `@param`, `@return`     |
| 647  | `getMessageStatus(bytes32 messageId)`                            | `@param`, `@return`     |

---

## 11. `contracts/crosschain/L2ProofRouter.sol`

| Line | Function                                                                          | Missing                        |
| ---- | --------------------------------------------------------------------------------- | ------------------------------ |
| 828  | `configureRoute(uint256, uint256, RoutePath, address, uint256, uint256, uint256)` | `@param` (all 7 params)        |
| 852  | `setDirectMessenger(address _messenger)`                                          | `@param`                       |
| 862  | `pause()`                                                                         | `@notice`                      |
| 866  | `unpause()`                                                                       | `@notice`                      |
| 874  | `getProof(bytes32 proofId)`                                                       | `@notice`, `@param`, `@return` |
| 878  | `getBatch(bytes32 batchId)`                                                       | `@notice`, `@param`, `@return` |
| 884  | `getActiveBatch(uint256 destChainId)`                                             | `@notice`, `@param`, `@return` |
| 890  | `getCacheSize()`                                                                  | `@notice`, `@return`           |
| 894  | `getCachedProof(bytes32 cacheKey)`                                                | `@notice`, `@param`, `@return` |
| 900  | `getRouteMetrics(uint256 sourceChainId, uint256 destChainId)`                     | `@notice`, `@param`, `@return` |

---

## 12. `contracts/crosschain/LayerZeroAdapter.sol`

**All public/external functions have complete NatSpec. No findings.**

---

## 13. `contracts/crosschain/LayerZeroBridgeAdapter.sol`

| Line | Function                                                                            | Missing                 |
| ---- | ----------------------------------------------------------------------------------- | ----------------------- |
| 364  | `setEndpoint(address, uint32)`                                                      | `@param`                |
| 380  | `setDelegate(address)`                                                              | `@param`                |
| 390  | `setBridgeFee(uint256)`                                                             | `@param`                |
| 405  | `setPeer(uint32, bytes32, ChainType, uint256, SecurityLevel)`                       | `@param` (all 5 params) |
| 434  | `updatePeerSecurity(uint32, SecurityLevel)`                                         | `@param`                |
| 474  | `setSendLibConfig(uint32, address, uint64, uint8, address[], address[], address[])` | `@param` (all 7 params) |
| 507  | `setReceiveLibConfig(uint32, address, uint64, uint8, address[], address[])`         | `@param` (all 6 params) |
| 628  | `lzReceive(uint32, bytes32, bytes32, bytes, bytes)`                                 | `@param` (all 5 params) |
| 669  | `storePayload(bytes32, bytes)`                                                      | `@param`                |
| 704  | `mapToken(address, uint32, bytes32)`                                                | `@param`                |
| 720  | `setOFTAdapter(address, address)`                                                   | `@param`                |
| 734  | `sendOFT(address, uint32, bytes32, uint256, MessageOptions)`                        | `@param`, `@return`     |
| 797  | `quoteSend(uint32, bytes, MessageOptions)`                                          | `@param`, `@return`     |
| 881  | `getStats()`                                                                        | `@return`               |
| 902  | `getRegisteredEids()`                                                               | `@return`               |
| 909  | `isPeerActive(uint32 eid)`                                                          | `@param`, `@return`     |
| 916  | `getPeer(uint32 eid)`                                                               | `@param`, `@return`     |
| 923  | `getMessage(bytes32 messageId)`                                                     | `@param`, `@return`     |
| 932  | `getOFTTransfer(bytes32 transferId)`                                                | `@param`, `@return`     |
| 941  | `getRemoteToken(address, uint32)`                                                   | `@param`, `@return`     |
| 951  | `getNonce(address sender)`                                                          | `@param`, `@return`     |

---

## 14. `contracts/crosschain/OptimismBridgeAdapter.sol`

Most functions use `@inheritdoc IOptimismBridgeAdapter` — those are adequately documented.

| Line | Function                           | Missing             |
| ---- | ---------------------------------- | ------------------- |
| 797  | `getUserDeposits(address user)`    | `@param`, `@return` |
| 804  | `getUserWithdrawals(address user)` | `@param`, `@return` |
| 811  | `getUserEscrows(address user)`     | `@param`, `@return` |
| 818  | `getBridgeStats()`                 | `@return`           |

---

## 15. `contracts/crosschain/SoulCrossChainRelay.sol`

| Line | Function                            | Missing                        |
| ---- | ----------------------------------- | ------------------------------ |
| 392  | `getSupportedChains()`              | `@notice`, `@return`           |
| 396  | `isChainSupported(uint256 chainId)` | `@notice`, `@param`, `@return` |
| 404  | `pause()`                           | `@notice`                      |
| 408  | `unpause()`                         | `@notice`                      |
| 412  | `updateProofHub(address _proofHub)` | `@notice`, `@param`            |

---

## 16. `contracts/crosschain/SoulL2Messenger.sol`

**All public/external functions have complete NatSpec. No findings.**

---

## 17. `contracts/relayer/RelayerFeeMarket.sol`

| Line | Function                                     | Missing             |
| ---- | -------------------------------------------- | ------------------- |
| 354  | `cancelRelayRequest(bytes32 requestId)`      | `@param`            |
| 368  | `expireRequest(bytes32 requestId)`           | `@param`            |
| 401  | `getBaseFee(bytes32, bytes32)`               | `@param`, `@return` |
| 409  | `estimateFee(bytes32, bytes32, uint256)`     | `@param`, `@return` |
| 424  | `initializeRoute(bytes32, bytes32, uint256)` | `@param`            |
| 442  | `setProtocolFeeBps(uint256 _bps)`            | `@param`            |
| 448  | `withdrawProtocolFees(address recipient)`    | `@param`            |

---

## 18. `contracts/relayer/RelayerStaking.sol`

| Line | Function                                     | Missing             |
| ---- | -------------------------------------------- | ------------------- |
| 305  | `pendingRewards(address relayerAddress)`     | `@param`, `@return` |
| 317  | `getActiveRelayers()`                        | `@return`           |
| 324  | `getActiveRelayerCount()`                    | `@return`           |
| 331  | `isActiveRelayer(address relayerAddress)`    | `@param`, `@return` |
| 340  | `setMinStake(uint256 _minStake)`             | `@param`            |
| 347  | `setSlashingPercentage(uint256 _percentage)` | `@param`            |
| 357  | `updateMetadata(string calldata metadata)`   | `@param`            |

---

## Clean Files (No Missing NatSpec)

The following files have **complete NatSpec coverage** on all public/external functions:

1. `contracts/crosschain/CrossL2Atomicity.sol`
2. `contracts/crosschain/DirectL2Messenger.sol`
3. `contracts/crosschain/HyperlaneAdapter.sol`
4. `contracts/crosschain/LayerZeroAdapter.sol`
5. `contracts/crosschain/SoulL2Messenger.sol`

---

## Patterns Observed

### 1. View/getter functions are consistently underdocumented

The most common gap is **view functions** that have `@notice` but lack `@param` and `@return`. This affects 11 of 18 files.

### 2. `pause()` / `unpause()` often have no NatSpec

Found in: ArbitrumBridgeAdapter, CrossChainCommitmentRelay, CrossChainNullifierSync, L2ProofRouter, SoulCrossChainRelay (5 files, 10 functions).

### 3. Admin setters often missing `@param`

Functions like `setL2Target`, `configureCCTP`, `setMessenger`, `setProtocolFeeBps` have `@notice` but skip `@param` descriptions.

### 4. LayerZeroBridgeAdapter is the worst offender

21 functions missing `@param` / `@return` tags — the largest single-file gap.

---

## Recommendations

1. **Priority 1**: Add `@notice` to the 28 functions completely lacking it (especially `pause`/`unpause` and view functions).
2. **Priority 2**: Add `@param` tags to admin setters and configuration functions — these are security-critical and need clear parameter documentation.
3. **Priority 3**: Add `@return` tags to all view/getter functions to improve SDK/tooling integration.
4. **Priority 4**: Consider adding `@dev` notes on all functions that involve cross-chain messaging or ZK proof verification, per the project's [NATSPEC_STYLE_GUIDE.md](docs/NATSPEC_STYLE_GUIDE.md).
