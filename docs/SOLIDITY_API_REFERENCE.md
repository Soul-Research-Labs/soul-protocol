# ZASEON — Solidity API Reference

> **Auto-generated from Solidity source** — covers all public/external functions, events, roles, and key state variables for core contracts and bridge adapters.

---

## Table of Contents

1. [CrossChainProofHubV3](#1-crosschainproofhubv3)
2. [ConfidentialStateContainerV3](#2-confidentialstatecontainerv3)
3. [NullifierRegistryV3](#3-nullifierregistryv3)
4. [ZaseonProtocolHub](#4-zaseonprotocolhub)
5. [ZaseonAtomicSwapV2](#5-zaseonatomicswapv2)
6. [DirectL2Messenger](#6-directl2messenger)
7. [UniversalShieldedPool](#7-universalshieldedpool)
8. [StealthAddressRegistry](#8-stealthaddressregistry)
9. [BN254 Library](#9-bn254-library)
10. [RingSignatureVerifier](#10-ringsignatureverifier)
11. [Bridge Adapters](#11-bridge-adapters)
12. [BatchAccumulator](#12-batchaccumulator)
13. [DecentralizedRelayerRegistry](#13-decentralizedrelayerregistry)
14. [CrossChainEmergencyRelay](#14-crosschainemergencyrelay)
15. [CrossChainNullifierSync](#15-crosschainnullifiersync)
16. [ProtocolEmergencyCoordinator](#16-protocolemergencycoordinator)
17. [GasNormalizer](#17-gasnormalizer)
18. [ProofEnvelope Library](#18-proofenvelope-library)
19. [FixedSizeMessageWrapper Library](#19-fixedsizemessagewrapper-library)
20. [Multi-Relayer Quorum (CrossChainPrivacyHub)](#20-multi-relayer-quorum-crosschainprivacyhub)
21. [Denomination Enforcement (CrossChainLiquidityVault)](#21-denomination-enforcement-crosschainliquidityvault)
22. [Relay Jitter (CrossChainPrivacyHub)](#22-relay-jitter-crosschainprivacyhub)
23. [Integration Contracts](#23-integration-contracts)
24. [Security Contracts](#24-security-contracts)

---

## 1. CrossChainProofHubV3

**Path:** `contracts/bridge/CrossChainProofHubV3.sol`
**Solidity:** `^0.8.20`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`, `SecurityModule`

Production-ready cross-chain proof relay with optimistic verification and dispute resolution. Implements batching, challenge periods, and gas-efficient proof storage.

### Roles

| Constant              | Description              |
| --------------------- | ------------------------ |
| `RELAYER_ROLE`        | Authorized relayers      |
| `VERIFIER_ADMIN_ROLE` | Verifier management      |
| `CHALLENGER_ROLE`     | Authorized challengers   |
| `OPERATOR_ROLE`       | Config & trusted remotes |
| `EMERGENCY_ROLE`      | Emergency pause          |

### Key State Variables

| Variable             | Type                | Description                      |
| -------------------- | ------------------- | -------------------------------- |
| `CHAIN_ID`           | `uint256 immutable` | Deployment chain ID              |
| `challengePeriod`    | `uint256`           | Challenge window (default 1h)    |
| `minRelayerStake`    | `uint256`           | Min relayer stake (0.1 ETH)      |
| `minChallengerStake` | `uint256`           | Min challenger stake (0.05 ETH)  |
| `proofSubmissionFee` | `uint256`           | Fee per proof (0.001 ETH)        |
| `maxProofsPerHour`   | `uint256`           | Circuit breaker limit (1000)     |
| `maxValuePerHour`    | `uint256`           | Circuit breaker limit (1000 ETH) |
| `totalProofs`        | `uint256`           | Counter                          |
| `totalBatches`       | `uint256`           | Counter                          |
| `accumulatedFees`    | `uint256`           | Collected fees                   |
| `MAX_BATCH_SIZE`     | `uint256`           | 100                              |
| `rolesSeparated`     | `bool`              | Must be true before operations   |

### Functions

#### Relayer Stake Management

```solidity
function confirmRoleSeparation(
    address guardian,
    address responder,
    address recovery
) external onlyRole(DEFAULT_ADMIN_ROLE)
```

Mark roles as properly separated. Validates that the three addresses are distinct, each holds its claimed role, no address holds more than one critical role, and the admin does not hold operational roles. Must be called before `submitProof` / `submitBatch` operations are enabled.

```solidity
function depositStake() external payable nonReentrant
```

Deposit ETH stake as a relayer.

```solidity
function withdrawStake(uint256 amount) external nonReentrant
```

Withdraw relayer stake. Includes TOCTOU protection — blocked while proofs are pending.

```solidity
function withdrawRewards(uint256 amount) external nonReentrant
```

Withdraw claimable rewards (for challengers who won disputes).

#### Proof Submission

```solidity
function submitProof(
    bytes calldata proof,
    bytes calldata publicInputs,
    bytes32 commitment,
    uint64 sourceChainId,
    uint64 destChainId
) external payable nonReentrant whenNotPaused returns (bytes32 proofId)
```

Submit a proof with optimistic verification (enters challenge period). Requires `RELAYER_ROLE`.

```solidity
function submitProofInstant(
    bytes calldata proof,
    bytes calldata publicInputs,
    bytes32 commitment,
    uint64 sourceChainId,
    uint64 destChainId,
    bytes32 proofType
) external payable nonReentrant whenNotPaused returns (bytes32 proofId)
```

Submit with instant on-chain verification (3x fee). No challenge period.

```solidity
function submitBatch(
    BatchProofInput[] calldata _proofs,
    bytes32 merkleRoot
) external payable nonReentrant whenNotPaused returns (bytes32 batchId)
```

Submit a batch of proofs (up to `MAX_BATCH_SIZE`). Requires `RELAYER_ROLE`.

#### Challenge System

```solidity
function challengeProof(bytes32 proofId, string calldata reason) external payable nonReentrant
```

Challenge a pending proof. Requires `minChallengerStake`.

```solidity
function resolveChallenge(
    bytes32 proofId,
    bytes calldata proof,
    bytes calldata publicInputs,
    bytes32 proofType
) external nonReentrant
```

Resolve a challenge via on-chain proof verification. Only the original challenger can call.

```solidity
function expireChallenge(bytes32 proofId) external nonReentrant whenNotPaused
```

Expire a stale challenge after deadline, resolving in the relayer's favor.

#### Finalization

```solidity
function finalizeProof(bytes32 proofId) external nonReentrant whenNotPaused
```

Finalize a proof after the challenge period has elapsed.

#### View Functions

```solidity
function getProof(bytes32 proofId) external view returns (ProofSubmission memory)
function getBatch(bytes32 batchId) external view returns (BatchSubmission memory)
function getChallenge(bytes32 proofId) external view returns (Challenge memory)
function isProofFinalized(bytes32 proofId) external view returns (bool)
function getRelayerStats(address relayer) external view returns (uint256 stake, uint256 successCount, uint256 slashCount)
```

#### Admin Functions

```solidity
function setVerifier(bytes32 proofType, address _verifier) external onlyRole(VERIFIER_ADMIN_ROLE)
function addSupportedChain(uint256 chainId) external onlyRole(DEFAULT_ADMIN_ROLE)
function removeSupportedChain(uint256 chainId) external onlyRole(DEFAULT_ADMIN_ROLE)
function setTrustedRemote(uint256 chainId, address remote) external onlyRole(OPERATOR_ROLE)
function setVerifierRegistry(address _registry) external onlyRole(DEFAULT_ADMIN_ROLE)
function setChallengePeriod(uint256 _period) external onlyRole(DEFAULT_ADMIN_ROLE)
function setMinStakes(uint256 _relayerStake, uint256 _challengerStake) external onlyRole(DEFAULT_ADMIN_ROLE)
function setProofSubmissionFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE)
function setRateLimits(uint256 _maxProofsPerHour, uint256 _maxValuePerHour) external onlyRole(DEFAULT_ADMIN_ROLE)
function withdrawFees(address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE)
function pause() external onlyRole(EMERGENCY_ROLE)
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE)
```

### Events

| Event                         | Parameters                                                         |
| ----------------------------- | ------------------------------------------------------------------ |
| `ProofSubmitted`              | `proofId`, `commitment`, `sourceChainId`, `destChainId`, `relayer` |
| `ProofDataEmitted`            | `proofId`, `proof`, `publicInputs`                                 |
| `BatchSubmitted`              | `batchId`, `merkleRoot`, `proofCount`, `relayer`                   |
| `ProofVerified`               | `proofId`, `status`                                                |
| `ProofFinalized`              | `proofId`                                                          |
| `ProofRejected`               | `proofId`, `reason`                                                |
| `ChallengeCreated`            | `proofId`, `challenger`, `reason`                                  |
| `ChallengeResolved`           | `proofId`, `challengerWon`, `winner`, `reward`                     |
| `RelayerStakeDeposited`       | `relayer`, `amount`                                                |
| `RelayerStakeWithdrawn`       | `relayer`, `amount`                                                |
| `RelayerSlashed`              | `relayer`, `amount`                                                |
| `ChainAdded` / `ChainRemoved` | `chainId`                                                          |
| `TrustedRemoteSet`            | `chainId`, `remote`                                                |
| `VerifierSet`                 | `proofType`, `verifier`                                            |

---

## 2. ConfidentialStateContainerV3

**Path:** `contracts/core/ConfidentialStateContainerV3.sol`
**Solidity:** `^0.8.20`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Gas-optimized confidential state management with EIP-712 meta-transaction support, packed storage, and ZK proof verification.

### Roles

| Constant              | Description                  |
| --------------------- | ---------------------------- |
| `OPERATOR_ROLE`       | State lock/unlock operations |
| `EMERGENCY_ROLE`      | Freeze states, pause         |
| `VERIFIER_ADMIN_ROLE` | Verifier management          |

### Key State Variables

| Variable             | Type                       | Description              |
| -------------------- | -------------------------- | ------------------------ |
| `verifier`           | `IProofVerifier immutable` | Proof verifier contract  |
| `CHAIN_ID`           | `uint256 immutable`        | Deployment chain ID      |
| `DOMAIN_SEPARATOR`   | `bytes32 immutable`        | EIP-712 domain separator |
| `MAX_BATCH_SIZE`     | `uint256`                  | 50                       |
| `MAX_HISTORY_LENGTH` | `uint256`                  | 100                      |

### Functions

#### Core

```solidity
function registerState(
    bytes calldata encryptedState,
    bytes32 commitment,
    bytes32 nullifier,
    bytes calldata proof,
    bytes32 metadata
) external nonReentrant whenNotPaused
```

Register a new confidential state with ZK proof verification.

```solidity
function registerStateWithSignature(
    bytes calldata encryptedState,
    bytes32 commitment,
    bytes32 nullifier,
    bytes calldata proof,
    bytes32 metadata,
    address owner,
    uint256 deadline,
    bytes calldata signature
) external nonReentrant whenNotPaused
```

Register state via EIP-712 meta-transaction (gasless for owner).

```solidity
function batchRegisterStates(
    BatchStateInput[] calldata stateInputs
) external nonReentrant whenNotPaused
```

Batch register up to `MAX_BATCH_SIZE` states.

```solidity
function transferState(
    bytes32 oldCommitment,
    bytes calldata newEncryptedState,
    bytes32 newCommitment,
    bytes32 newNullifier,
    bytes32 spendingNullifier,
    bytes calldata proof,
    address newOwner
) external nonReentrant whenNotPaused
```

Transfer state ownership with ZK proof. Retires old commitment and creates new one.

#### View Functions

```solidity
function totalStates() external view returns (uint256)
function activeStates() external view returns (uint256)
function isStateActive(bytes32 commitment) external view returns (bool)
function getState(bytes32 commitment) external view returns (EncryptedState memory)
function getOwnerCommitments(address owner) external view returns (bytes32[] memory)
function getOwnerCommitmentsPaginated(address owner, uint256 offset, uint256 limit) external view returns (bytes32[] memory, uint256 total)
function getStateHistory(bytes32 commitment) external view returns (StateTransition[] memory)
function getNonce(address account) external view returns (uint256)
```

#### Admin Functions

```solidity
function setProofValidityWindow(uint256 _window) external onlyRole(DEFAULT_ADMIN_ROLE)
function setMaxStateSize(uint256 _maxSize) external onlyRole(DEFAULT_ADMIN_ROLE)
function lockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE)
function unlockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE)
function freezeState(bytes32 commitment) external onlyRole(EMERGENCY_ROLE)
function pause() external onlyRole(EMERGENCY_ROLE)
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE)
```

### Events

| Event                  | Parameters                                              |
| ---------------------- | ------------------------------------------------------- |
| `StateRegistered`      | `commitment`, `owner`, `nullifier`, `timestamp`         |
| `StateTransferred`     | `fromCommitment`, `toCommitment`, `newOwner`, `version` |
| `StateStatusChanged`   | `commitment`, `oldStatus`, `newStatus`                  |
| `StateBatchRegistered` | `commitments[]`, `owner`, `count`                       |

---

## 3. NullifierRegistryV3

**Path:** `contracts/core/NullifierRegistryV3.sol`
**Solidity:** `^0.8.20`
**Inherits:** `AccessControl`, `Pausable`

Nullifier registry with incremental Merkle tree (depth 32, ~4B capacity), cross-chain sync, and assembly-optimized hashing.

### Roles

| Constant         | Description            |
| ---------------- | ---------------------- |
| `REGISTRAR_ROLE` | Register nullifiers    |
| `BRIDGE_ROLE`    | Cross-chain operations |
| `EMERGENCY_ROLE` | Emergency pause        |

### Key State Variables

| Variable            | Type      | Description       |
| ------------------- | --------- | ----------------- |
| `TREE_DEPTH`        | `uint256` | 32                |
| `ROOT_HISTORY_SIZE` | `uint256` | 100               |
| `MAX_BATCH_SIZE`    | `uint256` | 20                |
| `merkleRoot`        | `bytes32` | Current tree root |
| `totalNullifiers`   | `uint256` | Counter           |

### Functions

```solidity
function registerNullifier(bytes32 nullifier, bytes32 commitment)
    external onlyRole(REGISTRAR_ROLE) whenNotPaused returns (uint256 index)

function batchRegisterNullifiers(bytes32[] calldata _nullifiers, bytes32[] calldata _commitments)
    external onlyRole(REGISTRAR_ROLE) whenNotPaused returns (uint256 startIndex)

function receiveCrossChainNullifiers(uint256 sourceChainId, bytes32[] calldata _nullifiers, bytes32[] calldata _commitments, bytes32 sourceMerkleRoot)
    external onlyRole(BRIDGE_ROLE) whenNotPaused

function exists(bytes32 nullifier) external view returns (bool)
function batchExists(bytes32[] calldata _nullifiers) external view returns (bool[] memory)
function getNullifierData(bytes32 nullifier) external view returns (NullifierData memory)
function isValidRoot(bytes32 root) external view returns (bool)
function verifyMerkleProof(bytes32 nullifier, uint256 index, bytes32[] calldata siblings, bytes32 root)
    external view returns (bool)
function getTreeStats() external view returns (uint256, bytes32, uint256)
```

### Events

| Event                          | Parameters                                                 |
| ------------------------------ | ---------------------------------------------------------- |
| `NullifierRegistered`          | `nullifier`, `commitment`, `index`, `registrar`, `chainId` |
| `NullifierBatchRegistered`     | `nullifiers[]`, `startIndex`, `count`                      |
| `MerkleRootUpdated`            | `oldRoot`, `newRoot`, `nullifierCount`                     |
| `CrossChainNullifiersReceived` | `sourceChainId`, `merkleRoot`, `count`                     |

---

## 4. ZaseonProtocolHub

**Path:** `contracts/core/ZaseonProtocolHub.sol`
**Solidity:** `^0.8.24`
**Inherits:** `AccessControl`, `Pausable`

Central registry and integration hub for all ZASEON components. Routes requests to modules and maintains versioned component registrations.

### Roles

| Constant        | Description                |
| --------------- | -------------------------- |
| `OPERATOR_ROLE` | Register/update components |
| `GUARDIAN_ROLE` | Emergency deactivation     |
| `UPGRADER_ROLE` | Upgrade management         |

### Functions

#### Component Registration (all `onlyRole(OPERATOR_ROLE)`)

```solidity
// Verifiers
function setVerifierRegistry(address _registry) external
function setUniversalVerifier(address _verifier) external
function registerVerifier(bytes32 verifierType, address _verifier, uint256 gasLimit) external
function batchRegisterVerifiers(bytes32[] calldata, address[] calldata, uint256[] calldata) external

// Bridge
function registerBridgeAdapter(uint256 chainId, address adapter, bool supportsPrivacy, uint256 minConfirmations) external
function batchRegisterBridgeAdapters(...) external

// Privacy modules
function setStealthAddressRegistry(address) external
function setPrivateRelayerNetwork(address) external
function setViewKeyRegistry(address) external

// Security modules
function setRelayProofValidator(address) external
function setRelayWatchtower(address) external
function setRelayCircuitBreaker(address) external

// Primitives
function setZKBoundStateLocks(address) external
function setProofCarryingContainer(address) external
function setCrossDomainNullifierAlgebra(address) external
function setPolicyBoundProofs(address) external
function setMultiProver(address) external
```

#### View Functions

```solidity
function getVerifier(bytes32 verifierType) external view returns (address)
function getBridgeAdapter(uint256 chainId) external view returns (address)
function isChainSupported(uint256 chainId) external view returns (bool)
function getSupportedChainIds() external view returns (uint256[] memory)
```

#### Emergency

```solidity
function pause() external onlyRole(GUARDIAN_ROLE)
function unpause() external onlyRole(OPERATOR_ROLE)
function deactivateVerifier(bytes32 verifierType) external onlyRole(GUARDIAN_ROLE)
function deactivateBridge(uint256 chainId) external onlyRole(GUARDIAN_ROLE)
```

---

## 5. ZaseonAtomicSwapV2

**Path:** `contracts/bridge/ZaseonAtomicSwapV2.sol`
**Solidity:** `^0.8.20`
**Inherits:** `Ownable`, `ReentrancyGuard`, `Pausable`, `SecurityModule`

Atomic cross-chain swaps with HTLC, stealth address support, commit-reveal front-running protection, and SecurityModule integration.

### Key Constants

| Constant               | Value     | Description                       |
| ---------------------- | --------- | --------------------------------- |
| `MIN_TIMELOCK`         | 1 hour    | Minimum swap lock                 |
| `MAX_TIMELOCK`         | 7 days    | Maximum swap lock                 |
| `MAX_FEE_BPS`          | 100 (1%)  | Maximum fee                       |
| `FEE_WITHDRAWAL_DELAY` | 2 days    | Timelock on fee withdrawal        |
| `MIN_REVEAL_DELAY`     | 2 seconds | L2-compatible commit-reveal delay |

### Functions

#### Swap Creation

```solidity
function createSwapETH(address recipient, bytes32 hashLock, uint256 timeLock, bytes32 commitment)
    external payable nonReentrant whenNotPaused returns (bytes32 swapId)

function createSwapToken(address recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock, bytes32 commitment)
    external nonReentrant whenNotPaused returns (bytes32 swapId)
```

#### Claim (Commit-Reveal)

```solidity
function commitClaim(bytes32 swapId, bytes32 commitHash) external whenNotPaused
function revealClaim(bytes32 swapId, bytes32 secret, bytes32 salt) external nonReentrant whenNotPaused
function claim(bytes32 swapId, bytes32 secret) external nonReentrant whenNotPaused  // Legacy
function refund(bytes32 swapId) external nonReentrant
```

#### View Functions

```solidity
function getSwapByHashLock(bytes32 hashLock) external view returns (Swap memory)
function isClaimable(bytes32 swapId) external view returns (bool)
function isRefundable(bytes32 swapId) external view returns (bool)
```

### Events

| Event            | Parameters                                                                    |
| ---------------- | ----------------------------------------------------------------------------- |
| `SwapCreated`    | `swapId`, `initiator`, `recipient`, `token`, `amount`, `hashLock`, `timeLock` |
| `SwapClaimed`    | `swapId`, `claimer`, `secret`                                                 |
| `SwapRefunded`   | `swapId`, `initiator`                                                         |
| `ClaimCommitted` | `swapId`, `committer`, `commitHash`                                           |

---

## 6. DirectL2Messenger

**Path:** `contracts/crosschain/DirectL2Messenger.sol`
**Solidity:** `^0.8.24`
**Inherits:** `ReentrancyGuard`, `AccessControl`, `Pausable`

Direct L2-to-L2 messaging supporting four paths: OP Superchain native, shared sequencers (Espresso/Astria), bonded relayer network (fast path), and L1 completion (slow path).

### Roles

| Constant         | Description                         |
| ---------------- | ----------------------------------- |
| `OPERATOR_ROLE`  | Route config, slashing, pause       |
| `RELAYER_ROLE`   | Auto-granted on `registerRelayer()` |
| `SEQUENCER_ROLE` | Shared sequencer message delivery   |

### Enums

- **`MessagePath`**: `SUPERCHAIN`, `SHARED_SEQUENCER`, `FAST_RELAYER`, `SLOW_L1`
- **`MessageStatus`**: `NONE`, `SENT`, `RELAYED`, `CHALLENGED`, `EXECUTED`, `FAILED`, `REFUNDED`

### Functions

#### Message Sending & Receiving

```solidity
function sendMessage(uint256 destChainId, address recipient, bytes calldata payload, MessagePath path, bytes32 nullifierBinding)
    external payable nonReentrant whenNotPaused returns (bytes32 messageId)

function receiveMessage(bytes32 messageId, uint256 sourceChainId, address sender, address recipient, bytes calldata payload)
    external nonReentrant whenNotPaused

function receiveViaRelayer(bytes32 messageId, uint256 sourceChainId, address sender, address recipient, bytes calldata payload, bytes[] calldata signatures)
    external nonReentrant whenNotPaused

function executeMessage(bytes32 messageId) external nonReentrant whenNotPaused
```

#### Relayer Management

```solidity
function registerRelayer() external payable nonReentrant          // Bond 1 ETH
function withdrawRelayerBond() external nonReentrant              // After 7-day unbonding
function slashRelayer(address relayer, uint256 amount, bytes32 reason) external onlyRole(OPERATOR_ROLE)
```

#### Challenge Mechanism

```solidity
function challengeMessage(bytes32 messageId, bytes32 reason) external payable nonReentrant
function resolveChallenge(bytes32 messageId, bool fraudProven) external onlyRole(OPERATOR_ROLE) nonReentrant
```

#### Route Configuration

```solidity
function configureRoute(uint256 sourceChainId, uint256 destChainId, MessagePath path, address adapter, uint256 minConfirmations, uint256 challengeWindow)
    external onlyRole(OPERATOR_ROLE)
function setSuperchainMessenger(address messenger) external onlyRole(DEFAULT_ADMIN_ROLE)
function setEspressoSequencer(address sequencer) external onlyRole(DEFAULT_ADMIN_ROLE)
function setAstriaSequencer(address sequencer) external onlyRole(DEFAULT_ADMIN_ROLE)
```

### Events

| Event               | Parameters                                                                                     |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| `MessageSent`       | `messageId`, `sourceChainId`, `destChainId`, `sender`, `recipient`, `payload`, `nonce`, `path` |
| `MessageReceived`   | `messageId`, `sourceChainId`, `sender`, `recipient`, `payload`                                 |
| `MessageExecuted`   | `messageId`, `success`, `returnData`                                                           |
| `RelayerRegistered` | `relayer`, `bond`                                                                              |
| `RelayerSlashed`    | `relayer`, `amount`, `reason`                                                                  |
| `MessageChallenged` | `messageId`, `challenger`, `reason`                                                            |
| `ChallengeResolved` | `messageId`, `fraudProven`, `winner`                                                           |

---

## 7. UniversalShieldedPool

**Path:** `contracts/privacy/UniversalShieldedPool.sol`
**Solidity:** `^0.8.24`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Multi-asset shielded pool with Poseidon-based Merkle tree (depth 32), cross-chain commitment bridging, ZK withdrawal proofs, and sanctions screening.

### Roles

| Constant          | Description                         |
| ----------------- | ----------------------------------- |
| `RELAYER_ROLE`    | Sync cross-chain commitments        |
| `OPERATOR_ROLE`   | Asset registration, verifier config |
| `COMPLIANCE_ROLE` | Sanctions oracle config             |

### Key Constants

| Constant            | Value      | Description      |
| ------------------- | ---------- | ---------------- |
| `TREE_DEPTH`        | 32         | ~4B deposits     |
| `MAX_DEPOSIT`       | 10,000 ETH | Per deposit cap  |
| `MIN_DEPOSIT`       | 0.001 ETH  | Minimum deposit  |
| `ROOT_HISTORY_SIZE` | 100        | Root ring buffer |

### Functions

#### Deposits

```solidity
function depositETH(bytes32 commitment) external payable nonReentrant whenNotPaused
function depositERC20(bytes32 assetId, uint256 amount, bytes32 commitment) external nonReentrant whenNotPaused
```

#### Withdrawals

```solidity
function withdraw(WithdrawalProof calldata wp) external nonReentrant whenNotPaused
```

Withdraw with ZK proof. Marks nullifier as spent, transfers funds minus optional relayer fee.

> **Session 8 Change**: Now includes a solvency check — verifies pool has sufficient ETH or ERC20 balance before transfer.

#### Cross-Chain

```solidity
function insertCrossChainCommitments(CrossChainCommitmentBatch calldata batch)
    external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE)
```

> **Session 8 Change**: Now requires `batchVerifier != address(0)`. Reverts if no batch verifier is configured.

#### View Functions

```solidity
function getLastRoot() external view returns (bytes32)
function isKnownRoot(bytes32 root) external view returns (bool)
function isSpent(bytes32 nullifier) external view returns (bool)
function getPoolStats() external view returns (uint256, uint256, uint256, uint256, bytes32)
function getRegisteredAssets() external view returns (bytes32[] memory)
```

#### Admin Functions

```solidity
function registerAsset(bytes32 assetId, address tokenAddress) external onlyRole(OPERATOR_ROLE)
function setWithdrawalVerifier(address _verifier) external onlyRole(OPERATOR_ROLE)
function setBatchVerifier(address _verifier) external onlyRole(OPERATOR_ROLE)
function setSanctionsOracle(address _oracle) external onlyRole(COMPLIANCE_ROLE)
function disableTestMode() external onlyRole(DEFAULT_ADMIN_ROLE)  // Irreversible
```

### Events

| Event                           | Parameters                                                  |
| ------------------------------- | ----------------------------------------------------------- |
| `Deposit`                       | `commitment`, `assetId`, `leafIndex`, `amount`, `timestamp` |
| `Withdrawal`                    | `nullifier`, `assetId`, `recipient`, `amount`, `relayerFee` |
| `CrossChainCommitmentsInserted` | `sourceChainId`, `count`, `newRoot`                         |
| `AssetRegistered`               | `assetId`, `tokenAddress`                                   |

---

## 8. StealthAddressRegistry

**Path:** `contracts/privacy/StealthAddressRegistry.sol`
**Solidity:** `^0.8.24`
**Inherits:** `Initializable`, `UUPSUpgradeable`, `AccessControlUpgradeable`, `ReentrancyGuardUpgradeable`

ERC-5564 compatible stealth address registry supporting multiple curves (secp256k1, ed25519, BLS12-381, Pallas/Vesta, BN254), dual-key stealth, cross-chain derivation with ZK proofs, and view-tag-indexed scanning.

### Roles

| Constant         | Description                |
| ---------------- | -------------------------- |
| `OPERATOR_ROLE`  | General operations         |
| `ANNOUNCER_ROLE` | Authorized announcements   |
| `UPGRADER_ROLE`  | UUPS upgrade authorization |

### Enums

- **`CurveType`**: `SECP256K1`, `ED25519`, `BLS12_381`, `PALLAS`, `VESTA`, `BN254`
- **`KeyStatus`**: `INACTIVE`, `ACTIVE`, `REVOKED`

### Functions

#### Initialization

```solidity
function initialize(address admin) external initializer
function setDerivationVerifier(address _derivationVerifier) external onlyRole(DEFAULT_ADMIN_ROLE)
```

#### Meta-Address Management

```solidity
function registerMetaAddress(bytes calldata spendingPubKey, bytes calldata viewingPubKey, CurveType curveType, uint256 schemeId) external
function updateMetaAddressStatus(KeyStatus newStatus) external
function revokeMetaAddress() external  // Irreversible
```

#### Stealth Address Derivation

```solidity
function deriveStealthAddress(address recipient, bytes calldata ephemeralPubKey, bytes32 sharedSecretHash)
    external view returns (address stealthAddress, bytes1 viewTag)

function computeDualKeyStealth(bytes32 spendingPubKeyHash, bytes32 viewingPubKeyHash, bytes32 ephemeralPrivKeyHash, uint256 chainId)
    external returns (bytes32 stealthHash, address derivedAddress)
```

#### Announcements

```solidity
function announce(uint256 schemeId, address stealthAddress, bytes calldata ephemeralPubKey, bytes calldata viewTag, bytes calldata metadata)
    external onlyRole(ANNOUNCER_ROLE)

function announcePrivate(uint256 schemeId, address stealthAddress, bytes calldata ephemeralPubKey, bytes calldata viewTag, bytes calldata metadata)
    external payable  // Min 0.0001 ETH
```

#### Scanning

```solidity
function getAnnouncementsByViewTag(bytes1 viewTag) external view returns (address[] memory)
function checkStealthOwnership(address stealthAddress, bytes32 viewingPrivKeyHash, bytes32 spendingPubKeyHash)
    external view returns (bool isOwner)
function batchScan(bytes32 viewingPrivKeyHash, bytes32 spendingPubKeyHash, address[] calldata candidates)
    external view returns (address[] memory owned)
```

#### Cross-Chain Stealth

```solidity
function deriveCrossChainStealth(bytes32 sourceStealthKey, uint256 destChainId, bytes calldata derivationProof)
    external returns (bytes32 destStealthKey)
```

#### View Functions

```solidity
function getMetaAddress(address owner) external view returns (StealthMetaAddress memory)
function getAnnouncement(address stealthAddress) external view returns (Announcement memory)
function getStats() external view returns (uint256, uint256, uint256)
```

### Events

| Event                      | Parameters                                                                       |
| -------------------------- | -------------------------------------------------------------------------------- |
| `MetaAddressRegistered`    | `owner`, `spendingPubKey`, `viewingPubKey`, `curveType`, `schemeId`              |
| `StealthAnnouncement`      | `schemeId`, `stealthAddress`, `caller`, `ephemeralPubKey`, `viewTag`, `metadata` |
| `CrossChainStealthDerived` | `sourceKey`, `destKey`, `sourceChainId`, `destChainId`                           |
| `DualKeyStealthGenerated`  | `stealthHash`, `derivedAddress`, `chainId`                                       |

---

## 9. BN254 Library

**Path:** `contracts/libraries/BN254.sol`
**Solidity:** `^0.8.24`

Gas-efficient BN254 (alt_bn128) elliptic curve operations using EVM precompiles. Provides the cryptographic primitives for CLSAG ring signature verification.

### Types

```solidity
struct G1Point {
    uint256 x;
    uint256 y;
}
```

### Functions

```solidity
/// @notice Elliptic curve point addition on BN254
function add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory)

/// @notice Scalar multiplication on BN254
function mul(G1Point memory p, uint256 s) internal view returns (G1Point memory)

/// @notice Compress a G1 point to 32 bytes (x-coordinate + sign bit)
function compress(G1Point memory p) internal pure returns (bytes32)

/// @notice Decompress a 32-byte compressed point back to G1Point
function decompress(bytes32 compressed) internal view returns (G1Point memory)

/// @notice Hash arbitrary data to a BN254 curve point (hash-to-curve)
function hashToPoint(bytes memory data) internal view returns (G1Point memory)

/// @notice Check whether a point lies on the BN254 curve
function isOnCurve(G1Point memory p) internal pure returns (bool)

/// @notice Return the curve generator point G
function generator() internal pure returns (G1Point memory)

/// @notice Negate a G1 point (additive inverse)
function negate(G1Point memory p) internal pure returns (G1Point memory)
```

### Gas Costs

| Operation                 | Approximate Gas           |
| ------------------------- | ------------------------- |
| `add`                     | ~150 (ecAdd precompile)   |
| `mul`                     | ~6,000 (ecMul precompile) |
| `hashToPoint`             | ~6,200 (mul + keccak)     |
| `compress` / `decompress` | ~50 / ~6,200              |

---

## 10. RingSignatureVerifier

**Path:** `contracts/verifiers/RingSignatureVerifier.sol`
**Solidity:** `^0.8.24`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Production CLSAG (Compact Linkable Spontaneous Anonymous Group) ring signature verifier. Enables privacy-preserving authentication where a signer proves membership in a set without revealing which member they are.

### Roles

| Constant     | Description                        |
| ------------ | ---------------------------------- |
| `ADMIN_ROLE` | Key ring management, configuration |

### Key State Variables

| Variable        | Type                       | Description                                       |
| --------------- | -------------------------- | ------------------------------------------------- |
| `MAX_RING_SIZE` | `uint256 constant`         | Maximum ring members (default 32)                 |
| `keyImages`     | `mapping(bytes32 => bool)` | Tracks used key images to prevent double-spending |

### Core Functions

```solidity
/// @notice Verify a CLSAG ring signature
/// @param message The signed message hash
/// @param ring Array of public keys forming the ring
/// @param keyImage The key image (linkability tag)
/// @param c0 Initial challenge scalar
/// @param s Array of response scalars
/// @return valid Whether the signature is valid
function verifyRingSignature(
    bytes32 message,
    BN254.G1Point[] calldata ring,
    BN254.G1Point calldata keyImage,
    uint256 c0,
    uint256[] calldata s
) external view returns (bool valid)

/// @notice Check if a key image has been used (double-spend check)
function isKeyImageUsed(bytes32 keyImageHash) external view returns (bool)

/// @notice Register a key image as used
function markKeyImageUsed(bytes32 keyImageHash) external
```

### Events

| Event                   | Parameters                                |
| ----------------------- | ----------------------------------------- |
| `RingSignatureVerified` | `messageHash`, `ringSize`, `keyImageHash` |
| `KeyImageRegistered`    | `keyImageHash`, `registrar`               |

### Gas Costs

| Ring Size  | Approximate Verification Gas |
| ---------- | ---------------------------- |
| 2 members  | ~52,000                      |
| 4 members  | ~104,000                     |
| 8 members  | ~208,000                     |
| 16 members | ~416,000                     |
| 32 members | ~832,000                     |

> **Note:** ~26,000 gas per ring member, dominated by BN254 scalar multiplications.

---

## 11. Bridge Adapters

### Overview

All bridge adapters implement the `IBridgeAdapter` pattern and use role-based access control with `ReentrancyGuard` and `Pausable`.

### zkSyncBridgeAdapter

**Path:** `contracts/crosschain/zkSyncBridgeAdapter.sol`

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token, uint256 amount, uint256 l2GasLimit) external payable returns (bytes32 depositId)
function proveWithdrawal(bytes32 withdrawalId, L2LogProof calldata proof) external
function claimWithdrawal(bytes32 withdrawalId) external  // Transfers ETH to recipient
function configureBridge(uint256 chainId, address diamondProxy, address l1Bridge, address l2Bridge) external
```

### ScrollBridgeAdapter

**Path:** `contracts/crosschain/ScrollBridgeAdapter.sol`

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token, uint256 amount, uint256 l2GasLimit) external payable returns (bytes32 depositId)
function proveWithdrawal(bytes32 withdrawalId, ScrollWithdrawalProof calldata proof) external
function claimWithdrawal(bytes32 withdrawalId) external  // Transfers ETH to recipient
function configureScroll(uint256 chainId, address l1Messenger, address l1GatewayRouter, address l1MessageQueue, address rollup) external
```

### LineaBridgeAdapter

**Path:** `contracts/crosschain/LineaBridgeAdapter.sol`

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token, uint256 amount, uint256 messageFee) external payable returns (bytes32 depositId)
function proveWithdrawal(bytes32 withdrawalId, LineaClaimProof calldata proof) external
function claimWithdrawal(bytes32 withdrawalId) external  // Transfers ETH to recipient
function configureLinea(uint256 chainId, address messageService, address tokenBridge) external
```

### LayerZeroAdapter

**Path:** `contracts/crosschain/LayerZeroAdapter.sol`

```solidity
function send(uint32 dstEid, address receiver, bytes calldata payload, MessagingOptions calldata options) external payable returns (bytes32 messageId)
function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external
function estimateFee(uint32 dstEid, bytes calldata payload, uint128 dstGasLimit) external view returns (MessagingFee memory)
function configureEndpoint(uint32 eid, address endpoint, uint64 confirmations, uint128 baseGas) external
function setPeer(uint32 eid, bytes32 peer) external
```

### HyperlaneAdapter

**Path:** `contracts/crosschain/HyperlaneAdapter.sol`

```solidity
function dispatch(uint32 dstDomain, bytes32 recipient, bytes calldata body) external payable returns (bytes32 messageId)
function handle(uint32 srcDomain, bytes32 sender, bytes calldata body) external
function quoteDispatch(uint32 dstDomain, bytes calldata body) external view returns (uint256 nativeFee)
function configureDomain(uint32 domain, bytes32 router, address ism, uint256 gasOverhead) external
function configureISM(uint32 domain, ISMType ismType, address ismAddress, uint8 threshold, address[] calldata validators) external
```

### BitVMAdapter

**Path:** `contracts/crosschain/BitVMAdapter.sol`

```solidity
function bridgeMessage(address targetAddress, bytes calldata payload, address refundAddress) external payable returns (bytes32 messageId)
function estimateFee(address targetAddress, bytes calldata payload) external view returns (uint256 nativeFee)
function isMessageVerified(bytes32 messageId) external view returns (bool verified)
function markVerified(bytes32 messageId, bytes32 proofCommitment) external
function challengeMessage(bytes32 messageId, bytes32 challengeHash) external
function resolveChallenge(bytes32 messageId, bool challengeAccepted) external
function finalizeMessage(bytes32 messageId) external
function setFeeParams(uint256 _baseFee, uint256 _perByteFee, uint256 _bridgeFeeBps) external
function setChallengeWindow(uint256 newWindow) external
function emergencyWithdrawETH(address payable to, uint256 amount) external
function emergencyWithdrawERC20(address token, address to) external
```

---

## 12. BatchAccumulator

**Path:** `contracts/privacy/BatchAccumulator.sol`

Batches privacy transactions for efficient ZK proof verification. On batch failure, nullifiers and commitments are recovered so users can resubmit.

```solidity
function submitTransaction(bytes32 batchId, bytes32 nullifierHash, bytes32 commitment, bytes calldata encryptedData) external
function processBatch(bytes32 batchId, bytes calldata batchProof) external  // Recovers nullifiers on failure
function createBatch(bytes32 routeId) external returns (bytes32 batchId)
```

---

## 13. DecentralizedRelayerRegistry

**Path:** `contracts/relayer/DecentralizedRelayerRegistry.sol`

Manages relayer registration, staking, and rewards. Overpayment above `MIN_STAKE` is automatically refunded.

```solidity
function register() external payable  // Requires msg.value >= MIN_STAKE; refunds excess
function deregister() external
function claimRewards() external
function slash(address relayer, uint256 amount) external onlyRole(SLASHER_ROLE)
```

---

## 14. CrossChainEmergencyRelay

**Path:** `contracts/crosschain/CrossChainEmergencyRelay.sol`

Cross-chain emergency propagation. Validates source chain registration before accepting messages.

```solidity
function broadcastEmergency(EmergencyMessage calldata msg_) external
function receiveEmergency(EmergencyMessage calldata msg_) external  // Validates sourceChainId
function registerChain(uint256 chainId, address adapter) external
```

---

## 15. CrossChainNullifierSync

**Path:** `contracts/crosschain/CrossChainNullifierSync.sol`

Synchronizes nullifiers across chains with per-chain sequence numbers for replay protection.

```solidity
function flushToChain(uint256 targetChainId) external  // Includes syncSequence in payload
function receiveNullifiers(bytes calldata payload) external
function getPendingCount() external view returns (uint256)
```

---

## 16. ProtocolEmergencyCoordinator

**Path:** `contracts/security/ProtocolEmergencyCoordinator.sol`

Multi-role emergency coordination with validated role separation.

```solidity
function confirmRoleSeparation(address guardian, address responder, address recovery) external onlyRole(DEFAULT_ADMIN_ROLE)
function initiateIncident(EmergencySeverity severity, string calldata description) external
function escalateIncident(bytes32 incidentId) external
function resolveIncident(bytes32 incidentId) external
```

---

## 17. GasNormalizer

**Path:** `contracts/privacy/GasNormalizer.sol`
**Solidity:** `^0.8.24`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Normalizes gas consumption to fixed tiers to prevent gas-based fingerprinting of privacy operations. Integrated with the privacy tier system.

### Gas Tiers

| Tier   | Target Gas |
| ------ | ---------- |
| TIER_1 | 100,000    |
| TIER_2 | 200,000    |
| TIER_3 | 500,000    |
| TIER_4 | 1,000,000  |
| TIER_5 | 2,000,000  |
| TIER_6 | 5,000,000  |

```solidity
function normalizeGas(uint256 actualGas) public pure returns (uint256 normalizedGas)
function executeNormalized(address target, bytes calldata data) external returns (bytes memory)
function setTierEnabled(uint256 tier, bool enabled) external onlyRole(ADMIN_ROLE)
```

---

## 18. ProofEnvelope Library

**Path:** `contracts/libraries/ProofEnvelope.sol`
**Solidity:** `^0.8.24`

Pads ZK proofs to fixed sizes to prevent proof-system inference attacks. All proofs are wrapped in a standard envelope before on-chain submission.

### Envelope Sizes

| Size        | Bytes |
| ----------- | ----- |
| SMALL       | 512   |
| MEDIUM      | 1,024 |
| LARGE       | 2,048 |
| EXTRA_LARGE | 4,096 |

```solidity
function wrap(bytes memory proof) internal pure returns (bytes memory paddedProof)
function unwrap(bytes memory paddedProof) internal pure returns (bytes memory proof)
function getEnvelopeSize(uint256 proofLength) internal pure returns (uint256 size)
```

---

## 19. FixedSizeMessageWrapper Library

**Path:** `contracts/libraries/FixedSizeMessageWrapper.sol`
**Solidity:** `^0.8.24`

Pads cross-chain messages to fixed sizes to prevent payload-size correlation between source and destination chains.

### Message Sizes

| Tier        | Bytes  |
| ----------- | ------ |
| STANDARD    | 1,024  |
| LARGE       | 4,096  |
| EXTRA_LARGE | 16,384 |

```solidity
function wrapMessage(bytes memory message) internal pure returns (bytes memory paddedMessage)
function unwrapMessage(bytes memory paddedMessage) internal pure returns (bytes memory message)
function getMessageTier(uint256 messageLength) internal pure returns (uint256 tier)
```

---

## 20. Multi-Relayer Quorum (CrossChainPrivacyHub)

**Path:** `contracts/privacy/CrossChainPrivacyHub.sol` (inline feature)
**Solidity:** `^0.8.24`

Multi-relayer quorum verification is embedded in `CrossChainPrivacyHub`. It requires multiple independent relayers to confirm a transfer before execution, preventing single-relayer correlation attacks.

### Quorum Requirements

| Privacy Tier | Required Confirmations |
| ------------ | ---------------------- |
| ENHANCED     | 2                      |
| MAXIMUM      | 3                      |

```solidity
// State variables in CrossChainPrivacyHub
mapping(PrivacyLevel => uint8) public requiredRelayConfirmations;
mapping(bytes32 => mapping(address => bool)) public relayConfirmed;
mapping(bytes32 => uint8) public relayConfirmationCount;

// Admin configuration
function setRequiredRelayConfirmations(PrivacyLevel level, uint8 count) external onlyRole(DEFAULT_ADMIN_ROLE)
```

---

## 21. Denomination Enforcement (CrossChainLiquidityVault)

**Path:** `contracts/bridge/CrossChainLiquidityVault.sol` (inline feature)
**Solidity:** `^0.8.24`

Denomination enforcement is embedded in `CrossChainLiquidityVault`. It restricts ETH and ERC-20 transfers to fixed denominations in MAXIMUM privacy tier to prevent amount-based correlation.

### Standard Denominations (ETH)

0.1, 1, 10, 100 ether (configurable per-token)

```solidity
// Constants in CrossChainLiquidityVault
uint256 public constant DENOMINATION_TIER_1 = 0.1 ether;
uint256 public constant DENOMINATION_TIER_2 = 1 ether;
uint256 public constant DENOMINATION_TIER_3 = 10 ether;
uint256 public constant DENOMINATION_TIER_4 = 100 ether;
bool public denominationEnforcement = true;

// Per-token denomination tiers
mapping(address => uint256[]) public tokenDenominationTiers;
```

---

## 22. Relay Jitter (CrossChainPrivacyHub)

**Path:** `contracts/privacy/CrossChainPrivacyHub.sol` (inline feature)
**Solidity:** `^0.8.24`

Per-user relay scheduling jitter is embedded in `CrossChainPrivacyHub`. It adds randomized delays before transfers become relayable, decorrelating submission timing.

```solidity
// State variables in CrossChainPrivacyHub
uint256 public minRelayJitter = 5 minutes;
uint256 public maxRelayJitter = 25 minutes;
bool public relayJitterEnabled;
mapping(bytes32 => uint256) public transferRelayableAt;

// Admin configuration
function setRelayJitter(uint256 _min, uint256 _max) external onlyRole(DEFAULT_ADMIN_ROLE)
function setRelayJitterEnabled(bool _enabled) external onlyRole(DEFAULT_ADMIN_ROLE)
```

---

## 23. Integration Contracts

**Path:** `contracts/integrations/`

Eight integration contracts unify ZASEON's core primitives (stealth addresses, ring signatures, ZK proofs, nullifiers) with DeFi protocols, bridges, oracles, and security modules.

### 23.1 CorePrivacyIntegration

**Path:** `contracts/integrations/CorePrivacyIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Core `IPrivacyIntegration` implementation unifying stealth addresses (ERC-5564), CLSAG-style ring signatures, Pedersen commitments with Bulletproofs+ range proofs, and cross-domain nullifier algebra (CDNA).

| Function                       | Visibility    | Description                            |
| ------------------------------ | ------------- | -------------------------------------- |
| `registerStealthMetaAddress`   | external      | Register ERC-5564 stealth meta-address |
| `deriveStealthAddress`         | external      | Derive one-time stealth address        |
| `checkStealthAddressOwnership` | external view | Verify stealth address ownership       |
| `verifyRingSignature`          | external view | Verify CLSAG ring signature            |
| `isKeyImageUsed`               | external view | Check key image double-spend status    |
| `createCommitment`             | external      | Create Pedersen commitment             |
| `verifyCommitment`             | external view | Verify commitment opening              |
| `verifyRangeProof`             | external view | Verify Bulletproofs+ range proof       |
| `computeNullifier`             | external view | Compute nullifier hash                 |
| `isNullifierUsed`              | external view | Check nullifier spend status           |
| `registerNullifier`            | external      | Register nullifier as spent            |

### 23.2 CrossChainBridgeIntegration

**Path:** `contracts/integrations/CrossChainBridgeIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Unified cross-chain bridge entry point supporting 40+ chains across L2 rollups, interop protocols (LayerZero, Hyperlane), and privacy chains (Aztec). Auto-routing, batching, failover, and privacy integration.

| Function                | Visibility       | Description                            |
| ----------------------- | ---------------- | -------------------------------------- |
| `configureChain`        | external         | Configure chain parameters             |
| `registerBridgeAdapter` | external         | Register IBridgeAdapter implementation |
| `configureRoute`        | external         | Configure cross-chain route            |
| `bridgeTransfer`        | external payable | Initiate cross-chain transfer          |
| `completeTransfer`      | external         | Finalize incoming transfer             |
| `getQuote`              | external view    | Quote fees for a transfer              |
| `getSupportedChains`    | external view    | List all supported chain IDs           |

### 23.3 PrivacyOracleIntegration

**Path:** `contracts/integrations/PrivacyOracleIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Privacy-preserving oracle (`IPrivacyOracle`) for encrypted data feeds. Provides ECIES-encrypted price data from Chainlink/Pyth/Chronicle/private TEE oracles with Pedersen commitments and ZK range proofs.

| Function                | Visibility    | Description                      |
| ----------------------- | ------------- | -------------------------------- |
| `addPair`               | external      | Register a price pair            |
| `registerOracleNode`    | external      | Register an oracle node          |
| `getEncryptedPrice`     | external view | Get encrypted latest price       |
| `requestEncryptedPrice` | external      | Request fresh encrypted price    |
| `verifyPriceProof`      | external view | Verify ZK proof of price         |
| `verifyPriceInRange`    | external view | Verify price within range via ZK |
| `submitPriceUpdate`     | external      | Submit plaintext price update    |
| `submitEncryptedPrice`  | external      | Submit encrypted price update    |

### 23.4 PrivacyPoolIntegration

**Path:** `contracts/integrations/PrivacyPoolIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Privacy-preserving pool (`IPrivacyPool`) with hidden-amount deposits, ZK proof withdrawals, and confidential token swaps. Three-layer architecture: Pedersen commitment, privacy operations, and cross-chain nullifier management.

| Function              | Visibility       | Description                    |
| --------------------- | ---------------- | ------------------------------ |
| `privateDeposit`      | external payable | Deposit ETH with commitment    |
| `privateDepositERC20` | external         | Deposit ERC20 with commitment  |
| `privateWithdraw`     | external         | ZK-verified withdrawal         |
| `privateSwap`         | external         | Confidential token swap        |
| `getMerkleRoot`       | external view    | Current commitment Merkle root |
| `commitmentExists`    | external view    | Check commitment inclusion     |
| `isNullifierSpent`    | external view    | Check nullifier spend status   |
| `emergencyWithdraw`   | external         | Admin emergency fund recovery  |

### 23.5 PrivateProofRelayIntegration

**Path:** `contracts/integrations/PrivateProofRelayIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Cross-chain private proof relay connecting to CrossChainPrivacyHub. Stealth-address-based delivery, cross-chain nullifier tracking, ZK proofs for amount hiding, and encrypted metadata.

| Function                    | Visibility       | Description                     |
| --------------------------- | ---------------- | ------------------------------- |
| `initiatePrivateRelay`      | external payable | Start cross-chain private relay |
| `completePrivateRelay`      | external         | Finalize incoming relay         |
| `verifyCrossChainNullifier` | external view    | Verify cross-chain nullifier    |
| `refundExpiredRelay`        | external         | Refund expired relay            |
| `getRelayRecord`            | external view    | Get relay details               |
| `getSupportedChains`        | external view    | List supported chains           |

### 23.6 ZKSLockIntegration

**Path:** `contracts/integrations/ZKSLockIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Connects ZK-Bound State Locks with PC³ (ProofCarryingContainer), CDNA (CrossDomainNullifierAlgebra), EASC, and PBP primitives for unified cross-primitive operations.

| Function                | Visibility    | Description                    |
| ----------------------- | ------------- | ------------------------------ |
| `lockContainer`         | external      | Lock a container with ZK proof |
| `unlockContainer`       | external      | Unlock via ZK verification     |
| `createCrossDomainLock` | external      | Create cross-domain state lock |
| `createAtomicLock`      | external      | Create atomic multi-lock       |
| `batchCreateLocks`      | external      | Batch lock creation            |
| `getLockInfo`           | external view | Query lock details             |
| `isContainerLocked`     | external view | Check container lock status    |

### 23.7 AddedSecurityOrchestrator

**Path:** `contracts/integrations/AddedSecurityOrchestrator.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Lightweight orchestrator for security modules. Manages centralized alerts, protected contract registry, and security score tracking. Coordinates RuntimeSecurityMonitor, ZKFraudProof, ThresholdSignature, CryptographicAttestation, and MEVProtection modules.

| Function                | Visibility    | Description                         |
| ----------------------- | ------------- | ----------------------------------- |
| `protectContract`       | external      | Add contract to protection registry |
| `unprotectContract`     | external      | Remove contract from protection     |
| `updateSecurityScore`   | external      | Update security score for contract  |
| `createAlert`           | external      | Create security alert               |
| `resolveAlert`          | external      | Resolve alert                       |
| `getModuleAddresses`    | external view | All registered module addresses     |
| `getProtectedAddresses` | external view | All protected contracts             |

### 23.8 ZaseonAtomicSwapSecurityIntegration

**Path:** `contracts/integrations/ZaseonAtomicSwapSecurityIntegration.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Security wrapper for atomic swaps with 4-layer protection: MEV protection (commit-reveal), flash loan detection (balance snapshots), rate limiting + circuit breaker, and HTLC execution with stealth addresses.

| Function              | Visibility    | Description                     |
| --------------------- | ------------- | ------------------------------- |
| `commitSwap`          | external      | Phase 1: commit swap hash       |
| `revealSwap`          | external      | Phase 2: reveal and execute     |
| `takeBalanceSnapshot` | external      | Flash loan guard snapshot       |
| `validateBalance`     | external view | Validate balance hasn't changed |
| `claimSwap`           | external      | HTLC claim with preimage        |
| `refundSwap`          | external      | HTLC refund after expiry        |

### 23.9 UniswapV3RebalanceAdapter

**Path:** `contracts/integrations/UniswapV3RebalanceAdapter.sol`
**Inherits:** `IRebalanceSwapAdapter`, `AccessControl`, `ReentrancyGuard`, `Pausable`

DEX adapter for settlement rebalancing via Uniswap V3. Authorized vaults call `swap()` during cross-chain settlement to convert received tokens into the target denomination. Supports ETH↔ERC20 via WETH wrapping, configurable fee tiers per token pair, slippage protection, and deadline enforcement.

| Function              | Visibility    | Description                                             |
| --------------------- | ------------- | ------------------------------------------------------- |
| `swap`                | external      | Execute swap via Uniswap V3 (authorized callers only)   |
| `getQuote`            | external      | Estimate output amount for a given input                |
| `isSwapSupported`     | external view | Check if a swap pair is supported (pool exists)         |
| `setAuthorizedCaller` | external      | Authorize/deauthorize a vault to call swap (admin only) |
| `setFeeTierOverride`  | external      | Override Uniswap fee tier for a token pair (admin only) |

**Key Features:**

- Automatic ETH↔WETH wrapping/unwrapping for native ETH swaps
- Per-pair fee tier overrides (default: 3000 = 0.3%)
- Caller whitelist via `authorizedCallers` mapping
- Slippage protection via `minAmountOut` parameter
- Uses Uniswap V3 `ISwapRouter.exactInputSingle` for optimal single-hop execution

---

## 24. Security Contracts

**Path:** `contracts/security/`

Twenty security contracts providing circuit breakers, rate limiting, fraud proofs, MEV protection, flash loan guards, emergency recovery, watchtower networks, and health monitoring. `ProtocolEmergencyCoordinator` is documented in [Section 16](#16-protocolemergencycoordinator).

### 24.1 SecurityModule (Abstract)

**Path:** `contracts/security/SecurityModule.sol`
**Inherits:** (standalone abstract)

Inheritable security module providing rate limiting, circuit breakers, flash loan guards (same-block deposit/withdrawal detection), and daily/single withdrawal limits. Gas-optimized with packed boolean flags. Inherited by CrossChainProofHubV3, ZaseonAtomicSwapV2, etc.

| Function                  | Visibility  | Description                   |
| ------------------------- | ----------- | ----------------------------- |
| `rateLimitingEnabled`     | public view | Rate limiting status          |
| `circuitBreakerEnabled`   | public view | Circuit breaker status        |
| `circuitBreakerTripped`   | public view | Whether breaker is tripped    |
| `flashLoanGuardEnabled`   | public view | Flash loan guard status       |
| `withdrawalLimitsEnabled` | public view | Withdrawal limits status      |
| `getRemainingActions`     | public view | Remaining actions in window   |
| `getRemainingWithdrawal`  | public view | Remaining withdrawal capacity |

### 24.2 RelayCircuitBreaker

**Path:** `contracts/security/RelayCircuitBreaker.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Automatic circuit breaker with anomaly detection for bridge operations. Auto-pause on large withdrawals, velocity-based anomaly detection (WARNING/DEGRADED/HALTED), multi-sig recovery, and gradual recovery mechanism.

| Function            | Visibility    | Description                              |
| ------------------- | ------------- | ---------------------------------------- |
| `recordTransaction` | external      | Record bridge transaction for monitoring |
| `updateTVL`         | external      | Update tracked TVL                       |
| `reportAnomaly`     | external      | Report detected anomaly                  |
| `resolveAnomaly`    | external      | Mark anomaly as resolved                 |
| `proposeRecovery`   | external      | Propose recovery from halt               |
| `approveRecovery`   | external      | Approve recovery proposal                |
| `executeRecovery`   | external      | Execute approved recovery                |
| `emergencyHalt`     | external      | Immediate halt                           |
| `isOperational`     | external view | Check operational status                 |
| `isDegraded`        | external view | Check degraded status                    |

### 24.3 RelayRateLimiter

**Path:** `contracts/security/RelayRateLimiter.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Per-user and global rate limiting with hourly/daily caps, TVL caps, automatic circuit breakers, anomaly detection triggers, whitelist/blacklist management.

| Function                 | Visibility    | Description                    |
| ------------------------ | ------------- | ------------------------------ |
| `checkAndRecordTransfer` | external      | Validate and record a transfer |
| `checkTransfer`          | external view | Dry-run transfer validation    |
| `recordTVLChange`        | external      | Update TVL tracking            |
| `triggerCircuitBreaker`  | external      | Manual circuit breaker trigger |
| `resetCircuitBreaker`    | external      | Reset circuit breaker          |
| `getRemainingLimits`     | external view | Remaining user/global limits   |
| `isCircuitBreakerActive` | external view | Circuit breaker status         |

### 24.4 RelayProofValidator

**Path:** `contracts/security/RelayProofValidator.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Proof validation pipeline with expiry timestamps (256-block default), 4-hour challenge periods, watchtower integration for multi-sig confirmations, and per-epoch withdrawal caps.

| Function                    | Visibility    | Description                     |
| --------------------------- | ------------- | ------------------------------- |
| `submitProof`               | external      | Submit proof for validation     |
| `finalizeProof`             | external      | Finalize after challenge period |
| `challengeProof`            | external      | Challenge a pending proof       |
| `resolveChallenge`          | external      | Resolve challenge outcome       |
| `confirmProof`              | external      | Watchtower confirmation         |
| `addWatchtower`             | external      | Register watchtower             |
| `isProofValid`              | external view | Check proof validity            |
| `getRemainingEpochCapacity` | external view | Remaining epoch withdrawal cap  |

### 24.5 RelayWatchtower

**Path:** `contracts/security/RelayWatchtower.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Decentralized watchtower network for bridge monitoring with bonded registration, distributed proof verification, anomaly reporting with 2/3 consensus voting, slashing for misbehavior, and inactivity penalties.

| Function       | Visibility       | Description                     |
| -------------- | ---------------- | ------------------------------- |
| `register`     | external payable | Register as watchtower (bonded) |
| `addStake`     | external payable | Add additional stake            |
| `requestExit`  | external         | Begin exit process              |
| `completeExit` | external         | Complete exit and withdraw bond |
| `submitReport` | external         | Submit anomaly report           |
| `voteOnReport` | external         | Vote on report validity         |
| `attestProof`  | external         | Attest to proof correctness     |
| `slash`        | external         | Slash misbehaving watchtower    |
| `hasConsensus` | external view    | Check 2/3 consensus status      |

### 24.6 RelayFraudProof

**Path:** `contracts/security/RelayFraudProof.sol`
**Inherits:** `AccessControl`

Verifies fraud proofs and resolves challenges on `OptimisticRelayVerifier`. Validates original proof matches the pending transfer, then verifies fraud evidence.

| Function           | Visibility | Description                   |
| ------------------ | ---------- | ----------------------------- |
| `submitFraudProof` | external   | Submit and verify fraud proof |

### 24.7 RelaySecurityScorecard

**Path:** `contracts/security/RelaySecurityScorecard.sol`
**Inherits:** `AccessControl`

Maintains 5-factor security scores (0–100) for bridge adapters: validator decentralization, economic security, audit quality, uptime, and incident history. Minimum safe score: 70.

| Function              | Visibility    | Description                         |
| --------------------- | ------------- | ----------------------------------- |
| `updateScore`         | external      | Update adapter security score       |
| `isBridgeSafe`        | external view | Check if bridge meets minimum score |
| `getScore`            | external view | Get composite security score        |
| `setMinimumSafeScore` | external      | Set minimum safe threshold          |

### 24.8 ExperimentalFeatureRegistry

**Path:** `contracts/security/ExperimentalFeatureRegistry.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Registry for experimental features (`IExperimentalFeatureRegistry`) with status tracking (DISABLED → EXPERIMENTAL → BETA → PRODUCTION), per-feature value-at-risk limits, graduation requirements, and emergency disable.

| Function                 | Visibility    | Description                       |
| ------------------------ | ------------- | --------------------------------- |
| `registerFeature`        | external      | Register new experimental feature |
| `updateFeatureStatus`    | external      | Update feature lifecycle status   |
| `emergencyDisable`       | external      | Emergency disable a feature       |
| `isFeatureEnabled`       | external view | Check if feature is enabled       |
| `requireFeatureEnabled`  | external view | Revert if feature not enabled     |
| `requireProductionReady` | external view | Revert if not production-ready    |
| `lockValue`              | external      | Lock value against feature limit  |
| `unlockValue`            | external      | Release locked value              |
| `getRemainingCapacity`   | external view | Remaining VAR capacity            |

### 24.9 ExperimentalGraduationManager

**Path:** `contracts/security/ExperimentalGraduationManager.sol`
**Inherits:** `AccessControl`

Formalizes the BETA → PRODUCTION graduation lifecycle. Enforces on-chain criteria (audit attestation, test coverage, minimum time-in-beta, security review) with timelock-gated execution.

| Function               | Visibility    | Description                      |
| ---------------------- | ------------- | -------------------------------- |
| `setCriteria`          | external      | Set graduation criteria          |
| `recordBetaEntry`      | external      | Record feature beta start        |
| `attestAudit`          | external      | Attest audit completion          |
| `attestTestCoverage`   | external      | Attest test coverage met         |
| `attestSecurityReview` | external      | Attest security review done      |
| `proposeGraduation`    | external      | Propose graduation to production |
| `executeGraduation`    | external      | Execute after timelock           |
| `demoteFeature`        | external      | Demote from production to beta   |
| `isGraduationReady`    | external view | Check all criteria met           |

### 24.10 EnhancedKillSwitch

**Path:** `contracts/security/EnhancedKillSwitch.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`

5-level emergency response system (`IEnhancedKillSwitch`): WARNING → ELEVATED → SEVERE → CRITICAL → LOCKED. Guardian-confirmed escalation with increasing cooldowns (0 → 7 days) and confirmation thresholds (1 → 5). Multi-guardian recovery with 48h–7d delays.

| Function            | Visibility    | Description                         |
| ------------------- | ------------- | ----------------------------------- |
| `escalateEmergency` | external      | Propose escalation                  |
| `confirmEscalation` | external      | Guardian confirms escalation        |
| `executeEscalation` | external      | Execute confirmed escalation        |
| `initiateRecovery`  | external      | Start recovery process              |
| `confirmRecovery`   | external      | Guardian confirms recovery          |
| `executeRecovery`   | external      | Execute recovery de-escalation      |
| `isActionAllowed`   | external view | Check if action is allowed at level |
| `getProtocolState`  | external view | Current emergency level             |

### 24.11 EmergencyRecovery

**Path:** `contracts/security/EmergencyRecovery.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Multi-stage emergency recovery with 5 graduated stages (Monitoring → Alert → Degraded → Emergency → Recovery). Multi-sig approval for stage escalation, automatic cooldowns, asset protection, and audit trail.

| Function                    | Visibility    | Description                      |
| --------------------------- | ------------- | -------------------------------- |
| `proposeStageChange`        | external      | Propose stage escalation         |
| `approveAction`             | external      | Multi-sig approval               |
| `registerProtectedContract` | external      | Register contract for protection |
| `pauseContract`             | external      | Pause a protected contract       |
| `pauseAll`                  | external      | Pause all protected contracts    |
| `freezeAssets`              | external      | Freeze assets                    |
| `releaseAssets`             | external      | Release frozen assets            |
| `emergencyWithdraw`         | external      | Emergency fund recovery          |
| `getRecoveryStatus`         | external view | Current recovery stage           |

### 24.12 MEVProtection

**Path:** `contracts/security/MEVProtection.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Commit-reveal scheme for sensitive operations: frontrunning prevention, sandwich attack mitigation, time-locked reveals, and commitment expiry management.

| Function                    | Visibility    | Description                     |
| --------------------------- | ------------- | ------------------------------- |
| `commit`                    | external      | Phase 1: submit commitment hash |
| `reveal`                    | external      | Phase 2: reveal with preimage   |
| `cancelCommitment`          | external      | Cancel unexpired commitment     |
| `calculateCommitHash`       | external pure | Compute expected commit hash    |
| `getCommitmentStatus`       | external view | Query commitment state          |
| `getPendingCommitments`     | external view | List pending commitments        |
| `cleanupExpiredCommitments` | external      | Prune expired entries           |

### 24.13 CrossChainMEVShield

**Path:** `contracts/security/CrossChainMEVShield.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Source-chain commit-reveal for cross-chain privacy operations (`ICrossChainMEVShield`). 2-phase flow: commit hash → wait `commitmentDelay` blocks → reveal. Per chain-pair configuration for different L2 block times.

| Function               | Visibility    | Description                       |
| ---------------------- | ------------- | --------------------------------- |
| `commit`               | external      | Commit cross-chain operation hash |
| `reveal`               | external      | Reveal after delay                |
| `expireCommitment`     | external      | Expire stale commitment           |
| `configureShield`      | external      | Set per-chain-pair delays         |
| `getCommitment`        | external view | Query commitment details          |
| `isReadyToReveal`      | external view | Check if reveal window open       |
| `getEffectivenessRate` | external view | MEV prevention rate metrics       |

### 24.14 CrossChainMessageVerifier

**Path:** `contracts/security/CrossChainMessageVerifier.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Multi-oracle N-of-M cross-chain message verification with time-bounded verification, replay protection, dynamic verifier rotation, and challenge periods before execution.

| Function              | Visibility    | Description                |
| --------------------- | ------------- | -------------------------- |
| `submitMessage`       | external      | Submit cross-chain message |
| `confirmMessage`      | external      | Oracle confirms message    |
| `executeMessage`      | external      | Execute after threshold    |
| `challengeMessage`    | external      | Challenge message validity |
| `resolveChallenge`    | external      | Resolve challenge outcome  |
| `hasReachedThreshold` | external view | Check N-of-M threshold     |
| `isExecutionReady`    | external view | Ready for execution        |
| `addVerifier`         | external      | Add oracle verifier        |

### 24.15 FlashLoanGuard

**Path:** `contracts/security/FlashLoanGuard.sol`
**Inherits:** `AccessControl`, `Pausable`

Multi-layer flash loan attack defense: block-level reentrancy prevention, balance snapshot validation, price oracle cross-reference, velocity checks, and TVL delta limits per block.

| Function                    | Visibility    | Description                                   |
| --------------------------- | ------------- | --------------------------------------------- |
| `validateOperation`         | external      | Validate operation against flash loan vectors |
| `canOperateThisBlock`       | external view | Check block-level operation limit             |
| `getRemainingOperations`    | external view | Remaining ops this block                      |
| `whitelistToken`            | external      | Whitelist token for monitoring                |
| `updateTVLDeltaLimit`       | external      | Set max TVL change per block                  |
| `registerProtectedContract` | external      | Register contract for guarding                |

### 24.16 GriefingProtection

**Path:** `contracts/security/GriefingProtection.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`

Anti-griefing and DoS protection with gas limits for external calls, refund caps, batch size restrictions, failure rate limiting, cost-recovery deposits, and user suspension system.

| Function              | Visibility       | Description                 |
| --------------------- | ---------------- | --------------------------- |
| `canPerformOperation` | external view    | Check if user can operate   |
| `validateOperation`   | external         | Pre-operation validation    |
| `recordFailure`       | external         | Record operation failure    |
| `recordSuccess`       | external         | Record operation success    |
| `deposit`             | external payable | Cost-recovery deposit       |
| `withdrawDeposit`     | external         | Withdraw deposit            |
| `requestRefund`       | external         | Request refund for failures |
| `suspendUser`         | external         | Suspend abusive user        |
| `unsuspendUser`       | external         | Unsuspend user              |

### 24.17 OptimisticNullifierChallenge

**Path:** `contracts/security/OptimisticNullifierChallenge.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Optimistic verification layer for cross-chain nullifier sync. Quarantines nullifiers in PENDING state during challenge period (default 1h) before forwarding to NullifierRegistryV3. Bond-based challenge/slashing (0.1 ETH min bond, 50/50 split).

| Function                  | Visibility       | Description                     |
| ------------------------- | ---------------- | ------------------------------- |
| `submitPendingNullifiers` | external         | Submit nullifier batch          |
| `challengeNullifier`      | external payable | Challenge with bond             |
| `upholdChallenge`         | external         | Uphold valid challenge          |
| `dismissChallenge`        | external         | Dismiss invalid challenge       |
| `finalizeNullifiers`      | external         | Finalize after challenge period |
| `getBatch`                | external view    | Query batch status              |

### 24.18 OptimisticRelayVerifier

**Path:** `contracts/security/OptimisticRelayVerifier.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Optimistic verification with challenge periods for high-value transfers. Bond-based dispute resolution with auto-finalization after timeout.

| Function            | Visibility       | Description                      |
| ------------------- | ---------------- | -------------------------------- |
| `submitTransfer`    | external         | Submit transfer for verification |
| `challengeTransfer` | external payable | Challenge with bond              |
| `resolveChallenge`  | external         | Resolve challenge                |
| `finalizeTransfer`  | external         | Finalize after timeout           |
| `canFinalize`       | external view    | Check finalization readiness     |

### 24.19 ProtocolHealthAggregator

**Path:** `contracts/security/ProtocolHealthAggregator.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

Unified protocol health monitoring aggregating circuit breaker, relayer health, routing health, and security scorecard signals into a weighted composite score (0–100). Auto-triggers graduated emergency responses (HEALTHY ≥70, WARNING 40–69, CRITICAL <40).

| Function                 | Visibility    | Description                   |
| ------------------------ | ------------- | ----------------------------- |
| `registerSubsystem`      | external      | Register health subsystem     |
| `updateHealth`           | external      | Update subsystem health score |
| `batchUpdateHealth`      | external      | Batch update health scores    |
| `registerPausableTarget` | external      | Register auto-pause target    |
| `guardianEmergencyPause` | external      | Guardian manual pause         |
| `guardianRecoverPause`   | external      | Guardian manual unpause       |
| `getProtocolHealth`      | external view | Get composite health score    |
| `getSubsystemHealth`     | external view | Get subsystem health          |
| `setAutoPauseEnabled`    | external      | Toggle auto-pause             |

### 24.20 ZKFraudProof

**Path:** `contracts/security/ZKFraudProof.sol`
**Inherits:** `AccessControl`, `ReentrancyGuard`, `Pausable`

ZK-based fraud proofs for optimistic rollup security. Supports 8 proof types (execution, inclusion, ordering, DA, censorship, double-spend, invalid signature, custom) with 3 dispute windows (standard 7d, expedited 1d with ZK proof, instant with full ZK verification).

| Function               | Visibility    | Description                   |
| ---------------------- | ------------- | ----------------------------- |
| `submitBatch`          | external      | Submit batch for verification |
| `finalizeBatch`        | external      | Finalize after dispute window |
| `submitFraudProof`     | external      | Submit fraud proof            |
| `verifyFraudProof`     | external      | Verify fraud proof validity   |
| `applyFraudProof`      | external      | Apply fraud proof penalty     |
| `addVerificationKey`   | external      | Register verification key     |
| `isInDisputePeriod`    | external view | Check dispute window          |
| `getPendingProofCount` | external view | Pending fraud proofs          |
| `emergencyWithdraw`    | external      | Emergency fund recovery       |
