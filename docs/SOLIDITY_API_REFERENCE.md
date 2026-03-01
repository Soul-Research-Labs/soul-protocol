# ZASEON — Solidity API Reference

> **Auto-generated from Solidity source** — covers all public/external functions, events, roles, and key state variables for the eight core contracts.

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
function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE)
```

Mark roles as properly separated. Prevents mainnet deployment with centralized control.

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
function setBridgeProofValidator(address) external
function setBridgeWatchtower(address) external
function setBridgeCircuitBreaker(address) external

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
