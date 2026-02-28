// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {PoseidonYul} from "../libraries/PoseidonYul.sol";
import {UniversalChainRegistry} from "../libraries/UniversalChainRegistry.sol";

/**
 * @title UniversalShieldedPoolUpgradeable
 * @author ZASEON
 * @notice UUPS-upgradeable multi-asset shielded pool with cross-chain ZK deposits/withdrawals
 * @dev Upgradeable version of UniversalShieldedPool using UUPS proxy pattern.
 *      - Replaces constructor with `initialize()`
 *      - Uses OZ upgradeable base contracts
 *      - Includes `__gap` for storage layout safety
 *      - `universalChainId` moved from immutable to storage (proxy-safe)
 *
 * @custom:security-contact security@zaseon.network
 * @custom:oz-upgrades-from UniversalShieldedPool
 */
contract UniversalShieldedPoolUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant COMPLIANCE_ROLE =
        0x364d3d7565c7a8982189c6ab03c2167d1f2cc9c82a4c902413ce8d68cfbe88c3;
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant TREE_DEPTH = 32;
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 public constant ZERO_VALUE =
        0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c;
    uint256 public constant MAX_DEPOSIT = 10_000 ether;
    uint256 public constant MIN_DEPOSIT = 0.001 ether;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    bytes32 public constant NATIVE_ASSET = keccak256("ETH");

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    struct DepositNote {
        bytes32 commitment;
        bytes32 assetId;
        uint256 leafIndex;
        uint256 timestamp;
        bytes32 sourceChainId;
    }

    struct WithdrawalProof {
        bytes proof;
        bytes32 merkleRoot;
        bytes32 nullifier;
        address recipient;
        address relayerAddress;
        uint256 amount;
        uint256 relayerFee;
        bytes32 assetId;
        bytes32 destChainId;
    }

    struct CrossChainCommitmentBatch {
        bytes32 sourceChainId;
        bytes32[] commitments;
        bytes32[] assetIds;
        bytes32 batchRoot;
        bytes proof;
        uint256 sourceTreeSize;
    }

    struct AssetConfig {
        address tokenAddress;
        bytes32 assetId;
        uint256 totalDeposited;
        uint256 totalWithdrawn;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    // ─── Merkle Tree ────────────────────────────────────────────
    bytes32 public currentRoot;
    uint256 public nextLeafIndex;
    bytes32[TREE_DEPTH] public filledSubtrees;
    bytes32[ROOT_HISTORY_SIZE] public rootHistory;
    uint256 public currentRootIndex;

    // ─── Nullifiers ─────────────────────────────────────────────
    mapping(bytes32 => bool) public nullifiers;

    // ─── Assets ─────────────────────────────────────────────────
    mapping(bytes32 => AssetConfig) public assets;
    mapping(address => bytes32) public tokenToAssetId;
    bytes32[] public assetIds;

    // ─── Deposits ───────────────────────────────────────────────
    mapping(uint256 => bytes32) public commitments;
    mapping(bytes32 => bool) public commitmentExists;

    // ─── Verifier ───────────────────────────────────────────────
    address public withdrawalVerifier;
    bool public testMode;
    address public batchVerifier;

    // ─── Cross-Chain (non-immutable for proxy) ──────────────────
    bytes32 public universalChainId;
    mapping(bytes32 => bool) public processedBatches;

    // ─── Compliance ─────────────────────────────────────────────
    address public sanctionsOracle;

    // ─── Stats ──────────────────────────────────────────────────
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalCrossChainDeposits;

    // ─── Security Modules ───────────────────────────────────────
    /// @notice Rate limiter: max deposits per window
    uint256 public depositRateLimitWindow;
    uint256 public maxDepositsPerWindow;
    uint256 public currentWindowStart;
    uint256 public currentWindowDeposits;

    /// @notice Circuit breaker: pause on anomalous withdrawals
    uint256 public circuitBreakerThreshold;
    uint256 public withdrawalWindow;
    uint256 public withdrawalWindowStart;
    uint256 public withdrawalWindowCount;

    // ─── Upgrade Tracking ───────────────────────────────────────
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage for future upgrades  (50 slots)
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event Deposit(
        bytes32 indexed commitment,
        bytes32 indexed assetId,
        uint256 leafIndex,
        uint256 amount,
        uint256 timestamp
    );

    event Withdrawal(
        bytes32 indexed nullifier,
        bytes32 indexed assetId,
        address indexed recipient,
        uint256 amount,
        uint256 relayerFee
    );

    event CrossChainCommitmentsInserted(
        bytes32 indexed sourceChainId,
        uint256 count,
        bytes32 newRoot
    );

    event AssetRegistered(
        bytes32 indexed assetId,
        address indexed tokenAddress
    );
    event VerifierUpdated(address indexed newVerifier, string verifierType);
    event SanctionsOracleUpdated(address indexed newOracle);

    /// @notice Emitted when test mode is permanently disabled
    event TestModeDisabled(address indexed disabledBy);

    /// @notice Emitted when production readiness is confirmed on-chain
    event ProductionReadinessConfirmed(
        address indexed confirmedBy,
        address verifier
    );
    event CircuitBreakerTriggered(uint256 withdrawalCount, uint256 threshold);
    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidCommitment();
    error NullifierAlreadySpent(bytes32 nullifier);
    error InvalidMerkleRoot(bytes32 root);
    error WithdrawalProofFailed();
    error InvalidAmount();
    error AssetNotRegistered(bytes32 assetId);
    error AssetNotActive(bytes32 assetId);
    error AssetAlreadyRegistered(bytes32 assetId);
    error MerkleTreeFull();
    error InvalidRecipient();
    error InsufficientRelayerFee();
    error BatchAlreadyProcessed(bytes32 batchRoot);
    error BatchProofFailed();
    error SanctionedAddress(address addr);
    error ZeroAddress();
    error DepositTooLarge();
    error DepositTooSmall();
    error DepositRateLimitExceeded();
    error CircuitBreakerActive();

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the upgradeable shielded pool
    /// @param _admin Admin / default-admin address
    /// @param _withdrawalVerifier Address of the ZK withdrawal verifier
    /// @param _testMode Whether test-mode proof bypass is enabled
        /**
     * @notice Initializes the operation
     * @param _admin The _admin bound
     * @param _withdrawalVerifier The _withdrawal verifier
     * @param _testMode The _test mode
     */
function initialize(
        address _admin,
        address _withdrawalVerifier,
        bool _testMode
    ) external initializer {
        if (_admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
        testMode = _testMode;

        universalChainId = UniversalChainRegistry.computeEVMChainId(
            block.chainid
        );

        // Initialize Merkle tree with zero values
        bytes32 currentZero = ZERO_VALUE;
        for (uint256 i = 0; i < TREE_DEPTH; ) {
            filledSubtrees[i] = currentZero;
            currentZero = _hashPair(currentZero, currentZero);
            unchecked {
                ++i;
            }
        }
        currentRoot = currentZero;
        rootHistory[0] = currentRoot;

        // Register native ETH
        assets[NATIVE_ASSET] = AssetConfig({
            tokenAddress: address(0),
            assetId: NATIVE_ASSET,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });
        assetIds.push(NATIVE_ASSET);
        emit AssetRegistered(NATIVE_ASSET, address(0));

        if (_withdrawalVerifier != address(0)) {
            withdrawalVerifier = _withdrawalVerifier;
            emit VerifierUpdated(_withdrawalVerifier, "withdrawal");
        }

        // Security defaults
        depositRateLimitWindow = 1 hours;
        maxDepositsPerWindow = 100;
        circuitBreakerThreshold = 50;
        withdrawalWindow = 1 hours;

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                             DEPOSIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit native ETH into the shielded pool
        /**
     * @notice Deposits e t h
     * @param commitment The cryptographic commitment
     */
function depositETH(
        bytes32 commitment
    ) external payable nonReentrant whenNotPaused {
        if (commitment == bytes32(0) || uint256(commitment) >= FIELD_SIZE)
            revert InvalidCommitment();
        if (msg.value < MIN_DEPOSIT) revert DepositTooSmall();
        if (msg.value > MAX_DEPOSIT) revert DepositTooLarge();
        _checkSanctions(msg.sender);
        _enforceDepositRateLimit();

        _insertCommitment(commitment, NATIVE_ASSET, msg.value);
    }

    /// @notice Deposit ERC20 tokens into the shielded pool
        /**
     * @notice Deposits e r c20
     * @param assetId The assetId identifier
     * @param amount The amount to process
     * @param commitment The cryptographic commitment
     */
function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external nonReentrant whenNotPaused {
        if (commitment == bytes32(0) || uint256(commitment) >= FIELD_SIZE)
            revert InvalidCommitment();
        if (amount < MIN_DEPOSIT) revert DepositTooSmall();
        if (amount > MAX_DEPOSIT) revert DepositTooLarge();

        AssetConfig storage asset = assets[assetId];
        if (!asset.active) revert AssetNotActive(assetId);
        if (asset.tokenAddress == address(0))
            revert AssetNotRegistered(assetId);

        _checkSanctions(msg.sender);
        _enforceDepositRateLimit();

        IERC20(asset.tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );
        _insertCommitment(commitment, assetId, amount);
    }

    /*//////////////////////////////////////////////////////////////
                            WITHDRAW
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw from the shielded pool using a ZK proof
        /**
     * @notice Withdraws the operation
     * @param wp The wp
     */
function withdraw(
        WithdrawalProof calldata wp
    ) external nonReentrant whenNotPaused {
        if (wp.recipient == address(0)) revert InvalidRecipient();
        if (wp.amount == 0) revert InvalidAmount();
        if (nullifiers[wp.nullifier])
            revert NullifierAlreadySpent(wp.nullifier);
        if (!_isKnownRoot(wp.merkleRoot))
            revert InvalidMerkleRoot(wp.merkleRoot);

        AssetConfig storage asset = assets[wp.assetId];
        if (asset.assetId == bytes32(0)) revert AssetNotRegistered(wp.assetId);

        _checkSanctions(wp.recipient);
        if (wp.relayerAddress != address(0)) {
            _checkSanctions(wp.relayerAddress);
        }

        _enforceCircuitBreaker();

        bool valid = _verifyWithdrawalProof(wp);
        if (!valid) revert WithdrawalProofFailed();

        nullifiers[wp.nullifier] = true;

        uint256 netAmount = wp.amount - wp.relayerFee;
        asset.totalWithdrawn += wp.amount;
        unchecked {
            ++totalWithdrawals;
        }

        if (asset.tokenAddress == address(0)) {
            _safeTransferETH(wp.recipient, netAmount);
            if (wp.relayerFee > 0 && wp.relayerAddress != address(0)) {
                _safeTransferETH(wp.relayerAddress, wp.relayerFee);
            }
        } else {
            IERC20(asset.tokenAddress).safeTransfer(wp.recipient, netAmount);
            if (wp.relayerFee > 0 && wp.relayerAddress != address(0)) {
                IERC20(asset.tokenAddress).safeTransfer(
                    wp.relayerAddress,
                    wp.relayerFee
                );
            }
        }

        emit Withdrawal(
            wp.nullifier,
            wp.assetId,
            wp.recipient,
            wp.amount,
            wp.relayerFee
        );
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN COMMITMENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Insert commitments from a remote chain (bridged by relayer)
        /**
     * @notice Insert cross chain commitments
     * @param batch The batch
     */
function insertCrossChainCommitments(
        CrossChainCommitmentBatch calldata batch
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (processedBatches[batch.batchRoot])
            revert BatchAlreadyProcessed(batch.batchRoot);

        if (batchVerifier != address(0)) {
            bool validBatch = _verifyBatchProof(batch);
            if (!validBatch) revert BatchProofFailed();
        }

        uint256 count = batch.commitments.length;
        for (uint256 i = 0; i < count; ) {
            bytes32 commitment = batch.commitments[i];
            if (
                commitment != bytes32(0) &&
                uint256(commitment) < FIELD_SIZE &&
                !commitmentExists[commitment]
            ) {
                uint256 leafIndex = nextLeafIndex;
                _insertLeaf(commitment);
                commitments[leafIndex] = commitment;
                commitmentExists[commitment] = true;
            }
            unchecked {
                ++i;
            }
        }

        processedBatches[batch.batchRoot] = true;
        unchecked {
            totalCrossChainDeposits += count;
        }

        emit CrossChainCommitmentsInserted(
            batch.sourceChainId,
            count,
            currentRoot
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

        /**
     * @notice Registers asset
     * @param assetId The assetId identifier
     * @param tokenAddress The tokenAddress address
     */
function registerAsset(
        bytes32 assetId,
        address tokenAddress
    ) external onlyRole(OPERATOR_ROLE) {
        if (tokenAddress == address(0)) revert ZeroAddress();
        if (assets[assetId].active) revert AssetAlreadyRegistered(assetId);

        assets[assetId] = AssetConfig({
            tokenAddress: tokenAddress,
            assetId: assetId,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });
        tokenToAssetId[tokenAddress] = assetId;
        assetIds.push(assetId);
        emit AssetRegistered(assetId, tokenAddress);
    }

        /**
     * @notice Sets the withdrawal verifier
     * @param _verifier The _verifier
     */
function setWithdrawalVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        withdrawalVerifier = _verifier;
        emit VerifierUpdated(_verifier, "withdrawal");
    }

        /**
     * @notice Disables test mode
     */
function disableTestMode() external onlyRole(DEFAULT_ADMIN_ROLE) {
        testMode = false;
        emit TestModeDisabled(msg.sender);
    }

    /// @notice Assert production readiness on-chain (reverts if not ready)
    /// @dev Call after deployment to confirm verifier is set and testMode is off.
    ///      Emits ProductionReadinessConfirmed for off-chain monitoring.
        /**
     * @notice Confirm production ready
     */
function confirmProductionReady() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!testMode, "Test mode still enabled");
        require(withdrawalVerifier != address(0), "No withdrawal verifier set");
        emit ProductionReadinessConfirmed(msg.sender, withdrawalVerifier);
    }

        /**
     * @notice Sets the batch verifier
     * @param _verifier The _verifier
     */
function setBatchVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        batchVerifier = _verifier;
        emit VerifierUpdated(_verifier, "batch");
    }

        /**
     * @notice Sets the sanctions oracle
     * @param _oracle The _oracle
     */
function setSanctionsOracle(
        address _oracle
    ) external onlyRole(COMPLIANCE_ROLE) {
        sanctionsOracle = _oracle;
        emit SanctionsOracleUpdated(_oracle);
    }

        /**
     * @notice Deactivate asset
     * @param assetId The assetId identifier
     */
function deactivateAsset(bytes32 assetId) external onlyRole(OPERATOR_ROLE) {
        assets[assetId].active = false;
    }

    /// @notice Configure deposit rate limiting
        /**
     * @notice Sets the deposit rate limit
     * @param _window The _window
     * @param _maxDeposits The _maxDeposits bound
     */
function setDepositRateLimit(
        uint256 _window,
        uint256 _maxDeposits
    ) external onlyRole(OPERATOR_ROLE) {
        depositRateLimitWindow = _window;
        maxDepositsPerWindow = _maxDeposits;
    }

    /// @notice Configure circuit breaker threshold
        /**
     * @notice Sets the circuit breaker
     * @param _threshold The _threshold
     * @param _window The _window
     */
function setCircuitBreaker(
        uint256 _threshold,
        uint256 _window
    ) external onlyRole(OPERATOR_ROLE) {
        circuitBreakerThreshold = _threshold;
        withdrawalWindow = _window;
    }

        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

        /**
     * @notice Unpauses the operation
 */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

        /**
     * @notice Returns the last root
     * @return The result value
     */
function getLastRoot() external view returns (bytes32) {
        return currentRoot;
    }

        /**
     * @notice Checks if known root
     * @param root The Merkle root
     * @return The result value
     */
function isKnownRoot(bytes32 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

        /**
     * @notice Checks if spent
     * @param nullifier The nullifier hash
     * @return The result value
     */
function isSpent(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

        /**
     * @notice Returns the pool stats
     * @return deposits The deposits
     * @return withdrawalsCount The withdrawals count
     * @return crossChainDeposits The cross chain deposits
     * @return treeSize The tree size
     * @return root The root
     */
function getPoolStats()
        external
        view
        returns (
            uint256 deposits,
            uint256 withdrawalsCount,
            uint256 crossChainDeposits,
            uint256 treeSize,
            bytes32 root
        )
    {
        return (
            totalDeposits,
            totalWithdrawals,
            totalCrossChainDeposits,
            nextLeafIndex,
            currentRoot
        );
    }

        /**
     * @notice Returns the registered assets
     * @return The result value
     */
function getRegisteredAssets() external view returns (bytes32[] memory) {
        return assetIds;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _insertCommitment(
        bytes32 commitment,
        bytes32 assetId,
        uint256 amount
    ) internal {
        if (commitmentExists[commitment]) revert InvalidCommitment();

        uint256 leafIndex = nextLeafIndex;
        _insertLeaf(commitment);

        commitments[leafIndex] = commitment;
        commitmentExists[commitment] = true;
        assets[assetId].totalDeposited += amount;
        unchecked {
            ++totalDeposits;
        }

        emit Deposit(commitment, assetId, leafIndex, amount, block.timestamp);
    }

    function _insertLeaf(bytes32 leaf) internal {
        uint256 index = nextLeafIndex;
        if (index >= 2 ** TREE_DEPTH) revert MerkleTreeFull();

        bytes32 currentHash = leaf;
        for (uint256 i = 0; i < TREE_DEPTH; ) {
            if (index & 1 == 0) {
                filledSubtrees[i] = currentHash;
                currentHash = _hashPair(currentHash, _zeros(i));
            } else {
                currentHash = _hashPair(filledSubtrees[i], currentHash);
            }
            index >>= 1;
            unchecked {
                ++i;
            }
        }

        uint256 newRootIndex;
        unchecked {
            newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        }
        currentRootIndex = newRootIndex;
        rootHistory[newRootIndex] = currentHash;
        currentRoot = currentHash;
        unchecked {
            ++nextLeafIndex;
        }
    }

    function _isKnownRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ) {
            if (rootHistory[i] == root) return true;
            unchecked {
                ++i;
            }
        }
        return false;
    }

    function _zeros(uint256 level) internal pure returns (bytes32) {
        if (level == 0) return ZERO_VALUE;
        bytes32 z = ZERO_VALUE;
        for (uint256 i = 0; i < level; ) {
            z = _hashPair(z, z);
            unchecked {
                ++i;
            }
        }
        return z;
    }

    function _hashPair(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return bytes32(PoseidonYul.hash2(uint256(left), uint256(right)));
    }

    function _verifyWithdrawalProof(
        WithdrawalProof calldata wp
    ) internal view returns (bool) {
        if (withdrawalVerifier == address(0)) {
            // No verifier set — only allow in explicit test mode (irreversibly disableable)
            require(testMode, "No verifier configured");
            /// @custom:security TEST-ONLY bypass — testMode must be disabled before production.
            /// disableTestMode() is irreversible and enforced by deployment scripts.
            return true;
        }

        // Encode public inputs as uint256[] for IProofVerifier compatibility
        uint256[] memory inputs = new uint256[](7);
        inputs[0] = uint256(wp.merkleRoot);
        inputs[1] = uint256(wp.nullifier);
        inputs[2] = uint256(uint160(wp.recipient));
        inputs[3] = wp.amount;
        inputs[4] = uint256(wp.assetId);
        inputs[5] = uint256(uint160(wp.relayerAddress));
        inputs[6] = wp.relayerFee;

        bytes memory publicInputs = abi.encode(inputs);

        // Call IProofVerifier.verifyProof(bytes,bytes) — matches UltraHonkAdapter
        (bool success, bytes memory result) = withdrawalVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes,bytes)",
                wp.proof,
                publicInputs
            )
        );
        return success && result.length >= 32 && abi.decode(result, (bool));
    }

        /**
     * @notice _verify batch proof
     * @param batch The batch
     * @return The result value
     */
function _verifyBatchProof(
        CrossChainCommitmentBatch calldata batch
    ) internal view returns (bool) {
        bytes memory publicInputs = abi.encode(
            batch.sourceChainId,
            batch.batchRoot,
            batch.sourceTreeSize,
            keccak256(abi.encodePacked(batch.commitments))
        );

        (bool success, bytes memory result) = batchVerifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes)",
                batch.proof,
                publicInputs
            )
        );
        return success && result.length >= 32 && abi.decode(result, (bool));
    }

    function _checkSanctions(address addr) internal view {
        if (sanctionsOracle != address(0)) {
            (bool success, bytes memory result) = sanctionsOracle.staticcall(
                abi.encodeWithSignature("isSanctioned(address)", addr)
            );
            if (success && result.length >= 32 && abi.decode(result, (bool))) {
                revert SanctionedAddress(addr);
            }
        }
    }

    /// @notice Enforce deposit rate limiting
    function _enforceDepositRateLimit() internal {
        if (maxDepositsPerWindow == 0) return; // disabled

        if (block.timestamp >= currentWindowStart + depositRateLimitWindow) {
            currentWindowStart = block.timestamp;
            currentWindowDeposits = 1;
        } else {
            currentWindowDeposits++;
            if (currentWindowDeposits > maxDepositsPerWindow) {
                revert DepositRateLimitExceeded();
            }
        }
    }

    /// @notice Enforce circuit breaker on withdrawals
    function _enforceCircuitBreaker() internal {
        if (circuitBreakerThreshold == 0) return; // disabled

        if (block.timestamp >= withdrawalWindowStart + withdrawalWindow) {
            withdrawalWindowStart = block.timestamp;
            withdrawalWindowCount = 1;
        } else {
            withdrawalWindowCount++;
            if (withdrawalWindowCount > circuitBreakerThreshold) {
                _pause();
                emit CircuitBreakerTriggered(
                    withdrawalWindowCount,
                    circuitBreakerThreshold
                );
                revert CircuitBreakerActive();
            }
        }
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    /// @notice Authorize UUPS upgrade — restricted to UPGRADER_ROLE
    function _authorizeUpgrade(
        address /* _newImplementation */
    ) internal override onlyRole(UPGRADER_ROLE) {
        uint256 oldVersion = contractVersion;
        contractVersion = oldVersion + 1;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    receive() external payable {}
}
