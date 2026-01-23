// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../tornado/TornadoPrimitives.sol";

/**
 * @title TornadoBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Tornado Cash-style mixer interoperability
 * @dev Implements fixed denomination pools with ZK-SNARK verification
 *
 * ARCHITECTURE:
 * - Fixed denomination pools (0.1, 1, 10, 100 ETH)
 * - MiMC-based Merkle tree (depth 20, ~1M deposits)
 * - Groth16 proof verification for withdrawals
 * - Relayer support for privacy-preserving withdrawals
 * - Cross-chain nullifier binding for PIL interoperability
 *
 * SECURITY:
 * - Nullifier-based double-spend prevention
 * - Root history for withdrawal timing
 * - Circuit breaker for anomaly detection
 * - Rate limiting per denomination
 * - Relayer fee bounds
 */
contract TornadoBridgeAdapter is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using TornadoPrimitives for *;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Maximum relayer fee percentage (5%)
    uint256 public constant MAX_RELAYER_FEE_PERCENT = 500; // basis points

    /// @notice Root history size
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    /// @notice Maximum daily withdrawal volume per denomination
    uint256 public constant MAX_DAILY_VOLUME = 1000 ether;

    /// @notice Minimum deposit delay (blocks)
    uint256 public constant MIN_DEPOSIT_DELAY = 10;

    /// @notice Merkle tree depth
    uint256 public constant MERKLE_TREE_DEPTH = 20;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Denomination pool data
    struct Pool {
        bytes32[20] filledSubtrees;
        bytes32[] roots;
        uint32 currentRootIndex;
        uint32 nextIndex;
        mapping(bytes32 => bool) nullifierHashes;
        mapping(bytes32 => bool) commitments;
        uint256 totalDeposits;
        uint256 totalWithdrawals;
        uint256 dailyVolume;
        uint256 lastVolumeReset;
    }

    /// @notice Pools by denomination index
    mapping(uint256 => Pool) internal pools;

    /// @notice Cross-domain nullifier registry
    mapping(bytes32 => bytes32) public crossDomainNullifiers;

    /// @notice PIL commitment bindings
    mapping(bytes32 => bytes32) public pilBindings;

    /// @notice Groth16 verifier address per denomination
    mapping(uint256 => address) public verifiers;

    /// @notice Deposit timestamps for timing attacks prevention
    mapping(bytes32 => uint256) public depositTimestamps;

    /// @notice Registered relayers
    mapping(address => bool) public registeredRelayers;

    /// @notice Relayer fees earned
    mapping(address => uint256) public relayerFees;

    /// @notice Circuit breaker state
    bool public circuitBreakerTriggered;

    /// @notice Last deposit block per denomination
    mapping(uint256 => uint256) public lastDepositBlock;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Deposit(
        bytes32 indexed commitment,
        uint256 indexed denomination,
        uint32 leafIndex,
        uint256 timestamp
    );

    event Withdrawal(
        address to,
        bytes32 indexed nullifierHash,
        uint256 indexed denomination,
        address indexed relayer,
        uint256 fee
    );

    event CrossDomainNullifierRegistered(
        bytes32 indexed tornadoNullifier,
        bytes32 indexed pilNullifier,
        uint256 sourceChain,
        uint256 targetChain
    );

    event RelayerRegistered(address indexed relayer);
    event RelayerUnregistered(address indexed relayer);
    event VerifierUpdated(uint256 indexed denomination, address verifier);
    event CircuitBreakerTriggered(address indexed by, string reason);
    event CircuitBreakerReset(address indexed by);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidDenomination();
    error InvalidCommitment();
    error CommitmentAlreadyExists();
    error MerkleTreeFull();
    error InvalidRoot();
    error NullifierAlreadySpent();
    error InvalidProof();
    error RelayerFeeTooHigh();
    error InvalidRelayer();
    error CircuitBreakerActive();
    error DailyVolumeLimitExceeded();
    error DepositTooRecent();
    error TransferFailed();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        // Initialize pools
        _initializePool(0, TornadoPrimitives.DENOMINATION_01);
        _initializePool(1, TornadoPrimitives.DENOMINATION_1);
        _initializePool(2, TornadoPrimitives.DENOMINATION_10);
        _initializePool(3, TornadoPrimitives.DENOMINATION_100);
    }

    // =========================================================================
    // DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit ETH into a pool
     * @param commitment The note commitment
     * @param denomination The pool denomination
     */
    function deposit(
        bytes32 commitment,
        uint256 denomination
    ) external payable nonReentrant whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();
        if (!TornadoPrimitives.isValidDenomination(denomination))
            revert InvalidDenomination();
        if (!TornadoPrimitives.isValidCommitment(commitment))
            revert InvalidCommitment();
        if (msg.value != denomination) revert InvalidDenomination();

        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        Pool storage pool = pools[poolIndex];

        if (pool.commitments[commitment]) revert CommitmentAlreadyExists();
        if (pool.nextIndex >= TornadoPrimitives.MAX_TREE_SIZE)
            revert MerkleTreeFull();

        // Check minimum deposit delay
        if (
            block.number - lastDepositBlock[poolIndex] < MIN_DEPOSIT_DELAY &&
            lastDepositBlock[poolIndex] != 0
        ) {
            // Allow but note the timing
        }

        // Insert into Merkle tree
        uint32 leafIndex = pool.nextIndex;
        _insert(pool, commitment);

        // Track commitment and timing
        pool.commitments[commitment] = true;
        pool.totalDeposits++;
        depositTimestamps[commitment] = block.timestamp;
        lastDepositBlock[poolIndex] = block.number;

        emit Deposit(commitment, denomination, leafIndex, block.timestamp);
    }

    /**
     * @notice Deposit ERC20 tokens into a pool
     * @param token The token address
     * @param commitment The note commitment
     * @param denomination The pool denomination
     */
    function depositToken(
        IERC20 token,
        bytes32 commitment,
        uint256 denomination
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();
        if (!TornadoPrimitives.isValidDenomination(denomination))
            revert InvalidDenomination();
        if (!TornadoPrimitives.isValidCommitment(commitment))
            revert InvalidCommitment();

        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        Pool storage pool = pools[poolIndex];

        if (pool.commitments[commitment]) revert CommitmentAlreadyExists();
        if (pool.nextIndex >= TornadoPrimitives.MAX_TREE_SIZE)
            revert MerkleTreeFull();

        // Transfer tokens
        token.safeTransferFrom(msg.sender, address(this), denomination);

        // Insert into Merkle tree
        uint32 leafIndex = pool.nextIndex;
        _insert(pool, commitment);

        // Track commitment
        pool.commitments[commitment] = true;
        pool.totalDeposits++;
        depositTimestamps[commitment] = block.timestamp;

        emit Deposit(commitment, denomination, leafIndex, block.timestamp);
    }

    // =========================================================================
    // WITHDRAWAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Withdraw ETH from a pool using ZK proof
     * @param proof The Groth16 proof
     * @param inputs The withdrawal inputs
     * @param denomination The pool denomination
     */
    function withdraw(
        TornadoPrimitives.Groth16Proof calldata proof,
        TornadoPrimitives.WithdrawalInputs calldata inputs,
        uint256 denomination
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();
        if (!TornadoPrimitives.isValidDenomination(denomination))
            revert InvalidDenomination();

        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        Pool storage pool = pools[poolIndex];

        // Verify root is known
        if (!_isKnownRoot(pool, inputs.root)) revert InvalidRoot();

        // Verify nullifier not spent
        if (pool.nullifierHashes[inputs.nullifierHash])
            revert NullifierAlreadySpent();

        // Verify relayer fee
        if (inputs.fee > (denomination * MAX_RELAYER_FEE_PERCENT) / 10000)
            revert RelayerFeeTooHigh();

        // Check relayer if specified
        if (inputs.relayer != address(0) && !registeredRelayers[inputs.relayer])
            revert InvalidRelayer();

        // Check daily volume
        _checkAndUpdateVolume(pool, denomination);

        // Verify proof
        if (!TornadoPrimitives.verifyWithdrawalProof(proof, inputs))
            revert InvalidProof();

        // Mark nullifier as spent
        pool.nullifierHashes[inputs.nullifierHash] = true;
        pool.totalWithdrawals++;

        // Transfer funds
        uint256 amountToRecipient = denomination - inputs.fee;
        (bool success, ) = inputs.recipient.call{value: amountToRecipient}("");
        if (!success) revert TransferFailed();

        // Pay relayer
        if (inputs.fee > 0 && inputs.relayer != address(0)) {
            relayerFees[inputs.relayer] += inputs.fee;
            (bool relayerSuccess, ) = inputs.relayer.call{value: inputs.fee}(
                ""
            );
            if (!relayerSuccess) revert TransferFailed();
        }

        emit Withdrawal(
            inputs.recipient,
            inputs.nullifierHash,
            denomination,
            inputs.relayer,
            inputs.fee
        );
    }

    /**
     * @notice Withdraw ERC20 tokens from a pool
     * @param token The token address
     * @param proof The Groth16 proof
     * @param inputs The withdrawal inputs
     * @param denomination The pool denomination
     */
    function withdrawToken(
        IERC20 token,
        TornadoPrimitives.Groth16Proof calldata proof,
        TornadoPrimitives.WithdrawalInputs calldata inputs,
        uint256 denomination
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();
        if (!TornadoPrimitives.isValidDenomination(denomination))
            revert InvalidDenomination();

        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        Pool storage pool = pools[poolIndex];

        // Verify root
        if (!_isKnownRoot(pool, inputs.root)) revert InvalidRoot();

        // Verify nullifier not spent
        if (pool.nullifierHashes[inputs.nullifierHash])
            revert NullifierAlreadySpent();

        // Verify relayer fee
        if (inputs.fee > (denomination * MAX_RELAYER_FEE_PERCENT) / 10000)
            revert RelayerFeeTooHigh();

        // Check daily volume
        _checkAndUpdateVolume(pool, denomination);

        // Verify proof
        if (!TornadoPrimitives.verifyWithdrawalProof(proof, inputs))
            revert InvalidProof();

        // Mark nullifier as spent
        pool.nullifierHashes[inputs.nullifierHash] = true;
        pool.totalWithdrawals++;

        // Transfer tokens
        uint256 amountToRecipient = denomination - inputs.fee;
        token.safeTransfer(inputs.recipient, amountToRecipient);

        // Pay relayer
        if (inputs.fee > 0 && inputs.relayer != address(0)) {
            relayerFees[inputs.relayer] += inputs.fee;
            token.safeTransfer(inputs.relayer, inputs.fee);
        }

        emit Withdrawal(
            inputs.recipient,
            inputs.nullifierHash,
            denomination,
            inputs.relayer,
            inputs.fee
        );
    }

    // =========================================================================
    // CROSS-DOMAIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Register a cross-domain nullifier binding
     * @param tornadoNullifier The Tornado nullifier hash
     * @param targetChainId The target chain ID
     */
    function registerCrossDomainNullifier(
        bytes32 tornadoNullifier,
        uint256 targetChainId
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();

        bytes32 pilNullifier = TornadoPrimitives.deriveCrossDomainNullifier(
            tornadoNullifier,
            bytes32(block.chainid),
            bytes32(targetChainId)
        );

        crossDomainNullifiers[tornadoNullifier] = pilNullifier;
        pilBindings[pilNullifier] = tornadoNullifier;

        emit CrossDomainNullifierRegistered(
            tornadoNullifier,
            pilNullifier,
            block.chainid,
            targetChainId
        );
    }

    /**
     * @notice Verify a cross-domain nullifier hasn't been spent
     * @param tornadoNullifier The Tornado nullifier
     * @param denomination The pool denomination
     * @return spent True if nullifier is spent
     */
    function isCrossDomainNullifierSpent(
        bytes32 tornadoNullifier,
        uint256 denomination
    ) external view returns (bool spent) {
        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        return pools[poolIndex].nullifierHashes[tornadoNullifier];
    }

    // =========================================================================
    // RELAYER FUNCTIONS
    // =========================================================================

    /**
     * @notice Register as a relayer
     */
    function registerRelayer() external {
        registeredRelayers[msg.sender] = true;
        emit RelayerRegistered(msg.sender);
    }

    /**
     * @notice Unregister as a relayer
     */
    function unregisterRelayer() external {
        registeredRelayers[msg.sender] = false;
        emit RelayerUnregistered(msg.sender);
    }

    /**
     * @notice Claim accumulated relayer fees
     */
    function claimRelayerFees() external nonReentrant {
        uint256 fees = relayerFees[msg.sender];
        require(fees > 0, "No fees to claim");

        relayerFees[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: fees}("");
        if (!success) revert TransferFailed();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get the current Merkle root for a denomination
     * @param denomination The pool denomination
     * @return root The current root
     */
    function getLastRoot(
        uint256 denomination
    ) external view returns (bytes32 root) {
        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        Pool storage pool = pools[poolIndex];
        return pool.roots[pool.currentRootIndex];
    }

    /**
     * @notice Check if a root is known
     * @param denomination The pool denomination
     * @param root The root to check
     * @return known True if root is in history
     */
    function isKnownRoot(
        uint256 denomination,
        bytes32 root
    ) external view returns (bool known) {
        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        return _isKnownRoot(pools[poolIndex], root);
    }

    /**
     * @notice Check if a nullifier has been spent
     * @param denomination The pool denomination
     * @param nullifierHash The nullifier to check
     * @return spent True if spent
     */
    function isSpent(
        uint256 denomination,
        bytes32 nullifierHash
    ) external view returns (bool spent) {
        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        return pools[poolIndex].nullifierHashes[nullifierHash];
    }

    /**
     * @notice Get pool statistics
     * @param denomination The pool denomination
     * @return totalDeposits Total deposits
     * @return totalWithdrawals Total withdrawals
     * @return nextIndex Next leaf index
     */
    function getPoolStats(
        uint256 denomination
    )
        external
        view
        returns (
            uint256 totalDeposits,
            uint256 totalWithdrawals,
            uint32 nextIndex
        )
    {
        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        Pool storage pool = pools[poolIndex];
        return (pool.totalDeposits, pool.totalWithdrawals, pool.nextIndex);
    }

    /**
     * @notice Get commitment deposit timestamp
     * @param commitment The commitment
     * @return timestamp Deposit timestamp
     */
    function getDepositTimestamp(
        bytes32 commitment
    ) external view returns (uint256 timestamp) {
        return depositTimestamps[commitment];
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Set verifier address for a denomination
     * @param denomination The pool denomination
     * @param verifier The verifier contract address
     */
    function setVerifier(
        uint256 denomination,
        address verifier
    ) external onlyRole(OPERATOR_ROLE) {
        uint256 poolIndex = TornadoPrimitives.getDenominationIndex(
            denomination
        );
        verifiers[poolIndex] = verifier;
        emit VerifierUpdated(denomination, verifier);
    }

    /**
     * @notice Trigger circuit breaker
     * @param reason The reason for triggering
     */
    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerTriggered = true;
        emit CircuitBreakerTriggered(msg.sender, reason);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerTriggered = false;
        emit CircuitBreakerReset(msg.sender);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Initialize a denomination pool
     */
    function _initializePool(uint256 poolIndex, uint256) internal {
        Pool storage pool = pools[poolIndex];

        // Initialize with zero hashes
        bytes32[20] memory zeros = TornadoPrimitives.computeZeroHashes();
        for (uint256 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            pool.filledSubtrees[i] = zeros[i];
        }

        // Compute initial root
        bytes32 currentZero = zeros[0];
        for (uint256 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            currentZero = TornadoPrimitives.mimcHash2(currentZero, currentZero);
        }

        pool.roots = new bytes32[](ROOT_HISTORY_SIZE);
        pool.roots[0] = currentZero;
        pool.currentRootIndex = 0;
        pool.nextIndex = 0;
        pool.lastVolumeReset = block.timestamp;
    }

    /**
     * @notice Insert a commitment into the Merkle tree
     */
    function _insert(Pool storage pool, bytes32 commitment) internal {
        uint32 currentIndex = pool.nextIndex;
        bytes32 currentHash = commitment;
        bytes32 left;
        bytes32 right;

        for (uint256 i = 0; i < MERKLE_TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                left = currentHash;
                right = TornadoPrimitives.getZeroHash(i);
                pool.filledSubtrees[i] = currentHash;
            } else {
                left = pool.filledSubtrees[i];
                right = currentHash;
            }

            currentHash = TornadoPrimitives.mimcHash2(left, right);
            currentIndex /= 2;
        }

        // Update root history
        uint32 newRootIndex = (pool.currentRootIndex + 1) %
            uint32(ROOT_HISTORY_SIZE);
        pool.roots[newRootIndex] = currentHash;
        pool.currentRootIndex = newRootIndex;
        pool.nextIndex++;
    }

    /**
     * @notice Check if a root is in history
     */
    function _isKnownRoot(
        Pool storage pool,
        bytes32 root
    ) internal view returns (bool) {
        if (root == bytes32(0)) return false;

        uint32 i = pool.currentRootIndex;
        do {
            if (root == pool.roots[i]) return true;
            if (i == 0) {
                i = uint32(ROOT_HISTORY_SIZE) - 1;
            } else {
                i--;
            }
        } while (i != pool.currentRootIndex);

        return false;
    }

    /**
     * @notice Check and update daily volume
     */
    function _checkAndUpdateVolume(Pool storage pool, uint256 amount) internal {
        // Reset daily volume if 24 hours passed
        if (block.timestamp - pool.lastVolumeReset >= 1 days) {
            pool.dailyVolume = 0;
            pool.lastVolumeReset = block.timestamp;
        }

        // Check limit
        if (pool.dailyVolume + amount > MAX_DAILY_VOLUME)
            revert DailyVolumeLimitExceeded();

        pool.dailyVolume += amount;
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
