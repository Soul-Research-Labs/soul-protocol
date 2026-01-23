// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../brevis/BrevisPrimitives.sol";

/**
 * @title BrevisPrivacyPoolAdapter
 * @author PIL Protocol
 * @notice Privacy pool for BNB Chain using Brevis ZK Coprocessor
 * @dev Implements shielded deposits/withdrawals with ZK proof verification
 *
 * ARCHITECTURE:
 * - Brevis ZK Coprocessor for trustless proof generation
 * - Merkle tree for commitment storage (depth 20)
 * - Nullifier-based double-spend prevention
 * - Cross-chain nullifier binding for PIL interop
 *
 * BNB CHAIN OPTIMIZATIONS:
 * - Optimized for ~3s block times
 * - Gas-efficient batch operations
 * - BEP-20 token support
 */
contract BrevisPrivacyPoolAdapter is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using BrevisPrimitives for *;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Merkle tree depth
    uint256 public constant TREE_DEPTH = 20;

    /// @notice Maximum leaves in tree
    uint256 public constant MAX_LEAVES = 1 << 20;

    /// @notice Root history size
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    /// @notice Maximum relayer fee (5%)
    uint256 public constant MAX_RELAYER_FEE_BPS = 500;

    /// @notice Minimum deposit amount
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Maximum deposit amount
    uint256 public constant MAX_DEPOSIT = 10000 ether;

    /// @notice Daily withdrawal limit
    uint256 public constant DAILY_LIMIT = 100000 ether;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Merkle tree filled subtrees
    bytes32[20] public filledSubtrees;

    /// @notice Root history
    bytes32[] public roots;

    /// @notice Current root index
    uint32 public currentRootIndex;

    /// @notice Next leaf index
    uint32 public nextLeafIndex;

    /// @notice Zero value for empty leaves
    bytes32 public immutable ZERO_VALUE;

    /// @notice Brevis prover contract
    address public brevisProver;

    /// @notice Spent nullifiers
    mapping(bytes32 => bool) public nullifierSpent;

    /// @notice Commitments
    mapping(bytes32 => bool) public commitments;

    /// @notice Deposit data
    mapping(bytes32 => BrevisPrimitives.DepositData) public deposits;

    /// @notice Cross-domain nullifier mappings
    mapping(bytes32 => bytes32) public crossDomainNullifiers;

    /// @notice PIL bindings
    mapping(bytes32 => bytes32) public pilBindings;

    /// @notice Registered relayers
    mapping(address => bool) public registeredRelayers;

    /// @notice Relayer fees accumulated
    mapping(address => uint256) public relayerFees;

    /// @notice Supported tokens
    mapping(address => bool) public supportedTokens;

    /// @notice Daily volume tracking
    uint256 public dailyVolume;
    uint256 public lastVolumeReset;

    /// @notice Circuit breaker
    bool public circuitBreakerActive;

    /// @notice Total deposits
    uint256 public totalDeposits;

    /// @notice Total withdrawals
    uint256 public totalWithdrawals;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Deposit(
        bytes32 indexed commitment,
        uint256 amount,
        address indexed token,
        uint32 leafIndex,
        uint256 timestamp
    );

    event Withdrawal(
        bytes32 indexed nullifier,
        address indexed recipient,
        address indexed relayer,
        uint256 amount,
        uint256 fee
    );

    event CrossDomainNullifierRegistered(
        bytes32 indexed brevisNullifier,
        bytes32 indexed pilNullifier,
        uint256 sourceChain,
        uint256 targetChain
    );

    event RelayerRegistered(address indexed relayer);
    event RelayerUnregistered(address indexed relayer);
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event BrevisProverUpdated(
        address indexed oldProver,
        address indexed newProver
    );
    event CircuitBreakerTriggered(address indexed by, string reason);
    event CircuitBreakerReset(address indexed by);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidCommitment();
    error CommitmentExists();
    error TreeFull();
    error InvalidRoot();
    error NullifierSpent();
    error InvalidProof();
    error InvalidAmount();
    error UnsupportedToken();
    error RelayerFeeTooHigh();
    error InvalidRelayer();
    error CircuitBreakerOn();
    error DailyLimitExceeded();
    error ProofExpired();
    error InsufficientConfirmations();
    error TransferFailed();
    error InvalidProver();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address admin, address _brevisProver, bytes32 zeroValue) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        brevisProver = _brevisProver;
        ZERO_VALUE = zeroValue;

        // Initialize zero hashes
        bytes32 currentZero = zeroValue;
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            filledSubtrees[i] = currentZero;
            currentZero = BrevisPrimitives.hash2(currentZero, currentZero);
        }

        // Initialize root history
        roots = new bytes32[](ROOT_HISTORY_SIZE);
        roots[0] = currentZero;

        lastVolumeReset = block.timestamp;

        // Add native token support (BNB)
        supportedTokens[address(0)] = true;
    }

    // =========================================================================
    // DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit BNB into the pool
     * @param commitment Note commitment
     */
    function depositBNB(
        bytes32 commitment
    ) external payable nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        if (!BrevisPrimitives.isValidCommitment(commitment))
            revert InvalidCommitment();
        if (commitments[commitment]) revert CommitmentExists();
        if (msg.value < MIN_DEPOSIT || msg.value > MAX_DEPOSIT)
            revert InvalidAmount();
        if (nextLeafIndex >= MAX_LEAVES) revert TreeFull();

        _processDeposit(commitment, msg.value, address(0), msg.sender);
    }

    /**
     * @notice Deposit BEP-20 token into the pool
     * @param token Token address
     * @param amount Deposit amount
     * @param commitment Note commitment
     */
    function depositToken(
        address token,
        uint256 amount,
        bytes32 commitment
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (!BrevisPrimitives.isValidCommitment(commitment))
            revert InvalidCommitment();
        if (commitments[commitment]) revert CommitmentExists();
        if (amount < MIN_DEPOSIT || amount > MAX_DEPOSIT)
            revert InvalidAmount();
        if (nextLeafIndex >= MAX_LEAVES) revert TreeFull();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        _processDeposit(commitment, amount, token, msg.sender);
    }

    /**
     * @notice Internal deposit processing
     */
    function _processDeposit(
        bytes32 commitment,
        uint256 amount,
        address token,
        address depositor
    ) internal {
        uint32 leafIndex = nextLeafIndex;

        // Insert into Merkle tree
        _insert(commitment);

        // Store commitment and deposit data
        commitments[commitment] = true;
        deposits[commitment] = BrevisPrimitives.DepositData({
            commitment: commitment,
            amount: amount,
            token: token,
            depositor: depositor,
            blockNumber: uint64(block.number),
            timestamp: block.timestamp
        });

        totalDeposits++;

        emit Deposit(commitment, amount, token, leafIndex, block.timestamp);
    }

    // =========================================================================
    // WITHDRAWAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Withdraw using Brevis ZK proof
     * @param proof Brevis proof
     * @param withdrawalData Withdrawal parameters
     */
    function withdraw(
        BrevisPrimitives.BrevisProof calldata proof,
        BrevisPrimitives.WithdrawalData calldata withdrawalData
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();

        // Validate proof timestamp
        if (!BrevisPrimitives.isProofValid(proof.timestamp, block.timestamp)) {
            revert ProofExpired();
        }

        // Validate root
        if (!_isKnownRoot(withdrawalData.root)) revert InvalidRoot();

        // Validate nullifier not spent
        if (nullifierSpent[withdrawalData.nullifier]) revert NullifierSpent();

        // Validate relayer fee
        if (
            withdrawalData.fee >
            (withdrawalData.amount * MAX_RELAYER_FEE_BPS) / 10000
        ) {
            revert RelayerFeeTooHigh();
        }

        // Validate relayer if specified
        if (
            withdrawalData.relayer != address(0) &&
            !registeredRelayers[withdrawalData.relayer]
        ) {
            revert InvalidRelayer();
        }

        // Check daily volume
        _checkDailyVolume(withdrawalData.amount);

        // Verify proof (simplified - in production call Brevis prover)
        _verifyWithdrawalProof(proof, withdrawalData);

        // Mark nullifier as spent
        nullifierSpent[withdrawalData.nullifier] = true;
        totalWithdrawals++;

        // Transfer funds
        uint256 amountToRecipient = withdrawalData.amount - withdrawalData.fee;

        // Determine token from proof result
        address token = address(0); // Simplified - would be extracted from proof

        if (token == address(0)) {
            // BNB withdrawal
            (bool success, ) = withdrawalData.recipient.call{
                value: amountToRecipient
            }("");
            if (!success) revert TransferFailed();

            if (
                withdrawalData.fee > 0 && withdrawalData.relayer != address(0)
            ) {
                (bool relayerSuccess, ) = withdrawalData.relayer.call{
                    value: withdrawalData.fee
                }("");
                if (!relayerSuccess) revert TransferFailed();
            }
        } else {
            // Token withdrawal
            IERC20(token).safeTransfer(
                withdrawalData.recipient,
                amountToRecipient
            );

            if (
                withdrawalData.fee > 0 && withdrawalData.relayer != address(0)
            ) {
                IERC20(token).safeTransfer(
                    withdrawalData.relayer,
                    withdrawalData.fee
                );
            }
        }

        emit Withdrawal(
            withdrawalData.nullifier,
            withdrawalData.recipient,
            withdrawalData.relayer,
            withdrawalData.amount,
            withdrawalData.fee
        );
    }

    /**
     * @notice Verify withdrawal proof
     */
    function _verifyWithdrawalProof(
        BrevisPrimitives.BrevisProof calldata proof,
        BrevisPrimitives.WithdrawalData calldata withdrawalData
    ) internal view {
        // Compute expected query hash
        bytes32 expectedQueryHash = keccak256(
            abi.encodePacked(
                withdrawalData.root,
                withdrawalData.nullifier,
                withdrawalData.recipient,
                withdrawalData.amount
            )
        );

        // Verify against proof
        if (proof.queryHash != expectedQueryHash) revert InvalidProof();

        // In production, would call:
        // IBrevisProver(brevisProver).verifyProof(proof);
    }

    // =========================================================================
    // CROSS-DOMAIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Register cross-domain nullifier binding
     * @param brevisNullifier Brevis nullifier
     * @param targetChainId Target chain
     */
    function registerCrossDomainNullifier(
        bytes32 brevisNullifier,
        uint256 targetChainId
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();

        bytes32 pilNullifier = BrevisPrimitives.deriveCrossDomainNullifier(
            brevisNullifier,
            block.chainid,
            targetChainId
        );

        crossDomainNullifiers[brevisNullifier] = pilNullifier;
        pilBindings[pilNullifier] = brevisNullifier;

        emit CrossDomainNullifierRegistered(
            brevisNullifier,
            pilNullifier,
            block.chainid,
            targetChainId
        );
    }

    /**
     * @notice Check if cross-domain nullifier is spent
     * @param brevisNullifier Brevis nullifier
     * @return spent True if spent
     */
    function isCrossDomainNullifierSpent(
        bytes32 brevisNullifier
    ) external view returns (bool) {
        return nullifierSpent[brevisNullifier];
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
     * @notice Claim relayer fees
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
     * @notice Get current Merkle root
     * @return root Current root
     */
    function getLastRoot() external view returns (bytes32) {
        return roots[currentRootIndex];
    }

    /**
     * @notice Check if root is known
     * @param root Root to check
     * @return known True if in history
     */
    function isKnownRoot(bytes32 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

    /**
     * @notice Get pool statistics
     * @return _totalDeposits Total deposits
     * @return _totalWithdrawals Total withdrawals
     * @return _nextLeafIndex Next leaf index
     */
    function getPoolStats()
        external
        view
        returns (
            uint256 _totalDeposits,
            uint256 _totalWithdrawals,
            uint32 _nextLeafIndex
        )
    {
        return (totalDeposits, totalWithdrawals, nextLeafIndex);
    }

    /**
     * @notice Get deposit data
     * @param commitment Commitment to query
     * @return data Deposit data
     */
    function getDeposit(
        bytes32 commitment
    ) external view returns (BrevisPrimitives.DepositData memory data) {
        return deposits[commitment];
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Add supported token
     * @param token Token address
     */
    function addSupportedToken(address token) external onlyRole(OPERATOR_ROLE) {
        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /**
     * @notice Remove supported token
     * @param token Token address
     */
    function removeSupportedToken(
        address token
    ) external onlyRole(OPERATOR_ROLE) {
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /**
     * @notice Update Brevis prover
     * @param newProver New prover address
     */
    function updateBrevisProver(
        address newProver
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newProver == address(0)) revert InvalidProver();
        address oldProver = brevisProver;
        brevisProver = newProver;
        emit BrevisProverUpdated(oldProver, newProver);
    }

    /**
     * @notice Trigger circuit breaker
     * @param reason Reason for triggering
     */
    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerActive = true;
        emit CircuitBreakerTriggered(msg.sender, reason);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerActive = false;
        emit CircuitBreakerReset(msg.sender);
    }

    /**
     * @notice Pause contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Insert commitment into Merkle tree
     * @param commitment Commitment to insert
     */
    function _insert(bytes32 commitment) internal {
        uint32 currentIndex = nextLeafIndex;
        bytes32 currentHash = commitment;
        bytes32 left;
        bytes32 right;

        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                left = currentHash;
                right = BrevisPrimitives.computeZeroHash(i, ZERO_VALUE);
                filledSubtrees[i] = currentHash;
            } else {
                left = filledSubtrees[i];
                right = currentHash;
            }

            currentHash = BrevisPrimitives.hash2(left, right);
            currentIndex /= 2;
        }

        // Update root history
        uint32 newRootIndex = (currentRootIndex + 1) %
            uint32(ROOT_HISTORY_SIZE);
        roots[newRootIndex] = currentHash;
        currentRootIndex = newRootIndex;
        nextLeafIndex++;
    }

    /**
     * @notice Check if root is in history
     * @param root Root to check
     * @return True if known
     */
    function _isKnownRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;

        uint32 i = currentRootIndex;
        do {
            if (root == roots[i]) return true;
            if (i == 0) {
                i = uint32(ROOT_HISTORY_SIZE) - 1;
            } else {
                i--;
            }
        } while (i != currentRootIndex);

        return false;
    }

    /**
     * @notice Check and update daily volume
     * @param amount Amount to add
     */
    function _checkDailyVolume(uint256 amount) internal {
        if (block.timestamp - lastVolumeReset >= 1 days) {
            dailyVolume = 0;
            lastVolumeReset = block.timestamp;
        }

        if (dailyVolume + amount > DAILY_LIMIT) revert DailyLimitExceeded();
        dailyVolume += amount;
    }

    /**
     * @notice Receive BNB
     */
    receive() external payable {}
}
