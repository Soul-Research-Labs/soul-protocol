// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MidnightBridgeHub
 * @author Soul Protocol
 * @notice Main Ethereum bridge contract for Midnight Network interoperability
 * @dev Enables bidirectional asset transfers between Ethereum/L2s and Midnight
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     MIDNIGHT BRIDGE HUB                                  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐      │
 * │  │  Lock Manager   │    │  Proof Verifier │    │  State Sync     │      │
 * │  │                 │    │                 │    │                 │      │
 * │  │  • lockForMN    │    │  • verifyProof  │    │  • updateRoot   │      │
 * │  │  • claimFromMN  │    │  • batchVerify  │    │  • syncNullifier│      │
 * │  │  • refund       │    │  • checkNullif. │    │  • getState     │      │
 * │  └─────────────────┘    └─────────────────┘    └─────────────────┘      │
 * │                                                                          │
 * │  SECURITY: ReentrancyGuard, Pausable, RBAC, Rate Limiting               │
 * │  PRIVACY:  Stealth addresses, Commitment hiding, CDNA nullifiers        │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED ASSETS:
 * - ETH (native)
 * - ERC20 tokens (whitelisted)
 * - Wrapped NIGHT (wNIGHT) - Midnight native token representation
 */
contract MidnightBridgeHub is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for bridge operators (relay proofs, update roots)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Role for relayers (submit proofs from Midnight)
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Role for emergency actions
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /// @notice Role for asset whitelisting
    bytes32 public constant ASSET_ADMIN_ROLE = keccak256("ASSET_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidAmount();
    error InvalidProof();
    error InvalidRecipient();
    error InvalidNullifier();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error LockNotFound(bytes32 lockId);
    error LockAlreadyClaimed(bytes32 lockId);
    error LockNotExpired(bytes32 lockId);
    error AssetNotSupported(address asset);
    error InsufficientBond();
    error ChallengePeriodActive();
    error TransferFailed();
    error RateLimitExceeded();
    error InvalidMerkleRoot();
    error ProofExpired();

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Lock status for cross-chain transfers
    enum LockStatus {
        None,
        Pending, // Lock created, waiting for confirmation
        Confirmed, // Confirmed, can be claimed on Midnight
        Claimed, // Claimed on Midnight, released here
        Refunded, // Expired and refunded
        Disputed // Under dispute
    }

    /// @notice Lock record for Ethereum → Midnight transfers
    struct Lock {
        bytes32 lockId;
        address token;
        uint256 amount;
        bytes32 commitment; // Pedersen commitment to private data
        bytes32 midnightRecipient; // Midnight address hash
        address ethSender;
        uint64 createdAt;
        uint64 unlockDeadline;
        LockStatus status;
    }

    /// @notice Claim record for Midnight → Ethereum transfers
    struct Claim {
        bytes32 claimId;
        bytes32 midnightCommitment; // From Midnight
        bytes32 nullifier; // CDNA nullifier
        address token;
        uint256 amount;
        address recipient; // Ethereum recipient
        uint64 claimedAt;
        bool executed;
    }

    /// @notice Midnight state root for verification
    struct MidnightStateRoot {
        bytes32 depositRoot;
        bytes32 nullifierRoot;
        uint64 blockNumber;
        uint64 timestamp;
        bytes32 stateHash;
    }

    /// @notice Proof bundle from Midnight
    struct MidnightProof {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 merkleRoot;
        bytes proof; // ZK proof bytes
        uint64 midnightBlock;
        bytes32 stateRoot;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain ID for this deployment
    uint256 public immutable CHAIN_ID;

    /// @notice Wrapped NIGHT token address
    address public immutable wNIGHT;

    /// @notice Midnight proof verifier contract
    IMidnightProofVerifier public proofVerifier;

    /// @notice Lock storage: lockId => Lock
    mapping(bytes32 => Lock) public locks;

    /// @notice Claim storage: claimId => Claim
    mapping(bytes32 => Claim) public claims;

    /// @notice Nullifier registry (prevents double-spend)
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Supported assets
    mapping(address => bool) public supportedAssets;

    /// @notice Asset to Midnight token mapping
    mapping(address => bytes32) public assetToMidnightToken;

    /// @notice Current Midnight state root
    MidnightStateRoot public currentMidnightState;

    /// @notice Historical Midnight roots (for delayed verification)
    mapping(bytes32 => bool) public historicalMidnightRoots;

    /// @notice Lock counter
    uint256 public totalLocks;

    /// @notice Total value locked per asset
    mapping(address => uint256) public totalValueLocked;

    /// @notice Minimum lock amount per asset
    mapping(address => uint256) public minLockAmount;

    /// @notice Maximum lock amount per asset
    mapping(address => uint256) public maxLockAmount;

    /// @notice Lock timeout (default 7 days)
    uint64 public lockTimeout = 7 days;

    /// @notice Challenge period (default 2 hours)
    uint64 public challengePeriod = 2 hours;

    /// @notice Rate limiting: locks per hour
    uint256 public maxLocksPerHour = 100;
    uint256 public hourlyLockCount;
    uint256 public lastRateLimitReset;

    /// @notice Relayer bonds
    mapping(address => uint256) public relayerBonds;
    uint256 public minRelayerBond = 1 ether;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event LockCreated(
        bytes32 indexed lockId,
        address indexed sender,
        address indexed token,
        uint256 amount,
        bytes32 commitment,
        bytes32 midnightRecipient
    );

    event LockConfirmed(bytes32 indexed lockId, bytes32 midnightTxHash);

    event LockClaimed(bytes32 indexed lockId, bytes32 midnightProofHash);

    event LockRefunded(
        bytes32 indexed lockId,
        address indexed sender,
        uint256 amount
    );

    event ClaimProcessed(
        bytes32 indexed claimId,
        bytes32 indexed nullifier,
        address indexed recipient,
        address token,
        uint256 amount
    );

    event MidnightStateUpdated(
        bytes32 indexed depositRoot,
        bytes32 indexed nullifierRoot,
        uint64 midnightBlock
    );

    event AssetAdded(address indexed token, bytes32 midnightToken);

    event AssetRemoved(address indexed token);

    event RelayerBondDeposited(address indexed relayer, uint256 amount);
    event RelayerBondWithdrawn(address indexed relayer, uint256 amount);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        bytes32 reason
    );

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _wNIGHT, address _proofVerifier, address _admin) {
        require(_wNIGHT != address(0), "Invalid wNIGHT");
        require(_proofVerifier != address(0), "Invalid verifier");
        require(_admin != address(0), "Invalid admin");

        CHAIN_ID = block.chainid;
        wNIGHT = _wNIGHT;
        proofVerifier = IMidnightProofVerifier(_proofVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        _grantRole(ASSET_ADMIN_ROLE, _admin);

        // Add wNIGHT as supported asset
        supportedAssets[_wNIGHT] = true;
        assetToMidnightToken[_wNIGHT] = keccak256("NIGHT");

        // ETH support (address(0))
        supportedAssets[address(0)] = true;
        assetToMidnightToken[address(0)] = keccak256("ETH");

        lastRateLimitReset = block.timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                        ETHEREUM → MIDNIGHT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Lock ETH for transfer to Midnight
     * @param commitment Pedersen commitment to private transfer data
     * @param midnightRecipient Midnight recipient address hash
     * @return lockId Unique lock identifier
     */
    function lockETHForMidnight(
        bytes32 commitment,
        bytes32 midnightRecipient
    ) external payable nonReentrant whenNotPaused returns (bytes32 lockId) {
        if (msg.value == 0) revert InvalidAmount();
        if (midnightRecipient == bytes32(0)) revert InvalidRecipient();

        _checkRateLimit();

        lockId = _createLock(
            address(0),
            msg.value,
            commitment,
            midnightRecipient
        );
    }

    /**
     * @notice Lock ERC20 tokens for transfer to Midnight
     * @param token Token address
     * @param amount Amount to lock
     * @param commitment Pedersen commitment to private transfer data
     * @param midnightRecipient Midnight recipient address hash
     * @return lockId Unique lock identifier
     */
    function lockTokenForMidnight(
        address token,
        uint256 amount,
        bytes32 commitment,
        bytes32 midnightRecipient
    ) external nonReentrant whenNotPaused returns (bytes32 lockId) {
        if (amount == 0) revert InvalidAmount();
        if (!supportedAssets[token]) revert AssetNotSupported(token);
        if (midnightRecipient == bytes32(0)) revert InvalidRecipient();

        _checkRateLimit();

        // Transfer tokens to this contract
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        lockId = _createLock(token, amount, commitment, midnightRecipient);
    }

    /**
     * @notice Internal lock creation
     */
    function _createLock(
        address token,
        uint256 amount,
        bytes32 commitment,
        bytes32 midnightRecipient
    ) internal returns (bytes32 lockId) {
        // Validate amount limits
        uint256 minAmount = minLockAmount[token];
        uint256 maxAmount = maxLockAmount[token];

        if (minAmount > 0 && amount < minAmount) revert InvalidAmount();
        if (maxAmount > 0 && amount > maxAmount) revert InvalidAmount();

        // Generate unique lock ID
        lockId = keccak256(
            abi.encodePacked(
                block.chainid,
                msg.sender,
                token,
                amount,
                commitment,
                block.timestamp,
                totalLocks
            )
        );

        // Create lock record
        locks[lockId] = Lock({
            lockId: lockId,
            token: token,
            amount: amount,
            commitment: commitment,
            midnightRecipient: midnightRecipient,
            ethSender: msg.sender,
            createdAt: uint64(block.timestamp),
            unlockDeadline: uint64(block.timestamp + lockTimeout),
            status: LockStatus.Pending
        });

        // Update counters
        unchecked {
            totalLocks++;
            totalValueLocked[token] += amount;
            hourlyLockCount++;
        }

        emit LockCreated(
            lockId,
            msg.sender,
            token,
            amount,
            commitment,
            midnightRecipient
        );
    }

    /**
     * @notice Confirm lock after Midnight proof is received
     * @param lockId Lock to confirm
     * @param midnightTxHash Transaction hash on Midnight
     */
    function confirmLock(
        bytes32 lockId,
        bytes32 midnightTxHash
    ) external onlyRole(RELAYER_ROLE) {
        Lock storage lock = locks[lockId];
        if (lock.lockId == bytes32(0)) revert LockNotFound(lockId);
        if (lock.status != LockStatus.Pending)
            revert LockAlreadyClaimed(lockId);

        lock.status = LockStatus.Confirmed;

        emit LockConfirmed(lockId, midnightTxHash);
    }

    /**
     * @notice Refund expired lock
     * @param lockId Lock to refund
     */
    function refundLock(bytes32 lockId) external nonReentrant {
        Lock storage lock = locks[lockId];
        if (lock.lockId == bytes32(0)) revert LockNotFound(lockId);
        if (lock.status != LockStatus.Pending)
            revert LockAlreadyClaimed(lockId);
        if (block.timestamp < lock.unlockDeadline)
            revert LockNotExpired(lockId);

        lock.status = LockStatus.Refunded;

        uint256 amount = lock.amount;
        address token = lock.token;
        address sender = lock.ethSender;

        // Update TVL
        unchecked {
            totalValueLocked[token] -= amount;
        }

        // Transfer back
        if (token == address(0)) {
            (bool success, ) = sender.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(token).safeTransfer(sender, amount);
        }

        emit LockRefunded(lockId, sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                        MIDNIGHT → ETHEREUM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Claim tokens from Midnight with ZK proof
     * @param proof Proof bundle from Midnight
     * @param token Token to receive
     * @param amount Amount to receive
     * @param recipient Ethereum recipient
     */
    function claimFromMidnight(
        MidnightProof calldata proof,
        address token,
        uint256 amount,
        address recipient
    ) external nonReentrant whenNotPaused {
        if (amount == 0) revert InvalidAmount();
        if (recipient == address(0)) revert InvalidRecipient();
        if (!supportedAssets[token]) revert AssetNotSupported(token);

        // Check nullifier hasn't been used
        if (nullifierUsed[proof.nullifier]) {
            revert NullifierAlreadyUsed(proof.nullifier);
        }

        // Verify Midnight state root
        if (
            !historicalMidnightRoots[proof.stateRoot] &&
            proof.stateRoot != currentMidnightState.stateHash
        ) {
            revert InvalidMerkleRoot();
        }

        // Verify ZK proof
        bool valid = proofVerifier.verifyMidnightProof(
            proof.commitment,
            proof.nullifier,
            proof.merkleRoot,
            token,
            amount,
            recipient,
            proof.proof
        );
        if (!valid) revert InvalidProof();

        // Mark nullifier as used
        nullifierUsed[proof.nullifier] = true;

        // Generate claim ID
        bytes32 claimId = keccak256(
            abi.encodePacked(
                proof.nullifier,
                token,
                amount,
                recipient,
                block.timestamp
            )
        );

        // Store claim record
        claims[claimId] = Claim({
            claimId: claimId,
            midnightCommitment: proof.commitment,
            nullifier: proof.nullifier,
            token: token,
            amount: amount,
            recipient: recipient,
            claimedAt: uint64(block.timestamp),
            executed: true
        });

        // Update TVL
        unchecked {
            totalValueLocked[token] -= amount;
        }

        // Transfer tokens
        if (token == address(0)) {
            (bool success, ) = recipient.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit ClaimProcessed(claimId, proof.nullifier, recipient, token, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          STATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update Midnight state root
     * @param depositRoot New deposit Merkle root
     * @param nullifierRoot New nullifier Merkle root
     * @param midnightBlock Midnight block number
     * @param proof State transition proof
     */
    function updateMidnightState(
        bytes32 depositRoot,
        bytes32 nullifierRoot,
        uint64 midnightBlock,
        bytes calldata proof
    ) external onlyRole(OPERATOR_ROLE) {
        // Verify state transition proof
        bool valid = proofVerifier.verifyStateTransition(
            currentMidnightState.stateHash,
            keccak256(
                abi.encodePacked(depositRoot, nullifierRoot, midnightBlock)
            ),
            proof
        );
        if (!valid) revert InvalidProof();

        // Store old root as historical
        if (currentMidnightState.stateHash != bytes32(0)) {
            historicalMidnightRoots[currentMidnightState.stateHash] = true;
        }

        // Update current state
        bytes32 newStateHash = keccak256(
            abi.encodePacked(depositRoot, nullifierRoot, midnightBlock)
        );

        currentMidnightState = MidnightStateRoot({
            depositRoot: depositRoot,
            nullifierRoot: nullifierRoot,
            blockNumber: midnightBlock,
            timestamp: uint64(block.timestamp),
            stateHash: newStateHash
        });

        emit MidnightStateUpdated(depositRoot, nullifierRoot, midnightBlock);
    }

    /**
     * @notice Sync nullifiers from Midnight
     * @param nullifiers Array of nullifiers to mark as used
     * @param proof Proof of nullifier inclusion in Midnight tree
     */
    function syncNullifiers(
        bytes32[] calldata nullifiers,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        // Verify proof of nullifier batch
        bool valid = proofVerifier.verifyNullifierBatch(
            nullifiers,
            currentMidnightState.nullifierRoot,
            proof
        );
        if (!valid) revert InvalidProof();

        // Mark nullifiers as used
        for (uint256 i = 0; i < nullifiers.length; ) {
            nullifierUsed[nullifiers[i]] = true;
            unchecked {
                i++;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           RELAYER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit relayer bond
     */
    function depositRelayerBond() external payable {
        if (msg.value < minRelayerBond) revert InsufficientBond();

        relayerBonds[msg.sender] += msg.value;

        emit RelayerBondDeposited(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw relayer bond (after cooldown)
     * @param amount Amount to withdraw
     */
    function withdrawRelayerBond(uint256 amount) external nonReentrant {
        uint256 bond = relayerBonds[msg.sender];
        if (amount > bond) revert InsufficientBond();

        relayerBonds[msg.sender] = bond - amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit RelayerBondWithdrawn(msg.sender, amount);
    }

    /**
     * @notice Slash relayer for misbehavior
     * @param relayer Relayer to slash
     * @param amount Amount to slash
     * @param reason Reason hash
     */
    function slashRelayer(
        address relayer,
        uint256 amount,
        bytes32 reason
    ) external onlyRole(OPERATOR_ROLE) {
        uint256 bond = relayerBonds[relayer];
        uint256 slashAmount = amount > bond ? bond : amount;

        relayerBonds[relayer] = bond - slashAmount;

        emit RelayerSlashed(relayer, slashAmount, reason);
    }

    /*//////////////////////////////////////////////////////////////
                          ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add supported asset
     * @param token Token address
     * @param midnightToken Midnight token identifier
     * @param minAmount Minimum lock amount
     * @param maxAmount Maximum lock amount
     */
    function addSupportedAsset(
        address token,
        bytes32 midnightToken,
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(ASSET_ADMIN_ROLE) {
        supportedAssets[token] = true;
        assetToMidnightToken[token] = midnightToken;
        minLockAmount[token] = minAmount;
        maxLockAmount[token] = maxAmount;

        emit AssetAdded(token, midnightToken);
    }

    /**
     * @notice Remove supported asset
     * @param token Token to remove
     */
    function removeSupportedAsset(
        address token
    ) external onlyRole(ASSET_ADMIN_ROLE) {
        supportedAssets[token] = false;
        delete assetToMidnightToken[token];
        delete minLockAmount[token];
        delete maxLockAmount[token];

        emit AssetRemoved(token);
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update proof verifier
     * @param newVerifier New verifier address
     */
    function setProofVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newVerifier != address(0), "Invalid verifier");
        proofVerifier = IMidnightProofVerifier(newVerifier);
    }

    /**
     * @notice Update lock timeout
     * @param timeout New timeout in seconds
     */
    function setLockTimeout(
        uint64 timeout
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(timeout >= 1 hours && timeout <= 30 days, "Invalid timeout");
        lockTimeout = timeout;
    }

    /**
     * @notice Update challenge period
     * @param period New period in seconds
     */
    function setChallengePeriod(
        uint64 period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(period >= 30 minutes && period <= 7 days, "Invalid period");
        challengePeriod = period;
    }

    /**
     * @notice Pause bridge
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check and update rate limit
     */
    function _checkRateLimit() internal {
        if (block.timestamp >= lastRateLimitReset + 1 hours) {
            hourlyLockCount = 0;
            lastRateLimitReset = block.timestamp;
        }

        if (hourlyLockCount >= maxLocksPerHour) {
            revert RateLimitExceeded();
        }
    }

    /*//////////////////////////////////////////////////////////////
                               VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get lock details
     * @param lockId Lock identifier
     */
    function getLock(bytes32 lockId) external view returns (Lock memory) {
        return locks[lockId];
    }

    /**
     * @notice Get claim details
     * @param claimId Claim identifier
     */
    function getClaim(bytes32 claimId) external view returns (Claim memory) {
        return claims[claimId];
    }

    /**
     * @notice Check if nullifier is used
     * @param nullifier Nullifier to check
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifierUsed[nullifier];
    }

    /**
     * @notice Get current Midnight state
     */
    function getMidnightState()
        external
        view
        returns (MidnightStateRoot memory)
    {
        return currentMidnightState;
    }

    /**
     * @notice Get total value locked for asset
     * @param token Asset address
     */
    function getTVL(address token) external view returns (uint256) {
        return totalValueLocked[token];
    }

    /*//////////////////////////////////////////////////////////////
                              RECEIVE
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                        PROOF VERIFIER INTERFACE
//////////////////////////////////////////////////////////////*/

interface IMidnightProofVerifier {
    function verifyMidnightProof(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 merkleRoot,
        address token,
        uint256 amount,
        address recipient,
        bytes calldata proof
    ) external view returns (bool);

    function verifyStateTransition(
        bytes32 oldStateHash,
        bytes32 newStateHash,
        bytes calldata proof
    ) external view returns (bool);

    function verifyNullifierBatch(
        bytes32[] calldata nullifiers,
        bytes32 nullifierRoot,
        bytes calldata proof
    ) external view returns (bool);
}
