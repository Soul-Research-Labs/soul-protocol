// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title MEVProtection
 * @author Soul Protocol
 * @notice Commit-reveal scheme to protect against MEV extraction
 * @dev Implements a two-phase commit-reveal pattern for sensitive operations
 *
 * Security Properties:
 * 1. Frontrunning Prevention: Operations are hidden until reveal
 * 2. Sandwich Attack Prevention: Commit-reveal delay breaks sandwich timing
 * 3. Time-Locked Reveals: Prevents immediate extraction
 * 4. Commitment Expiry: Prevents stale commits from being exploited
 */
contract MEVProtection is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error CommitmentAlreadyExists();
    error CommitmentNotFound();
    error CommitmentExpired();
    error CommitmentNotReady();
    error CommitmentAlreadyRevealed();
    error InvalidReveal();
    error TooManyPendingCommitments();
    error MinDelayTooShort();
    error MaxDelayTooLong();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event CommitmentCreated(
        bytes32 indexed commitmentId,
        address indexed sender,
        uint256 readyAt,
        uint256 expiresAt
    );

    event CommitmentRevealed(
        bytes32 indexed commitmentId,
        address indexed sender,
        bytes32 operationType,
        bytes data
    );

    event CommitmentCancelled(
        bytes32 indexed commitmentId,
        address indexed sender
    );
    event CommitmentExpiredEvent(bytes32 indexed commitmentId);
    event DelaysUpdated(uint256 minDelay, uint256 maxDelay);

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Commitment {
        address sender;
        bytes32 commitHash;
        uint256 createdAt;
        uint256 readyAt;
        uint256 expiresAt;
        bool revealed;
        bool cancelled;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Minimum blocks before reveal is allowed
    uint256 public minRevealDelay;

    /// @notice Maximum blocks before commitment expires
    uint256 public maxCommitmentAge;

    /// @notice Maximum pending commitments per address
    uint256 public constant MAX_PENDING_COMMITMENTS = 10;

    /// @notice All commitments
    mapping(bytes32 => Commitment) public commitments;

    /// @notice User's pending commitment count
    mapping(address => uint256) public pendingCommitmentCount;

    /// @notice User's commitment IDs
    mapping(address => bytes32[]) public userCommitments;

    /// @notice Nonce for unique commitment IDs
    mapping(address => uint256) public commitmentNonce;

    /// @notice Domain separator for commitment hashing
    bytes32 public immutable DOMAIN_SEPARATOR;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize MEV protection with delay parameters
     * @param _minRevealDelay Minimum blocks before reveal (e.g., 2)
     * @param _maxCommitmentAge Maximum blocks before expiry (e.g., 100)
     * @param admin Admin address
     */
    constructor(
        uint256 _minRevealDelay,
        uint256 _maxCommitmentAge,
        address admin
    ) {
        if (_minRevealDelay < 1) revert MinDelayTooShort();
        if (_maxCommitmentAge > 7200) revert MaxDelayTooLong(); // ~24h at 12s blocks

        minRevealDelay = _minRevealDelay;
        maxCommitmentAge = _maxCommitmentAge;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("SoulMEVProtection"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                           COMMIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a commitment for a future operation
     * @param commitHash Hash of (sender, operationType, data, salt)
     * @return commitmentId Unique identifier for this commitment
     */
    function commit(
        bytes32 commitHash
    ) external nonReentrant whenNotPaused returns (bytes32 commitmentId) {
        if (pendingCommitmentCount[msg.sender] >= MAX_PENDING_COMMITMENTS) {
            revert TooManyPendingCommitments();
        }

        // Generate unique commitment ID
        commitmentId = keccak256(
            abi.encodePacked(
                msg.sender,
                commitHash,
                commitmentNonce[msg.sender]++,
                block.number
            )
        );

        if (commitments[commitmentId].createdAt != 0) {
            revert CommitmentAlreadyExists();
        }

        uint256 readyAt = block.number + minRevealDelay;
        uint256 expiresAt = block.number + maxCommitmentAge;

        commitments[commitmentId] = Commitment({
            sender: msg.sender,
            commitHash: commitHash,
            createdAt: block.number,
            readyAt: readyAt,
            expiresAt: expiresAt,
            revealed: false,
            cancelled: false
        });

        pendingCommitmentCount[msg.sender]++;
        userCommitments[msg.sender].push(commitmentId);

        emit CommitmentCreated(commitmentId, msg.sender, readyAt, expiresAt);
    }

    /**
     * @notice Reveal a previously committed operation
     * @param commitmentId The commitment to reveal
     * @param operationType Type of operation (e.g., "WITHDRAW", "SWAP")
     * @param data Operation data
     * @param salt Random salt used in commitment
     * @return success Whether reveal was valid
     */
    function reveal(
        bytes32 commitmentId,
        bytes32 operationType,
        bytes calldata data,
        bytes32 salt
    ) external nonReentrant whenNotPaused returns (bool success) {
        Commitment storage commitment = commitments[commitmentId];

        if (commitment.createdAt == 0) revert CommitmentNotFound();
        if (commitment.sender != msg.sender) revert InvalidReveal();
        if (commitment.revealed) revert CommitmentAlreadyRevealed();
        if (commitment.cancelled) revert CommitmentNotFound();
        if (block.number < commitment.readyAt) revert CommitmentNotReady();
        if (block.number > commitment.expiresAt) revert CommitmentExpired();

        // Verify the reveal matches the commitment
        bytes32 expectedHash = keccak256(
            abi.encodePacked(
                DOMAIN_SEPARATOR,
                msg.sender,
                operationType,
                data,
                salt
            )
        );

        if (expectedHash != commitment.commitHash) revert InvalidReveal();

        commitment.revealed = true;
        pendingCommitmentCount[msg.sender]--;

        emit CommitmentRevealed(commitmentId, msg.sender, operationType, data);

        return true;
    }

    /**
     * @notice Cancel a pending commitment
     * @param commitmentId The commitment to cancel
     */
    function cancelCommitment(bytes32 commitmentId) external nonReentrant {
        Commitment storage commitment = commitments[commitmentId];

        if (commitment.createdAt == 0) revert CommitmentNotFound();
        if (commitment.sender != msg.sender) revert InvalidReveal();
        if (commitment.revealed || commitment.cancelled)
            revert CommitmentAlreadyRevealed();

        commitment.cancelled = true;
        pendingCommitmentCount[msg.sender]--;

        emit CommitmentCancelled(commitmentId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculate commitment hash (call off-chain)
     * @param sender Address making the commitment
     * @param operationType Type of operation
     * @param data Operation data
     * @param salt Random salt (keep secret until reveal!)
     * @return commitHash The hash to use for commit()
     */
    function calculateCommitHash(
        address sender,
        bytes32 operationType,
        bytes calldata data,
        bytes32 salt
    ) external view returns (bytes32 commitHash) {
        return
            keccak256(
                abi.encodePacked(
                    DOMAIN_SEPARATOR,
                    sender,
                    operationType,
                    data,
                    salt
                )
            );
    }

    /**
     * @notice Check if a commitment can be revealed
     * @param commitmentId The commitment to check
     * @return canReveal Whether reveal is possible
     * @return blocksUntilReady Blocks until ready (0 if ready)
     * @return blocksUntilExpiry Blocks until expiry
     */
    function getCommitmentStatus(
        bytes32 commitmentId
    )
        external
        view
        returns (
            bool canReveal,
            uint256 blocksUntilReady,
            uint256 blocksUntilExpiry
        )
    {
        Commitment storage commitment = commitments[commitmentId];

        if (
            commitment.createdAt == 0 ||
            commitment.revealed ||
            commitment.cancelled
        ) {
            return (false, 0, 0);
        }

        blocksUntilReady = block.number >= commitment.readyAt
            ? 0
            : commitment.readyAt - block.number;

        blocksUntilExpiry = block.number >= commitment.expiresAt
            ? 0
            : commitment.expiresAt - block.number;

        canReveal = blocksUntilReady == 0 && blocksUntilExpiry > 0;
    }

    /**
     * @notice Get all pending commitments for an address
     * @param user The user address
     * @return commitmentIds Array of pending commitment IDs
     */
    function getPendingCommitments(
        address user
    ) external view returns (bytes32[] memory commitmentIds) {
        bytes32[] storage all = userCommitments[user];
        uint256 pending = pendingCommitmentCount[user];
        commitmentIds = new bytes32[](pending);

        uint256 index = 0;
        for (uint256 i = 0; i < all.length && index < pending; i++) {
            Commitment storage c = commitments[all[i]];
            if (!c.revealed && !c.cancelled && block.number <= c.expiresAt) {
                commitmentIds[index++] = all[i];
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update reveal delay parameters
     * @param _minRevealDelay New minimum delay
     * @param _maxCommitmentAge New maximum age
     */
    function updateDelays(
        uint256 _minRevealDelay,
        uint256 _maxCommitmentAge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_minRevealDelay < 1) revert MinDelayTooShort();
        if (_maxCommitmentAge > 7200) revert MaxDelayTooLong();

        minRevealDelay = _minRevealDelay;
        maxCommitmentAge = _maxCommitmentAge;

        emit DelaysUpdated(_minRevealDelay, _maxCommitmentAge);
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

    /**
     * @notice Cleanup expired commitments for a user (gas refund)
     * @param user The user to cleanup
     * @param maxCleanup Maximum commitments to cleanup
     */
    function cleanupExpiredCommitments(
        address user,
        uint256 maxCleanup
    ) external {
        bytes32[] storage all = userCommitments[user];
        uint256 cleaned = 0;

        for (uint256 i = 0; i < all.length && cleaned < maxCleanup; i++) {
            Commitment storage c = commitments[all[i]];
            if (!c.revealed && !c.cancelled && block.number > c.expiresAt) {
                c.cancelled = true;
                pendingCommitmentCount[user]--;
                cleaned++;
                emit CommitmentExpiredEvent(all[i]);
            }
        }
    }
}
