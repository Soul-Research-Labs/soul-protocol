// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PrivateRelayCommitReveal
 * @author ZASEON
 * @notice Commit-reveal scheme for relay requests to prevent relay adapter selection leakage
 *
 * @dev PROBLEM:
 *      When users submit relay requests directly to MultiRelayerRouter, the calldata reveals:
 *        - Which adapter is likely to be selected (based on priority order)
 *        - The destination target and payload
 *        - The gas limit (correlates with transfer complexity)
 *      Other relayers or observers can use this to build traffic analysis profiles.
 *
 *      SOLUTION:
 *      Two-phase relay submission using commit-reveal:
 *        1. COMMIT: User submits hash(payload, salt) → opaque commitment on-chain
 *        2. REVEAL: After commit block confirmation, user reveals payload + salt
 *           → Router executes the relay
 *
 *      This ensures relay parameters are hidden until the reveal phase,
 *      preventing front-running and adapter selection leakage.
 *
 *      TIMING:
 *      - Minimum reveal delay: 1 block (front-running protection)
 *      - Maximum reveal window: 256 blocks (~50 minutes on L2, ~50 minutes on L1)
 *      - After window expires, commitment is void and fee is refundable
 */
contract PrivateRelayCommitReveal is AccessControl, ReentrancyGuard {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Minimum blocks between commit and reveal (front-running protection)
    uint256 public constant MIN_REVEAL_DELAY = 1;

    /// @notice Maximum blocks after commit before it expires
    uint256 public constant MAX_REVEAL_WINDOW = 256;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct Commitment {
        bytes32 commitHash;
        address sender;
        uint256 commitBlock;
        uint256 depositedFee;
        bool revealed;
        bool expired;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// @notice Commitment registry: commitId => Commitment
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Address of the MultiRelayerRouter
    address public relayerRouter;

    /// @notice Total commits
    uint256 public totalCommits;

    /// @notice Total reveals
    uint256 public totalReveals;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event RelayCommitted(
        bytes32 indexed commitId,
        address indexed sender,
        uint256 commitBlock
    );

    event RelayRevealed(
        bytes32 indexed commitId,
        address indexed sender,
        address target,
        uint256 gasLimit
    );

    event CommitmentExpired(
        bytes32 indexed commitId,
        address indexed sender,
        uint256 refundedAmount
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAddress();
    error CommitmentAlreadyExists(bytes32 commitId);
    error CommitmentNotFound(bytes32 commitId);
    error RevealTooEarly(uint256 currentBlock, uint256 minRevealBlock);
    error RevealTooLate(uint256 currentBlock, uint256 maxRevealBlock);
    error InvalidReveal(bytes32 expected, bytes32 actual);
    error AlreadyRevealed(bytes32 commitId);
    error NotExpired(bytes32 commitId);
    error NotCommitter(address caller, address committer);

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address _admin, address _relayerRouter) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_relayerRouter == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        relayerRouter = _relayerRouter;
    }

    // =========================================================================
    // COMMIT PHASE
    // =========================================================================

    /**
     * @notice Commit to a relay request without revealing parameters
     * @dev The commitHash should be: keccak256(abi.encode(target, payload, gasLimit, salt))
     *      where salt is a random bytes32 known only to the sender.
     * @param commitId Unique identifier for this commitment (can be hash of salt)
     * @param commitHash Hash of the relay parameters + salt
     */
    function commit(
        bytes32 commitId,
        bytes32 commitHash
    ) external payable nonReentrant {
        if (commitments[commitId].commitBlock != 0) {
            revert CommitmentAlreadyExists(commitId);
        }

        commitments[commitId] = Commitment({
            commitHash: commitHash,
            sender: msg.sender,
            commitBlock: block.number,
            depositedFee: msg.value,
            revealed: false,
            expired: false
        });

        ++totalCommits;

        emit RelayCommitted(commitId, msg.sender, block.number);
    }

    // =========================================================================
    // REVEAL PHASE
    // =========================================================================

    /**
     * @notice Reveal relay parameters and execute the relay
     * @dev Must be called between MIN_REVEAL_DELAY and MAX_REVEAL_WINDOW blocks after commit.
     *      Verifies the reveal matches the commitment hash, then forwards to the router.
     * @param commitId The commitment ID from the commit phase
     * @param target The relay target address
     * @param payload The relay message payload
     * @param gasLimit The gas limit for relay execution
     * @param salt The random salt used in the commitment
     */
    function reveal(
        bytes32 commitId,
        address target,
        bytes calldata payload,
        uint256 gasLimit,
        bytes32 salt
    ) external nonReentrant {
        Commitment storage c = commitments[commitId];
        if (c.commitBlock == 0) revert CommitmentNotFound(commitId);
        if (c.revealed) revert AlreadyRevealed(commitId);
        if (msg.sender != c.sender) revert NotCommitter(msg.sender, c.sender);

        // Timing checks
        uint256 minBlock = c.commitBlock + MIN_REVEAL_DELAY;
        uint256 maxBlock = c.commitBlock + MAX_REVEAL_WINDOW;

        if (block.number < minBlock) {
            revert RevealTooEarly(block.number, minBlock);
        }
        if (block.number > maxBlock) {
            revert RevealTooLate(block.number, maxBlock);
        }

        // Verify commitment
        bytes32 computedHash = keccak256(
            abi.encode(target, payload, gasLimit, salt)
        );
        if (computedHash != c.commitHash) {
            revert InvalidReveal(c.commitHash, computedHash);
        }

        c.revealed = true;
        ++totalReveals;

        // Forward to router with deposited fee
        (bool success, ) = relayerRouter.call{value: c.depositedFee}(
            abi.encodeWithSignature(
                "relay(address,bytes,uint256)",
                target,
                payload,
                gasLimit
            )
        );
        require(success, "Relay execution failed");

        emit RelayRevealed(commitId, msg.sender, target, gasLimit);
    }

    // =========================================================================
    // EXPIRY / REFUND
    // =========================================================================

    /**
     * @notice Reclaim deposited fee for an expired commitment
     * @dev Can only be called after MAX_REVEAL_WINDOW blocks have passed without a reveal.
     * @param commitId The expired commitment ID
     */
    function reclaimExpired(bytes32 commitId) external nonReentrant {
        Commitment storage c = commitments[commitId];
        if (c.commitBlock == 0) revert CommitmentNotFound(commitId);
        if (c.revealed) revert AlreadyRevealed(commitId);
        if (c.expired) revert AlreadyRevealed(commitId); // reuse error for simplicity
        if (msg.sender != c.sender) revert NotCommitter(msg.sender, c.sender);

        uint256 maxBlock = c.commitBlock + MAX_REVEAL_WINDOW;
        if (block.number <= maxBlock) revert NotExpired(commitId);

        c.expired = true;

        uint256 refund = c.depositedFee;
        if (refund > 0) {
            (bool sent, ) = c.sender.call{value: refund}("");
            require(sent, "Refund failed");
        }

        emit CommitmentExpired(commitId, c.sender, refund);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /**
     * @notice Update the relayer router address
     * @param _relayerRouter New router address
     */
    function setRelayerRouter(
        address _relayerRouter
    ) external onlyRole(OPERATOR_ROLE) {
        if (_relayerRouter == address(0)) revert ZeroAddress();
        relayerRouter = _relayerRouter;
    }
}
