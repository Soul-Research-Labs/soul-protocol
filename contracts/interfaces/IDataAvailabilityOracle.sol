// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDataAvailabilityOracle
 * @author ZASEON
 * @notice Interface for SVID-inspired Data Availability Oracle
 * @dev Enables off-chain storage of encrypted payloads with on-chain DA commitments
 *      and a staked attestor/challenge system for availability guarantees.
 */
interface IDataAvailabilityOracle {
    // ============================================
    // ENUMS
    // ============================================

    /// @notice Status of a DA commitment
    enum CommitmentStatus {
        Pending,      // Submitted, awaiting attestation
        Attested,     // At least one attestor has confirmed availability
        Challenged,   // Availability has been disputed
        Verified,     // Challenge resolved — data proven available
        Unavailable,  // Challenge resolved — data proven unavailable
        Expired       // TTL expired
    }

    /// @notice Role of a DA participant
    enum ParticipantRole {
        Attestor,     // Confirms data availability
        Challenger    // Disputes data availability
    }

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice On-chain DA commitment (replaces storing full encrypted payloads)
    struct DACommitment {
        bytes32 commitmentId;        // Unique commitment ID
        bytes32 payloadHash;         // Keccak256 hash of the encrypted payload
        bytes32 erasureCodingRoot;   // Merkle root of erasure-coded fragments
        uint256 dataSize;            // Size of the payload in bytes
        string storageURI;           // Off-chain storage location (IPFS CID, Arweave TX, etc.)
        address submitter;           // Who submitted the commitment
        uint64 submittedAt;          // Submission timestamp
        uint64 expiresAt;            // TTL expiry timestamp
        uint256 attestationCount;    // Number of attestations
        CommitmentStatus status;     // Current status
    }

    /// @notice Attestor registration
    struct Attestor {
        address addr;                // Attestor address
        uint256 stake;               // Staked amount (bond)
        uint256 successfulAttestations; // Total successful attestations
        uint256 failedAttestations;  // Attestations that were challenged and lost
        uint64 registeredAt;         // Registration timestamp
        bool active;                 // Currently active
    }

    /// @notice Availability challenge
    struct Challenge {
        bytes32 challengeId;         // Unique challenge ID
        bytes32 commitmentId;        // Target commitment
        address challenger;          // Who raised the challenge
        uint256 challengerBond;      // Bond posted by challenger
        uint64 raisedAt;             // Challenge timestamp
        uint64 responseDeadline;     // Deadline for attestor response
        bool resolved;               // Whether resolved
        bool challengerWon;          // Challenge outcome
    }

    // ============================================
    // EVENTS
    // ============================================

    event DACommitmentSubmitted(
        bytes32 indexed commitmentId,
        bytes32 payloadHash,
        uint256 dataSize,
        string storageURI,
        address indexed submitter
    );

    event AvailabilityAttested(
        bytes32 indexed commitmentId,
        address indexed attestor,
        uint256 attestationCount
    );

    event AvailabilityChallenged(
        bytes32 indexed challengeId,
        bytes32 indexed commitmentId,
        address indexed challenger
    );

    event ChallengeResolved(
        bytes32 indexed challengeId,
        bool challengerWon,
        uint256 slashedAmount
    );

    event AttestorRegistered(address indexed attestor, uint256 stake);
    event AttestorSlashed(address indexed attestor, uint256 amount);
    event AttestorExited(address indexed attestor, uint256 stakeReturned);

    // ============================================
    // ERRORS
    // ============================================

    error CommitmentDoesNotExist(bytes32 commitmentId);
    error CommitmentNotPending(bytes32 commitmentId);
    error CommitmentExpired(bytes32 commitmentId);
    error InsufficientStake(uint256 provided, uint256 required);
    error NotActiveAttestor(address addr);
    error AlreadyAttested(bytes32 commitmentId, address attestor);
    error ChallengeDoesNotExist(bytes32 challengeId);
    error ChallengeAlreadyResolved(bytes32 challengeId);
    error ChallengeResponseDeadlinePassed(bytes32 challengeId);
    error ChallengeResponseDeadlineNotPassed(bytes32 challengeId);
    error InvalidPayloadHash();
    error InvalidStorageURI();

    // ============================================
    // DA COMMITMENT MANAGEMENT
    // ============================================

    /// @notice Submit a DA commitment for off-chain encrypted payload
    function submitDACommitment(
        bytes32 payloadHash,
        bytes32 erasureCodingRoot,
        uint256 dataSize,
        string calldata storageURI,
        uint64 ttlSeconds
    ) external returns (bytes32 commitmentId);

    /// @notice Attest that data for a commitment is available and retrievable
    function attestAvailability(bytes32 commitmentId) external;

    // ============================================
    // CHALLENGE/RESPONSE
    // ============================================

    /// @notice Challenge the availability of data
    function challengeAvailability(bytes32 commitmentId) external payable returns (bytes32 challengeId);

    /// @notice Respond to a challenge by providing a retrieval proof
    function resolveChallenge(bytes32 challengeId, bytes calldata retrievalProof) external;

    /// @notice Finalize an unresponded challenge (challenger wins by default)
    function finalizeExpiredChallenge(bytes32 challengeId) external;

    // ============================================
    // ATTESTOR MANAGEMENT
    // ============================================

    /// @notice Register as a DA attestor
    function registerAttestor() external payable;

    /// @notice Exit as an attestor and reclaim stake
    function exitAttestor() external;

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    function getCommitment(bytes32 commitmentId) external view returns (DACommitment memory);
    function getAttestor(address addr) external view returns (Attestor memory);
    function getChallenge(bytes32 challengeId) external view returns (Challenge memory);
    function isDataAvailable(bytes32 commitmentId) external view returns (bool);
    function getMinAttestorStake() external view returns (uint256);
    function getMinChallengerBond() external view returns (uint256);
}
