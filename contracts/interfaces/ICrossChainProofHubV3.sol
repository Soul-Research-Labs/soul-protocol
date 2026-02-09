// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IProofVerifier} from "./IProofVerifier.sol";

/**
 * @title ICrossChainProofHubV3
 * @notice Interface for the CrossChainProofHubV3 proof aggregation hub
 * @dev Main entrypoint for cross-chain ZK proof submission, challenge, and finalization
 */
interface ICrossChainProofHubV3 {
    /*//////////////////////////////////////////////////////////////
                               ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ProofStatus {
        Pending,
        Verified,
        Challenged,
        Rejected,
        Finalized
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ProofSubmission {
        bytes32 proofHash;
        bytes32 publicInputsHash;
        bytes32 commitment;
        uint64 sourceChainId;
        uint64 destChainId;
        uint64 submittedAt;
        uint64 challengeDeadline;
        address relayer;
        ProofStatus status;
        uint256 stake;
    }

    struct BatchSubmission {
        bytes32 batchId;
        bytes32 merkleRoot;
        uint256 proofCount;
        uint64 submittedAt;
        uint64 challengeDeadline;
        address relayer;
        ProofStatus status;
        uint256 totalStake;
    }

    struct Challenge {
        bytes32 proofId;
        address challenger;
        uint256 stake;
        uint64 createdAt;
        uint64 deadline;
        bool resolved;
        bool challengerWon;
        string reason;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        address indexed relayer
    );
    event ProofDataEmitted(
        bytes32 indexed proofId,
        bytes proof,
        bytes publicInputs
    );
    event BatchSubmitted(
        bytes32 indexed batchId,
        bytes32 indexed merkleRoot,
        uint256 indexed proofCount,
        address relayer
    );
    event ProofVerified(bytes32 indexed proofId, ProofStatus status);
    event ProofFinalized(bytes32 indexed proofId);
    event ProofRejected(bytes32 indexed proofId, string reason);
    event ChallengeCreated(
        bytes32 indexed proofId,
        address indexed challenger,
        string reason
    );
    event ChallengeResolved(
        bytes32 indexed proofId,
        bool challengerWon,
        address indexed winner,
        uint256 reward
    );
    event RelayerStakeDeposited(
        address indexed relayer,
        uint256 indexed amount
    );
    event RelayerStakeWithdrawn(
        address indexed relayer,
        uint256 indexed amount
    );
    event RelayerSlashed(address indexed relayer, uint256 indexed amount);
    event ChainAdded(uint256 indexed chainId);
    event ChainRemoved(uint256 indexed chainId);
    event TrustedRemoteSet(uint256 indexed chainId, address indexed remote);
    event VerifierSet(bytes32 indexed proofType, address verifier);
    event VerifierRegistryUpdated(
        address indexed oldRegistry,
        address indexed newRegistry
    );
    event ChallengePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event MinStakesUpdated(uint256 relayerStake, uint256 challengerStake);
    event ProofSubmissionFeeUpdated(uint256 oldFee, uint256 newFee);
    event RateLimitsUpdated(uint256 maxProofsPerHour, uint256 maxValuePerHour);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientStake(uint256 provided, uint256 required);
    error ProofNotFound(bytes32 proofId);
    error ProofAlreadyExists(bytes32 proofId);
    error InvalidProofStatus(
        bytes32 proofId,
        ProofStatus current,
        ProofStatus expected
    );
    error ChallengePeriodNotOver(bytes32 proofId, uint256 deadline);
    error ChallengePeriodOver(bytes32 proofId);
    error ChallengeAlreadyExists(bytes32 proofId);
    error ChallengeNotFound(bytes32 proofId);
    error UnsupportedChain(uint256 chainId);
    error VerifierNotSet(bytes32 proofType);
    error InvalidProof();
    error BatchTooLarge(uint256 size, uint256 maxSize);
    error EmptyBatch();
    error InvalidMerkleProof();
    error UnauthorizedRelayer();
    error WithdrawFailed();
    error InsufficientFee(uint256 provided, uint256 required);
    error ZeroAddress();
    error InvalidChainId(uint256 chainId);
    error InvalidChallengePeriod();
    error AdminNotAllowed();
    error RolesNotSeparated();
    error TransferFailed();
    error ProofRateLimitExceeded();

    /*//////////////////////////////////////////////////////////////
                         RELAYER STAKE MGMT
    //////////////////////////////////////////////////////////////*/

    function depositStake() external payable;

    function withdrawStake(uint256 amount) external;

    function withdrawRewards(uint256 amount) external;

    /*//////////////////////////////////////////////////////////////
                         PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function submitProof(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId
    ) external payable returns (bytes32 proofId);

    function submitProofInstant(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        bytes32 proofType
    ) external payable returns (bytes32 proofId);

    function submitBatch(
        BatchProofInput[] calldata _proofs,
        bytes32 merkleRoot
    ) external payable returns (bytes32 batchId);

    /*//////////////////////////////////////////////////////////////
                         CHALLENGE SYSTEM
    //////////////////////////////////////////////////////////////*/

    function challengeProof(
        bytes32 proofId,
        string calldata reason
    ) external payable;

    function resolveChallenge(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 proofType
    ) external;

    function expireChallenge(bytes32 proofId) external;

    /*//////////////////////////////////////////////////////////////
                          FINALIZATION
    //////////////////////////////////////////////////////////////*/

    function finalizeProof(bytes32 proofId) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getProof(
        bytes32 proofId
    ) external view returns (ProofSubmission memory);

    function getBatch(
        bytes32 batchId
    ) external view returns (BatchSubmission memory);

    function getChallenge(
        bytes32 proofId
    ) external view returns (Challenge memory);

    function isProofFinalized(bytes32 proofId) external view returns (bool);

    function getRelayerStats(
        address relayer
    )
        external
        view
        returns (uint256 stake, uint256 successCount, uint256 slashCount);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function confirmRoleSeparation() external;

    function setVerifier(bytes32 proofType, address _verifier) external;

    function addSupportedChain(uint256 chainId) external;

    function removeSupportedChain(uint256 chainId) external;

    function setTrustedRemote(uint256 chainId, address remote) external;

    function setVerifierRegistry(address _registry) external;

    function setChallengePeriod(uint256 _period) external;

    function setMinStakes(
        uint256 _relayerStake,
        uint256 _challengerStake
    ) external;

    function setProofSubmissionFee(uint256 _fee) external;

    function setRateLimits(
        uint256 _maxProofsPerHour,
        uint256 _maxValuePerHour
    ) external;

    function withdrawFees(address to) external;

    function pause() external;

    function unpause() external;
}

/**
 * @title BatchProofInput
 * @notice Input struct for batch proof submissions
 */
struct BatchProofInput {
    bytes32 proofHash;
    bytes32 publicInputsHash;
    bytes32 commitment;
    uint64 sourceChainId;
    uint64 destChainId;
}
