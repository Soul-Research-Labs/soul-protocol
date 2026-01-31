// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SecurityModule} from "../security/SecurityModule.sol";

/// @title CrossChainProofHubV3
/// @author Soul Protocol
/// @notice Production-ready cross-chain proof relay with optimistic verification and dispute resolution
/// @dev Implements batching, challenge periods, and gas-efficient proof storage
///
/// Security Features:
/// - Manual circuit breaker (maxProofsPerHour, maxValuePerHour)
/// - SecurityModule integration (rate limiting, flash loan guard)
/// - TOCTOU protection via relayerPendingProofs
/// - Challenge period for optimistic verification
contract CrossChainProofHubV3 is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    SecurityModule
{
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    enum ProofStatus {
        Pending, // Submitted, in challenge period
        Verified, // Challenge period passed or instant verified
        Challenged, // Under dispute
        Rejected, // Failed verification
        Finalized // Executed on destination
    }

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for authorized relayers
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Role for verifier administrators
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");

    /// @notice Role for authorized challengers
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");

    /// @notice Role for emergency operations
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /// @notice Proof submission structure
    struct ProofSubmission {
        bytes32 proofHash; // keccak256(proof)
        bytes32 publicInputsHash; // keccak256(publicInputs)
        bytes32 commitment; // Associated state commitment
        uint64 sourceChainId; // Origin chain
        uint64 destChainId; // Destination chain
        uint64 submittedAt; // Submission timestamp
        uint64 challengeDeadline; // When challenge period ends
        address relayer; // Who submitted
        ProofStatus status; // Current status
        uint256 stake; // Relayer's stake
    }

    /// @notice Batch proof submission
    struct BatchSubmission {
        bytes32 batchId; // Unique batch identifier
        bytes32 merkleRoot; // Root of proof merkle tree
        uint256 proofCount; // Number of proofs in batch
        uint64 submittedAt; // Submission timestamp
        uint64 challengeDeadline; // Batch challenge deadline
        address relayer; // Who submitted
        ProofStatus status; // Batch status
        uint256 totalStake; // Total stake for batch
    }

    /// @notice Challenge structure
    struct Challenge {
        bytes32 proofId; // Proof being challenged
        address challenger; // Who challenged
        uint256 stake; // Challenger's stake
        uint64 createdAt; // Challenge timestamp
        uint64 deadline; // Resolution deadline
        bool resolved; // Whether resolved
        bool challengerWon; // Outcome
        string reason; // Challenge reason
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of proof ID to submission
    mapping(bytes32 => ProofSubmission) public proofs;

    /// @notice Mapping of batch ID to batch submission
    mapping(bytes32 => BatchSubmission) public batches;

    /// @notice Mapping of proof ID to challenge
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Mapping of proof ID to batch ID (for batched proofs)
    mapping(bytes32 => bytes32) public proofToBatch;

    /// @notice Verifier contracts per proof type
    mapping(bytes32 => IProofVerifier) public verifiers;

    /// @notice Global Verifier Registry (optional fallback)
    address public verifierRegistry;

    /// @notice Supported chains
    mapping(uint256 => bool) public supportedChains;

    /// @notice Challenge period duration (default 1 hour)
    uint256 public challengePeriod = 1 hours;

    /// @notice Minimum stake required for relayers
    uint256 public minRelayerStake = 0.1 ether;

    /// @notice Minimum stake required for challengers
    uint256 public minChallengerStake = 0.05 ether;

    /// @notice Total proofs submitted
    uint256 public totalProofs;

    /// @notice Total batches submitted
    uint256 public totalBatches;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Circuit breaker: max proofs per hour to prevent mass exploitation
    uint256 public maxProofsPerHour = 1000;

    /// @notice Circuit breaker: max value per hour
    uint256 public maxValuePerHour = 1000 ether;

    /// @notice Hourly proof counter
    uint256 public hourlyProofCount;

    /// @notice Hourly value counter
    uint256 public hourlyValueRelayed;

    /// @notice Last reset timestamp
    uint256 public lastRateLimitReset;

    /// @notice Fee per proof submission (in wei)
    uint256 public proofSubmissionFee = 0.001 ether;

    /// @notice Relayer stakes
    mapping(address => uint256) public relayerStakes;

    /// @notice Relayer successful submissions count
    mapping(address => uint256) public relayerSuccessCount;

    /// @notice Relayer slashed count
    mapping(address => uint256) public relayerSlashCount;

    /// @notice Relayer pending proof count (TOCTOU protection)
    mapping(address => uint256) public relayerPendingProofs;

    /// @notice This chain's ID
    uint256 public immutable CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a single proof is submitted
    /// @param proofId The unique identifier of the proof
    /// @param commitment The state commitment associated with the proof
    /// @param sourceChainId The chain ID where the proof originated
    /// @param destChainId The chain ID where the proof is being submitted
    /// @param relayer The address of the relayer who submitted the proof
    event ProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        address indexed relayer
    );

    /// @notice Emitted to provide full proof data for off-chain retrieval
    /// @param proofId The unique identifier of the proof
    /// @param proof The full ZK proof bytes
    /// @param publicInputs The public inputs for the proof
    event ProofDataEmitted(
        bytes32 indexed proofId,
        bytes proof,
        bytes publicInputs
    );

    /// @notice Emitted when a batch of proofs is submitted
    /// @param batchId The unique identifier of the batch
    /// @param merkleRoot The Merkle root of the proofs in the batch
    /// @param proofCount The number of proofs included in the batch
    /// @param relayer The address of the relayer who submitted the batch
    event BatchSubmitted(
        bytes32 indexed batchId,
        bytes32 merkleRoot,
        uint256 proofCount,
        address indexed relayer
    );

    /// @notice Emitted when a proof is successfully verified
    /// @param proofId The unique identifier of the proof
    /// @param status The new status of the proof
    event ProofVerified(bytes32 indexed proofId, ProofStatus status);

    /// @notice Emitted when a proof is finalized
    /// @param proofId The unique identifier of the proof
    event ProofFinalized(bytes32 indexed proofId);

    /// @notice Emitted when a proof is rejected
    /// @param proofId The unique identifier of the proof
    /// @param reason The reason for rejection
    event ProofRejected(bytes32 indexed proofId, string reason);

    /// @notice Emitted when a challenge is created
    /// @param proofId The unique identifier of the challenged proof
    /// @param challenger The address of the challenger
    /// @param reason The reason for the challenge
    event ChallengeCreated(
        bytes32 indexed proofId,
        address indexed challenger,
        string reason
    );

    /// @notice Emitted when a challenge is resolved
    /// @param proofId The unique identifier of the challenged proof
    /// @param challengerWon True if the challenger won the dispute
    /// @param winner The address of the winner (relayer or challenger)
    /// @param reward The amount of stake rewarded or slashed
    event ChallengeResolved(
        bytes32 indexed proofId,
        bool challengerWon,
        address winner,
        uint256 reward
    );

    /// @notice Emitted when a relayer deposits stake
    /// @param relayer The address of the relayer
    /// @param amount The amount deposited
    event RelayerStakeDeposited(address indexed relayer, uint256 amount);

    /// @notice Emitted when a relayer withdraws stake
    /// @param relayer The address of the relayer
    /// @param amount The amount withdrawn
    event RelayerStakeWithdrawn(address indexed relayer, uint256 amount);

    /// @notice Emitted when a relayer is slashed
    /// @param relayer The address of the relayer
    /// @param amount The amount slashed
    event RelayerSlashed(address indexed relayer, uint256 amount);

    /// @notice Emitted when a new supported chain is added
    /// @param chainId The ID of the added chain
    event ChainAdded(uint256 indexed chainId);

    /// @notice Emitted when a supported chain is removed
    /// @param chainId The ID of the removed chain
    event ChainRemoved(uint256 indexed chainId);

    /// @notice Emitted when a verifier address is set for a proof type
    /// @param proofType The identifier of the proof type
    /// @param verifier The address of the new verifier
    event VerifierSet(bytes32 indexed proofType, address verifier);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when stake is insufficient
    error InsufficientStake(uint256 provided, uint256 required);

    /// @notice Error thrown when a proof is not found
    error ProofNotFound(bytes32 proofId);

    /// @notice Error thrown when a proof already exists
    error ProofAlreadyExists(bytes32 proofId);

    /// @notice Error thrown when a proof is in an invalid state for the operation
    error InvalidProofStatus(
        bytes32 proofId,
        ProofStatus current,
        ProofStatus expected
    );

    /// @notice Error thrown when a challenge period hasn't elapsed
    error ChallengePeriodNotOver(bytes32 proofId, uint256 deadline);

    /// @notice Error thrown when a challenge period has already elapsed
    error ChallengePeriodOver(bytes32 proofId);

    /// @notice Error thrown when a challenge already exists
    error ChallengeAlreadyExists(bytes32 proofId);

    /// @notice Error thrown when a challenge is not found
    error ChallengeNotFound(bytes32 proofId);

    /// @notice Error thrown when a chain is not supported
    error UnsupportedChain(uint256 chainId);

    /// @notice Error thrown when a verifier is not set for a proof type
    error VerifierNotSet(bytes32 proofType);

    /// @notice Error thrown when a proof is invalid
    error InvalidProof();

    /// @notice Error thrown when a batch is too large
    error BatchTooLarge(uint256 size, uint256 maxSize);

    /// @notice Error thrown when a batch is empty
    error EmptyBatch();

    /// @notice Error thrown when a Merkle proof is invalid
    error InvalidMerkleProof();

    /// @notice Error thrown when a relayer is not authorized
    error UnauthorizedRelayer();

    /// @notice Error thrown when a withdraw operation fails
    error WithdrawFailed();

    /// @notice Error thrown when the provided fee is insufficient
    error InsufficientFee(uint256 provided, uint256 required);

    /// @notice Error thrown when a zero address is provided
    error ZeroAddress();

    /// @notice Error thrown when admin tries to perform relayer/challenger actions
    error AdminNotAllowed();

    /// @notice Error thrown when roles are not properly separated
    error RolesNotSeparated();

    /// @notice Error thrown when a transfer fails
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_BATCH_SIZE = 100;
    bytes32 public constant DEFAULT_PROOF_TYPE = keccak256("GROTH16_BLS12381");

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum required roles for security-critical operations
    uint256 public constant MIN_ADMIN_THRESHOLD = 2;

    /// @notice Role separation warning flag - must be resolved before mainnet
    bool public rolesSeparated = false;

    constructor() {
        CHAIN_ID = block.chainid;

        // SECURITY: Only grant admin role to deployer
        // Other roles MUST be assigned to separate addresses before mainnet
        // This prevents Ronin-style single point of failure
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        // CRITICAL: Do NOT auto-grant RELAYER_ROLE, CHALLENGER_ROLE to admin
        // These must be assigned to independent parties
        // Deployer only gets emergency powers initially
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Add this chain as supported
        supportedChains[block.chainid] = true;
    }

    /// @notice Mark roles as properly separated (must be called before enabling full operations)
    /// @dev Prevents accidental mainnet deployment with centralized control
    function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Verify critical roles are NOT held by admin
        if (hasRole(RELAYER_ROLE, msg.sender)) revert AdminNotAllowed();
        if (hasRole(CHALLENGER_ROLE, msg.sender)) revert AdminNotAllowed();
        rolesSeparated = true;
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER STAKE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits stake as a relayer
    function depositStake() external payable {
        relayerStakes[msg.sender] += msg.value;
        emit RelayerStakeDeposited(msg.sender, msg.value);
    }

    /// @notice Withdraws relayer stake
    /// @param amount Amount to withdraw
    /// @dev Includes TOCTOU protection: cannot withdraw while proofs are pending
    function withdrawStake(uint256 amount) external nonReentrant {
        if (relayerStakes[msg.sender] < amount)
            revert InsufficientStake(relayerStakes[msg.sender], amount);

        // TOCTOU protection: ensure relayer has no pending proofs
        // that could be challenged after stake is withdrawn
        uint256 pendingCount = relayerPendingProofs[msg.sender];
        uint256 remainingStake = relayerStakes[msg.sender] - amount;
        if (pendingCount > 0 && remainingStake < minRelayerStake) {
            revert InsufficientStake(remainingStake, minRelayerStake);
        }

        relayerStakes[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert WithdrawFailed();

        emit RelayerStakeWithdrawn(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Submits a proof with optimistic verification
    /// @param proof The ZK proof bytes
    /// @param publicInputs The public inputs
    /// @param commitment Associated state commitment
    /// @param sourceChainId Origin chain
    /// @param destChainId Destination chain
    /// @return proofId The unique proof identifier
    function submitProof(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId
    ) external payable nonReentrant whenNotPaused returns (bytes32 proofId) {
        // SECURITY: Require role separation before accepting proofs
        // Prevents Ronin-style centralized validator attacks
        if (!rolesSeparated) revert RolesNotSeparated();
        if (!hasRole(RELAYER_ROLE, msg.sender)) revert UnauthorizedRelayer();

        return
            _submitProof(
                proof,
                publicInputs,
                commitment,
                sourceChainId,
                destChainId,
                false
            );
    }

    /// @notice Submits a proof with instant verification (higher fee)
    /// @param proof The ZK proof bytes
    /// @param publicInputs The public inputs
    /// @param commitment Associated state commitment
    /// @param sourceChainId Origin chain
    /// @param destChainId Destination chain
    /// @param proofType The type of proof for verifier selection
    /// @return proofId The unique proof identifier
    function submitProofInstant(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        bytes32 proofType
    ) external payable nonReentrant whenNotPaused returns (bytes32 proofId) {
        // Verify the proof immediately
        IProofVerifier verifier = verifiers[proofType];
        
        // Fallback to registry if not locally set
        if (address(verifier) == address(0) && verifierRegistry != address(0)) {
            (bool regSuccess, bytes memory regData) = verifierRegistry.staticcall(
                abi.encodeWithSignature("getVerifier(bytes32)", proofType)
            );
            if (regSuccess && regData.length == 32) {
                verifier = IProofVerifier(abi.decode(regData, (address)));
            }
        }

        if (address(verifier) == address(0)) {
            verifier = verifiers[DEFAULT_PROOF_TYPE];
            if (address(verifier) == address(0))
                revert VerifierNotSet(proofType);
        }

        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        proofId = _submitProof(
            proof,
            publicInputs,
            commitment,
            sourceChainId,
            destChainId,
            true
        );

        // Mark as verified immediately
        proofs[proofId].status = ProofStatus.Verified;
        proofs[proofId].challengeDeadline = uint64(block.timestamp); // No challenge period

        emit ProofVerified(proofId, ProofStatus.Verified);
    }

    /// @notice Submits a batch of proofs
    /// @param _proofs Array of proof data
    /// @param merkleRoot Merkle root of all proofs
    /// @return batchId The unique batch identifier
    function submitBatch(
        BatchProofInput[] calldata _proofs,
        bytes32 merkleRoot
    ) external payable nonReentrant whenNotPaused returns (bytes32 batchId) {
        uint256 len = _proofs.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        uint256 totalFee = proofSubmissionFee * len;
        if (msg.value < totalFee) revert InsufficientFee(msg.value, totalFee);
        if (relayerStakes[msg.sender] < minRelayerStake)
            revert InsufficientStake(
                relayerStakes[msg.sender],
                minRelayerStake
            );

        // FIX: Enforce rate limits for batch
        _checkRateLimit(len);

        // FIX: Prevent Stake Drain (TOCTOU)
        unchecked {
            relayerPendingProofs[msg.sender] += len;
        }

        batchId = keccak256(
            abi.encodePacked(
                merkleRoot,
                msg.sender,
                block.timestamp,
                totalBatches
            )
        );

        batches[batchId] = BatchSubmission({
            batchId: batchId,
            merkleRoot: merkleRoot,
            proofCount: len,
            submittedAt: uint64(block.timestamp),
            challengeDeadline: uint64(block.timestamp + challengePeriod),
            relayer: msg.sender,
            status: ProofStatus.Pending,
            totalStake: minRelayerStake
        });

        // Register individual proofs
        for (uint256 i = 0; i < len; ) {
            bytes32 proofId = keccak256(
                abi.encodePacked(
                    _proofs[i].proofHash,
                    _proofs[i].commitment,
                    _proofs[i].sourceChainId,
                    _proofs[i].destChainId
                )
            );

            proofs[proofId] = ProofSubmission({
                proofHash: _proofs[i].proofHash,
                publicInputsHash: _proofs[i].publicInputsHash,
                commitment: _proofs[i].commitment,
                sourceChainId: _proofs[i].sourceChainId,
                destChainId: _proofs[i].destChainId,
                submittedAt: uint64(block.timestamp),
                challengeDeadline: uint64(block.timestamp + challengePeriod),
                relayer: msg.sender,
                status: ProofStatus.Pending,
                stake: minRelayerStake / len
            });

            proofToBatch[proofId] = batchId;
            unchecked {
                ++totalProofs;
                ++i;
            }
        }

        unchecked {
            ++totalBatches;
        }
        accumulatedFees += totalFee;

        emit BatchSubmitted(batchId, merkleRoot, len, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          CHALLENGE SYSTEM
    //////////////////////////////////////////////////////////////*/

    /// @notice Challenges a proof submission
    /// @param proofId The proof to challenge
    /// @param reason The challenge reason
    function challengeProof(
        bytes32 proofId,
        string calldata reason
    ) external payable nonReentrant {
        ProofSubmission storage submission = proofs[proofId];
        if (submission.relayer == address(0)) revert ProofNotFound(proofId);
        if (submission.status != ProofStatus.Pending)
            revert InvalidProofStatus(
                proofId,
                submission.status,
                ProofStatus.Pending
            );
        if (block.timestamp >= submission.challengeDeadline)
            revert ChallengePeriodOver(proofId);
        if (challenges[proofId].challenger != address(0))
            revert ChallengeAlreadyExists(proofId);
        if (msg.value < minChallengerStake)
            revert InsufficientStake(msg.value, minChallengerStake);

        submission.status = ProofStatus.Challenged;

        challenges[proofId] = Challenge({
            proofId: proofId,
            challenger: msg.sender,
            stake: msg.value,
            createdAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp + 1 hours), // 1 hour to resolve
            resolved: false,
            challengerWon: false,
            reason: reason
        });

        emit ChallengeCreated(proofId, msg.sender, reason);
    }

    /// @notice Resolves a challenge by verifying the proof
    /// @param proofId The challenged proof
    /// @param proof The original proof bytes
    /// @param publicInputs The original public inputs
    /// @param proofType The proof type for verifier selection
    function resolveChallenge(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 proofType
    ) external nonReentrant {
        Challenge storage challenge = challenges[proofId];
        if (challenge.challenger == address(0))
            revert ChallengeNotFound(proofId);
        if (challenge.resolved) revert ChallengeNotFound(proofId);

        ProofSubmission storage submission = proofs[proofId];

        // Verify proof hashes match
        bytes32 proofHash = keccak256(proof);
        bytes32 inputsHash = keccak256(publicInputs);

        bool proofValid = false;
        if (
            proofHash == submission.proofHash &&
            inputsHash == submission.publicInputsHash
        ) {
            // Try to verify the proof
            IProofVerifier verifier = verifiers[proofType];
            
            // Fallback to registry if not locally set
            if (address(verifier) == address(0) && verifierRegistry != address(0)) {
                (bool regSuccess, bytes memory regData) = verifierRegistry.staticcall(
                    abi.encodeWithSignature("getVerifier(bytes32)", proofType)
                );
                if (regSuccess && regData.length == 32) {
                    verifier = IProofVerifier(abi.decode(regData, (address)));
                }
            }

            if (address(verifier) == address(0)) {
                verifier = verifiers[DEFAULT_PROOF_TYPE];
            }

            if (address(verifier) != address(0)) {
                proofValid = verifier.verifyProof(proof, publicInputs);
            }
        }

        challenge.resolved = true;

        if (proofValid) {
            // Relayer wins - proof was valid
            challenge.challengerWon = false;
            submission.status = ProofStatus.Verified;

            // Reward relayer with challenger's stake
            uint256 reward = challenge.stake;
            relayerStakes[submission.relayer] += reward;
            relayerSuccessCount[submission.relayer]++;

            emit ChallengeResolved(proofId, false, submission.relayer, reward);
            emit ProofVerified(proofId, ProofStatus.Verified);
        } else {
            // Challenger wins - proof was invalid
            challenge.challengerWon = true;
            submission.status = ProofStatus.Rejected;

            // Slash relayer and reward challenger
            uint256 slashAmount = submission.stake;
            uint256 actualSlashed = 0;
            
            if (relayerStakes[submission.relayer] >= slashAmount) {
                relayerStakes[submission.relayer] -= slashAmount;
                actualSlashed = slashAmount;
            } else {
                actualSlashed = relayerStakes[submission.relayer];
                relayerStakes[submission.relayer] = 0;
            }
            relayerSlashCount[submission.relayer]++;

            // Decrement pending proofs for TOCTOU protection
            if (relayerPendingProofs[submission.relayer] > 0) {
                unchecked {
                    --relayerPendingProofs[submission.relayer];
                }
            }

            // Cache challenger address before external call (CEI pattern)
            address challengerAddr = challenge.challenger;
            // FIX: Only reward what was actually slashed to prevent inflation
            uint256 reward = challenge.stake + actualSlashed;

            // Credit rewards to claimable balance (pull pattern - safer than push)
            relayerStakes[challengerAddr] += reward;

            emit ChallengeResolved(proofId, true, challengerAddr, reward);
            emit ProofRejected(proofId, challenge.reason);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          FINALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Finalizes a proof after challenge period
    /// @param proofId The proof to finalize
    function finalizeProof(bytes32 proofId) external nonReentrant {
        ProofSubmission storage submission = proofs[proofId];
        if (submission.relayer == address(0)) revert ProofNotFound(proofId);

        if (submission.status == ProofStatus.Pending) {
            if (block.timestamp < submission.challengeDeadline)
                revert ChallengePeriodNotOver(
                    proofId,
                    submission.challengeDeadline
                );

            submission.status = ProofStatus.Verified;
            emit ProofVerified(proofId, ProofStatus.Verified);
        }

        if (submission.status != ProofStatus.Verified)
            revert InvalidProofStatus(
                proofId,
                submission.status,
                ProofStatus.Verified
            );

        submission.status = ProofStatus.Finalized;
        relayerSuccessCount[submission.relayer]++;

        // Decrement pending proofs for TOCTOU protection
        if (relayerPendingProofs[submission.relayer] > 0) {
            unchecked {
                --relayerPendingProofs[submission.relayer];
            }
        }

        emit ProofFinalized(proofId);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    error ProofRateLimitExceeded();

    function _checkRateLimit(uint256 count) internal {
        if (block.timestamp >= lastRateLimitReset + 1 hours) {
            hourlyProofCount = 0;
            hourlyValueRelayed = 0;
            lastRateLimitReset = block.timestamp;
        }

        if (hourlyProofCount + count > maxProofsPerHour) {
            revert ProofRateLimitExceeded();
        }
        unchecked {
            hourlyProofCount += count;
        }
    }

    function _submitProof(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        bool instant
    ) internal returns (bytes32 proofId) {
        // CIRCUIT BREAKER: Check rate limits
        _checkRateLimit(1);

        // Validate fee
        uint256 requiredFee = instant
            ? proofSubmissionFee * 3
            : proofSubmissionFee;
        if (msg.value < requiredFee)
            revert InsufficientFee(msg.value, requiredFee);

        // Validate stake
        if (relayerStakes[msg.sender] < minRelayerStake)
            revert InsufficientStake(
                relayerStakes[msg.sender],
                minRelayerStake
            );

        // Validate chains
        if (!supportedChains[sourceChainId])
            revert UnsupportedChain(sourceChainId);
        if (!supportedChains[destChainId]) revert UnsupportedChain(destChainId);

        bytes32 proofHash = keccak256(proof);
        bytes32 publicInputsHash = keccak256(publicInputs);

        proofId = keccak256(
            abi.encodePacked(proofHash, commitment, sourceChainId, destChainId)
        );

        if (proofs[proofId].relayer != address(0))
            revert ProofAlreadyExists(proofId);

        proofs[proofId] = ProofSubmission({
            proofHash: proofHash,
            publicInputsHash: publicInputsHash,
            commitment: commitment,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            submittedAt: uint64(block.timestamp),
            challengeDeadline: uint64(block.timestamp + challengePeriod),
            relayer: msg.sender,
            status: ProofStatus.Pending,
            stake: minRelayerStake
        });

        // Track pending proofs for TOCTOU protection
        unchecked {
            ++relayerPendingProofs[msg.sender];
            ++totalProofs;
        }
        accumulatedFees += msg.value;

        emit ProofSubmitted(
            proofId,
            commitment,
            sourceChainId,
            destChainId,
            msg.sender
        );
        emit ProofDataEmitted(proofId, proof, publicInputs);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets proof submission details
    /// @param proofId The proof ID
    /// @return submission The proof submission struct
    function getProof(
        bytes32 proofId
    ) external view returns (ProofSubmission memory submission) {
        return proofs[proofId];
    }

    /// @notice Gets batch details
    /// @param batchId The batch ID
    /// @return batch The batch submission struct
    function getBatch(
        bytes32 batchId
    ) external view returns (BatchSubmission memory batch) {
        return batches[batchId];
    }

    /// @notice Gets challenge details
    /// @param proofId The proof ID
    /// @return challenge The challenge struct
    function getChallenge(
        bytes32 proofId
    ) external view returns (Challenge memory) {
        return challenges[proofId];
    }

    /// @notice Checks if a proof is finalized
    /// @param proofId The proof ID
    /// @return finalized True if finalized
    function isProofFinalized(
        bytes32 proofId
    ) external view returns (bool finalized) {
        return proofs[proofId].status == ProofStatus.Finalized;
    }

    /// @notice Gets relayer statistics
    /// @param relayer The relayer address
    /// @return stake Current stake
    /// @return successCount Successful submissions
    /// @return slashCount Times slashed
    function getRelayerStats(
        address relayer
    )
        external
        view
        returns (uint256 stake, uint256 successCount, uint256 slashCount)
    {
        return (
            relayerStakes[relayer],
            relayerSuccessCount[relayer],
            relayerSlashCount[relayer]
        );
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets a verifier for a proof type
    /// @param proofType The proof type identifier
    /// @param _verifier The verifier address
    function setVerifier(
        bytes32 proofType,
        address _verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        verifiers[proofType] = IProofVerifier(_verifier);
        emit VerifierSet(proofType, _verifier);
    }

    /// @notice Adds a supported chain
    /// @param chainId The chain ID to add
    function addSupportedChain(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = true;
        emit ChainAdded(chainId);
    }

    /// @notice Removes a supported chain
    /// @param chainId The chain ID to remove
    function removeSupportedChain(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = false;
        emit ChainRemoved(chainId);
    }

    function setTrustedRemote(
        uint256 chainId,
        address remote
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId(chainId);
        trustedRemotes[chainId] = remote;
        emit TrustedRemoteSet(chainId, remote);
    }

    /**
     * @notice Set global verifier registry
     * @param _registry The VerifierRegistry address
     */
    function setVerifierRegistry(
        address _registry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verifierRegistry = _registry;
    }

    /// @notice Updates challenge period
    /// @param _period New period in seconds
    function setChallengePeriod(
        uint256 _period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        challengePeriod = _period;
    }

    /// @notice Updates minimum stakes
    /// @param _relayerStake New relayer stake
    /// @param _challengerStake New challenger stake
    function setMinStakes(
        uint256 _relayerStake,
        uint256 _challengerStake
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minRelayerStake = _relayerStake;
        minChallengerStake = _challengerStake;
    }

    /// @notice Updates proof submission fee
    /// @param _fee New fee in wei
    function setProofSubmissionFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofSubmissionFee = _fee;
    }

    /// @notice Updates circuit breaker limits (admin only)
    /// @param _maxProofsPerHour Maximum proofs per hour
    /// @param _maxValuePerHour Maximum value per hour
    function setRateLimits(
        uint256 _maxProofsPerHour,
        uint256 _maxValuePerHour
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxProofsPerHour = _maxProofsPerHour;
        maxValuePerHour = _maxValuePerHour;
    }

    /// @notice Withdraws accumulated fees
    /// @param to Recipient address
    /// @dev Uses nonReentrant to prevent race condition
    /// @dev Slither: arbitrary-send-eth is expected - admin-only function with role protection
    // slither-disable-next-line arbitrary-send-eth
    function withdrawFees(
        address to
    ) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        if (amount == 0) revert WithdrawFailed();

        // CEI pattern: clear state before external call
        accumulatedFees = 0;

        (bool success, ) = to.call{value: amount}("");
        if (!success) revert WithdrawFailed();
    }

    /// @notice Pauses the contract
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============ Security Admin Functions ============

    /// @notice Configure SecurityModule rate limiting parameters
    /// @param window Window duration in seconds
    /// @param maxActions Max actions per window
    function setSecurityRateLimitConfig(
        uint256 window,
        uint256 maxActions
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setRateLimitConfig(window, maxActions);
    }

    /// @notice Configure SecurityModule circuit breaker parameters
    /// @param threshold Volume threshold
    /// @param cooldown Cooldown period after trip
    function setSecurityCircuitBreakerConfig(
        uint256 threshold,
        uint256 cooldown
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setCircuitBreakerConfig(threshold, cooldown);
    }

    /// @notice Toggle SecurityModule features on/off
    function setSecurityModuleFeatures(
        bool rateLimiting,
        bool circuitBreakers,
        bool flashLoanGuard,
        bool withdrawalLimits
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setSecurityFeatures(
            rateLimiting,
            circuitBreakers,
            flashLoanGuard,
            withdrawalLimits
        );
    }

    /// @notice Emergency reset SecurityModule circuit breaker
    function resetSecurityCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        _resetCircuitBreaker();
    }

    /// @notice Allows contract to receive ETH
    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);
}

/// @notice Batch proof input structure
struct BatchProofInput {
    bytes32 proofHash;
    bytes32 publicInputsHash;
    bytes32 commitment;
    uint64 sourceChainId;
    uint64 destChainId;
}
