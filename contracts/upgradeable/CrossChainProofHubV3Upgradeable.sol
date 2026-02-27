// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SecurityModule} from "../security/SecurityModule.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../interfaces/ICrossChainProofHubV3.sol";

/// @title CrossChainProofHubV3Upgradeable
/// @author Soul Protocol
/// @notice UUPS-upgradeable version of CrossChainProofHubV3 with optimistic verification
/// @dev Converts immutable CHAIN_ID to storage variable for proxy compatibility.
///      Inherits SecurityModule directly (abstract, no constructor params needed).
///      Preserves all security features: role separation, TOCTOU protection,
///      circuit breakers, challenge periods.
///
/// @custom:security-contact security@soul.network
/// @custom:oz-upgrades-from CrossChainProofHubV3
/**
 * @title CrossChainProofHubV3Upgradeable
 * @author Soul Protocol Team
 * @notice Cross Chain Proof Hub V3 Upgradeable contract
 */
contract CrossChainProofHubV3Upgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    SecurityModule,
    ICrossChainProofHubV3
{
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    // Types (ProofStatus, ProofSubmission, BatchSubmission, Challenge)
    // are inherited from ICrossChainProofHubV3 to prevent struct drift.

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed: keccak256("RELAYER_ROLE")
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    /// @dev Pre-computed: keccak256("VERIFIER_ADMIN_ROLE")
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70;

    /// @dev Pre-computed: keccak256("CHALLENGER_ROLE")
    bytes32 public constant CHALLENGER_ROLE =
        0xe752add323323eb13e36c71ee508dfd16d74e9e4c4fd78786ba97989e5e13818;

    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev Pre-computed: keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @notice Role for contract upgrades
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @dev Pre-computed: keccak256("DEFAULT_PROOF_TYPE")
    bytes32 public constant DEFAULT_PROOF_TYPE =
        0x8cdf3a8b78ebe00eba9fa85c0a9029fb57ab374b0492d22d68498e28e9e5b598;

    uint256 public constant MIN_ADMIN_THRESHOLD = 2;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice This chain's ID (storage instead of immutable for proxy)
    uint256 public chainId;

    /// @notice Role separation flag
    bool public rolesSeparated;

    /// @notice Proof submissions
    mapping(bytes32 => ProofSubmission) public proofs;

    /// @notice Batch submissions
    mapping(bytes32 => BatchSubmission) public batches;

    /// @notice Challenges
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Proof to batch mapping
    mapping(bytes32 => bytes32) public proofToBatch;

    /// @notice Verifier contracts per proof type
    mapping(bytes32 => ICCPHProofVerifier) public verifiers;

    /// @notice Global Verifier Registry
    address public verifierRegistry;

    /// @notice Supported chains
    mapping(uint256 => bool) public supportedChains;

    /// @notice Stored proof type per proof ID (SECURITY FIX M-10)
    mapping(bytes32 => bytes32) public proofProofType;

    /// @notice Challenge period duration
    uint256 public challengePeriod;

    /// @notice Minimum stake for relayers
    uint256 public minRelayerStake;

    /// @notice Minimum stake for challengers
    uint256 public minChallengerStake;

    /// @notice Total proofs submitted
    uint256 public totalProofs;

    /// @notice Total batches submitted
    uint256 public totalBatches;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Circuit breaker: max proofs per hour
    uint256 public maxProofsPerHour;

    /// @notice Circuit breaker: max value per hour
    uint256 public maxValuePerHour;

    /// @notice Hourly proof counter
    uint256 public hourlyProofCount;

    /// @notice Hourly value counter
    uint256 public hourlyValueRelayed;

    /// @notice Last reset timestamp
    uint256 public lastRateLimitReset;

    /// @notice Fee per proof submission
    uint256 public proofSubmissionFee;

    /// @notice Relayer stakes
    mapping(address => uint256) public relayerStakes;

    /// @notice Relayer successful submissions
    mapping(address => uint256) public relayerSuccessCount;

    /// @notice Relayer slashed count
    mapping(address => uint256) public relayerSlashCount;

    /// @notice Relayer pending proof count (TOCTOU protection)
    mapping(address => uint256) public relayerPendingProofs;

    /// @notice Claimable rewards for challengers
    mapping(address => uint256) public claimableRewards;

    /// @notice Trusted remote addresses per chain
    mapping(uint256 => address) public trustedRemotes;

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    // Events inherited from ICrossChainProofHubV3

    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

    // Errors inherited from ICrossChainProofHubV3

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract (replaces constructor)
    /// @param admin The initial admin address
    /**
     * @notice Initializes the operation
     * @param admin The admin bound
     */
    function initialize(address admin) public initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        chainId = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Add this chain as supported
        supportedChains[block.chainid] = true;

        // Set defaults
        challengePeriod = 1 hours;
        minRelayerStake = 0.1 ether;
        minChallengerStake = 0.05 ether;
        maxProofsPerHour = 1000;
        maxValuePerHour = 1000 ether;
        proofSubmissionFee = 0.001 ether;

        // Initialize SecurityModule defaults (field initializers don't execute through proxy)
        __initSecurityModule();

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          UPGRADE AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Authorize upgrade - only UPGRADER_ROLE can upgrade
    function _authorizeUpgrade(
        address /* newImplementation */
    ) internal override onlyRole(UPGRADER_ROLE) {
        uint256 oldVersion = contractVersion;
        contractVersion++;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    /*//////////////////////////////////////////////////////////////
                          ROLE SEPARATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Mark roles as properly separated
    /**
     * @notice Confirm role separation
     */
    function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(RELAYER_ROLE, msg.sender)) revert AdminNotAllowed();
        if (hasRole(CHALLENGER_ROLE, msg.sender)) revert AdminNotAllowed();
        rolesSeparated = true;
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER STAKE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits stake as a relayer
    /**
     * @notice Deposits stake
     */
    function depositStake() external payable nonReentrant {
        relayerStakes[msg.sender] += msg.value;
        emit RelayerStakeDeposited(msg.sender, msg.value);
    }

    /// @notice Withdraws relayer stake
    /// @param amount Amount to withdraw
    /**
     * @notice Withdraws stake
     * @param amount The amount to process
     */
    function withdrawStake(uint256 amount) external nonReentrant {
        if (relayerStakes[msg.sender] < amount)
            revert InsufficientStake(relayerStakes[msg.sender], amount);

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

    /// @notice Withdraws claimable rewards
    /// @param amount Amount to withdraw
    /**
     * @notice Withdraws rewards
     * @param amount The amount to process
     */
    function withdrawRewards(uint256 amount) external nonReentrant {
        if (claimableRewards[msg.sender] < amount)
            revert InsufficientStake(claimableRewards[msg.sender], amount);

        claimableRewards[msg.sender] -= amount;

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
    /**
     * @notice Submits proof
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param commitment The cryptographic commitment
     * @param sourceChainId The source chain identifier
     * @param destChainId The destination chain identifier
     * @return proofId The proof id
     */
    function submitProof(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId
    ) external payable nonReentrant whenNotPaused returns (bytes32 proofId) {
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

    /// @notice Submits a proof with instant verification
    /// @param proof The ZK proof bytes
    /// @param publicInputs The public inputs
    /// @param commitment Associated state commitment
    /// @param sourceChainId Origin chain
    /// @param destChainId Destination chain
    /// @param proofType The type of proof for verifier selection
    /// @return proofId The unique proof identifier
    /**
     * @notice Submits proof instant
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param commitment The cryptographic commitment
     * @param sourceChainId The source chain identifier
     * @param destChainId The destination chain identifier
     * @param proofType The proof type
     * @return proofId The proof id
     */
    function submitProofInstant(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        bytes32 proofType
    ) external payable nonReentrant whenNotPaused returns (bytes32 proofId) {
        if (!rolesSeparated) revert RolesNotSeparated();
        if (!hasRole(RELAYER_ROLE, msg.sender)) revert UnauthorizedRelayer();

        ICCPHProofVerifier verifier = verifiers[proofType];

        if (address(verifier) == address(0) && verifierRegistry != address(0)) {
            (bool regSuccess, bytes memory regData) = verifierRegistry
                .staticcall(
                    abi.encodeWithSignature("getVerifier(bytes32)", proofType)
                );
            if (regSuccess && regData.length == 32) {
                verifier = ICCPHProofVerifier(abi.decode(regData, (address)));
            }
        }

        if (address(verifier) == address(0)) {
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

        // SECURITY FIX M-10: Store proofType for challenge resolution
        proofProofType[proofId] = proofType;

        proofs[proofId].status = ProofStatus.Verified;
        proofs[proofId].challengeDeadline = uint64(block.timestamp);

        emit ProofVerified(proofId, ProofStatus.Verified);
    }

    /// @notice Submits a batch of proofs
    /// @param _proofs Array of proof data
    /// @param merkleRoot Merkle root of all proofs
    /// @return batchId The unique batch identifier
    /**
     * @notice Submits batch
     * @param _proofs The _proofs
     * @param merkleRoot The Merkle tree root
     * @return batchId The batch id
     */
    function submitBatch(
        BatchProofInput[] calldata _proofs,
        bytes32 merkleRoot
    ) external payable nonReentrant whenNotPaused returns (bytes32 batchId) {
        if (!rolesSeparated) revert RolesNotSeparated();
        if (!hasRole(RELAYER_ROLE, msg.sender)) revert UnauthorizedRelayer();

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

        _checkRateLimit(len);

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
    /**
     * @notice Challenge proof
     * @param proofId The proofId identifier
     * @param reason The reason string
     */
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
            deadline: uint64(block.timestamp + 1 hours),
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
    /// @param /* proofType */ Ignored - uses stored proof type for security
    /**
     * @notice Resolves challenge
     * @param proofId The proofId identifier
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     */
    function resolveChallenge(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 /* proofType */
    ) external nonReentrant {
        Challenge storage challenge = challenges[proofId];
        if (challenge.challenger == address(0))
            revert ChallengeNotFound(proofId);
        if (challenge.resolved) revert ChallengeNotFound(proofId);

        // SECURITY FIX M-10: Allow both challenger and relayer to resolve
        ProofSubmission storage submission = proofs[proofId];
        require(
            msg.sender == challenge.challenger ||
                msg.sender == submission.relayer,
            "Only challenger or relayer can resolve"
        );

        // SECURITY FIX M-10: Enforce challenge deadline
        require(
            block.timestamp <= challenge.deadline,
            "Challenge deadline passed, use expireChallenge"
        );

        bytes32 proofHash = keccak256(proof);
        bytes32 inputsHash = keccak256(publicInputs);

        bool proofValid = false;
        if (
            proofHash == submission.proofHash &&
            inputsHash == submission.publicInputsHash
        ) {
            // SECURITY FIX M-10: Use the proofType from submission, not from caller input
            // This prevents challenger from specifying wrong verifier type
            bytes32 submissionProofType = proofProofType[proofId];
            ICCPHProofVerifier verifier = verifiers[submissionProofType];

            if (
                address(verifier) == address(0) &&
                verifierRegistry != address(0)
            ) {
                (bool regSuccess, bytes memory regData) = verifierRegistry
                    .staticcall(
                        abi.encodeWithSignature(
                            "getVerifier(bytes32)",
                            submissionProofType
                        )
                    );
                if (regSuccess && regData.length == 32) {
                    verifier = ICCPHProofVerifier(
                        abi.decode(regData, (address))
                    );
                }
            }

            if (address(verifier) != address(0)) {
                proofValid = verifier.verifyProof(proof, publicInputs);
            }
        }

        challenge.resolved = true;

        if (proofValid) {
            challenge.challengerWon = false;
            submission.status = ProofStatus.Verified;

            uint256 reward = challenge.stake;
            relayerStakes[submission.relayer] += reward;

            emit ChallengeResolved(proofId, false, submission.relayer, reward);
            emit ProofVerified(proofId, ProofStatus.Verified);
        } else {
            challenge.challengerWon = true;
            submission.status = ProofStatus.Rejected;

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

            if (relayerPendingProofs[submission.relayer] > 0) {
                unchecked {
                    --relayerPendingProofs[submission.relayer];
                }
            }

            address challengerAddr = challenge.challenger;
            uint256 reward = challenge.stake + actualSlashed;
            claimableRewards[challengerAddr] += reward;

            emit ChallengeResolved(proofId, true, challengerAddr, reward);
            emit ProofRejected(proofId, challenge.reason);
        }
    }

    /// @notice Expires a stale challenge
    /// @param proofId The proof with a stale challenge
    /**
     * @notice Expire challenge
     * @param proofId The proofId identifier
     */
    function expireChallenge(
        bytes32 proofId
    ) external nonReentrant whenNotPaused {
        Challenge storage challenge = challenges[proofId];
        if (challenge.challenger == address(0))
            revert ChallengeNotFound(proofId);
        if (challenge.resolved) revert ChallengeNotFound(proofId);
        if (block.timestamp < challenge.deadline)
            revert ChallengePeriodNotOver(proofId, challenge.deadline);

        ProofSubmission storage submission = proofs[proofId];

        challenge.resolved = true;
        challenge.challengerWon = false;
        submission.status = ProofStatus.Verified;

        uint256 reward = challenge.stake;
        relayerStakes[submission.relayer] += reward;

        emit ChallengeResolved(proofId, false, submission.relayer, reward);
        emit ProofVerified(proofId, ProofStatus.Verified);
    }

    /*//////////////////////////////////////////////////////////////
                          FINALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Finalizes a proof after challenge period
    /// @param proofId The proof to finalize
    /**
     * @notice Finalizes proof
     * @param proofId The proofId identifier
     */
    function finalizeProof(
        bytes32 proofId
    ) external nonReentrant whenNotPaused {
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
        _checkRateLimit(1);

        uint256 requiredFee = instant
            ? proofSubmissionFee * 3
            : proofSubmissionFee;
        if (msg.value < requiredFee)
            revert InsufficientFee(msg.value, requiredFee);

        if (relayerStakes[msg.sender] < minRelayerStake)
            revert InsufficientStake(
                relayerStakes[msg.sender],
                minRelayerStake
            );

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
    /**
     * @notice Returns the proof
     * @param proofId The proofId identifier
     * @return submission The submission
     */
    function getProof(
        bytes32 proofId
    ) external view returns (ProofSubmission memory submission) {
        return proofs[proofId];
    }

    /// @notice Gets batch details
    /// @param batchId The batch ID
    /// @return batch The batch submission struct
    /**
     * @notice Returns the batch
     * @param batchId The batchId identifier
     * @return batch The batch
     */
    function getBatch(
        bytes32 batchId
    ) external view returns (BatchSubmission memory batch) {
        return batches[batchId];
    }

    /// @notice Gets challenge details
    /// @param proofId The proof ID
    /// @return The challenge struct
    /**
     * @notice Returns the challenge
     * @param proofId The proofId identifier
     * @return The Challenge struct for the given proof ID
     */
    function getChallenge(
        bytes32 proofId
    ) external view returns (Challenge memory) {
        return challenges[proofId];
    }

    /// @notice Checks if a proof is finalized
    /// @param proofId The proof ID
    /// @return finalized True if finalized
    /**
     * @notice Checks if proof finalized
     * @param proofId The proofId identifier
     * @return finalized The finalized
     */
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
    /**
     * @notice Returns the relayer stats
     * @param relayer The relayer address
     * @return stake The stake
     * @return successCount The success count
     * @return slashCount The slash count
     */
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
    /**
     * @notice Sets the verifier
     * @param proofType The proof type
     * @param _verifier The _verifier
     */
    function setVerifier(
        bytes32 proofType,
        address _verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        verifiers[proofType] = ICCPHProofVerifier(_verifier);
        emit VerifierSet(proofType, _verifier);
    }

    /// @notice Adds a supported chain
    /// @param chainId_ The chain ID to add
    /**
     * @notice Adds supported chain
     * @param chainId_ The chainId_ identifier
     */
    function addSupportedChain(
        uint256 chainId_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId_] = true;
        emit ChainAdded(chainId_);
    }

    /// @notice Removes a supported chain
    /// @param chainId_ The chain ID to remove
    /**
     * @notice Removes supported chain
     * @param chainId_ The chainId_ identifier
     */
    function removeSupportedChain(
        uint256 chainId_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId_] = false;
        emit ChainRemoved(chainId_);
    }

    /// @notice Sets trusted remote address
    /// @param chainId_ The chain ID
    /// @param remote The trusted remote address
    /**
     * @notice Sets the trusted remote
     * @param chainId_ The chainId_ identifier
     * @param remote The remote
     */
    function setTrustedRemote(
        uint256 chainId_,
        address remote
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId_ == 0) revert InvalidChainId(chainId_);
        if (remote == address(0)) revert ZeroAddress();
        trustedRemotes[chainId_] = remote;
        emit TrustedRemoteSet(chainId_, remote);
    }

    /// @notice Set global verifier registry
    /// @param _registry The VerifierRegistry address
    /**
     * @notice Sets the verifier registry
     * @param _registry The _registry
     */
    function setVerifierRegistry(
        address _registry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_registry == address(0)) revert ZeroAddress();
        address oldRegistry = verifierRegistry;
        verifierRegistry = _registry;
        emit VerifierRegistryUpdated(oldRegistry, _registry);
    }

    /// @notice Updates challenge period
    /// @param _period New period in seconds
    /**
     * @notice Sets the challenge period
     * @param _period The _period
     */
    function setChallengePeriod(
        uint256 _period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_period < 10 minutes) revert InvalidChallengePeriod();
        if (_period > 30 days) revert InvalidChallengePeriod();
        uint256 oldPeriod = challengePeriod;
        challengePeriod = _period;
        emit ChallengePeriodUpdated(oldPeriod, _period);
    }

    /// @notice Updates minimum stakes
    /// @param _relayerStake New relayer stake
    /// @param _challengerStake New challenger stake
    /**
     * @notice Sets the min stakes
     * @param _relayerStake The _relayer stake
     * @param _challengerStake The _challenger stake
     */
    function setMinStakes(
        uint256 _relayerStake,
        uint256 _challengerStake
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            _relayerStake > 0 && _challengerStake > 0,
            "Stakes must be non-zero"
        );
        minRelayerStake = _relayerStake;
        minChallengerStake = _challengerStake;
        emit MinStakesUpdated(_relayerStake, _challengerStake);
    }

    /// @notice Updates proof submission fee
    /// @param _fee New fee in wei
    /**
     * @notice Sets the proof submission fee
     * @param _fee The _fee
     */
    function setProofSubmissionFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldFee = proofSubmissionFee;
        proofSubmissionFee = _fee;
        emit ProofSubmissionFeeUpdated(oldFee, _fee);
    }

    /// @notice Updates circuit breaker limits
    /// @param _maxProofsPerHour Maximum proofs per hour
    /// @param _maxValuePerHour Maximum value per hour
    /**
     * @notice Sets the rate limits
     * @param _maxProofsPerHour The _maxProofsPerHour bound
     * @param _maxValuePerHour The _maxValuePerHour bound
     */
    function setRateLimits(
        uint256 _maxProofsPerHour,
        uint256 _maxValuePerHour
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxProofsPerHour = _maxProofsPerHour;
        maxValuePerHour = _maxValuePerHour;
        emit RateLimitsUpdated(_maxProofsPerHour, _maxValuePerHour);
    }

    /// @notice Withdraws accumulated fees
    /// @param to Recipient address
    // slither-disable-next-line arbitrary-send-eth
    /**
     * @notice Withdraws fees
     * @param to The destination address
     */
    function withdrawFees(
        address to
    ) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        if (amount == 0) revert WithdrawFailed();

        accumulatedFees = 0;

        (bool success, ) = to.call{value: amount}("");
        if (!success) revert WithdrawFailed();
    }

    /// @notice Pauses the contract
    /**
     * @notice Pauses the operation
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    /**
     * @notice Unpauses the operation
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============ Security Admin Functions ============

    /// @notice Configure SecurityModule rate limiting
    /// @param window Window duration in seconds
    /// @param maxActions Max actions per window
    /**
     * @notice Sets the security rate limit config
     * @param window The window
     * @param maxActions The maxActions bound
     */
    function setSecurityRateLimitConfig(
        uint256 window,
        uint256 maxActions
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setRateLimitConfig(window, maxActions);
    }

    /// @notice Configure SecurityModule circuit breaker
    /// @param threshold Volume threshold
    /// @param cooldown Cooldown period after trip
    /**
     * @notice Sets the security circuit breaker config
     * @param threshold The threshold value
     * @param cooldown The cooldown
     */
    function setSecurityCircuitBreakerConfig(
        uint256 threshold,
        uint256 cooldown
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setCircuitBreakerConfig(threshold, cooldown);
    }

    /// @notice Toggle SecurityModule features
    /// @param rateLimiting Enable rate limiting
    /// @param circuitBreakers Enable circuit breakers
    /// @param flashLoanGuard Enable flash loan guard
    /// @param withdrawalLimits Enable withdrawal limits
    /**
     * @notice Sets the security module features
     * @param rateLimiting The rate limiting
     * @param circuitBreakers The circuit breakers
     * @param flashLoanGuard The flash loan guard
     * @param withdrawalLimits The withdrawal limits
     */
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

    /// @notice Emergency reset circuit breaker
    /**
     * @notice Resets security circuit breaker
     */
    function resetSecurityCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        _resetCircuitBreaker();
    }

    /// @notice Allows contract to receive ETH
    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

interface ICCPHProofVerifier {
    /**
     * @notice Verifys proof
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return True if the proof is valid, false otherwise
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);
}

// CCPHBatchProofInput removed — using BatchProofInput from ICrossChainProofHubV3 to avoid overload clash
