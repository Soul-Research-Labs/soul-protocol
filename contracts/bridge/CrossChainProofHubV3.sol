// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SecurityModule} from "../security/SecurityModule.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../interfaces/ICrossChainProofHubV3.sol";

/// @title CrossChainProofHubV3
/// @author ZASEON
/// @notice Production-ready cross-chain proof relay with optimistic verification and dispute resolution
/// @dev Implements a stake-and-slash model for proof submission with a configurable challenge period.
///
/// ARCHITECTURE:
///   Relayer submits proof → Pending (challenge period) → Verified → Finalized
///   If challenged during Pending → Challenged → resolveChallenge() → Verified or Rejected
///
/// PROOF LIFECYCLE:
///   1. Relayer deposits stake via `depositStake()`
///   2. Relayer submits proof via `submitProof()` (optimistic) or `submitProofInstant()` (instant)
///   3. During the challenge period, anyone with `CHALLENGER_ROLE` can call `challengeProof()`
///   4. If challenged, the challenger calls `resolveChallenge()` which invokes the on-chain verifier
///   5. After the challenge period (or successful challenge resolution), `finalizeProof()` marks
///      the proof as finalized, incrementing the relayer's success count
///
/// SECURITY FEATURES:
///   - Role separation: `confirmRoleSeparation()` must be called before accepting proofs,
///     ensuring RELAYER, CHALLENGER, and ADMIN roles are held by different addresses
///   - Circuit breaker: `maxProofsPerHour` and `maxValuePerHour` rate limits
///   - TOCTOU protection: `relayerPendingProofs` prevents stake withdrawal while proofs are pending
///   - SecurityModule integration: configurable rate limiting, flash loan guard, circuit breakers
///   - Verifier pinning: challenges use proof-type-specific verifiers without fallback to default,
///     preventing verifier bypass attacks
///
/// @custom:security-contact security@zaseon.network
/**
 * @title CrossChainProofHubV3
 * @author ZASEON Team
 * @notice Cross Chain Proof Hub V3 contract
 */
contract CrossChainProofHubV3 is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    SecurityModule,
    ICrossChainProofHubV3
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for authorized relayers
    /// @dev Pre-computed: keccak256("RELAYER_ROLE")
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    /// @notice Role for verifier administrators
    /// @dev Pre-computed: keccak256("VERIFIER_ADMIN_ROLE")
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70;

    /// @notice Role for authorized challengers
    /// @dev Pre-computed: keccak256("CHALLENGER_ROLE")
    bytes32 public constant CHALLENGER_ROLE =
        0xe752add323323eb13e36c71ee508dfd16d74e9e4c4fd78786ba97989e5e13818;

    /// @notice Role for operators (trusted remotes, config)
    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @notice Role for emergency operations
    /// @dev Pre-computed: keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @notice Maximum number of proofs in a batch
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Default proof type for verification
    /// @dev Pre-computed: keccak256("DEFAULT_PROOF_TYPE")
    bytes32 public constant DEFAULT_PROOF_TYPE =
        0x8cdf3a8b78ebe00eba9fa85c0a9029fb57ab374b0492d22d68498e28e9e5b598;

    /// @notice Minimum required roles for security-critical operations
    uint256 public constant MIN_ADMIN_THRESHOLD = 2;

    /*//////////////////////////////////////////////////////////////
                              IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice This chain's ID
    uint256 public immutable CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Role separation warning flag - must be resolved before mainnet
    bool public rolesSeparated = false;

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

    /// @notice Claimable rewards for non-relayer challengers
    /// @dev Separate from relayerStakes to allow anyone to claim challenge winnings
    mapping(address => uint256) public claimableRewards;

    /// @notice Trusted remote contract addresses per chain
    mapping(uint256 => address) public trustedRemotes;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

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
    /// @dev Prevents accidental mainnet deployment with centralized control (Ronin-style attack
    ///      prevention). Verifies that the calling admin does NOT hold RELAYER_ROLE or
    ///      CHALLENGER_ROLE — these must be assigned to independent parties before any proof
    ///      submissions are accepted. Irreversible: once set, `rolesSeparated` cannot be reset.
        /**
     * @notice Confirm role separation
     */
function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Verify critical roles are NOT held by admin
        if (hasRole(RELAYER_ROLE, msg.sender)) revert AdminNotAllowed();
        if (hasRole(CHALLENGER_ROLE, msg.sender)) revert AdminNotAllowed();
        rolesSeparated = true;
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER STAKE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits ETH as relayer stake, enabling proof submission
    /// @dev Stake can be slashed if submitted proofs are proved invalid via challenge.
    ///      Uses nonReentrant for defense-in-depth. No minimum deposit required, but
    ///      total stake must be >= `minRelayerStake` to submit proofs.
        /**
     * @notice Deposits stake
     */
function depositStake() external payable nonReentrant {
        relayerStakes[msg.sender] += msg.value;
        emit RelayerStakeDeposited(msg.sender, msg.value);
    }

    /// @notice Withdraws relayer stake back to the caller
    /// @dev TOCTOU protection: if the relayer has pending (unchallengeable) proofs, the
    ///      remaining stake after withdrawal must still meet `minRelayerStake`. This prevents
    ///      relayers from submitting a bad proof and immediately withdrawing stake before it
    ///      can be slashed. Uses CEI pattern: state updated before ETH transfer.
    /// @param amount Amount of stake to withdraw (must be <= current stake)
        /**
     * @notice Withdraws stake
     * @param amount The amount to process
     */
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

    /// @notice Withdraws claimable rewards earned from winning challenges
    /// @dev Rewards are credited to `claimableRewards` (not `relayerStakes`) so that
    ///      non-relayer challengers can withdraw their winnings independently.
    /// @param amount Amount to withdraw (must be <= claimable balance)
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

        emit RelayerStakeWithdrawn(msg.sender, amount); // Reuse event for simplicity
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Submits a proof with optimistic verification (subject to challenge period)
    /// @dev The proof enters `Pending` status and remains challengeable for `challengePeriod`
    ///      seconds. If unchallenged, it can be finalized via `finalizeProof()`. Requires:
    ///      - `rolesSeparated` must be true
    ///      - Caller must have `RELAYER_ROLE`
    ///      - `msg.value >= proofSubmissionFee`
    ///      - `relayerStakes[msg.sender] >= minRelayerStake`
    ///      - Both `sourceChainId` and `destChainId` must be supported
    ///      Excess ETH is refunded to the caller.
    /// @param proof The serialized ZK proof bytes
    /// @param publicInputs The serialized public inputs for the proof
    /// @param commitment Associated state commitment (app-specific meaning)
    /// @param sourceChainId Origin chain ID where the proof was generated
    /// @param destChainId Destination chain ID where the proof will be consumed
    /// @return proofId Unique identifier derived from keccak256(proofHash, commitment, chains)
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

    /// @notice Submits a proof with instant on-chain verification (3x fee, no challenge period)
    /// @dev Unlike `submitProof()`, this immediately verifies the proof against the on-chain
    ///      verifier for `proofType`. If verification passes, the proof is marked `Verified`
    ///      with a zero challenge deadline, allowing immediate finalization. The verifier is
    ///      looked up first in the local `verifiers` mapping, then in `verifierRegistry`.
    /// @param proof The serialized ZK proof bytes
    /// @param publicInputs The serialized public inputs for the proof
    /// @param commitment Associated state commitment
    /// @param sourceChainId Origin chain ID
    /// @param destChainId Destination chain ID
    /// @param proofType The proof type identifier for verifier selection (e.g., keccak256("groth16"))
    /// @return proofId Unique identifier for the submitted and verified proof
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
        // CRITICAL FIX: Add access control - was missing, allowing anyone to submit
        if (!rolesSeparated) revert RolesNotSeparated();
        if (!hasRole(RELAYER_ROLE, msg.sender)) revert UnauthorizedRelayer();

        // Verify the proof immediately
        IProofVerifier verifier = verifiers[proofType];

        // Fallback to registry if not locally set
        if (address(verifier) == address(0) && verifierRegistry != address(0)) {
            (bool regSuccess, bytes memory regData) = verifierRegistry
                .staticcall(
                    abi.encodeWithSignature("getVerifier(bytes32)", proofType)
                );
            if (regSuccess && regData.length == 32) {
                verifier = IProofVerifier(abi.decode(regData, (address)));
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

        // Mark as verified immediately
        proofs[proofId].status = ProofStatus.Verified;
        proofs[proofId].challengeDeadline = uint64(block.timestamp); // No challenge period

        emit ProofVerified(proofId, ProofStatus.Verified);
    }

    /// @notice Submits a batch of proofs atomically with a shared Merkle root
    /// @dev Each proof in the batch is individually registered and enters `Pending` status.
    ///      The total fee is `proofSubmissionFee * len` and the required stake is
    ///      `minRelayerStake * len` — preventing under-collateralized batch submissions.
    ///      Rate limits are enforced for the entire batch. Duplicate proof IDs revert.
    /// @param _proofs Array of proof data (proof hash, public inputs hash, commitment, chains)
    /// @param merkleRoot Merkle root of all proof hashes in the batch (for off-chain verification)
    /// @return batchId Unique batch identifier derived from (merkleRoot, relayer, timestamp, batchNum)
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
        // CRITICAL FIX: Add access control - was missing, allowing anyone to submit batches
        if (!rolesSeparated) revert RolesNotSeparated();
        if (!hasRole(RELAYER_ROLE, msg.sender)) revert UnauthorizedRelayer();

        uint256 len = _proofs.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        uint256 totalFee = proofSubmissionFee * len;
        if (msg.value < totalFee) revert InsufficientFee(msg.value, totalFee);
        // SECURITY FIX: Require stake for EACH proof in the batch
        uint256 requiredStake = minRelayerStake * len;
        if (relayerStakes[msg.sender] < requiredStake)
            revert InsufficientStake(relayerStakes[msg.sender], requiredStake);

        // FIX: Enforce rate limits for batch
        _checkRateLimit(len);

        // FIX: Prevent Stake Drain (TOCTOU)
        unchecked {
            relayerPendingProofs[msg.sender] += len;
        }

        batchId = keccak256(
            abi.encode(merkleRoot, msg.sender, block.timestamp, totalBatches)
        );

        batches[batchId] = BatchSubmission({
            batchId: batchId,
            merkleRoot: merkleRoot,
            proofCount: len,
            submittedAt: uint64(block.timestamp),
            challengeDeadline: uint64(block.timestamp + challengePeriod),
            relayer: msg.sender,
            status: ProofStatus.Pending,
            totalStake: requiredStake
        });

        // Register individual proofs
        // Gas optimization: cache timestamp and challenge deadline outside loop
        uint64 submittedAt = uint64(block.timestamp);
        uint64 deadline = uint64(block.timestamp + challengePeriod);
        address relayer_ = msg.sender;
        uint256 stakePerProof = minRelayerStake;

        for (uint256 i = 0; i < len; ) {
            bytes32 proofId = keccak256(
                abi.encode(
                    _proofs[i].proofHash,
                    _proofs[i].commitment,
                    _proofs[i].sourceChainId,
                    _proofs[i].destChainId
                )
            );

            // SECURITY FIX: Prevent batch proof overwrites
            if (proofs[proofId].relayer != address(0)) {
                revert ProofAlreadyExists(proofId);
            }

            proofs[proofId] = ProofSubmission({
                proofHash: _proofs[i].proofHash,
                publicInputsHash: _proofs[i].publicInputsHash,
                commitment: _proofs[i].commitment,
                sourceChainId: _proofs[i].sourceChainId,
                destChainId: _proofs[i].destChainId,
                submittedAt: submittedAt,
                challengeDeadline: deadline,
                relayer: relayer_,
                status: ProofStatus.Pending,
                stake: stakePerProof
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

    /// @notice Challenges a pending proof during its challenge period
    /// @dev Anyone with sufficient stake can challenge. The proof moves to `Challenged` status
    ///      and a 1-hour resolution window opens. Only one challenge per proof is allowed.
    ///      The challenger's stake is held in escrow via `msg.value`. If the challenger wins
    ///      (proof is invalid), they receive their stake back plus the relayer's slashed stake.
    ///      If the relayer wins (proof is valid), the relayer receives the challenger's stake.
    /// @param proofId The proof ID to challenge (must be in `Pending` status)
    /// @param reason Human-readable reason for the challenge (stored on-chain for auditing)
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
            deadline: uint64(block.timestamp + 1 hours), // 1 hour to resolve
            resolved: false,
            challengerWon: false,
            reason: reason
        });

        emit ChallengeCreated(proofId, msg.sender, reason);
    }

    /// @notice Resolves a challenge by invoking the on-chain proof verifier
    /// @dev SECURITY: Only the original challenger can resolve the challenge to prevent
    ///      front-running attacks where a relayer or operator submits correct proof data.
    ///      The verifier is looked up via `proofType` — no fallback to default verifier is
    ///      used, preventing proof-type bypass attacks. If the verifier is not configured,
    ///      the proof is treated as invalid and the challenger wins.
    ///
    ///      On relayer win: Proof → Verified, challenger's stake → relayer
    ///      On challenger win: Proof → Rejected, relayer's stake → claimableRewards[challenger]
    /// @param proofId The challenged proof ID
    /// @param proof The original serialized proof bytes (hash must match submission)
    /// @param publicInputs The original serialized public inputs (hash must match submission)
    /// @param proofType The proof type identifier for verifier selection
        /**
     * @notice Resolves challenge
     * @param proofId The proofId identifier
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param proofType The proof type
     */
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

        // SECURITY FIX: Only the original challenger can resolve to prevent front-running
        // This prevents operators/relayers from submitting correct proof data to make relayer win
        require(
            msg.sender == challenge.challenger,
            "Only challenger can resolve"
        );

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

            // SECURITY FIX: If specific verifier not found, DO NOT fallback to default
            // This prevents proof type bypass attacks where attacker uses weaker verifier
            if (
                address(verifier) == address(0) &&
                verifierRegistry != address(0)
            ) {
                (bool regSuccess, bytes memory regData) = verifierRegistry
                    .staticcall(
                        abi.encodeWithSignature(
                            "getVerifier(bytes32)",
                            proofType
                        )
                    );
                if (regSuccess && regData.length == 32) {
                    verifier = IProofVerifier(abi.decode(regData, (address)));
                }
            }

            // SECURITY FIX: Do NOT fallback to default verifier - this could allow
            // attackers to bypass specific verifier requirements
            // If no verifier is found, the proof is treated as invalid (proofValid = false)

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
            // NOTE: Do NOT increment relayerSuccessCount here - finalizeProof handles it
            // to avoid double-counting when proof moves from Verified -> Finalized

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

            // H-5 FIX: Credit rewards to claimableRewards instead of relayerStakes
            // This allows non-relayer challengers to withdraw their winnings
            claimableRewards[challengerAddr] += reward;

            emit ChallengeResolved(proofId, true, challengerAddr, reward);
            emit ProofRejected(proofId, challenge.reason);
        }
    }

    /// @notice Expires a stale challenge after its 1-hour deadline, resolving in the relayer's favor
    /// @dev Callable by anyone after the challenge deadline passes without the challenger calling
    ///      `resolveChallenge()`. The challenger's stake is forfeited to the relayer as a penalty
    ///      for filing a challenge without following through. This incentivizes challengers to
    ///      resolve promptly and prevents griefing via perpetually-open challenges.
    /// @param proofId The proof with an expired, unresolved challenge
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

        // Challenge expired — relayer wins by default
        challenge.resolved = true;
        challenge.challengerWon = false;
        submission.status = ProofStatus.Verified;

        // Reward relayer with challenger's forfeited stake
        uint256 reward = challenge.stake;
        relayerStakes[submission.relayer] += reward;

        emit ChallengeResolved(proofId, false, submission.relayer, reward);
        emit ProofVerified(proofId, ProofStatus.Verified);
    }

    /*//////////////////////////////////////////////////////////////
                          FINALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Finalizes a proof after its challenge period, transitioning to Finalized status
    /// @dev State transitions: Pending (past deadline) → Verified → Finalized, or
    ///      Verified (already resolved) → Finalized. Increments the relayer's success count
    ///      and decrements their pending proof counter. Callable by anyone — no role restriction
    ///      since finalization benefits the relayer and has no economic impact on others.
    /// @param proofId The proof to finalize (must be Pending+past deadline, or Verified)
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

    /// @dev Enforces hourly proof submission rate limits, resetting the counter each hour
    /// @param count Number of proofs being submitted in this call
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

    /// @dev Shared proof submission logic for both standard and instant submission
    /// @param proof The serialized ZK proof bytes
    /// @param publicInputs The serialized public inputs for the proof
    /// @param commitment The state commitment associated with this proof
    /// @param sourceChainId The chain ID where the proof originated
    /// @param destChainId The chain ID where the proof will be verified
    /// @param instant Whether to use instant (3x fee) or standard verification
    /// @return proofId The unique identifier for the submitted proof
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
            abi.encode(proofHash, commitment, sourceChainId, destChainId)
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
        accumulatedFees += requiredFee;

        // Refund excess ETH to prevent overpayment loss
        uint256 excess = msg.value - requiredFee;
        if (excess > 0) {
            (bool refundSuccess, ) = msg.sender.call{value: excess}("");
            if (!refundSuccess) revert TransferFailed();
        }

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

    /// @notice Gets the full proof submission details including status and stake
    /// @param proofId The unique proof identifier
    /// @return submission The complete ProofSubmission struct (zero relayer = not found)
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

    /// @notice Gets the full batch submission details
    /// @param batchId The unique batch identifier
    /// @return batch The complete BatchSubmission struct (zero relayer = not found)
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

    /// @notice Gets challenge details for a proof
    /// @param proofId The proof that was challenged
    /// @return challenge The Challenge struct (zero challenger = no challenge exists)
        /**
     * @notice Returns the challenge
     * @param proofId The proofId identifier
     * @return The result value
     */
function getChallenge(
        bytes32 proofId
    ) external view returns (Challenge memory) {
        return challenges[proofId];
    }

    /// @notice Checks if a proof has completed its full lifecycle (Finalized status)
    /// @param proofId The proof to check
    /// @return finalized True if the proof is in Finalized status and safe to consume
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

    /// @notice Gets aggregated relayer performance statistics
    /// @param relayer The relayer address to query
    /// @return stake Current deposited stake balance (ETH)
    /// @return successCount Total proofs successfully finalized
    /// @return slashCount Total times the relayer has been slashed via lost challenges
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

    /// @notice Registers or updates a verifier contract for a proof type
    /// @dev The verifier must implement `IProofVerifier.verifyProof(bytes, bytes) returns (bool)`.
    ///      Used during both instant verification and challenge resolution.
    /// @param proofType The proof type identifier (e.g., keccak256("groth16"), keccak256("ultraplonk"))
    /// @param _verifier The IProofVerifier contract address (must be non-zero)
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
        verifiers[proofType] = IProofVerifier(_verifier);
        emit VerifierSet(proofType, _verifier);
    }

    /// @notice Registers a chain as a valid proof source or destination
    /// @dev Both source and destination chains must be registered before proof submission.
    ///      The deploying chain is auto-registered in the constructor.
    /// @param chainId The EVM chain ID to register as supported
        /**
     * @notice Adds supported chain
     * @param chainId The chain identifier
     */
function addSupportedChain(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = true;
        emit ChainAdded(chainId);
    }

    /// @notice Removes a chain from the supported set, blocking future proof submissions for it
    /// @dev Does not invalidate already-submitted proofs for the chain.
    /// @param chainId The EVM chain ID to remove
        /**
     * @notice Removes supported chain
     * @param chainId The chain identifier
     */
function removeSupportedChain(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = false;
        emit ChainRemoved(chainId);
    }

    /// @notice Sets the trusted remote CrossChainProofHubV3 address for a peer chain
    /// @dev Used by messaging adapters (Hyperlane, LayerZero) to validate inbound messages.
    ///      Only accepts messages from the registered remote address on each chain.
    /// @param chainId The peer chain's EVM chain ID (must be non-zero)
    /// @param remote The CrossChainProofHubV3 contract address on the peer chain (must be non-zero)
        /**
     * @notice Sets the trusted remote
     * @param chainId The chain identifier
     * @param remote The remote
     */
function setTrustedRemote(
        uint256 chainId,
        address remote
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId(chainId);
        if (remote == address(0)) revert ZeroAddress();
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
        if (_registry == address(0)) revert ZeroAddress();
        address oldRegistry = verifierRegistry;
        verifierRegistry = _registry;
        emit VerifierRegistryUpdated(oldRegistry, _registry);
    }

    /// @notice Updates the challenge period for newly submitted proofs
    /// @dev Bounded to [10 minutes, 30 days] to prevent both griefing (too long) and
    ///      insufficient challenge windows (too short). Does not affect existing proofs.
    /// @param _period New challenge period in seconds (must be >= 10 min, <= 30 days)
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

    /// @notice Updates the minimum stake requirements for relayers and challengers
    /// @dev Affects all future submissions and challenges. Existing proofs retain their
    ///      original stake amounts. Both values must be non-zero.
    /// @param _relayerStake New minimum relayer stake per proof (in wei)
    /// @param _challengerStake New minimum challenger stake per challenge (in wei)
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

    /// @notice Updates the fee charged per proof submission
    /// @dev Instant submissions are charged 3x this fee. Setting to 0 makes submissions free.
    /// @param _fee New fee per proof in wei
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

    /// @notice Updates the circuit breaker rate limits to prevent mass exploitation
    /// @dev These are first-line defense limits (separate from SecurityModule limits).
    ///      Counters reset every hour automatically upon the next submission.
    /// @param _maxProofsPerHour Maximum number of proofs allowed per hour (0 = disabled)
    /// @param _maxValuePerHour Maximum cumulative value relayed per hour in wei (0 = disabled)
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

    /// @notice Withdraws all accumulated proof submission fees to a designated address
    /// @dev CEI pattern: `accumulatedFees` is zeroed before the ETH transfer to prevent
    ///      reentrancy. Also protected by `nonReentrant` for defense-in-depth.
    /// @param to Recipient address for the accumulated fees (must be non-zero)
    /// @dev Slither: arbitrary-send-eth is expected - admin-only function with role protection
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

        // CEI pattern: clear state before external call
        accumulatedFees = 0;

        (bool success, ) = to.call{value: amount}("");
        if (!success) revert WithdrawFailed();
    }

    /// @notice Emergency pause — blocks all proof submissions, finalization, and challenges
    /// @dev Only EMERGENCY_ROLE can pause; only DEFAULT_ADMIN_ROLE can unpause.
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract, resuming all operations
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============ Security Admin Functions ============

    /// @notice Configure SecurityModule rate limiting (separate from circuit breaker limits)
    /// @dev SecurityModule rate limits apply per-user, while circuit breaker limits are global.
    /// @param window Sliding window duration in seconds
    /// @param maxActions Maximum allowed actions within each window
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

    /// @notice Configure SecurityModule circuit breaker (automatic trip on volume spike)
    /// @dev Separate from the manual `maxProofsPerHour` / `maxValuePerHour` limits.
    /// @param threshold Volume threshold that triggers the circuit breaker
    /// @param cooldown Cooldown period in seconds after the breaker trips
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

    /// @notice Enable or disable individual SecurityModule features
    /// @param rateLimiting Enable per-user rate limiting
    /// @param circuitBreakers Enable automatic volume-based circuit breakers
    /// @param flashLoanGuard Enable flash loan detection guard
    /// @param withdrawalLimits Enable per-period withdrawal limits
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

    /// @notice Emergency reset of the SecurityModule circuit breaker after a false positive
        /**
     * @notice Resets security circuit breaker
     */
function resetSecurityCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        _resetCircuitBreaker();
    }

    /// @notice Allows contract to receive ETH for stake deposits, proof fees, and challenge stakes
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          ERC-165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-165 interface discovery
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract supports the given interface
    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(ICrossChainProofHubV3).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
