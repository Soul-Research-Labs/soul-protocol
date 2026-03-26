// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SecurityModule} from "../security/SecurityModule.sol";
import {ICrossChainProofHubV3, BatchProofInput} from "../interfaces/ICrossChainProofHubV3.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

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
    ICrossChainProofHubV3,
    AccessControl,
    ReentrancyGuard,
    Pausable,
    SecurityModule
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

    /// @notice Monotonic nonce for unique proof ID generation
    uint256 private _proofNonce;

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

    /// @notice Maximum age of a proof before it is considered stale and cannot be finalized
    /// @dev Prevents very old proofs from being finalized after extended periods of inactivity
    uint256 public maxProofAge = 7 days;

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
    /// @dev Prevents accidental mainnet deployment with centralized control
    function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Verify critical roles are NOT held by admin
        if (hasRole(RELAYER_ROLE, msg.sender)) revert AdminNotAllowed();
        if (hasRole(CHALLENGER_ROLE, msg.sender)) revert AdminNotAllowed();
        rolesSeparated = true;
    }

    /// @dev Override _grantRole to enforce role separation after confirmation.
    ///      Prevents admin from granting RELAYER_ROLE or CHALLENGER_ROLE to themselves
    ///      after rolesSeparated is set, closing the post-confirmation bypass vector.
    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual override returns (bool) {
        if (rolesSeparated) {
            // Prevent any admin from also holding relayer or challenger roles
            if (
                (role == RELAYER_ROLE || role == CHALLENGER_ROLE) &&
                hasRole(DEFAULT_ADMIN_ROLE, account)
            ) {
                revert AdminNotAllowed();
            }
            // Prevent relayers/challengers from being granted admin
            if (role == DEFAULT_ADMIN_ROLE) {
                if (
                    hasRole(RELAYER_ROLE, account) ||
                    hasRole(CHALLENGER_ROLE, account)
                ) {
                    revert AdminNotAllowed();
                }
            }
        }
        return super._grantRole(role, account);
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER STAKE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits stake as a relayer
    /// @dev Uses nonReentrant for defense-in-depth against reentrancy attacks
    function depositStake() external payable nonReentrant {
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

    /// @notice Withdraws claimable rewards (for challengers who won disputes)
    /// @param amount Amount to withdraw
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
        // CRITICAL FIX: Add access control - was missing, allowing anyone to submit
        if (!rolesSeparated) revert RolesNotSeparated();
        if (!hasRole(RELAYER_ROLE, msg.sender)) revert UnauthorizedRelayer();

        // SECURITY FIX M-10: Validate proof and publicInputs length before verifier call
        if (proof.length < 32) revert InvalidProof();
        if (publicInputs.length < 32) revert InvalidProof();

        // Verify the proof immediately — uses shared verifier resolution
        IProofVerifier verifier = _resolveVerifier(proofType);

        // H-1 FIX: Do not fall back to default verifier — respect _resolveVerifier's security design
        if (address(verifier) == address(0)) revert VerifierNotSet(proofType);

        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // SECURITY FIX H-6: Bind public inputs to submission parameters.
        // Verify that the publicInputs encode the expected commitment and chain IDs
        // to prevent proof replay across different submissions.
        bytes32 inputBinding = keccak256(
            abi.encodePacked(commitment, sourceChainId, destChainId)
        );
        // The first 32 bytes of publicInputs must contain the binding hash
        // This ensures the verified proof corresponds to the stated parameters
        if (publicInputs.length >= 32) {
            bytes32 encodedBinding;
            bytes calldata pi = publicInputs;
            assembly {
                encodedBinding := calldataload(pi.offset)
            }
            if (encodedBinding != inputBinding) revert ProofBindingMismatch();
        }

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
        // CRITICAL FIX: Add access control - was missing, allowing anyone to submit batches
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

        // FIX: Enforce rate limits for batch
        _checkRateLimit(len, msg.value);

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
        uint256 stakePerProof = minRelayerStake / len;
        for (uint256 i = 0; i < len; ) {
            _registerBatchProof(_proofs[i], batchId, stakePerProof);
            unchecked {
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
    /// @dev SECURITY: Only the challenger can call this to prevent front-running
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

        // SECURITY FIX: Only the original challenger can resolve to prevent front-running
        // This prevents operators/relayers from submitting correct proof data to make relayer win
        require(
            msg.sender == challenge.challenger,
            "Only challenger can resolve"
        );

        ProofSubmission storage submission = proofs[proofId];

        // Verify proof — delegated to helper to reduce stack depth
        bool proofValid = _verifyChallengeProof(
            submission,
            proof,
            publicInputs,
            proofType
        );

        challenge.resolved = true;

        if (proofValid) {
            _resolveChallengeRelayerWins(proofId, challenge, submission);
        } else {
            _resolveChallengeChallengerWins(proofId, challenge, submission);
        }
    }

    /// @dev Registers a single proof within a batch submission. Extracted from
    ///      submitBatch loop body to avoid stack depth issues.
    function _registerBatchProof(
        BatchProofInput calldata input,
        bytes32 batchId,
        uint256 stakePerProof
    ) internal {
        bytes32 proofId = keccak256(
            abi.encodePacked(
                input.proofHash,
                input.commitment,
                input.sourceChainId,
                input.destChainId,
                _proofNonce++
            )
        );

        proofs[proofId] = ProofSubmission({
            proofHash: input.proofHash,
            publicInputsHash: input.publicInputsHash,
            commitment: input.commitment,
            sourceChainId: input.sourceChainId,
            destChainId: input.destChainId,
            submittedAt: uint64(block.timestamp),
            challengeDeadline: uint64(block.timestamp + challengePeriod),
            relayer: msg.sender,
            status: ProofStatus.Pending,
            stake: stakePerProof
        });

        proofToBatch[proofId] = batchId;
        unchecked {
            ++totalProofs;
        }
    }

    /// @dev Verifies the proof data matches the submission and validates via the verifier.
    ///      Extracted from resolveChallenge to reduce stack depth.
    function _verifyChallengeProof(
        ProofSubmission storage submission,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 proofType
    ) internal view returns (bool) {
        bytes32 proofHash = keccak256(proof);
        bytes32 inputsHash = keccak256(publicInputs);

        // SECURITY FIX C1: Revert on hash mismatch instead of returning false.
        // Returning false would let a malicious challenger submit garbage data
        // (hash mismatch → false → challenger wins), exploiting the system.
        // By reverting, the challenger must provide the original proof data
        // for on-chain verification.
        require(
            proofHash == submission.proofHash &&
                inputsHash == submission.publicInputsHash,
            "Proof data mismatch"
        );

        // Resolve verifier — _resolveVerifier reverts if no verifier is found
        IProofVerifier verifier = _resolveVerifier(proofType);

        return verifier.verifyProof(proof, publicInputs);
    }

    /// @dev Resolves the proof verifier for a given proof type, checking local mapping
    ///      first, then the verifier registry.
    function _resolveVerifier(
        bytes32 proofType
    ) internal view returns (IProofVerifier verifier) {
        verifier = verifiers[proofType];

        // If specific verifier not found, check the registry as a second source
        if (address(verifier) == address(0) && verifierRegistry != address(0)) {
            (bool regSuccess, bytes memory regData) = verifierRegistry
                .staticcall(
                    abi.encodeWithSignature("getVerifier(bytes32)", proofType)
                );
            if (regSuccess && regData.length == 32) {
                verifier = IProofVerifier(abi.decode(regData, (address)));
            }
        }

        // SECURITY FIX: Revert explicitly if no verifier found instead of returning address(0).
        // Callers should not need to check — a zero-address verifier leads to silent verification skip.
        if (address(verifier) == address(0)) revert VerifierNotSet(proofType);
    }

    /// @dev Handles challenge resolution when the relayer wins (valid proof).
    function _resolveChallengeRelayerWins(
        bytes32 proofId,
        Challenge storage challenge,
        ProofSubmission storage submission
    ) internal {
        challenge.challengerWon = false;
        submission.status = ProofStatus.Verified;

        // Reward relayer with challenger's stake
        uint256 reward = challenge.stake;
        relayerStakes[submission.relayer] += reward;
        // NOTE: Do NOT increment relayerSuccessCount here - finalizeProof handles it
        // to avoid double-counting when proof moves from Verified -> Finalized

        emit ChallengeResolved(proofId, false, submission.relayer, reward);
        emit ProofVerified(proofId, ProofStatus.Verified);
    }

    /// @dev Handles challenge resolution when the challenger wins (invalid proof).
    function _resolveChallengeChallengerWins(
        bytes32 proofId,
        Challenge storage challenge,
        ProofSubmission storage submission
    ) internal {
        challenge.challengerWon = true;
        submission.status = ProofStatus.Rejected;

        // Slash relayer and reward challenger
        uint256 slashAmount = submission.stake;
        uint256 actualSlashed;

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

    /// @notice Expires a stale challenge after its deadline, resolving in the relayer's favor
    /// @dev Callable by anyone after the challenge deadline passes without resolution
    /// @param proofId The proof with a stale challenge
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

    /// @notice Finalizes a proof after challenge period
    /// @param proofId The proof to finalize
    function finalizeProof(
        bytes32 proofId
    ) external nonReentrant whenNotPaused {
        ProofSubmission storage submission = proofs[proofId];
        if (submission.relayer == address(0)) revert ProofNotFound(proofId);

        // SECURITY FIX: Reject stale proofs that have been sitting unfinalized too long.
        // This prevents very old proofs from being finalized after extended inactivity,
        // which could reference outdated state or expired commitments.
        if (block.timestamp > submission.submittedAt + maxProofAge) {
            revert ProofTooStale(proofId, submission.submittedAt);
        }

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
    function _checkRateLimit(uint256 count, uint256 value) internal {
        if (block.timestamp >= lastRateLimitReset + 1 hours) {
            hourlyProofCount = 0;
            hourlyValueRelayed = 0;
            lastRateLimitReset = block.timestamp;
        }

        if (hourlyProofCount + count > maxProofsPerHour) {
            revert ProofRateLimitExceeded();
        }
        if (hourlyValueRelayed + value > maxValuePerHour) {
            revert ValueRateLimitExceeded();
        }
        // SECURITY FIX L-5: Use checked arithmetic for rate limit counters
        hourlyProofCount += count;
        hourlyValueRelayed += value;
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
        _checkRateLimit(1, msg.value);

        // Phase 1: Validate fee and stake (scoped to free locals)
        {
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
        }

        // Validate chains
        if (!supportedChains[sourceChainId])
            revert UnsupportedChain(sourceChainId);
        if (!supportedChains[destChainId]) revert UnsupportedChain(destChainId);

        // Phase 2: Compute hashes and store proof (scoped)
        {
            bytes32 proofHash = keccak256(proof);
            bytes32 publicInputsHash = keccak256(publicInputs);

            proofId = keccak256(
                abi.encodePacked(
                    proofHash,
                    commitment,
                    sourceChainId,
                    destChainId,
                    _proofNonce++
                )
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
        }

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
        if (_verifier == address(0)) revert ZeroAddress();
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

    /// @notice Sets the trusted remote contract address for a given chain
    /// @param chainId The chain ID to set the trusted remote for
    /// @param remote The trusted remote contract address on the target chain
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

    /// @notice Updates challenge period
    /// @param _period New period in seconds
    /// @dev M-8: Added minimum period validation and event emission
    function setChallengePeriod(
        uint256 _period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_period < 10 minutes) revert InvalidChallengePeriod();
        uint256 oldPeriod = challengePeriod;
        challengePeriod = _period;
        emit ChallengePeriodUpdated(oldPeriod, _period);
    }

    /// @notice Updates minimum stakes
    /// @param _relayerStake New relayer stake
    /// @param _challengerStake New challenger stake
    /// @dev M-9: Added event emission
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
    function setProofSubmissionFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldFee = proofSubmissionFee;
        proofSubmissionFee = _fee;
        emit ProofSubmissionFeeUpdated(oldFee, _fee);
    }

    /// @notice Updates circuit breaker limits (admin only)
    /// @param _maxProofsPerHour Maximum proofs per hour
    /// @param _maxValuePerHour Maximum value per hour
    /// @dev M-24: Added event emission
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
