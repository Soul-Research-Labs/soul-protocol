// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title CrossChainProofHubV3
/// @author PIL Protocol
/// @notice Production-ready cross-chain proof relay with optimistic verification and dispute resolution
/// @dev Implements batching, challenge periods, and gas-efficient proof storage
contract CrossChainProofHubV3 is AccessControl, ReentrancyGuard, Pausable {

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    enum ProofStatus {
        Pending,      // Submitted, in challenge period
        Verified,     // Challenge period passed or instant verified
        Challenged,   // Under dispute
        Rejected,     // Failed verification
        Finalized     // Executed on destination
    }

    /// @notice Proof submission structure
    struct ProofSubmission {
        bytes32 proofHash;           // keccak256(proof)
        bytes32 publicInputsHash;    // keccak256(publicInputs)
        bytes32 commitment;          // Associated state commitment
        uint64 sourceChainId;        // Origin chain
        uint64 destChainId;          // Destination chain
        uint64 submittedAt;          // Submission timestamp
        uint64 challengeDeadline;    // When challenge period ends
        address relayer;             // Who submitted
        ProofStatus status;          // Current status
        uint256 stake;               // Relayer's stake
    }

    /// @notice Batch proof submission
    struct BatchSubmission {
        bytes32 batchId;             // Unique batch identifier
        bytes32 merkleRoot;          // Root of proof merkle tree
        uint256 proofCount;          // Number of proofs in batch
        uint64 submittedAt;          // Submission timestamp
        uint64 challengeDeadline;    // Batch challenge deadline
        address relayer;             // Who submitted
        ProofStatus status;          // Batch status
        uint256 totalStake;          // Total stake for batch
    }

    /// @notice Challenge structure
    struct Challenge {
        bytes32 proofId;             // Proof being challenged
        address challenger;          // Who challenged
        uint256 stake;               // Challenger's stake
        uint64 createdAt;            // Challenge timestamp
        uint64 deadline;             // Resolution deadline
        bool resolved;               // Whether resolved
        bool challengerWon;          // Outcome
        string reason;               // Challenge reason
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

    /// @notice Fee per proof submission (in wei)
    uint256 public proofSubmissionFee = 0.001 ether;

    /// @notice Relayer stakes
    mapping(address => uint256) public relayerStakes;

    /// @notice Relayer successful submissions count
    mapping(address => uint256) public relayerSuccessCount;

    /// @notice Relayer slashed count
    mapping(address => uint256) public relayerSlashCount;

    /// @notice This chain's ID
    uint256 public immutable CHAIN_ID;

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
        bytes32 merkleRoot,
        uint256 proofCount,
        address indexed relayer
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
        address winner,
        uint256 reward
    );

    event RelayerStakeDeposited(address indexed relayer, uint256 amount);
    event RelayerStakeWithdrawn(address indexed relayer, uint256 amount);
    event RelayerSlashed(address indexed relayer, uint256 amount);

    event ChainAdded(uint256 indexed chainId);
    event ChainRemoved(uint256 indexed chainId);
    event VerifierSet(bytes32 indexed proofType, address verifier);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientStake(uint256 provided, uint256 required);
    error ProofNotFound(bytes32 proofId);
    error ProofAlreadyExists(bytes32 proofId);
    error InvalidProofStatus(bytes32 proofId, ProofStatus current, ProofStatus expected);
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

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_BATCH_SIZE = 100;
    bytes32 public constant DEFAULT_PROOF_TYPE = keccak256("GROTH16_BLS12381");

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        CHAIN_ID = block.chainid;
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        _grantRole(CHALLENGER_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Add this chain as supported
        supportedChains[block.chainid] = true;
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
    function withdrawStake(uint256 amount) external nonReentrant {
        if (relayerStakes[msg.sender] < amount) 
            revert InsufficientStake(relayerStakes[msg.sender], amount);
        
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
        return _submitProof(proof, publicInputs, commitment, sourceChainId, destChainId, false);
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
        if (address(verifier) == address(0)) {
            verifier = verifiers[DEFAULT_PROOF_TYPE];
            if (address(verifier) == address(0)) revert VerifierNotSet(proofType);
        }

        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        proofId = _submitProof(proof, publicInputs, commitment, sourceChainId, destChainId, true);
        
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
            revert InsufficientStake(relayerStakes[msg.sender], minRelayerStake);

        batchId = keccak256(abi.encodePacked(
            merkleRoot,
            msg.sender,
            block.timestamp,
            totalBatches
        ));

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
            bytes32 proofId = keccak256(abi.encodePacked(
                _proofs[i].proofHash,
                _proofs[i].commitment,
                _proofs[i].sourceChainId,
                _proofs[i].destChainId
            ));

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
            unchecked { ++totalProofs; ++i; }
        }

        unchecked { ++totalBatches; }
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
            revert InvalidProofStatus(proofId, submission.status, ProofStatus.Pending);
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
        if (challenge.challenger == address(0)) revert ChallengeNotFound(proofId);
        if (challenge.resolved) revert ChallengeNotFound(proofId);

        ProofSubmission storage submission = proofs[proofId];

        // Verify proof hashes match
        bytes32 proofHash = keccak256(proof);
        bytes32 inputsHash = keccak256(publicInputs);
        
        bool proofValid = false;
        if (proofHash == submission.proofHash && inputsHash == submission.publicInputsHash) {
            // Try to verify the proof
            IProofVerifier verifier = verifiers[proofType];
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
            if (relayerStakes[submission.relayer] >= slashAmount) {
                relayerStakes[submission.relayer] -= slashAmount;
            }
            relayerSlashCount[submission.relayer]++;
            
            uint256 reward = challenge.stake + slashAmount;
            (bool success, ) = challenge.challenger.call{value: reward}("");
            if (!success) {
                // If transfer fails, add to their "claimable" balance
                relayerStakes[challenge.challenger] += reward;
            }
            
            emit ChallengeResolved(proofId, true, challenge.challenger, reward);
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
                revert ChallengePeriodNotOver(proofId, submission.challengeDeadline);
            
            submission.status = ProofStatus.Verified;
            emit ProofVerified(proofId, ProofStatus.Verified);
        }
        
        if (submission.status != ProofStatus.Verified)
            revert InvalidProofStatus(proofId, submission.status, ProofStatus.Verified);

        submission.status = ProofStatus.Finalized;
        relayerSuccessCount[submission.relayer]++;

        emit ProofFinalized(proofId);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _submitProof(
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 sourceChainId,
        uint64 destChainId,
        bool instant
    ) internal returns (bytes32 proofId) {
        // Validate fee
        uint256 requiredFee = instant ? proofSubmissionFee * 3 : proofSubmissionFee;
        if (msg.value < requiredFee) revert InsufficientFee(msg.value, requiredFee);

        // Validate stake
        if (relayerStakes[msg.sender] < minRelayerStake)
            revert InsufficientStake(relayerStakes[msg.sender], minRelayerStake);

        // Validate chains
        if (!supportedChains[sourceChainId]) revert UnsupportedChain(sourceChainId);
        if (!supportedChains[destChainId]) revert UnsupportedChain(destChainId);

        bytes32 proofHash = keccak256(proof);
        bytes32 publicInputsHash = keccak256(publicInputs);

        proofId = keccak256(abi.encodePacked(
            proofHash,
            commitment,
            sourceChainId,
            destChainId
        ));

        if (proofs[proofId].relayer != address(0)) revert ProofAlreadyExists(proofId);

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

        unchecked { ++totalProofs; }
        accumulatedFees += msg.value;

        emit ProofSubmitted(proofId, commitment, sourceChainId, destChainId, msg.sender);
        emit ProofDataEmitted(proofId, proof, publicInputs);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Gets proof submission details
    /// @param proofId The proof ID
    /// @return submission The proof submission struct
    function getProof(bytes32 proofId) external view returns (ProofSubmission memory submission) {
        return proofs[proofId];
    }

    /// @notice Gets batch details
    /// @param batchId The batch ID
    /// @return batch The batch submission struct
    function getBatch(bytes32 batchId) external view returns (BatchSubmission memory batch) {
        return batches[batchId];
    }

    /// @notice Gets challenge details
    /// @param proofId The proof ID
    /// @return challenge The challenge struct
    function getChallenge(bytes32 proofId) external view returns (Challenge memory) {
        return challenges[proofId];
    }

    /// @notice Checks if a proof is finalized
    /// @param proofId The proof ID
    /// @return finalized True if finalized
    function isProofFinalized(bytes32 proofId) external view returns (bool finalized) {
        return proofs[proofId].status == ProofStatus.Finalized;
    }

    /// @notice Gets relayer statistics
    /// @param relayer The relayer address
    /// @return stake Current stake
    /// @return successCount Successful submissions
    /// @return slashCount Times slashed
    function getRelayerStats(address relayer) external view returns (
        uint256 stake,
        uint256 successCount,
        uint256 slashCount
    ) {
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
    function setVerifier(bytes32 proofType, address _verifier) external onlyRole(VERIFIER_ADMIN_ROLE) {
        verifiers[proofType] = IProofVerifier(_verifier);
        emit VerifierSet(proofType, _verifier);
    }

    /// @notice Adds a supported chain
    /// @param chainId The chain ID to add
    function addSupportedChain(uint256 chainId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = true;
        emit ChainAdded(chainId);
    }

    /// @notice Removes a supported chain
    /// @param chainId The chain ID to remove
    function removeSupportedChain(uint256 chainId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChains[chainId] = false;
        emit ChainRemoved(chainId);
    }

    /// @notice Updates challenge period
    /// @param _period New period in seconds
    function setChallengePeriod(uint256 _period) external onlyRole(DEFAULT_ADMIN_ROLE) {
        challengePeriod = _period;
    }

    /// @notice Updates minimum stakes
    /// @param _relayerStake New relayer stake
    /// @param _challengerStake New challenger stake
    function setMinStakes(uint256 _relayerStake, uint256 _challengerStake) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minRelayerStake = _relayerStake;
        minChallengerStake = _challengerStake;
    }

    /// @notice Updates proof submission fee
    /// @param _fee New fee in wei
    function setProofSubmissionFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofSubmissionFee = _fee;
    }

    /// @notice Withdraws accumulated fees
    /// @param to Recipient address
    function withdrawFees(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
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

    /// @notice Allows contract to receive ETH
    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

interface IProofVerifier {
    function verifyProof(bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
}

/// @notice Batch proof input structure
struct BatchProofInput {
    bytes32 proofHash;
    bytes32 publicInputsHash;
    bytes32 commitment;
    uint64 sourceChainId;
    uint64 destChainId;
}
