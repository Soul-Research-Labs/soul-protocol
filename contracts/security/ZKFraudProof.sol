// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ZKFraudProof
 * @author Soul Security Team
 * @notice Zero-Knowledge Fraud Proofs for optimistic rollup security
 * @dev Implements ZK-based fraud proving for faster finality and reduced gas costs
 */
contract ZKFraudProof is AccessControl, ReentrancyGuard, Pausable {
    // ============ Roles ============
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============ Enums ============
    enum ProofType {
        EXECUTION, // Invalid state transition
        INCLUSION, // Missing transaction
        ORDERING, // Wrong transaction order
        DATA_AVAILABILITY, // DA failure
        CENSORSHIP, // Transaction censorship
        DOUBLE_SPEND, // Double-spend attempt
        INVALID_SIGNATURE, // Invalid signature in batch
        CUSTOM // Custom fraud type
    }

    enum ProofStatus {
        PENDING,
        VERIFYING,
        VERIFIED,
        REJECTED,
        APPLIED,
        EXPIRED
    }

    enum DisputeWindow {
        STANDARD, // 7 days
        EXPEDITED, // 1 day (with ZK proof)
        INSTANT // Immediate (full ZK verification)
    }

    // ============ Structs ============
    struct FraudProof {
        bytes32 id;
        ProofType proofType;
        ProofStatus status;
        DisputeWindow window;
        address challenger;
        bytes32 stateRoot; // Claimed incorrect state root
        bytes32 correctStateRoot; // Proven correct state root
        bytes32 batchId; // Disputed batch
        uint256 transactionIndex; // Transaction index in batch
        bytes zkProof; // ZK proof data
        bytes32 publicInputsHash; // Hash of public inputs
        uint256 submittedAt;
        uint256 verifiedAt;
        uint256 expiresAt;
        uint256 bondAmount;
        bool slashed;
    }

    struct Batch {
        bytes32 id;
        bytes32 stateRoot;
        bytes32 previousStateRoot;
        bytes32 transactionsRoot;
        uint256 submittedAt;
        uint256 finalizedAt;
        address sequencer;
        bool finalized;
        bool disputed;
        bytes32[] fraudProofIds;
    }

    struct VerificationKey {
        bytes32 id;
        ProofType proofType;
        bytes vkData; // Verification key bytes
        uint256 addedAt;
        bool active;
    }

    struct ProverStats {
        address prover;
        uint256 proofsSubmitted;
        uint256 proofsVerified;
        uint256 proofsFailed;
        uint256 totalBonded;
        uint256 totalSlashed;
        uint256 reputation;
    }

    struct DisputeResolution {
        bytes32 proofId;
        bytes32 batchId;
        bool fraudConfirmed;
        bytes32 revertToState;
        uint256 slashedAmount;
        address slashedParty;
        uint256 resolvedAt;
    }

    // ============ Constants ============
    uint256 public constant STANDARD_DISPUTE_PERIOD = 7 days;
    uint256 public constant EXPEDITED_DISPUTE_PERIOD = 1 days;
    uint256 public constant MIN_BOND = 1 ether;
    uint256 public constant MAX_PROOF_SIZE = 2048; // bytes
    uint256 public constant SLASH_PERCENTAGE = 50; // 50% of bond
    uint256 public constant PROVER_REWARD_PERCENTAGE = 30; // 30% of slashed

    // ZK Circuit Constants (Groth16 BN254)
    uint256 private constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // ============ State Variables ============
    mapping(bytes32 => FraudProof) public fraudProofs;
    mapping(bytes32 => Batch) public batches;
    mapping(bytes32 => VerificationKey) public verificationKeys;
    mapping(address => ProverStats) public proverStats;
    mapping(bytes32 => DisputeResolution) public resolutions;

    bytes32[] public proofIds;
    bytes32[] public batchIds;
    bytes32[] public pendingProofs;

    // Verified state
    bytes32 public latestVerifiedStateRoot;
    uint256 public latestVerifiedBatchIndex;

    // External contracts
    address public stateCommitmentChain;
    address public bondManager;
    address public zkVerifier;

    // Statistics
    uint256 public totalProofsSubmitted;
    uint256 public totalProofsVerified;
    uint256 public totalFraudConfirmed;
    uint256 public totalSlashed;

    // ============ Events ============
    event FraudProofSubmitted(
        bytes32 indexed proofId,
        ProofType proofType,
        bytes32 indexed batchId,
        address indexed challenger
    );
    event FraudProofVerified(bytes32 indexed proofId, bool valid);
    event FraudProofApplied(
        bytes32 indexed proofId,
        bytes32 indexed batchId,
        bytes32 revertToState
    );
    event BatchSubmitted(
        bytes32 indexed batchId,
        bytes32 stateRoot,
        address sequencer
    );
    event BatchFinalized(bytes32 indexed batchId, bytes32 stateRoot);
    event BatchReverted(bytes32 indexed batchId, bytes32 revertToState);
    event VerificationKeyAdded(bytes32 indexed vkId, ProofType proofType);
    event SlashExecuted(
        address indexed slashedParty,
        uint256 amount,
        bytes32 indexed proofId
    );
    event ProverRewarded(
        address indexed prover,
        uint256 amount,
        bytes32 indexed proofId
    );

    // ============ Errors ============
    error InvalidProof();
    error ProofNotFound();
    error BatchNotFound();
    error ProofExpired();
    error BatchAlreadyFinalized();
    error BatchNotDisputed();
    error InsufficientBond();
    error ProofTooLarge();
    error InvalidVerificationKey();
    error VerificationFailed();
    error DisputePeriodActive();
    error NotProver();
    error ZeroAddress();
    error InvalidStateTransition();

    // ============ Constructor ============
    constructor(
        address _stateCommitmentChain,
        address _bondManager,
        address _zkVerifier
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROVER_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        stateCommitmentChain = _stateCommitmentChain;
        bondManager = _bondManager;
        zkVerifier = _zkVerifier;

        latestVerifiedStateRoot = bytes32(0);
    }

    // ============ Batch Management ============

    /**
     * @notice Submit a new batch
     * @param stateRoot New state root after batch
     * @param previousStateRoot Previous state root
     * @param transactionsRoot Merkle root of transactions
     * @return batchId The batch ID
     */
    function submitBatch(
        bytes32 stateRoot,
        bytes32 previousStateRoot,
        bytes32 transactionsRoot
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 batchId) {
        // Verify state transition
        if (
            latestVerifiedStateRoot != bytes32(0) &&
            previousStateRoot != latestVerifiedStateRoot
        ) {
            revert InvalidStateTransition();
        }

        batchId = keccak256(
            abi.encodePacked(
                stateRoot,
                previousStateRoot,
                transactionsRoot,
                block.timestamp,
                msg.sender
            )
        );

        batches[batchId] = Batch({
            id: batchId,
            stateRoot: stateRoot,
            previousStateRoot: previousStateRoot,
            transactionsRoot: transactionsRoot,
            submittedAt: block.timestamp,
            finalizedAt: 0,
            sequencer: msg.sender,
            finalized: false,
            disputed: false,
            fraudProofIds: new bytes32[](0)
        });

        batchIds.push(batchId);

        emit BatchSubmitted(batchId, stateRoot, msg.sender);
    }

    /**
     * @notice Finalize a batch after dispute period
     * @param batchId Batch to finalize
     */
    function finalizeBatch(bytes32 batchId) external {
        Batch storage batch = batches[batchId];
        if (batch.submittedAt == 0) revert BatchNotFound();
        if (batch.finalized) revert BatchAlreadyFinalized();
        if (batch.disputed) revert BatchNotDisputed();

        // Check dispute period
        if (block.timestamp < batch.submittedAt + STANDARD_DISPUTE_PERIOD) {
            revert DisputePeriodActive();
        }

        batch.finalized = true;
        batch.finalizedAt = block.timestamp;
        latestVerifiedStateRoot = batch.stateRoot;
        latestVerifiedBatchIndex++;

        emit BatchFinalized(batchId, batch.stateRoot);
    }

    // ============ Fraud Proof Submission ============

    /**
     * @notice Submit a ZK fraud proof
     * @param proofType Type of fraud
     * @param batchId Disputed batch
     * @param transactionIndex Transaction index in batch
     * @param correctStateRoot Proven correct state
     * @param zkProof ZK proof data
     * @param publicInputsHash Hash of public inputs
     * @return proofId The proof ID
     */
    function submitFraudProof(
        ProofType proofType,
        bytes32 batchId,
        uint256 transactionIndex,
        bytes32 correctStateRoot,
        bytes calldata zkProof,
        bytes32 publicInputsHash
    )
        external
        payable
        nonReentrant
        onlyRole(PROVER_ROLE)
        returns (bytes32 proofId)
    {
        Batch storage batch = batches[batchId];
        if (batch.submittedAt == 0) revert BatchNotFound();
        if (batch.finalized) revert BatchAlreadyFinalized();
        if (msg.value < MIN_BOND) revert InsufficientBond();
        if (zkProof.length > MAX_PROOF_SIZE) revert ProofTooLarge();

        proofId = keccak256(
            abi.encodePacked(
                proofType,
                batchId,
                transactionIndex,
                correctStateRoot,
                block.timestamp,
                msg.sender
            )
        );

        // Determine dispute window based on proof
        DisputeWindow window = DisputeWindow.STANDARD;
        uint256 expiresAt = block.timestamp + STANDARD_DISPUTE_PERIOD;

        // ZK proofs enable expedited resolution
        if (zkProof.length > 0) {
            window = DisputeWindow.EXPEDITED;
            expiresAt = block.timestamp + EXPEDITED_DISPUTE_PERIOD;
        }

        fraudProofs[proofId] = FraudProof({
            id: proofId,
            proofType: proofType,
            status: ProofStatus.PENDING,
            window: window,
            challenger: msg.sender,
            stateRoot: batch.stateRoot,
            correctStateRoot: correctStateRoot,
            batchId: batchId,
            transactionIndex: transactionIndex,
            zkProof: zkProof,
            publicInputsHash: publicInputsHash,
            submittedAt: block.timestamp,
            verifiedAt: 0,
            expiresAt: expiresAt,
            bondAmount: msg.value,
            slashed: false
        });

        batch.disputed = true;
        batch.fraudProofIds.push(proofId);
        proofIds.push(proofId);
        pendingProofs.push(proofId);
        totalProofsSubmitted++;

        // Update prover stats
        proverStats[msg.sender].proofsSubmitted++;
        proverStats[msg.sender].totalBonded += msg.value;

        emit FraudProofSubmitted(proofId, proofType, batchId, msg.sender);
    }

    // ============ Proof Verification ============

    /**
     * @notice Verify a fraud proof
     * @param proofId Proof to verify
     * @return valid Whether the proof is valid
     */
    function verifyFraudProof(
        bytes32 proofId
    ) external onlyRole(VERIFIER_ROLE) nonReentrant returns (bool valid) {
        FraudProof storage proof = fraudProofs[proofId];
        if (proof.challenger == address(0)) revert ProofNotFound();
        if (proof.status != ProofStatus.PENDING) return false;
        if (block.timestamp > proof.expiresAt) {
            proof.status = ProofStatus.EXPIRED;
            revert ProofExpired();
        }

        proof.status = ProofStatus.VERIFYING;

        // Verify ZK proof
        if (proof.zkProof.length > 0) {
            valid = _verifyZKProof(proof);
        } else {
            // Fallback to interactive verification
            valid = _verifyInteractive(proof);
        }

        proof.verifiedAt = block.timestamp;
        totalProofsVerified++;

        if (valid) {
            proof.status = ProofStatus.VERIFIED;
            proverStats[proof.challenger].proofsVerified++;
            proverStats[proof.challenger].reputation += 10;
        } else {
            proof.status = ProofStatus.REJECTED;
            proverStats[proof.challenger].proofsFailed++;
            if (proverStats[proof.challenger].reputation > 5) {
                proverStats[proof.challenger].reputation -= 5;
            }
        }

        emit FraudProofVerified(proofId, valid);
    }

    /**
     * @notice Apply verified fraud proof (revert state)
     * @param proofId Verified proof to apply
     */
    function applyFraudProof(
        bytes32 proofId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        FraudProof storage proof = fraudProofs[proofId];
        if (proof.status != ProofStatus.VERIFIED) revert InvalidProof();

        Batch storage batch = batches[proof.batchId];

        // Revert state to before the fraudulent batch
        latestVerifiedStateRoot = proof.correctStateRoot;
        proof.status = ProofStatus.APPLIED;
        totalFraudConfirmed++;

        // Slash the sequencer
        uint256 slashAmount = (batch.submittedAt > 0) ? MIN_BOND : 0;
        if (slashAmount > 0) {
            _executeSlash(batch.sequencer, slashAmount, proofId);
        }

        // Reward the prover
        uint256 reward = (slashAmount * PROVER_REWARD_PERCENTAGE) / 100;
        if (reward > 0) {
            _rewardProver(proof.challenger, reward, proofId);
        }

        // Return prover's bond
        (bool bondSuccess, ) = payable(proof.challenger).call{value: proof.bondAmount}("");
        require(bondSuccess, "Bond transfer failed");

        // Record resolution
        resolutions[proofId] = DisputeResolution({
            proofId: proofId,
            batchId: proof.batchId,
            fraudConfirmed: true,
            revertToState: proof.correctStateRoot,
            slashedAmount: slashAmount,
            slashedParty: batch.sequencer,
            resolvedAt: block.timestamp
        });

        emit FraudProofApplied(proofId, proof.batchId, proof.correctStateRoot);
        emit BatchReverted(proof.batchId, proof.correctStateRoot);
    }

    // ============ Verification Key Management ============

    /**
     * @notice Add a verification key for a proof type
     * @param proofType Type of proof this VK verifies
     * @param vkData Verification key data
     * @return vkId Verification key ID
     */
    function addVerificationKey(
        ProofType proofType,
        bytes calldata vkData
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32 vkId) {
        if (vkData.length == 0) revert InvalidVerificationKey();

        vkId = keccak256(abi.encodePacked(proofType, vkData, block.timestamp));

        verificationKeys[vkId] = VerificationKey({
            id: vkId,
            proofType: proofType,
            vkData: vkData,
            addedAt: block.timestamp,
            active: true
        });

        emit VerificationKeyAdded(vkId, proofType);
    }

    /**
     * @notice Deactivate a verification key
     * @param vkId Verification key to deactivate
     */
    function deactivateVerificationKey(
        bytes32 vkId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verificationKeys[vkId].active = false;
    }

    // ============ View Functions ============

    /**
     * @notice Get fraud proof details
     * @param proofId Proof ID
     */
    function getFraudProof(
        bytes32 proofId
    ) external view returns (FraudProof memory) {
        return fraudProofs[proofId];
    }

    /**
     * @notice Get batch details
     * @param batchId Batch ID
     */
    function getBatch(
        bytes32 batchId
    )
        external
        view
        returns (
            bytes32 stateRoot,
            bytes32 previousStateRoot,
            uint256 submittedAt,
            bool finalized,
            bool disputed,
            address sequencer
        )
    {
        Batch storage batch = batches[batchId];
        return (
            batch.stateRoot,
            batch.previousStateRoot,
            batch.submittedAt,
            batch.finalized,
            batch.disputed,
            batch.sequencer
        );
    }

    /**
     * @notice Get prover statistics
     * @param prover Prover address
     */
    function getProverStats(
        address prover
    ) external view returns (ProverStats memory) {
        return proverStats[prover];
    }

    /**
     * @notice Check if batch is in dispute period
     * @param batchId Batch ID
     */
    function isInDisputePeriod(bytes32 batchId) external view returns (bool) {
        Batch storage batch = batches[batchId];
        return
            !batch.finalized &&
            block.timestamp < batch.submittedAt + STANDARD_DISPUTE_PERIOD;
    }

    /**
     * @notice Get pending proof count
     */
    function getPendingProofCount() external view returns (uint256) {
        return pendingProofs.length;
    }

    /**
     * @notice Get effective dispute period for a proof type
     * @param hasZKProof Whether ZK proof is provided
     */
    function getDisputePeriod(bool hasZKProof) external pure returns (uint256) {
        return hasZKProof ? EXPEDITED_DISPUTE_PERIOD : STANDARD_DISPUTE_PERIOD;
    }

    // ============ Admin Functions ============

    /**
     * @notice Update external contract addresses
     * @param _stateCommitmentChain State commitment chain address
     * @param _bondManager Bond manager address
     * @param _zkVerifier ZK verifier address
     */
    function updateContracts(
        address _stateCommitmentChain,
        address _bondManager,
        address _zkVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_stateCommitmentChain != address(0))
            stateCommitmentChain = _stateCommitmentChain;
        if (_bondManager != address(0)) bondManager = _bondManager;
        if (_zkVerifier != address(0)) zkVerifier = _zkVerifier;
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Withdraw stuck funds (emergency)
     * @param to Recipient
     * @param amount Amount
     */
    function emergencyWithdraw(
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ============ Internal Functions ============

    function _verifyZKProof(
        FraudProof storage proof
    ) internal view returns (bool) {
        // Get verification key for this proof type
        bytes32 vkId = _getActiveVKForType(proof.proofType);
        if (vkId == bytes32(0)) return false;

        VerificationKey storage vk = verificationKeys[vkId];
        if (!vk.active) return false;

        // Call external ZK verifier
        if (zkVerifier == address(0)) return false;

        // Construct public inputs
        bytes memory publicInputs = abi.encodePacked(
            proof.stateRoot,
            proof.correctStateRoot,
            proof.batchId,
            proof.transactionIndex
        );

        // Verify hash matches
        if (keccak256(publicInputs) != proof.publicInputsHash) return false;

        // Call verifier contract
        (bool success, bytes memory result) = zkVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes,bytes,bytes)",
                vk.vkData,
                proof.zkProof,
                publicInputs
            )
        );

        if (!success) return false;

        return abi.decode(result, (bool));
    }

    function _verifyInteractive(
        FraudProof storage proof
    ) internal view returns (bool) {
        // Interactive verification fallback
        // This would involve step-by-step state transition verification

        // For now, basic checks
        if (proof.correctStateRoot == bytes32(0)) return false;
        if (proof.correctStateRoot == proof.stateRoot) return false;

        // In production, this would verify the state transition
        // by replaying transactions and checking the resulting state
        return true;
    }

    function _getActiveVKForType(
        ProofType proofType
    ) internal view returns (bytes32) {
        // Find active VK for this proof type
        // In production, maintain a mapping for O(1) lookup
        for (uint256 i = 0; i < proofIds.length; i++) {
            bytes32 vkId = keccak256(abi.encodePacked(proofType, i));
            if (
                verificationKeys[vkId].active &&
                verificationKeys[vkId].proofType == proofType
            ) {
                return vkId;
            }
        }
        return bytes32(0);
    }

    function _executeSlash(
        address party,
        uint256 amount,
        bytes32 proofId
    ) internal {
        // In production, call bond manager to slash
        totalSlashed += amount;
        proverStats[party].totalSlashed += amount;

        emit SlashExecuted(party, amount, proofId);
    }

    function _rewardProver(
        address prover,
        uint256 amount,
        bytes32 proofId
    ) internal {
        // Transfer reward to prover
        (bool success, ) = payable(prover).call{value: amount}("");
        require(success, "Reward transfer failed");

        emit ProverRewarded(prover, amount, proofId);
    }

    // ============ Receive Function ============
    receive() external payable {}
}
