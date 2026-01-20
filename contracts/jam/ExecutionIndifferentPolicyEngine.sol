// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ExecutionIndifferentPolicyEngine
 * @author Soul Protocol
 * @notice JAM-inspired: Policies enforced regardless of HOW or WHERE computation happened
 * @dev Core JAM insight: Execution is irrelevant. Only the proof and its policy binding matter.
 *
 * JAM'S EXECUTION NEUTRALITY:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ "Programs are not special. Proofs are."                                    │
 * │                                                                            │
 * │ The kernel doesn't care:                                                   │
 * │ - What language the program was written in                                 │
 * │ - What runtime executed it                                                 │
 * │ - Where (which chain/TEE/MPC) it ran                                       │
 * │                                                                            │
 * │ It ONLY cares:                                                             │
 * │ - Is the proof valid?                                                      │
 * │ - Does the state transition satisfy policies?                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S EXTENSION (Execution Indifference + Privacy):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Policy enforcement is BLIND to execution details:                          │
 * │ - Policy doesn't know if computation used ZK/TEE/MPC                       │
 * │ - Policy doesn't know which chain originated the proof                     │
 * │ - Policy only sees: proof, commitments, policy claims                      │
 * │                                                                            │
 * │ This enables TRUE HETEROGENEITY:                                           │
 * │ - Same policy works for any execution backend                              │
 * │ - Policies are portable across chains                                      │
 * │ - No backend-specific policy logic needed                                  │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract ExecutionIndifferentPolicyEngine is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Policy constraint types
     * @dev These are EXECUTION-AGNOSTIC constraints
     */
    enum ConstraintType {
        Unknown,
        // State constraints
        STATE_MEMBERSHIP, // State must be in allowed set
        STATE_EXCLUSION, // State must NOT be in set
        STATE_RANGE, // State value in range
        STATE_TRANSITION, // Valid state transition
        // Value constraints
        VALUE_LIMIT, // Value within limits
        VALUE_RATIO, // Values maintain ratio
        VALUE_CONSERVATION, // Sum conserved
        // Identity constraints
        IDENTITY_AUTHORIZED, // Identity has authorization
        IDENTITY_SANCTIONED, // Identity not sanctioned
        IDENTITY_THRESHOLD, // N-of-M identities
        // Temporal constraints
        TIME_WINDOW, // Within time window
        TIME_SEQUENCE, // Correct ordering
        TIME_COOLDOWN, // Minimum time between
        // Proof constraints
        PROOF_FRESHNESS, // Proof not too old
        PROOF_CHAIN, // Proof references valid chain
        PROOF_AGGREGATION, // Aggregated proof requirements
        // Custom
        CUSTOM_PREDICATE // Custom constraint logic
    }

    /**
     * @notice Policy constraint - execution-indifferent
     */
    struct PolicyConstraint {
        bytes32 constraintId;
        ConstraintType constraintType;
        string description;
        // Constraint parameters (execution-agnostic)
        bytes32 parameterHash; // Hash of constraint parameters
        bytes parameters; // Encoded parameters
        // Evaluation
        bool requiresProof; // Must provide ZK proof?
        bytes32 constraintCircuitHash; // Circuit for ZK constraint
        // Status
        bool active;
        uint64 createdAt;
    }

    /**
     * @notice Execution-indifferent policy
     */
    struct IndifferentPolicy {
        bytes32 policyId;
        string name;
        string description;
        // Constraints
        bytes32[] constraintIds;
        uint256 constraintCount;
        // Enforcement
        EnforcementMode mode;
        bool strictMode; // All constraints must pass?
        uint256 minimumPassing; // Minimum constraints that must pass
        // Execution indifference
        bool allowAnyBackend;
        bool allowAnyChain;
        bool allowAnyProofType;
        // Status
        bool active;
        uint64 createdAt;
        uint64 updatedAt;
    }

    enum EnforcementMode {
        Advisory, // Warn but don't block
        Mandatory, // Block if violated
        Cryptographic // Require ZK proof of compliance
    }

    /**
     * @notice Policy claim - what the proof claims about policy
     * @dev This is the ONLY thing the engine evaluates
     */
    struct PolicyClaim {
        bytes32 claimId;
        bytes32 policyId;
        // Claims are execution-agnostic
        bytes32[] constraintResults; // Result per constraint
        bytes32 aggregateResult; // Aggregate claim
        // Proof of claim (if cryptographic)
        bytes32 claimProofHash;
        bytes claimProof;
        // Source (but engine doesn't care about details)
        bytes32 sourceCommitment; // Hidden source
        bytes32 executorCommitment; // Hidden executor
        // Verification
        bool verified;
        ClaimStatus status;
        uint64 createdAt;
        uint64 verifiedAt;
    }

    enum ClaimStatus {
        Pending,
        Verified,
        Accepted,
        Rejected
    }

    /**
     * @notice Policy evaluation result
     */
    struct EvaluationResult {
        bytes32 evaluationId;
        bytes32 policyId;
        bytes32 claimId;
        // Results (execution-agnostic)
        bool compliant;
        uint256 constraintsPassed;
        uint256 constraintsFailed;
        bytes32[] passedConstraints;
        bytes32[] failedConstraints;
        // Enforcement
        EnforcementMode appliedMode;
        bool blocked;
        string reason;
        // Metadata
        uint64 evaluatedAt;
        address evaluator;
    }

    /**
     * @notice Universal proof envelope - hides execution details
     */
    struct UniversalProofEnvelope {
        bytes32 envelopeId;
        // Proof content (backend-agnostic)
        bytes32 proofHash;
        bytes32 publicInputsHash;
        bytes32 stateTransitionHash;
        // Policy binding
        bytes32 policyId;
        bytes32 policyClaimId;
        // The engine only sees this envelope, not execution details
        bytes32 executionCommitment; // Hides: backend, chain, etc.
        // Verification
        bool verified;
        bool policyCompliant;
        uint64 createdAt;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Constraints: constraintId => constraint
    mapping(bytes32 => PolicyConstraint) public constraints;

    /// @notice Policies: policyId => policy
    mapping(bytes32 => IndifferentPolicy) public policies;

    /// @notice Policy constraints: policyId => constraintIds
    mapping(bytes32 => bytes32[]) public policyConstraints;

    /// @notice Claims: claimId => claim
    mapping(bytes32 => PolicyClaim) public claims;

    /// @notice Evaluations: evaluationId => result
    mapping(bytes32 => EvaluationResult) public evaluations;

    /// @notice Envelopes: envelopeId => envelope
    mapping(bytes32 => UniversalProofEnvelope) public envelopes;

    /// @notice Claim to policy: claimId => policyId
    mapping(bytes32 => bytes32) public claimToPolicy;

    /// @notice Counters
    uint256 public totalConstraints;
    uint256 public totalPolicies;
    uint256 public totalClaims;
    uint256 public totalEvaluations;
    uint256 public totalCompliant;
    uint256 public totalBlocked;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ConstraintCreated(
        bytes32 indexed constraintId,
        ConstraintType constraintType,
        bool requiresProof
    );

    event PolicyCreated(
        bytes32 indexed policyId,
        string name,
        EnforcementMode mode,
        uint256 constraintCount
    );

    event ClaimSubmitted(
        bytes32 indexed claimId,
        bytes32 indexed policyId,
        bytes32 sourceCommitment
    );

    event ClaimVerified(bytes32 indexed claimId, bool verified);

    event PolicyEvaluated(
        bytes32 indexed evaluationId,
        bytes32 indexed policyId,
        bool compliant,
        bool blocked
    );

    event ProofEnvelopeSubmitted(
        bytes32 indexed envelopeId,
        bytes32 indexed policyId,
        bytes32 executionCommitment
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_ADMIN_ROLE, msg.sender);
        _grantRole(ENFORCER_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTRAINT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a policy constraint
     * @dev Constraints are execution-agnostic
     */
    function createConstraint(
        ConstraintType constraintType,
        string calldata description,
        bytes calldata parameters,
        bool requiresProof,
        bytes32 constraintCircuitHash
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 constraintId) {
        require(constraintType != ConstraintType.Unknown, "EIPE: unknown type");

        constraintId = keccak256(
            abi.encodePacked(
                constraintType,
                parameters,
                block.timestamp,
                totalConstraints
            )
        );

        constraints[constraintId] = PolicyConstraint({
            constraintId: constraintId,
            constraintType: constraintType,
            description: description,
            parameterHash: keccak256(parameters),
            parameters: parameters,
            requiresProof: requiresProof,
            constraintCircuitHash: constraintCircuitHash,
            active: true,
            createdAt: uint64(block.timestamp)
        });

        totalConstraints++;

        emit ConstraintCreated(constraintId, constraintType, requiresProof);
    }

    /*//////////////////////////////////////////////////////////////
                        POLICY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an execution-indifferent policy
     */
    function createPolicy(
        string calldata name,
        string calldata description,
        bytes32[] calldata constraintIds,
        EnforcementMode mode,
        bool strictMode,
        uint256 minimumPassing,
        bool allowAnyBackend,
        bool allowAnyChain,
        bool allowAnyProofType
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 policyId) {
        require(constraintIds.length > 0, "EIPE: no constraints");
        if (!strictMode) {
            require(minimumPassing > 0, "EIPE: minimum must be > 0");
            require(
                minimumPassing <= constraintIds.length,
                "EIPE: minimum too high"
            );
        }

        // Verify all constraints exist
        for (uint256 i = 0; i < constraintIds.length; i++) {
            require(
                constraints[constraintIds[i]].constraintId != bytes32(0),
                "EIPE: constraint not found"
            );
        }

        policyId = keccak256(
            abi.encodePacked(
                name,
                constraintIds,
                block.timestamp,
                totalPolicies
            )
        );

        policies[policyId] = IndifferentPolicy({
            policyId: policyId,
            name: name,
            description: description,
            constraintIds: constraintIds,
            constraintCount: constraintIds.length,
            mode: mode,
            strictMode: strictMode,
            minimumPassing: strictMode ? constraintIds.length : minimumPassing,
            allowAnyBackend: allowAnyBackend,
            allowAnyChain: allowAnyChain,
            allowAnyProofType: allowAnyProofType,
            active: true,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        policyConstraints[policyId] = constraintIds;
        totalPolicies++;

        emit PolicyCreated(policyId, name, mode, constraintIds.length);
    }

    /*//////////////////////////////////////////////////////////////
                          CLAIM SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a policy claim
     * @dev Claims are execution-agnostic - engine doesn't see execution details
     */
    function submitClaim(
        bytes32 policyId,
        bytes32[] calldata constraintResults,
        bytes32 aggregateResult,
        bytes calldata claimProof,
        bytes32 sourceCommitment,
        bytes32 executorCommitment
    ) external whenNotPaused nonReentrant returns (bytes32 claimId) {
        IndifferentPolicy storage policy = policies[policyId];
        require(policy.active, "EIPE: policy not active");
        require(
            constraintResults.length == policy.constraintCount,
            "EIPE: constraint count mismatch"
        );

        claimId = keccak256(
            abi.encodePacked(
                policyId,
                aggregateResult,
                sourceCommitment,
                block.timestamp,
                totalClaims
            )
        );

        claims[claimId] = PolicyClaim({
            claimId: claimId,
            policyId: policyId,
            constraintResults: constraintResults,
            aggregateResult: aggregateResult,
            claimProofHash: keccak256(claimProof),
            claimProof: claimProof,
            sourceCommitment: sourceCommitment,
            executorCommitment: executorCommitment,
            verified: false,
            status: ClaimStatus.Pending,
            createdAt: uint64(block.timestamp),
            verifiedAt: 0
        });

        claimToPolicy[claimId] = policyId;
        totalClaims++;

        emit ClaimSubmitted(claimId, policyId, sourceCommitment);
    }

    /**
     * @notice Verify a claim's proof
     */
    function verifyClaim(
        bytes32 claimId,
        bool valid
    ) external onlyRole(ENFORCER_ROLE) {
        PolicyClaim storage claim = claims[claimId];
        require(claim.claimId != bytes32(0), "EIPE: claim not found");
        require(claim.status == ClaimStatus.Pending, "EIPE: not pending");

        claim.verified = valid;
        claim.status = valid ? ClaimStatus.Verified : ClaimStatus.Rejected;
        claim.verifiedAt = uint64(block.timestamp);

        emit ClaimVerified(claimId, valid);
    }

    /*//////////////////////////////////////////////////////////////
                        POLICY EVALUATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Evaluate a claim against its policy
     * @dev The engine is INDIFFERENT to how/where computation happened
     */
    function evaluatePolicy(
        bytes32 claimId
    )
        external
        onlyRole(ENFORCER_ROLE)
        whenNotPaused
        returns (bytes32 evaluationId)
    {
        PolicyClaim storage claim = claims[claimId];
        require(claim.verified, "EIPE: claim not verified");
        require(claim.status == ClaimStatus.Verified, "EIPE: invalid status");

        IndifferentPolicy storage policy = policies[claim.policyId];

        // Count passing/failing constraints
        uint256 passed = 0;
        uint256 failed = 0;
        bytes32[] memory passedIds = new bytes32[](policy.constraintCount);
        bytes32[] memory failedIds = new bytes32[](policy.constraintCount);

        for (uint256 i = 0; i < policy.constraintCount; i++) {
            // Non-zero result means constraint passed
            if (claim.constraintResults[i] != bytes32(0)) {
                passedIds[passed] = policy.constraintIds[i];
                passed++;
            } else {
                failedIds[failed] = policy.constraintIds[i];
                failed++;
            }
        }

        // Determine compliance
        bool compliant = passed >= policy.minimumPassing;
        bool blocked = false;

        if (!compliant && policy.mode == EnforcementMode.Mandatory) {
            blocked = true;
            totalBlocked++;
        } else if (compliant) {
            totalCompliant++;
        }

        evaluationId = keccak256(
            abi.encodePacked(
                claimId,
                compliant,
                block.timestamp,
                totalEvaluations
            )
        );

        // Resize arrays
        bytes32[] memory passedFinal = new bytes32[](passed);
        bytes32[] memory failedFinal = new bytes32[](failed);
        for (uint256 i = 0; i < passed; i++) passedFinal[i] = passedIds[i];
        for (uint256 i = 0; i < failed; i++) failedFinal[i] = failedIds[i];

        evaluations[evaluationId] = EvaluationResult({
            evaluationId: evaluationId,
            policyId: claim.policyId,
            claimId: claimId,
            compliant: compliant,
            constraintsPassed: passed,
            constraintsFailed: failed,
            passedConstraints: passedFinal,
            failedConstraints: failedFinal,
            appliedMode: policy.mode,
            blocked: blocked,
            reason: blocked ? "Mandatory constraints failed" : "",
            evaluatedAt: uint64(block.timestamp),
            evaluator: msg.sender
        });

        // Update claim status
        claim.status = compliant ? ClaimStatus.Accepted : ClaimStatus.Rejected;

        totalEvaluations++;

        emit PolicyEvaluated(evaluationId, claim.policyId, compliant, blocked);
    }

    /*//////////////////////////////////////////////////////////////
                      UNIVERSAL PROOF ENVELOPE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a proof in universal envelope
     * @dev The envelope hides ALL execution details from the policy engine
     */
    function submitProofEnvelope(
        bytes32 proofHash,
        bytes32 publicInputsHash,
        bytes32 stateTransitionHash,
        bytes32 policyId,
        bytes32 policyClaimId,
        bytes32 executionCommitment
    ) external whenNotPaused returns (bytes32 envelopeId) {
        require(policies[policyId].active, "EIPE: policy not active");

        envelopeId = keccak256(
            abi.encodePacked(
                proofHash,
                policyId,
                executionCommitment,
                block.timestamp
            )
        );

        envelopes[envelopeId] = UniversalProofEnvelope({
            envelopeId: envelopeId,
            proofHash: proofHash,
            publicInputsHash: publicInputsHash,
            stateTransitionHash: stateTransitionHash,
            policyId: policyId,
            policyClaimId: policyClaimId,
            executionCommitment: executionCommitment,
            verified: false,
            policyCompliant: false,
            createdAt: uint64(block.timestamp)
        });

        emit ProofEnvelopeSubmitted(envelopeId, policyId, executionCommitment);
    }

    /**
     * @notice Mark envelope as verified and policy-compliant
     */
    function verifyEnvelope(
        bytes32 envelopeId,
        bool verified,
        bool policyCompliant
    ) external onlyRole(ENFORCER_ROLE) {
        UniversalProofEnvelope storage envelope = envelopes[envelopeId];
        require(envelope.envelopeId != bytes32(0), "EIPE: envelope not found");

        envelope.verified = verified;
        envelope.policyCompliant = verified && policyCompliant;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getConstraint(
        bytes32 constraintId
    ) external view returns (PolicyConstraint memory) {
        return constraints[constraintId];
    }

    function getPolicy(
        bytes32 policyId
    ) external view returns (IndifferentPolicy memory) {
        return policies[policyId];
    }

    function getPolicyConstraints(
        bytes32 policyId
    ) external view returns (bytes32[] memory) {
        return policyConstraints[policyId];
    }

    function getClaim(
        bytes32 claimId
    ) external view returns (PolicyClaim memory) {
        return claims[claimId];
    }

    function getEvaluation(
        bytes32 evaluationId
    ) external view returns (EvaluationResult memory) {
        return evaluations[evaluationId];
    }

    function getEnvelope(
        bytes32 envelopeId
    ) external view returns (UniversalProofEnvelope memory) {
        return envelopes[envelopeId];
    }

    function getMetrics()
        external
        view
        returns (
            uint256 _totalPolicies,
            uint256 _totalClaims,
            uint256 _totalEvaluations,
            uint256 _totalCompliant,
            uint256 _totalBlocked
        )
    {
        return (
            totalPolicies,
            totalClaims,
            totalEvaluations,
            totalCompliant,
            totalBlocked
        );
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function deactivatePolicy(
        bytes32 policyId
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        policies[policyId].active = false;
        policies[policyId].updatedAt = uint64(block.timestamp);
    }

    function deactivateConstraint(
        bytes32 constraintId
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        constraints[constraintId].active = false;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
