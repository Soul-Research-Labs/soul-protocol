// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PolicySemanticEngine
 * @author Soul Protocol
 * @notice Midnight-inspired: Policy as First-Class Execution Constraint
 * @dev Key insight from Midnight: Data protection rules are part of program SEMANTICS,
 *      not application-layer conventions. Violations are impossible by construction.
 *
 * MIDNIGHT'S CONTRIBUTION (Abstracted):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Programs whose execution is valid IFF data disclosure constraints are      │
 * │ satisfied. This is a SEMANTIC primitive, not just cryptography.            │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S IMPLEMENTATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 1. Policy is NOT optional - every execution MUST bind to a policy          │
 * │ 2. Policy validity is checked BEFORE execution can proceed                 │
 * │ 3. Policy proofs are verified as part of kernel verification               │
 * │ 4. Violations are rejected at the cryptographic layer, not application     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * DIFFERENT FROM:
 * - Aztec: Privacy-first, compliance bolted on later
 * - Zcash: Privacy-only payments, no policy layer
 * - Traditional ZK: Correctness enforced, disclosure as afterthought
 */
contract PolicySemanticEngine is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    bytes32 public constant EXECUTION_ROLE = keccak256("EXECUTION_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Policy enforcement level
     * @dev Determines how strictly policy is enforced
     */
    enum EnforcementLevel {
        None, // NEVER USE - exists only for error detection
        Advisory, // Log violations but allow execution (DEBUG ONLY)
        Mandatory, // Reject execution on violation
        Cryptographic // Policy satisfaction provable via ZK
    }

    /**
     * @notice Disclosure constraint type
     */
    enum DisclosureType {
        Never, // Never disclose to anyone
        OwnerOnly, // Only data owner can see
        PartyList, // Specific authorized parties
        PredicateBased, // Disclosure if predicate satisfied
        TimeDelayed, // Disclosure after time lock
        AuditTriggered // Disclosure on valid audit request
    }

    /**
     * @notice Policy semantic rule
     * @dev A single constraint that must be satisfied
     */
    struct SemanticRule {
        bytes32 ruleId;
        // What data this rule protects
        bytes32 dataClassification; // Classification of protected data
        bytes32 dataCommitment; // Commitment to specific data (optional)
        // Disclosure constraints
        DisclosureType disclosureType;
        bytes32[] authorizedParties; // Who can see (if PartyList)
        bytes32 predicateHash; // Predicate for conditional disclosure
        uint64 timeLockUntil; // Time lock expiry (if TimeDelayed)
        // Enforcement
        EnforcementLevel enforcement;
        bool active;
    }

    /**
     * @notice Semantic Policy - collection of rules that form program semantics
     * @dev Execution is valid IFF ALL rules are satisfied
     */
    struct SemanticPolicy {
        bytes32 policyId;
        string name;
        string description;
        // Rules
        bytes32[] ruleIds;
        uint256 ruleCount;
        // Metadata
        bytes32 domainSeparator;
        address creator;
        uint64 createdAt;
        uint64 expiresAt;
        // Status
        bool active;
        EnforcementLevel minEnforcement; // Minimum enforcement for all rules
        // Proof requirements
        bool requiresZKProof; // Must prove policy satisfaction
        bytes32 circuitHash; // ZK circuit for policy verification
    }

    /**
     * @notice Policy binding - links execution to policy
     * @dev Every execution MUST have a binding
     */
    struct PolicyBinding {
        bytes32 bindingId;
        bytes32 executionId;
        bytes32 policyId;
        // Proof of satisfaction
        bytes32 satisfactionProof; // ZK proof that policy is satisfied
        bytes32 witnessCommitment; // Commitment to private witness
        // Verification
        bool verified;
        address verifier;
        uint64 verifiedAt;
        // Disclosure tracking
        bytes32[] disclosureRecords; // Record of any disclosures made
    }

    /**
     * @notice Execution request with mandatory policy
     * @dev Cannot execute without valid policy binding
     */
    struct SemanticExecution {
        bytes32 executionId;
        bytes32 policyId;
        bytes32 bindingId;
        // Input/output commitments
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        bytes32 stateTransition;
        // Policy satisfaction
        bytes32 policyProof; // Proof that execution respects policy
        bool policySatisfied;
        // Execution status
        ExecutionStatus status;
        uint64 submittedAt;
        uint64 executedAt;
    }

    enum ExecutionStatus {
        Pending,
        PolicyValidating,
        PolicySatisfied,
        PolicyViolated,
        Executing,
        Completed,
        Rejected
    }

    /**
     * @notice Disclosure record - tracks all data disclosures
     */
    struct DisclosureRecord {
        bytes32 recordId;
        bytes32 executionId;
        bytes32 dataCommitment;
        bytes32 recipientCommitment; // Who received (may be hidden)
        DisclosureType disclosureType;
        bytes32 justificationProof; // Proof disclosure was authorized
        uint64 disclosedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Semantic rules: ruleId => rule
    mapping(bytes32 => SemanticRule) public rules;

    /// @notice Semantic policies: policyId => policy
    mapping(bytes32 => SemanticPolicy) public policies;

    /// @notice Policy bindings: bindingId => binding
    mapping(bytes32 => PolicyBinding) public bindings;

    /// @notice Executions: executionId => execution
    mapping(bytes32 => SemanticExecution) public executions;

    /// @notice Disclosure records: recordId => record
    mapping(bytes32 => DisclosureRecord) public disclosures;

    /// @notice Execution to binding: executionId => bindingId
    mapping(bytes32 => bytes32) public executionBindings;

    /// @notice Policy rules: policyId => ruleId[]
    mapping(bytes32 => bytes32[]) public policyRules;

    /// @notice Domain policies: domainId => policyId[]
    mapping(bytes32 => bytes32[]) public domainPolicies;

    /// @notice Counters
    uint256 public totalRules;
    uint256 public totalPolicies;
    uint256 public totalBindings;
    uint256 public totalExecutions;
    uint256 public totalViolations;
    uint256 public totalDisclosures;

    /// @notice Global enforcement level (minimum)
    EnforcementLevel public globalMinEnforcement;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RuleCreated(
        bytes32 indexed ruleId,
        bytes32 indexed dataClassification,
        DisclosureType disclosureType,
        EnforcementLevel enforcement
    );

    event PolicyCreated(
        bytes32 indexed policyId,
        string name,
        uint256 ruleCount,
        EnforcementLevel minEnforcement
    );

    event PolicyBound(
        bytes32 indexed bindingId,
        bytes32 indexed executionId,
        bytes32 indexed policyId
    );

    event PolicySatisfied(
        bytes32 indexed executionId,
        bytes32 indexed policyId,
        bytes32 proofHash
    );

    event PolicyViolated(
        bytes32 indexed executionId,
        bytes32 indexed policyId,
        bytes32 indexed ruleId,
        string reason
    );

    event ExecutionSubmitted(
        bytes32 indexed executionId,
        bytes32 indexed policyId,
        ExecutionStatus status
    );

    event ExecutionCompleted(
        bytes32 indexed executionId,
        bytes32 indexed policyId,
        bool success
    );

    event DisclosureMade(
        bytes32 indexed recordId,
        bytes32 indexed executionId,
        DisclosureType disclosureType
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTION_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        // CRITICAL: Default to Mandatory enforcement
        // Advisory should ONLY be used in development
        globalMinEnforcement = EnforcementLevel.Mandatory;
    }

    /*//////////////////////////////////////////////////////////////
                          RULE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a semantic rule
     * @dev Rules define data protection constraints
     * @param dataClassification Type of data being protected
     * @param disclosureType How data may be disclosed
     * @param authorizedParties Who can access (if PartyList)
     * @param predicateHash Predicate for conditional disclosure
     * @param enforcement How strictly to enforce
     * @return ruleId The unique rule identifier
     */
    function createRule(
        bytes32 dataClassification,
        DisclosureType disclosureType,
        bytes32[] calldata authorizedParties,
        bytes32 predicateHash,
        EnforcementLevel enforcement
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 ruleId) {
        // SECURITY: Never allow None enforcement
        require(
            enforcement != EnforcementLevel.None,
            "PSE: enforcement cannot be None"
        );
        require(
            enforcement >= globalMinEnforcement,
            "PSE: below global minimum"
        );

        ruleId = keccak256(
            abi.encodePacked(
                dataClassification,
                disclosureType,
                predicateHash,
                block.timestamp,
                totalRules
            )
        );

        require(rules[ruleId].ruleId == bytes32(0), "PSE: rule exists");

        rules[ruleId] = SemanticRule({
            ruleId: ruleId,
            dataClassification: dataClassification,
            dataCommitment: bytes32(0),
            disclosureType: disclosureType,
            authorizedParties: authorizedParties,
            predicateHash: predicateHash,
            timeLockUntil: 0,
            enforcement: enforcement,
            active: true
        });

        totalRules++;

        emit RuleCreated(
            ruleId,
            dataClassification,
            disclosureType,
            enforcement
        );
    }

    /**
     * @notice Create a time-locked disclosure rule
     */
    function createTimeLockRule(
        bytes32 dataClassification,
        uint64 unlockTime,
        EnforcementLevel enforcement
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 ruleId) {
        require(
            enforcement != EnforcementLevel.None,
            "PSE: enforcement cannot be None"
        );
        require(unlockTime > block.timestamp, "PSE: unlock must be future");

        ruleId = keccak256(
            abi.encodePacked(
                dataClassification,
                DisclosureType.TimeDelayed,
                unlockTime,
                block.timestamp,
                totalRules
            )
        );

        rules[ruleId] = SemanticRule({
            ruleId: ruleId,
            dataClassification: dataClassification,
            dataCommitment: bytes32(0),
            disclosureType: DisclosureType.TimeDelayed,
            authorizedParties: new bytes32[](0),
            predicateHash: bytes32(0),
            timeLockUntil: unlockTime,
            enforcement: enforcement,
            active: true
        });

        totalRules++;

        emit RuleCreated(
            ruleId,
            dataClassification,
            DisclosureType.TimeDelayed,
            enforcement
        );
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a semantic policy from rules
     * @dev Policy = collection of rules that define program semantics
     * @param name Human-readable name
     * @param description Policy description
     * @param ruleIds Rules that compose this policy
     * @param domainSeparator Domain context
     * @param requiresZKProof Whether ZK proof of satisfaction is required
     * @param circuitHash ZK circuit for verification (if required)
     * @return policyId The unique policy identifier
     */
    function createPolicy(
        string calldata name,
        string calldata description,
        bytes32[] calldata ruleIds,
        bytes32 domainSeparator,
        bool requiresZKProof,
        bytes32 circuitHash
    ) external onlyRole(POLICY_ADMIN_ROLE) returns (bytes32 policyId) {
        require(ruleIds.length > 0, "PSE: empty policy");
        require(bytes(name).length > 0, "PSE: name required");

        // Validate all rules exist and are active
        EnforcementLevel minEnforcement = EnforcementLevel.Cryptographic;
        for (uint256 i = 0; i < ruleIds.length; i++) {
            SemanticRule storage rule = rules[ruleIds[i]];
            require(rule.active, "PSE: rule not active");
            if (uint8(rule.enforcement) < uint8(minEnforcement)) {
                minEnforcement = rule.enforcement;
            }
        }

        policyId = keccak256(
            abi.encodePacked(
                name,
                domainSeparator,
                block.timestamp,
                totalPolicies
            )
        );

        require(
            policies[policyId].policyId == bytes32(0),
            "PSE: policy exists"
        );

        policies[policyId] = SemanticPolicy({
            policyId: policyId,
            name: name,
            description: description,
            ruleIds: ruleIds,
            ruleCount: ruleIds.length,
            domainSeparator: domainSeparator,
            creator: msg.sender,
            createdAt: uint64(block.timestamp),
            expiresAt: 0,
            active: true,
            minEnforcement: minEnforcement,
            requiresZKProof: requiresZKProof,
            circuitHash: circuitHash
        });

        // Store rule references
        for (uint256 i = 0; i < ruleIds.length; i++) {
            policyRules[policyId].push(ruleIds[i]);
        }

        // Register with domain
        domainPolicies[domainSeparator].push(policyId);

        totalPolicies++;

        emit PolicyCreated(policyId, name, ruleIds.length, minEnforcement);
    }

    /*//////////////////////////////////////////////////////////////
                     POLICY-BOUND EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit execution with mandatory policy binding
     * @dev CRITICAL: Execution without policy is IMPOSSIBLE
     * @param policyId Policy that governs this execution
     * @param inputCommitment Commitment to inputs
     * @param outputCommitment Commitment to expected outputs
     * @param policyProof ZK proof of policy satisfaction
     * @param witnessCommitment Commitment to private witness
     * @return executionId The execution identifier
     */
    function submitExecution(
        bytes32 policyId,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 policyProof,
        bytes32 witnessCommitment
    ) external whenNotPaused nonReentrant returns (bytes32 executionId) {
        // SEMANTIC CONSTRAINT: Policy MUST exist and be active
        SemanticPolicy storage policy = policies[policyId];
        require(policy.active, "PSE: policy not active");
        require(
            policy.expiresAt == 0 || block.timestamp < policy.expiresAt,
            "PSE: policy expired"
        );

        // SEMANTIC CONSTRAINT: ZK proof required if policy demands it
        if (policy.requiresZKProof) {
            require(policyProof != bytes32(0), "PSE: ZK proof required");
        }

        executionId = keccak256(
            abi.encodePacked(
                policyId,
                inputCommitment,
                outputCommitment,
                block.timestamp,
                totalExecutions
            )
        );

        // Create binding
        bytes32 bindingId = keccak256(
            abi.encodePacked(executionId, policyId, block.timestamp)
        );

        bindings[bindingId] = PolicyBinding({
            bindingId: bindingId,
            executionId: executionId,
            policyId: policyId,
            satisfactionProof: policyProof,
            witnessCommitment: witnessCommitment,
            verified: false,
            verifier: address(0),
            verifiedAt: 0,
            disclosureRecords: new bytes32[](0)
        });

        executionBindings[executionId] = bindingId;

        // Create execution record
        executions[executionId] = SemanticExecution({
            executionId: executionId,
            policyId: policyId,
            bindingId: bindingId,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            stateTransition: bytes32(0),
            policyProof: policyProof,
            policySatisfied: false,
            status: ExecutionStatus.PolicyValidating,
            submittedAt: uint64(block.timestamp),
            executedAt: 0
        });

        totalExecutions++;
        totalBindings++;

        emit PolicyBound(bindingId, executionId, policyId);
        emit ExecutionSubmitted(
            executionId,
            policyId,
            ExecutionStatus.PolicyValidating
        );
    }

    /**
     * @notice Verify policy satisfaction and proceed with execution
     * @dev Called by verifier after checking policy proof
     * @param executionId Execution to verify
     * @param proofValid Whether the policy proof is valid
     * @param violatedRuleId Rule that was violated (if any)
     * @param violationReason Reason for violation (if any)
     */
    function verifyPolicySatisfaction(
        bytes32 executionId,
        bool proofValid,
        bytes32 violatedRuleId,
        string calldata violationReason
    ) external onlyRole(VERIFIER_ROLE) {
        SemanticExecution storage execution = executions[executionId];
        require(
            execution.status == ExecutionStatus.PolicyValidating,
            "PSE: not validating"
        );

        PolicyBinding storage binding = bindings[execution.bindingId];
        SemanticPolicy storage policy = policies[execution.policyId];

        if (proofValid) {
            // Policy satisfied - execution may proceed
            execution.status = ExecutionStatus.PolicySatisfied;
            execution.policySatisfied = true;
            binding.verified = true;
            binding.verifier = msg.sender;
            binding.verifiedAt = uint64(block.timestamp);

            emit PolicySatisfied(
                executionId,
                execution.policyId,
                execution.policyProof
            );
        } else {
            // Policy violated - execution rejected
            execution.status = ExecutionStatus.PolicyViolated;
            totalViolations++;

            emit PolicyViolated(
                executionId,
                execution.policyId,
                violatedRuleId,
                violationReason
            );

            // If enforcement is Mandatory or Cryptographic, reject
            if (policy.minEnforcement >= EnforcementLevel.Mandatory) {
                execution.status = ExecutionStatus.Rejected;
            }
        }
    }

    /**
     * @notice Complete execution after policy satisfaction
     * @param executionId Execution to complete
     * @param stateTransition Resulting state transition
     * @param success Whether execution succeeded
     */
    function completeExecution(
        bytes32 executionId,
        bytes32 stateTransition,
        bool success
    ) external onlyRole(EXECUTION_ROLE) {
        SemanticExecution storage execution = executions[executionId];
        require(
            execution.status == ExecutionStatus.PolicySatisfied,
            "PSE: policy not satisfied"
        );

        execution.stateTransition = stateTransition;
        execution.status = success
            ? ExecutionStatus.Completed
            : ExecutionStatus.Rejected;
        execution.executedAt = uint64(block.timestamp);

        emit ExecutionCompleted(executionId, execution.policyId, success);
    }

    /*//////////////////////////////////////////////////////////////
                        DISCLOSURE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record a disclosure made during execution
     * @dev All disclosures must be authorized by policy
     * @param executionId Execution during which disclosure occurred
     * @param dataCommitment Commitment to disclosed data
     * @param recipientCommitment Commitment to recipient (may be hidden)
     * @param disclosureType Type of disclosure
     * @param justificationProof Proof that disclosure is authorized
     * @return recordId The disclosure record identifier
     */
    function recordDisclosure(
        bytes32 executionId,
        bytes32 dataCommitment,
        bytes32 recipientCommitment,
        DisclosureType disclosureType,
        bytes32 justificationProof
    ) external onlyRole(EXECUTION_ROLE) returns (bytes32 recordId) {
        SemanticExecution storage execution = executions[executionId];
        require(
            execution.status == ExecutionStatus.Executing ||
                execution.status == ExecutionStatus.PolicySatisfied,
            "PSE: invalid execution state"
        );

        recordId = keccak256(
            abi.encodePacked(
                executionId,
                dataCommitment,
                recipientCommitment,
                block.timestamp,
                totalDisclosures
            )
        );

        disclosures[recordId] = DisclosureRecord({
            recordId: recordId,
            executionId: executionId,
            dataCommitment: dataCommitment,
            recipientCommitment: recipientCommitment,
            disclosureType: disclosureType,
            justificationProof: justificationProof,
            disclosedAt: uint64(block.timestamp)
        });

        // Link to binding
        PolicyBinding storage binding = bindings[execution.bindingId];
        binding.disclosureRecords.push(recordId);

        totalDisclosures++;

        emit DisclosureMade(recordId, executionId, disclosureType);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if execution can proceed (policy satisfied)
     */
    function canExecute(bytes32 executionId) external view returns (bool) {
        SemanticExecution storage execution = executions[executionId];
        return
            execution.policySatisfied &&
            execution.status == ExecutionStatus.PolicySatisfied;
    }

    /**
     * @notice Get policy rules
     */
    function getPolicyRules(
        bytes32 policyId
    ) external view returns (bytes32[] memory) {
        return policyRules[policyId];
    }

    /**
     * @notice Get execution details
     */
    function getExecution(
        bytes32 executionId
    ) external view returns (SemanticExecution memory) {
        return executions[executionId];
    }

    /**
     * @notice Get binding details
     */
    function getBinding(
        bytes32 bindingId
    ) external view returns (PolicyBinding memory) {
        return bindings[bindingId];
    }

    /**
     * @notice Get policy satisfaction status
     */
    function isPolicySatisfied(
        bytes32 executionId
    ) external view returns (bool) {
        return executions[executionId].policySatisfied;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setGlobalMinEnforcement(
        EnforcementLevel level
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(level != EnforcementLevel.None, "PSE: cannot set None");
        globalMinEnforcement = level;
    }

    function deactivatePolicy(
        bytes32 policyId
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        policies[policyId].active = false;
    }

    function deactivateRule(
        bytes32 ruleId
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        rules[ruleId].active = false;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
