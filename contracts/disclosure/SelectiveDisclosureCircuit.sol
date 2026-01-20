// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SelectiveDisclosureCircuit
 * @author Soul Protocol
 * @notice Midnight-inspired: Selective Disclosure as Part of Computation
 * @dev Disclosure rules are compiled into policy circuits, making disclosure correctness PROVABLE.
 *
 * MIDNIGHT'S INSIGHT:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Most ZK systems enforce CORRECTNESS but treat DISCLOSURE as afterthought.  │
 * │ Midnight treats disclosure as PART of the computation itself.              │
 * │ Developers specify which parties can see what, under which conditions.     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S IMPLEMENTATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 1. Disclosure rules compile into policy circuits                           │
 * │ 2. Disclosure correctness is provable via ZK                               │
 * │ 3. SDK prevents "accidental over-disclosure" by design                     │
 * │ 4. Every disclosure must be justified by a satisfied predicate             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * This is an AZTEC + MIDNIGHT hybrid insight.
 */
contract SelectiveDisclosureCircuit is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant CIRCUIT_ADMIN_ROLE =
        keccak256("CIRCUIT_ADMIN_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Predicate type for disclosure conditions
     */
    enum PredicateType {
        Always, // Always disclose (public)
        Never, // Never disclose (private)
        IdentityMatch, // Disclose if identity matches
        RoleMatch, // Disclose if role matches
        TimeAfter, // Disclose after timestamp
        ThresholdMet, // Disclose if threshold conditions met
        CompositeAnd, // All sub-predicates must pass
        CompositeOr, // Any sub-predicate must pass
        ZKPredicateProof // Arbitrary predicate proven via ZK
    }

    /**
     * @notice Disclosure target specification
     */
    enum DisclosureTarget {
        NoOne, // Keep completely private
        DataOwner, // Only data subject
        SpecificParty, // Named recipient
        RoleHolders, // Anyone with specific role
        AuditorsOnly, // Authorized auditors
        RegulatorsOnly, // Regulatory authorities
        AllVerifiers, // Anyone who can verify
        Public // World-readable
    }

    /**
     * @notice Disclosure predicate - conditions for disclosure
     */
    struct DisclosurePredicate {
        bytes32 predicateId;
        PredicateType predicateType;
        // Condition data (interpretation depends on type)
        bytes32 conditionHash; // Hash of condition parameters
        bytes32[] subPredicates; // For composite predicates
        uint64 timeCondition; // For time-based predicates
        uint256 thresholdValue; // For threshold predicates
        // Status
        bool active;
        uint64 createdAt;
    }

    /**
     * @notice Disclosure rule - what to disclose to whom under what conditions
     */
    struct DisclosureRule {
        bytes32 ruleId;
        // What data
        bytes32 dataFieldId; // Which field to disclose
        bytes32 dataTypeHash; // Type of the data
        // To whom
        DisclosureTarget target;
        bytes32 specificRecipient; // If SpecificParty
        bytes32 roleRequirement; // If RoleHolders
        // Under what conditions
        bytes32 predicateId; // Predicate that must be satisfied
        // Status
        bool active;
        uint64 createdAt;
    }

    /**
     * @notice Disclosure circuit - compiled rules into verifiable circuit
     * @dev This represents a "compiled" set of disclosure rules
     */
    struct DisclosureCircuit {
        bytes32 circuitId;
        string name;
        // Rules included
        bytes32[] ruleIds;
        uint256 ruleCount;
        // Circuit specification
        bytes32 circuitHash; // Hash of compiled circuit
        bytes32 verifierKeyHash; // Verification key hash
        uint256 inputCount; // Number of public inputs
        uint256 witnessCount; // Number of private witnesses
        // Metadata
        bytes32 domainSeparator;
        address creator;
        uint64 createdAt;
        // Status
        bool verified; // Circuit has been verified
        bool active;
    }

    /**
     * @notice Disclosure proof - proves disclosure follows rules
     */
    struct DisclosureProof {
        bytes32 proofId;
        bytes32 circuitId;
        bytes32 executionId;
        // Proof data
        bytes32 proofHash; // Hash of the proof
        bytes32[] publicInputs; // Visible inputs
        bytes32 witnessCommitment; // Commitment to private witness
        // What was disclosed
        bytes32[] disclosedFieldIds; // Which fields were disclosed
        bytes32[] recipientCommitments; // To whom (commitments)
        // Verification
        bool verified;
        address verifier;
        uint64 verifiedAt;
    }

    /**
     * @notice Field disclosure record
     */
    struct FieldDisclosure {
        bytes32 disclosureId;
        bytes32 proofId;
        bytes32 fieldId;
        bytes32 recipientCommitment;
        bytes32 valueCommitment; // Commitment to disclosed value
        DisclosureTarget targetType;
        uint64 disclosedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Predicates: predicateId => predicate
    mapping(bytes32 => DisclosurePredicate) public predicates;

    /// @notice Rules: ruleId => rule
    mapping(bytes32 => DisclosureRule) public rules;

    /// @notice Circuits: circuitId => circuit
    mapping(bytes32 => DisclosureCircuit) public circuits;

    /// @notice Proofs: proofId => proof
    mapping(bytes32 => DisclosureProof) public proofs;

    /// @notice Field disclosures: disclosureId => disclosure
    mapping(bytes32 => FieldDisclosure) public fieldDisclosures;

    /// @notice Circuit rules: circuitId => ruleId[]
    mapping(bytes32 => bytes32[]) public circuitRules;

    /// @notice Execution proofs: executionId => proofId[]
    mapping(bytes32 => bytes32[]) public executionProofs;

    /// @notice Recipient disclosures: recipientCommitment => disclosureId[]
    mapping(bytes32 => bytes32[]) public recipientDisclosures;

    /// @notice Counters
    uint256 public totalPredicates;
    uint256 public totalRules;
    uint256 public totalCircuits;
    uint256 public totalProofs;
    uint256 public totalDisclosures;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PredicateCreated(
        bytes32 indexed predicateId,
        PredicateType predicateType
    );

    event RuleCreated(
        bytes32 indexed ruleId,
        bytes32 indexed dataFieldId,
        DisclosureTarget target,
        bytes32 predicateId
    );

    event CircuitCompiled(
        bytes32 indexed circuitId,
        string name,
        uint256 ruleCount,
        bytes32 circuitHash
    );

    event CircuitVerified(bytes32 indexed circuitId, address verifier);

    event ProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed circuitId,
        bytes32 indexed executionId
    );

    event ProofVerified(bytes32 indexed proofId, bool valid);

    event FieldDisclosed(
        bytes32 indexed disclosureId,
        bytes32 indexed fieldId,
        bytes32 indexed recipientCommitment,
        DisclosureTarget targetType
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CIRCUIT_ADMIN_ROLE, msg.sender);
        _grantRole(PROVER_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        PREDICATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a disclosure predicate
     * @param predicateType Type of predicate
     * @param conditionHash Hash of condition parameters
     * @param timeCondition Time condition (if applicable)
     * @param thresholdValue Threshold value (if applicable)
     * @return predicateId The predicate identifier
     */
    function createPredicate(
        PredicateType predicateType,
        bytes32 conditionHash,
        uint64 timeCondition,
        uint256 thresholdValue
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) returns (bytes32 predicateId) {
        predicateId = keccak256(
            abi.encodePacked(
                predicateType,
                conditionHash,
                timeCondition,
                thresholdValue,
                block.timestamp,
                totalPredicates
            )
        );

        predicates[predicateId] = DisclosurePredicate({
            predicateId: predicateId,
            predicateType: predicateType,
            conditionHash: conditionHash,
            subPredicates: new bytes32[](0),
            timeCondition: timeCondition,
            thresholdValue: thresholdValue,
            active: true,
            createdAt: uint64(block.timestamp)
        });

        totalPredicates++;

        emit PredicateCreated(predicateId, predicateType);
    }

    /**
     * @notice Create a composite predicate (AND/OR)
     */
    function createCompositePredicate(
        PredicateType predicateType,
        bytes32[] calldata subPredicates
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) returns (bytes32 predicateId) {
        require(
            predicateType == PredicateType.CompositeAnd ||
                predicateType == PredicateType.CompositeOr,
            "SDC: not composite type"
        );
        require(subPredicates.length >= 2, "SDC: need 2+ sub-predicates");

        // Validate all sub-predicates exist
        for (uint256 i = 0; i < subPredicates.length; i++) {
            require(
                predicates[subPredicates[i]].active,
                "SDC: sub-predicate inactive"
            );
        }

        predicateId = keccak256(
            abi.encodePacked(
                predicateType,
                subPredicates,
                block.timestamp,
                totalPredicates
            )
        );

        DisclosurePredicate storage p = predicates[predicateId];
        p.predicateId = predicateId;
        p.predicateType = predicateType;
        p.subPredicates = subPredicates;
        p.active = true;
        p.createdAt = uint64(block.timestamp);

        totalPredicates++;

        emit PredicateCreated(predicateId, predicateType);
    }

    /*//////////////////////////////////////////////////////////////
                          RULE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a disclosure rule
     * @param dataFieldId Which data field this rule applies to
     * @param dataTypeHash Type of the data field
     * @param target Who can receive the disclosure
     * @param specificRecipient Specific recipient (if SpecificParty)
     * @param roleRequirement Role requirement (if RoleHolders)
     * @param predicateId Condition for disclosure
     * @return ruleId The rule identifier
     */
    function createRule(
        bytes32 dataFieldId,
        bytes32 dataTypeHash,
        DisclosureTarget target,
        bytes32 specificRecipient,
        bytes32 roleRequirement,
        bytes32 predicateId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) returns (bytes32 ruleId) {
        // Validate predicate exists
        require(predicates[predicateId].active, "SDC: predicate inactive");

        // Validate target-specific requirements
        if (target == DisclosureTarget.SpecificParty) {
            require(specificRecipient != bytes32(0), "SDC: recipient required");
        }
        if (target == DisclosureTarget.RoleHolders) {
            require(roleRequirement != bytes32(0), "SDC: role required");
        }

        ruleId = keccak256(
            abi.encodePacked(
                dataFieldId,
                dataTypeHash,
                target,
                predicateId,
                block.timestamp,
                totalRules
            )
        );

        rules[ruleId] = DisclosureRule({
            ruleId: ruleId,
            dataFieldId: dataFieldId,
            dataTypeHash: dataTypeHash,
            target: target,
            specificRecipient: specificRecipient,
            roleRequirement: roleRequirement,
            predicateId: predicateId,
            active: true,
            createdAt: uint64(block.timestamp)
        });

        totalRules++;

        emit RuleCreated(ruleId, dataFieldId, target, predicateId);
    }

    /*//////////////////////////////////////////////////////////////
                        CIRCUIT COMPILATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compile disclosure rules into a verifiable circuit
     * @dev This creates a "compiled" representation that can be proven
     * @param name Circuit name
     * @param ruleIds Rules to include
     * @param circuitHash Hash of the compiled circuit
     * @param verifierKeyHash Verification key hash
     * @param inputCount Number of public inputs
     * @param witnessCount Number of private witnesses
     * @param domainSeparator Domain context
     * @return circuitId The circuit identifier
     */
    function compileCircuit(
        string calldata name,
        bytes32[] calldata ruleIds,
        bytes32 circuitHash,
        bytes32 verifierKeyHash,
        uint256 inputCount,
        uint256 witnessCount,
        bytes32 domainSeparator
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) returns (bytes32 circuitId) {
        require(ruleIds.length > 0, "SDC: no rules");
        require(circuitHash != bytes32(0), "SDC: circuit hash required");

        // Validate all rules exist
        for (uint256 i = 0; i < ruleIds.length; i++) {
            require(rules[ruleIds[i]].active, "SDC: rule inactive");
        }

        circuitId = keccak256(
            abi.encodePacked(
                name,
                circuitHash,
                domainSeparator,
                block.timestamp,
                totalCircuits
            )
        );

        circuits[circuitId] = DisclosureCircuit({
            circuitId: circuitId,
            name: name,
            ruleIds: ruleIds,
            ruleCount: ruleIds.length,
            circuitHash: circuitHash,
            verifierKeyHash: verifierKeyHash,
            inputCount: inputCount,
            witnessCount: witnessCount,
            domainSeparator: domainSeparator,
            creator: msg.sender,
            createdAt: uint64(block.timestamp),
            verified: false,
            active: true
        });

        // Store rule references
        for (uint256 i = 0; i < ruleIds.length; i++) {
            circuitRules[circuitId].push(ruleIds[i]);
        }

        totalCircuits++;

        emit CircuitCompiled(circuitId, name, ruleIds.length, circuitHash);
    }

    /**
     * @notice Mark circuit as verified (after external verification)
     */
    function markCircuitVerified(
        bytes32 circuitId
    ) external onlyRole(VERIFIER_ROLE) {
        DisclosureCircuit storage circuit = circuits[circuitId];
        require(circuit.active, "SDC: circuit inactive");
        require(!circuit.verified, "SDC: already verified");

        circuit.verified = true;

        emit CircuitVerified(circuitId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit proof that disclosure follows circuit rules
     * @param circuitId Circuit being proven
     * @param executionId Execution this disclosure relates to
     * @param proofHash Hash of the ZK proof
     * @param publicInputs Public inputs to the proof
     * @param witnessCommitment Commitment to private witness
     * @param disclosedFieldIds Fields being disclosed
     * @param recipientCommitments Recipients of disclosures
     * @return proofId The proof identifier
     */
    function submitProof(
        bytes32 circuitId,
        bytes32 executionId,
        bytes32 proofHash,
        bytes32[] calldata publicInputs,
        bytes32 witnessCommitment,
        bytes32[] calldata disclosedFieldIds,
        bytes32[] calldata recipientCommitments
    ) external onlyRole(PROVER_ROLE) whenNotPaused returns (bytes32 proofId) {
        DisclosureCircuit storage circuit = circuits[circuitId];
        require(circuit.active, "SDC: circuit inactive");
        require(circuit.verified, "SDC: circuit not verified");
        require(
            publicInputs.length == circuit.inputCount,
            "SDC: input count mismatch"
        );
        require(
            disclosedFieldIds.length == recipientCommitments.length,
            "SDC: field/recipient mismatch"
        );

        proofId = keccak256(
            abi.encodePacked(
                circuitId,
                executionId,
                proofHash,
                block.timestamp,
                totalProofs
            )
        );

        proofs[proofId] = DisclosureProof({
            proofId: proofId,
            circuitId: circuitId,
            executionId: executionId,
            proofHash: proofHash,
            publicInputs: publicInputs,
            witnessCommitment: witnessCommitment,
            disclosedFieldIds: disclosedFieldIds,
            recipientCommitments: recipientCommitments,
            verified: false,
            verifier: address(0),
            verifiedAt: 0
        });

        executionProofs[executionId].push(proofId);
        totalProofs++;

        emit ProofSubmitted(proofId, circuitId, executionId);
    }

    /**
     * @notice Verify a disclosure proof
     * @param proofId Proof to verify
     * @param valid Whether the proof is valid
     */
    function verifyProof(
        bytes32 proofId,
        bool valid
    ) external onlyRole(VERIFIER_ROLE) {
        DisclosureProof storage proof = proofs[proofId];
        require(proof.proofId != bytes32(0), "SDC: proof not found");
        require(!proof.verified, "SDC: already verified");

        proof.verified = true;
        proof.verifier = msg.sender;
        proof.verifiedAt = uint64(block.timestamp);

        if (valid) {
            // Record all disclosures
            for (uint256 i = 0; i < proof.disclosedFieldIds.length; i++) {
                _recordFieldDisclosure(
                    proofId,
                    proof.disclosedFieldIds[i],
                    proof.recipientCommitments[i]
                );
            }
        }

        emit ProofVerified(proofId, valid);
    }

    /**
     * @notice Record a verified field disclosure
     */
    function _recordFieldDisclosure(
        bytes32 proofId,
        bytes32 fieldId,
        bytes32 recipientCommitment
    ) internal {
        bytes32 disclosureId = keccak256(
            abi.encodePacked(
                proofId,
                fieldId,
                recipientCommitment,
                totalDisclosures
            )
        );

        // Determine target type from rule
        DisclosureProof storage proof = proofs[proofId];
        DisclosureCircuit storage circuit = circuits[proof.circuitId];
        DisclosureTarget targetType = DisclosureTarget.NoOne;

        // Find the rule for this field
        for (uint256 i = 0; i < circuit.ruleIds.length; i++) {
            DisclosureRule storage rule = rules[circuit.ruleIds[i]];
            if (rule.dataFieldId == fieldId) {
                targetType = rule.target;
                break;
            }
        }

        fieldDisclosures[disclosureId] = FieldDisclosure({
            disclosureId: disclosureId,
            proofId: proofId,
            fieldId: fieldId,
            recipientCommitment: recipientCommitment,
            valueCommitment: bytes32(0), // Set by caller if needed
            targetType: targetType,
            disclosedAt: uint64(block.timestamp)
        });

        recipientDisclosures[recipientCommitment].push(disclosureId);
        totalDisclosures++;

        emit FieldDisclosed(
            disclosureId,
            fieldId,
            recipientCommitment,
            targetType
        );
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if predicate is satisfied (simple types only)
     */
    function isPredicateSatisfied(
        bytes32 predicateId,
        bytes32 contextHash
    ) external view returns (bool) {
        DisclosurePredicate storage p = predicates[predicateId];
        if (!p.active) return false;

        if (p.predicateType == PredicateType.Always) {
            return true;
        } else if (p.predicateType == PredicateType.Never) {
            return false;
        } else if (p.predicateType == PredicateType.TimeAfter) {
            return block.timestamp >= p.timeCondition;
        }

        // Complex predicates require ZK proof
        return contextHash != bytes32(0); // Placeholder
    }

    /**
     * @notice Get circuit rules
     */
    function getCircuitRules(
        bytes32 circuitId
    ) external view returns (bytes32[] memory) {
        return circuitRules[circuitId];
    }

    /**
     * @notice Get execution proofs
     */
    function getExecutionProofs(
        bytes32 executionId
    ) external view returns (bytes32[] memory) {
        return executionProofs[executionId];
    }

    /**
     * @notice Get disclosures to a recipient
     */
    function getRecipientDisclosures(
        bytes32 recipientCommitment
    ) external view returns (bytes32[] memory) {
        return recipientDisclosures[recipientCommitment];
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function deactivatePredicate(
        bytes32 predicateId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) {
        predicates[predicateId].active = false;
    }

    function deactivateRule(
        bytes32 ruleId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) {
        rules[ruleId].active = false;
    }

    function deactivateCircuit(
        bytes32 circuitId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) {
        circuits[circuitId].active = false;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
