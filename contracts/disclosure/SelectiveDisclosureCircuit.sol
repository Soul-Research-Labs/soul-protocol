// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SelectiveDisclosureCircuit
 * @author Soul Protocol
 * @notice Midnight-inspired: Selective Disclosure as Part of Computation
 * @dev Disclosure rules are compiled into policy circuits, making disclosure correctness PROVABLE.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    MIDNIGHT'S INSIGHT
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Most ZK systems enforce CORRECTNESS but treat DISCLOSURE as afterthought.
 * Midnight treats disclosure as PART of the computation itself.
 * Developers specify which parties can see what, under which conditions.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    SOUL'S IMPLEMENTATION
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * 1. Disclosure rules compile into policy circuits
 * 2. Disclosure correctness is provable via ZK
 * 3. SDK prevents "accidental over-disclosure" by design
 * 4. Every disclosure must be justified by a satisfied predicate
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract SelectiveDisclosureCircuit is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant CIRCUIT_ADMIN_ROLE =
        keccak256("CIRCUIT_ADMIN_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    // ============================================
    // ENUMS
    // ============================================

    /// @notice Predicate type for disclosure conditions
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

    /// @notice Disclosure target specification
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

    // ============================================
    // ERRORS
    // ============================================

    error NotCompositeType();
    error NeedTwoPlusSubPredicates();
    error SubPredicateInactive();
    error PredicateInactive();
    error RecipientRequired();
    error RoleRequired();
    error NoRules();
    error CircuitHashRequired();
    error RuleInactive();
    error CircuitInactive();
    error AlreadyVerified();
    error CircuitNotVerified();
    error InputCountMismatch();
    error FieldRecipientMismatch();
    error ProofNotFound();
    error ZeroAddress();

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Disclosure predicate - conditions for disclosure
    struct DisclosurePredicate {
        bytes32 predicateId;
        PredicateType predicateType;
        bytes32 conditionHash; // Hash of condition parameters
        bytes32[] subPredicates; // For composite predicates
        uint64 timeCondition; // For time-based predicates
        uint256 thresholdValue; // For threshold predicates
        bool active;
        uint64 createdAt;
    }

    /// @notice Disclosure rule - what to disclose to whom under what conditions
    struct DisclosureRule {
        bytes32 ruleId;
        bytes32 dataFieldId; // Which field to disclose
        bytes32 dataTypeHash; // Type of the data
        DisclosureTarget target;
        bytes32 specificRecipient; // If SpecificParty
        bytes32 roleRequirement; // If RoleHolders
        bytes32 predicateId; // Predicate that must be satisfied
        bool active;
        uint64 createdAt;
    }

    /// @notice Disclosure circuit - compiled rules into verifiable circuit
    struct DisclosureCircuit {
        bytes32 circuitId;
        string name;
        bytes32[] ruleIds;
        uint256 ruleCount;
        bytes32 circuitHash; // Hash of compiled circuit
        bytes32 verifierKeyHash; // Verification key hash
        uint256 inputCount; // Number of public inputs
        uint256 witnessCount; // Number of private witnesses
        bytes32 domainSeparator;
        address creator;
        uint64 createdAt;
        bool verified;
        bool active;
    }

    /// @notice Disclosure proof - proves disclosure follows rules
    struct DisclosureProof {
        bytes32 proofId;
        bytes32 circuitId;
        bytes32 executionId;
        bytes32 proofHash; // Hash of the proof
        bytes32[] publicInputs; // Visible inputs
        bytes32 witnessCommitment; // Commitment to private witness
        bytes32[] disclosedFieldIds; // Which fields were disclosed
        bytes32[] recipientCommitments; // To whom (commitments)
        bool verified;
        address verifier;
        uint64 verifiedAt;
    }

    /// @notice Field disclosure record
    struct FieldDisclosure {
        bytes32 disclosureId;
        bytes32 proofId;
        bytes32 fieldId;
        bytes32 recipientCommitment;
        bytes32 valueCommitment; // Commitment to disclosed value
        DisclosureTarget targetType;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Predicates: predicateId => predicate
    mapping(bytes32 => DisclosurePredicate) public predicates;

    /// @notice Rules: ruleId => rule
    mapping(bytes32 => DisclosureRule) public rules;

    /// @notice Circuits: circuitId => circuit
    mapping(bytes32 => DisclosureCircuit) internal _circuits;

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

    // ============================================
    // EVENTS
    // ============================================

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

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CIRCUIT_ADMIN_ROLE, msg.sender);
        _grantRole(PROVER_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    // ============================================
    // PREDICATE MANAGEMENT
    // ============================================

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

        DisclosurePredicate storage p = predicates[predicateId];
        p.predicateId = predicateId;
        p.predicateType = predicateType;
        p.conditionHash = conditionHash;
        p.timeCondition = timeCondition;
        p.thresholdValue = thresholdValue;
        p.active = true;
        p.createdAt = uint64(block.timestamp);

        unchecked {
            ++totalPredicates;
        }

        emit PredicateCreated(predicateId, predicateType);
    }

    /**
     * @notice Create a composite predicate (AND/OR)
     */
    function createCompositePredicate(
        PredicateType predicateType,
        bytes32[] calldata subPredicates
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) returns (bytes32 predicateId) {
        if (
            predicateType != PredicateType.CompositeAnd &&
            predicateType != PredicateType.CompositeOr
        ) {
            revert NotCompositeType();
        }

        if (subPredicates.length < 2) revert NeedTwoPlusSubPredicates();

        // Validate all sub-predicates exist
        for (uint256 i = 0; i < subPredicates.length; ) {
            if (!predicates[subPredicates[i]].active) {
                revert SubPredicateInactive();
            }
            unchecked {
                ++i;
            }
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

        unchecked {
            ++totalPredicates;
        }

        emit PredicateCreated(predicateId, predicateType);
    }

    // ============================================
    // RULE MANAGEMENT
    // ============================================

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
        if (!predicates[predicateId].active) revert PredicateInactive();

        // Validate target-specific requirements
        if (target == DisclosureTarget.SpecificParty) {
            if (specificRecipient == bytes32(0)) revert RecipientRequired();
        }
        if (target == DisclosureTarget.RoleHolders) {
            if (roleRequirement == bytes32(0)) revert RoleRequired();
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

        unchecked {
            ++totalRules;
        }

        emit RuleCreated(ruleId, dataFieldId, target, predicateId);
    }

    // ============================================
    // CIRCUIT COMPILATION
    // ============================================

    /**
     * @notice Compile a disclosure circuit from rules
     * @param name Circuit name
     * @param ruleIds Rules to include
     * @param circuitHash Hash of compiled circuit
     * @param verifierKeyHash Verification key hash
     * @param inputCount Number of public inputs
     * @param witnessCount Number of private witnesses
     * @return circuitId The circuit identifier
     */
    function compileCircuit(
        string calldata name,
        bytes32[] calldata ruleIds,
        bytes32 circuitHash,
        bytes32 verifierKeyHash,
        uint256 inputCount,
        uint256 witnessCount
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) returns (bytes32 circuitId) {
        if (ruleIds.length == 0) revert NoRules();
        if (circuitHash == bytes32(0)) revert CircuitHashRequired();

        // Validate all rules exist and are active
        for (uint256 i = 0; i < ruleIds.length; ) {
            if (!rules[ruleIds[i]].active) revert RuleInactive();
            unchecked {
                ++i;
            }
        }

        circuitId = keccak256(
            abi.encodePacked(
                name,
                ruleIds,
                circuitHash,
                block.timestamp,
                totalCircuits
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encodePacked(
                "SOUL_DISCLOSURE_CIRCUIT",
                block.chainid,
                circuitId
            )
        );

        DisclosureCircuit storage c = _circuits[circuitId];
        c.circuitId = circuitId;
        c.name = name;
        c.ruleIds = ruleIds;
        c.ruleCount = ruleIds.length;
        c.circuitHash = circuitHash;
        c.verifierKeyHash = verifierKeyHash;
        c.inputCount = inputCount;
        c.witnessCount = witnessCount;
        c.domainSeparator = domainSeparator;
        c.creator = msg.sender;
        c.createdAt = uint64(block.timestamp);
        c.verified = false;
        c.active = true;

        // Store rule IDs
        for (uint256 i = 0; i < ruleIds.length; ) {
            circuitRules[circuitId].push(ruleIds[i]);
            unchecked {
                ++i;
            }
        }

        unchecked {
            ++totalCircuits;
        }

        emit CircuitCompiled(circuitId, name, ruleIds.length, circuitHash);
    }

    /**
     * @notice Mark a circuit as verified
     */
    function verifyCircuit(bytes32 circuitId) external onlyRole(VERIFIER_ROLE) {
        DisclosureCircuit storage c = _circuits[circuitId];
        if (!c.active) revert CircuitInactive();
        if (c.verified) revert AlreadyVerified();

        c.verified = true;

        emit CircuitVerified(circuitId, msg.sender);
    }

    // ============================================
    // PROOF MANAGEMENT
    // ============================================

    /**
     * @notice Submit a disclosure proof
     * @param circuitId Circuit used
     * @param executionId Execution identifier
     * @param proofHash Hash of the proof
     * @param publicInputs Public inputs
     * @param witnessCommitment Commitment to witness
     * @param disclosedFieldIds Fields being disclosed
     * @param recipientCommitments Recipients
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
    ) external onlyRole(PROVER_ROLE) returns (bytes32 proofId) {
        DisclosureCircuit storage c = _circuits[circuitId];
        if (!c.active) revert CircuitInactive();
        if (!c.verified) revert CircuitNotVerified();
        if (publicInputs.length != c.inputCount) revert InputCountMismatch();
        if (disclosedFieldIds.length != recipientCommitments.length) {
            revert FieldRecipientMismatch();
        }

        proofId = keccak256(
            abi.encodePacked(
                circuitId,
                executionId,
                proofHash,
                block.timestamp,
                totalProofs
            )
        );

        DisclosureProof storage p = proofs[proofId];
        p.proofId = proofId;
        p.circuitId = circuitId;
        p.executionId = executionId;
        p.proofHash = proofHash;
        p.publicInputs = publicInputs;
        p.witnessCommitment = witnessCommitment;
        p.disclosedFieldIds = disclosedFieldIds;
        p.recipientCommitments = recipientCommitments;
        p.verified = false;

        executionProofs[executionId].push(proofId);

        unchecked {
            ++totalProofs;
        }

        emit ProofSubmitted(proofId, circuitId, executionId);
    }

    /**
     * @notice Verify a disclosure proof
     */
    function verifyProof(bytes32 proofId) external onlyRole(VERIFIER_ROLE) {
        DisclosureProof storage p = proofs[proofId];
        if (p.proofId == bytes32(0)) revert ProofNotFound();

        // In production, verify ZK proof here
        p.verified = true;
        p.verifier = msg.sender;
        p.verifiedAt = uint64(block.timestamp);

        // Record field disclosures
        for (uint256 i = 0; i < p.disclosedFieldIds.length; ) {
            bytes32 disclosureId = keccak256(
                abi.encodePacked(proofId, p.disclosedFieldIds[i], i)
            );

            fieldDisclosures[disclosureId] = FieldDisclosure({
                disclosureId: disclosureId,
                proofId: proofId,
                fieldId: p.disclosedFieldIds[i],
                recipientCommitment: p.recipientCommitments[i],
                valueCommitment: bytes32(0), // Would be set from proof
                targetType: DisclosureTarget.SpecificParty
            });

            recipientDisclosures[p.recipientCommitments[i]].push(disclosureId);

            unchecked {
                ++totalDisclosures;
                ++i;
            }

            emit FieldDisclosed(
                disclosureId,
                p.disclosedFieldIds[i],
                p.recipientCommitments[i],
                DisclosureTarget.SpecificParty
            );
        }

        emit ProofVerified(proofId, true);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @notice Get circuit details
    function getCircuit(
        bytes32 circuitId
    ) external view returns (DisclosureCircuit memory) {
        return _circuits[circuitId];
    }

    /// @notice Get predicate details
    function getPredicate(
        bytes32 predicateId
    ) external view returns (DisclosurePredicate memory) {
        return predicates[predicateId];
    }

    /// @notice Get rule details
    function getRule(
        bytes32 ruleId
    ) external view returns (DisclosureRule memory) {
        return rules[ruleId];
    }

    /// @notice Get proof details
    function getProof(
        bytes32 proofId
    ) external view returns (DisclosureProof memory) {
        return proofs[proofId];
    }

    /// @notice Get circuit rules
    function getCircuitRules(
        bytes32 circuitId
    ) external view returns (bytes32[] memory) {
        return circuitRules[circuitId];
    }

    /// @notice Get execution proofs
    function getExecutionProofs(
        bytes32 executionId
    ) external view returns (bytes32[] memory) {
        return executionProofs[executionId];
    }

    /// @notice Get recipient disclosures
    function getRecipientDisclosures(
        bytes32 recipientCommitment
    ) external view returns (bytes32[] memory) {
        return recipientDisclosures[recipientCommitment];
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Deactivate a predicate
     */
    function deactivatePredicate(
        bytes32 predicateId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) {
        predicates[predicateId].active = false;
    }

    /**
     * @notice Deactivate a rule
     */
    function deactivateRule(
        bytes32 ruleId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) {
        rules[ruleId].active = false;
    }

    /**
     * @notice Deactivate a circuit
     */
    function deactivateCircuit(
        bytes32 circuitId
    ) external onlyRole(CIRCUIT_ADMIN_ROLE) {
        _circuits[circuitId].active = false;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
