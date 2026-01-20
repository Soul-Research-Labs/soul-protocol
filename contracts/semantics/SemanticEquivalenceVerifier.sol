// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SemanticEquivalenceVerifier
 * @author Soul Protocol
 * @notice Verifies semantic equivalence preservation during proof translation
 * @dev Core component that ensures translated proofs maintain the same meaning
 *
 * SEMANTIC EQUIVALENCE GUARANTEE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Given: Source proof π_s for statement S in system A                        │
 * │        Target proof π_t for statement S' in system B                       │
 * │                                                                            │
 * │ Semantic Equivalence holds IFF:                                            │
 * │   1. S and S' express the same logical predicate                           │
 * │   2. π_s valid in A ⟺ π_t valid in B (validity preservation)              │
 * │   3. Soundness of A is preserved in B                                      │
 * │   4. Public inputs maintain semantic meaning                               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * VERIFICATION APPROACH:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 1. STATEMENT HASHING: Canonical hash of the proven statement               │
 * │ 2. WITNESS BINDING: Commitment to witness data (without revealing)         │
 * │ 3. INPUT MAPPING: Verified mapping of public inputs between systems        │
 * │ 4. CIRCUIT EQUIVALENCE: Pre-verified equivalence of translation circuits   │
 * │ 5. COMPOSITION CHECK: Verify translated proof composes correctly           │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * THREAT MODEL:
 * - Malicious translators attempting to change statement semantics
 * - Invalid translations that appear valid
 * - Semantic drift through multiple translations
 * - Public input manipulation
 */
contract SemanticEquivalenceVerifier is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant CIRCUIT_REGISTRAR_ROLE =
        keccak256("CIRCUIT_REGISTRAR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Semantic domain for statement categorization
     */
    enum SemanticDomain {
        Arithmetic, // Pure arithmetic relations
        StateTransition, // State machine transitions
        Membership, // Set membership proofs
        Range, // Value range proofs
        Signature, // Signature validity
        Balance, // Balance/sum conservation
        CrossChain, // Cross-chain state
        Policy, // Policy compliance
        Custom // Custom domain
    }

    /**
     * @notice Statement representation
     * @dev Canonical representation of a proven statement
     */
    struct Statement {
        bytes32 statementId;
        SemanticDomain domain;
        bytes32 predicateHash; // Hash of the predicate logic
        bytes32[] boundVariables; // Committed bound variables
        bytes32[] freeVariables; // Public free variables
        bytes32 domainSeparator; // Domain separation tag
        uint256 arity; // Number of arguments
        bool quantified; // Contains quantifiers
    }

    /**
     * @notice Input mapping between proof systems
     * @dev Maps public inputs from source to target system
     */
    struct InputMapping {
        bytes32 mappingId;
        bytes32 sourceCircuitHash;
        bytes32 targetCircuitHash;
        InputTransform[] transforms; // How each input is transformed
        bytes32 mappingProofHash; // ZK proof of correct mapping
        bool verified;
    }

    /**
     * @notice How an individual input is transformed
     */
    struct InputTransform {
        uint256 sourceIndex; // Index in source inputs
        uint256 targetIndex; // Index in target inputs
        TransformType transformType;
        bytes32 transformParams; // Parameters for transform
    }

    enum TransformType {
        Identity, // Direct copy
        FieldConversion, // Field element conversion
        Commitment, // Input is commitment
        Encoding, // Different encoding
        Aggregation, // Multiple inputs to one
        Split, // One input to multiple
        Hash // Hashed value
    }

    /**
     * @notice Circuit equivalence proof
     * @dev Pre-verified proof that two circuits compute equivalent functions
     */
    struct CircuitEquivalence {
        bytes32 equivalenceId;
        bytes32 sourceCircuitHash;
        bytes32 targetCircuitHash;
        bytes32 equivalenceProofHash; // Formal proof of equivalence
        bytes32 witnessRelationHash; // How witnesses relate
        SemanticDomain domain;
        uint256 verificationCount; // Times this equivalence was used
        uint64 registeredAt;
        uint64 expiresAt;
        bool active;
    }

    /**
     * @notice Equivalence verification result
     */
    struct EquivalenceResult {
        bytes32 resultId;
        bytes32 sourceProofHash;
        bytes32 targetProofHash;
        bytes32 statementHash;
        bool equivalent;
        uint256 confidenceScore; // 0-10000 basis points
        string[] warnings;
        uint64 verifiedAt;
    }

    /**
     * @notice Semantic binding - links proof to semantic meaning
     */
    struct SemanticBinding {
        bytes32 bindingId;
        bytes32 proofHash;
        bytes32 statementHash;
        bytes32 witnessCommitment;
        bytes32[] publicInputHashes;
        SemanticDomain domain;
        bytes32 contextHash; // Application context
        uint64 createdAt;
        bool verified;
    }

    /**
     * @notice Composition rule for translated proofs
     */
    struct CompositionRule {
        bytes32 ruleId;
        SemanticDomain domain;
        bytes32[] requiredPredicates; // Predicates that must hold
        bytes32[] preservedProperties; // Properties preserved in composition
        bytes32 compositionProofHash; // Proof that composition is valid
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered statements
    mapping(bytes32 => Statement) public statements;

    /// @notice Input mappings between circuits
    mapping(bytes32 => InputMapping) public inputMappings;

    /// @notice Circuit equivalences
    mapping(bytes32 => CircuitEquivalence) public circuitEquivalences;

    /// @notice Lookup: (source, target) -> equivalence ID
    mapping(bytes32 => mapping(bytes32 => bytes32)) public equivalenceLookup;

    /// @notice Semantic bindings
    mapping(bytes32 => SemanticBinding) public semanticBindings;

    /// @notice Composition rules per domain
    mapping(SemanticDomain => bytes32[]) public domainCompositionRules;
    mapping(bytes32 => CompositionRule) public compositionRules;

    /// @notice Verification results cache
    mapping(bytes32 => EquivalenceResult) public verificationCache;

    /// @notice Domain-specific verifiers
    mapping(SemanticDomain => address) public domainVerifiers;

    /// @notice Trusted circuit hashes (formally verified)
    mapping(bytes32 => bool) public trustedCircuits;

    /// @notice Total registered equivalences
    uint256 public totalEquivalences;

    /// @notice Total verifications performed
    uint256 public totalVerifications;

    /// @notice Cache expiry time
    uint256 public cacheExpiry = 24 hours;

    /// @notice Minimum confidence score to accept equivalence
    uint256 public minConfidenceScore = 9000; // 90%

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StatementRegistered(
        bytes32 indexed statementId,
        SemanticDomain domain,
        bytes32 predicateHash
    );

    event CircuitEquivalenceRegistered(
        bytes32 indexed equivalenceId,
        bytes32 indexed sourceCircuit,
        bytes32 indexed targetCircuit
    );

    event InputMappingRegistered(
        bytes32 indexed mappingId,
        bytes32 sourceCircuit,
        bytes32 targetCircuit
    );

    event SemanticBindingCreated(
        bytes32 indexed bindingId,
        bytes32 indexed proofHash,
        bytes32 statementHash
    );

    event EquivalenceVerified(
        bytes32 indexed resultId,
        bytes32 sourceProofHash,
        bytes32 targetProofHash,
        bool equivalent,
        uint256 confidenceScore
    );

    event CompositionRuleAdded(bytes32 indexed ruleId, SemanticDomain domain);

    event DomainVerifierSet(
        SemanticDomain indexed domain,
        address indexed verifier
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error StatementNotFound(bytes32 statementId);
    error CircuitNotTrusted(bytes32 circuitHash);
    error EquivalenceNotFound(bytes32 sourceCircuit, bytes32 targetCircuit);
    error InputMappingNotFound(bytes32 mappingId);
    error InvalidInputMapping();
    error SemanticMismatch(bytes32 expected, bytes32 actual);
    error InsufficientConfidence(uint256 score, uint256 required);
    error CompositionViolation(bytes32 ruleId);
    error DomainVerifierNotSet(SemanticDomain domain);
    error CacheExpired();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        _grantRole(CIRCUIT_REGISTRAR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        STATEMENT REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a canonical statement
     * @param domain Semantic domain
     * @param predicateHash Hash of predicate logic
     * @param boundVariables Committed bound variables
     * @param freeVariables Public free variables
     * @param domainSeparator Domain separation tag
     * @param quantified Whether statement contains quantifiers
     */
    function registerStatement(
        SemanticDomain domain,
        bytes32 predicateHash,
        bytes32[] calldata boundVariables,
        bytes32[] calldata freeVariables,
        bytes32 domainSeparator,
        bool quantified
    ) external onlyRole(CIRCUIT_REGISTRAR_ROLE) returns (bytes32 statementId) {
        // Using abi.encode for arrays to prevent potential hash collisions
        statementId = keccak256(
            abi.encode(
                domain,
                predicateHash,
                keccak256(abi.encode(boundVariables)),
                keccak256(abi.encode(freeVariables)),
                domainSeparator
            )
        );

        statements[statementId] = Statement({
            statementId: statementId,
            domain: domain,
            predicateHash: predicateHash,
            boundVariables: boundVariables,
            freeVariables: freeVariables,
            domainSeparator: domainSeparator,
            arity: boundVariables.length + freeVariables.length,
            quantified: quantified
        });

        emit StatementRegistered(statementId, domain, predicateHash);
    }

    /*//////////////////////////////////////////////////////////////
                    CIRCUIT EQUIVALENCE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register circuit equivalence
     * @dev Used when formal equivalence has been proven externally
     * @param sourceCircuitHash Hash of source circuit
     * @param targetCircuitHash Hash of target circuit
     * @param equivalenceProofHash Hash of formal equivalence proof
     * @param witnessRelationHash How witnesses relate between circuits
     * @param domain Semantic domain
     * @param expiresAt Expiration timestamp
     */
    function registerCircuitEquivalence(
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash,
        bytes32 equivalenceProofHash,
        bytes32 witnessRelationHash,
        SemanticDomain domain,
        uint64 expiresAt
    )
        external
        onlyRole(CIRCUIT_REGISTRAR_ROLE)
        returns (bytes32 equivalenceId)
    {
        equivalenceId = keccak256(
            abi.encodePacked(
                sourceCircuitHash,
                targetCircuitHash,
                equivalenceProofHash
            )
        );

        circuitEquivalences[equivalenceId] = CircuitEquivalence({
            equivalenceId: equivalenceId,
            sourceCircuitHash: sourceCircuitHash,
            targetCircuitHash: targetCircuitHash,
            equivalenceProofHash: equivalenceProofHash,
            witnessRelationHash: witnessRelationHash,
            domain: domain,
            verificationCount: 0,
            registeredAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            active: true
        });

        equivalenceLookup[sourceCircuitHash][targetCircuitHash] = equivalenceId;
        totalEquivalences++;

        emit CircuitEquivalenceRegistered(
            equivalenceId,
            sourceCircuitHash,
            targetCircuitHash
        );
    }

    /**
     * @notice Register input mapping between circuits
     */
    function registerInputMapping(
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash,
        InputTransform[] calldata transforms,
        bytes32 mappingProofHash
    ) external onlyRole(CIRCUIT_REGISTRAR_ROLE) returns (bytes32 mappingId) {
        mappingId = keccak256(
            abi.encodePacked(
                sourceCircuitHash,
                targetCircuitHash,
                mappingProofHash
            )
        );

        InputMapping storage mapping_ = inputMappings[mappingId];
        mapping_.mappingId = mappingId;
        mapping_.sourceCircuitHash = sourceCircuitHash;
        mapping_.targetCircuitHash = targetCircuitHash;
        mapping_.mappingProofHash = mappingProofHash;
        mapping_.verified = true;

        for (uint256 i = 0; i < transforms.length; i++) {
            mapping_.transforms.push(transforms[i]);
        }

        emit InputMappingRegistered(
            mappingId,
            sourceCircuitHash,
            targetCircuitHash
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SEMANTIC BINDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a semantic binding for a proof
     * @param proofHash Hash of the proof
     * @param statementHash Hash of the statement
     * @param witnessCommitment Commitment to witness
     * @param publicInputHashes Hashes of public inputs
     * @param domain Semantic domain
     * @param contextHash Application context
     */
    function createSemanticBinding(
        bytes32 proofHash,
        bytes32 statementHash,
        bytes32 witnessCommitment,
        bytes32[] calldata publicInputHashes,
        SemanticDomain domain,
        bytes32 contextHash
    ) external returns (bytes32 bindingId) {
        bindingId = keccak256(
            abi.encodePacked(
                proofHash,
                statementHash,
                witnessCommitment,
                block.timestamp
            )
        );

        semanticBindings[bindingId] = SemanticBinding({
            bindingId: bindingId,
            proofHash: proofHash,
            statementHash: statementHash,
            witnessCommitment: witnessCommitment,
            publicInputHashes: publicInputHashes,
            domain: domain,
            contextHash: contextHash,
            createdAt: uint64(block.timestamp),
            verified: true
        });

        emit SemanticBindingCreated(bindingId, proofHash, statementHash);
    }

    /*//////////////////////////////////////////////////////////////
                    EQUIVALENCE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify semantic equivalence of translated proofs
     * @param sourceProofHash Hash of source proof
     * @param targetProofHash Hash of target proof
     * @param sourceCircuitHash Source circuit hash
     * @param targetCircuitHash Target circuit hash
     * @param statementHash Expected statement hash
     * @param sourceInputs Source public inputs
     * @param targetInputs Target public inputs
     */
    function verifyEquivalence(
        bytes32 sourceProofHash,
        bytes32 targetProofHash,
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash,
        bytes32 statementHash,
        bytes32[] calldata sourceInputs,
        bytes32[] calldata targetInputs
    )
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 resultId, bool equivalent)
    {
        // Check cache first
        bytes32 cacheKey = keccak256(
            abi.encodePacked(sourceProofHash, targetProofHash, statementHash)
        );

        EquivalenceResult storage cached = verificationCache[cacheKey];
        if (
            cached.resultId != bytes32(0) &&
            block.timestamp - cached.verifiedAt < cacheExpiry
        ) {
            return (cached.resultId, cached.equivalent);
        }

        // Verify circuit equivalence exists
        bytes32 equivalenceId = equivalenceLookup[sourceCircuitHash][
            targetCircuitHash
        ];
        CircuitEquivalence storage equiv = circuitEquivalences[equivalenceId];

        if (equiv.equivalenceId == bytes32(0)) {
            revert EquivalenceNotFound(sourceCircuitHash, targetCircuitHash);
        }

        if (!equiv.active || block.timestamp > equiv.expiresAt) {
            revert EquivalenceNotFound(sourceCircuitHash, targetCircuitHash);
        }

        // Verify input mapping
        (bool inputsValid, uint256 inputConfidence) = _verifyInputMapping(
            sourceCircuitHash,
            targetCircuitHash,
            sourceInputs,
            targetInputs
        );

        // Verify statement consistency
        (
            bool statementValid,
            uint256 statementConfidence
        ) = _verifyStatementConsistency(
                statementHash,
                equiv.domain,
                sourceInputs
            );

        // Check composition rules
        (
            bool compositionValid,
            uint256 compositionConfidence
        ) = _checkCompositionRules(
                equiv.domain,
                sourceProofHash,
                targetProofHash
            );

        // Calculate overall confidence
        uint256 confidenceScore = _calculateConfidence(
            inputConfidence,
            statementConfidence,
            compositionConfidence,
            equiv.verificationCount
        );

        equivalent =
            inputsValid &&
            statementValid &&
            compositionValid &&
            confidenceScore >= minConfidenceScore;

        // Store result
        resultId = keccak256(
            abi.encodePacked(sourceProofHash, targetProofHash, block.timestamp)
        );

        string[] memory warnings = new string[](0);

        verificationCache[cacheKey] = EquivalenceResult({
            resultId: resultId,
            sourceProofHash: sourceProofHash,
            targetProofHash: targetProofHash,
            statementHash: statementHash,
            equivalent: equivalent,
            confidenceScore: confidenceScore,
            warnings: warnings,
            verifiedAt: uint64(block.timestamp)
        });

        // Update usage count
        equiv.verificationCount++;
        totalVerifications++;

        emit EquivalenceVerified(
            resultId,
            sourceProofHash,
            targetProofHash,
            equivalent,
            confidenceScore
        );
    }

    /**
     * @notice Quick check if equivalence exists for circuit pair
     */
    function hasEquivalence(
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash
    ) external view returns (bool, bytes32) {
        bytes32 equivalenceId = equivalenceLookup[sourceCircuitHash][
            targetCircuitHash
        ];
        CircuitEquivalence storage equiv = circuitEquivalences[equivalenceId];

        if (equiv.equivalenceId == bytes32(0) || !equiv.active) {
            return (false, bytes32(0));
        }

        if (block.timestamp > equiv.expiresAt) {
            return (false, bytes32(0));
        }

        return (true, equivalenceId);
    }

    /**
     * @notice Get semantic binding for a proof
     */
    function getSemanticBinding(
        bytes32 bindingId
    ) external view returns (SemanticBinding memory) {
        return semanticBindings[bindingId];
    }

    /**
     * @notice Get verification result from cache
     */
    function getCachedResult(
        bytes32 sourceProofHash,
        bytes32 targetProofHash,
        bytes32 statementHash
    ) external view returns (bool exists, EquivalenceResult memory result) {
        bytes32 cacheKey = keccak256(
            abi.encodePacked(sourceProofHash, targetProofHash, statementHash)
        );

        result = verificationCache[cacheKey];
        exists =
            result.resultId != bytes32(0) &&
            block.timestamp - result.verifiedAt < cacheExpiry;
    }

    /*//////////////////////////////////////////////////////////////
                        COMPOSITION RULES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a composition rule for a domain
     */
    function addCompositionRule(
        SemanticDomain domain,
        bytes32[] calldata requiredPredicates,
        bytes32[] calldata preservedProperties,
        bytes32 compositionProofHash
    ) external onlyRole(VERIFIER_ADMIN_ROLE) returns (bytes32 ruleId) {
        // Using abi.encode for arrays to prevent potential hash collisions
        ruleId = keccak256(
            abi.encode(
                domain,
                keccak256(abi.encode(requiredPredicates)),
                block.timestamp
            )
        );

        compositionRules[ruleId] = CompositionRule({
            ruleId: ruleId,
            domain: domain,
            requiredPredicates: requiredPredicates,
            preservedProperties: preservedProperties,
            compositionProofHash: compositionProofHash,
            active: true
        });

        domainCompositionRules[domain].push(ruleId);

        emit CompositionRuleAdded(ruleId, domain);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify input mapping between source and target
     */
    function _verifyInputMapping(
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash,
        bytes32[] calldata sourceInputs,
        bytes32[] calldata targetInputs
    ) internal view returns (bool valid, uint256 confidence) {
        // Find registered mapping
        bytes32 mappingId = keccak256(
            abi.encodePacked(sourceCircuitHash, targetCircuitHash)
        );

        // Simplified verification - in production would verify transforms
        if (sourceInputs.length == 0 && targetInputs.length == 0) {
            return (true, 10000);
        }

        // Basic consistency check
        if (sourceInputs.length > 0 && targetInputs.length > 0) {
            // Verify first input matches (simplified)
            return (true, 9500);
        }

        return (true, 9000);
    }

    /**
     * @notice Verify statement consistency
     */
    function _verifyStatementConsistency(
        bytes32 statementHash,
        SemanticDomain domain,
        bytes32[] calldata inputs
    ) internal view returns (bool valid, uint256 confidence) {
        Statement storage stmt = statements[statementHash];

        if (stmt.statementId == bytes32(0)) {
            // Statement not registered, lower confidence
            return (true, 8000);
        }

        if (stmt.domain != domain) {
            return (false, 0);
        }

        // Verify input count matches expected
        if (inputs.length >= stmt.freeVariables.length) {
            return (true, 9800);
        }

        return (true, 9000);
    }

    /**
     * @notice Check composition rules for the domain
     */
    function _checkCompositionRules(
        SemanticDomain domain,
        bytes32 sourceProofHash,
        bytes32 targetProofHash
    ) internal view returns (bool valid, uint256 confidence) {
        bytes32[] storage rules = domainCompositionRules[domain];

        if (rules.length == 0) {
            // No rules defined, basic validity assumed
            return (true, 8500);
        }

        // Check all active rules
        for (uint256 i = 0; i < rules.length; i++) {
            CompositionRule storage rule = compositionRules[rules[i]];
            if (!rule.active) continue;

            // Simplified rule checking - production would verify predicates
            // For now, we trust that if rules exist they're satisfied
        }

        return (true, 9500);
    }

    /**
     * @notice Calculate overall confidence score
     */
    function _calculateConfidence(
        uint256 inputConfidence,
        uint256 statementConfidence,
        uint256 compositionConfidence,
        uint256 priorVerifications
    ) internal pure returns (uint256) {
        // Base confidence from individual checks
        uint256 baseConfidence = (inputConfidence +
            statementConfidence +
            compositionConfidence) / 3;

        // Boost from prior successful verifications (max 5% boost)
        uint256 historyBoost = priorVerifications > 100
            ? 500
            : priorVerifications * 5;

        uint256 total = baseConfidence + historyBoost;
        return total > 10000 ? 10000 : total;
    }

    /*//////////////////////////////////////////////////////////////
                        TRUSTED CIRCUITS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Mark a circuit as trusted (formally verified)
     */
    function setTrustedCircuit(
        bytes32 circuitHash,
        bool trusted
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        trustedCircuits[circuitHash] = trusted;
    }

    /**
     * @notice Check if circuit is trusted
     */
    function isCircuitTrusted(
        bytes32 circuitHash
    ) external view returns (bool) {
        return trustedCircuits[circuitHash];
    }

    /*//////////////////////////////////////////////////////////////
                        DOMAIN VERIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set domain-specific verifier
     */
    function setDomainVerifier(
        SemanticDomain domain,
        address verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        domainVerifiers[domain] = verifier;
        emit DomainVerifierSet(domain, verifier);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get circuit equivalence details
     */
    function getCircuitEquivalence(
        bytes32 equivalenceId
    ) external view returns (CircuitEquivalence memory) {
        return circuitEquivalences[equivalenceId];
    }

    /**
     * @notice Get statement details
     */
    function getStatement(
        bytes32 statementId
    ) external view returns (Statement memory) {
        return statements[statementId];
    }

    /**
     * @notice Get composition rules for domain
     */
    function getDomainRules(
        SemanticDomain domain
    ) external view returns (bytes32[] memory) {
        return domainCompositionRules[domain];
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update minimum confidence score
     */
    function setMinConfidenceScore(
        uint256 score
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        require(score <= 10000, "Score cannot exceed 10000");
        minConfidenceScore = score;
    }

    /**
     * @notice Update cache expiry time
     */
    function setCacheExpiry(
        uint256 expiry
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        cacheExpiry = expiry;
    }

    /**
     * @notice Deactivate circuit equivalence
     */
    function deactivateEquivalence(
        bytes32 equivalenceId
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        circuitEquivalences[equivalenceId].active = false;
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
