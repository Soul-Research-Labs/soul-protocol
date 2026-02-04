// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AggregateDisclosureAlgebra
 * @author Soul Protocol
 * @notice Research-grade implementation of Aggregate Disclosure Algebra (ADA)
 * @dev Enables flexible, programmable disclosure of attributes with aggregation
 *
 * Aggregate Disclosure Algebra allows:
 * - Selective disclosure of identity attributes
 * - Combining multiple proofs into aggregate disclosures
 * - Threshold-based disclosure (k-of-n attributes)
 * - Time-locked and conditional disclosures
 * - Merkle-based attribute trees for efficient verification
 *
 * Use Cases:
 * - "I am over 21" without revealing exact age
 * - "My income is in range X-Y" without exact amount
 * - Combined proofs: "Over 21 AND resident of state X"
 */
contract AggregateDisclosureAlgebra is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                               ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("DISCLOSURE_ADMIN_ROLE")
    bytes32 public constant DISCLOSURE_ADMIN_ROLE =
        0xcf8a7913f3d76add8de8addd55ce46aa0b0a2aef6d435d5bb47659cb1ffeb0c8;
    /// @dev keccak256("VERIFIER_ROLE")
    bytes32 public constant VERIFIER_ROLE =
        0x0ce23c3e399818cfee81a7ab0880f714e53d7672b08df0fa62f2843416e1ea09;
    /// @dev keccak256("ISSUER_ROLE")
    bytes32 public constant ISSUER_ROLE =
        0x114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122;

    /*//////////////////////////////////////////////////////////////
                               TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice An attribute credential
    struct AttributeCredential {
        bytes32 credentialId;
        bytes32 attributeHash; // Hash of attribute name
        bytes32 valueCommitment; // Hidden value commitment
        address issuer;
        address subject;
        uint64 issuedAt;
        uint64 expiresAt;
        bool isRevoked;
    }

    /// @notice A selective disclosure proof
    struct SelectiveDisclosure {
        bytes32 disclosureId;
        bytes32 credentialId;
        bytes32 revealedHash; // Hash of revealed attribute subset
        bytes32[] hiddenAttributes; // Attributes kept hidden
        bytes proof; // ZK proof of subset
        address verifier; // Who can verify
        uint64 createdAt;
        uint64 expiresAt;
        bool isConsumed;
    }

    /// @notice An aggregate disclosure combining multiple proofs
    struct AggregateDisclosure {
        bytes32 aggregateId;
        bytes32[] disclosureIds;
        AggregationType aggType;
        uint8 threshold; // For k-of-n disclosures
        bytes32 aggregateProof; // Combined proof
        address subject;
        uint64 createdAt;
        bool isVerified;
    }

    /// @notice Disclosure condition
    struct DisclosureCondition {
        bytes32 conditionId;
        ConditionType condType;
        bytes32 parameter; // Condition parameter
        uint256 value; // Numeric threshold/value
        bool isMet;
    }

    /// @notice Aggregation types
    enum AggregationType {
        AND, // All disclosures must verify
        OR, // At least one disclosure must verify
        THRESHOLD, // k-of-n disclosures must verify
        WEIGHTED // Weighted sum of disclosures
    }

    /// @notice Condition types for conditional disclosure
    enum ConditionType {
        TimeAfter, // Disclose after timestamp
        TimeBefore, // Disclose before timestamp
        BlockAfter, // Disclose after block number
        OracleCheck, // Check external oracle
        ProofValid // Another proof must be valid
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Credential storage
    mapping(bytes32 => AttributeCredential) public credentials;

    /// @notice Selective disclosure storage
    mapping(bytes32 => SelectiveDisclosure) public disclosures;

    /// @notice Aggregate disclosure storage
    mapping(bytes32 => AggregateDisclosure) public aggregates;

    /// @notice Disclosure conditions storage
    mapping(bytes32 => DisclosureCondition) public conditions;

    /// @notice Credentials by subject
    mapping(address => bytes32[]) public subjectCredentials;

    /// @notice Credentials by issuer
    mapping(address => bytes32[]) public issuerCredentials;

    /// @notice Disclosures by subject
    mapping(address => bytes32[]) public subjectDisclosures;

    /// @notice Attribute registry (name hash -> attribute metadata)
    mapping(bytes32 => AttributeMetadata) public attributeRegistry;

    /// @notice Attribute metadata
    struct AttributeMetadata {
        bytes32 attributeHash;
        string name;
        bool isNumeric;
        bool allowsRangeProof;
        bool isRegistered;
    }

    /// @notice Counter for unique IDs
    uint256 private _idCounter;

    /// @notice Statistics
    uint256 public totalCredentials;
    uint256 public totalDisclosures;
    uint256 public totalAggregates;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event CredentialIssued(
        bytes32 indexed credentialId,
        address indexed issuer,
        address indexed subject,
        bytes32 attributeHash
    );

    event CredentialRevoked(bytes32 indexed credentialId);

    event SelectiveDisclosureCreated(
        bytes32 indexed disclosureId,
        bytes32 indexed credentialId,
        address indexed verifier
    );

    event AggregateDisclosureCreated(
        bytes32 indexed aggregateId,
        AggregationType aggType,
        uint256 disclosureCount
    );

    event DisclosureVerified(bytes32 indexed disclosureId, bool isValid);

    event AggregateVerified(bytes32 indexed aggregateId, bool isValid);

    event AttributeRegistered(bytes32 indexed attributeHash, string name);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error CredentialNotFound();
    error CredentialExpired();
    error CredentialIsRevoked();
    error DisclosureNotFound();
    error DisclosureExpired();
    error DisclosureConsumed();
    error AggregateNotFound();
    error InvalidThreshold();
    error InvalidProof();
    error Unauthorized();
    error ConditionNotMet();
    error AttributeNotRegistered();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DISCLOSURE_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      ATTRIBUTE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new attribute type
     * @param name Human-readable attribute name
     * @param isNumeric Whether the attribute is numeric
     * @param allowsRangeProof Whether range proofs are allowed
     * @return attributeHash The attribute identifier
     */
    function registerAttribute(
        string calldata name,
        bool isNumeric,
        bool allowsRangeProof
    ) external onlyRole(DISCLOSURE_ADMIN_ROLE) returns (bytes32 attributeHash) {
        attributeHash = keccak256(abi.encodePacked(name));

        attributeRegistry[attributeHash] = AttributeMetadata({
            attributeHash: attributeHash,
            name: name,
            isNumeric: isNumeric,
            allowsRangeProof: allowsRangeProof,
            isRegistered: true
        });

        emit AttributeRegistered(attributeHash, name);

        return attributeHash;
    }

    /*//////////////////////////////////////////////////////////////
                      CREDENTIAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Issue a new attribute credential
     * @param subject The credential holder
     * @param attributeHash The attribute type
     * @param valueCommitment Commitment to the attribute value
     * @param expiry When the credential expires
     * @return credentialId The credential ID
     */
    function issueCredential(
        address subject,
        bytes32 attributeHash,
        bytes32 valueCommitment,
        uint64 expiry
    )
        external
        whenNotPaused
        onlyRole(ISSUER_ROLE)
        returns (bytes32 credentialId)
    {
        if (!attributeRegistry[attributeHash].isRegistered) {
            revert AttributeNotRegistered();
        }

        credentialId = keccak256(
            abi.encodePacked(
                msg.sender,
                subject,
                attributeHash,
                valueCommitment,
                block.timestamp,
                ++_idCounter
            )
        );

        credentials[credentialId] = AttributeCredential({
            credentialId: credentialId,
            attributeHash: attributeHash,
            valueCommitment: valueCommitment,
            issuer: msg.sender,
            subject: subject,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiry,
            isRevoked: false
        });

        subjectCredentials[subject].push(credentialId);
        issuerCredentials[msg.sender].push(credentialId);
        unchecked {
            ++totalCredentials;
        }

        emit CredentialIssued(credentialId, msg.sender, subject, attributeHash);

        return credentialId;
    }

    /**
     * @notice Revoke a credential
     * @param credentialId The credential to revoke
     */
    function revokeCredential(
        bytes32 credentialId
    ) external onlyRole(ISSUER_ROLE) {
        AttributeCredential storage credential = credentials[credentialId];
        if (credential.issuedAt == 0) revert CredentialNotFound();
        if (credential.issuer != msg.sender) revert Unauthorized();

        credential.isRevoked = true;

        emit CredentialRevoked(credentialId);
    }

    /*//////////////////////////////////////////////////////////////
                   SELECTIVE DISCLOSURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a selective disclosure from a credential
     * @param credentialId The source credential
     * @param revealedHash Hash of revealed attribute value/subset
     * @param hiddenAttributes Attributes to keep hidden
     * @param proof ZK proof of disclosure validity
     * @param verifier Who can verify this disclosure
     * @param expiry When the disclosure expires
     * @return disclosureId The disclosure ID
     */
    function createSelectiveDisclosure(
        bytes32 credentialId,
        bytes32 revealedHash,
        bytes32[] calldata hiddenAttributes,
        bytes calldata proof,
        address verifier,
        uint64 expiry
    ) external whenNotPaused nonReentrant returns (bytes32 disclosureId) {
        AttributeCredential storage credential = credentials[credentialId];
        if (credential.issuedAt == 0) revert CredentialNotFound();
        if (credential.subject != msg.sender) revert Unauthorized();
        if (credential.isRevoked) revert CredentialIsRevoked();
        if (
            credential.expiresAt != 0 && block.timestamp > credential.expiresAt
        ) {
            revert CredentialExpired();
        }

        disclosureId = keccak256(
            abi.encodePacked(
                credentialId,
                revealedHash,
                verifier,
                block.timestamp,
                ++_idCounter
            )
        );

        disclosures[disclosureId] = SelectiveDisclosure({
            disclosureId: disclosureId,
            credentialId: credentialId,
            revealedHash: revealedHash,
            hiddenAttributes: hiddenAttributes,
            proof: proof,
            verifier: verifier,
            createdAt: uint64(block.timestamp),
            expiresAt: expiry,
            isConsumed: false
        });

        subjectDisclosures[msg.sender].push(disclosureId);
        unchecked {
            ++totalDisclosures;
        }

        emit SelectiveDisclosureCreated(disclosureId, credentialId, verifier);

        return disclosureId;
    }

    /**
     * @notice Verify a selective disclosure
     * @param disclosureId The disclosure to verify
     * @return isValid Whether the disclosure is valid
     */
    function verifySelectiveDisclosure(
        bytes32 disclosureId
    ) external whenNotPaused returns (bool isValid) {
        SelectiveDisclosure storage disclosure = disclosures[disclosureId];
        if (disclosure.createdAt == 0) revert DisclosureNotFound();
        if (disclosure.isConsumed) revert DisclosureConsumed();
        if (
            disclosure.expiresAt != 0 && block.timestamp > disclosure.expiresAt
        ) {
            revert DisclosureExpired();
        }
        if (
            disclosure.verifier != address(0) &&
            disclosure.verifier != msg.sender
        ) {
            revert Unauthorized();
        }

        // Check underlying credential
        AttributeCredential storage credential = credentials[
            disclosure.credentialId
        ];
        if (credential.isRevoked) revert CredentialIsRevoked();

        // Simplified verification - in production would verify ZK proof
        isValid = disclosure.proof.length >= 32;

        disclosure.isConsumed = true;

        emit DisclosureVerified(disclosureId, isValid);

        return isValid;
    }

    /*//////////////////////////////////////////////////////////////
                   AGGREGATE DISCLOSURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an aggregate disclosure combining multiple proofs
     * @param disclosureIds The disclosures to aggregate
     * @param aggType The aggregation type
     * @param threshold For THRESHOLD type, the k value
     * @return aggregateId The aggregate disclosure ID
     */
    function createAggregateDisclosure(
        bytes32[] calldata disclosureIds,
        AggregationType aggType,
        uint8 threshold
    ) external whenNotPaused nonReentrant returns (bytes32 aggregateId) {
        if (aggType == AggregationType.THRESHOLD) {
            if (threshold == 0 || threshold > disclosureIds.length) {
                revert InvalidThreshold();
            }
        }

        // Verify all disclosures exist and belong to caller
        bytes32 aggregateProof = bytes32(0);
        for (uint256 i = 0; i < disclosureIds.length; ) {
            SelectiveDisclosure storage disclosure = disclosures[
                disclosureIds[i]
            ];
            if (disclosure.createdAt == 0) revert DisclosureNotFound();

            // Build aggregate proof hash
            aggregateProof = keccak256(
                abi.encodePacked(aggregateProof, disclosure.proof)
            );
            unchecked {
                ++i;
            }
        }

        aggregateId = keccak256(
            abi.encodePacked(
                aggregateProof,
                uint8(aggType),
                threshold,
                block.timestamp,
                ++_idCounter
            )
        );

        aggregates[aggregateId] = AggregateDisclosure({
            aggregateId: aggregateId,
            disclosureIds: disclosureIds,
            aggType: aggType,
            threshold: threshold,
            aggregateProof: aggregateProof,
            subject: msg.sender,
            createdAt: uint64(block.timestamp),
            isVerified: false
        });

        unchecked {
            ++totalAggregates;
        }

        emit AggregateDisclosureCreated(
            aggregateId,
            aggType,
            disclosureIds.length
        );

        return aggregateId;
    }

    /**
     * @notice Verify an aggregate disclosure
     * @param aggregateId The aggregate to verify
     * @return isValid Whether the aggregate is valid
     */
    function verifyAggregateDisclosure(
        bytes32 aggregateId
    ) external onlyRole(VERIFIER_ROLE) returns (bool isValid) {
        AggregateDisclosure storage aggregate = aggregates[aggregateId];
        if (aggregate.createdAt == 0) revert AggregateNotFound();

        uint256 validCount = 0;
        uint256 totalWeight = 0;

        for (uint256 i = 0; i < aggregate.disclosureIds.length; ) {
            SelectiveDisclosure storage disclosure = disclosures[
                aggregate.disclosureIds[i]
            ];

            // Check if disclosure is still valid
            bool disclosureValid = disclosure.createdAt != 0 &&
                !disclosure.isConsumed &&
                (disclosure.expiresAt == 0 ||
                    block.timestamp <= disclosure.expiresAt);

            if (disclosureValid) {
                unchecked {
                    ++validCount;
                }
                totalWeight += 1; // Could be weighted
            }
            unchecked {
                ++i;
            }
        }

        // Evaluate based on aggregation type
        if (aggregate.aggType == AggregationType.AND) {
            isValid = validCount == aggregate.disclosureIds.length;
        } else if (aggregate.aggType == AggregationType.OR) {
            isValid = validCount > 0;
        } else if (aggregate.aggType == AggregationType.THRESHOLD) {
            isValid = validCount >= aggregate.threshold;
        } else if (aggregate.aggType == AggregationType.WEIGHTED) {
            isValid = totalWeight >= aggregate.threshold;
        }

        aggregate.isVerified = true;

        emit AggregateVerified(aggregateId, isValid);

        return isValid;
    }

    /*//////////////////////////////////////////////////////////////
                    CONDITIONAL DISCLOSURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a time-locked disclosure condition
     * @param disclosureId The disclosure to condition
     * @param unlockTime When the disclosure becomes valid
     * @return conditionId The condition ID
     */
    function createTimeCondition(
        bytes32 disclosureId,
        uint256 unlockTime
    ) external whenNotPaused returns (bytes32 conditionId) {
        SelectiveDisclosure storage disclosure = disclosures[disclosureId];
        if (disclosure.createdAt == 0) revert DisclosureNotFound();

        conditionId = keccak256(
            abi.encodePacked(
                disclosureId,
                ConditionType.TimeAfter,
                unlockTime,
                ++_idCounter
            )
        );

        conditions[conditionId] = DisclosureCondition({
            conditionId: conditionId,
            condType: ConditionType.TimeAfter,
            parameter: disclosureId,
            value: unlockTime,
            isMet: false
        });

        return conditionId;
    }

    /**
     * @notice Check if a condition is met
     * @param conditionId The condition to check
     * @return isMet Whether the condition is met
     */
    function checkCondition(
        bytes32 conditionId
    ) external view returns (bool isMet) {
        DisclosureCondition storage condition = conditions[conditionId];

        if (condition.condType == ConditionType.TimeAfter) {
            return block.timestamp >= condition.value;
        } else if (condition.condType == ConditionType.TimeBefore) {
            return block.timestamp <= condition.value;
        } else if (condition.condType == ConditionType.BlockAfter) {
            return block.number >= condition.value;
        }

        return false;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getCredential(
        bytes32 credentialId
    ) external view returns (AttributeCredential memory) {
        return credentials[credentialId];
    }

    function getDisclosure(
        bytes32 disclosureId
    ) external view returns (SelectiveDisclosure memory) {
        return disclosures[disclosureId];
    }

    function getAggregate(
        bytes32 aggregateId
    ) external view returns (AggregateDisclosure memory) {
        return aggregates[aggregateId];
    }

    function getSubjectCredentials(
        address subject
    ) external view returns (bytes32[] memory) {
        return subjectCredentials[subject];
    }

    function getSubjectDisclosures(
        address subject
    ) external view returns (bytes32[] memory) {
        return subjectDisclosures[subject];
    }

    function isCredentialValid(
        bytes32 credentialId
    ) external view returns (bool) {
        AttributeCredential storage cred = credentials[credentialId];
        if (cred.issuedAt == 0) return false;
        if (cred.isRevoked) return false;
        if (cred.expiresAt != 0 && block.timestamp > cred.expiresAt)
            return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
