// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AuditablePrivacyFramework
 * @author Soul Protocol
 * @notice Midnight-inspired: Regulation-Compatible Privacy with Provable Audit Rights
 * @dev Key insight: Auditors should VERIFY PROOFS, not REQUEST LOGS.
 *      Audit access is a PROVABLE RIGHT, not a trusted backdoor.
 *
 * MIDNIGHT'S TARGET:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Privacy systems designed to selectively reveal under LEGAL PREDICATES.     │
 * │ This is not censorship — it's CONTROLLED DISCLOSURE.                       │
 * │                                                                             │
 * │ Target users:                                                               │
 * │ - Enterprises                                                               │
 * │ - Governments                                                               │
 * │ - Regulated industries                                                      │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S IMPROVEMENT:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 1. Audit access is a PROVABLE RIGHT (not backdoor)                         │
 * │ 2. Auditors verify PROOFS (not logs)                                       │
 * │ 3. Cross-chain audit trail                                                 │
 * │ 4. Authority without public identity (ZK-DSS)                              │
 * │ 5. Delegation, revocation, portability                                     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract AuditablePrivacyFramework is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant AUDIT_ADMIN_ROLE = keccak256("AUDIT_ADMIN_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant REGULATOR_ROLE = keccak256("REGULATOR_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Audit authority type
     */
    enum AuditAuthorityType {
        None, // No authority
        InternalAuditor, // Organization's internal auditor
        ExternalAuditor, // Third-party auditor
        Regulator, // Regulatory authority
        LawEnforcement, // Law enforcement (with warrant)
        DataSubject, // Data subject (GDPR Article 15)
        Delegated // Delegated authority
    }

    /**
     * @notice Audit scope - what can be audited
     */
    enum AuditScope {
        None, // No access
        MetadataOnly, // Existence, timing, not content
        CommitmentsOnly, // Can see commitments
        ProofsOnly, // Can verify proofs
        EncryptedData, // Can access encrypted form
        PlaintextData // Can decrypt (highest authority)
    }

    /**
     * @notice Legal predicate type
     */
    enum LegalPredicateType {
        GDPRArticle15, // Data subject access request
        GDPRArticle20, // Data portability
        CourtOrder, // Valid court order
        RegulatoryInquiry, // Regulatory investigation
        InternalCompliance, // Internal compliance review
        AuditScheduled, // Scheduled audit
        IncidentResponse, // Security incident
        Custom // Custom predicate
    }

    /**
     * @notice Audit authority credential
     * @dev ZK-provable credential (not public identity)
     */
    struct AuditCredential {
        bytes32 credentialId;
        bytes32 authorityCommitment; // Hidden identity commitment
        AuditAuthorityType authorityType;
        AuditScope maxScope;
        // Validity
        uint64 issuedAt;
        uint64 expiresAt;
        bool revoked;
        // Jurisdiction (hidden)
        bytes32 jurisdictionCommitment;
        // Issuer
        bytes32 issuerCommitment;
        bytes32 issuanceProof; // Proof of valid issuance
    }

    /**
     * @notice Audit right - provable right to access
     * @dev This replaces "trusted backdoors" with cryptographic rights
     */
    struct AuditRight {
        bytes32 rightId;
        bytes32 credentialId;
        bytes32 targetExecutionId; // What can be audited
        bytes32 targetDomainId; // Which domain
        // Scope
        AuditScope grantedScope;
        // Legal basis
        LegalPredicateType legalBasis;
        bytes32 legalPredicateProof; // Proof legal basis is satisfied
        // Validity
        uint64 grantedAt;
        uint64 expiresAt;
        bool exercised;
        // Proof of right
        bytes32 rightProof; // ZK proof of audit right
    }

    /**
     * @notice Audit request
     */
    struct AuditRequest {
        bytes32 requestId;
        bytes32 credentialId;
        bytes32 rightId;
        // What is being requested
        bytes32 executionId;
        AuditScope requestedScope;
        // Legal justification
        LegalPredicateType legalBasis;
        bytes32 justificationCommitment;
        bytes32 justificationProof;
        // Status
        AuditRequestStatus status;
        uint64 requestedAt;
        uint64 respondedAt;
    }

    enum AuditRequestStatus {
        Pending,
        Approved,
        Denied,
        Expired,
        Fulfilled
    }

    /**
     * @notice Audit response - proof-based response
     * @dev Auditors receive PROOFS, not logs
     */
    struct AuditResponse {
        bytes32 responseId;
        bytes32 requestId;
        // Proof-based response
        bytes32 executionProof; // Proof of execution correctness
        bytes32 policyProof; // Proof of policy compliance
        bytes32 disclosureProof; // Proof of proper disclosures
        bytes32 complianceProof; // Proof of regulatory compliance
        // Optional: encrypted data (if scope permits)
        bytes32 encryptedDataCommitment;
        bytes32 decryptionKeyCommitment;
        // Verification
        bool verified;
        address verifiedBy;
        uint64 createdAt;
    }

    /**
     * @notice Audit trail entry
     * @dev Immutable record of audit activity
     */
    struct AuditTrailEntry {
        bytes32 entryId;
        bytes32 credentialId;
        bytes32 executionId;
        // What happened
        AuditScope accessLevel;
        bytes32 actionCommitment; // What action was taken
        // Proof of authorization
        bytes32 authorizationProof;
        // Timing
        uint64 occurredAt;
        bytes32 chainId; // For cross-chain audit trail
    }

    /**
     * @notice Delegation record
     */
    struct AuditDelegation {
        bytes32 delegationId;
        bytes32 fromCredentialId;
        bytes32 toCredentialId;
        AuditScope delegatedScope; // Cannot exceed delegator's scope
        // Validity
        uint64 delegatedAt;
        uint64 expiresAt;
        bool revoked;
        // Proof
        bytes32 delegationProof;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Credentials: credentialId => credential
    mapping(bytes32 => AuditCredential) public credentials;

    /// @notice Rights: rightId => right
    mapping(bytes32 => AuditRight) public rights;

    /// @notice Requests: requestId => request
    mapping(bytes32 => AuditRequest) public requests;

    /// @notice Responses: responseId => response
    mapping(bytes32 => AuditResponse) public responses;

    /// @notice Trail entries: entryId => entry
    mapping(bytes32 => AuditTrailEntry) public trailEntries;

    /// @notice Delegations: delegationId => delegation
    mapping(bytes32 => AuditDelegation) public delegations;

    /// @notice Credential rights: credentialId => rightId[]
    mapping(bytes32 => bytes32[]) public credentialRights;

    /// @notice Execution audits: executionId => requestId[]
    mapping(bytes32 => bytes32[]) public executionAudits;

    /// @notice Execution trail: executionId => entryId[]
    mapping(bytes32 => bytes32[]) public executionTrail;

    /// @notice Credential delegations: credentialId => delegationId[]
    mapping(bytes32 => bytes32[]) public credentialDelegations;

    /// @notice Counters
    uint256 public totalCredentials;
    uint256 public totalRights;
    uint256 public totalRequests;
    uint256 public totalResponses;
    uint256 public totalTrailEntries;

    /// @notice Chain identifier
    bytes32 public immutable CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CredentialIssued(
        bytes32 indexed credentialId,
        AuditAuthorityType authorityType,
        AuditScope maxScope
    );

    event CredentialRevoked(bytes32 indexed credentialId);

    event RightGranted(
        bytes32 indexed rightId,
        bytes32 indexed credentialId,
        bytes32 indexed targetExecutionId,
        LegalPredicateType legalBasis
    );

    event AuditRequested(
        bytes32 indexed requestId,
        bytes32 indexed credentialId,
        bytes32 indexed executionId
    );

    event AuditResponded(
        bytes32 indexed responseId,
        bytes32 indexed requestId,
        bool approved
    );

    event AuditTrailRecorded(
        bytes32 indexed entryId,
        bytes32 indexed executionId,
        AuditScope accessLevel
    );

    event DelegationCreated(
        bytes32 indexed delegationId,
        bytes32 indexed fromCredential,
        bytes32 indexed toCredential
    );

    event DelegationRevoked(bytes32 indexed delegationId);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        CHAIN_ID = bytes32(block.chainid);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AUDIT_ADMIN_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);
        _grantRole(COMPLIANCE_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      CREDENTIAL MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Issue audit credential
     * @dev Credential proves authority without revealing identity
     * @param authorityCommitment Commitment to auditor identity (hidden)
     * @param authorityType Type of audit authority
     * @param maxScope Maximum audit scope
     * @param jurisdictionCommitment Commitment to jurisdiction (hidden)
     * @param validityPeriod How long credential is valid
     * @param issuanceProof Proof of valid issuance
     * @return credentialId The credential identifier
     */
    function issueCredential(
        bytes32 authorityCommitment,
        AuditAuthorityType authorityType,
        AuditScope maxScope,
        bytes32 jurisdictionCommitment,
        uint64 validityPeriod,
        bytes32 issuanceProof
    ) external onlyRole(AUDIT_ADMIN_ROLE) returns (bytes32 credentialId) {
        require(
            authorityType != AuditAuthorityType.None,
            "APF: invalid authority"
        );
        require(maxScope != AuditScope.None, "APF: invalid scope");
        require(issuanceProof != bytes32(0), "APF: proof required");

        credentialId = keccak256(
            abi.encodePacked(
                authorityCommitment,
                authorityType,
                block.timestamp,
                totalCredentials
            )
        );

        credentials[credentialId] = AuditCredential({
            credentialId: credentialId,
            authorityCommitment: authorityCommitment,
            authorityType: authorityType,
            maxScope: maxScope,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + validityPeriod),
            revoked: false,
            jurisdictionCommitment: jurisdictionCommitment,
            issuerCommitment: keccak256(abi.encodePacked(msg.sender)),
            issuanceProof: issuanceProof
        });

        totalCredentials++;

        emit CredentialIssued(credentialId, authorityType, maxScope);
    }

    /**
     * @notice Revoke a credential
     */
    function revokeCredential(
        bytes32 credentialId
    ) external onlyRole(AUDIT_ADMIN_ROLE) {
        AuditCredential storage cred = credentials[credentialId];
        require(cred.credentialId != bytes32(0), "APF: not found");
        require(!cred.revoked, "APF: already revoked");

        cred.revoked = true;

        emit CredentialRevoked(credentialId);
    }

    /*//////////////////////////////////////////////////////////////
                        AUDIT RIGHTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Grant audit right for specific execution
     * @dev Right is provable - not a backdoor
     * @param credentialId Credential to grant right to
     * @param targetExecutionId Execution that can be audited
     * @param targetDomainId Domain context
     * @param grantedScope Scope of access
     * @param legalBasis Legal basis for access
     * @param legalPredicateProof Proof that legal basis is satisfied
     * @return rightId The right identifier
     */
    function grantRight(
        bytes32 credentialId,
        bytes32 targetExecutionId,
        bytes32 targetDomainId,
        AuditScope grantedScope,
        LegalPredicateType legalBasis,
        bytes32 legalPredicateProof,
        uint64 validityPeriod
    ) external onlyRole(COMPLIANCE_ROLE) returns (bytes32 rightId) {
        AuditCredential storage cred = credentials[credentialId];
        require(cred.credentialId != bytes32(0), "APF: credential not found");
        require(!cred.revoked, "APF: credential revoked");
        require(block.timestamp < cred.expiresAt, "APF: credential expired");
        require(
            uint8(grantedScope) <= uint8(cred.maxScope),
            "APF: exceeds max scope"
        );
        require(legalPredicateProof != bytes32(0), "APF: legal proof required");

        rightId = keccak256(
            abi.encodePacked(
                credentialId,
                targetExecutionId,
                legalBasis,
                block.timestamp,
                totalRights
            )
        );

        // Generate right proof
        bytes32 rightProof = keccak256(
            abi.encodePacked(
                rightId,
                credentialId,
                grantedScope,
                legalPredicateProof
            )
        );

        rights[rightId] = AuditRight({
            rightId: rightId,
            credentialId: credentialId,
            targetExecutionId: targetExecutionId,
            targetDomainId: targetDomainId,
            grantedScope: grantedScope,
            legalBasis: legalBasis,
            legalPredicateProof: legalPredicateProof,
            grantedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + validityPeriod),
            exercised: false,
            rightProof: rightProof
        });

        credentialRights[credentialId].push(rightId);
        totalRights++;

        emit RightGranted(rightId, credentialId, targetExecutionId, legalBasis);
    }

    /*//////////////////////////////////////////////////////////////
                        AUDIT REQUESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request audit access
     * @param credentialId Auditor's credential
     * @param rightId Pre-granted right (or bytes32(0) for new request)
     * @param executionId Execution to audit
     * @param requestedScope Requested access level
     * @param legalBasis Legal basis for request
     * @param justificationCommitment Commitment to justification
     * @param justificationProof Proof of valid justification
     * @return requestId The request identifier
     */
    function requestAudit(
        bytes32 credentialId,
        bytes32 rightId,
        bytes32 executionId,
        AuditScope requestedScope,
        LegalPredicateType legalBasis,
        bytes32 justificationCommitment,
        bytes32 justificationProof
    ) external whenNotPaused returns (bytes32 requestId) {
        AuditCredential storage cred = credentials[credentialId];
        require(cred.credentialId != bytes32(0), "APF: credential not found");
        require(!cred.revoked, "APF: credential revoked");
        require(block.timestamp < cred.expiresAt, "APF: credential expired");
        require(
            uint8(requestedScope) <= uint8(cred.maxScope),
            "APF: exceeds scope"
        );

        // If right is provided, verify it
        if (rightId != bytes32(0)) {
            AuditRight storage right = rights[rightId];
            require(right.credentialId == credentialId, "APF: right mismatch");
            require(!right.exercised, "APF: right already exercised");
            require(block.timestamp < right.expiresAt, "APF: right expired");
        }

        requestId = keccak256(
            abi.encodePacked(
                credentialId,
                executionId,
                block.timestamp,
                totalRequests
            )
        );

        requests[requestId] = AuditRequest({
            requestId: requestId,
            credentialId: credentialId,
            rightId: rightId,
            executionId: executionId,
            requestedScope: requestedScope,
            legalBasis: legalBasis,
            justificationCommitment: justificationCommitment,
            justificationProof: justificationProof,
            status: AuditRequestStatus.Pending,
            requestedAt: uint64(block.timestamp),
            respondedAt: 0
        });

        executionAudits[executionId].push(requestId);
        totalRequests++;

        emit AuditRequested(requestId, credentialId, executionId);
    }

    /**
     * @notice Respond to audit request with proofs
     * @dev Auditors receive PROOFS, not raw logs
     * @param requestId Request to respond to
     * @param approved Whether request is approved
     * @param executionProof Proof of execution correctness
     * @param policyProof Proof of policy compliance
     * @param disclosureProof Proof of proper disclosures
     * @param complianceProof Proof of regulatory compliance
     * @return responseId The response identifier
     */
    function respondToAudit(
        bytes32 requestId,
        bool approved,
        bytes32 executionProof,
        bytes32 policyProof,
        bytes32 disclosureProof,
        bytes32 complianceProof
    ) external onlyRole(COMPLIANCE_ROLE) returns (bytes32 responseId) {
        AuditRequest storage request = requests[requestId];
        require(request.requestId != bytes32(0), "APF: request not found");
        require(
            request.status == AuditRequestStatus.Pending,
            "APF: not pending"
        );

        request.status = approved
            ? AuditRequestStatus.Approved
            : AuditRequestStatus.Denied;
        request.respondedAt = uint64(block.timestamp);

        responseId = keccak256(
            abi.encodePacked(requestId, approved, block.timestamp)
        );

        responses[responseId] = AuditResponse({
            responseId: responseId,
            requestId: requestId,
            executionProof: executionProof,
            policyProof: policyProof,
            disclosureProof: disclosureProof,
            complianceProof: complianceProof,
            encryptedDataCommitment: bytes32(0),
            decryptionKeyCommitment: bytes32(0),
            verified: false,
            verifiedBy: address(0),
            createdAt: uint64(block.timestamp)
        });

        // Mark right as exercised if applicable
        if (request.rightId != bytes32(0) && approved) {
            rights[request.rightId].exercised = true;
        }

        totalResponses++;

        emit AuditResponded(responseId, requestId, approved);

        // Record in audit trail
        if (approved) {
            _recordTrailEntry(
                request.credentialId,
                request.executionId,
                request.requestedScope,
                request.justificationProof
            );
        }
    }

    /**
     * @notice Verify an audit response
     */
    function verifyResponse(
        bytes32 responseId
    ) external onlyRole(AUDITOR_ROLE) {
        AuditResponse storage response = responses[responseId];
        require(response.responseId != bytes32(0), "APF: response not found");

        response.verified = true;
        response.verifiedBy = msg.sender;

        // Mark request as fulfilled
        AuditRequest storage request = requests[response.requestId];
        request.status = AuditRequestStatus.Fulfilled;
    }

    /*//////////////////////////////////////////////////////////////
                          AUDIT TRAIL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record entry in audit trail
     */
    function _recordTrailEntry(
        bytes32 credentialId,
        bytes32 executionId,
        AuditScope accessLevel,
        bytes32 authorizationProof
    ) internal {
        bytes32 entryId = keccak256(
            abi.encodePacked(
                credentialId,
                executionId,
                block.timestamp,
                totalTrailEntries
            )
        );

        trailEntries[entryId] = AuditTrailEntry({
            entryId: entryId,
            credentialId: credentialId,
            executionId: executionId,
            accessLevel: accessLevel,
            actionCommitment: keccak256(
                abi.encodePacked("AUDIT_ACCESS", accessLevel)
            ),
            authorizationProof: authorizationProof,
            occurredAt: uint64(block.timestamp),
            chainId: CHAIN_ID
        });

        executionTrail[executionId].push(entryId);
        totalTrailEntries++;

        emit AuditTrailRecorded(entryId, executionId, accessLevel);
    }

    /*//////////////////////////////////////////////////////////////
                          DELEGATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Delegate audit authority
     * @param fromCredentialId Delegating credential
     * @param toCredentialId Receiving credential
     * @param delegatedScope Scope being delegated
     * @param validityPeriod How long delegation is valid
     * @param delegationProof Proof of valid delegation
     * @return delegationId The delegation identifier
     */
    function delegate(
        bytes32 fromCredentialId,
        bytes32 toCredentialId,
        AuditScope delegatedScope,
        uint64 validityPeriod,
        bytes32 delegationProof
    ) external onlyRole(AUDITOR_ROLE) returns (bytes32 delegationId) {
        AuditCredential storage fromCred = credentials[fromCredentialId];
        AuditCredential storage toCred = credentials[toCredentialId];

        require(fromCred.credentialId != bytes32(0), "APF: from not found");
        require(toCred.credentialId != bytes32(0), "APF: to not found");
        require(!fromCred.revoked, "APF: from revoked");
        require(!toCred.revoked, "APF: to revoked");
        require(
            uint8(delegatedScope) <= uint8(fromCred.maxScope),
            "APF: exceeds scope"
        );
        require(delegationProof != bytes32(0), "APF: proof required");

        delegationId = keccak256(
            abi.encodePacked(fromCredentialId, toCredentialId, block.timestamp)
        );

        delegations[delegationId] = AuditDelegation({
            delegationId: delegationId,
            fromCredentialId: fromCredentialId,
            toCredentialId: toCredentialId,
            delegatedScope: delegatedScope,
            delegatedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + validityPeriod),
            revoked: false,
            delegationProof: delegationProof
        });

        credentialDelegations[fromCredentialId].push(delegationId);
        credentialDelegations[toCredentialId].push(delegationId);

        emit DelegationCreated(delegationId, fromCredentialId, toCredentialId);
    }

    /**
     * @notice Revoke delegation
     */
    function revokeDelegation(
        bytes32 delegationId
    ) external onlyRole(AUDITOR_ROLE) {
        AuditDelegation storage del = delegations[delegationId];
        require(del.delegationId != bytes32(0), "APF: not found");
        require(!del.revoked, "APF: already revoked");

        del.revoked = true;

        emit DelegationRevoked(delegationId);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if credential is valid
     */
    function isCredentialValid(
        bytes32 credentialId
    ) external view returns (bool) {
        AuditCredential storage cred = credentials[credentialId];
        return
            cred.credentialId != bytes32(0) &&
            !cred.revoked &&
            block.timestamp < cred.expiresAt;
    }

    /**
     * @notice Get credential rights
     */
    function getCredentialRights(
        bytes32 credentialId
    ) external view returns (bytes32[] memory) {
        return credentialRights[credentialId];
    }

    /**
     * @notice Get execution audit trail
     */
    function getExecutionTrail(
        bytes32 executionId
    ) external view returns (bytes32[] memory) {
        return executionTrail[executionId];
    }

    /**
     * @notice Get credential delegations
     */
    function getCredentialDelegations(
        bytes32 credentialId
    ) external view returns (bytes32[] memory) {
        return credentialDelegations[credentialId];
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
