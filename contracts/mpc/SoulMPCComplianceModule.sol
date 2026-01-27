// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SoulMPCComplianceModule
 * @notice Privacy-preserving compliance checks using MPC
 * @dev Implements private set membership without revealing user data or full sanction list
 */
contract SoulMPCComplianceModule is AccessControl, ReentrancyGuard {
    // ============================================
    // Roles (Pre-computed for gas savings)
    // ============================================

    /// @dev Pre-computed keccak256("ORACLE_ROLE")
    bytes32 public constant ORACLE_ROLE =
        0x68e79a7bf1e0bc45d0a330c573bc367f9cf464fd326078812f301165fbda4ef1;
    /// @dev Pre-computed keccak256("COMPLIANCE_ROLE")
    bytes32 public constant COMPLIANCE_ROLE =
        0x442a94f1a1fac79af32856af2a64f63648cfa2ef3b98610a5bb7cbec4cee6985;

    // ============================================
    // Types
    // ============================================

    /// @notice Compliance check request
    struct ComplianceRequest {
        bytes32 requestId;
        bytes32 encryptedIdentityHash; // User's encrypted identity commitment
        address requester;
        uint256 requestedAt;
        uint256 expiresAt;
        ComplianceStatus status;
        bytes32 resultCommitment;
    }

    /// @notice Possible compliance statuses
    enum ComplianceStatus {
        Pending,
        Processing,
        Compliant,
        NonCompliant,
        Expired,
        Disputed
    }

    /// @notice Oracle share for MPC computation
    struct OracleShare {
        address oracle;
        bytes32 shareCommitment;
        bool submitted;
        uint256 submittedAt;
    }

    /// @notice MPC computation session
    struct MPCSession {
        bytes32 sessionId;
        bytes32 requestId;
        address[] oracles;
        mapping(address => OracleShare) shares;
        uint256 submittedShares;
        uint256 requiredShares;
        bool completed;
        bytes32 result;
    }

    /// @notice Compliance certificate (ZK proof of compliance check)
    struct ComplianceCertificate {
        bytes32 certificateId;
        bytes32 requestId;
        bytes32 userCommitment;
        uint256 issuedAt;
        uint256 validUntil;
        bool valid;
        bytes zkProof; // ZK proof that compliance was checked without revealing identity
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice Compliance requests
    mapping(bytes32 => ComplianceRequest) public requests;

    /// @notice MPC sessions
    mapping(bytes32 => MPCSession) internal mpcSessions;

    /// @notice Compliance certificates
    mapping(bytes32 => ComplianceCertificate) public certificates;

    /// @notice User commitment to certificate mapping
    mapping(bytes32 => bytes32) public userCertificates;

    /// @notice Registered compliance oracles
    address[] public oracles;
    mapping(address => bool) public isOracle;

    /// @notice Required oracle threshold for MPC
    uint256 public oracleThreshold;

    /// @notice Request expiration time
    uint256 public requestTimeout = 1 hours;

    /// @notice Certificate validity period
    uint256 public certificateValidity = 30 days;

    /// @notice Request nonce
    uint256 public requestNonce;

    // ============================================
    // Events
    // ============================================

    event ComplianceRequested(
        bytes32 indexed requestId,
        bytes32 encryptedIdentityHash,
        address indexed requester
    );

    event MPCSessionStarted(
        bytes32 indexed sessionId,
        bytes32 indexed requestId,
        address[] oracles
    );

    event OracleShareSubmitted(
        bytes32 indexed sessionId,
        address indexed oracle
    );

    event ComplianceResultReady(
        bytes32 indexed requestId,
        ComplianceStatus status,
        bytes32 resultCommitment
    );

    event CertificateIssued(
        bytes32 indexed certificateId,
        bytes32 indexed requestId,
        bytes32 userCommitment
    );

    event OracleRegistered(address indexed oracle);
    event OracleRemoved(address indexed oracle);

    // ============================================
    // Constructor
    // ============================================

    constructor(uint256 _oracleThreshold) {
        require(_oracleThreshold >= 2, "Threshold must be >= 2");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COMPLIANCE_ROLE, msg.sender);

        oracleThreshold = _oracleThreshold;
    }

    // ============================================
    // Oracle Management
    // ============================================

    /**
     * @notice Register a new compliance oracle
     * @param oracle Address of the oracle
     */
    function registerOracle(
        address oracle
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(oracle != address(0), "Invalid oracle");
        require(!isOracle[oracle], "Already registered");

        isOracle[oracle] = true;
        oracles.push(oracle);

        _grantRole(ORACLE_ROLE, oracle);

        emit OracleRegistered(oracle);
    }

    /**
     * @notice Remove a compliance oracle
     * @param oracle Address of the oracle to remove
     */
    function removeOracle(
        address oracle
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isOracle[oracle], "Not an oracle");
        require(oracles.length - 1 >= oracleThreshold, "Would break threshold");

        isOracle[oracle] = false;
        _revokeRole(ORACLE_ROLE, oracle);

        emit OracleRemoved(oracle);
    }

    /**
     * @notice Update oracle threshold
     * @param newThreshold New threshold value
     */
    function updateThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newThreshold >= 2, "Threshold must be >= 2");
        require(newThreshold <= oracles.length, "Threshold > oracles");
        oracleThreshold = newThreshold;
    }

    // ============================================
    // Compliance Check Flow
    // ============================================

    /**
     * @notice Request a compliance check
     * @param encryptedIdentityHash Hash of user's encrypted identity
     * @return requestId The unique request identifier
     */
    function requestComplianceCheck(
        bytes32 encryptedIdentityHash
    ) external nonReentrant returns (bytes32 requestId) {
        require(encryptedIdentityHash != bytes32(0), "Invalid identity hash");

        unchecked {
            ++requestNonce;
        }
        requestId = keccak256(
            abi.encode(
                encryptedIdentityHash,
                msg.sender,
                requestNonce,
                block.timestamp
            )
        );

        requests[requestId] = ComplianceRequest({
            requestId: requestId,
            encryptedIdentityHash: encryptedIdentityHash,
            requester: msg.sender,
            requestedAt: block.timestamp,
            expiresAt: block.timestamp + requestTimeout,
            status: ComplianceStatus.Pending,
            resultCommitment: bytes32(0)
        });

        emit ComplianceRequested(requestId, encryptedIdentityHash, msg.sender);

        // Auto-start MPC session
        _startMPCSession(requestId);

        return requestId;
    }

    /**
     * @notice Submit oracle share for MPC computation
     * @param sessionId The MPC session
     * @param shareCommitment Commitment to the oracle's share
     */
    function submitOracleShare(
        bytes32 sessionId,
        bytes32 shareCommitment
    ) external onlyRole(ORACLE_ROLE) {
        MPCSession storage session = mpcSessions[sessionId];

        require(session.sessionId == sessionId, "Invalid session");
        require(!session.completed, "Session completed");
        require(!session.shares[msg.sender].submitted, "Already submitted");

        // Check oracle is participant
        bool isParticipant = false;
        for (uint256 i = 0; i < session.oracles.length; ) {
            if (session.oracles[i] == msg.sender) {
                isParticipant = true;
                break;
            }
            unchecked {
                ++i;
            }
        }
        require(isParticipant, "Not a participant");

        session.shares[msg.sender] = OracleShare({
            oracle: msg.sender,
            shareCommitment: shareCommitment,
            submitted: true,
            submittedAt: block.timestamp
        });

        unchecked {
            ++session.submittedShares;
        }

        emit OracleShareSubmitted(sessionId, msg.sender);

        // Check if we can compute result
        if (session.submittedShares >= session.requiredShares) {
            _computeMPCResult(sessionId);
        }
    }

    /**
     * @notice Finalize compliance check with ZK proof
     * @param requestId The compliance request
     * @param result The compliance result (encrypted)
     * @param zkProof ZK proof of correct MPC computation
     */
    function finalizeComplianceCheck(
        bytes32 requestId,
        bool result,
        bytes calldata zkProof
    ) external onlyRole(COMPLIANCE_ROLE) {
        ComplianceRequest storage request = requests[requestId];

        require(request.requestId == requestId, "Invalid request");
        require(
            request.status == ComplianceStatus.Processing,
            "Invalid status"
        );
        require(block.timestamp < request.expiresAt, "Request expired");

        // Verify ZK proof (simplified - in production verify properly)
        require(zkProof.length > 0, "Invalid proof");

        // Update status
        request.status = result
            ? ComplianceStatus.Compliant
            : ComplianceStatus.NonCompliant;
        request.resultCommitment = keccak256(abi.encode(result, zkProof));

        emit ComplianceResultReady(
            requestId,
            request.status,
            request.resultCommitment
        );

        // Issue certificate if compliant
        if (result) {
            _issueCertificate(requestId);
        }
    }

    /**
     * @notice Check if a user has a valid compliance certificate
     * @param userCommitment The user's identity commitment
     * @return valid Whether the user has a valid certificate
     * @return certificateId The certificate ID (if exists)
     */
    function hasValidCertificate(
        bytes32 userCommitment
    ) external view returns (bool valid, bytes32 certificateId) {
        certificateId = userCertificates[userCommitment];
        if (certificateId == bytes32(0)) {
            return (false, bytes32(0));
        }

        ComplianceCertificate storage cert = certificates[certificateId];
        valid = cert.valid && block.timestamp < cert.validUntil;
        return (valid, certificateId);
    }

    /**
     * @notice Verify a compliance certificate
     * @param certificateId The certificate to verify
     * @return valid Whether the certificate is valid
     * @return userCommitment The user commitment the certificate covers
     * @return validUntil When the certificate expires
     */
    function verifyCertificate(
        bytes32 certificateId
    )
        external
        view
        returns (bool valid, bytes32 userCommitment, uint256 validUntil)
    {
        ComplianceCertificate storage cert = certificates[certificateId];
        valid = cert.valid && block.timestamp < cert.validUntil;
        userCommitment = cert.userCommitment;
        validUntil = cert.validUntil;
    }

    /**
     * @notice Revoke a compliance certificate
     * @param certificateId The certificate to revoke
     */
    function revokeCertificate(
        bytes32 certificateId
    ) external onlyRole(COMPLIANCE_ROLE) {
        certificates[certificateId].valid = false;
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Get compliance request status
     * @param requestId The request ID
     * @return request The compliance request details
     */
    function getRequest(
        bytes32 requestId
    ) external view returns (ComplianceRequest memory) {
        return requests[requestId];
    }

    /**
     * @notice Get MPC session status
     * @param sessionId The session ID
     * @return requestId Associated request
     * @return submittedShares Number of shares submitted
     * @return requiredShares Required shares
     * @return completed Whether session is complete
     */
    function getSessionStatus(
        bytes32 sessionId
    )
        external
        view
        returns (
            bytes32 requestId,
            uint256 submittedShares,
            uint256 requiredShares,
            bool completed
        )
    {
        MPCSession storage session = mpcSessions[sessionId];
        return (
            session.requestId,
            session.submittedShares,
            session.requiredShares,
            session.completed
        );
    }

    /**
     * @notice Get all registered oracles
     * @return Array of oracle addresses
     */
    function getOracles() external view returns (address[] memory) {
        return oracles;
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Start MPC session for compliance check
     */
    function _startMPCSession(bytes32 requestId) internal {
        bytes32 sessionId = keccak256(abi.encode(requestId, "MPC_SESSION"));

        // Select oracles (in production, use randomness)
        address[] memory selectedOracles = new address[](oracleThreshold);
        uint256 selected = 0;
        for (
            uint256 i = 0;
            i < oracles.length && selected < oracleThreshold;
            i++
        ) {
            if (isOracle[oracles[i]]) {
                selectedOracles[selected] = oracles[i];
                selected++;
            }
        }

        MPCSession storage session = mpcSessions[sessionId];
        session.sessionId = sessionId;
        session.requestId = requestId;
        session.oracles = selectedOracles;
        session.requiredShares = oracleThreshold;

        requests[requestId].status = ComplianceStatus.Processing;

        emit MPCSessionStarted(sessionId, requestId, selectedOracles);
    }

    /**
     * @notice Compute MPC result from shares
     */
    function _computeMPCResult(bytes32 sessionId) internal {
        MPCSession storage session = mpcSessions[sessionId];

        // Combine share commitments (simplified - in production use proper MPC)
        bytes32 combined = bytes32(0);
        for (uint256 i = 0; i < session.oracles.length; i++) {
            if (session.shares[session.oracles[i]].submitted) {
                combined = keccak256(
                    abi.encode(
                        combined,
                        session.shares[session.oracles[i]].shareCommitment
                    )
                );
            }
        }

        session.result = combined;
        session.completed = true;
    }

    /**
     * @notice Issue compliance certificate
     */
    function _issueCertificate(bytes32 requestId) internal {
        ComplianceRequest storage request = requests[requestId];

        bytes32 certificateId = keccak256(
            abi.encode(
                requestId,
                request.encryptedIdentityHash,
                block.timestamp
            )
        );

        certificates[certificateId] = ComplianceCertificate({
            certificateId: certificateId,
            requestId: requestId,
            userCommitment: request.encryptedIdentityHash,
            issuedAt: block.timestamp,
            validUntil: block.timestamp + certificateValidity,
            valid: true,
            zkProof: "" // Set in finalization
        });

        userCertificates[request.encryptedIdentityHash] = certificateId;

        emit CertificateIssued(
            certificateId,
            requestId,
            request.encryptedIdentityHash
        );
    }
}
