// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title CryptographicAttestation
 * @author Soul Security Team
 * @notice TEE-based attestation and remote verification for watchtower nodes
 * @dev Implements SGX/TDX-style attestation quotes and verification
 */
contract CryptographicAttestation is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============ Roles ============
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    // ============ Enums ============
    enum AttestationType {
        SGX_DCAP, // Intel SGX Data Center Attestation
        TDX, // Intel Trust Domain Extensions
        SEV_SNP, // AMD SEV-SNP
        ARM_CCA, // ARM Confidential Compute
        TPM, // Trusted Platform Module
        NITRO, // AWS Nitro Enclaves
        CUSTOM // Custom attestation scheme
    }

    enum AttestationStatus {
        PENDING,
        VERIFIED,
        EXPIRED,
        REVOKED,
        FAILED
    }

    enum NodeType {
        WATCHTOWER,
        PROVER,
        RELAYER,
        VALIDATOR,
        ORACLE
    }

    // ============ Structs ============
    struct AttestationQuote {
        bytes32 id;
        address attester;
        AttestationType attestationType;
        NodeType nodeType;
        bytes32 enclaveHash; // MRENCLAVE or equivalent
        bytes32 signerHash; // MRSIGNER or equivalent
        bytes32 reportData; // Custom data in attestation
        bytes signature; // Quote signature
        uint256 timestamp;
        uint256 expiresAt;
        AttestationStatus status;
        bytes32 pccsRoot; // Intel PCCS root hash
        uint16 tcbLevel; // TCB (Trusted Computing Base) level
    }

    struct AttesterNode {
        address attester;
        NodeType nodeType;
        bytes32 currentQuoteId;
        uint256 registeredAt;
        uint256 lastAttestationAt;
        bool active;
        uint256 attestationCount;
        uint256 failedAttestations;
        bytes32[] quoteHistory;
        mapping(bytes32 => bool) revokedQuotes;
    }

    struct TrustedMeasurement {
        bytes32 measurementHash;
        string version;
        uint256 addedAt;
        uint256 expiresAt;
        bool active;
        NodeType nodeType;
    }

    struct VerificationResult {
        bool valid;
        bytes32 quoteId;
        string reason;
        uint256 verifiedAt;
        address verifier;
    }

    struct RemoteAttestationChallenge {
        bytes32 challengeId;
        address challenger;
        address target;
        bytes32 nonce;
        uint256 createdAt;
        uint256 expiresAt;
        bool completed;
        bool passed;
    }

    // ============ Constants ============
    uint256 public constant ATTESTATION_VALIDITY = 24 hours;
    uint256 public constant CHALLENGE_TIMEOUT = 5 minutes;
    uint256 public constant MAX_TCB_LEVEL = 100;
    uint256 public constant MIN_ATTESTATION_INTERVAL = 1 hours;
    uint256 public constant MAX_FAILED_ATTESTATIONS = 5;

    // ============ State Variables ============
    mapping(bytes32 => AttestationQuote) public quotes;
    mapping(address => AttesterNode) private _attesterNodes;
    mapping(bytes32 => TrustedMeasurement) public trustedMeasurements;
    mapping(bytes32 => RemoteAttestationChallenge) public challenges;
    mapping(bytes32 => VerificationResult) public verificationResults;

    bytes32[] public quoteIds;
    bytes32[] public trustedMeasurementHashes;
    address[] public registeredAttesters;

    // PCCS (Provisioning Certification Caching Service) roots
    mapping(bytes32 => bool) public trustedPCCSRoots;

    // TCB info
    mapping(AttestationType => uint16) public minTcbLevel;

    // Statistics
    uint256 public totalAttestations;
    uint256 public activeAttestations;
    uint256 public totalVerifications;

    // ============ Events ============
    event AttesterRegistered(address indexed attester, NodeType nodeType);
    event AttestationSubmitted(
        bytes32 indexed quoteId,
        address indexed attester,
        AttestationType attestationType
    );
    event AttestationVerified(
        bytes32 indexed quoteId,
        address indexed verifier,
        bool valid
    );
    event AttestationExpired(bytes32 indexed quoteId);
    event AttestationRevoked(bytes32 indexed quoteId, string reason);
    event TrustedMeasurementAdded(
        bytes32 indexed measurementHash,
        NodeType nodeType,
        string version
    );
    event TrustedMeasurementRevoked(bytes32 indexed measurementHash);
    event ChallengeIssued(
        bytes32 indexed challengeId,
        address indexed challenger,
        address indexed target
    );
    event ChallengeCompleted(bytes32 indexed challengeId, bool passed);
    event PCCSRootUpdated(bytes32 pccsRoot, bool trusted);
    event TCBLevelUpdated(AttestationType attestationType, uint16 minLevel);

    // ============ Errors ============
    error NotRegistered();
    error AlreadyRegistered();
    error InvalidQuote();
    error QuoteExpired();
    error QuoteNotFound();
    error UntrustedMeasurement();
    error UntrustedPCCSRoot();
    error TCBLevelTooLow();
    error AttestationTooRecent();
    error TooManyFailedAttestations();
    error ChallengeExpired();
    error ChallengeNotFound();
    error InvalidSignature();
    error ZeroAddress();
    error LevelTooHigh();


    // ============ Constructor ============
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);

        // Set default minimum TCB levels
        minTcbLevel[AttestationType.SGX_DCAP] = 5;
        minTcbLevel[AttestationType.TDX] = 3;
        minTcbLevel[AttestationType.SEV_SNP] = 3;
        minTcbLevel[AttestationType.NITRO] = 1;
    }

    // ============ Registration ============

    /**
     * @notice Register as an attester node
     * @param nodeType Type of node
     */
    function registerAttester(NodeType nodeType) external {
        if (_attesterNodes[msg.sender].attester != address(0))
            revert AlreadyRegistered();

        AttesterNode storage node = _attesterNodes[msg.sender];
        node.attester = msg.sender;
        node.nodeType = nodeType;
        node.registeredAt = block.timestamp;
        node.active = true;

        registeredAttesters.push(msg.sender);

        emit AttesterRegistered(msg.sender, nodeType);
    }

    // ============ Attestation Submission ============

    /**
     * @notice Submit an attestation quote
     * @param attestationType Type of attestation
     * @param enclaveHash MRENCLAVE or equivalent measurement
     * @param signerHash MRSIGNER or equivalent
     * @param reportData Custom data embedded in attestation
     * @param signature Quote signature from TEE
     * @param pccsRoot PCCS root hash
     * @param tcbLevel TCB level of the platform
     * @return quoteId Unique quote ID
     */
    function submitAttestation(
        AttestationType attestationType,
        bytes32 enclaveHash,
        bytes32 signerHash,
        bytes32 reportData,
        bytes calldata signature,
        bytes32 pccsRoot,
        uint16 tcbLevel
    ) external nonReentrant returns (bytes32 quoteId) {
        AttesterNode storage node = _attesterNodes[msg.sender];
        if (node.attester == address(0)) revert NotRegistered();
        if (node.failedAttestations >= MAX_FAILED_ATTESTATIONS)
            revert TooManyFailedAttestations();

        // Rate limit
        if (
            block.timestamp < node.lastAttestationAt + MIN_ATTESTATION_INTERVAL
        ) {
            revert AttestationTooRecent();
        }

        // Verify PCCS root is trusted
        if (!trustedPCCSRoots[pccsRoot]) revert UntrustedPCCSRoot();

        // Verify TCB level
        if (tcbLevel < minTcbLevel[attestationType]) revert TCBLevelTooLow();

        // Verify enclave measurement is trusted
        bytes32 measurementKey = keccak256(
            abi.encodePacked(enclaveHash, node.nodeType)
        );
        if (!trustedMeasurements[measurementKey].active)
            revert UntrustedMeasurement();

        quoteId = keccak256(
            abi.encodePacked(
                msg.sender,
                attestationType,
                enclaveHash,
                block.timestamp,
                totalAttestations
            )
        );

        quotes[quoteId] = AttestationQuote({
            id: quoteId,
            attester: msg.sender,
            attestationType: attestationType,
            nodeType: node.nodeType,
            enclaveHash: enclaveHash,
            signerHash: signerHash,
            reportData: reportData,
            signature: signature,
            timestamp: block.timestamp,
            expiresAt: block.timestamp + ATTESTATION_VALIDITY,
            status: AttestationStatus.PENDING,
            pccsRoot: pccsRoot,
            tcbLevel: tcbLevel
        });

        quoteIds.push(quoteId);
        node.quoteHistory.push(quoteId);
        node.lastAttestationAt = block.timestamp;
        totalAttestations++;

        emit AttestationSubmitted(quoteId, msg.sender, attestationType);
    }

    // ============ Verification ============

    /**
     * @notice Verify an attestation quote
     * @param quoteId Quote to verify
     * @return result Verification result
     */
    function verifyAttestation(
        bytes32 quoteId
    )
        external
        onlyRole(VERIFIER_ROLE)
        returns (VerificationResult memory result)
    {
        AttestationQuote storage quote = quotes[quoteId];
        if (quote.attester == address(0)) revert QuoteNotFound();

        result.quoteId = quoteId;
        result.verifiedAt = block.timestamp;
        result.verifier = msg.sender;

        // Check expiry
        if (block.timestamp > quote.expiresAt) {
            result.valid = false;
            result.reason = "Quote expired";
            quote.status = AttestationStatus.EXPIRED;
            emit AttestationExpired(quoteId);
            return result;
        }

        // Verify signature
        bytes32 messageHash = _computeQuoteHash(quote);
        bool signatureValid = _verifyQuoteSignature(
            messageHash,
            quote.signature,
            quote.attester
        );

        if (!signatureValid) {
            result.valid = false;
            result.reason = "Invalid signature";
            quote.status = AttestationStatus.FAILED;
            _attesterNodes[quote.attester].failedAttestations++;
            return result;
        }

        // All checks passed
        result.valid = true;
        result.reason = "Verification successful";
        quote.status = AttestationStatus.VERIFIED;

        AttesterNode storage node = _attesterNodes[quote.attester];
        node.currentQuoteId = quoteId;
        node.attestationCount++;
        activeAttestations++;

        verificationResults[quoteId] = result;
        totalVerifications++;

        emit AttestationVerified(quoteId, msg.sender, true);
    }

    /**
     * @notice Issue a remote attestation challenge
     * @param target Target attester
     * @return challengeId Challenge ID
     */
    function issueChallenge(
        address target
    ) external onlyRole(VERIFIER_ROLE) returns (bytes32 challengeId) {
        if (target == address(0)) revert ZeroAddress();
        if (_attesterNodes[target].attester == address(0))
            revert NotRegistered();

        bytes32 nonce = keccak256(
            abi.encodePacked(
                block.timestamp,
                block.prevrandao,
                msg.sender,
                target
            )
        );

        challengeId = keccak256(abi.encodePacked(nonce, block.number));

        challenges[challengeId] = RemoteAttestationChallenge({
            challengeId: challengeId,
            challenger: msg.sender,
            target: target,
            nonce: nonce,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + CHALLENGE_TIMEOUT,
            completed: false,
            passed: false
        });

        emit ChallengeIssued(challengeId, msg.sender, target);
    }

    /**
     * @notice Respond to a challenge with fresh attestation
     * @param challengeId Challenge to respond to
     * @param quoteId Fresh attestation quote
     */
    function respondToChallenge(bytes32 challengeId, bytes32 quoteId) external {
        RemoteAttestationChallenge storage challenge = challenges[challengeId];
        if (challenge.target == address(0)) revert ChallengeNotFound();
        if (challenge.target != msg.sender) revert NotRegistered();
        if (block.timestamp > challenge.expiresAt) revert ChallengeExpired();

        AttestationQuote storage quote = quotes[quoteId];
        if (quote.attester != msg.sender) revert InvalidQuote();

        // Quote must be fresh (submitted after challenge)
        bool passed = quote.timestamp >= challenge.createdAt &&
            quote.status == AttestationStatus.VERIFIED &&
            quote.reportData == challenge.nonce;

        challenge.completed = true;
        challenge.passed = passed;

        emit ChallengeCompleted(challengeId, passed);
    }

    // ============ Trusted Measurements ============

    /**
     * @notice Add a trusted enclave measurement
     * @param measurementHash Enclave measurement hash
     * @param nodeType Type of node this measurement is for
     * @param version Version string
     * @param validityPeriod How long this measurement is trusted
     */
    function addTrustedMeasurement(
        bytes32 measurementHash,
        NodeType nodeType,
        string calldata version,
        uint256 validityPeriod
    ) external onlyRole(GOVERNANCE_ROLE) {
        bytes32 key = keccak256(abi.encodePacked(measurementHash, nodeType));

        trustedMeasurements[key] = TrustedMeasurement({
            measurementHash: measurementHash,
            version: version,
            addedAt: block.timestamp,
            expiresAt: block.timestamp + validityPeriod,
            active: true,
            nodeType: nodeType
        });

        trustedMeasurementHashes.push(key);

        emit TrustedMeasurementAdded(measurementHash, nodeType, version);
    }

    /**
     * @notice Revoke a trusted measurement
     * @param measurementHash Measurement to revoke
     * @param nodeType Node type
     */
    function revokeTrustedMeasurement(
        bytes32 measurementHash,
        NodeType nodeType
    ) external onlyRole(GOVERNANCE_ROLE) {
        bytes32 key = keccak256(abi.encodePacked(measurementHash, nodeType));
        trustedMeasurements[key].active = false;

        emit TrustedMeasurementRevoked(measurementHash);
    }

    /**
     * @notice Update PCCS root trust status
     * @param pccsRoot PCCS root hash
     * @param trusted Whether it's trusted
     */
    function updatePCCSRoot(
        bytes32 pccsRoot,
        bool trusted
    ) external onlyRole(GOVERNANCE_ROLE) {
        trustedPCCSRoots[pccsRoot] = trusted;
        emit PCCSRootUpdated(pccsRoot, trusted);
    }

    /**
     * @notice Update minimum TCB level
     * @param attestationType Attestation type
     * @param minLevel Minimum level
     */
    function updateMinTCBLevel(
        AttestationType attestationType,
        uint16 minLevel
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (minLevel > MAX_TCB_LEVEL) revert LevelTooHigh();
        minTcbLevel[attestationType] = minLevel;
        emit TCBLevelUpdated(attestationType, minLevel);
    }

    // ============ View Functions ============

    /**
     * @notice Check if an attester has valid attestation
     * @param attester Attester address
     * @return valid Whether attestation is valid
     * @return quoteId Current quote ID
     */
    function isAttested(
        address attester
    ) external view returns (bool valid, bytes32 quoteId) {
        AttesterNode storage node = _attesterNodes[attester];
        if (node.attester == address(0)) return (false, bytes32(0));

        quoteId = node.currentQuoteId;
        if (quoteId == bytes32(0)) return (false, bytes32(0));

        AttestationQuote storage quote = quotes[quoteId];
        valid =
            quote.status == AttestationStatus.VERIFIED &&
            block.timestamp <= quote.expiresAt;
    }

    /**
     * @notice Get attester info
     * @param attester Attester address
     */
    function getAttesterInfo(
        address attester
    )
        external
        view
        returns (
            NodeType nodeType,
            bytes32 currentQuoteId,
            uint256 attestationCount,
            uint256 failedAttestations,
            bool active
        )
    {
        AttesterNode storage node = _attesterNodes[attester];
        return (
            node.nodeType,
            node.currentQuoteId,
            node.attestationCount,
            node.failedAttestations,
            node.active
        );
    }

    /**
     * @notice Get quote details
     * @param quoteId Quote ID
     */
    function getQuote(
        bytes32 quoteId
    ) external view returns (AttestationQuote memory) {
        return quotes[quoteId];
    }

    /**
     * @notice Get all registered attesters
     */
    function getRegisteredAttesters() external view returns (address[] memory) {
        return registeredAttesters;
    }

    /**
     * @notice Get attesters with valid attestations
     */
    function getActiveAttesters() external view returns (address[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < registeredAttesters.length; i++) {
            AttesterNode storage node = _attesterNodes[registeredAttesters[i]];
            if (node.active && node.currentQuoteId != bytes32(0)) {
                AttestationQuote storage quote = quotes[node.currentQuoteId];
                if (
                    quote.status == AttestationStatus.VERIFIED &&
                    block.timestamp <= quote.expiresAt
                ) {
                    count++;
                }
            }
        }

        address[] memory active = new address[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < registeredAttesters.length; i++) {
            AttesterNode storage node = _attesterNodes[registeredAttesters[i]];
            if (node.active && node.currentQuoteId != bytes32(0)) {
                AttestationQuote storage quote = quotes[node.currentQuoteId];
                if (
                    quote.status == AttestationStatus.VERIFIED &&
                    block.timestamp <= quote.expiresAt
                ) {
                    active[index++] = registeredAttesters[i];
                }
            }
        }

        return active;
    }

    // ============ Admin Functions ============

    /**
     * @notice Revoke an attestation
     * @param quoteId Quote to revoke
     * @param reason Reason for revocation
     */
    function revokeAttestation(
        bytes32 quoteId,
        string calldata reason
    ) external onlyRole(GOVERNANCE_ROLE) {
        AttestationQuote storage quote = quotes[quoteId];
        if (quote.attester == address(0)) revert QuoteNotFound();

        quote.status = AttestationStatus.REVOKED;
        _attesterNodes[quote.attester].revokedQuotes[quoteId] = true;

        if (_attesterNodes[quote.attester].currentQuoteId == quoteId) {
            _attesterNodes[quote.attester].currentQuoteId = bytes32(0);
            activeAttestations--;
        }

        emit AttestationRevoked(quoteId, reason);
    }

    /**
     * @notice Deactivate an attester node
     * @param attester Attester to deactivate
     */
    function deactivateAttester(
        address attester
    ) external onlyRole(GOVERNANCE_ROLE) {
        _attesterNodes[attester].active = false;
    }

    // ============ Internal Functions ============

    function _computeQuoteHash(
        AttestationQuote storage quote
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    quote.attester,
                    quote.attestationType,
                    quote.enclaveHash,
                    quote.signerHash,
                    quote.reportData,
                    quote.timestamp,
                    quote.pccsRoot,
                    quote.tcbLevel
                )
            );
    }

    function _verifyQuoteSignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        // Verify attestation quote signature using ECDSA
        // TEE attestations (Intel SGX, AWS Nitro) are verified off-chain
        // The on-chain attestation is signed by the trusted attester's key
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address recovered = ethSignedHash.recover(signature);
        return recovered == expectedSigner;
    }
}
