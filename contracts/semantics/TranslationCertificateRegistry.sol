// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title TranslationCertificateRegistry
 * @author Soul Protocol
 * @notice Registry for certified proof translators and their attestations
 * @dev Manages translator certification, reputation, and capability attestations
 *
 * TRANSLATOR CERTIFICATION MODEL:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Level 1: PROVISIONAL                                                       │
 * │   - Basic verification complete                                            │
 * │   - Limited translation volume                                             │
 * │   - Higher stake requirements                                              │
 * │                                                                            │
 * │ Level 2: CERTIFIED                                                         │
 * │   - Proven track record (100+ translations)                                │
 * │   - Formal verification of translator circuit                              │
 * │   - Standard stake requirements                                            │
 * │                                                                            │
 * │ Level 3: TRUSTED                                                           │
 * │   - Extensive track record (1000+ translations)                            │
 * │   - Multi-party attestation                                                │
 * │   - Reduced stake requirements                                             │
 * │   - Fast-path translation approval                                         │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * CAPABILITY ATTESTATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Attesters vouch for translator capability in specific proof system pairs   │
 * │ through stake-backed attestations. Invalid attestations result in slashing.│
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract TranslationCertificateRegistry is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Certification levels for translators
     */
    enum CertificationLevel {
        None,
        Provisional, // Entry level
        Certified, // Standard certification
        Trusted // Highest trust level
    }

    /**
     * @notice Proof system types (mirrored from SPTC)
     */
    enum ProofSystem {
        Unknown,
        GROTH16_BN254,
        GROTH16_BLS12_381,
        PLONK,
        ULTRAPLONK,
        STARK,
        FRI,
        HALO2,
        NOVA,
        SUPERNOVA,
        BULLETPROOFS,
        CUSTOM
    }

    /**
     * @notice Translator profile
     */
    struct TranslatorProfile {
        address translator;
        bytes32 profileId;
        string name;
        string organization;
        bytes32 publicKeyHash; // Public key for encrypted communications
        CertificationLevel level;
        uint256 totalStake;
        uint256 translationsCompleted;
        uint256 translationsFailed;
        uint256 challengesReceived;
        uint256 challengesLost;
        uint64 registeredAt;
        uint64 lastActivityAt;
        uint64 certifiedAt;
        bool active;
        bool suspended;
    }

    /**
     * @notice Capability certification - proves translator can handle specific translations
     */
    struct CapabilityCertification {
        bytes32 certificationId;
        address translator;
        ProofSystem sourceSystem;
        ProofSystem targetSystem;
        bytes32 translatorCircuitHash; // Hash of their translation circuit
        bytes32 verificationKeyHash; // Verification key for translation proofs
        uint256 maxProofSize; // Maximum proof size they can handle
        uint256 attestationCount; // Number of attestations received
        uint256 totalAttestationStake; // Total stake backing attestations
        uint64 certifiedAt;
        uint64 expiresAt;
        bool active;
    }

    /**
     * @notice Attestation - vouch for translator capability
     */
    struct Attestation {
        bytes32 attestationId;
        bytes32 capabilityId; // What capability is being attested
        address attester;
        uint256 stake; // Stake backing this attestation
        bytes32 evidenceHash; // Hash of evidence (audit report, test results)
        string comments;
        uint64 createdAt;
        uint64 expiresAt;
        bool active;
        bool slashed;
    }

    /**
     * @notice Audit record - formal audit of translator
     */
    struct AuditRecord {
        bytes32 auditId;
        address translator;
        address auditor;
        bytes32 reportHash; // IPFS hash of audit report
        AuditResult result;
        uint256 score; // 0-100 score
        string[] findings;
        uint64 auditedAt;
        bool acknowledged;
    }

    enum AuditResult {
        Pending,
        Passed,
        ConditionalPass,
        Failed
    }

    /**
     * @notice Certification upgrade request
     */
    struct UpgradeRequest {
        bytes32 requestId;
        address translator;
        CertificationLevel currentLevel;
        CertificationLevel targetLevel;
        bytes32[] attestationIds; // Supporting attestations
        bytes32[] auditIds; // Supporting audits
        uint256 additionalStake;
        uint64 requestedAt;
        UpgradeStatus status;
    }

    enum UpgradeStatus {
        Pending,
        Approved,
        Rejected,
        Expired
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Translator profiles
    mapping(address => TranslatorProfile) public translators;
    address[] public registeredTranslators;

    /// @notice Profile ID to address mapping
    mapping(bytes32 => address) public profileIdToAddress;

    /// @notice Capability certifications
    mapping(bytes32 => CapabilityCertification) public capabilities;
    bytes32[] public capabilityIds;

    /// @notice Translator capabilities lookup
    mapping(address => bytes32[]) public translatorCapabilities;

    /// @notice System pair to capabilities lookup
    mapping(ProofSystem => mapping(ProofSystem => bytes32[]))
        public systemPairCapabilities;

    /// @notice Attestations
    mapping(bytes32 => Attestation) public attestations;

    /// @notice Attester to attestations mapping
    mapping(address => bytes32[]) public attesterAttestations;

    /// @notice Audit records
    mapping(bytes32 => AuditRecord) public audits;
    mapping(address => bytes32[]) public translatorAudits;

    /// @notice Upgrade requests
    mapping(bytes32 => UpgradeRequest) public upgradeRequests;
    mapping(address => bytes32) public pendingUpgrade;

    /// @notice Certification requirements
    mapping(CertificationLevel => CertificationRequirements)
        public levelRequirements;

    struct CertificationRequirements {
        uint256 minStake;
        uint256 minTranslations;
        uint256 maxFailureRate; // In basis points (100 = 1%)
        uint256 minAttestations;
        uint256 minAttestationStake;
        uint256 minAuditScore;
        bool requiresAudit;
    }

    /// @notice Minimum stake for attesters
    uint256 public minAttesterStake = 0.1 ether;

    /// @notice Attestation expiry period (default 180 days)
    uint256 public attestationValidityPeriod = 180 days;

    /// @notice Capability certification expiry (default 1 year)
    uint256 public capabilityValidityPeriod = 365 days;

    /// @notice Total registered translators
    uint256 public totalTranslators;

    /// @notice Total active capabilities
    uint256 public totalCapabilities;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event TranslatorRegistered(
        address indexed translator,
        bytes32 indexed profileId,
        string name
    );

    event TranslatorSuspended(address indexed translator, string reason);
    event TranslatorReinstated(address indexed translator);

    event CapabilityCertified(
        bytes32 indexed certificationId,
        address indexed translator,
        ProofSystem sourceSystem,
        ProofSystem targetSystem
    );

    event CapabilityRevoked(bytes32 indexed certificationId, string reason);

    event AttestationCreated(
        bytes32 indexed attestationId,
        bytes32 indexed capabilityId,
        address indexed attester,
        uint256 stake
    );

    event AttestationRevoked(bytes32 indexed attestationId);
    event AttestationSlashed(
        bytes32 indexed attestationId,
        uint256 slashedAmount
    );

    event AuditCompleted(
        bytes32 indexed auditId,
        address indexed translator,
        AuditResult result,
        uint256 score
    );

    event CertificationUpgraded(
        address indexed translator,
        CertificationLevel oldLevel,
        CertificationLevel newLevel
    );

    event CertificationDowngraded(
        address indexed translator,
        CertificationLevel oldLevel,
        CertificationLevel newLevel,
        string reason
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error TranslatorAlreadyRegistered(address translator);
    error TranslatorNotFound(address translator);
    error TranslatorIsSuspended(address translator);
    error CapabilityNotFound(bytes32 capabilityId);
    error CapabilityExpired(bytes32 capabilityId);
    error AttestationNotFound(bytes32 attestationId);
    error InsufficientStake(uint256 required, uint256 provided);
    error InsufficientAttesterStake();
    error InvalidCertificationLevel();
    error RequirementsNotMet();
    error UpgradeAlreadyPending();
    error NoUpgradePending();
    error CannotDowngrade();
    error AuditRequired();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
        _initializeCertificationRequirements();
    }

    /**
     * @notice Initialize default certification requirements
     */
    function _initializeCertificationRequirements() internal {
        // Provisional level
        levelRequirements[
            CertificationLevel.Provisional
        ] = CertificationRequirements({
            minStake: 0.5 ether,
            minTranslations: 0,
            maxFailureRate: 1000, // 10%
            minAttestations: 0,
            minAttestationStake: 0,
            minAuditScore: 0,
            requiresAudit: false
        });

        // Certified level
        levelRequirements[
            CertificationLevel.Certified
        ] = CertificationRequirements({
            minStake: 2 ether,
            minTranslations: 100,
            maxFailureRate: 500, // 5%
            minAttestations: 3,
            minAttestationStake: 1 ether,
            minAuditScore: 70,
            requiresAudit: true
        });

        // Trusted level
        levelRequirements[
            CertificationLevel.Trusted
        ] = CertificationRequirements({
            minStake: 10 ether,
            minTranslations: 1000,
            maxFailureRate: 100, // 1%
            minAttestations: 10,
            minAttestationStake: 5 ether,
            minAuditScore: 90,
            requiresAudit: true
        });
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSLATOR REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a translator
     * @param name Display name
     * @param organization Organization name
     * @param publicKeyHash Hash of public key for encrypted communications
     */
    function registerTranslator(
        string calldata name,
        string calldata organization,
        bytes32 publicKeyHash
    ) external payable nonReentrant whenNotPaused returns (bytes32 profileId) {
        if (translators[msg.sender].translator != address(0)) {
            revert TranslatorAlreadyRegistered(msg.sender);
        }

        CertificationRequirements memory req = levelRequirements[
            CertificationLevel.Provisional
        ];
        if (msg.value < req.minStake) {
            revert InsufficientStake(req.minStake, msg.value);
        }

        // Using abi.encode instead of abi.encodePacked to prevent hash collisions with dynamic types
        profileId = keccak256(abi.encode(msg.sender, name, block.timestamp));

        translators[msg.sender] = TranslatorProfile({
            translator: msg.sender,
            profileId: profileId,
            name: name,
            organization: organization,
            publicKeyHash: publicKeyHash,
            level: CertificationLevel.Provisional,
            totalStake: msg.value,
            translationsCompleted: 0,
            translationsFailed: 0,
            challengesReceived: 0,
            challengesLost: 0,
            registeredAt: uint64(block.timestamp),
            lastActivityAt: uint64(block.timestamp),
            certifiedAt: uint64(block.timestamp),
            active: true,
            suspended: false
        });

        profileIdToAddress[profileId] = msg.sender;
        registeredTranslators.push(msg.sender);
        totalTranslators++;

        emit TranslatorRegistered(msg.sender, profileId, name);
    }

    /**
     * @notice Add stake to translator profile
     */
    function addStake() external payable {
        TranslatorProfile storage profile = translators[msg.sender];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(msg.sender);
        }
        profile.totalStake += msg.value;
    }

    /**
     * @notice Withdraw excess stake
     * @param amount Amount to withdraw
     */
    function withdrawStake(uint256 amount) external nonReentrant {
        TranslatorProfile storage profile = translators[msg.sender];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(msg.sender);
        }

        CertificationRequirements memory req = levelRequirements[profile.level];
        require(
            profile.totalStake - amount >= req.minStake,
            "Would go below minimum"
        );

        profile.totalStake -= amount;
        // Using call instead of transfer for gas compatibility with smart contract wallets
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Stake withdrawal failed");
    }

    /*//////////////////////////////////////////////////////////////
                        CAPABILITY CERTIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Certify a translation capability
     * @param sourceSystem Source proof system
     * @param targetSystem Target proof system
     * @param translatorCircuitHash Hash of translation circuit
     * @param verificationKeyHash Hash of verification key
     * @param maxProofSize Maximum proof size supported
     */
    function certifyCapability(
        ProofSystem sourceSystem,
        ProofSystem targetSystem,
        bytes32 translatorCircuitHash,
        bytes32 verificationKeyHash,
        uint256 maxProofSize
    ) external nonReentrant whenNotPaused returns (bytes32 certificationId) {
        TranslatorProfile storage profile = translators[msg.sender];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(msg.sender);
        }
        if (profile.suspended) {
            revert TranslatorIsSuspended(msg.sender);
        }

        certificationId = keccak256(
            abi.encodePacked(
                msg.sender,
                sourceSystem,
                targetSystem,
                translatorCircuitHash,
                block.timestamp
            )
        );

        capabilities[certificationId] = CapabilityCertification({
            certificationId: certificationId,
            translator: msg.sender,
            sourceSystem: sourceSystem,
            targetSystem: targetSystem,
            translatorCircuitHash: translatorCircuitHash,
            verificationKeyHash: verificationKeyHash,
            maxProofSize: maxProofSize,
            attestationCount: 0,
            totalAttestationStake: 0,
            certifiedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + capabilityValidityPeriod),
            active: true
        });

        capabilityIds.push(certificationId);
        translatorCapabilities[msg.sender].push(certificationId);
        systemPairCapabilities[sourceSystem][targetSystem].push(
            certificationId
        );
        totalCapabilities++;

        emit CapabilityCertified(
            certificationId,
            msg.sender,
            sourceSystem,
            targetSystem
        );
    }

    /**
     * @notice Revoke a capability certification
     */
    function revokeCapability(
        bytes32 certificationId,
        string calldata reason
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        CapabilityCertification storage cap = capabilities[certificationId];
        if (cap.certificationId == bytes32(0)) {
            revert CapabilityNotFound(certificationId);
        }
        cap.active = false;
        emit CapabilityRevoked(certificationId, reason);
    }

    /*//////////////////////////////////////////////////////////////
                            ATTESTATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an attestation for a capability
     * @param capabilityId The capability to attest
     * @param evidenceHash Hash of supporting evidence
     * @param comments Attestation comments
     */
    function createAttestation(
        bytes32 capabilityId,
        bytes32 evidenceHash,
        string calldata comments
    )
        external
        payable
        nonReentrant
        onlyRole(ATTESTER_ROLE)
        returns (bytes32 attestationId)
    {
        if (msg.value < minAttesterStake) {
            revert InsufficientAttesterStake();
        }

        CapabilityCertification storage cap = capabilities[capabilityId];
        if (cap.certificationId == bytes32(0)) {
            revert CapabilityNotFound(capabilityId);
        }

        attestationId = keccak256(
            abi.encodePacked(capabilityId, msg.sender, block.timestamp)
        );

        attestations[attestationId] = Attestation({
            attestationId: attestationId,
            capabilityId: capabilityId,
            attester: msg.sender,
            stake: msg.value,
            evidenceHash: evidenceHash,
            comments: comments,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + attestationValidityPeriod),
            active: true,
            slashed: false
        });

        cap.attestationCount++;
        cap.totalAttestationStake += msg.value;
        attesterAttestations[msg.sender].push(attestationId);

        emit AttestationCreated(
            attestationId,
            capabilityId,
            msg.sender,
            msg.value
        );
    }

    /**
     * @notice Revoke an attestation
     */
    function revokeAttestation(bytes32 attestationId) external nonReentrant {
        Attestation storage att = attestations[attestationId];
        require(att.attester == msg.sender, "Not attester");
        require(att.active, "Already revoked");

        att.active = false;

        // Update capability stats
        CapabilityCertification storage cap = capabilities[att.capabilityId];
        if (cap.attestationCount > 0) {
            cap.attestationCount--;
            cap.totalAttestationStake -= att.stake;
        }

        // Return stake (using call instead of transfer for gas compatibility)
        (bool success, ) = payable(msg.sender).call{value: att.stake}("");
        require(success, "Stake return failed");

        emit AttestationRevoked(attestationId);
    }

    /**
     * @notice Slash an attestation (if capability proven faulty)
     */
    function slashAttestation(
        bytes32 attestationId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Attestation storage att = attestations[attestationId];
        require(att.active, "Not active");
        require(!att.slashed, "Already slashed");

        att.slashed = true;
        att.active = false;

        uint256 slashAmount = att.stake;

        emit AttestationSlashed(attestationId, slashAmount);
    }

    /*//////////////////////////////////////////////////////////////
                              AUDITING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an audit report
     */
    function submitAudit(
        address translator,
        bytes32 reportHash,
        AuditResult result,
        uint256 score,
        string[] calldata findings
    ) external onlyRole(AUDITOR_ROLE) returns (bytes32 auditId) {
        if (translators[translator].translator == address(0)) {
            revert TranslatorNotFound(translator);
        }

        auditId = keccak256(
            abi.encodePacked(translator, msg.sender, block.timestamp)
        );

        audits[auditId] = AuditRecord({
            auditId: auditId,
            translator: translator,
            auditor: msg.sender,
            reportHash: reportHash,
            result: result,
            score: score,
            findings: findings,
            auditedAt: uint64(block.timestamp),
            acknowledged: false
        });

        translatorAudits[translator].push(auditId);

        emit AuditCompleted(auditId, translator, result, score);
    }

    /*//////////////////////////////////////////////////////////////
                        CERTIFICATION UPGRADES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request certification upgrade
     * @param targetLevel Target certification level
     * @param attestationIds Supporting attestation IDs
     * @param auditIds Supporting audit IDs
     */
    function requestUpgrade(
        CertificationLevel targetLevel,
        bytes32[] calldata attestationIds,
        bytes32[] calldata auditIds
    ) external payable nonReentrant returns (bytes32 requestId) {
        TranslatorProfile storage profile = translators[msg.sender];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(msg.sender);
        }
        if (targetLevel <= profile.level) {
            revert CannotDowngrade();
        }
        if (pendingUpgrade[msg.sender] != bytes32(0)) {
            revert UpgradeAlreadyPending();
        }

        requestId = keccak256(
            abi.encodePacked(msg.sender, targetLevel, block.timestamp)
        );

        upgradeRequests[requestId] = UpgradeRequest({
            requestId: requestId,
            translator: msg.sender,
            currentLevel: profile.level,
            targetLevel: targetLevel,
            attestationIds: attestationIds,
            auditIds: auditIds,
            additionalStake: msg.value,
            requestedAt: uint64(block.timestamp),
            status: UpgradeStatus.Pending
        });

        pendingUpgrade[msg.sender] = requestId;
    }

    /**
     * @notice Approve upgrade request
     */
    function approveUpgrade(
        bytes32 requestId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        UpgradeRequest storage req = upgradeRequests[requestId];
        require(req.status == UpgradeStatus.Pending, "Not pending");

        TranslatorProfile storage profile = translators[req.translator];

        // Check requirements
        if (!_meetsRequirements(req.translator, req.targetLevel)) {
            revert RequirementsNotMet();
        }

        CertificationLevel oldLevel = profile.level;
        profile.level = req.targetLevel;
        profile.totalStake += req.additionalStake;
        profile.certifiedAt = uint64(block.timestamp);

        req.status = UpgradeStatus.Approved;
        delete pendingUpgrade[req.translator];

        emit CertificationUpgraded(req.translator, oldLevel, req.targetLevel);
    }

    /**
     * @notice Reject upgrade request
     */
    function rejectUpgrade(
        bytes32 requestId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        UpgradeRequest storage req = upgradeRequests[requestId];
        require(req.status == UpgradeStatus.Pending, "Not pending");

        req.status = UpgradeStatus.Rejected;
        delete pendingUpgrade[req.translator];

        // Return additional stake (using call instead of transfer for gas compatibility)
        if (req.additionalStake > 0) {
            (bool success, ) = payable(req.translator).call{
                value: req.additionalStake
            }("");
            require(success, "Stake return failed");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        SUSPENSION & MODERATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Suspend a translator
     */
    function suspendTranslator(
        address translator,
        string calldata reason
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        TranslatorProfile storage profile = translators[translator];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(translator);
        }
        profile.suspended = true;
        emit TranslatorSuspended(translator, reason);
    }

    /**
     * @notice Reinstate a suspended translator
     */
    function reinstateTranslator(
        address translator
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        TranslatorProfile storage profile = translators[translator];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(translator);
        }
        profile.suspended = false;
        emit TranslatorReinstated(translator);
    }

    /**
     * @notice Downgrade a translator's certification
     */
    function downgradeCertification(
        address translator,
        CertificationLevel newLevel,
        string calldata reason
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        TranslatorProfile storage profile = translators[translator];
        if (profile.translator == address(0)) {
            revert TranslatorNotFound(translator);
        }

        CertificationLevel oldLevel = profile.level;
        profile.level = newLevel;

        emit CertificationDowngraded(translator, oldLevel, newLevel, reason);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get translator profile
     */
    function getTranslator(
        address translator
    ) external view returns (TranslatorProfile memory) {
        return translators[translator];
    }

    /**
     * @notice Get translator capabilities
     */
    function getTranslatorCapabilities(
        address translator
    ) external view returns (bytes32[] memory) {
        return translatorCapabilities[translator];
    }

    /**
     * @notice Check if translator is certified for a capability
     */
    function isTranslatorCertified(
        address translator,
        ProofSystem source,
        ProofSystem target
    ) external view returns (bool, bytes32) {
        bytes32[] storage caps = translatorCapabilities[translator];
        for (uint256 i = 0; i < caps.length; i++) {
            CapabilityCertification storage cap = capabilities[caps[i]];
            if (
                cap.sourceSystem == source &&
                cap.targetSystem == target &&
                cap.active &&
                block.timestamp < cap.expiresAt
            ) {
                return (true, caps[i]);
            }
        }
        return (false, bytes32(0));
    }

    /**
     * @notice Get capabilities for a system pair
     */
    function getSystemPairCapabilities(
        ProofSystem source,
        ProofSystem target
    ) external view returns (bytes32[] memory) {
        return systemPairCapabilities[source][target];
    }

    /**
     * @notice Get translator's failure rate in basis points
     */
    function getFailureRate(
        address translator
    ) external view returns (uint256) {
        TranslatorProfile storage profile = translators[translator];
        uint256 total = profile.translationsCompleted +
            profile.translationsFailed;
        if (total == 0) return 0;
        return (profile.translationsFailed * 10000) / total;
    }

    /**
     * @notice Check if translator meets requirements for a level
     */
    function meetsRequirements(
        address translator,
        CertificationLevel level
    ) external view returns (bool) {
        return _meetsRequirements(translator, level);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Internal requirement check
     */
    function _meetsRequirements(
        address translator,
        CertificationLevel level
    ) internal view returns (bool) {
        TranslatorProfile storage profile = translators[translator];
        CertificationRequirements memory req = levelRequirements[level];

        if (profile.totalStake < req.minStake) return false;
        if (profile.translationsCompleted < req.minTranslations) return false;

        // Check failure rate
        uint256 total = profile.translationsCompleted +
            profile.translationsFailed;
        if (total > 0) {
            uint256 failureRate = (profile.translationsFailed * 10000) / total;
            if (failureRate > req.maxFailureRate) return false;
        }

        // Check attestations (simplified - would aggregate from capabilities)
        // For production, implement proper attestation aggregation

        // Check audit requirements
        if (req.requiresAudit) {
            bytes32[] storage translatorAuditList = translatorAudits[
                translator
            ];
            bool hasPassingAudit = false;
            for (uint256 i = 0; i < translatorAuditList.length; i++) {
                AuditRecord storage audit = audits[translatorAuditList[i]];
                if (
                    audit.result == AuditResult.Passed &&
                    audit.score >= req.minAuditScore
                ) {
                    hasPassingAudit = true;
                    break;
                }
            }
            if (!hasPassingAudit) return false;
        }

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update certification requirements
     */
    function updateRequirements(
        CertificationLevel level,
        CertificationRequirements calldata requirements
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        levelRequirements[level] = requirements;
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
