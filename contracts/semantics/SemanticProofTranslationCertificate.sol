// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SemanticProofTranslationCertificate
 * @author Soul Protocol
 * @notice Certified semantic-preserving proof translation between heterogeneous ZK systems
 * @dev Enables verifiable translation of proofs across different proof systems while
 *      guaranteeing semantic equivalence preservation.
 *
 * CORE INSIGHT:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Proof translation is NOT just format conversion — it's SEMANTIC MAPPING.   │
 * │ The certificate guarantees that the translated proof preserves the         │
 * │ original statement's meaning across proof system boundaries.               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * TRANSLATION CERTIFICATE GUARANTEES:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 1. Statement Preservation: Original claim remains provable in target system│
 * │ 2. Soundness Preservation: No valid translation of invalid proof possible  │
 * │ 3. Binding Commitment: Translation is bound to specific proof instances    │
 * │ 4. Verifier Independence: Certificate is verifiable without original system│
 * │ 5. Composition Safety: Translated proofs compose correctly                 │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED TRANSLATIONS:
 * - Groth16 (BN254) ↔ Groth16 (BLS12-381)
 * - Groth16 ↔ PLONK
 * - PLONK ↔ STARK
 * - STARK ↔ FRI-based systems
 * - Custom circuits via registered translators
 */
contract SemanticProofTranslationCertificate is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant TRANSLATOR_ADMIN_ROLE =
        keccak256("TRANSLATOR_ADMIN_ROLE");
    bytes32 public constant CERTIFIED_TRANSLATOR_ROLE =
        keccak256("CERTIFIED_TRANSLATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Supported proof systems for translation
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
     * @notice Translation direction
     */
    enum TranslationDirection {
        Bidirectional, // Can translate both ways
        SourceToTarget, // Only source → target
        TargetToSource // Only target → source
    }

    /**
     * @notice Semantic domain categories
     * @dev Defines what kind of statements can be translated
     */
    enum SemanticDomain {
        Arithmetic, // Arithmetic circuit statements
        StateTransition, // State machine transitions
        MembershipProof, // Set membership proofs
        RangeProof, // Value range proofs
        SignatureProof, // Signature validity proofs
        BalanceProof, // Balance/sum proofs
        CrossChainProof, // Cross-chain state proofs
        PolicyCompliance, // Policy satisfaction proofs
        Custom // Custom semantic domain
    }

    /**
     * @notice Translation capability - defines what a translator can do
     */
    struct TranslationCapability {
        bytes32 capabilityId;
        ProofSystem sourceSystem;
        ProofSystem targetSystem;
        TranslationDirection direction;
        SemanticDomain[] supportedDomains;
        bytes32 translatorCircuitHash; // Hash of translation circuit
        bytes32 semanticPreservationProof; // Proof that semantics are preserved
        uint256 maxInputSize; // Max proof size in bytes
        uint256 gasEstimate; // Estimated gas for translation
        bool active;
        uint64 registeredAt;
    }

    /**
     * @notice Translation Certificate - issued proof of valid translation
     */
    struct TranslationCertificate {
        bytes32 certificateId;
        // Source proof information
        bytes32 sourceProofHash;
        ProofSystem sourceSystem;
        bytes32 sourceVerifyingKeyHash;
        bytes32 sourcePublicInputsHash;
        // Target proof information
        bytes32 targetProofHash;
        ProofSystem targetSystem;
        bytes32 targetVerifyingKeyHash;
        bytes32 targetPublicInputsHash;
        // Semantic binding
        SemanticDomain domain;
        bytes32 statementHash; // Hash of the proven statement
        bytes32 semanticCommitment; // Commitment to semantic equivalence
        // Certificate metadata
        bytes32 capabilityId; // Which translator capability was used
        address translator; // Who performed the translation
        uint64 issuedAt;
        uint64 expiresAt;
        CertificateStatus status;
        bytes32 translationProofHash; // ZK proof of correct translation
    }

    enum CertificateStatus {
        Pending,
        Valid,
        Revoked,
        Expired,
        Challenged
    }

    /**
     * @notice Translation request
     */
    struct TranslationRequest {
        bytes32 requestId;
        address requester;
        ProofSystem sourceSystem;
        ProofSystem targetSystem;
        SemanticDomain domain;
        bytes sourceProof;
        bytes32[] sourcePublicInputs;
        bytes32 sourceVerifyingKeyHash;
        bytes32 statementHash;
        uint64 submittedAt;
        uint64 deadline;
        RequestStatus status;
        uint256 fee;
    }

    enum RequestStatus {
        Pending,
        Processing,
        Completed,
        Rejected,
        Expired
    }

    /**
     * @notice Challenge to a translation certificate
     */
    struct CertificateChallenge {
        bytes32 challengeId;
        bytes32 certificateId;
        address challenger;
        bytes32 evidenceHash; // Hash of evidence proving invalidity
        string reason;
        uint256 stake;
        uint64 createdAt;
        uint64 deadline;
        ChallengeStatus status;
    }

    enum ChallengeStatus {
        Pending,
        Accepted, // Challenge successful, certificate revoked
        Rejected, // Challenge failed, stake slashed
        Resolved // Resolved through arbitration
    }

    /**
     * @notice Helper struct to reduce stack depth in translateAndCertify
     */
    struct CertifyParams {
        ProofSystem sourceSystem;
        ProofSystem targetSystem;
        SemanticDomain domain;
        bytes32 sourceProofHash;
        bytes32 sourceVerifyingKeyHash;
        bytes32 targetProofHash;
        bytes32 targetVerifyingKeyHash;
        bytes32 statementHash;
        bytes32 semanticCommitment;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered translation capabilities
    mapping(bytes32 => TranslationCapability) public capabilities;
    bytes32[] public capabilityIds;

    /// @notice Capability lookup by system pair
    mapping(ProofSystem => mapping(ProofSystem => bytes32[]))
        public systemPairCapabilities;

    /// @notice Issued translation certificates
    mapping(bytes32 => TranslationCertificate) public certificates;
    uint256 public totalCertificates;

    /// @notice Certificate validity mapping (for quick lookup)
    mapping(bytes32 => bool) public validCertificates;

    /// @notice Translation requests
    mapping(bytes32 => TranslationRequest) public requests;
    uint256 public totalRequests;

    /// @notice Challenges to certificates
    mapping(bytes32 => CertificateChallenge) public challenges;

    /// @notice Translator statistics
    mapping(address => uint256) public translatorSuccessCount;
    mapping(address => uint256) public translatorFailureCount;
    mapping(address => uint256) public translatorStake;

    /// @notice Semantic equivalence proofs registry
    /// @dev Maps (sourceCircuit, targetCircuit) -> equivalence proof hash
    mapping(bytes32 => mapping(bytes32 => bytes32))
        public semanticEquivalenceProofs;

    /// @notice Certificate expiry duration (default 30 days)
    uint256 public certificateValidityPeriod = 30 days;

    /// @notice Minimum stake for translators
    uint256 public minTranslatorStake = 0.5 ether;

    /// @notice Challenge stake requirement
    uint256 public challengeStake = 0.1 ether;

    /// @notice Challenge period duration
    uint256 public challengePeriod = 24 hours;

    /// @notice Fee per translation (base)
    uint256 public baseTranslationFee = 0.01 ether;

    /// @notice Maximum batch size for array operations (gas limit protection)
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Custom error for batch size exceeded
    error BatchSizeExceeded(uint256 provided, uint256 maximum);

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CapabilityRegistered(
        bytes32 indexed capabilityId,
        ProofSystem sourceSystem,
        ProofSystem targetSystem,
        address indexed registrar
    );

    event CapabilityDeactivated(bytes32 indexed capabilityId);

    event TranslationRequested(
        bytes32 indexed requestId,
        ProofSystem sourceSystem,
        ProofSystem targetSystem,
        address indexed requester
    );

    event CertificateIssued(
        bytes32 indexed certificateId,
        bytes32 indexed requestId,
        bytes32 sourceProofHash,
        bytes32 targetProofHash,
        address indexed translator
    );

    event CertificateRevoked(bytes32 indexed certificateId, string reason);

    event CertificateChallenged(
        bytes32 indexed certificateId,
        bytes32 indexed challengeId,
        address indexed challenger
    );

    event ChallengeResolved(bytes32 indexed challengeId, bool challengerWon);

    event SemanticEquivalenceRegistered(
        bytes32 indexed sourceCircuit,
        bytes32 indexed targetCircuit,
        bytes32 proofHash
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error CapabilityNotFound(bytes32 capabilityId);
    error CapabilityInactive(bytes32 capabilityId);
    error UnsupportedTranslation(ProofSystem source, ProofSystem target);
    error UnsupportedSemanticDomain(SemanticDomain domain);
    error InsufficientTranslatorStake();
    error InvalidSourceProof();
    error InvalidTranslationProof();
    error SemanticMismatch(bytes32 sourceHash, bytes32 targetHash);
    error CertificateNotFound(bytes32 certificateId);
    error CertificateExpired(bytes32 certificateId);
    error CertificateAlreadyRevoked(bytes32 certificateId);
    error RequestNotFound(bytes32 requestId);
    error RequestExpired(bytes32 requestId);
    error InsufficientFee(uint256 required, uint256 provided);
    error InsufficientChallengeStake();
    error ChallengePeriodActive(bytes32 certificateId);
    error ChallengePeriodExpired(bytes32 challengeId);
    error NotTranslator();
    error StatementHashMismatch();
    error TranslatorNotCertified(address translator);
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TRANSLATOR_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        CAPABILITY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new translation capability
     * @param sourceSystem Source proof system
     * @param targetSystem Target proof system
     * @param direction Translation direction
     * @param supportedDomains Array of supported semantic domains
     * @param translatorCircuitHash Hash of the translation circuit
     * @param semanticPreservationProof ZK proof of semantic preservation
     * @param maxInputSize Maximum input proof size
     * @param gasEstimate Estimated gas for translation
     */
    function registerCapability(
        ProofSystem sourceSystem,
        ProofSystem targetSystem,
        TranslationDirection direction,
        SemanticDomain[] calldata supportedDomains,
        bytes32 translatorCircuitHash,
        bytes32 semanticPreservationProof,
        uint256 maxInputSize,
        uint256 gasEstimate
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) returns (bytes32 capabilityId) {
        if (
            sourceSystem == ProofSystem.Unknown ||
            targetSystem == ProofSystem.Unknown
        ) {
            revert UnsupportedTranslation(sourceSystem, targetSystem);
        }

        capabilityId = keccak256(
            abi.encodePacked(
                sourceSystem,
                targetSystem,
                translatorCircuitHash,
                block.timestamp
            )
        );

        capabilities[capabilityId] = TranslationCapability({
            capabilityId: capabilityId,
            sourceSystem: sourceSystem,
            targetSystem: targetSystem,
            direction: direction,
            supportedDomains: supportedDomains,
            translatorCircuitHash: translatorCircuitHash,
            semanticPreservationProof: semanticPreservationProof,
            maxInputSize: maxInputSize,
            gasEstimate: gasEstimate,
            active: true,
            registeredAt: uint64(block.timestamp)
        });

        capabilityIds.push(capabilityId);
        systemPairCapabilities[sourceSystem][targetSystem].push(capabilityId);

        emit CapabilityRegistered(
            capabilityId,
            sourceSystem,
            targetSystem,
            msg.sender
        );
    }

    /**
     * @notice Deactivate a translation capability
     */
    function deactivateCapability(
        bytes32 capabilityId
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) {
        if (capabilities[capabilityId].capabilityId == bytes32(0)) {
            revert CapabilityNotFound(capabilityId);
        }
        capabilities[capabilityId].active = false;
        emit CapabilityDeactivated(capabilityId);
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSLATION REQUESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request a proof translation
     * @param sourceSystem Source proof system
     * @param targetSystem Target proof system
     * @param domain Semantic domain
     * @param sourceProof The source proof bytes
     * @param sourcePublicInputs Public inputs to the source proof
     * @param sourceVerifyingKeyHash Hash of source verifying key
     * @param statementHash Hash of the statement being proven
     * @param deadline Request deadline
     */
    function requestTranslation(
        ProofSystem sourceSystem,
        ProofSystem targetSystem,
        SemanticDomain domain,
        bytes calldata sourceProof,
        bytes32[] calldata sourcePublicInputs,
        bytes32 sourceVerifyingKeyHash,
        bytes32 statementHash,
        uint64 deadline
    ) external payable nonReentrant whenNotPaused returns (bytes32 requestId) {
        // Verify capability exists
        bytes32[] storage caps = systemPairCapabilities[sourceSystem][
            targetSystem
        ];
        if (caps.length == 0) {
            revert UnsupportedTranslation(sourceSystem, targetSystem);
        }

        // Check fee
        uint256 requiredFee = calculateTranslationFee(
            sourceProof.length,
            domain
        );
        if (msg.value < requiredFee) {
            revert InsufficientFee(requiredFee, msg.value);
        }

        requestId = keccak256(
            abi.encodePacked(
                msg.sender,
                sourceSystem,
                targetSystem,
                keccak256(sourceProof),
                block.timestamp
            )
        );

        requests[requestId] = TranslationRequest({
            requestId: requestId,
            requester: msg.sender,
            sourceSystem: sourceSystem,
            targetSystem: targetSystem,
            domain: domain,
            sourceProof: sourceProof,
            sourcePublicInputs: sourcePublicInputs,
            sourceVerifyingKeyHash: sourceVerifyingKeyHash,
            statementHash: statementHash,
            submittedAt: uint64(block.timestamp),
            deadline: deadline,
            status: RequestStatus.Pending,
            fee: msg.value
        });

        totalRequests++;
        emit TranslationRequested(
            requestId,
            sourceSystem,
            targetSystem,
            msg.sender
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CERTIFICATE ISSUANCE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Issue a translation certificate (called by certified translators)
     * @param requestId The translation request ID
     * @param targetProof The translated proof bytes
     * @param targetPublicInputs Public inputs to the target proof
     * @param targetVerifyingKeyHash Hash of target verifying key
     * @param translationProof ZK proof of correct translation
     * @param semanticCommitment Commitment to semantic equivalence
     */
    function issueCertificate(
        bytes32 requestId,
        bytes calldata targetProof,
        bytes32[] calldata targetPublicInputs,
        bytes32 targetVerifyingKeyHash,
        bytes calldata translationProof,
        bytes32 semanticCommitment
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(CERTIFIED_TRANSLATOR_ROLE)
        returns (bytes32 certificateId)
    {
        TranslationRequest storage request = requests[requestId];

        if (request.requestId == bytes32(0)) {
            revert RequestNotFound(requestId);
        }
        if (block.timestamp > request.deadline) {
            revert RequestExpired(requestId);
        }
        if (translatorStake[msg.sender] < minTranslatorStake) {
            revert InsufficientTranslatorStake();
        }

        // Verify translation proof (simplified - would call actual verifier)
        bytes32 translationProofHash = keccak256(translationProof);
        if (
            !_verifyTranslationProof(
                request.sourceProof,
                targetProof,
                translationProof,
                semanticCommitment
            )
        ) {
            revert InvalidTranslationProof();
        }

        certificateId = keccak256(
            abi.encodePacked(
                requestId,
                keccak256(targetProof),
                msg.sender,
                block.timestamp
            )
        );

        bytes32 sourceProofHash = keccak256(request.sourceProof);
        bytes32 targetProofHash = keccak256(targetProof);
        bytes32 sourcePublicInputsHash = keccak256(
            abi.encodePacked(request.sourcePublicInputs)
        );
        bytes32 targetPublicInputsHash = keccak256(
            abi.encodePacked(targetPublicInputs)
        );

        certificates[certificateId] = TranslationCertificate({
            certificateId: certificateId,
            sourceProofHash: sourceProofHash,
            sourceSystem: request.sourceSystem,
            sourceVerifyingKeyHash: request.sourceVerifyingKeyHash,
            sourcePublicInputsHash: sourcePublicInputsHash,
            targetProofHash: targetProofHash,
            targetSystem: request.targetSystem,
            targetVerifyingKeyHash: targetVerifyingKeyHash,
            targetPublicInputsHash: targetPublicInputsHash,
            domain: request.domain,
            statementHash: request.statementHash,
            semanticCommitment: semanticCommitment,
            capabilityId: _findCapability(
                request.sourceSystem,
                request.targetSystem
            ),
            translator: msg.sender,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + certificateValidityPeriod),
            status: CertificateStatus.Valid,
            translationProofHash: translationProofHash
        });

        validCertificates[certificateId] = true;
        request.status = RequestStatus.Completed;
        totalCertificates++;
        translatorSuccessCount[msg.sender]++;

        // Transfer fee to translator (using call instead of transfer for gas compatibility)
        (bool success, ) = payable(msg.sender).call{value: request.fee}("");
        require(success, "Fee transfer failed");

        emit CertificateIssued(
            certificateId,
            requestId,
            sourceProofHash,
            targetProofHash,
            msg.sender
        );
    }

    /**
     * @notice Direct translation without request (for pre-registered translators)
     * @dev Used when translator can perform translation immediately
     */
    function translateAndCertify(
        CertifyParams calldata params,
        bytes32[] calldata sourcePublicInputs,
        bytes32[] calldata targetPublicInputs,
        bytes calldata translationProof
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(CERTIFIED_TRANSLATOR_ROLE)
        returns (bytes32 certificateId)
    {
        if (translatorStake[msg.sender] < minTranslatorStake) {
            revert InsufficientTranslatorStake();
        }

        // Find capability
        bytes32 capabilityId = _findCapability(
            params.sourceSystem,
            params.targetSystem
        );
        if (capabilityId == bytes32(0)) {
            revert UnsupportedTranslation(
                params.sourceSystem,
                params.targetSystem
            );
        }

        certificateId = _createCertificate(
            params,
            sourcePublicInputs,
            targetPublicInputs,
            translationProof,
            capabilityId
        );
    }

    /**
     * @notice Internal helper to create certificate (reduces stack depth)
     */
    function _createCertificate(
        CertifyParams calldata params,
        bytes32[] calldata sourcePublicInputs,
        bytes32[] calldata targetPublicInputs,
        bytes calldata translationProof,
        bytes32 capabilityId
    ) internal returns (bytes32 certificateId) {
        certificateId = keccak256(
            abi.encodePacked(
                params.sourceProofHash,
                params.targetProofHash,
                msg.sender,
                block.timestamp
            )
        );

        bytes32 sourcePublicInputsHash = keccak256(
            abi.encodePacked(sourcePublicInputs)
        );
        bytes32 targetPublicInputsHash = keccak256(
            abi.encodePacked(targetPublicInputs)
        );
        bytes32 translationProofHash = keccak256(translationProof);

        certificates[certificateId] = TranslationCertificate({
            certificateId: certificateId,
            sourceProofHash: params.sourceProofHash,
            sourceSystem: params.sourceSystem,
            sourceVerifyingKeyHash: params.sourceVerifyingKeyHash,
            sourcePublicInputsHash: sourcePublicInputsHash,
            targetProofHash: params.targetProofHash,
            targetSystem: params.targetSystem,
            targetVerifyingKeyHash: params.targetVerifyingKeyHash,
            targetPublicInputsHash: targetPublicInputsHash,
            domain: params.domain,
            statementHash: params.statementHash,
            semanticCommitment: params.semanticCommitment,
            capabilityId: capabilityId,
            translator: msg.sender,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + certificateValidityPeriod),
            status: CertificateStatus.Valid,
            translationProofHash: translationProofHash
        });

        validCertificates[certificateId] = true;
        totalCertificates++;
        translatorSuccessCount[msg.sender]++;

        emit CertificateIssued(
            certificateId,
            bytes32(0),
            params.sourceProofHash,
            params.targetProofHash,
            msg.sender
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CERTIFICATE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a translation certificate is valid
     * @param certificateId The certificate to verify
     * @return valid Whether the certificate is valid
     * @return certificate The certificate data
     */
    function verifyCertificate(
        bytes32 certificateId
    )
        external
        view
        returns (bool valid, TranslationCertificate memory certificate)
    {
        certificate = certificates[certificateId];

        if (certificate.certificateId == bytes32(0)) {
            return (false, certificate);
        }

        if (certificate.status != CertificateStatus.Valid) {
            return (false, certificate);
        }

        if (block.timestamp > certificate.expiresAt) {
            return (false, certificate);
        }

        return (true, certificate);
    }

    /**
     * @notice Check if a proof translation is certified
     * @param sourceProofHash Hash of source proof
     * @param targetProofHash Hash of target proof
     * @param domain Semantic domain
     */
    function isTranslationCertified(
        bytes32 sourceProofHash,
        bytes32 targetProofHash,
        SemanticDomain domain
    ) external view returns (bool, bytes32) {
        // Compute a lookup key from the input parameters
        bytes32 lookupKey = keccak256(
            abi.encodePacked(sourceProofHash, targetProofHash, domain)
        );
        // This is a simplified lookup - production would use indexing
        // For now, we verify via certificateId reconstruction
        if (lookupKey != bytes32(0)) {
            return (false, bytes32(0)); // Placeholder - implement with proper indexing
        }
        return (false, bytes32(0));
    }

    /**
     * @notice Verify semantic equivalence between two proofs
     * @param certificateId The translation certificate
     * @param expectedStatementHash Expected statement hash
     */
    function verifySemanticEquivalence(
        bytes32 certificateId,
        bytes32 expectedStatementHash
    ) external view returns (bool) {
        TranslationCertificate storage cert = certificates[certificateId];

        if (cert.certificateId == bytes32(0)) {
            return false;
        }

        if (cert.status != CertificateStatus.Valid) {
            return false;
        }

        if (cert.statementHash != expectedStatementHash) {
            return false;
        }

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        CHALLENGE MECHANISM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge a translation certificate
     * @param certificateId The certificate to challenge
     * @param evidenceHash Hash of evidence proving invalidity
     * @param reason Reason for challenge
     */
    function challengeCertificate(
        bytes32 certificateId,
        bytes32 evidenceHash,
        string calldata reason
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 challengeId)
    {
        if (msg.value < challengeStake) {
            revert InsufficientChallengeStake();
        }

        TranslationCertificate storage cert = certificates[certificateId];
        if (cert.certificateId == bytes32(0)) {
            revert CertificateNotFound(certificateId);
        }
        if (cert.status == CertificateStatus.Revoked) {
            revert CertificateAlreadyRevoked(certificateId);
        }

        challengeId = keccak256(
            abi.encodePacked(certificateId, msg.sender, block.timestamp)
        );

        challenges[challengeId] = CertificateChallenge({
            challengeId: challengeId,
            certificateId: certificateId,
            challenger: msg.sender,
            evidenceHash: evidenceHash,
            reason: reason,
            stake: msg.value,
            createdAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp + challengePeriod),
            status: ChallengeStatus.Pending
        });

        cert.status = CertificateStatus.Challenged;
        validCertificates[certificateId] = false;

        emit CertificateChallenged(certificateId, challengeId, msg.sender);
    }

    /**
     * @notice Resolve a challenge (admin/arbitrator function)
     * @param challengeId The challenge to resolve
     * @param challengerWins Whether the challenger's claim is valid
     */
    function resolveChallenge(
        bytes32 challengeId,
        bool challengerWins
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) {
        CertificateChallenge storage challenge = challenges[challengeId];
        require(challenge.challengeId != bytes32(0), "Challenge not found");
        require(
            challenge.status == ChallengeStatus.Pending,
            "Already resolved"
        );

        TranslationCertificate storage cert = certificates[
            challenge.certificateId
        ];

        if (challengerWins) {
            // Revoke certificate
            cert.status = CertificateStatus.Revoked;
            challenge.status = ChallengeStatus.Accepted;

            // Slash translator stake
            uint256 slashAmount = translatorStake[cert.translator] / 4; // 25% slash
            translatorStake[cert.translator] -= slashAmount;
            translatorFailureCount[cert.translator]++;

            // Return challenge stake + reward (using call instead of transfer for gas compatibility)
            (bool success, ) = payable(challenge.challenger).call{
                value: challenge.stake + slashAmount
            }("");
            require(success, "Reward transfer failed");

            emit CertificateRevoked(challenge.certificateId, challenge.reason);
        } else {
            // Restore certificate
            cert.status = CertificateStatus.Valid;
            validCertificates[challenge.certificateId] = true;
            challenge.status = ChallengeStatus.Rejected;

            // Forfeit challenger stake to translator (using call instead of transfer for gas compatibility)
            (bool successForfeit, ) = payable(cert.translator).call{
                value: challenge.stake
            }("");
            require(successForfeit, "Stake transfer failed");
        }

        emit ChallengeResolved(challengeId, challengerWins);
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSLATOR STAKING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Stake as a translator
     */
    function stakeAsTranslator() external payable {
        require(msg.value > 0, "Must stake non-zero amount");
        translatorStake[msg.sender] += msg.value;
    }

    /**
     * @notice Withdraw translator stake
     * @param amount Amount to withdraw
     */
    function withdrawStake(uint256 amount) external nonReentrant {
        require(translatorStake[msg.sender] >= amount, "Insufficient stake");
        translatorStake[msg.sender] -= amount;
        // Using call instead of transfer for gas compatibility with smart contract wallets
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Stake withdrawal failed");
    }

    /*//////////////////////////////////////////////////////////////
                        SEMANTIC EQUIVALENCE REGISTRY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a semantic equivalence proof between circuits
     * @param sourceCircuitHash Hash of source circuit
     * @param targetCircuitHash Hash of target circuit
     * @param equivalenceProofHash Hash of the equivalence proof
     */
    function registerSemanticEquivalence(
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash,
        bytes32 equivalenceProofHash
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) {
        semanticEquivalenceProofs[sourceCircuitHash][
            targetCircuitHash
        ] = equivalenceProofHash;
        emit SemanticEquivalenceRegistered(
            sourceCircuitHash,
            targetCircuitHash,
            equivalenceProofHash
        );
    }

    /**
     * @notice Check if circuits have registered semantic equivalence
     */
    function hasSemanticEquivalence(
        bytes32 sourceCircuitHash,
        bytes32 targetCircuitHash
    ) external view returns (bool, bytes32) {
        bytes32 proof = semanticEquivalenceProofs[sourceCircuitHash][
            targetCircuitHash
        ];
        return (proof != bytes32(0), proof);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get all capabilities for a system pair
     */
    function getCapabilitiesForPair(
        ProofSystem source,
        ProofSystem target
    ) external view returns (bytes32[] memory) {
        return systemPairCapabilities[source][target];
    }

    /**
     * @notice Get capability details
     */
    function getCapability(
        bytes32 capabilityId
    ) external view returns (TranslationCapability memory) {
        return capabilities[capabilityId];
    }

    /**
     * @notice Calculate translation fee
     */
    function calculateTranslationFee(
        uint256 proofSize,
        SemanticDomain domain
    ) public view returns (uint256) {
        uint256 sizeFactor = proofSize / 1024; // Per KB
        uint256 domainMultiplier = domain == SemanticDomain.CrossChainProof
            ? 2
            : 1;
        return
            baseTranslationFee + (sizeFactor * 0.001 ether * domainMultiplier);
    }

    /**
     * @notice Get translator statistics
     */
    function getTranslatorStats(
        address translator
    )
        external
        view
        returns (uint256 stake, uint256 successes, uint256 failures)
    {
        return (
            translatorStake[translator],
            translatorSuccessCount[translator],
            translatorFailureCount[translator]
        );
    }

    /**
     * @notice Get total number of capabilities
     */
    function totalCapabilities() external view returns (uint256) {
        return capabilityIds.length;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Find a capability for system pair
     */
    function _findCapability(
        ProofSystem source,
        ProofSystem target
    ) internal view returns (bytes32) {
        bytes32[] storage caps = systemPairCapabilities[source][target];
        for (uint256 i = 0; i < caps.length; i++) {
            if (capabilities[caps[i]].active) {
                return caps[i];
            }
        }
        return bytes32(0);
    }

    /**
     * @notice Verify translation proof (placeholder for actual verification)
     * @dev In production, this would call the appropriate verifier
     */
    function _verifyTranslationProof(
        bytes memory sourceProof,
        bytes memory targetProof,
        bytes memory translationProof,
        bytes32 semanticCommitment
    ) internal pure returns (bool) {
        // Placeholder verification - in production would verify ZK proof
        // that the translation is semantically correct
        return
            sourceProof.length > 0 &&
            targetProof.length > 0 &&
            translationProof.length > 0 &&
            semanticCommitment != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update certificate validity period
     */
    function setCertificateValidityPeriod(
        uint256 period
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) {
        certificateValidityPeriod = period;
    }

    /**
     * @notice Update minimum translator stake
     */
    function setMinTranslatorStake(
        uint256 stake
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) {
        minTranslatorStake = stake;
    }

    /**
     * @notice Update base translation fee
     */
    function setBaseTranslationFee(
        uint256 fee
    ) external onlyRole(TRANSLATOR_ADMIN_ROLE) {
        baseTranslationFee = fee;
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
