// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";

/**
 * @title HybridPQCVerifier
 * @author ZASEON
 * @notice Hybrid post-quantum + classical signature verification contract
 * @dev Implements the Phase 1 PQC migration: both classical (ECDSA) and PQC
 *      signatures must validate for a transaction to be accepted.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                         ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * The HybridPQCVerifier serves as the central on-chain registry for PQC
 * public keys and the verification entry point for hybrid signatures.
 *
 * CURRENT APPROACH (Phase 1 — Pre-Precompile):
 *   On-chain PQC signature verification is gas-prohibitive without dedicated
 *   EVM precompiles. This contract therefore:
 *
 *   1. Stores PQC public key commitments (keccak256 hashes) on-chain
 *   2. Validates PQC key metadata (algorithm, security level, key sizes)
 *   3. Provides a standardized interface for future precompile integration
 *   4. Implements hybrid verification logic with configurable modes
 *   5. Tracks key lifecycle (registration, rotation, revocation)
 *
 *   Actual PQC signature verification is delegated to off-chain verifiers
 *   (relayers / ZK circuits) in Phase 1, with results submitted as proofs.
 *
 * FUTURE (Phase 2+ — With Precompiles):
 *   When EVM PQC precompiles ship (EIP-TBD), the `_verifyPQCSignatureRaw`
 *   function will call the precompile directly for on-chain verification.
 *
 * SUPPORTED ALGORITHMS:
 *   - FN-DSA-512 (Falcon-512): Recommended for on-chain (~690B signatures)
 *   - ML-DSA-44 (Dilithium-2): Standard NIST PQC (~2.4KB signatures)
 *   - ML-DSA-65 (Dilithium-3): Higher security (~3.3KB signatures)
 *   - SLH-DSA-128s (SPHINCS+): Conservative hash-based (~7.9KB signatures)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract HybridPQCVerifier is AccessControl, ReentrancyGuard, Pausable {
    using IPQCVerifierLib for IPQCVerifier.PQCAlgorithm;

    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant KEY_REGISTRAR_ROLE =
        keccak256("KEY_REGISTRAR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator for PQC key registration
    bytes32 public constant PQC_KEY_DOMAIN =
        keccak256("ZASEON_PQC_KEY_REGISTRATION_V1");

    /// @notice Domain separator for hybrid signature verification
    bytes32 public constant HYBRID_SIG_DOMAIN =
        keccak256("ZASEON_HYBRID_SIGNATURE_V1");

    /// @notice Minimum required security level for new key registrations
    IPQCVerifier.SecurityLevel public constant MIN_SECURITY_LEVEL =
        IPQCVerifier.SecurityLevel.LEVEL_1;

    /// @notice Maximum PQC public key size (ML-KEM-1024 = 1568 bytes)
    uint256 public constant MAX_PQC_PUBKEY_SIZE = 2048;

    /// @notice Maximum PQC signature size (SLH-DSA-128f = 17088 bytes)
    uint256 public constant MAX_PQC_SIGNATURE_SIZE = 18000;

    /// @notice Key rotation cooldown period (prevents rapid key cycling)
    uint256 public constant KEY_ROTATION_COOLDOWN = 1 hours;

    /*//////////////////////////////////////////////////////////////
                          EXPECTED SIZES
    //////////////////////////////////////////////////////////////*/

    // NIST PQC Standard signature sizes
    uint256 private constant ML_DSA_44_SIG_SIZE = 2420;
    uint256 private constant ML_DSA_65_SIG_SIZE = 3293;
    uint256 private constant ML_DSA_87_SIG_SIZE = 4595;
    uint256 private constant FN_DSA_512_SIG_SIZE = 690;
    uint256 private constant FN_DSA_1024_SIG_SIZE = 1280;
    uint256 private constant SLH_DSA_128S_SIG_SIZE = 7856;
    uint256 private constant SLH_DSA_128F_SIG_SIZE = 17088;
    uint256 private constant SLH_DSA_256S_SIG_SIZE = 29792;

    // NIST PQC Standard public key sizes
    uint256 private constant ML_DSA_44_PK_SIZE = 1312;
    uint256 private constant ML_DSA_65_PK_SIZE = 1952;
    uint256 private constant ML_DSA_87_PK_SIZE = 2592;
    uint256 private constant FN_DSA_512_PK_SIZE = 897;
    uint256 private constant FN_DSA_1024_PK_SIZE = 1793;
    uint256 private constant SLH_DSA_128S_PK_SIZE = 32;
    uint256 private constant SLH_DSA_128F_PK_SIZE = 32;
    uint256 private constant SLH_DSA_256S_PK_SIZE = 64;

    // KEM public key sizes
    uint256 private constant ML_KEM_512_PK_SIZE = 800;
    uint256 private constant ML_KEM_768_PK_SIZE = 1184;
    uint256 private constant ML_KEM_1024_PK_SIZE = 1568;

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                   PHASE 2: VERIFICATION BACKEND
    //////////////////////////////////////////////////////////////*/

    /// @notice Verification backend for PQC signature verification
    enum VerificationBackend {
        ORACLE, // Phase 1: Off-chain oracle verification
        PRECOMPILE, // Phase 2+: EVM precompile (EIP-TBD)
        ZK_PROOF // Phase 2+: ZK circuit verification
    }

    /// @notice KEM session state for stealth address key exchange
    struct KEMSession {
        bytes32 sessionId;
        address initiator;
        address responder;
        IPQCVerifier.PQCAlgorithm kemAlgorithm;
        bytes32 ciphertextHash; // Hash of ML-KEM ciphertext
        bytes32 sharedSecretHash; // Hash of derived shared secret
        uint256 createdAt;
        uint256 expiresAt;
        bool completed;
    }

    /// @notice PQC public keys registered per address
    mapping(address => IPQCVerifier.PQCPublicKey) public pqcKeys;

    /// @notice Key hash to owner reverse lookup
    mapping(bytes32 => address) public keyHashToOwner;

    /// @notice Last key rotation timestamp per address
    mapping(address => uint256) public lastKeyRotation;

    /// @notice Total registered PQC keys
    uint256 public totalKeysRegistered;

    /// @notice Total hybrid verifications performed
    uint256 public totalVerifications;

    /// @notice Total successful hybrid verifications
    uint256 public successfulVerifications;

    /// @notice Default verification mode
    IPQCVerifier.VerificationMode public defaultMode;

    /// @notice Off-chain PQC verification oracle
    address public pqcOracle;

    /// @notice Approved off-chain PQC verification results (Phase 1)
    mapping(bytes32 => bool) public approvedPQCResults;

    /// @notice Phase 2: Verification backend per algorithm
    mapping(IPQCVerifier.PQCAlgorithm => VerificationBackend)
        public algorithmBackend;

    /// @notice Phase 2: Precompile addresses per algorithm (for future EVM PQC precompiles)
    mapping(IPQCVerifier.PQCAlgorithm => address) public precompileAddresses;

    /// @notice Phase 2: KEM session tracking
    mapping(bytes32 => KEMSession) public kemSessions;

    /// @notice Phase 2: Total KEM sessions initiated
    uint256 public totalKEMSessions;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event PQCKeyRegistered(
        address indexed owner,
        IPQCVerifier.PQCAlgorithm algorithm,
        bytes32 keyHash,
        IPQCVerifier.SecurityLevel level
    );

    event PQCKeyRevoked(
        address indexed owner,
        bytes32 keyHash,
        uint256 revokedAt
    );

    event PQCKeyRotated(
        address indexed owner,
        bytes32 oldKeyHash,
        bytes32 newKeyHash,
        IPQCVerifier.PQCAlgorithm newAlgorithm
    );

    event HybridVerificationResult(
        address indexed signer,
        IPQCVerifier.PQCAlgorithm algorithm,
        IPQCVerifier.VerificationMode mode,
        bool classicalValid,
        bool pqcValid,
        bool overallResult
    );

    event DefaultModeUpdated(
        IPQCVerifier.VerificationMode oldMode,
        IPQCVerifier.VerificationMode newMode
    );

    event PQCOracleUpdated(
        address indexed oldOracle,
        address indexed newOracle
    );

    event PQCResultApproved(
        bytes32 indexed resultHash,
        address indexed submitter
    );

    event VerificationBackendUpdated(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        VerificationBackend oldBackend,
        VerificationBackend newBackend
    );

    event PrecompileAddressSet(
        IPQCVerifier.PQCAlgorithm indexed algorithm,
        address precompileAddress
    );

    event KEMSessionInitiated(
        bytes32 indexed sessionId,
        address indexed initiator,
        address indexed responder,
        IPQCVerifier.PQCAlgorithm algorithm
    );

    event KEMSessionCompleted(
        bytes32 indexed sessionId,
        bytes32 sharedSecretHash
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidKeySize(
        IPQCVerifier.PQCAlgorithm algorithm,
        uint256 expected,
        uint256 actual
    );
    error KeyAlreadyRegistered(address owner);
    error KeyNotRegistered(address owner);
    error KeyRevoked(address owner);
    error RotationCooldownActive(uint256 cooldownEnds);
    error InvalidSignatureSize(
        IPQCVerifier.PQCAlgorithm algorithm,
        uint256 expected,
        uint256 actual
    );
    error HybridVerificationFailed(bool classicalResult, bool pqcResult);
    error InvalidOracle();
    error OnlyOracle();
    error PQCResultNotApproved(bytes32 resultHash);
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _pqcOracle) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(KEY_REGISTRAR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        pqcOracle = _pqcOracle;
        defaultMode = IPQCVerifier.VerificationMode.HYBRID;
    }

    /*//////////////////////////////////////////////////////////////
                        KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a PQC public key for an address
     * @dev Validates key size against expected size for the algorithm.
     *      In Phase 1, stores the key hash for off-chain verification lookups.
     * @param keyData Raw PQC public key bytes
     * @param algorithm The NIST PQC algorithm
     */
    function registerPQCKey(
        bytes calldata keyData,
        IPQCVerifier.PQCAlgorithm algorithm
    ) external nonReentrant whenNotPaused {
        if (
            pqcKeys[msg.sender].keyHash != bytes32(0) &&
            !pqcKeys[msg.sender].revoked
        ) {
            revert KeyAlreadyRegistered(msg.sender);
        }

        uint256 expectedSize = _getPublicKeySize(algorithm);
        if (keyData.length != expectedSize) {
            revert InvalidKeySize(algorithm, expectedSize, keyData.length);
        }

        IPQCVerifier.SecurityLevel level = _getSecurityLevel(algorithm);
        bytes32 keyHash = keccak256(
            abi.encodePacked(PQC_KEY_DOMAIN, msg.sender, keyData)
        );

        pqcKeys[msg.sender] = IPQCVerifier.PQCPublicKey({
            keyData: keyData,
            algorithm: algorithm,
            level: level,
            keyHash: keyHash,
            registeredAt: block.timestamp,
            revoked: false
        });

        keyHashToOwner[keyHash] = msg.sender;
        lastKeyRotation[msg.sender] = block.timestamp;
        totalKeysRegistered++;

        emit PQCKeyRegistered(msg.sender, algorithm, keyHash, level);
    }

    /**
     * @notice Revoke a PQC public key
     * @dev Only the key owner or a guardian can revoke
     */
    function revokePQCKey() external nonReentrant {
        if (pqcKeys[msg.sender].keyHash == bytes32(0)) {
            revert KeyNotRegistered(msg.sender);
        }

        bytes32 oldHash = pqcKeys[msg.sender].keyHash;
        pqcKeys[msg.sender].revoked = true;
        delete keyHashToOwner[oldHash];

        emit PQCKeyRevoked(msg.sender, oldHash, block.timestamp);
    }

    /**
     * @notice Guardian-initiated key revocation (for compromised keys)
     * @param owner Address whose key to revoke
     */
    function guardianRevokeKey(
        address owner
    ) external onlyRole(GUARDIAN_ROLE) nonReentrant {
        if (pqcKeys[owner].keyHash == bytes32(0)) {
            revert KeyNotRegistered(owner);
        }

        bytes32 oldHash = pqcKeys[owner].keyHash;
        pqcKeys[owner].revoked = true;
        delete keyHashToOwner[oldHash];

        emit PQCKeyRevoked(owner, oldHash, block.timestamp);
    }

    /**
     * @notice Rotate to a new PQC public key
     * @dev Subject to cooldown period to prevent rapid key cycling attacks
     * @param newKeyData New PQC public key bytes
     * @param newAlgorithm Algorithm for the new key (can differ from old)
     */
    function rotatePQCKey(
        bytes calldata newKeyData,
        IPQCVerifier.PQCAlgorithm newAlgorithm
    ) external nonReentrant whenNotPaused {
        if (pqcKeys[msg.sender].keyHash == bytes32(0)) {
            revert KeyNotRegistered(msg.sender);
        }

        uint256 cooldownEnd = lastKeyRotation[msg.sender] +
            KEY_ROTATION_COOLDOWN;
        if (block.timestamp < cooldownEnd) {
            revert RotationCooldownActive(cooldownEnd);
        }

        uint256 expectedSize = _getPublicKeySize(newAlgorithm);
        if (newKeyData.length != expectedSize) {
            revert InvalidKeySize(
                newAlgorithm,
                expectedSize,
                newKeyData.length
            );
        }

        bytes32 oldHash = pqcKeys[msg.sender].keyHash;
        delete keyHashToOwner[oldHash];

        IPQCVerifier.SecurityLevel level = _getSecurityLevel(newAlgorithm);
        bytes32 newHash = keccak256(
            abi.encodePacked(PQC_KEY_DOMAIN, msg.sender, newKeyData)
        );

        pqcKeys[msg.sender] = IPQCVerifier.PQCPublicKey({
            keyData: newKeyData,
            algorithm: newAlgorithm,
            level: level,
            keyHash: newHash,
            registeredAt: block.timestamp,
            revoked: false
        });

        keyHashToOwner[newHash] = msg.sender;
        lastKeyRotation[msg.sender] = block.timestamp;

        emit PQCKeyRotated(msg.sender, oldHash, newHash, newAlgorithm);
    }

    /*//////////////////////////////////////////////////////////////
                     HYBRID VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a hybrid signature (classical ECDSA + PQC)
     * @dev Phase 1: PQC verification delegated to off-chain oracle.
     *      The oracle submits approved verification results as hashes.
     *      Classical ECDSA verification is done on-chain via ecrecover.
     *
     * @param messageHash The hash of the signed message (EIP-191 compliant)
     * @param classicalSig ECDSA signature (65 bytes: r, s, v)
     * @param pqcSig PQC signature bytes
     * @param signer Expected signer address
     * @param mode Verification mode (HYBRID, PQC_ONLY, CLASSICAL_ONLY)
     * @return valid True if verification passes
     */
    function verifyHybrid(
        bytes32 messageHash,
        bytes calldata classicalSig,
        bytes calldata pqcSig,
        address signer,
        IPQCVerifier.VerificationMode mode
    ) external nonReentrant whenNotPaused returns (bool valid) {
        totalVerifications++;

        bool classicalValid = false;
        bool pqcValid = false;

        // Classical ECDSA verification (on-chain)
        if (
            mode == IPQCVerifier.VerificationMode.CLASSICAL_ONLY ||
            mode == IPQCVerifier.VerificationMode.HYBRID
        ) {
            classicalValid = _verifyECDSA(messageHash, classicalSig, signer);
        }

        // PQC verification (Phase 1: oracle-based)
        if (
            mode == IPQCVerifier.VerificationMode.PQC_ONLY ||
            mode == IPQCVerifier.VerificationMode.HYBRID
        ) {
            pqcValid = _verifyPQCViaOracle(messageHash, pqcSig, signer);
        }

        // Determine overall result based on mode
        if (mode == IPQCVerifier.VerificationMode.HYBRID) {
            valid = classicalValid && pqcValid;
        } else if (mode == IPQCVerifier.VerificationMode.CLASSICAL_ONLY) {
            valid = classicalValid;
        } else {
            valid = pqcValid;
        }

        if (valid) {
            successfulVerifications++;
        }

        emit HybridVerificationResult(
            signer,
            pqcKeys[signer].algorithm,
            mode,
            classicalValid,
            pqcValid,
            valid
        );
    }

    /**
     * @notice Verify using the default verification mode
     * @param messageHash The hash of the signed message
     * @param classicalSig ECDSA signature
     * @param pqcSig PQC signature
     * @param signer Expected signer
     * @return valid Whether verification passed
     */
    function verifyDefault(
        bytes32 messageHash,
        bytes calldata classicalSig,
        bytes calldata pqcSig,
        address signer
    ) external nonReentrant whenNotPaused returns (bool valid) {
        totalVerifications++;

        bool classicalValid = _verifyECDSA(messageHash, classicalSig, signer);
        bool pqcValid = _verifyPQCViaOracle(messageHash, pqcSig, signer);

        if (defaultMode == IPQCVerifier.VerificationMode.HYBRID) {
            valid = classicalValid && pqcValid;
        } else if (
            defaultMode == IPQCVerifier.VerificationMode.CLASSICAL_ONLY
        ) {
            valid = classicalValid;
        } else {
            valid = pqcValid;
        }

        if (valid) {
            successfulVerifications++;
        }

        emit HybridVerificationResult(
            signer,
            pqcKeys[signer].algorithm,
            defaultMode,
            classicalValid,
            pqcValid,
            valid
        );
    }

    /*//////////////////////////////////////////////////////////////
                     ORACLE FUNCTIONS (Phase 1)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an approved PQC verification result (oracle only)
     * @dev The oracle verifies PQC signatures off-chain and submits the result hash
     * @param resultHash Hash of (messageHash, pqcSig, signer, algorithm, valid)
     */
    function submitPQCResult(bytes32 resultHash) external {
        if (msg.sender != pqcOracle) revert OnlyOracle();

        approvedPQCResults[resultHash] = true;
        emit PQCResultApproved(resultHash, msg.sender);
    }

    /**
     * @notice Batch submit PQC verification results
     * @param resultHashes Array of result hashes to approve
     */
    function batchSubmitPQCResults(bytes32[] calldata resultHashes) external {
        if (msg.sender != pqcOracle) revert OnlyOracle();

        for (uint256 i = 0; i < resultHashes.length; ) {
            approvedPQCResults[resultHashes[i]] = true;
            emit PQCResultApproved(resultHashes[i], msg.sender);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the default verification mode
     * @param newMode New default mode
     */
    function setDefaultMode(
        IPQCVerifier.VerificationMode newMode
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IPQCVerifier.VerificationMode oldMode = defaultMode;
        defaultMode = newMode;
        emit DefaultModeUpdated(oldMode, newMode);
    }

    /**
     * @notice Update the PQC oracle address
     * @param newOracle New oracle address
     */
    function setPQCOracle(
        address newOracle
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newOracle == address(0)) revert InvalidOracle();
        address oldOracle = pqcOracle;
        pqcOracle = newOracle;
        emit PQCOracleUpdated(oldOracle, newOracle);
    }

    /**
     * @notice Set the verification backend for a PQC algorithm (Phase 2)
     * @param algorithm The PQC algorithm
     * @param backend The verification backend
     */
    function setVerificationBackend(
        IPQCVerifier.PQCAlgorithm algorithm,
        VerificationBackend backend
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        VerificationBackend oldBackend = algorithmBackend[algorithm];
        algorithmBackend[algorithm] = backend;
        emit VerificationBackendUpdated(algorithm, oldBackend, backend);
    }

    /**
     * @notice Set the precompile address for a PQC algorithm (Phase 2+)
     * @dev Will be used when EVM PQC precompiles are available
     * @param algorithm The PQC algorithm
     * @param precompile The precompile address
     */
    function setPrecompileAddress(
        IPQCVerifier.PQCAlgorithm algorithm,
        address precompile
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (precompile == address(0)) revert ZeroAddress();
        precompileAddresses[algorithm] = precompile;
        emit PrecompileAddressSet(algorithm, precompile);
    }

    /**
     * @notice Initiate a KEM session for stealth address key exchange (Phase 2)
     * @dev The actual KEM encapsulation happens off-chain. This records the
     *      session context and ciphertext commitment on-chain.
     * @param responder The other party (stealth address recipient)
     * @param kemAlgorithm The KEM algorithm (must be ML-KEM variant)
     * @param ciphertextHash Hash of the ML-KEM ciphertext
     * @param duration Session duration in seconds
     * @return sessionId The unique session identifier
     */
    function initiateKEMSession(
        address responder,
        IPQCVerifier.PQCAlgorithm kemAlgorithm,
        bytes32 ciphertextHash,
        uint256 duration
    ) external nonReentrant whenNotPaused returns (bytes32 sessionId) {
        // Validate KEM algorithm
        require(
            IPQCVerifierLib.isKEMAlgorithm(kemAlgorithm),
            "Not a KEM algorithm"
        );
        require(
            responder != address(0) && responder != msg.sender,
            "Invalid responder"
        );
        require(duration > 0 && duration <= 7 days, "Invalid duration");

        sessionId = keccak256(
            abi.encodePacked(
                PQC_KEY_DOMAIN,
                msg.sender,
                responder,
                kemAlgorithm,
                ciphertextHash,
                block.timestamp,
                totalKEMSessions
            )
        );

        kemSessions[sessionId] = KEMSession({
            sessionId: sessionId,
            initiator: msg.sender,
            responder: responder,
            kemAlgorithm: kemAlgorithm,
            ciphertextHash: ciphertextHash,
            sharedSecretHash: bytes32(0),
            createdAt: block.timestamp,
            expiresAt: block.timestamp + duration,
            completed: false
        });

        totalKEMSessions++;

        emit KEMSessionInitiated(
            sessionId,
            msg.sender,
            responder,
            kemAlgorithm
        );
    }

    /**
     * @notice Complete a KEM session (responder confirms decapsulation)
     * @param sessionId The session to complete
     * @param sharedSecretHash Hash of the derived shared secret
     */
    function completeKEMSession(
        bytes32 sessionId,
        bytes32 sharedSecretHash
    ) external nonReentrant {
        KEMSession storage session = kemSessions[sessionId];
        require(session.sessionId != bytes32(0), "Session not found");
        require(msg.sender == session.responder, "Not responder");
        require(!session.completed, "Already completed");
        require(block.timestamp <= session.expiresAt, "Session expired");

        session.sharedSecretHash = sharedSecretHash;
        session.completed = true;

        emit KEMSessionCompleted(sessionId, sharedSecretHash);
    }

    /// @notice Pause the contract
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get PQC key info for an address
     * @param owner The key owner
     * @return key The PQC public key struct
     */
    function getPQCKey(
        address owner
    ) external view returns (IPQCVerifier.PQCPublicKey memory key) {
        return pqcKeys[owner];
    }

    /**
     * @notice Check if an address has a valid (non-revoked) PQC key
     * @param owner The address to check
     * @return hasKey True if the address has a valid PQC key
     */
    function hasValidPQCKey(address owner) external view returns (bool hasKey) {
        return pqcKeys[owner].keyHash != bytes32(0) && !pqcKeys[owner].revoked;
    }

    /**
     * @notice Get verification statistics
     * @return total Total verifications
     * @return successful Successful verifications
     * @return successRate Success rate as basis points (0-10000)
     */
    function getVerificationStats()
        external
        view
        returns (uint256 total, uint256 successful, uint256 successRate)
    {
        total = totalVerifications;
        successful = successfulVerifications;
        successRate = total > 0 ? (successful * 10_000) / total : 0;
    }

    /**
     * @notice Get expected public key size for a PQC algorithm
     * @param algorithm The algorithm
     * @return size Expected key size in bytes
     */
    function getExpectedKeySize(
        IPQCVerifier.PQCAlgorithm algorithm
    ) external pure returns (uint256 size) {
        return _getPublicKeySize(algorithm);
    }

    /**
     * @notice Get expected signature size for a PQC algorithm
     * @param algorithm The algorithm
     * @return size Expected signature size in bytes
     */
    function getExpectedSignatureSize(
        IPQCVerifier.PQCAlgorithm algorithm
    ) external pure returns (uint256 size) {
        return _getSignatureSize(algorithm);
    }

    /*//////////////////////////////////////////////////////////////
                     INTERNAL VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify ECDSA signature on-chain via ecrecover
     */
    function _verifyECDSA(
        bytes32 messageHash,
        bytes calldata signature,
        address expectedSigner
    ) internal pure returns (bool) {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Signature malleability protection
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return false;
        }

        if (v != 27 && v != 28) return false;

        address recovered = ecrecover(messageHash, v, r, s);
        return recovered != address(0) && recovered == expectedSigner;
    }

    /**
     * @dev Phase 1/2: Verify PQC signature via configurable backend
     *      Phase 1 (default): Oracle-based verification
     *      Phase 2: Precompile or ZK proof verification
     */
    function _verifyPQCViaOracle(
        bytes32 messageHash,
        bytes calldata pqcSig,
        address signer
    ) internal view returns (bool) {
        // Check signer has registered PQC key
        IPQCVerifier.PQCPublicKey storage key = pqcKeys[signer];
        if (key.keyHash == bytes32(0)) return false;
        if (key.revoked) return false;

        // Validate signature size
        uint256 expectedSigSize = _getSignatureSize(key.algorithm);
        if (pqcSig.length != expectedSigSize) return false;

        // Route to appropriate backend
        VerificationBackend backend = algorithmBackend[key.algorithm];

        if (backend == VerificationBackend.PRECOMPILE) {
            return
                _verifyPQCViaPrecompile(
                    messageHash,
                    pqcSig,
                    signer,
                    key.algorithm
                );
        }

        if (backend == VerificationBackend.ZK_PROOF) {
            return
                _verifyPQCViaZKProof(
                    messageHash,
                    pqcSig,
                    signer,
                    key.algorithm
                );
        }

        // Default: Oracle-based verification (Phase 1)
        bytes32 resultHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                messageHash,
                keccak256(pqcSig),
                signer,
                key.algorithm
            )
        );

        return approvedPQCResults[resultHash];
    }

    /**
     * @dev Phase 2+: Verify PQC signature via EVM precompile (stub)
     *      Will be activated when EIP for PQC precompiles is finalized.
     *      The precompile ABI: staticcall(gas, precompile, abi.encode(pubkey, message, signature))
     */
    function _verifyPQCViaPrecompile(
        bytes32 messageHash,
        bytes calldata pqcSig,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal view returns (bool) {
        address precompile = precompileAddresses[algorithm];
        if (precompile == address(0)) return false;

        // Encode verification inputs per the expected precompile ABI
        bytes memory input = abi.encode(
            pqcKeys[signer].keyHash,
            messageHash,
            keccak256(pqcSig)
        );

        // Static call to precompile
        (bool success, bytes memory result) = precompile.staticcall(input);
        if (!success || result.length < 32) return false;

        return abi.decode(result, (bool));
    }

    /**
     * @dev Phase 2+: Verify PQC signature via ZK proof
     *      Routes to a ZK verifier contract that proves correct PQC
     *      signature verification was performed off-chain.
     */
    function _verifyPQCViaZKProof(
        bytes32 messageHash,
        bytes calldata pqcSig,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal view returns (bool) {
        // For ZK_PROOF mode, we check if the oracle has already
        // approved the ZK proof verification result
        bytes32 zkResultHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                "ZK_VERIFIED",
                messageHash,
                keccak256(pqcSig),
                signer,
                algorithm
            )
        );
        return approvedPQCResults[zkResultHash];
    }

    /*//////////////////////////////////////////////////////////////
                     INTERNAL SIZE LOOKUPS
    //////////////////////////////////////////////////////////////*/

    function _getPublicKeySize(
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_44)
            return ML_DSA_44_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_65)
            return ML_DSA_65_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_87)
            return ML_DSA_87_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.FN_DSA_512)
            return FN_DSA_512_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.FN_DSA_1024)
            return FN_DSA_1024_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_128S)
            return SLH_DSA_128S_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_128F)
            return SLH_DSA_128F_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_256S)
            return SLH_DSA_256S_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_KEM_512)
            return ML_KEM_512_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_KEM_768)
            return ML_KEM_768_PK_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_KEM_1024)
            return ML_KEM_1024_PK_SIZE;
        revert("Unknown algorithm");
    }

    function _getSignatureSize(
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal pure returns (uint256) {
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_44)
            return ML_DSA_44_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_65)
            return ML_DSA_65_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_87)
            return ML_DSA_87_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.FN_DSA_512)
            return FN_DSA_512_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.FN_DSA_1024)
            return FN_DSA_1024_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_128S)
            return SLH_DSA_128S_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_128F)
            return SLH_DSA_128F_SIG_SIZE;
        if (algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_256S)
            return SLH_DSA_256S_SIG_SIZE;
        // KEM algorithms don't have signatures
        return 0;
    }

    function _getSecurityLevel(
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal pure returns (IPQCVerifier.SecurityLevel) {
        if (
            algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_44 ||
            algorithm == IPQCVerifier.PQCAlgorithm.FN_DSA_512 ||
            algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_128S ||
            algorithm == IPQCVerifier.PQCAlgorithm.SLH_DSA_128F ||
            algorithm == IPQCVerifier.PQCAlgorithm.ML_KEM_512
        ) {
            return IPQCVerifier.SecurityLevel.LEVEL_1;
        }
        if (
            algorithm == IPQCVerifier.PQCAlgorithm.ML_DSA_65 ||
            algorithm == IPQCVerifier.PQCAlgorithm.ML_KEM_768
        ) {
            return IPQCVerifier.SecurityLevel.LEVEL_3;
        }
        return IPQCVerifier.SecurityLevel.LEVEL_5;
    }
}

/*//////////////////////////////////////////////////////////////
                  LIBRARY FOR PQC ALGORITHM UTILS
//////////////////////////////////////////////////////////////*/

/**
 * @title IPQCVerifierLib
 * @notice Utility library for PQC algorithm type checks
 */
library IPQCVerifierLib {
    /**
     * @notice Check if an algorithm is a signature scheme (not KEM)
     * @param algorithm The PQC algorithm
     * @return True if it's a signature algorithm
     */
    function isSignatureAlgorithm(
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal pure returns (bool) {
        return
            uint8(algorithm) <= uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S);
    }

    /**
     * @notice Check if an algorithm is a KEM scheme
     * @param algorithm The PQC algorithm
     * @return True if it's a KEM algorithm
     */
    function isKEMAlgorithm(
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal pure returns (bool) {
        return uint8(algorithm) >= uint8(IPQCVerifier.PQCAlgorithm.ML_KEM_512);
    }
}
