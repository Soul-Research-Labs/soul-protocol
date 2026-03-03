// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";

/**
 * @title PQCNativeStealth
 * @author ZASEON
 * @notice Fully PQC-native stealth address scheme — no classical ECDH dependency
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                 PHASE 3: PQC-NATIVE STEALTH ADDRESS SCHEME
 * ══════════════════════════════════════════════════════════════════════════
 *
 * This contract replaces the classical ECDH-based stealth address scheme
 * entirely with post-quantum cryptographic primitives:
 *
 * SPENDING KEYS:  Falcon-512 / ML-DSA (lattice-based signatures)
 *   - ZK circuit proves ownership of spending key
 *   - Verified on-chain via FalconZKVerifier or HybridPQCVerifier
 *
 * VIEWING KEYS:   ML-KEM (Kyber) key encapsulation
 *   - Client-side Encaps/Decaps for shared secret derivation
 *   - Ciphertext commitment stored on-chain
 *
 * ADDRESS DERIVATION:
 *   1. Sender: SS ← ML-KEM.Encaps(pk_view) → (ct, SS)
 *   2. Stealth addr = H(PQC_NATIVE_DOMAIN || pk_spend_hash || SS || nonce) mod 2^160
 *   3. On-chain: store (ct_hash, stealth_addr, view_tag, nonce)
 *   4. Recipient: SS = ML-KEM.Decaps(sk_view, ct) → recover stealth addr
 *
 * OWNERSHIP PROOF:
 *   A ZK proof is required to claim a stealth address:
 *   - Private inputs: sk_spend, SS (shared secret)
 *   - Public inputs:  stealth_addr, pk_spend_hash, ct_hash
 *   - Constraint:     stealth_addr == H(domain || pk_spend_hash || SS || nonce) mod 2^160
 *
 * CROSS-CHAIN (enhanced):
 *   - Stealth transfer between L2s uses chain-specific domain separation
 *   - Proof-of-derivation required (verified via PQCPrecompileRouter or ZK)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PQCNativeStealth is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PQC_NATIVE_DOMAIN =
        keccak256("ZASEON_PQC_NATIVE_STEALTH_V1");

    /// @notice ML-KEM ciphertext sizes
    uint256 public constant ML_KEM_768_CT_SIZE = 1088;
    uint256 public constant ML_KEM_512_CT_SIZE = 768;
    uint256 public constant ML_KEM_1024_CT_SIZE = 1568;

    /// @notice Falcon-512 public key size
    uint256 public constant FALCON_512_PK_SIZE = 897;

    /// @notice Falcon-1024 public key size
    uint256 public constant FALCON_1024_PK_SIZE = 1793;

    /// @notice Minimum ZK proof length for ownership claims
    uint256 public constant MIN_OWNERSHIP_PROOF_SIZE = 128;

    /// @notice Maximum stealth addresses per meta-address
    uint256 public constant MAX_STEALTH_PER_META = 10_000;

    /// @notice View tag size (1 byte)
    uint8 public constant VIEW_TAG_SIZE = 1;

    /*//////////////////////////////////////////////////////////////
                               ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice KEM variant used for stealth derivation
    enum KEMVariant {
        ML_KEM_512, // NIST Level 1
        ML_KEM_768, // NIST Level 3 (recommended)
        ML_KEM_1024 // NIST Level 5
    }

    /// @notice PQC signature algorithm for spending key
    enum SpendAlgorithm {
        FALCON_512, // Compact signatures
        FALCON_1024, // Higher security
        ML_DSA_44, // Dilithium L2
        ML_DSA_65, // Dilithium L3
        ML_DSA_87 // Dilithium L5
    }

    /// @notice Stealth address state
    enum StealthState {
        ACTIVE, // Address can receive funds
        CLAIMED, // Ownership proven and funds claimed
        EXPIRED, // Past expiry window
        REVOKED // Revoked by either party
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC native meta-address (fully quantum-safe)
    struct NativeMetaAddress {
        bytes32 spendKeyHash; // H(pqcSpendingPubKey)
        bytes32 viewKeyHash; // H(pqcViewingPubKey)
        SpendAlgorithm spendAlgo; // Spending key algorithm
        KEMVariant kemVariant; // Viewing key KEM variant
        uint256 registeredAt;
        uint256 stealthCount; // Number of stealth addresses derived
        bool active;
    }

    /// @notice Stealth address record (fully PQC)
    struct StealthRecord {
        address stealthAddress; // Derived stealth address
        address recipient; // Meta-address owner (can discover)
        bytes32 ciphertextHash; // H(kemCiphertext)
        bytes32 spendKeyHash; // From meta-address
        bytes1 viewTag; // First byte of H(SS) for scanning
        uint32 nonce; // Derivation nonce
        uint256 createdAt;
        uint256 claimedAt; // 0 if unclaimed
        StealthState state;
        KEMVariant kemVariant;
    }

    /// @notice Ownership claim (ZK-proven)
    struct OwnershipClaim {
        address stealthAddress;
        address claimant; // Address that submitted the claim
        bytes32 proofHash; // H(zkProof)
        uint256 claimedAt;
        bool verified; // ZK proof verified
    }

    /// @notice Cross-chain stealth transfer
    struct CrossChainTransfer {
        bytes32 sourceStealthId; // keccak256(sourceChainId, stealthAddress)
        bytes32 destStealthId; // keccak256(destChainId, destStealthAddress)
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 derivationProofHash; // H(zkProof of correct derivation)
        uint256 timestamp;
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Meta-addresses by owner
    mapping(address => NativeMetaAddress) public metaAddresses;

    /// @notice Stealth records by stealth address
    mapping(address => StealthRecord) public stealthRecords;

    /// @notice Ownership claims by stealth address
    mapping(address => OwnershipClaim) public ownershipClaims;

    /// @notice View tag index → stealth addresses
    mapping(bytes1 => address[]) public viewTagIndex;

    /// @notice Cross-chain transfers by sourceStealthId → destStealthId
    mapping(bytes32 => mapping(bytes32 => CrossChainTransfer))
        public crossChainTransfers;

    /// @notice Nonce tracking per meta-address to prevent replay
    mapping(address => uint32) public metaNonces;

    /// @notice Used ciphertext hashes (prevent ciphertext reuse)
    mapping(bytes32 => bool) public usedCiphertexts;

    /// @notice HybridPQCVerifier address
    address public hybridPQCVerifier;

    /// @notice FalconZKVerifier address
    address public falconZKVerifier;

    /// @notice PQCPrecompileRouter address (Phase 3)
    address public pqcPrecompileRouter;

    /// @notice PQCStealthIntegration (Phase 2, for migration)
    address public legacyPQCStealth;

    /// Statistics
    uint256 public totalMetaAddresses;
    uint256 public totalStealthAddresses;
    uint256 public totalClaims;
    uint256 public totalCrossChainTransfers;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event NativeMetaAddressRegistered(
        address indexed owner,
        SpendAlgorithm spendAlgo,
        KEMVariant kemVariant,
        bytes32 spendKeyHash,
        bytes32 viewKeyHash
    );

    event NativeMetaAddressRevoked(address indexed owner, uint256 revokedAt);

    event StealthAddressCreated(
        address indexed stealthAddress,
        address indexed recipient,
        bytes32 ciphertextHash,
        bytes1 viewTag,
        uint32 nonce,
        KEMVariant kemVariant
    );

    event OwnershipClaimSubmitted(
        address indexed stealthAddress,
        address indexed claimant,
        bytes32 proofHash
    );

    event OwnershipClaimVerified(
        address indexed stealthAddress,
        address indexed claimant,
        bool success
    );

    event CrossChainStealthTransfer(
        bytes32 indexed sourceStealthId,
        bytes32 indexed destStealthId,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event LegacyMigration(
        address indexed owner,
        bytes32 oldSpendKeyHash,
        bytes32 newSpendKeyHash
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error MetaAddressAlreadyExists(address owner);
    error MetaAddressNotFound(address owner);
    error MetaAddressRevoked();
    error StealthAddressAlreadyExists(address stealth);
    error StealthAddressNotFound(address stealth);
    error StealthAddressNotActive(address stealth);
    error CiphertextAlreadyUsed(bytes32 ctHash);
    error InvalidCiphertextSize(
        KEMVariant variant,
        uint256 expected,
        uint256 actual
    );
    error InvalidProofSize(uint256 size);
    error InvalidSpendKeySize(SpendAlgorithm algo, uint256 size);
    error ClaimAlreadySubmitted(address stealth);
    error MaxStealthReached(address owner);
    error InvalidChainId();
    error CrossChainTransferExists(bytes32 sourceId, bytes32 destId);
    error VerificationFailed();
    error InvalidNonce(uint32 expected, uint32 provided);

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address admin,
        address _hybridPQCVerifier,
        address _falconZKVerifier
    ) {
        if (admin == address(0)) revert ZeroAddress();
        if (_hybridPQCVerifier == address(0)) revert ZeroAddress();
        if (_falconZKVerifier == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);

        hybridPQCVerifier = _hybridPQCVerifier;
        falconZKVerifier = _falconZKVerifier;
    }

    /*//////////////////////////////////////////////////////////////
                  META-ADDRESS REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a fully PQC-native meta-address
     * @param spendingPubKey PQC spending public key (Falcon/ML-DSA)
     * @param viewingPubKey  ML-KEM public key for viewing
     * @param spendAlgo      Spending key algorithm
     * @param kemVariant     KEM variant for viewing
     */
    function registerNativeMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        SpendAlgorithm spendAlgo,
        KEMVariant kemVariant
    ) external nonReentrant whenNotPaused {
        if (metaAddresses[msg.sender].active)
            revert MetaAddressAlreadyExists(msg.sender);

        _validateSpendKeySize(spendingPubKey, spendAlgo);
        _validateViewKeySize(viewingPubKey, kemVariant);

        bytes32 spendHash = keccak256(
            abi.encodePacked(PQC_NATIVE_DOMAIN, "spend", spendingPubKey)
        );
        bytes32 viewHash = keccak256(
            abi.encodePacked(PQC_NATIVE_DOMAIN, "view", viewingPubKey)
        );

        metaAddresses[msg.sender] = NativeMetaAddress({
            spendKeyHash: spendHash,
            viewKeyHash: viewHash,
            spendAlgo: spendAlgo,
            kemVariant: kemVariant,
            registeredAt: block.timestamp,
            stealthCount: 0,
            active: true
        });

        totalMetaAddresses++;

        emit NativeMetaAddressRegistered(
            msg.sender,
            spendAlgo,
            kemVariant,
            spendHash,
            viewHash
        );
    }

    /**
     * @notice Revoke a PQC-native meta-address
     */
    function revokeMetaAddress() external nonReentrant {
        if (!metaAddresses[msg.sender].active)
            revert MetaAddressNotFound(msg.sender);

        metaAddresses[msg.sender].active = false;
        emit NativeMetaAddressRevoked(msg.sender, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
               STEALTH ADDRESS CREATION (SEND-SIDE)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a PQC-native stealth address
     * @dev Called by the sender after performing ML-KEM.Encaps off-chain.
     *      The stealth address is derived as:
     *        H(PQC_NATIVE_DOMAIN || spendKeyHash || ssHash || nonce) mod 2^160
     *      where ssHash = H("shared_secret" || sharedSecret)
     *
     * @param recipient       Meta-address owner who can discover this
     * @param kemCiphertext   ML-KEM ciphertext from Encaps(viewingPubKey)
     * @param stealthAddress  Pre-computed stealth address
     * @param viewTag         First byte of H(sharedSecret) for scanning
     * @param nonce           Derivation nonce (must match meta-nonce)
     */
    function createStealthAddress(
        address recipient,
        bytes calldata kemCiphertext,
        address stealthAddress,
        bytes1 viewTag,
        uint32 nonce
    ) external nonReentrant whenNotPaused {
        if (recipient == address(0)) revert ZeroAddress();
        if (stealthAddress == address(0)) revert ZeroAddress();

        NativeMetaAddress storage meta = metaAddresses[recipient];
        if (!meta.active) revert MetaAddressNotFound(recipient);
        if (meta.stealthCount >= MAX_STEALTH_PER_META)
            revert MaxStealthReached(recipient);

        // Validate ciphertext
        uint256 expectedCT = _getKEMCiphertextSize(meta.kemVariant);
        if (kemCiphertext.length != expectedCT)
            revert InvalidCiphertextSize(
                meta.kemVariant,
                expectedCT,
                kemCiphertext.length
            );

        // Prevent ciphertext reuse
        bytes32 ctHash = keccak256(kemCiphertext);
        if (usedCiphertexts[ctHash]) revert CiphertextAlreadyUsed(ctHash);

        // Prevent duplicate stealth address
        if (stealthRecords[stealthAddress].createdAt != 0)
            revert StealthAddressAlreadyExists(stealthAddress);

        // Validate nonce
        if (nonce != metaNonces[recipient])
            revert InvalidNonce(metaNonces[recipient], nonce);

        // Store record
        usedCiphertexts[ctHash] = true;
        metaNonces[recipient]++;
        meta.stealthCount++;

        stealthRecords[stealthAddress] = StealthRecord({
            stealthAddress: stealthAddress,
            recipient: recipient,
            ciphertextHash: ctHash,
            spendKeyHash: meta.spendKeyHash,
            viewTag: viewTag,
            nonce: nonce,
            createdAt: block.timestamp,
            claimedAt: 0,
            state: StealthState.ACTIVE,
            kemVariant: meta.kemVariant
        });

        // View tag index for scanning
        viewTagIndex[viewTag].push(stealthAddress);

        totalStealthAddresses++;

        emit StealthAddressCreated(
            stealthAddress,
            recipient,
            ctHash,
            viewTag,
            nonce,
            meta.kemVariant
        );
    }

    /*//////////////////////////////////////////////////////////////
              OWNERSHIP CLAIM (RECEIVE-SIDE, ZK-PROVEN)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an ownership claim for a stealth address with ZK proof
     * @dev The claimant provides a ZK proof that they know:
     *      - The spending secret key corresponding to spendKeyHash
     *      - The shared secret from ML-KEM.Decaps
     *      - Their derivation produces the claimed stealth address
     *
     * @param stealthAddress  The stealth address being claimed
     * @param ownershipProof  ZK proof of ownership
     */
    function claimStealthAddress(
        address stealthAddress,
        bytes calldata ownershipProof
    ) external nonReentrant whenNotPaused {
        StealthRecord storage record = stealthRecords[stealthAddress];
        if (record.createdAt == 0)
            revert StealthAddressNotFound(stealthAddress);
        if (record.state != StealthState.ACTIVE)
            revert StealthAddressNotActive(stealthAddress);
        if (ownershipProof.length < MIN_OWNERSHIP_PROOF_SIZE)
            revert InvalidProofSize(ownershipProof.length);
        if (ownershipClaims[stealthAddress].claimedAt != 0)
            revert ClaimAlreadySubmitted(stealthAddress);

        bytes32 proofHash = keccak256(ownershipProof);

        // Verify the ZK proof via FalconZKVerifier or HybridPQCVerifier
        bool verified = _verifyOwnershipProof(
            stealthAddress,
            record.spendKeyHash,
            record.ciphertextHash,
            ownershipProof
        );

        ownershipClaims[stealthAddress] = OwnershipClaim({
            stealthAddress: stealthAddress,
            claimant: msg.sender,
            proofHash: proofHash,
            claimedAt: block.timestamp,
            verified: verified
        });

        if (verified) {
            record.state = StealthState.CLAIMED;
            record.claimedAt = block.timestamp;
            totalClaims++;
        }

        emit OwnershipClaimSubmitted(stealthAddress, msg.sender, proofHash);
        emit OwnershipClaimVerified(stealthAddress, msg.sender, verified);
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN STEALTH TRANSFER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a cross-chain stealth transfer with proof of derivation
     * @param sourceStealthAddress  Source stealth address (on this chain)
     * @param destStealthAddress    Destination stealth address (on dest chain)
     * @param destChainId           Destination chain ID
     * @param derivationProof       ZK proof of correct cross-chain derivation
     */
    function registerCrossChainTransfer(
        address sourceStealthAddress,
        address destStealthAddress,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external nonReentrant whenNotPaused {
        if (destChainId == 0 || destChainId == block.chainid)
            revert InvalidChainId();
        if (derivationProof.length < MIN_OWNERSHIP_PROOF_SIZE)
            revert InvalidProofSize(derivationProof.length);

        StealthRecord storage record = stealthRecords[sourceStealthAddress];
        if (record.createdAt == 0)
            revert StealthAddressNotFound(sourceStealthAddress);

        bytes32 sourceId = keccak256(
            abi.encodePacked(block.chainid, sourceStealthAddress)
        );
        bytes32 destId = keccak256(
            abi.encodePacked(destChainId, destStealthAddress)
        );

        if (crossChainTransfers[sourceId][destId].timestamp != 0)
            revert CrossChainTransferExists(sourceId, destId);

        // Verify derivation proof
        bool verified = _verifyCrossChainDerivation(
            sourceStealthAddress,
            destStealthAddress,
            destChainId,
            derivationProof
        );

        crossChainTransfers[sourceId][destId] = CrossChainTransfer({
            sourceStealthId: sourceId,
            destStealthId: destId,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            derivationProofHash: keccak256(derivationProof),
            timestamp: block.timestamp,
            verified: verified
        });

        totalCrossChainTransfers++;

        emit CrossChainStealthTransfer(
            sourceId,
            destId,
            block.chainid,
            destChainId
        );
    }

    /*//////////////////////////////////////////////////////////////
                      MIGRATION FROM PHASE 2
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Migrate from Phase 2 PQCStealthIntegration meta-address
     * @dev Reads existing meta from legacyPQCStealth and creates a
     *      native meta-address with the same key hashes
     * @param spendingPubKey New (or same) spending public key
     * @param viewingPubKey  New (or same) viewing public key
     * @param spendAlgo      Spending algorithm
     * @param kemVariant     KEM variant
     */
    function migrateFromLegacy(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        SpendAlgorithm spendAlgo,
        KEMVariant kemVariant
    ) external nonReentrant whenNotPaused {
        if (legacyPQCStealth == address(0)) revert ZeroAddress();
        if (metaAddresses[msg.sender].active)
            revert MetaAddressAlreadyExists(msg.sender);

        // Check that the caller has a legacy meta-address
        (bool success, bytes memory data) = legacyPQCStealth.staticcall(
            abi.encodeWithSignature("pqcMetaAddresses(address)", msg.sender)
        );
        if (!success) revert MetaAddressNotFound(msg.sender);

        // Decode the legacy meta: active flag is the last field
        // Struct: (bytes, bytes, uint8, uint8, bytes32, bytes32, uint256, bool)
        // We check that active == true (last decoded bool)
        (, , , , bytes32 oldSpendHash, , , bool active) = abi.decode(
            data,
            (bytes, bytes, uint8, uint8, bytes32, bytes32, uint256, bool)
        );
        if (!active) revert MetaAddressRevoked();

        _validateSpendKeySize(spendingPubKey, spendAlgo);
        _validateViewKeySize(viewingPubKey, kemVariant);

        bytes32 newSpendHash = keccak256(
            abi.encodePacked(PQC_NATIVE_DOMAIN, "spend", spendingPubKey)
        );
        bytes32 newViewHash = keccak256(
            abi.encodePacked(PQC_NATIVE_DOMAIN, "view", viewingPubKey)
        );

        metaAddresses[msg.sender] = NativeMetaAddress({
            spendKeyHash: newSpendHash,
            viewKeyHash: newViewHash,
            spendAlgo: spendAlgo,
            kemVariant: kemVariant,
            registeredAt: block.timestamp,
            stealthCount: 0,
            active: true
        });

        totalMetaAddresses++;

        emit NativeMetaAddressRegistered(
            msg.sender,
            spendAlgo,
            kemVariant,
            newSpendHash,
            newViewHash
        );
        emit LegacyMigration(msg.sender, oldSpendHash, newSpendHash);
    }

    /*//////////////////////////////////////////////////////////////
                        SCANNING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get stealth addresses by view tag (scanning optimization)
     */
    function getByViewTag(bytes1 tag) external view returns (address[] memory) {
        return viewTagIndex[tag];
    }

    /**
     * @notice Get stealth record details
     */
    function getStealthRecord(
        address stealthAddress
    ) external view returns (StealthRecord memory) {
        return stealthRecords[stealthAddress];
    }

    /**
     * @notice Get ownership claim status
     */
    function getOwnershipClaim(
        address stealthAddress
    ) external view returns (OwnershipClaim memory) {
        return ownershipClaims[stealthAddress];
    }

    /**
     * @notice Protocol statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 metaCount,
            uint256 stealthCount,
            uint256 claimCount,
            uint256 crossChainCount
        )
    {
        return (
            totalMetaAddresses,
            totalStealthAddresses,
            totalClaims,
            totalCrossChainTransfers
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setHybridPQCVerifier(
        address addr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (addr == address(0)) revert ZeroAddress();
        hybridPQCVerifier = addr;
    }

    function setFalconZKVerifier(
        address addr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (addr == address(0)) revert ZeroAddress();
        falconZKVerifier = addr;
    }

    function setPQCPrecompileRouter(
        address addr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (addr == address(0)) revert ZeroAddress();
        pqcPrecompileRouter = addr;
    }

    function setLegacyPQCStealth(
        address addr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (addr == address(0)) revert ZeroAddress();
        legacyPQCStealth = addr;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                     INTERNAL: ZK PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify ownership ZK proof via available PQC verification backends
     *
     * Verification path (in order of preference):
     *   1. PQCPrecompileRouter (if configured) — routes to precompile or ZK_PROOF
     *   2. FalconZKVerifier — ZK proof for Falcon-512 spending key
     *   3. HybridPQCVerifier — oracle-verified result check
     */
    function _verifyOwnershipProof(
        address stealthAddress,
        bytes32 spendKeyHash,
        bytes32 ciphertextHash,
        bytes calldata proof
    ) internal view returns (bool) {
        // Compute the expected result hash for this claim
        bytes32 expectedHash = keccak256(
            abi.encodePacked(
                PQC_NATIVE_DOMAIN,
                "ownership_proof",
                stealthAddress,
                spendKeyHash,
                ciphertextHash
            )
        );

        // Path 1: Try PQCPrecompileRouter (Phase 3 preferred path)
        if (pqcPrecompileRouter != address(0)) {
            (bool success, bytes memory result) = pqcPrecompileRouter
                .staticcall(
                    abi.encodeWithSignature(
                        "routeVerification(uint8,bytes32,bytes,bytes)",
                        uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512),
                        expectedHash,
                        proof,
                        abi.encodePacked(spendKeyHash)
                    )
                );
            if (success && result.length >= 32) {
                (bool verified, ) = abi.decode(result, (bool, uint8));
                if (verified) return true;
            }
        }

        // Path 2: Try FalconZKVerifier
        if (falconZKVerifier != address(0)) {
            (bool success, bytes memory result) = falconZKVerifier.staticcall(
                abi.encodeWithSignature(
                    "isProofVerified(bytes32)",
                    expectedHash
                )
            );
            if (success && result.length >= 32) {
                bool verified = abi.decode(result, (bool));
                if (verified) return true;
            }
        }

        // Path 3: Try HybridPQCVerifier (oracle path — check approvedPQCResults)
        if (hybridPQCVerifier != address(0)) {
            bytes32 oracleResultHash = keccak256(
                abi.encodePacked(
                    keccak256("ZASEON_HYBRID_PQC_V1"),
                    "ZK_VERIFIED",
                    expectedHash,
                    keccak256(proof),
                    address(this),
                    uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
                )
            );

            (bool success, bytes memory result) = hybridPQCVerifier.staticcall(
                abi.encodeWithSignature(
                    "approvedPQCResults(bytes32)",
                    oracleResultHash
                )
            );
            if (success && result.length >= 32) {
                bool approved = abi.decode(result, (bool));
                if (approved) return true;
            }
        }

        return false;
    }

    /**
     * @dev Verify cross-chain derivation proof
     */
    function _verifyCrossChainDerivation(
        address sourceStealthAddress,
        address destStealthAddress,
        uint256 destChainId,
        bytes calldata proof
    ) internal view returns (bool) {
        bytes32 derivationHash = keccak256(
            abi.encodePacked(
                PQC_NATIVE_DOMAIN,
                "cross_chain_derivation",
                sourceStealthAddress,
                destStealthAddress,
                block.chainid,
                destChainId
            )
        );

        // Try FalconZKVerifier
        if (falconZKVerifier != address(0)) {
            (bool success, bytes memory result) = falconZKVerifier.staticcall(
                abi.encodeWithSignature(
                    "isProofVerified(bytes32)",
                    derivationHash
                )
            );
            if (success && result.length >= 32) {
                bool verified = abi.decode(result, (bool));
                if (verified) return true;
            }
        }

        // Try HybridPQCVerifier oracle fallback
        if (hybridPQCVerifier != address(0)) {
            bytes32 oracleHash = keccak256(
                abi.encodePacked(
                    keccak256("ZASEON_HYBRID_PQC_V1"),
                    derivationHash,
                    keccak256(proof),
                    address(this),
                    uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
                )
            );

            (bool success, bytes memory result) = hybridPQCVerifier.staticcall(
                abi.encodeWithSignature(
                    "approvedPQCResults(bytes32)",
                    oracleHash
                )
            );
            if (success && result.length >= 32) {
                bool approved = abi.decode(result, (bool));
                if (approved) return true;
            }
        }

        return false;
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL: KEY SIZE VALIDATION
    //////////////////////////////////////////////////////////////*/

    function _validateSpendKeySize(
        bytes calldata key,
        SpendAlgorithm algo
    ) internal pure {
        uint256 expected;
        if (algo == SpendAlgorithm.FALCON_512) expected = 897;
        else if (algo == SpendAlgorithm.FALCON_1024) expected = 1793;
        else if (algo == SpendAlgorithm.ML_DSA_44) expected = 1312;
        else if (algo == SpendAlgorithm.ML_DSA_65) expected = 1952;
        else if (algo == SpendAlgorithm.ML_DSA_87) expected = 2592;

        if (key.length != expected)
            revert InvalidSpendKeySize(algo, key.length);
    }

    function _validateViewKeySize(
        bytes calldata key,
        KEMVariant variant
    ) internal pure {
        uint256 expected;
        if (variant == KEMVariant.ML_KEM_512) expected = 800;
        else if (variant == KEMVariant.ML_KEM_768) expected = 1184;
        else if (variant == KEMVariant.ML_KEM_1024) expected = 1568;

        if (key.length != expected)
            revert InvalidCiphertextSize(variant, expected, key.length);
    }

    function _getKEMCiphertextSize(
        KEMVariant variant
    ) internal pure returns (uint256) {
        if (variant == KEMVariant.ML_KEM_512) return ML_KEM_512_CT_SIZE;
        if (variant == KEMVariant.ML_KEM_768) return ML_KEM_768_CT_SIZE;
        if (variant == KEMVariant.ML_KEM_1024) return ML_KEM_1024_CT_SIZE;
        return 0;
    }
}
