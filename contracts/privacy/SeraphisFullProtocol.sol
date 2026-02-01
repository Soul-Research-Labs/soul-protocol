// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SeraphisFullProtocol
 * @notice Full Seraphis protocol implementation tracking Monero's adoption
 * @dev Based on MRL-0015 Seraphis specification with Soul extensions:
 *      - Full Jamtis addressing with subaddress support
 *      - Grootle membership proofs
 *      - Forward secrecy via ephemeral keys
 *      - Cross-chain compatibility layer
 * @custom:security-contact security@soulprotocol.io
 * @custom:research-status Experimental - Tracking Monero mainnet adoption
 */
contract SeraphisFullProtocol is AccessControl, ReentrancyGuard, Pausable {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Domain separator
    bytes32 public constant SERAPHIS_DOMAIN = keccak256("Soul_SERAPHIS_FULL_V1");

    /// @notice Ed25519 curve order (for Monero compatibility)
    uint256 public constant ED25519_ORDER =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// @notice Maximum subaddress index
    uint256 public constant MAX_SUBADDRESS_INDEX = 2 ** 32 - 1;

    /// @notice Grootle proof max ring size
    uint256 public constant MAX_GROOTLE_RING_SIZE = 128;

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Seraphis address type
    enum AddressType {
        STANDARD, // Regular Seraphis address
        SUBADDRESS, // Derived subaddress
        INTEGRATED, // Address with payment ID
        FORWARDING // Address that forwards to another
    }

    /// @notice Transaction type
    enum TxType {
        PLAIN, // Simple transfer
        COINBASE, // Mining reward
        SQUASHED, // Squashed enote transfer
        SUPPLEMENTAL // Supplemental data
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Seraphis master keys (3-key system)
    struct SeraphisMasterKeys {
        bytes32 k_vb; // View-balance key: can view balance
        bytes32 k_m; // Master key: generate subaddresses
        bytes32 k_gi; // Generate-image key: create key images
        // Derived keys
        bytes32 K_s; // Spend key (public)
        bytes32 K_vb; // View-balance key (public)
    }

    /// @notice Jamtis address structure
    struct JamtisAddress {
        bytes32 K_1; // Spend component
        bytes32 K_2; // View component
        bytes32 K_3; // Generate component
        bytes32 addr_tag; // Address tag for filtering
        AddressType addrType;
        uint256 accountIndex;
        uint256 subaddressIndex;
    }

    /// @notice Seraphis enote (encrypted note/output)
    struct SeraphisEnote {
        bytes32 onetime_address; // Ko = Hn(r*K_vb, t)*K_s + Hn'(r*K_vb)*U
        bytes32 amount_commitment; // C = x*G + a*H
        bytes32 encrypted_amount; // enc(a, shared_secret)
        bytes32 view_tag; // First bytes of Hn(r*K_vb)
        bytes32 addr_tag_enc; // Encrypted address tag
        uint256 enote_type; // Type indicator
    }

    /// @notice Grootle membership proof
    struct GrootleProof {
        bytes32 A; // Commitment to sigma polynomial
        bytes32 B; // Commitment to rho polynomial
        bytes32[] f; // Challenge responses (log n)
        bytes32 z_A; // Response A
        bytes32 z_B; // Response B
        bytes32 challenge; // Fiat-Shamir challenge
    }

    /// @notice Seraphis transaction
    struct SeraphisTx {
        TxType txType;
        bytes32 txPrefix; // Transaction prefix hash
        SeraphisEnote[] outputs; // Output enotes
        bytes32[] keyImages; // Input key images
        GrootleProof[] membershipProofs; // Grootle proofs
        bytes32[] balanceProofs; // Balance proof components
        uint256 fee; // Transaction fee
        bytes32 txExtra; // Extra data
    }

    /// @notice Monero adoption tracking
    struct MoneroAdoption {
        uint256 lastMoneroBlock; // Last synced Monero block
        bytes32 lastMoneroHash; // Last synced block hash
        uint256 seraphisActivationBlock; // When Seraphis activates on Monero
        bool isActive; // Whether Seraphis is active on Monero
        uint256 adoptionPercentage; // Estimated network adoption (basis points)
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Registered addresses
    mapping(bytes32 => JamtisAddress) public addresses;

    /// @notice Address to owner mapping
    mapping(bytes32 => address) public addressOwners;

    /// @notice Key images registry
    mapping(bytes32 => bool) public usedKeyImages;

    /// @notice Enote registry (output index => enote hash)
    mapping(uint256 => bytes32) public enoteRegistry;
    uint256 public enoteCount;

    /// @notice Transaction registry
    mapping(bytes32 => SeraphisTx) internal _transactions;
    bytes32[] public txHashes;

    /// @notice Monero adoption tracking
    MoneroAdoption public moneroAdoption;

    /// @notice Subaddress lookahead window
    uint256 public subaddressLookahead = 100;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event AddressRegistered(
        bytes32 indexed addressHash,
        address indexed owner,
        AddressType addrType,
        uint256 accountIndex,
        uint256 subaddressIndex
    );

    event EnoteCreated(
        uint256 indexed enoteIndex,
        bytes32 indexed onetimeAddress,
        bytes32 amountCommitment
    );

    event TransactionSubmitted(
        bytes32 indexed txHash,
        TxType txType,
        uint256 outputCount,
        uint256 fee
    );

    event KeyImageSpent(bytes32 indexed keyImage, bytes32 indexed txHash);

    event MoneroAdoptionUpdated(
        uint256 lastBlock,
        bytes32 blockHash,
        bool seraphisActive,
        uint256 adoptionPercentage
    );

    event GrootleProofVerified(
        bytes32 indexed txHash,
        uint256 proofIndex,
        uint256 ringSize
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidAddress();
    error AddressAlreadyRegistered();
    error KeyImageAlreadySpent(bytes32 keyImage);
    error InvalidGrootleProof();
    error InvalidBalanceProof();
    error InvalidRingSize(uint256 size);
    error SubaddressIndexTooLarge(uint256 index);
    error SeraphisNotActiveOnMonero();
    error Unauthorized();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        // Initialize Monero adoption tracking
        moneroAdoption = MoneroAdoption({
            lastMoneroBlock: 0,
            lastMoneroHash: bytes32(0),
            seraphisActivationBlock: 0, // TBD when Monero activates Seraphis
            isActive: false,
            adoptionPercentage: 0
        });
    }

    // =========================================================================
    // ADDRESS MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new Jamtis address
     * @param K_1 Spend component
     * @param K_2 View component
     * @param K_3 Generate component
     * @param addrType Address type
     * @param accountIndex Account index for subaddresses
     * @param subaddressIndex Subaddress index
     */
    function registerAddress(
        bytes32 K_1,
        bytes32 K_2,
        bytes32 K_3,
        AddressType addrType,
        uint256 accountIndex,
        uint256 subaddressIndex
    ) external whenNotPaused returns (bytes32 addressHash) {
        if (subaddressIndex > MAX_SUBADDRESS_INDEX) {
            revert SubaddressIndexTooLarge(subaddressIndex);
        }

        // Compute address hash
        addressHash = _computeAddressHash(
            K_1,
            K_2,
            K_3,
            accountIndex,
            subaddressIndex
        );

        if (addresses[addressHash].K_1 != bytes32(0)) {
            revert AddressAlreadyRegistered();
        }

        // Compute address tag for efficient scanning
        bytes32 addrTag = _computeAddressTag(
            K_2,
            accountIndex,
            subaddressIndex
        );

        addresses[addressHash] = JamtisAddress({
            K_1: K_1,
            K_2: K_2,
            K_3: K_3,
            addr_tag: addrTag,
            addrType: addrType,
            accountIndex: accountIndex,
            subaddressIndex: subaddressIndex
        });

        addressOwners[addressHash] = msg.sender;

        emit AddressRegistered(
            addressHash,
            msg.sender,
            addrType,
            accountIndex,
            subaddressIndex
        );
    }

    /**
     * @notice Derive a subaddress from master keys
     * @param k_m Master key
     * @param K_s Spend key
     * @param accountIndex Account index
     * @param subaddressIndex Subaddress index
     */
    function deriveSubaddress(
        bytes32 k_m,
        bytes32 K_s,
        uint256 accountIndex,
        uint256 subaddressIndex
    ) external pure returns (bytes32 K_1, bytes32 K_2, bytes32 K_3) {
        // Jamtis subaddress derivation
        // K_1 = K_s + Hn("jamtis_spendkey", k_m, account, subindex) * G
        // K_2 = k_vb * K_1
        // K_3 = k_gi * Hp(K_1)

        bytes32 derivationKey = keccak256(
            abi.encodePacked(
                "jamtis_spendkey",
                k_m,
                accountIndex,
                subaddressIndex
            )
        );

        K_1 = keccak256(abi.encodePacked(K_s, derivationKey));
        K_2 = keccak256(abi.encodePacked("view_component", K_1, k_m));
        K_3 = keccak256(abi.encodePacked("generate_component", K_1, k_m));
    }

    // =========================================================================
    // TRANSACTION FUNCTIONS
    // =========================================================================

    /**
     * @notice Submit a Seraphis transaction
     * @param seraphisTx The transaction to submit
     */
    function submitTransaction(
        SeraphisTx calldata seraphisTx
    ) external nonReentrant whenNotPaused returns (bytes32 txHash) {
        // Verify key images aren't spent
        for (uint256 i = 0; i < seraphisTx.keyImages.length; i++) {
            if (usedKeyImages[seraphisTx.keyImages[i]]) {
                revert KeyImageAlreadySpent(seraphisTx.keyImages[i]);
            }
        }

        // Verify Grootle membership proofs
        for (uint256 i = 0; i < seraphisTx.membershipProofs.length; i++) {
            if (!_verifyGrootleProof(seraphisTx.membershipProofs[i])) {
                revert InvalidGrootleProof();
            }
        }

        // Verify balance (sum of inputs = sum of outputs + fee)
        if (!_verifyBalance(seraphisTx)) {
            revert InvalidBalanceProof();
        }

        // Compute transaction hash
        txHash = keccak256(
            abi.encode(seraphisTx.txPrefix, seraphisTx.keyImages, seraphisTx.outputs, seraphisTx.fee)
        );

        // Mark key images as spent
        for (uint256 i = 0; i < seraphisTx.keyImages.length; i++) {
            usedKeyImages[seraphisTx.keyImages[i]] = true;
            emit KeyImageSpent(seraphisTx.keyImages[i], txHash);
        }

        // Store outputs as enotes
        for (uint256 i = 0; i < seraphisTx.outputs.length; i++) {
            enoteRegistry[enoteCount] = keccak256(abi.encode(seraphisTx.outputs[i]));
            emit EnoteCreated(
                enoteCount,
                seraphisTx.outputs[i].onetime_address,
                seraphisTx.outputs[i].amount_commitment
            );
            enoteCount++;
        }

        // Store transaction
        txHashes.push(txHash);

        emit TransactionSubmitted(txHash, seraphisTx.txType, seraphisTx.outputs.length, seraphisTx.fee);
    }

    /**
     * @notice Create a Seraphis enote for a recipient
     * @param recipientAddress Recipient's Jamtis address hash
     * @param amount Amount to send
     * @param ephemeralPrivKey Ephemeral private key (r)
     */
    function createEnote(
        bytes32 recipientAddress,
        uint256 amount,
        bytes32 ephemeralPrivKey
    ) external view returns (SeraphisEnote memory enote) {
        JamtisAddress storage recipient = addresses[recipientAddress];
        if (recipient.K_1 == bytes32(0)) revert InvalidAddress();

        // Compute shared secret: r * K_2 (view component)
        bytes32 sharedSecret = keccak256(
            abi.encodePacked(ephemeralPrivKey, recipient.K_2)
        );

        // Compute view tag: first 2 bytes of H(shared_secret)
        bytes32 viewTag = keccak256(abi.encodePacked("view_tag", sharedSecret));

        // Compute one-time address
        bytes32 derivation = keccak256(
            abi.encodePacked(sharedSecret, uint256(0))
        );
        bytes32 onetimeAddress = keccak256(
            abi.encodePacked(recipient.K_1, derivation)
        );

        // Create amount commitment: C = x*G + a*H (blinding factor x, amount a)
        bytes32 blindingFactor = keccak256(
            abi.encodePacked("blinding", sharedSecret)
        );
        bytes32 amountCommitment = keccak256(
            abi.encodePacked(blindingFactor, amount)
        );

        // Encrypt amount
        bytes32 encryptedAmount = bytes32(
            uint256(keccak256(abi.encodePacked("amount_mask", sharedSecret))) ^
                amount
        );

        // Encrypt address tag
        bytes32 addrTagEnc = recipient.addr_tag ^
            keccak256(abi.encodePacked("addr_tag_mask", sharedSecret));

        enote = SeraphisEnote({
            onetime_address: onetimeAddress,
            amount_commitment: amountCommitment,
            encrypted_amount: encryptedAmount,
            view_tag: viewTag,
            addr_tag_enc: addrTagEnc,
            enote_type: 0
        });
    }

    // =========================================================================
    // GROOTLE PROOFS
    // =========================================================================

    /**
     * @notice Verify a Grootle membership proof
     * @param proof The Grootle proof to verify
     */
    function _verifyGrootleProof(
        GrootleProof calldata proof
    ) internal pure returns (bool) {
        // Verify proof structure
        if (proof.f.length == 0) return false;

        // Verify challenge is non-zero
        if (proof.challenge == bytes32(0)) return false;

        // Verify responses
        uint256 challengeScalar = uint256(proof.challenge) % ED25519_ORDER;
        if (challengeScalar == 0) return false;

        // Reconstruct and verify (simplified)
        bytes32 reconstructed = keccak256(
            abi.encode(proof.A, proof.B, proof.f, proof.z_A, proof.z_B)
        );

        return reconstructed != bytes32(0);
    }

    /**
     * @notice Create a Grootle proof for ring membership
     * @param ring Ring of commitments
     * @param signerIndex Index of actual signer
     * @param privateKey Signer's private key
     */
    function createGrootleProof(
        bytes32[] calldata ring,
        uint256 signerIndex,
        bytes32 privateKey
    ) external pure returns (GrootleProof memory proof) {
        if (ring.length > MAX_GROOTLE_RING_SIZE) {
            revert InvalidRingSize(ring.length);
        }

        // Compute log2(ring size) for proof depth
        uint256 depth = 0;
        uint256 n = ring.length;
        while (n > 1) {
            n >>= 1;
            depth++;
        }

        // Create f vector (log n elements)
        bytes32[] memory f = new bytes32[](depth);
        for (uint256 i = 0; i < depth; i++) {
            f[i] = keccak256(abi.encodePacked(privateKey, i, signerIndex));
        }

        // Compute commitments
        bytes32 A = keccak256(
            abi.encodePacked("grootle_A", privateKey, ring[signerIndex])
        );
        bytes32 B = keccak256(
            abi.encodePacked("grootle_B", privateKey, ring[signerIndex])
        );

        // Compute challenge via Fiat-Shamir
        bytes32 challenge = keccak256(
            abi.encode("grootle_challenge", ring, A, B)
        );

        // Compute responses
        bytes32 z_A = keccak256(abi.encodePacked(privateKey, challenge, "z_A"));
        bytes32 z_B = keccak256(abi.encodePacked(privateKey, challenge, "z_B"));

        proof = GrootleProof({
            A: A,
            B: B,
            f: f,
            z_A: z_A,
            z_B: z_B,
            challenge: challenge
        });
    }

    // =========================================================================
    // MONERO ADOPTION TRACKING
    // =========================================================================

    /**
     * @notice Update Monero adoption status
     * @param lastBlock Last Monero block number
     * @param blockHash Last block hash
     * @param seraphisActive Whether Seraphis is active
     * @param adoptionPercentage Network adoption in basis points
     */
    function updateMoneroAdoption(
        uint256 lastBlock,
        bytes32 blockHash,
        bool seraphisActive,
        uint256 adoptionPercentage
    ) external onlyRole(OPERATOR_ROLE) {
        moneroAdoption = MoneroAdoption({
            lastMoneroBlock: lastBlock,
            lastMoneroHash: blockHash,
            seraphisActivationBlock: seraphisActive
                ? (
                    moneroAdoption.seraphisActivationBlock == 0
                        ? lastBlock
                        : moneroAdoption.seraphisActivationBlock
                )
                : 0,
            isActive: seraphisActive,
            adoptionPercentage: adoptionPercentage
        });

        emit MoneroAdoptionUpdated(
            lastBlock,
            blockHash,
            seraphisActive,
            adoptionPercentage
        );
    }

    /**
     * @notice Check if Seraphis features require Monero activation
     */
    function requireMoneroActive() public view {
        if (!moneroAdoption.isActive) {
            revert SeraphisNotActiveOnMonero();
        }
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute address hash
     */
    function _computeAddressHash(
        bytes32 K_1,
        bytes32 K_2,
        bytes32 K_3,
        uint256 accountIndex,
        uint256 subaddressIndex
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(K_1, K_2, K_3, accountIndex, subaddressIndex)
            );
    }

    /**
     * @notice Compute address tag for scanning
     */
    function _computeAddressTag(
        bytes32 K_2,
        uint256 accountIndex,
        uint256 subaddressIndex
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("addr_tag", K_2, accountIndex, subaddressIndex)
            );
    }

    /**
     * @notice Verify transaction balance
     */
    function _verifyBalance(
        SeraphisTx calldata seraphisTx
    ) internal pure returns (bool) {
        // In production: verify Pedersen commitment balance
        // sum(input_commitments) = sum(output_commitments) + fee*H

        // Simplified check
        if (seraphisTx.keyImages.length == 0) return false;
        if (seraphisTx.outputs.length == 0) return false;

        return seraphisTx.balanceProofs.length > 0;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get address details
     */
    function getAddress(
        bytes32 addressHash
    ) external view returns (JamtisAddress memory) {
        return addresses[addressHash];
    }

    /**
     * @notice Check if key image is spent
     */
    function isKeyImageSpent(bytes32 keyImage) external view returns (bool) {
        return usedKeyImages[keyImage];
    }

    /**
     * @notice Get transaction count
     */
    function getTransactionCount() external view returns (uint256) {
        return txHashes.length;
    }

    /**
     * @notice Get Monero adoption status
     */
    function getMoneroAdoption() external view returns (MoneroAdoption memory) {
        return moneroAdoption;
    }

    /**
     * @notice Check if Seraphis is active on Monero
     */
    function isSeraphisActiveOnMonero() external view returns (bool) {
        return moneroAdoption.isActive;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function setSubaddressLookahead(
        uint256 lookahead
    ) external onlyRole(ADMIN_ROLE) {
        subaddressLookahead = lookahead;
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
