// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPrivacyIntegration
 * @notice Interface for integrating privacy primitives across Soul
 * @dev Unified interface for stealth addresses, ring signatures, and nullifiers
 */
interface IPrivacyIntegration {
    // =========================================================================
    // STEALTH ADDRESS TYPES
    // =========================================================================

    struct StealthMetaAddress {
        bytes32 spendPubKey;
        bytes32 viewPubKey;
    }

    struct StealthAddress {
        bytes32 stealthPubKey;
        bytes32 ephemeralPubKey;
        uint8 viewTag;
    }

    // =========================================================================
    // RING SIGNATURE TYPES
    // =========================================================================

    struct RingMember {
        bytes32 publicKeyX;
        bytes32 publicKeyY;
    }

    struct KeyImage {
        bytes32 x;
        bytes32 y;
    }

    struct RingSignature {
        bytes32 c0; // Initial challenge
        bytes32[] s; // Response scalars
        KeyImage keyImage;
    }

    // =========================================================================
    // COMMITMENT TYPES
    // =========================================================================

    struct PedersenCommitment {
        bytes32 x;
        bytes32 y;
    }

    struct RangeProof {
        bytes proof;
        uint64 minValue;
        uint64 maxValue;
    }

    // =========================================================================
    // NULLIFIER TYPES
    // =========================================================================

    struct Nullifier {
        bytes32 nullifierHash;
        uint256 chainId;
        bytes32 domainSeparator;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event StealthMetaAddressRegistered(
        address indexed account,
        bytes32 spendPubKey,
        bytes32 viewPubKey
    );

    event StealthTransferInitiated(
        bytes32 indexed stealthAddress,
        bytes32 ephemeralPubKey,
        uint8 viewTag
    );

    event RingSignatureVerified(bytes32 indexed keyImage, uint256 ringSize);

    event CommitmentRegistered(
        bytes32 indexed commitmentHash,
        bytes32 x,
        bytes32 y
    );

    event NullifierUsed(bytes32 indexed nullifierHash, uint256 chainId);

    // =========================================================================
    // STEALTH ADDRESS FUNCTIONS
    // =========================================================================

    /**
     * @notice Register a stealth meta-address for receiving private transfers
     * @param metaAddress The meta-address containing spend and view public keys
     */
    function registerStealthMetaAddress(
        StealthMetaAddress calldata metaAddress
    ) external;

    /**
     * @notice Derive a stealth address for a recipient
     * @param recipient The recipient's meta-address
     * @param ephemeralPrivateKey Sender's ephemeral private key (should be random)
     * @return stealthAddress The derived one-time address
     */
    function deriveStealthAddress(
        StealthMetaAddress calldata recipient,
        uint256 ephemeralPrivateKey
    ) external view returns (StealthAddress memory stealthAddress);

    /**
     * @notice Check if a stealth address belongs to an account
     * @param stealthAddress The stealth address to check
     * @param viewPrivateKey The view private key for scanning
     * @return isOwner True if the account owns this stealth address
     */
    function checkStealthAddressOwnership(
        StealthAddress calldata stealthAddress,
        uint256 viewPrivateKey
    ) external view returns (bool isOwner);

    // =========================================================================
    // RING SIGNATURE FUNCTIONS
    // =========================================================================

    /**
     * @notice Verify a ring signature
     * @param message The signed message hash
     * @param ring Array of public keys in the ring
     * @param signature The ring signature to verify
     * @return valid True if signature is valid
     */
    function verifyRingSignature(
        bytes32 message,
        RingMember[] calldata ring,
        RingSignature calldata signature
    ) external view returns (bool valid);

    /**
     * @notice Check if a key image has been used (for double-spend prevention)
     * @param keyImage The key image to check
     * @return used True if already used
     */
    function isKeyImageUsed(
        KeyImage calldata keyImage
    ) external view returns (bool used);

    /**
     * @notice Register a key image as used
     * @param keyImage The key image to register
     */
    function registerKeyImage(KeyImage calldata keyImage) external;

    // =========================================================================
    // COMMITMENT FUNCTIONS
    // =========================================================================

    /**
     * @notice Create a Pedersen commitment
     * @param value The value to commit to
     * @param blinding The blinding factor
     * @return commitment The resulting commitment point
     */
    function createCommitment(
        uint256 value,
        uint256 blinding
    ) external view returns (PedersenCommitment memory commitment);

    /**
     * @notice Verify a commitment opening
     * @param commitment The commitment to verify
     * @param value The claimed value
     * @param blinding The claimed blinding factor
     * @return valid True if opening is valid
     */
    function verifyCommitment(
        PedersenCommitment calldata commitment,
        uint256 value,
        uint256 blinding
    ) external view returns (bool valid);

    /**
     * @notice Verify a range proof for a commitment
     * @param commitment The commitment
     * @param proof The range proof
     * @return valid True if proof is valid
     */
    function verifyRangeProof(
        PedersenCommitment calldata commitment,
        RangeProof calldata proof
    ) external view returns (bool valid);

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute a cross-domain nullifier
     * @param secret The user's secret
     * @param commitment The commitment being nullified
     * @param chainId The chain ID for domain separation
     * @return nullifier The computed nullifier
     */
    function computeNullifier(
        uint256 secret,
        bytes32 commitment,
        uint256 chainId
    ) external view returns (Nullifier memory nullifier);

    /**
     * @notice Check if a nullifier has been used
     * @param nullifier The nullifier to check
     * @return used True if already used
     */
    function isNullifierUsed(
        Nullifier calldata nullifier
    ) external view returns (bool used);

    /**
     * @notice Register a nullifier as used
     * @param nullifier The nullifier to register
     */
    function registerNullifier(Nullifier calldata nullifier) external;

    /**
     * @notice Verify a cross-chain nullifier proof
     * @param nullifier The nullifier
     * @param proof ZK proof of valid nullifier derivation
     * @return valid True if proof is valid
     */
    function verifyNullifierProof(
        Nullifier calldata nullifier,
        bytes calldata proof
    ) external view returns (bool valid);
}

/**
 * @title IPrivacyOracle
 * @notice Oracle interface for privacy-preserving data feeds
 */
interface IPrivacyOracle {
    /**
     * @notice Get encrypted price data
     * @param pairId The trading pair identifier
     * @param recipientPubKey Recipient's public key for encryption
     * @return encryptedPrice Encrypted price data
     */
    function getEncryptedPrice(
        bytes32 pairId,
        bytes32 recipientPubKey
    ) external view returns (bytes memory encryptedPrice);

    /**
     * @notice Verify a price proof without revealing the price
     * @param pairId The trading pair
     * @param commitment Commitment to the price
     * @param proof ZK proof of price validity
     * @return valid True if proof is valid
     */
    function verifyPriceProof(
        bytes32 pairId,
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool valid);
}

/**
 * @title IPrivacyPool
 * @notice Interface for privacy-preserving liquidity pools
 */
interface IPrivacyPool {
    /**
     * @notice Deposit with hidden amount
     * @param commitment Commitment to the deposit amount
     * @param rangeProof Proof that amount is in valid range
     * @param nullifier Nullifier for the deposit
     */
    function privateDeposit(
        bytes32 commitment,
        bytes calldata rangeProof,
        bytes32 nullifier
    ) external payable;

    /**
     * @notice Withdraw with ZK proof
     * @param proof ZK proof of valid withdrawal
     * @param nullifierHash Nullifier to prevent double-spend
     * @param recipient Stealth address of recipient
     */
    function privateWithdraw(
        bytes calldata proof,
        bytes32 nullifierHash,
        bytes32 recipient
    ) external;

    /**
     * @notice Private swap between two tokens
     * @param inputCommitment Commitment to input amount
     * @param outputCommitment Expected output commitment
     * @param proof ZK proof of valid swap
     * @param inputNullifier Nullifier for input
     */
    function privateSwap(
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes calldata proof,
        bytes32 inputNullifier
    ) external;
}

/**
 * @title IPrivateBridge
 * @notice Interface for cross-chain private transfers
 */
interface IPrivateBridge {
    struct PrivateBridgeMessage {
        bytes32 commitment;
        bytes32 nullifierHash;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 destRecipient; // Stealth address
        bytes proof;
    }

    /**
     * @notice Initiate a private cross-chain transfer
     * @param message The bridge message with privacy proofs
     */
    function initiatePrivateTransfer(
        PrivateBridgeMessage calldata message
    ) external payable;

    /**
     * @notice Complete a private cross-chain transfer
     * @param message The bridge message
     * @param crossChainProof Proof from source chain
     */
    function completePrivateTransfer(
        PrivateBridgeMessage calldata message,
        bytes calldata crossChainProof
    ) external;

    /**
     * @notice Verify cross-chain nullifier hasn't been used on dest chain
     * @param nullifierHash The nullifier to check
     * @param sourceChain The source chain ID
     */
    function verifyCrossChainNullifier(
        bytes32 nullifierHash,
        uint256 sourceChain
    ) external view returns (bool unused);
}
