// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPrivacyPrimitives
/// @notice Interface for all privacy primitive contracts
/// @dev Unified interface for cross-chain privacy operations
interface IPrivacyPrimitives {
    // =========================================================================
    // COMMITMENT OPERATIONS
    // =========================================================================

    /// @notice Compute a Pedersen commitment
    /// @param value The value to commit
    /// @param blinding The blinding factor
    /// @return commitment The commitment C = value*H + blinding*G
    function computeCommitment(
        uint256 value,
        bytes32 blinding
    ) external pure returns (bytes32 commitment);

    /// @notice Verify a commitment opening
    /// @param commitment The commitment to verify
    /// @param value The claimed value
    /// @param blinding The blinding factor
    /// @return valid True if commitment opens correctly
    function verifyCommitmentOpening(
        bytes32 commitment,
        uint256 value,
        bytes32 blinding
    ) external pure returns (bool valid);

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /// @notice Compute a nullifier from secret and commitment
    /// @param secret The secret value
    /// @param commitment The commitment being nullified
    /// @return nullifier The computed nullifier
    function computeNullifier(
        bytes32 secret,
        bytes32 commitment
    ) external pure returns (bytes32 nullifier);

    /// @notice Check if a nullifier has been used
    /// @param nullifier The nullifier to check
    /// @return used True if nullifier was already used
    function isNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool used);

    /// @notice Mark a nullifier as used
    /// @param nullifier The nullifier to mark
    function useNullifier(bytes32 nullifier) external;

    // =========================================================================
    // KEY IMAGE OPERATIONS
    // =========================================================================

    /// @notice Compute a key image for ring signatures
    /// @param secretKey The secret key
    /// @param publicKey The corresponding public key
    /// @return keyImage The computed key image
    function computeKeyImage(
        bytes32 secretKey,
        bytes32 publicKey
    ) external pure returns (bytes32 keyImage);

    /// @notice Check if a key image has been used
    /// @param keyImage The key image to check
    /// @return used True if key image was already used
    function isKeyImageUsed(bytes32 keyImage) external view returns (bool used);

    // =========================================================================
    // STEALTH ADDRESS OPERATIONS
    // =========================================================================

    /// @notice Derive a stealth address
    /// @param recipientSpendKey Recipient's spend public key
    /// @param recipientViewKey Recipient's view public key
    /// @param ephemeralKey Sender's ephemeral private key
    /// @return stealthAddress The derived stealth address
    /// @return ephemeralPubKey The ephemeral public key to share
    function deriveStealthAddress(
        bytes32 recipientSpendKey,
        bytes32 recipientViewKey,
        bytes32 ephemeralKey
    ) external pure returns (bytes32 stealthAddress, bytes32 ephemeralPubKey);

    /// @notice Compute view tag for efficient scanning
    /// @param sharedSecret The ECDH shared secret
    /// @return viewTag The 8-bit view tag
    function computeViewTag(
        bytes32 sharedSecret
    ) external pure returns (uint8 viewTag);

    // =========================================================================
    // MERKLE OPERATIONS
    // =========================================================================

    /// @notice Verify a Merkle proof
    /// @param root The Merkle root
    /// @param leaf The leaf to verify
    /// @param proof The Merkle proof (siblings)
    /// @param index The leaf index
    /// @return valid True if proof is valid
    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) external pure returns (bool valid);

    /// @notice Get the current Merkle root
    /// @return root The current root
    function getMerkleRoot() external view returns (bytes32 root);

    /// @notice Insert a leaf into the Merkle tree
    /// @param leaf The leaf to insert
    /// @return index The index of the inserted leaf
    function insertLeaf(bytes32 leaf) external returns (uint256 index);
}

/// @title IRingSignature
/// @notice Interface for ring signature verification
interface IRingSignature {
    /// @notice Ring member structure
    struct RingMember {
        bytes32 publicKey;
        bytes32 commitment; // Optional for RingCT
    }

    /// @notice Verify a ring signature
    /// @param message The signed message
    /// @param ring The ring of public keys
    /// @param keyImage The key image
    /// @param signature The signature data
    /// @return valid True if signature is valid
    function verifyRingSignature(
        bytes32 message,
        RingMember[] calldata ring,
        bytes32 keyImage,
        bytes calldata signature
    ) external view returns (bool valid);

    /// @notice Get minimum ring size
    function getMinRingSize() external view returns (uint256);

    /// @notice Get maximum ring size
    function getMaxRingSize() external view returns (uint256);
}

/// @title IZKVerifier
/// @notice Interface for ZK proof verification
interface IZKVerifier {
    /// @notice Verify a ZK proof
    /// @param proof The proof data
    /// @param publicInputs The public inputs
    /// @return valid True if proof is valid
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool valid);

    /// @notice Get the verification key hash
    function getVerificationKeyHash() external view returns (bytes32);
}

/// @title IFHEOperations
/// @notice Interface for FHE operations
interface IFHEOperations {
    /// @notice Ciphertext types
    enum CiphertextType {
        EUINT8,
        EUINT16,
        EUINT32,
        EUINT64,
        EUINT256,
        EBOOL,
        EADDRESS
    }

    /// @notice Store an encrypted value
    /// @param ciphertext The encrypted data
    /// @param ctype The ciphertext type
    /// @return handle The ciphertext handle
    function storeCiphertext(
        bytes calldata ciphertext,
        CiphertextType ctype
    ) external returns (bytes32 handle);

    /// @notice Request homomorphic addition
    /// @param a First operand handle
    /// @param b Second operand handle
    /// @return requestId The computation request ID
    function requestAdd(
        bytes32 a,
        bytes32 b
    ) external returns (bytes32 requestId);

    /// @notice Request homomorphic comparison
    /// @param a First operand handle
    /// @param b Second operand handle
    /// @return requestId The computation request ID
    function requestLessThan(
        bytes32 a,
        bytes32 b
    ) external returns (bytes32 requestId);

    /// @notice Request decryption
    /// @param handle The ciphertext handle
    /// @return requestId The decryption request ID
    function requestDecryption(
        bytes32 handle
    ) external returns (bytes32 requestId);
}

/// @title ICrossChainPrivacy
/// @notice Interface for cross-chain privacy operations
interface ICrossChainPrivacy {
    /// @notice Derive a cross-domain nullifier
    /// @param localNullifier The local chain nullifier
    /// @param targetDomain The target domain ID
    /// @return crossDomainNullifier The cross-domain nullifier
    function deriveCrossDomainNullifier(
        bytes32 localNullifier,
        uint256 targetDomain
    ) external pure returns (bytes32 crossDomainNullifier);

    /// @notice Verify a cross-chain privacy proof
    /// @param proof The proof data
    /// @param sourceChain Source chain ID
    /// @param targetChain Target chain ID
    /// @param publicInputs Public inputs
    /// @return valid True if proof is valid
    function verifyCrossChainProof(
        bytes calldata proof,
        uint256 sourceChain,
        uint256 targetChain,
        bytes32[] calldata publicInputs
    ) external view returns (bool valid);

    /// @notice Get supported domains
    function getSupportedDomains() external view returns (uint256[] memory);
}

/// @title IPrivateRelayer
/// @notice Interface for privacy-preserving relayer operations
interface IPrivateRelayer {
    /// @notice Submit a private transaction through relayer
    /// @param encryptedTx The encrypted transaction data
    /// @param proof Privacy proof
    /// @param fee Relayer fee
    /// @return success True if submission successful
    function submitPrivateTransaction(
        bytes calldata encryptedTx,
        bytes calldata proof,
        uint256 fee
    ) external returns (bool success);

    /// @notice Request private relayer selection
    /// @param commitmentHash Selection commitment hash
    /// @param numRelayers Number of relayers to select
    /// @return requestId Selection request ID
    function requestRelayerSelection(
        bytes32 commitmentHash,
        uint256 numRelayers
    ) external returns (bytes32 requestId);

    /// @notice Get selected relayers
    /// @param requestId The selection request ID
    /// @return relayers Array of selected relayer addresses
    function getSelectedRelayers(
        bytes32 requestId
    ) external view returns (address[] memory relayers);
}
