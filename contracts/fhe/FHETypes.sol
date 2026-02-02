// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FHETypes
 * @author Soul Protocol
 * @notice Type definitions for FHE operations
 */

/// @notice FHE type constants
library FHETypes {
    uint8 public constant TYPE_EBOOL = 0;
    uint8 public constant TYPE_EUINT8 = 1;
    uint8 public constant TYPE_EUINT16 = 2;
    uint8 public constant TYPE_EUINT32 = 3;
    uint8 public constant TYPE_EUINT64 = 4;
    uint8 public constant TYPE_EUINT128 = 5;
    uint8 public constant TYPE_EUINT256 = 6;
    uint8 public constant TYPE_EADDRESS = 7;
    uint8 public constant TYPE_EBYTES256 = 8;
}

/// @notice Encrypted uint256 type
struct euint256 {
    bytes32 ciphertext;
}

/// @notice Encrypted uint128 type
struct euint128 {
    bytes32 ciphertext;
}

/// @notice Encrypted uint64 type
struct euint64 {
    bytes32 ciphertext;
}

/// @notice Encrypted boolean type
struct ebool {
    bytes32 ciphertext;
}

/// @notice FHE public key
struct FHEPublicKey {
    bytes32 keyHash;
    bytes publicKeyData;
}

/// @notice Re-encryption request
struct ReencryptionRequest {
    bytes32 ciphertext;
    bytes32 targetPublicKey;
    address requester;
    uint256 timestamp;
    bool completed;
}

/// @notice Cross-chain FHE transfer
struct FHETransfer {
    bytes32 encryptedAmount;
    bytes32 senderCommitment;
    bytes32 recipientPublicKey;
    uint256 sourceChainId;
    uint256 destChainId;
    uint64 nonce;
}
