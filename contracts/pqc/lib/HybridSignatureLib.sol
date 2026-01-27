// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title HybridSignatureLib
 * @author Soul Protocol
 * @notice Library for hybrid classical/post-quantum signature operations
 * @dev Provides utilities for creating, encoding, and verifying hybrid signatures
 *      that combine ECDSA with post-quantum algorithms for defense-in-depth.
 */

library HybridSignatureLib {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Magic bytes for hybrid signature identification
    bytes4 public constant HYBRID_SIG_MAGIC = 0x50514331; // "PQC1"

    /// @notice Version byte
    uint8 public constant VERSION = 1;

    /// @notice ECDSA signature size
    uint256 public constant ECDSA_SIG_SIZE = 65;

    /// @notice Algorithm identifiers
    uint8 public constant ALG_DILITHIUM3 = 1;
    uint8 public constant ALG_DILITHIUM5 = 2;
    uint8 public constant ALG_SPHINCS_128S = 3;
    uint8 public constant ALG_SPHINCS_256S = 4;

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice Hybrid signature structure
     */
    struct HybridSig {
        bytes4 magic; // Magic bytes for identification
        uint8 version; // Format version
        uint8 algorithm; // PQ algorithm identifier
        bytes ecdsaSig; // ECDSA signature (65 bytes)
        bytes pqSig; // Post-quantum signature
        bytes pqPubKey; // Post-quantum public key
    }

    /**
     * @notice Compact hybrid signature (without public key)
     */
    struct CompactHybridSig {
        bytes4 magic;
        uint8 version;
        uint8 algorithm;
        bytes32 ecdsaR;
        bytes32 ecdsaS;
        uint8 ecdsaV;
        bytes pqSig;
        bytes32 pqPubKeyHash; // Hash of public key (lookup separately)
    }

    // =============================================================================
    // ENCODING FUNCTIONS
    // =============================================================================

    /**
     * @notice Encode a hybrid signature to bytes
     * @param sig The hybrid signature struct
     * @return encoded The encoded signature bytes
     */
    function encode(
        HybridSig memory sig
    ) internal pure returns (bytes memory encoded) {
        return
            abi.encodePacked(
                sig.magic,
                sig.version,
                sig.algorithm,
                uint16(sig.ecdsaSig.length),
                sig.ecdsaSig,
                uint16(sig.pqSig.length),
                sig.pqSig,
                uint16(sig.pqPubKey.length),
                sig.pqPubKey
            );
    }

    /**
     * @notice Encode a compact hybrid signature
     */
    function encodeCompact(
        CompactHybridSig memory sig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                sig.magic,
                sig.version,
                sig.algorithm,
                sig.ecdsaR,
                sig.ecdsaS,
                sig.ecdsaV,
                sig.pqPubKeyHash,
                uint16(sig.pqSig.length),
                sig.pqSig
            );
    }

    /**
     * @notice Decode a hybrid signature from bytes
     * @param encoded The encoded signature
     * @return sig The decoded signature struct
     */
    function decode(
        bytes calldata encoded
    ) internal pure returns (HybridSig memory sig) {
        require(encoded.length >= 10, "HybridSig: too short");

        sig.magic = bytes4(encoded[0:4]);
        require(sig.magic == HYBRID_SIG_MAGIC, "HybridSig: invalid magic");

        sig.version = uint8(encoded[4]);
        require(sig.version == VERSION, "HybridSig: unsupported version");

        sig.algorithm = uint8(encoded[5]);

        uint256 offset = 6;

        // ECDSA signature
        uint16 ecdsaLen = uint16(bytes2(encoded[offset:offset + 2]));
        offset += 2;
        sig.ecdsaSig = encoded[offset:offset + ecdsaLen];
        offset += ecdsaLen;

        // PQ signature
        uint16 pqSigLen = uint16(bytes2(encoded[offset:offset + 2]));
        offset += 2;
        sig.pqSig = encoded[offset:offset + pqSigLen];
        offset += pqSigLen;

        // PQ public key
        uint16 pqKeyLen = uint16(bytes2(encoded[offset:offset + 2]));
        offset += 2;
        sig.pqPubKey = encoded[offset:offset + pqKeyLen];
    }

    /**
     * @notice Decode compact hybrid signature
     */
    function decodeCompact(
        bytes calldata encoded
    ) internal pure returns (CompactHybridSig memory sig) {
        require(encoded.length >= 106, "HybridSig: too short for compact");

        sig.magic = bytes4(encoded[0:4]);
        require(sig.magic == HYBRID_SIG_MAGIC, "HybridSig: invalid magic");

        sig.version = uint8(encoded[4]);
        sig.algorithm = uint8(encoded[5]);
        sig.ecdsaR = bytes32(encoded[6:38]);
        sig.ecdsaS = bytes32(encoded[38:70]);
        sig.ecdsaV = uint8(encoded[70]);
        sig.pqPubKeyHash = bytes32(encoded[71:103]);

        uint16 pqSigLen = uint16(bytes2(encoded[103:105]));
        sig.pqSig = encoded[105:105 + pqSigLen];
    }

    // =============================================================================
    // VERIFICATION HELPERS
    // =============================================================================

    /**
     * @notice Extract ECDSA components from signature
     */
    function extractECDSA(
        bytes memory sig
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "HybridSig: invalid ECDSA length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }
    }

    /**
     * @notice Verify ECDSA component of hybrid signature
     * @param messageHash The message hash
     * @param ecdsaSig The ECDSA signature
     * @param expectedSigner The expected signer address
     * @return valid True if ECDSA signature is valid
     */
    function verifyECDSA(
        bytes32 messageHash,
        bytes memory ecdsaSig,
        address expectedSigner
    ) internal pure returns (bool valid) {
        (bytes32 r, bytes32 s, uint8 v) = extractECDSA(ecdsaSig);

        address recovered = ecrecover(messageHash, v, r, s);
        return recovered == expectedSigner && recovered != address(0);
    }

    /**
     * @notice Verify ECDSA with EIP-191 prefix
     */
    function verifyECDSAWithPrefix(
        bytes32 messageHash,
        bytes memory ecdsaSig,
        address expectedSigner
    ) internal pure returns (bool valid) {
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        return verifyECDSA(prefixedHash, ecdsaSig, expectedSigner);
    }

    // =============================================================================
    // UTILITY FUNCTIONS
    // =============================================================================

    /**
     * @notice Create a new hybrid signature struct
     */
    function create(
        uint8 algorithm,
        bytes memory ecdsaSig,
        bytes memory pqSig,
        bytes memory pqPubKey
    ) internal pure returns (HybridSig memory) {
        return
            HybridSig({
                magic: HYBRID_SIG_MAGIC,
                version: VERSION,
                algorithm: algorithm,
                ecdsaSig: ecdsaSig,
                pqSig: pqSig,
                pqPubKey: pqPubKey
            });
    }

    /**
     * @notice Check if bytes represent a hybrid signature
     */
    function isHybridSignature(
        bytes calldata sig
    ) internal pure returns (bool) {
        if (sig.length < 10) return false;
        return bytes4(sig[0:4]) == HYBRID_SIG_MAGIC;
    }

    /**
     * @notice Get algorithm name
     */
    function algorithmName(
        uint8 algorithm
    ) internal pure returns (string memory) {
        if (algorithm == ALG_DILITHIUM3) return "Dilithium3";
        if (algorithm == ALG_DILITHIUM5) return "Dilithium5";
        if (algorithm == ALG_SPHINCS_128S) return "SPHINCS+-128s";
        if (algorithm == ALG_SPHINCS_256S) return "SPHINCS+-256s";
        return "Unknown";
    }

    /**
     * @notice Estimate signature size for an algorithm
     */
    function estimateSize(uint8 algorithm) internal pure returns (uint256) {
        // Base: magic(4) + version(1) + algorithm(1) + lengths(6) + ecdsa(65)
        uint256 baseSize = 77;

        if (algorithm == ALG_DILITHIUM3) {
            return baseSize + 3293 + 1952; // sig + pubkey
        } else if (algorithm == ALG_DILITHIUM5) {
            return baseSize + 4595 + 2592;
        } else if (algorithm == ALG_SPHINCS_128S) {
            return baseSize + 7856 + 32;
        } else if (algorithm == ALG_SPHINCS_256S) {
            return baseSize + 29792 + 64;
        }
        return baseSize;
    }

    /**
     * @notice Hash a hybrid signature for caching/indexing
     */
    function hash(HybridSig memory sig) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    sig.magic,
                    sig.version,
                    sig.algorithm,
                    keccak256(sig.ecdsaSig),
                    keccak256(sig.pqSig),
                    keccak256(sig.pqPubKey)
                )
            );
    }
}
