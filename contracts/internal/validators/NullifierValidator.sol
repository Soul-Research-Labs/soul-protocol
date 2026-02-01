// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NullifierValidator
 * @author Soul Protocol
 * @notice Nullifier validation and management utilities
 * @dev Extracted from UnifiedNullifierManager to reduce stack depth
 *      and enable better test coverage.
 *
 * NULLIFIER TYPES:
 * - Standard: Single-domain nullifier
 * - Cross-Domain: Bridging nullifier (CDNA)
 * - Time-Bound: Expiring nullifier
 * - Batch: Aggregate nullifier
 */
library NullifierValidator {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NullifierAlreadySpent(bytes32 nullifier);
    error NullifierExpired(bytes32 nullifier, uint256 expiresAt);
    error InvalidNullifierFormat();
    error DomainMismatch(bytes32 expected, bytes32 actual);

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Nullifier record for storage
     */
    struct NullifierRecord {
        bytes32 commitment;
        uint256 chainId;
        uint256 timestamp;
        uint256 expiresAt;
        bool spent;
    }

    /**
     * @notice Cross-domain nullifier binding
     */
    struct CrossDomainBinding {
        bytes32 sourceNullifier;
        bytes32 destNullifier;
        uint256 sourceChainId;
        uint256 destChainId;
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator for standard nullifiers
    bytes32 public constant STANDARD_DOMAIN =
        keccak256("Soul_NULLIFIER_STANDARD_V1");

    /// @notice Domain separator for cross-domain nullifiers
    bytes32 public constant CROSS_DOMAIN =
        keccak256("Soul_NULLIFIER_CROSS_DOMAIN_V1");

    /// @notice Domain separator for time-bound nullifiers
    bytes32 public constant TIME_BOUND_DOMAIN =
        keccak256("Soul_NULLIFIER_TIME_BOUND_V1");

    /*//////////////////////////////////////////////////////////////
                          COMPUTATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes a standard nullifier
     * @param secret User's secret
     * @param commitment Associated commitment
     * @param chainId Current chain ID
     * @return nullifier The computed nullifier
     */
    function computeStandardNullifier(
        bytes32 secret,
        bytes32 commitment,
        uint256 chainId
    ) internal pure returns (bytes32 nullifier) {
        return
            keccak256(
                abi.encodePacked(STANDARD_DOMAIN, secret, commitment, chainId)
            );
    }

    /**
     * @notice Computes a cross-domain nullifier (CDNA)
     * @dev N_cross = H(N_source || sourceChain || destChain || "CROSS_DOMAIN")
     * @param sourceNullifier Nullifier on source chain
     * @param sourceChainId Source chain ID
     * @param destChainId Destination chain ID
     * @return nullifier The cross-domain nullifier
     */
    function computeCrossDomainNullifier(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId
    ) internal pure returns (bytes32 nullifier) {
        return
            keccak256(
                abi.encodePacked(
                    CROSS_DOMAIN,
                    sourceNullifier,
                    sourceChainId,
                    destChainId
                )
            );
    }

    /**
     * @notice Computes a time-bound nullifier
     * @param secret User's secret
     * @param commitment Associated commitment
     * @param epoch Time epoch
     * @return nullifier The time-bound nullifier
     */
    function computeTimeBoundNullifier(
        bytes32 secret,
        bytes32 commitment,
        uint256 epoch
    ) internal pure returns (bytes32 nullifier) {
        return
            keccak256(
                abi.encodePacked(TIME_BOUND_DOMAIN, secret, commitment, epoch)
            );
    }

    /**
     * @notice Computes a Soul binding nullifier
     * @dev Unified nullifier that binds across all Soul domains
     * @param sourceNullifier Original nullifier
     * @param domainTag Domain-specific tag
     * @return soulBinding The Soul-bound nullifier
     */
    function computeSoulBinding(
        bytes32 sourceNullifier,
        bytes32 domainTag
    ) internal pure returns (bytes32 soulBinding) {
        return
            keccak256(
                abi.encodePacked("Soul_BINDING", sourceNullifier, domainTag)
            );
    }

    /*//////////////////////////////////////////////////////////////
                          VALIDATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates nullifier format
     * @param nullifier The nullifier to validate
     * @return isValid True if format is valid (non-zero)
     */
    function isValidFormat(
        bytes32 nullifier
    ) internal pure returns (bool isValid) {
        return nullifier != bytes32(0);
    }

    /**
     * @notice Checks if nullifier has expired
     * @param record The nullifier record
     * @return expired True if past expiration
     */
    function isExpired(
        NullifierRecord memory record
    ) internal view returns (bool expired) {
        if (record.expiresAt == 0) {
            return false; // Never expires
        }
        return block.timestamp > record.expiresAt;
    }

    /**
     * @notice Validates cross-domain binding
     * @param binding The cross-domain binding
     * @param expectedSource Expected source nullifier
     * @return isValid True if binding is valid
     */
    function validateCrossDomainBinding(
        CrossDomainBinding memory binding,
        bytes32 expectedSource
    ) internal pure returns (bool isValid) {
        if (binding.sourceNullifier != expectedSource) {
            return false;
        }

        // Recompute and verify destination nullifier
        bytes32 expectedDest = computeCrossDomainNullifier(
            binding.sourceNullifier,
            binding.sourceChainId,
            binding.destChainId
        );

        return binding.destNullifier == expectedDest;
    }

    /*//////////////////////////////////////////////////////////////
                            BATCH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Computes batch nullifier root
     * @param nullifiers Array of nullifiers
     * @return root Merkle root of nullifiers
     */
    function computeBatchRoot(
        bytes32[] memory nullifiers
    ) internal pure returns (bytes32 root) {
        if (nullifiers.length == 0) {
            return bytes32(0);
        }
        if (nullifiers.length == 1) {
            return nullifiers[0];
        }

        // Simple hash chain for small batches
        root = nullifiers[0];
        for (uint256 i = 1; i < nullifiers.length; i++) {
            root = keccak256(abi.encodePacked(root, nullifiers[i]));
        }
    }

    /**
     * @notice Validates all nullifiers in batch are unique
     * @param nullifiers Array of nullifiers to check
     * @return allUnique True if no duplicates
     */
    function validateBatchUniqueness(
        bytes32[] memory nullifiers
    ) internal pure returns (bool allUnique) {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            for (uint256 j = i + 1; j < nullifiers.length; j++) {
                if (nullifiers[i] == nullifiers[j]) {
                    return false;
                }
            }
        }
        return true;
    }
}
