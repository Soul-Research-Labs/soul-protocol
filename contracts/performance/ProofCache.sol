// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProofCache
 * @notice Caching layer for verified proofs to avoid redundant verification
 * @dev Stores proof verification results with expiration
 */
contract ProofCache {
    // Cache entry structure
    struct CacheEntry {
        bool verified;
        uint256 timestamp;
        uint256 expiresAt;
        bytes32 verifierHash;
    }

    // Proof hash => Cache entry
    mapping(bytes32 => CacheEntry) public cache;

    // Default cache duration (1 hour)
    uint256 public constant DEFAULT_CACHE_DURATION = 1 hours;

    // Maximum cache duration (24 hours)
    uint256 public constant MAX_CACHE_DURATION = 24 hours;

    // Events
    event ProofCached(
        bytes32 indexed proofHash,
        bool verified,
        uint256 expiresAt
    );
    event CacheHit(bytes32 indexed proofHash);
    event CacheExpired(bytes32 indexed proofHash);

    /**
     * @notice Check if a proof is in the cache and still valid
     * @param proofHash Hash of the proof
     * @return hit Whether the cache contains a valid entry
     * @return verified The verification result if hit
     */
    function checkCache(
        bytes32 proofHash
    ) external view returns (bool hit, bool verified) {
        CacheEntry storage entry = cache[proofHash];

        if (entry.timestamp == 0) {
            return (false, false);
        }

        if (block.timestamp > entry.expiresAt) {
            return (false, false);
        }

        return (true, entry.verified);
    }

    /**
     * @notice Store a proof verification result in the cache
     * @param proofHash Hash of the proof
     * @param verified Whether the proof was valid
     * @param duration How long to cache (capped at MAX_CACHE_DURATION)
     */
    function cacheProof(
        bytes32 proofHash,
        bool verified,
        uint256 duration
    ) external {
        uint256 cacheDuration = duration > MAX_CACHE_DURATION
            ? MAX_CACHE_DURATION
            : duration;
        if (cacheDuration == 0) cacheDuration = DEFAULT_CACHE_DURATION;

        uint256 expiresAt = block.timestamp + cacheDuration;

        cache[proofHash] = CacheEntry({
            verified: verified,
            timestamp: block.timestamp,
            expiresAt: expiresAt,
            verifierHash: bytes32(0)
        });

        emit ProofCached(proofHash, verified, expiresAt);
    }

    /**
     * @notice Get proof hash from proof data
     * @param proof The proof bytes
     * @param publicInputs The public inputs
     * @return The keccak256 hash
     */
    function getProofHash(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(proof, publicInputs));
    }

    /**
     * @notice Invalidate a cache entry
     * @param proofHash Hash of the proof to invalidate
     */
    function invalidateCache(bytes32 proofHash) external {
        delete cache[proofHash];
        emit CacheExpired(proofHash);
    }

    /**
     * @notice Check if cache entry exists (even if expired)
     * @param proofHash Hash of the proof
     * @return Whether an entry exists
     */
    function hasEntry(bytes32 proofHash) external view returns (bool) {
        return cache[proofHash].timestamp > 0;
    }

    /**
     * @notice Get cache entry details
     * @param proofHash Hash of the proof
     * @return entry The cache entry
     */
    function getEntry(
        bytes32 proofHash
    ) external view returns (CacheEntry memory entry) {
        return cache[proofHash];
    }
}
