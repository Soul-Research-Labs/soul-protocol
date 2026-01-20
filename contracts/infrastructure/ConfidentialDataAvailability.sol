// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ConfidentialDataAvailability
 * @author Soul Protocol
 * @notice Confidential Data Availability (CDA) - Celestia DA evolved for privacy
 * @dev Key innovation: Availability proofs do NOT reveal plaintext
 *
 * CELESTIA DA vs SOUL CDA:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Celestia DA                       │ Soul CDA                               │
 * ├───────────────────────────────────┼─────────────────────────────────────────│
 * │ Data is public                    │ Data is encrypted                      │
 * │ Availability = downloadable       │ Availability = recoverable + private   │
 * │ No access control                 │ Policy-bound access                    │
 * │ No semantic meaning               │ Typed confidential containers          │
 * │ Sampling proves availability      │ ZK proofs prove availability           │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * USE CASES:
 * - Private state recovery after node failure
 * - Auditor access to historical data (policy-bound)
 * - Delayed disclosure (time-locked data)
 * - Cross-chain state migration
 */
contract ConfidentialDataAvailability is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Erasure coding scheme for data shards
     * @dev Different schemes optimize for different recovery/overhead tradeoffs
     */
    enum ErasureScheme {
        None, // No erasure coding (single replica)
        ReedSolomon44, // 4 data shards, 4 parity (2x overhead, 50% recovery)
        ReedSolomon84, // 8 data shards, 4 parity (1.5x overhead, 33% recovery)
        ReedSolomon168, // 16 data shards, 8 parity (1.5x overhead, 33% recovery)
        Fountain // Rateless erasure code (flexible recovery)
    }

    /**
     * @notice Data availability status
     */
    enum AvailabilityStatus {
        Unknown, // Not yet proven
        Available, // Proven available
        Unavailable, // Proven unavailable (challenge succeeded)
        Expired, // Past retention period
        Recovered // Recovered from erasure coding
    }

    /**
     * @notice Access level for data retrieval
     */
    enum AccessLevel {
        None, // No access
        MetadataOnly, // Can see existence, not content
        Commitment, // Can see commitment, not data
        Encrypted, // Can retrieve encrypted form
        Plaintext // Can decrypt (authorized only)
    }

    /**
     * @notice Confidential Data Blob - the core CDA primitive
     * @dev Encrypted, erasure-coded, availability-proven
     */
    struct ConfidentialBlob {
        // Identity
        bytes32 blobId; // Unique identifier
        bytes32 domainId; // Owning domain
        uint64 version; // Blob version
        // Content (encrypted)
        bytes32 dataCommitment; // Pedersen commitment to plaintext
        bytes32 encryptedDataRoot; // Merkle root of encrypted shards
        uint256 dataSize; // Original data size (for padding verification)
        // Erasure coding
        ErasureScheme erasureScheme;
        uint8 totalShards; // Total shards (data + parity)
        uint8 requiredShards; // Minimum shards for recovery
        bytes32[] shardCommitments; // Commitment per shard
        // Encryption
        bytes32 encryptionKeyCommitment; // Commitment to encryption key
        bytes32 keyDerivationSalt; // Salt for key derivation
        // Access control
        bytes32 accessPolicyHash; // Policy for who can access
        bytes32 disclosurePolicyHash; // Policy for disclosure timing
        // Availability
        AvailabilityStatus status;
        uint64 publishedAt;
        uint64 expiresAt;
        uint64 lastProvenAt;
        // Proofs
        bytes32 availabilityProofHash; // Hash of latest availability proof
        uint256 challengeStake; // Stake required to challenge
    }

    /**
     * @notice Availability proof - proves data is available without revealing it
     * @dev Uses KZG commitments or similar for efficient verification
     */
    struct AvailabilityProof {
        bytes32 blobId;
        bytes32 proofId;
        // Proof data
        bytes32[] sampledShardIndices; // Which shards were sampled
        bytes32[] shardProofs; // Merkle proofs for sampled shards
        bytes32 aggregateProof; // Aggregated availability proof
        // Verification
        address prover;
        uint64 provenAt;
        bool verified;
        // ZK component (key innovation)
        bytes32 zkProofHash; // ZK proof that data matches commitment
    }

    /**
     * @notice Recovery request - for accessing data via erasure decoding
     */
    struct RecoveryRequest {
        bytes32 requestId;
        bytes32 blobId;
        address requester;
        // Authorization
        bytes32 accessProof; // Proof of access rights
        AccessLevel grantedLevel;
        // Recovery state
        uint8 shardsCollected;
        bytes32[] collectedShardIds;
        bool recoveryComplete;
        // Timing
        uint64 requestedAt;
        uint64 completedAt;
        uint64 expiresAt;
    }

    /**
     * @notice Challenge - disputes availability claims
     */
    struct AvailabilityChallenge {
        bytes32 challengeId;
        bytes32 blobId;
        address challenger;
        // Challenge details
        bytes32[] challengedShardIndices;
        uint256 stake;
        // Resolution
        bool resolved;
        bool challengerWon;
        uint64 challengedAt;
        uint64 deadline;
    }

    /**
     * @notice Delayed disclosure configuration
     */
    struct DelayedDisclosure {
        bytes32 blobId;
        bytes32 keyCommitment; // Commitment to decryption key
        uint64 disclosureTime; // When key becomes available
        bool disclosed;
        bytes32 disclosedKeyHash; // Hash of disclosed key (for verification)
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // Blob storage
    mapping(bytes32 => ConfidentialBlob) public blobs;
    mapping(bytes32 => bytes32[]) public domainBlobs; // domain -> blobIds

    // Proof storage
    mapping(bytes32 => AvailabilityProof) public proofs;
    mapping(bytes32 => bytes32[]) public blobProofs; // blob -> proofIds

    // Recovery storage
    mapping(bytes32 => RecoveryRequest) public recoveryRequests;
    mapping(address => bytes32[]) public userRecoveryRequests;

    // Challenge storage
    mapping(bytes32 => AvailabilityChallenge) public challenges;
    mapping(bytes32 => bytes32[]) public blobChallenges;

    // Delayed disclosure
    mapping(bytes32 => DelayedDisclosure) public delayedDisclosures;

    // Shard storage (off-chain references)
    mapping(bytes32 => mapping(uint8 => bytes32)) public shardLocations;

    // Global metrics
    uint256 public totalBlobs;
    uint256 public totalDataSize;
    uint256 public totalProofs;
    uint256 public totalChallenges;
    uint256 public successfulRecoveries;

    // Configuration
    uint256 public minChallengeStake;
    uint64 public defaultRetentionPeriod;
    uint64 public challengeWindow;
    uint8 public minSamplingRatio; // percentage of shards to sample

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BlobPublished(
        bytes32 indexed blobId,
        bytes32 indexed domainId,
        bytes32 dataCommitment,
        ErasureScheme scheme,
        uint64 expiresAt
    );

    event AvailabilityProven(
        bytes32 indexed blobId,
        bytes32 indexed proofId,
        address prover,
        uint8 shardsSampled
    );

    event ChallengeCreated(
        bytes32 indexed challengeId,
        bytes32 indexed blobId,
        address challenger,
        uint256 stake
    );

    event ChallengeResolved(
        bytes32 indexed challengeId,
        bytes32 indexed blobId,
        bool challengerWon
    );

    event RecoveryRequested(
        bytes32 indexed requestId,
        bytes32 indexed blobId,
        address requester,
        AccessLevel level
    );

    event RecoveryCompleted(
        bytes32 indexed requestId,
        bytes32 indexed blobId,
        uint8 shardsUsed
    );

    event DelayedDisclosureScheduled(
        bytes32 indexed blobId,
        uint64 disclosureTime
    );

    event KeyDisclosed(bytes32 indexed blobId, bytes32 keyHash);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _minChallengeStake,
        uint64 _defaultRetentionPeriod,
        uint64 _challengeWindow
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PUBLISHER_ROLE, msg.sender);
        _grantRole(VALIDATOR_ROLE, msg.sender);

        minChallengeStake = _minChallengeStake;
        defaultRetentionPeriod = _defaultRetentionPeriod;
        challengeWindow = _challengeWindow;
        minSamplingRatio = 25; // 25% of shards must be sampled
    }

    /*//////////////////////////////////////////////////////////////
                            PUBLISH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Publish a confidential blob
     * @dev Data is encrypted and erasure-coded off-chain, only commitments stored
     * @param domainId The owning domain
     * @param dataCommitment Commitment to original plaintext
     * @param encryptedDataRoot Merkle root of encrypted shards
     * @param dataSize Original data size
     * @param scheme Erasure coding scheme
     * @param shardCommitments Commitment for each shard
     * @param encryptionKeyCommitment Commitment to encryption key
     * @param accessPolicyHash Policy for access control
     * @param retentionPeriod How long data should be available
     * @return blobId The unique blob identifier
     */
    function publishBlob(
        bytes32 domainId,
        bytes32 dataCommitment,
        bytes32 encryptedDataRoot,
        uint256 dataSize,
        ErasureScheme scheme,
        bytes32[] calldata shardCommitments,
        bytes32 encryptionKeyCommitment,
        bytes32 accessPolicyHash,
        uint64 retentionPeriod
    )
        external
        onlyRole(PUBLISHER_ROLE)
        whenNotPaused
        nonReentrant
        returns (bytes32 blobId)
    {
        require(shardCommitments.length > 0, "CDA: no shards");
        require(dataSize > 0, "CDA: zero size");

        (uint8 totalShards, uint8 requiredShards) = _getSchemeParams(scheme);
        require(
            shardCommitments.length == totalShards,
            "CDA: shard count mismatch"
        );

        blobId = keccak256(
            abi.encodePacked(
                domainId,
                dataCommitment,
                encryptedDataRoot,
                block.timestamp,
                msg.sender
            )
        );

        require(blobs[blobId].publishedAt == 0, "CDA: blob exists");

        uint64 expiresAt = retentionPeriod > 0
            ? uint64(block.timestamp) + retentionPeriod
            : uint64(block.timestamp) + defaultRetentionPeriod;

        blobs[blobId] = ConfidentialBlob({
            blobId: blobId,
            domainId: domainId,
            version: 1,
            dataCommitment: dataCommitment,
            encryptedDataRoot: encryptedDataRoot,
            dataSize: dataSize,
            erasureScheme: scheme,
            totalShards: totalShards,
            requiredShards: requiredShards,
            shardCommitments: shardCommitments,
            encryptionKeyCommitment: encryptionKeyCommitment,
            keyDerivationSalt: bytes32(0),
            accessPolicyHash: accessPolicyHash,
            disclosurePolicyHash: bytes32(0),
            status: AvailabilityStatus.Unknown,
            publishedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            lastProvenAt: 0,
            availabilityProofHash: bytes32(0),
            challengeStake: minChallengeStake
        });

        domainBlobs[domainId].push(blobId);
        totalBlobs++;
        totalDataSize += dataSize;

        emit BlobPublished(blobId, domainId, dataCommitment, scheme, expiresAt);
    }

    /**
     * @notice Register shard locations (off-chain storage references)
     * @param blobId The blob to register shards for
     * @param shardIndices Indices of shards being registered
     * @param locations Storage location identifiers (IPFS CIDs, etc.)
     */
    function registerShardLocations(
        bytes32 blobId,
        uint8[] calldata shardIndices,
        bytes32[] calldata locations
    ) external onlyRole(PUBLISHER_ROLE) {
        require(blobs[blobId].publishedAt > 0, "CDA: blob not found");
        require(
            shardIndices.length == locations.length,
            "CDA: length mismatch"
        );

        for (uint256 i = 0; i < shardIndices.length; i++) {
            require(
                shardIndices[i] < blobs[blobId].totalShards,
                "CDA: invalid index"
            );
            shardLocations[blobId][shardIndices[i]] = locations[i];
        }
    }

    /*//////////////////////////////////////////////////////////////
                        AVAILABILITY PROOF FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit availability proof
     * @dev Proves data is available WITHOUT revealing content
     * @param blobId The blob to prove
     * @param sampledShardIndices Which shards were sampled
     * @param shardProofs Merkle proofs for sampled shards
     * @param zkProofHash ZK proof that samples match commitments
     * @return proofId The proof identifier
     */
    function proveAvailability(
        bytes32 blobId,
        bytes32[] calldata sampledShardIndices,
        bytes32[] calldata shardProofs,
        bytes32 zkProofHash
    )
        external
        onlyRole(VALIDATOR_ROLE)
        whenNotPaused
        returns (bytes32 proofId)
    {
        ConfidentialBlob storage blob = blobs[blobId];
        require(blob.publishedAt > 0, "CDA: blob not found");
        require(block.timestamp < blob.expiresAt, "CDA: blob expired");

        // Verify minimum sampling
        uint8 minSamples = (blob.totalShards * minSamplingRatio) / 100;
        require(
            sampledShardIndices.length >= minSamples,
            "CDA: insufficient sampling"
        );

        proofId = keccak256(
            abi.encodePacked(blobId, block.timestamp, msg.sender, zkProofHash)
        );

        // Verify ZK proof (simplified - would call verifier contract)
        require(
            _verifyAvailabilityProof(
                blobId,
                sampledShardIndices,
                shardProofs,
                zkProofHash
            ),
            "CDA: invalid proof"
        );

        proofs[proofId] = AvailabilityProof({
            blobId: blobId,
            proofId: proofId,
            sampledShardIndices: sampledShardIndices,
            shardProofs: shardProofs,
            aggregateProof: bytes32(0),
            prover: msg.sender,
            provenAt: uint64(block.timestamp),
            verified: true,
            zkProofHash: zkProofHash
        });

        blob.status = AvailabilityStatus.Available;
        blob.lastProvenAt = uint64(block.timestamp);
        blob.availabilityProofHash = proofId;

        blobProofs[blobId].push(proofId);
        totalProofs++;

        emit AvailabilityProven(
            blobId,
            proofId,
            msg.sender,
            uint8(sampledShardIndices.length)
        );
    }

    /**
     * @notice Verify availability proof (internal)
     * @dev Would integrate with ZK verifier contract
     */
    function _verifyAvailabilityProof(
        bytes32 blobId,
        bytes32[] calldata sampledShardIndices,
        bytes32[] calldata shardProofs,
        bytes32 zkProofHash
    ) internal view returns (bool) {
        // Simplified verification - production would use ZK verifier
        ConfidentialBlob storage blob = blobs[blobId];

        // Verify each sampled shard has a valid proof
        for (uint256 i = 0; i < sampledShardIndices.length; i++) {
            // In production: verify Merkle proof against encryptedDataRoot
            // For now: check proof is non-zero
            if (shardProofs[i] == bytes32(0)) {
                return false;
            }
        }

        // Verify ZK proof hash is non-zero
        if (zkProofHash == bytes32(0)) {
            return false;
        }

        // Additional checks would verify:
        // 1. ZK proof that samples decrypt correctly
        // 2. ZK proof that commitments match
        // 3. Aggregate proof validity

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           CHALLENGE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge availability claim
     * @dev Stake is slashed if challenge fails, rewarded if succeeds
     * @param blobId The blob to challenge
     * @param challengedShardIndices Specific shards being challenged
     * @return challengeId The challenge identifier
     */
    function challengeAvailability(
        bytes32 blobId,
        bytes32[] calldata challengedShardIndices
    ) external payable whenNotPaused returns (bytes32 challengeId) {
        ConfidentialBlob storage blob = blobs[blobId];
        require(blob.publishedAt > 0, "CDA: blob not found");
        require(
            blob.status == AvailabilityStatus.Available,
            "CDA: not marked available"
        );
        require(msg.value >= blob.challengeStake, "CDA: insufficient stake");

        challengeId = keccak256(
            abi.encodePacked(
                blobId,
                msg.sender,
                block.timestamp,
                challengedShardIndices.length
            )
        );

        challenges[challengeId] = AvailabilityChallenge({
            challengeId: challengeId,
            blobId: blobId,
            challenger: msg.sender,
            challengedShardIndices: challengedShardIndices,
            stake: msg.value,
            resolved: false,
            challengerWon: false,
            challengedAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp) + challengeWindow
        });

        blobChallenges[blobId].push(challengeId);
        totalChallenges++;

        emit ChallengeCreated(challengeId, blobId, msg.sender, msg.value);
    }

    /**
     * @notice Respond to challenge with proof
     * @param challengeId The challenge to respond to
     * @param shardProofs Proofs for challenged shards
     * @param zkProof ZK proof of valid response
     */
    function respondToChallenge(
        bytes32 challengeId,
        bytes32[] calldata shardProofs,
        bytes32 zkProof
    ) external onlyRole(VALIDATOR_ROLE) {
        AvailabilityChallenge storage challenge = challenges[challengeId];
        require(!challenge.resolved, "CDA: already resolved");
        require(block.timestamp < challenge.deadline, "CDA: deadline passed");

        // Verify response (simplified)
        bool validResponse = _verifyChallenge(
            challenge.blobId,
            challenge.challengedShardIndices,
            shardProofs,
            zkProof
        );

        if (validResponse) {
            // Challenger loses stake
            challenge.resolved = true;
            challenge.challengerWon = false;
            // Stake goes to protocol/responder - transfer to validator
            (bool success, ) = payable(msg.sender).call{value: challenge.stake}(
                ""
            );
            require(success, "CDA: stake transfer failed");
        } else {
            // Challenger wins
            challenge.resolved = true;
            challenge.challengerWon = true;
            blobs[challenge.blobId].status = AvailabilityStatus.Unavailable;
            // Return stake + bonus to challenger using safe pattern
            (bool success, ) = payable(challenge.challenger).call{
                value: challenge.stake
            }("");
            require(success, "CDA: stake return failed");
        }

        emit ChallengeResolved(
            challengeId,
            challenge.blobId,
            challenge.challengerWon
        );
    }

    /**
     * @notice Resolve challenge after deadline (challenger wins by default)
     */
    function resolveExpiredChallenge(bytes32 challengeId) external {
        AvailabilityChallenge storage challenge = challenges[challengeId];
        require(!challenge.resolved, "CDA: already resolved");
        require(
            block.timestamp >= challenge.deadline,
            "CDA: deadline not passed"
        );

        challenge.resolved = true;
        challenge.challengerWon = true;
        blobs[challenge.blobId].status = AvailabilityStatus.Unavailable;

        // Security: Use safe ETH transfer pattern instead of transfer()
        (bool success, ) = payable(challenge.challenger).call{
            value: challenge.stake
        }("");
        require(success, "CDA: stake return failed");

        emit ChallengeResolved(challengeId, challenge.blobId, true);
    }

    function _verifyChallenge(
        bytes32 blobId,
        bytes32[] storage challengedShardIndices,
        bytes32[] calldata shardProofs,
        bytes32 zkProof
    ) internal view returns (bool) {
        // Security: Validate proof count matches challenged shards
        if (shardProofs.length != challengedShardIndices.length) {
            return false;
        }

        // Security: ZK proof must be non-zero
        if (zkProof == bytes32(0)) {
            return false;
        }

        // Verify blob exists and get commitment data
        ConfidentialBlob storage blob = blobs[blobId];
        if (blob.publishedAt == 0) {
            return false;
        }

        // TODO: PRODUCTION REQUIREMENT
        // Uncomment after deploying shard verifier:
        // for (uint256 i = 0; i < shardProofs.length; i++) {
        //     if (!IShardVerifier(shardVerifier).verifyShard(
        //         blob.shardCommitments[uint256(challengedShardIndices[i])],
        //         shardProofs[i]
        //     )) {
        //         return false;
        //     }
        // }
        // return IZKVerifier(zkVerifier).verify(zkProof);

        // DEVELOPMENT ONLY: Remove in production
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           RECOVERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request data recovery (for authorized parties)
     * @param blobId The blob to recover
     * @param accessProof Proof of access authorization
     * @return requestId The recovery request identifier
     */
    function requestRecovery(
        bytes32 blobId,
        bytes32 accessProof
    ) external whenNotPaused nonReentrant returns (bytes32 requestId) {
        ConfidentialBlob storage blob = blobs[blobId];
        require(blob.publishedAt > 0, "CDA: blob not found");
        require(
            blob.status == AvailabilityStatus.Available ||
                blob.status == AvailabilityStatus.Unknown,
            "CDA: not available"
        );

        // Verify access authorization
        AccessLevel level = _verifyAccessAuthorization(
            blobId,
            msg.sender,
            accessProof
        );
        require(level != AccessLevel.None, "CDA: unauthorized");

        requestId = keccak256(
            abi.encodePacked(blobId, msg.sender, block.timestamp, accessProof)
        );

        recoveryRequests[requestId] = RecoveryRequest({
            requestId: requestId,
            blobId: blobId,
            requester: msg.sender,
            accessProof: accessProof,
            grantedLevel: level,
            shardsCollected: 0,
            collectedShardIds: new bytes32[](0),
            recoveryComplete: false,
            requestedAt: uint64(block.timestamp),
            completedAt: 0,
            expiresAt: uint64(block.timestamp) + 1 days
        });

        userRecoveryRequests[msg.sender].push(requestId);

        emit RecoveryRequested(requestId, blobId, msg.sender, level);
    }

    /**
     * @notice Submit shard for recovery
     * @param requestId The recovery request
     * @param shardIndex The shard index
     * @param shardProof Proof that shard is valid
     */
    function submitShardForRecovery(
        bytes32 requestId,
        uint8 shardIndex,
        bytes32 shardProof
    ) external {
        RecoveryRequest storage request = recoveryRequests[requestId];
        require(!request.recoveryComplete, "CDA: already complete");
        require(block.timestamp < request.expiresAt, "CDA: request expired");

        ConfidentialBlob storage blob = blobs[request.blobId];
        require(shardIndex < blob.totalShards, "CDA: invalid shard index");

        // Verify shard proof
        require(
            _verifyShardProof(request.blobId, shardIndex, shardProof),
            "CDA: invalid shard"
        );

        request.shardsCollected++;
        request.collectedShardIds.push(bytes32(uint256(shardIndex)));

        // Check if we have enough shards to recover
        if (request.shardsCollected >= blob.requiredShards) {
            request.recoveryComplete = true;
            request.completedAt = uint64(block.timestamp);
            blob.status = AvailabilityStatus.Recovered;
            successfulRecoveries++;

            emit RecoveryCompleted(
                requestId,
                request.blobId,
                request.shardsCollected
            );
        }
    }

    function _verifyAccessAuthorization(
        bytes32 blobId,
        address requester,
        bytes32 accessProof
    ) internal view returns (AccessLevel) {
        // Check roles first
        if (hasRole(RECOVERY_ROLE, requester)) {
            return AccessLevel.Plaintext;
        }
        if (hasRole(AUDITOR_ROLE, requester)) {
            return AccessLevel.Encrypted;
        }

        // In production: verify ZK proof of authorization
        if (accessProof != bytes32(0)) {
            return AccessLevel.Commitment;
        }

        return AccessLevel.None;
    }

    function _verifyShardProof(
        bytes32 blobId,
        uint8 shardIndex,
        bytes32 shardProof
    ) internal view returns (bool) {
        ConfidentialBlob storage blob = blobs[blobId];

        // Verify proof against stored commitment
        // Production: Merkle proof verification
        if (shardIndex >= blob.shardCommitments.length) {
            return false;
        }

        return shardProof != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                       DELAYED DISCLOSURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule delayed disclosure (time-locked data)
     * @param blobId The blob to disclose later
     * @param disclosureTime When the key becomes available
     * @param keyCommitment Commitment to the decryption key
     */
    function scheduleDelayedDisclosure(
        bytes32 blobId,
        uint64 disclosureTime,
        bytes32 keyCommitment
    ) external onlyRole(PUBLISHER_ROLE) {
        require(blobs[blobId].publishedAt > 0, "CDA: blob not found");
        require(disclosureTime > block.timestamp, "CDA: invalid time");
        require(
            delayedDisclosures[blobId].disclosureTime == 0,
            "CDA: already scheduled"
        );

        delayedDisclosures[blobId] = DelayedDisclosure({
            blobId: blobId,
            keyCommitment: keyCommitment,
            disclosureTime: disclosureTime,
            disclosed: false,
            disclosedKeyHash: bytes32(0)
        });

        blobs[blobId].disclosurePolicyHash = keccak256(
            abi.encodePacked("DELAYED", disclosureTime, keyCommitment)
        );

        emit DelayedDisclosureScheduled(blobId, disclosureTime);
    }

    /**
     * @notice Disclose key after time lock expires
     * @param blobId The blob to disclose
     * @param keyHash Hash of the actual decryption key
     * @param keyProof Proof that key matches commitment
     */
    function discloseKey(
        bytes32 blobId,
        bytes32 keyHash,
        bytes32 keyProof
    ) external {
        DelayedDisclosure storage disclosure = delayedDisclosures[blobId];
        require(disclosure.disclosureTime > 0, "CDA: no disclosure scheduled");
        require(block.timestamp >= disclosure.disclosureTime, "CDA: too early");
        require(!disclosure.disclosed, "CDA: already disclosed");

        // Verify key matches commitment
        require(
            _verifyKeyDisclosure(disclosure.keyCommitment, keyHash, keyProof),
            "CDA: invalid key"
        );

        disclosure.disclosed = true;
        disclosure.disclosedKeyHash = keyHash;

        emit KeyDisclosed(blobId, keyHash);
    }

    function _verifyKeyDisclosure(
        bytes32 keyCommitment,
        bytes32 keyHash,
        bytes32 keyProof
    ) internal pure returns (bool) {
        // Security: Basic validation
        if (keyProof == bytes32(0) || keyCommitment == bytes32(0)) {
            return false;
        }
        if (keyHash == bytes32(0)) {
            return false;
        }

        // TODO: PRODUCTION REQUIREMENT
        // Verify ZK proof that key opens commitment:
        // return IKeyVerifier(keyVerifier).verifyKeyOpensCommitment(
        //     keyCommitment,
        //     keyHash,
        //     keyProof
        // );

        // DEVELOPMENT ONLY: Remove in production
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get blob details
     */
    function getBlob(
        bytes32 blobId
    ) external view returns (ConfidentialBlob memory) {
        return blobs[blobId];
    }

    /**
     * @notice Get availability proof
     */
    function getProof(
        bytes32 proofId
    ) external view returns (AvailabilityProof memory) {
        return proofs[proofId];
    }

    /**
     * @notice Get recovery request
     */
    function getRecoveryRequest(
        bytes32 requestId
    ) external view returns (RecoveryRequest memory) {
        return recoveryRequests[requestId];
    }

    /**
     * @notice Check if blob is available
     */
    function isAvailable(bytes32 blobId) external view returns (bool) {
        ConfidentialBlob storage blob = blobs[blobId];
        return
            blob.status == AvailabilityStatus.Available &&
            block.timestamp < blob.expiresAt;
    }

    /**
     * @notice Get domain's blobs
     */
    function getDomainBlobs(
        bytes32 domainId
    ) external view returns (bytes32[] memory) {
        return domainBlobs[domainId];
    }

    /**
     * @notice Get erasure scheme parameters
     */
    function _getSchemeParams(
        ErasureScheme scheme
    ) internal pure returns (uint8 total, uint8 required) {
        if (scheme == ErasureScheme.None) {
            return (1, 1);
        } else if (scheme == ErasureScheme.ReedSolomon44) {
            return (8, 4); // 4 data + 4 parity
        } else if (scheme == ErasureScheme.ReedSolomon84) {
            return (12, 8); // 8 data + 4 parity
        } else if (scheme == ErasureScheme.ReedSolomon168) {
            return (24, 16); // 16 data + 8 parity
        } else if (scheme == ErasureScheme.Fountain) {
            return (32, 16); // Flexible
        }
        return (1, 1);
    }

    /**
     * @notice Get global metrics (privacy-preserving)
     */
    function getMetrics()
        external
        view
        returns (
            uint256 _totalBlobs,
            uint256 _totalDataSize,
            uint256 _totalProofs,
            uint256 _totalChallenges,
            uint256 _successfulRecoveries
        )
    {
        return (
            totalBlobs,
            totalDataSize,
            totalProofs,
            totalChallenges,
            successfulRecoveries
        );
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setMinChallengeStake(
        uint256 stake
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minChallengeStake = stake;
    }

    function setDefaultRetentionPeriod(
        uint64 period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        defaultRetentionPeriod = period;
    }

    function setChallengeWindow(
        uint64 window
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        challengeWindow = window;
    }

    function setMinSamplingRatio(
        uint8 ratio
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(ratio <= 100, "CDA: invalid ratio");
        minSamplingRatio = ratio;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
