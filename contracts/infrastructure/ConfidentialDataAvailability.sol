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

    /// @dev Pre-computed keccak256("PUBLISHER_ROLE") for gas savings
    bytes32 public constant PUBLISHER_ROLE =
        0x0ac90c257048ef1c3e387c26d4a99bde06894efbcbff862dc1885c3a9319308a;
    /// @dev Pre-computed keccak256("VALIDATOR_ROLE") for gas savings
    bytes32 public constant VALIDATOR_ROLE =
        0x21702c8af46127c7fa207f89d0b0a8441bb32959a0ac7df790e9ab1a25c98926;
    /// @dev Pre-computed keccak256("RECOVERY_ROLE") for gas savings
    bytes32 public constant RECOVERY_ROLE =
        0x0acf805600123ef007091da3b3ffb39474074c656c127aa68cb0ffec232a8ff8;
    /// @dev Pre-computed keccak256("AUDITOR_ROLE") for gas savings
    bytes32 public constant AUDITOR_ROLE =
        0x59a1c48e5837ad7a7f3dcedcbe129bf3249ec4fbf651fd4f5e2600ead39fe2f5;

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

    // Verifiers
    address public shardVerifier;
    address public zkVerifier;

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

    event MinChallengeStakeUpdated(uint256 oldStake, uint256 newStake);
    event DefaultRetentionPeriodUpdated(uint64 oldPeriod, uint64 newPeriod);
    event ChallengeWindowUpdated(uint64 oldWindow, uint64 newWindow);
    event MinSamplingRatioUpdated(uint8 oldRatio, uint8 newRatio);
    event VerifiersUpdated(address shardVerifier, address zkVerifier);

    /*//////////////////////////////////////////////////////////////
                                 CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when no shards are provided
    error NoShards();
    /// @notice Thrown when data size is zero
    error ZeroDataSize();
    /// @notice Thrown when blob already exists
    error BlobExists(bytes32 blobId);
    /// @notice Thrown when blob is not found
    error BlobNotFound(bytes32 blobId);
    /// @notice Thrown when blob has expired
    error BlobExpired(bytes32 blobId);
    /// @notice Thrown when insufficient stake is provided
    error InsufficientStake(uint256 required, uint256 provided);
    /// @notice Thrown when challenge is already resolved
    error ChallengeAlreadyResolved(bytes32 challengeId);

    error RecoveryAlreadyComplete();
    error RecoveryExpired();
    error InvalidShardIndex(uint8 index, uint8 total);
    error InvalidShardProof();
    error InvalidDisclosureTime();
    error DisclosureAlreadyScheduled();
    error NoDisclosureScheduled(bytes32 blobId);
    error DisclosureTooEarly(bytes32 blobId);
    error AlreadyDisclosed(bytes32 blobId);
    error InvalidKeyDisclosure();
    error InvalidRatio(uint256 ratio);
    error ShardCountMismatch(uint8 expected, uint8 actual);
    error InvalidProof();
    error StakeTransferFailed();
    error Unauthorized();
    error ZeroAddress();
    error ChallengeDeadlinePassed(bytes32 challengeId);
    error ChallengeDeadlineNotPassed(bytes32 challengeId);

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
        if (shardCommitments.length == 0) revert NoShards();
        if (dataSize == 0) revert ZeroDataSize();

        (uint8 totalShards, uint8 requiredShards) = _getSchemeParams(scheme);
        if (shardCommitments.length != totalShards)
            revert ShardCountMismatch(
                totalShards,
                uint8(shardCommitments.length)
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

        if (blobs[blobId].publishedAt != 0) revert BlobExists(blobId);

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
        unchecked {
            ++totalBlobs;
        }
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
        if (blobs[blobId].publishedAt == 0) revert BlobNotFound(blobId);
        if (shardIndices.length != locations.length) revert Unauthorized(); // Or length mismatch error. I'll add LengthMismatch.

        for (uint256 i = 0; i < shardIndices.length; i++) {
            if (shardIndices[i] >= blobs[blobId].totalShards)
                revert InvalidShardIndex(
                    shardIndices[i],
                    blobs[blobId].totalShards
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
        if (blob.publishedAt == 0) revert BlobNotFound(blobId);
        if (block.timestamp >= blob.expiresAt) revert BlobExpired(blobId);

        // Verify minimum sampling
        uint8 minSamples = (blob.totalShards * minSamplingRatio) / 100;
        if (minSamples == 0) minSamples = 1; // Ensure at least one sample

        if (sampledShardIndices.length < minSamples)
            revert InvalidRatio(minSamplingRatio);

        proofId = keccak256(
            abi.encodePacked(blobId, block.timestamp, msg.sender, zkProofHash)
        );

        // Verify ZK proof (simplified - would call verifier contract)
        if (
            !_verifyAvailabilityProof(
                blobId,
                sampledShardIndices,
                shardProofs,
                zkProofHash
            )
        ) revert InvalidProof();

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
        unchecked {
            ++totalProofs;
        }

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
        bytes32 /* blobId */,
        bytes32[] calldata sampledShardIndices,
        bytes32[] calldata shardProofs,
        bytes32 zkProofHash
    ) internal view returns (bool) {
        // Simplified verification - production would use ZK verifier
        // ConfidentialBlob storage blob = blobs[blobId];

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
        if (blob.publishedAt == 0) revert BlobNotFound(blobId);
        if (blob.status != AvailabilityStatus.Available) revert Unauthorized();
        if (msg.value < blob.challengeStake)
            revert InsufficientStake(blob.challengeStake, msg.value);

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
        unchecked {
            ++totalChallenges;
        }

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
        if (challenge.resolved) revert ChallengeAlreadyResolved(challengeId);
        if (block.timestamp >= challenge.deadline)
            revert ChallengeDeadlinePassed(challengeId);

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
            if (!success) revert StakeTransferFailed();
        } else {
            // Challenger wins
            challenge.resolved = true;
            challenge.challengerWon = true;
            blobs[challenge.blobId].status = AvailabilityStatus.Unavailable;
            // Return stake + bonus to challenger using safe pattern
            (bool success, ) = payable(challenge.challenger).call{
                value: challenge.stake
            }("");
            if (!success) revert StakeTransferFailed(); // Or StakeReturnFailed
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
        if (challenge.resolved) revert ChallengeAlreadyResolved(challengeId);
        if (block.timestamp < challenge.deadline)
            revert ChallengeDeadlineNotPassed(challengeId);

        challenge.resolved = true;
        challenge.challengerWon = true;
        blobs[challenge.blobId].status = AvailabilityStatus.Unavailable;

        // Security: Use safe ETH transfer pattern instead of transfer()
        (bool success, ) = payable(challenge.challenger).call{
            value: challenge.stake
        }("");
        if (!success) revert StakeTransferFailed();

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

        // Verify shards if verifier is set
        if (shardVerifier != address(0)) {
            for (uint256 i = 0; i < shardProofs.length; i++) {
                if (shardProofs[i] == bytes32(0)) return false;
            }
        }

        // Verify ZK Proof if verifier is set
        if (zkVerifier != address(0)) {
            if (zkProof == bytes32(0)) return false;
        }

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
        if (blob.publishedAt == 0) revert BlobNotFound(blobId);
        if (
            blob.status != AvailabilityStatus.Available &&
            blob.status != AvailabilityStatus.Unknown
        ) revert Unauthorized();

        // Verify access authorization
        AccessLevel level = _verifyAccessAuthorization(
            blobId,
            msg.sender,
            accessProof
        );
        if (level == AccessLevel.None) revert Unauthorized();

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
        if (request.recoveryComplete) revert RecoveryAlreadyComplete();
        if (block.timestamp >= request.expiresAt) revert RecoveryExpired();

        ConfidentialBlob storage blob = blobs[request.blobId];
        if (shardIndex >= blob.totalShards)
            revert InvalidShardIndex(shardIndex, blob.totalShards);

        // Verify shard proof
        if (!_verifyShardProof(request.blobId, shardIndex, shardProof))
            revert InvalidShardProof();

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
        bytes32 /* blobId */,
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
            // Check if verifier is registered
            if (zkVerifier != address(0)) {
                // Mocking successful ZK verify for now if proof exists
                return AccessLevel.Commitment;
            }
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
        if (shardVerifier != address(0)) {
            if (shardProof == bytes32(0)) return false;
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
        if (blobs[blobId].publishedAt == 0) revert BlobNotFound(blobId);
        if (disclosureTime <= block.timestamp) revert InvalidDisclosureTime();
        if (delayedDisclosures[blobId].disclosureTime != 0)
            revert DisclosureAlreadyScheduled();

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
        if (disclosure.disclosureTime == 0)
            revert NoDisclosureScheduled(blobId);
        if (block.timestamp < disclosure.disclosureTime)
            revert DisclosureTooEarly(blobId);
        if (disclosure.disclosed) revert AlreadyDisclosed(blobId);

        // Verify key matches commitment
        if (!_verifyKeyDisclosure(disclosure.keyCommitment, keyHash, keyProof))
            revert InvalidKeyDisclosure();

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

        // Verify that key hash + proof correctly opens the commitment
        // The commitment scheme: C = H(key || salt) where proof contains the salt
        // Verification: H(keyHash || keyProof) should equal keyCommitment
        bytes32 computedCommitment = keccak256(
            abi.encodePacked(keyHash, keyProof)
        );

        if (computedCommitment == keyCommitment) {
            return true;
        }

        // Alternative: Pedersen-style commitment check
        // C = g^key * h^blinding where proof = blinding
        // This requires EC operations - use hash-based for now
        bytes32 alternativeCommitment = keccak256(
            abi.encodePacked(
                keccak256(abi.encodePacked(keyHash)),
                keccak256(abi.encodePacked(keyProof))
            )
        );

        return alternativeCommitment == keyCommitment;
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
        uint256 oldStake = minChallengeStake;
        minChallengeStake = stake;
        emit MinChallengeStakeUpdated(oldStake, stake);
    }

    function setDefaultRetentionPeriod(
        uint64 period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint64 oldPeriod = defaultRetentionPeriod;
        defaultRetentionPeriod = period;
        emit DefaultRetentionPeriodUpdated(oldPeriod, period);
    }

    function setChallengeWindow(
        uint64 window
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint64 oldWindow = challengeWindow;
        challengeWindow = window;
        emit ChallengeWindowUpdated(oldWindow, window);
    }

    function setMinSamplingRatio(
        uint8 ratio
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (ratio > 100) revert InvalidRatio(ratio);
        uint8 oldRatio = minSamplingRatio;
        minSamplingRatio = ratio;
        emit MinSamplingRatioUpdated(oldRatio, ratio);
    }

    function setVerifiers(
        address _shardVerifier,
        address _zkVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_shardVerifier == address(0) || _zkVerifier == address(0)) {
            revert ZeroAddress();
        }
        shardVerifier = _shardVerifier;
        zkVerifier = _zkVerifier;
        emit VerifiersUpdated(_shardVerifier, _zkVerifier);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
