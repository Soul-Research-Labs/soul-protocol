// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CelestiaPrimitives
 * @notice Core cryptographic primitives for Celestia modular DA network integration
 * @dev Implements BLS12-381, Ed25519, Namespaced Merkle Trees (NMT), and Data Availability Sampling
 *
 * Celestia Architecture:
 * - Modular blockchain focused on Data Availability (DA)
 * - Consensus: Tendermint BFT with 2/3+1 quorum
 * - Data: Namespaced Merkle Trees for efficient blob retrieval
 * - Verification: Data Availability Sampling (DAS) for light clients
 * - Cross-chain: Blobstream for bridging DA attestations to EVM chains
 */
library CelestiaPrimitives {
    // =========================================================================
    // CRYPTOGRAPHIC CONSTANTS
    // =========================================================================

    /// @notice BLS12-381 scalar field order (same as other BLS chains)
    uint256 public constant BLS12_381_SCALAR_ORDER =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice Ed25519 curve order
    uint256 public constant ED25519_ORDER =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// @notice Ed25519 field prime (2^255 - 19)
    uint256 public constant ED25519_PRIME =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;

    /// @notice BLS signature length (compressed G1 point)
    uint256 public constant BLS_SIGNATURE_LENGTH = 48;

    /// @notice BLS public key length (compressed G2 point)
    uint256 public constant BLS_PUBKEY_LENGTH = 96;

    /// @notice Ed25519 signature length
    uint256 public constant ED25519_SIGNATURE_LENGTH = 64;

    /// @notice Ed25519 public key length
    uint256 public constant ED25519_PUBKEY_LENGTH = 32;

    /// @notice Namespace ID size in bytes (29 bytes = 1 version + 28 ID)
    uint256 public constant NAMESPACE_SIZE = 29;

    /// @notice Namespace version for v0 namespaces
    uint8 public constant NAMESPACE_VERSION_0 = 0;

    /// @notice Share size in bytes
    uint256 public constant SHARE_SIZE = 512;

    /// @notice Maximum blob size (2MB for mainnet)
    uint256 public constant MAX_BLOB_SIZE = 2 * 1024 * 1024;

    /// @notice Minimum square size (power of 2)
    uint256 public constant MIN_SQUARE_SIZE = 1;

    /// @notice Maximum square size (power of 2, 128 for mainnet)
    uint256 public constant MAX_SQUARE_SIZE = 128;

    /// @notice Quorum threshold in basis points (66.67% = 6667 bps)
    uint256 public constant QUORUM_THRESHOLD_BPS = 6667;

    /// @notice Celestia mainnet chain ID
    string public constant CELESTIA_MAINNET = "celestia";

    /// @notice Celestia testnet chain ID (Mocha)
    string public constant CELESTIA_TESTNET = "mocha-4";

    /// @notice Celestia devnet chain ID (Arabica)
    string public constant CELESTIA_DEVNET = "arabica-11";

    // =========================================================================
    // DATA STRUCTURES
    // =========================================================================

    /// @notice Namespace identifier (v0 format: 1 byte version + 28 bytes ID)
    struct Namespace {
        uint8 version;
        bytes28 id;
    }

    /// @notice Data share within a blob
    struct Share {
        Namespace namespace;
        bytes data; // Up to SHARE_SIZE - info bytes
        bool isSequenceStart;
        uint32 sequenceLength;
    }

    /// @notice Blob transaction data
    struct Blob {
        Namespace namespace;
        bytes data;
        uint8 shareVersion;
        bytes32 commitment; // Subtree root commitment
    }

    /// @notice Namespaced Merkle Tree proof
    struct NMTProof {
        bytes32[] sideNodes;
        uint256 start; // Start index
        uint256 end; // End index (exclusive)
        Namespace minNamespace;
        Namespace maxNamespace;
        bytes32 leafHash;
    }

    /// @notice Data availability header
    struct DataAvailabilityHeader {
        bytes32[] rowRoots;
        bytes32[] columnRoots;
        uint64 squareSize;
    }

    /// @notice Extended data square commitment
    struct DataCommitment {
        bytes32 dataRoot;
        uint64 startBlock;
        uint64 endBlock;
        uint64 nonce;
    }

    /// @notice Celestia block header
    struct CelestiaHeader {
        uint64 height;
        uint64 timestamp;
        bytes32 lastBlockId;
        bytes32 dataHash;
        bytes32 validatorsHash;
        bytes32 nextValidatorsHash;
        bytes32 consensusHash;
        bytes32 appHash;
        bytes32 lastResultsHash;
        bytes32 evidenceHash;
        bytes proposerAddress;
    }

    /// @notice Validator info
    struct Validator {
        bytes pubKey; // BLS public key
        uint256 votingPower;
        bytes proposerPriority;
    }

    /// @notice Data availability sampling proof
    struct DASProof {
        uint64 rowIndex;
        uint64 colIndex;
        Share share;
        NMTProof rowProof;
        NMTProof colProof;
    }

    /// @notice Share commitment for blob inclusion
    struct ShareCommitment {
        bytes32 commitment;
        uint64 startShare;
        uint64 endShare;
        Namespace namespace;
    }

    /// @notice Blobstream attestation
    struct BlobstreamAttestation {
        bytes32 dataRoot;
        uint64 height;
        bytes32 validatorSetHash;
        bytes aggregateSignature;
        bytes signerBitmap;
    }

    /// @notice Cross-domain nullifier binding
    struct CelestiaNullifierBinding {
        bytes32 celestiaCommitment;
        bytes32 pilNullifier;
        bytes32 domainSeparator;
        uint64 height;
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /// @notice Compute SHA256 hash (Tendermint standard)
    function sha256Hash(bytes memory data) internal pure returns (bytes32) {
        return sha256(data);
    }

    /// @notice Compute hash of two nodes (for Merkle tree)
    function hashNode(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(uint8(1), left, right));
    }

    /// @notice Compute leaf hash with namespace (NMT leaf hash)
    function hashLeaf(
        Namespace memory ns,
        bytes memory data
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    uint8(0), // Leaf prefix
                    ns.version,
                    ns.id,
                    data
                )
            );
    }

    /// @notice Compute namespaced hash for inner node
    function hashNamespacedNode(
        bytes32 left,
        bytes32 right,
        Namespace memory minNs,
        Namespace memory maxNs
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    uint8(1), // Inner prefix
                    minNs.version,
                    minNs.id,
                    maxNs.version,
                    maxNs.id,
                    left,
                    right
                )
            );
    }

    /// @notice Compute blob commitment (subtree root)
    function computeBlobCommitment(
        Blob memory blob
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    blob.namespace.version,
                    blob.namespace.id,
                    blob.shareVersion,
                    sha256(blob.data)
                )
            );
    }

    /// @notice Compute data root from row/column roots
    function computeDataRoot(
        DataAvailabilityHeader memory dah
    ) internal pure returns (bytes32) {
        require(
            dah.rowRoots.length == dah.columnRoots.length,
            "Row/column count mismatch"
        );
        require(dah.rowRoots.length > 0, "Empty DAH");

        bytes32 rowRoot = computeMerkleRoot(dah.rowRoots);
        bytes32 colRoot = computeMerkleRoot(dah.columnRoots);

        return sha256(abi.encodePacked(rowRoot, colRoot));
    }

    /// @notice Compute Merkle root from leaves
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        uint256 n = leaves.length;
        while (n > 1) {
            uint256 newN = (n + 1) / 2;
            for (uint256 i = 0; i < newN; i++) {
                if (2 * i + 1 < n) {
                    leaves[i] = hashNode(leaves[2 * i], leaves[2 * i + 1]);
                } else {
                    leaves[i] = leaves[2 * i];
                }
            }
            n = newN;
        }
        return leaves[0];
    }

    // =========================================================================
    // NAMESPACE OPERATIONS
    // =========================================================================

    /// @notice Create namespace from version and ID
    function createNamespace(
        uint8 version,
        bytes28 id
    ) internal pure returns (Namespace memory) {
        return Namespace({version: version, id: id});
    }

    /// @notice Create v0 namespace from ID
    function createV0Namespace(
        bytes28 id
    ) internal pure returns (Namespace memory) {
        return Namespace({version: NAMESPACE_VERSION_0, id: id});
    }

    /// @notice Compare two namespaces
    function compareNamespaces(
        Namespace memory a,
        Namespace memory b
    ) internal pure returns (int8) {
        if (a.version < b.version) return -1;
        if (a.version > b.version) return 1;
        if (a.id < b.id) return -1;
        if (a.id > b.id) return 1;
        return 0;
    }

    /// @notice Check if namespace is within range
    function isNamespaceInRange(
        Namespace memory ns,
        Namespace memory min,
        Namespace memory max
    ) internal pure returns (bool) {
        return
            compareNamespaces(ns, min) >= 0 && compareNamespaces(ns, max) <= 0;
    }

    /// @notice Encode namespace to bytes
    function encodeNamespace(
        Namespace memory ns
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(ns.version, ns.id);
    }

    /// @notice Decode namespace from bytes
    function decodeNamespace(
        bytes memory data
    ) internal pure returns (Namespace memory) {
        require(data.length == NAMESPACE_SIZE, "Invalid namespace size");
        uint8 version = uint8(data[0]);
        bytes28 id;
        assembly {
            id := mload(add(data, 29))
        }
        return Namespace({version: version, id: id});
    }

    // =========================================================================
    // NAMESPACED MERKLE TREE VERIFICATION
    // =========================================================================

    /// @notice Verify NMT proof for data inclusion
    function verifyNMTProof(
        NMTProof memory proof,
        bytes32 root,
        Namespace memory namespace,
        bytes memory data
    ) internal pure returns (bool) {
        // Verify namespace is within proof range
        if (
            !isNamespaceInRange(
                namespace,
                proof.minNamespace,
                proof.maxNamespace
            )
        ) {
            return false;
        }

        // Compute leaf hash
        bytes32 computedLeaf = hashLeaf(namespace, data);
        if (computedLeaf != proof.leafHash) {
            return false;
        }

        // Verify Merkle path
        bytes32 currentHash = proof.leafHash;
        uint256 idx = proof.start;

        for (uint256 i = 0; i < proof.sideNodes.length; i++) {
            if (idx & 1 == 0) {
                currentHash = hashNode(currentHash, proof.sideNodes[i]);
            } else {
                currentHash = hashNode(proof.sideNodes[i], currentHash);
            }
            idx >>= 1;
        }

        return currentHash == root;
    }

    /// @notice Verify absence proof (namespace not in tree)
    function verifyNMTAbsenceProof(
        NMTProof memory proof,
        bytes32 root,
        Namespace memory namespace
    ) internal pure returns (bool) {
        // For absence proof, namespace should NOT be in range
        if (
            isNamespaceInRange(
                namespace,
                proof.minNamespace,
                proof.maxNamespace
            )
        ) {
            return false;
        }

        // Verify the proof itself is valid for its claimed range
        bytes32 currentHash = proof.leafHash;
        uint256 idx = proof.start;

        for (uint256 i = 0; i < proof.sideNodes.length; i++) {
            if (idx & 1 == 0) {
                currentHash = hashNode(currentHash, proof.sideNodes[i]);
            } else {
                currentHash = hashNode(proof.sideNodes[i], currentHash);
            }
            idx >>= 1;
        }

        return currentHash == root;
    }

    // =========================================================================
    // DATA AVAILABILITY SAMPLING
    // =========================================================================

    /// @notice Verify DAS proof for a single sample
    function verifyDASSample(
        DASProof memory proof,
        DataAvailabilityHeader memory dah
    ) internal pure returns (bool) {
        require(proof.rowIndex < dah.squareSize, "Row index out of bounds");
        require(proof.colIndex < dah.squareSize, "Col index out of bounds");

        // Verify row proof
        bytes32 rowRoot = dah.rowRoots[proof.rowIndex];
        Namespace memory shareNs = proof.share.namespace;

        bytes32 shareHash = hashLeaf(shareNs, proof.share.data);

        // Simplified verification - in production would verify full NMT proof
        if (proof.rowProof.leafHash != shareHash) {
            return false;
        }

        // Verify column proof
        bytes32 colRoot = dah.columnRoots[proof.colIndex];
        if (proof.colProof.leafHash != shareHash) {
            return false;
        }

        return true;
    }

    /// @notice Compute sample coordinates from random seed
    function computeSampleCoordinates(
        bytes32 seed,
        uint64 squareSize,
        uint256 sampleIndex
    ) internal pure returns (uint64 row, uint64 col) {
        bytes32 coordHash = sha256(abi.encodePacked(seed, sampleIndex));
        uint256 coord = uint256(coordHash);
        row = uint64(coord % squareSize);
        col = uint64((coord / squareSize) % squareSize);
    }

    // =========================================================================
    // BLOB OPERATIONS
    // =========================================================================

    /// @notice Create blob from data and namespace
    function createBlob(
        Namespace memory namespace,
        bytes memory data
    ) internal pure returns (Blob memory) {
        require(data.length <= MAX_BLOB_SIZE, "Blob too large");

        bytes32 commitment = sha256(
            abi.encodePacked(namespace.version, namespace.id, sha256(data))
        );

        return
            Blob({
                namespace: namespace,
                data: data,
                shareVersion: 0,
                commitment: commitment
            });
    }

    /// @notice Compute share commitment for blob
    function computeShareCommitment(
        Blob memory blob,
        uint64 startShare,
        uint64 endShare
    ) internal pure returns (ShareCommitment memory) {
        return
            ShareCommitment({
                commitment: blob.commitment,
                startShare: startShare,
                endShare: endShare,
                namespace: blob.namespace
            });
    }

    /// @notice Calculate number of shares needed for data
    function calculateShareCount(
        uint256 dataSize
    ) internal pure returns (uint256) {
        // Each share has some overhead, simplified calculation
        uint256 dataPerShare = SHARE_SIZE - 2; // 2 bytes for info
        return (dataSize + dataPerShare - 1) / dataPerShare;
    }

    // =========================================================================
    // VALIDATOR OPERATIONS
    // =========================================================================

    /// @notice Check if signing power meets quorum
    function hasQuorum(
        uint256 signingPower,
        uint256 totalPower
    ) internal pure returns (bool) {
        if (totalPower == 0) return false;
        return signingPower * 10000 >= totalPower * QUORUM_THRESHOLD_BPS;
    }

    /// @notice Compute validator set hash
    function computeValidatorSetHash(
        Validator[] memory validators
    ) internal pure returns (bytes32) {
        bytes memory encoded;
        for (uint256 i = 0; i < validators.length; i++) {
            encoded = abi.encodePacked(
                encoded,
                validators[i].pubKey,
                validators[i].votingPower
            );
        }
        return sha256(encoded);
    }

    /// @notice Calculate total voting power
    function calculateTotalPower(
        Validator[] memory validators
    ) internal pure returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            total += validators[i].votingPower;
        }
        return total;
    }

    /// @notice Calculate signing power from bitmap
    function calculateSigningPower(
        bytes memory bitmap,
        Validator[] memory validators
    ) internal pure returns (uint256) {
        uint256 signingPower = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            uint256 byteIndex = i / 8;
            uint256 bitIndex = i % 8;
            if (byteIndex < bitmap.length) {
                if (uint8(bitmap[byteIndex]) & (1 << bitIndex) != 0) {
                    signingPower += validators[i].votingPower;
                }
            }
        }
        return signingPower;
    }

    // =========================================================================
    // SIGNATURE VERIFICATION (ABSTRACT)
    // =========================================================================

    /// @notice Verify BLS aggregate signature (abstract)
    function verifyBLSSignature(
        bytes32 message,
        bytes memory signature,
        bytes memory publicKey
    ) internal pure returns (bool) {
        require(
            signature.length == BLS_SIGNATURE_LENGTH,
            "Invalid BLS sig length"
        );
        require(
            publicKey.length == BLS_PUBKEY_LENGTH,
            "Invalid BLS key length"
        );
        // Abstract - requires BLS precompile
        return
            signature.length == BLS_SIGNATURE_LENGTH &&
            publicKey.length == BLS_PUBKEY_LENGTH;
    }

    /// @notice Verify Ed25519 signature (abstract)
    function verifyEd25519Signature(
        bytes32 message,
        bytes memory signature,
        bytes memory publicKey
    ) internal pure returns (bool) {
        require(
            signature.length == ED25519_SIGNATURE_LENGTH,
            "Invalid Ed25519 sig length"
        );
        require(
            publicKey.length == ED25519_PUBKEY_LENGTH,
            "Invalid Ed25519 key length"
        );
        // Abstract - requires Ed25519 precompile
        return
            signature.length == ED25519_SIGNATURE_LENGTH &&
            publicKey.length == ED25519_PUBKEY_LENGTH;
    }

    // =========================================================================
    // BLOBSTREAM OPERATIONS
    // =========================================================================

    /// @notice Verify Blobstream attestation
    function verifyBlobstreamAttestation(
        BlobstreamAttestation memory attestation,
        Validator[] memory validators
    ) internal pure returns (bool) {
        // Calculate signing power
        uint256 signingPower = calculateSigningPower(
            attestation.signerBitmap,
            validators
        );
        uint256 totalPower = calculateTotalPower(validators);

        // Check quorum
        if (!hasQuorum(signingPower, totalPower)) {
            return false;
        }

        // Verify validator set hash matches
        bytes32 computedHash = computeValidatorSetHash(validators);
        if (computedHash != attestation.validatorSetHash) {
            return false;
        }

        return true;
    }

    /// @notice Compute data commitment for Blobstream
    function computeDataCommitmentHash(
        DataCommitment memory commitment
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    commitment.dataRoot,
                    commitment.startBlock,
                    commitment.endBlock,
                    commitment.nonce
                )
            );
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER
    // =========================================================================

    /// @notice Compute Celestia nullifier from blob commitment
    function computeCelestiaNullifier(
        bytes32 blobCommitment,
        uint64 height,
        Namespace memory namespace
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    blobCommitment,
                    height,
                    namespace.version,
                    namespace.id,
                    "CELESTIA_NF"
                )
            );
    }

    /// @notice Compute cross-domain nullifier binding
    function computeCrossChainNullifier(
        bytes32 celestiaNullifier,
        bytes32 pilDomain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(celestiaNullifier, pilDomain, "CELESTIA2PIL")
            );
    }

    /// @notice Bind Celestia nullifier to PIL nullifier
    function bindNullifier(
        bytes32 celestiaCommitment,
        bytes32 pilNullifier,
        bytes32 domainSeparator,
        uint64 height
    ) internal pure returns (CelestiaNullifierBinding memory) {
        return
            CelestiaNullifierBinding({
                celestiaCommitment: celestiaCommitment,
                pilNullifier: pilNullifier,
                domainSeparator: domainSeparator,
                height: height
            });
    }

    /// @notice Verify nullifier binding
    function verifyNullifierBinding(
        CelestiaNullifierBinding memory binding
    ) internal pure returns (bool) {
        bytes32 expectedPilNullifier = keccak256(
            abi.encodePacked(
                binding.celestiaCommitment,
                binding.domainSeparator,
                binding.height,
                "CELESTIA2PIL"
            )
        );
        return expectedPilNullifier == binding.pilNullifier;
    }

    // =========================================================================
    // HEADER VERIFICATION
    // =========================================================================

    /// @notice Compute header hash
    function computeHeaderHash(
        CelestiaHeader memory header
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    header.height,
                    header.timestamp,
                    header.lastBlockId,
                    header.dataHash,
                    header.validatorsHash,
                    header.nextValidatorsHash,
                    header.consensusHash,
                    header.appHash,
                    header.lastResultsHash,
                    header.evidenceHash,
                    header.proposerAddress
                )
            );
    }

    /// @notice Validate header structure
    function isValidHeader(
        CelestiaHeader memory header
    ) internal pure returns (bool) {
        if (header.height == 0) return false;
        if (header.dataHash == bytes32(0)) return false;
        if (header.validatorsHash == bytes32(0)) return false;
        return true;
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /// @notice Check if square size is valid (power of 2)
    function isValidSquareSize(uint64 size) internal pure returns (bool) {
        if (size < MIN_SQUARE_SIZE || size > MAX_SQUARE_SIZE) return false;
        // Check if power of 2
        return size > 0 && (size & (size - 1)) == 0;
    }

    /// @notice Calculate extended square size from original
    function extendedSquareSize(
        uint64 originalSize
    ) internal pure returns (uint64) {
        return originalSize * 2;
    }

    /// @notice Check if chain ID is valid Celestia chain
    function isValidChainId(
        string memory chainId
    ) internal pure returns (bool) {
        bytes32 hash = keccak256(bytes(chainId));
        return
            hash == keccak256(bytes(CELESTIA_MAINNET)) ||
            hash == keccak256(bytes(CELESTIA_TESTNET)) ||
            hash == keccak256(bytes(CELESTIA_DEVNET));
    }
}
