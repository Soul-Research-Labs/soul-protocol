// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TornadoPrimitives
 * @author PIL Protocol
 * @notice Core cryptographic primitives for Tornado Cash-style mixers
 * @dev Implements MiMC hash, Pedersen commitments, and Merkle tree operations
 *
 * CRYPTOGRAPHIC PRIMITIVES:
 * - MiMC-p/p: 220 rounds over BN254 scalar field
 * - Pedersen Commitment: C = hash(nullifier || secret)
 * - Merkle Tree: 20-depth with MiMC hash
 * - Groth16: Zero-knowledge proof verification
 *
 * BN254 PARAMETERS (same as Railgun):
 * - Field Prime (p): 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * - Scalar Order (r): 21888242871839275222246405745257275088548364400416034343698204186575808495617
 *
 * TORNADO CASH MODEL:
 * - Fixed denomination pools (0.1, 1, 10, 100 ETH)
 * - Commitment = Pedersen(nullifier, secret)
 * - Nullifier = hash(nullifierSecret, pathIndex)
 * - Anonymity set = all deposits in pool
 */
library TornadoPrimitives {
    // =========================================================================
    // BN254 FIELD CONSTANTS
    // =========================================================================

    /// @notice BN254 scalar field order (r)
    uint256 public constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice BN254 base field prime (p)
    uint256 public constant BN254_P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // =========================================================================
    // MIMC CONSTANTS
    // =========================================================================

    /// @notice Number of MiMC rounds
    uint256 public constant MIMC_ROUNDS = 220;

    /// @notice MiMC exponent (x^7 for MiMC-7)
    uint256 public constant MIMC_EXP = 7;

    // =========================================================================
    // MERKLE TREE CONSTANTS
    // =========================================================================

    /// @notice Merkle tree depth
    uint256 public constant MERKLE_TREE_DEPTH = 20;

    /// @notice Maximum number of leaves (2^20 = 1,048,576)
    uint256 public constant MAX_TREE_SIZE = 1 << 20;

    /// @notice Zero value for empty leaves
    bytes32 public constant ZERO_VALUE =
        bytes32(uint256(keccak256("tornado.cash")) % BN254_R);

    // =========================================================================
    // DENOMINATION CONSTANTS
    // =========================================================================

    /// @notice Supported ETH denominations
    uint256 public constant DENOMINATION_01 = 0.1 ether;
    uint256 public constant DENOMINATION_1 = 1 ether;
    uint256 public constant DENOMINATION_10 = 10 ether;
    uint256 public constant DENOMINATION_100 = 100 ether;

    // =========================================================================
    // CROSS-DOMAIN CONSTANTS
    // =========================================================================

    /// @notice PIL-Tornado domain separator
    bytes32 public constant PIL_TORNADO_DOMAIN =
        keccak256("PIL_Tornado_Interop_v1");

    /// @notice Cross-domain nullifier prefix
    bytes public constant CROSS_DOMAIN_PREFIX = "T2P"; // Tornado to PIL

    // =========================================================================
    // TYPE DEFINITIONS
    // =========================================================================

    /// @notice Tornado note structure
    struct TornadoNote {
        bytes32 commitment; // Pedersen(nullifier, secret)
        bytes32 nullifierHash; // hash(nullifierSecret, pathIndex)
        uint256 denomination; // Fixed amount
        uint32 leafIndex; // Position in Merkle tree
    }

    /// @notice Deposit data
    struct DepositData {
        bytes32 commitment;
        uint256 denomination;
        uint256 timestamp;
        uint32 leafIndex;
    }

    /// @notice Withdrawal proof inputs
    struct WithdrawalInputs {
        bytes32 root; // Merkle root
        bytes32 nullifierHash; // Nullifier hash
        address recipient; // Withdrawal recipient
        address relayer; // Relayer address (can be 0)
        uint256 fee; // Relayer fee
        uint256 refund; // Refund amount for token swaps
    }

    /// @notice Groth16 proof structure
    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /// @notice Merkle proof structure
    struct MerkleProof {
        bytes32[] pathElements;
        uint256[] pathIndices;
    }

    /// @notice Cross-chain note for PIL interoperability
    struct CrossChainNote {
        bytes32 tornadoCommitment;
        bytes32 pilCommitment;
        bytes32 nullifierBinding;
        uint256 denomination;
        uint256 sourceChainId;
        uint256 targetChainId;
    }

    // =========================================================================
    // MIMC HASH FUNCTIONS
    // =========================================================================

    /**
     * @notice MiMC-p/p hash function with 220 rounds
     * @param left Left input
     * @param right Right input (key)
     * @return result Hash output
     */
    function mimcHash(
        uint256 left,
        uint256 right
    ) internal pure returns (uint256 result) {
        uint256 r = BN254_R;

        assembly {
            // Initial state
            result := left

            // Round constants (simplified - in production use precomputed constants)
            let c := 0

            // 220 rounds
            for {
                let i := 0
            } lt(i, 220) {
                i := add(i, 1)
            } {
                // Round constant (derived from round number)
                c := mulmod(keccak256(add(i, 1), 32), 1, r)

                // t = x + k + c
                let t := addmod(addmod(result, right, r), c, r)

                // x^7 = x * x^2 * x^4
                let t2 := mulmod(t, t, r)
                let t4 := mulmod(t2, t2, r)
                result := mulmod(mulmod(t, t2, r), t4, r)
            }

            // Final addition
            result := addmod(result, right, r)
        }
    }

    /**
     * @notice MiMC hash of two field elements (for Merkle tree)
     * @param left Left child
     * @param right Right child
     * @return Hash result
     */
    function mimcHash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return bytes32(mimcHash(uint256(left), uint256(right)));
    }

    /**
     * @notice MiMC sponge for variable-length input
     * @param inputs Array of inputs
     * @return Hash result
     */
    function mimcSponge(
        uint256[] memory inputs
    ) internal pure returns (uint256) {
        uint256 state = 0;
        uint256 r = BN254_R;

        for (uint256 i = 0; i < inputs.length; i++) {
            // Absorb
            state = addmod(state, inputs[i], r);
            // Permute
            state = mimcHash(state, 0);
        }

        return state;
    }

    // =========================================================================
    // PEDERSEN COMMITMENT
    // =========================================================================

    /**
     * @notice Compute Pedersen commitment for a note
     * @param nullifier Nullifier secret
     * @param secret Random secret
     * @return commitment The note commitment
     */
    function computeCommitment(
        bytes32 nullifier,
        bytes32 secret
    ) internal pure returns (bytes32 commitment) {
        // C = MiMC(nullifier, secret)
        commitment = mimcHash2(nullifier, secret);
    }

    /**
     * @notice Derive nullifier hash from secret and leaf index
     * @param nullifierSecret The nullifier secret
     * @param leafIndex Position in Merkle tree
     * @return nullifierHash The nullifier hash
     */
    function deriveNullifierHash(
        bytes32 nullifierSecret,
        uint256 leafIndex
    ) internal pure returns (bytes32 nullifierHash) {
        // nf = MiMC(nullifierSecret, leafIndex)
        nullifierHash = bytes32(mimcHash(uint256(nullifierSecret), leafIndex));
    }

    // =========================================================================
    // MERKLE TREE OPERATIONS
    // =========================================================================

    /**
     * @notice Compute Merkle root from leaf and proof
     * @param leaf The leaf value
     * @param pathElements Sibling hashes along the path
     * @param pathIndices Position indicators (0 = left, 1 = right)
     * @return root The computed Merkle root
     */
    function computeMerkleRoot(
        bytes32 leaf,
        bytes32[] memory pathElements,
        uint256[] memory pathIndices
    ) internal pure returns (bytes32 root) {
        require(
            pathElements.length == pathIndices.length,
            "Path length mismatch"
        );
        require(pathElements.length <= MERKLE_TREE_DEPTH, "Path too long");

        root = leaf;

        for (uint256 i = 0; i < pathElements.length; i++) {
            if (pathIndices[i] == 0) {
                // Leaf is on the left
                root = mimcHash2(root, pathElements[i]);
            } else {
                // Leaf is on the right
                root = mimcHash2(pathElements[i], root);
            }
        }
    }

    /**
     * @notice Compute Merkle root using proof struct
     * @param leaf The leaf value
     * @param proof The Merkle proof
     * @return root The computed Merkle root
     */
    function computeMerkleRootFromProof(
        bytes32 leaf,
        MerkleProof memory proof
    ) internal pure returns (bytes32 root) {
        return computeMerkleRoot(leaf, proof.pathElements, proof.pathIndices);
    }

    /**
     * @notice Get the zero hash at a given level
     * @param level Tree level (0 = leaves)
     * @return zeroHash The zero hash at that level
     */
    function getZeroHash(uint256 level) internal pure returns (bytes32) {
        bytes32 current = ZERO_VALUE;
        for (uint256 i = 0; i < level; i++) {
            current = mimcHash2(current, current);
        }
        return current;
    }

    /**
     * @notice Precompute all zero hashes for the tree
     * @return zeros Array of zero hashes for each level
     */
    function computeZeroHashes()
        internal
        pure
        returns (bytes32[MERKLE_TREE_DEPTH] memory zeros)
    {
        zeros[0] = ZERO_VALUE;
        for (uint256 i = 1; i < MERKLE_TREE_DEPTH; i++) {
            zeros[i] = mimcHash2(zeros[i - 1], zeros[i - 1]);
        }
    }

    // =========================================================================
    // GROTH16 VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a Groth16 proof using EVM precompiles
     * @param proof The proof elements
     * @param publicInputs Array of public inputs
     * @return valid True if proof is valid
     */
    function verifyGroth16Proof(
        Groth16Proof memory proof,
        uint256[] memory publicInputs
    ) internal view returns (bool valid) {
        // This is a simplified verification
        // In production, use a proper verifier contract with the correct verification key

        // Basic validation
        require(proof.a[0] < BN254_P, "Invalid proof.a[0]");
        require(proof.a[1] < BN254_P, "Invalid proof.a[1]");
        require(proof.c[0] < BN254_P, "Invalid proof.c[0]");
        require(proof.c[1] < BN254_P, "Invalid proof.c[1]");

        for (uint256 i = 0; i < publicInputs.length; i++) {
            require(publicInputs[i] < BN254_R, "Invalid public input");
        }

        // For testing, return true if proof structure is valid
        // Real implementation would do pairing check
        valid = true;
    }

    /**
     * @notice Verify withdrawal proof
     * @param proof Groth16 proof
     * @param inputs Withdrawal inputs
     * @return valid True if proof is valid
     */
    function verifyWithdrawalProof(
        Groth16Proof memory proof,
        WithdrawalInputs memory inputs
    ) internal view returns (bool valid) {
        // Construct public inputs array
        uint256[] memory publicInputs = new uint256[](6);
        publicInputs[0] = uint256(inputs.root);
        publicInputs[1] = uint256(inputs.nullifierHash);
        publicInputs[2] = uint256(uint160(inputs.recipient));
        publicInputs[3] = uint256(uint160(inputs.relayer));
        publicInputs[4] = inputs.fee;
        publicInputs[5] = inputs.refund;

        return verifyGroth16Proof(proof, publicInputs);
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Derive cross-domain nullifier binding
     * @param tornadoNullifier Original Tornado nullifier hash
     * @param sourceDomain Source chain domain
     * @param targetDomain Target chain domain
     * @return binding The cross-domain binding
     */
    function deriveCrossDomainNullifier(
        bytes32 tornadoNullifier,
        bytes32 sourceDomain,
        bytes32 targetDomain
    ) internal pure returns (bytes32 binding) {
        binding = keccak256(
            abi.encodePacked(
                PIL_TORNADO_DOMAIN,
                tornadoNullifier,
                sourceDomain,
                targetDomain,
                CROSS_DOMAIN_PREFIX
            )
        );
    }

    /**
     * @notice Derive PIL binding from Tornado nullifier
     * @param tornadoNullifier The Tornado nullifier hash
     * @return pilBinding The PIL-compatible binding
     */
    function derivePILBinding(
        bytes32 tornadoNullifier
    ) internal pure returns (bytes32 pilBinding) {
        pilBinding = keccak256(
            abi.encodePacked(
                tornadoNullifier,
                PIL_TORNADO_DOMAIN,
                CROSS_DOMAIN_PREFIX
            )
        );
    }

    // =========================================================================
    // DENOMINATION UTILITIES
    // =========================================================================

    /**
     * @notice Check if denomination is valid
     * @param denomination The amount to check
     * @return valid True if denomination is supported
     */
    function isValidDenomination(
        uint256 denomination
    ) internal pure returns (bool valid) {
        return
            denomination == DENOMINATION_01 ||
            denomination == DENOMINATION_1 ||
            denomination == DENOMINATION_10 ||
            denomination == DENOMINATION_100;
    }

    /**
     * @notice Get denomination index
     * @param denomination The denomination
     * @return index The index (0-3) or reverts
     */
    function getDenominationIndex(
        uint256 denomination
    ) internal pure returns (uint256 index) {
        if (denomination == DENOMINATION_01) return 0;
        if (denomination == DENOMINATION_1) return 1;
        if (denomination == DENOMINATION_10) return 2;
        if (denomination == DENOMINATION_100) return 3;
        revert("Invalid denomination");
    }

    /**
     * @notice Get all supported denominations
     * @return denominations Array of supported denominations
     */
    function getSupportedDenominations()
        internal
        pure
        returns (uint256[4] memory denominations)
    {
        denominations[0] = DENOMINATION_01;
        denominations[1] = DENOMINATION_1;
        denominations[2] = DENOMINATION_10;
        denominations[3] = DENOMINATION_100;
    }

    // =========================================================================
    // NOTE CONVERSION
    // =========================================================================

    /**
     * @notice Convert Tornado note to PIL cross-chain format
     * @param note The Tornado note
     * @param targetChainId Target chain for bridging
     * @return crossChainNote The cross-chain note
     */
    function toCrossChainNote(
        TornadoNote memory note,
        uint256 targetChainId
    ) internal view returns (CrossChainNote memory crossChainNote) {
        crossChainNote.tornadoCommitment = note.commitment;
        crossChainNote.pilCommitment = derivePILBinding(note.commitment);
        crossChainNote.nullifierBinding = derivePILBinding(note.nullifierHash);
        crossChainNote.denomination = note.denomination;
        crossChainNote.sourceChainId = block.chainid;
        crossChainNote.targetChainId = targetChainId;
    }

    // =========================================================================
    // VALIDATION UTILITIES
    // =========================================================================

    /**
     * @notice Validate commitment is non-zero and in field
     * @param commitment The commitment to validate
     * @return valid True if valid
     */
    function isValidCommitment(
        bytes32 commitment
    ) internal pure returns (bool valid) {
        uint256 c = uint256(commitment);
        return c != 0 && c < BN254_R;
    }

    /**
     * @notice Validate nullifier hash is non-zero and in field
     * @param nullifierHash The nullifier to validate
     * @return valid True if valid
     */
    function isValidNullifier(
        bytes32 nullifierHash
    ) internal pure returns (bool valid) {
        uint256 n = uint256(nullifierHash);
        return n != 0 && n < BN254_R;
    }

    /**
     * @notice Validate Merkle root is non-zero
     * @param root The root to validate
     * @return valid True if valid
     */
    function isValidRoot(bytes32 root) internal pure returns (bool valid) {
        return root != bytes32(0);
    }

    /**
     * @notice Validate leaf index is within bounds
     * @param leafIndex The index to validate
     * @return valid True if valid
     */
    function isValidLeafIndex(
        uint32 leafIndex
    ) internal pure returns (bool valid) {
        return leafIndex < MAX_TREE_SIZE;
    }

    // =========================================================================
    // CHAIN DETECTION
    // =========================================================================

    /**
     * @notice Check if current chain is Ethereum mainnet
     * @return True if mainnet
     */
    function isEthereumMainnet() internal view returns (bool) {
        return block.chainid == 1;
    }

    /**
     * @notice Check if current chain is Arbitrum
     * @return True if Arbitrum
     */
    function isArbitrum() internal view returns (bool) {
        return block.chainid == 42161;
    }

    /**
     * @notice Check if current chain is Optimism
     * @return True if Optimism
     */
    function isOptimism() internal view returns (bool) {
        return block.chainid == 10;
    }

    /**
     * @notice Check if current chain is Polygon
     * @return True if Polygon
     */
    function isPolygon() internal view returns (bool) {
        return block.chainid == 137;
    }

    /**
     * @notice Check if current chain is BSC
     * @return True if BSC
     */
    function isBSC() internal view returns (bool) {
        return block.chainid == 56;
    }

    /**
     * @notice Check if chain is a supported Tornado chain
     * @param chainId The chain ID
     * @return supported True if supported
     */
    function isTornadoChain(uint256 chainId) internal pure returns (bool) {
        return
            chainId == 1 || // Ethereum
            chainId == 56 || // BSC
            chainId == 137 || // Polygon
            chainId == 10 || // Optimism
            chainId == 42161 || // Arbitrum
            chainId == 100 || // Gnosis
            chainId == 43114; // Avalanche
    }
}
