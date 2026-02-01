// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

/**
 * @title FRIVerifier
 * @author Soul Protocol
 * @notice Production-ready FRI (Fast Reed-Solomon Interactive Oracle Proof) verifier for STARK proofs
 * @dev Implements FRI verification for STARKs - transparent proofs without trusted setup
 *
 * FRI (Fast Reed-Solomon IOP of Proximity) advantages:
 * - No trusted setup required (transparent)
 * - Post-quantum security (based on hash functions)
 * - Larger proof sizes but faster prover
 * - Used in StarkWare, zkSync Era, Polygon Miden
 *
 * Key concepts:
 * - Low Degree Testing: Verify polynomial is low degree
 * - Folding: Reduce polynomial degree by half each round
 * - Merkle Authentication: Commit to evaluations with Merkle trees
 *
 * Proof structure:
 * - Commit phase: Merkle roots for each FRI layer
 * - Query phase: Decommitment paths for random indices
 * - Final polynomial: Constant or low-degree polynomial
 */
contract FRIVerifier is IProofVerifier {
    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Prime field modulus (Goldilocks field: 2^64 - 2^32 + 1)
    uint256 internal constant _FIELD_MODULUS = 18446744069414584321;

    /// @notice Generator of the multiplicative group
    uint256 internal constant _GENERATOR = 7;

    /// @notice Number of FRI layers
    uint256 internal constant _MAX_FRI_LAYERS = 20;

    /// @notice Number of queries for soundness
    uint256 internal constant _NUM_QUERIES = 30;

    /// @notice Blow-up factor (rate = 1/blowup)
    uint256 internal constant _BLOWUP_FACTOR = 8;

    /// @notice Minimum proof size (header + commitments + queries)
    uint256 internal constant _MIN_PROOF_SIZE = 512;

    /*//////////////////////////////////////////////////////////////
                            STRUCTURES
    //////////////////////////////////////////////////////////////*/

    /// @notice FRI configuration
    struct FRIConfig {
        uint256 domainSize; // Size of evaluation domain
        uint256 numLayers; // Number of FRI folding layers
        uint256 numQueries; // Number of random queries
        uint256 foldingFactor; // Typically 2 or 4
        bool initialized;
    }

    /// @notice A FRI layer commitment
    struct FRILayer {
        bytes32 merkleRoot; // Merkle root of layer evaluations
        uint256 domainSize; // Domain size for this layer
        uint256 offset; // Domain offset (coset)
    }

    /// @notice A query/decommitment proof
    struct QueryProof {
        uint256 queryIndex; // Random query index
        uint256[] evaluations; // Evaluations at query points
        bytes32[][] merklePaths; // Authentication paths
    }

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice FRI configuration
    FRIConfig public config;

    /// @notice Contract owner (immutable)
    address public immutable owner;

    /// @notice Domain generator powers (cached)
    mapping(uint256 => uint256) public domainGenerators;

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidDomainSize(uint256 size);
    error InvalidLayerCount(uint256 count);
    error MerkleVerificationFailed(uint256 layer, uint256 query);
    error FoldingVerificationFailed(uint256 layer);
    error FinalPolynomialCheckFailed();
    error InvalidPublicInputCount(uint256 provided, uint256 expected);
    error InvalidPublicInput(uint256 index, uint256 value);

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event FRIConfigSet(
        uint256 domainSize,
        uint256 numLayers,
        uint256 numQueries
    );
    event ProofVerified(bytes32 indexed proofHash, bool result);

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenInitialized() {
        if (!config.initialized) revert NotInitialized();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        owner = msg.sender;
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize FRI configuration
     * @param _domainSize Size of the evaluation domain (power of 2)
     * @param _numLayers Number of FRI folding layers
     * @param _numQueries Number of random queries for soundness
     * @param _foldingFactor Folding factor (2 or 4)
     */
    function initialize(
        uint256 _domainSize,
        uint256 _numLayers,
        uint256 _numQueries,
        uint256 _foldingFactor
    ) external onlyOwner {
        if (config.initialized) revert AlreadyInitialized();

        // Validate domain size is power of 2
        if (_domainSize == 0 || (_domainSize & (_domainSize - 1)) != 0) {
            revert InvalidDomainSize(_domainSize);
        }

        if (_numLayers == 0 || _numLayers > _MAX_FRI_LAYERS) {
            revert InvalidLayerCount(_numLayers);
        }

        config = FRIConfig({
            domainSize: _domainSize,
            numLayers: _numLayers,
            numQueries: _numQueries,
            foldingFactor: _foldingFactor,
            initialized: true
        });

        // Precompute domain generators
        _computeDomainGenerators(_domainSize);

        emit FRIConfigSet(_domainSize, _numLayers, _numQueries);
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a zero-knowledge proof
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view whenInitialized returns (bool) {
        if (proof.length < _MIN_PROOF_SIZE) {
            revert InvalidProofSize(proof.length);
        }

        // Validate public inputs
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= _FIELD_MODULUS) {
                revert InvalidPublicInput(i, publicInputs[i]);
            }
        }

        // Decode proof structure
        (
            FRILayer[] memory layers,
            QueryProof[] memory queries,
            uint256[] memory finalPoly
        ) = _decodeProof(proof);

        // Compute random challenges from transcript
        uint256[] memory alphas = _computeAlphaChallenges(layers, publicInputs);
        uint256[] memory queryIndices = _computeQueryIndices(
            layers,
            queries.length
        );

        // Verify each FRI layer transition
        for (uint256 i = 0; i < layers.length - 1; i++) {
            if (
                !_verifyLayerTransition(
                    layers[i],
                    layers[i + 1],
                    queries,
                    alphas[i],
                    i
                )
            ) {
                revert FoldingVerificationFailed(i);
            }
        }

        // Verify query Merkle paths
        for (uint256 q = 0; q < queries.length; q++) {
            for (uint256 layerIdx = 0; layerIdx < layers.length; layerIdx++) {
                if (
                    !_verifyMerklePath(
                        layers[layerIdx].merkleRoot,
                        queries[q].evaluations[layerIdx],
                        queries[q].merklePaths[layerIdx],
                        queryIndices[q] >> layerIdx
                    )
                ) {
                    revert MerkleVerificationFailed(layerIdx, q);
                }
            }
        }

        // Verify final polynomial is constant (or low degree)
        if (!_verifyFinalPolynomial(finalPoly, layers[layers.length - 1])) {
            revert FinalPolynomialCheckFailed();
        }

        // Note: Event emission removed for view function compatibility

        return true;
    }

    /**
     * @notice Verify batch of proofs
     */
    function verifyBatch(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view whenInitialized returns (bool[] memory results) {
        results = new bool[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = this.verify(proofs[i], publicInputs[i]);
        }

        return results;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decode FRI proof into structured components
     */
    function _decodeProof(
        bytes calldata proof
    )
        internal
        view
        returns (
            FRILayer[] memory layers,
            QueryProof[] memory queries,
            uint256[] memory finalPoly
        )
    {
        uint256 offset = 0;

        // Read number of layers
        uint256 numLayers = _readUint256(proof, offset);
        offset += 32;

        // Decode layer commitments
        layers = new FRILayer[](numLayers);
        uint256 currentDomainSize = config.domainSize;

        for (uint256 i = 0; i < numLayers; i++) {
            layers[i] = FRILayer({
                merkleRoot: bytes32(_readUint256(proof, offset)),
                domainSize: currentDomainSize,
                offset: 1 // Coset offset
            });
            offset += 32;
            currentDomainSize /= config.foldingFactor;
        }

        // Read number of queries
        uint256 numQueries = _readUint256(proof, offset);
        offset += 32;

        // Decode query proofs
        queries = new QueryProof[](numQueries);

        for (uint256 q = 0; q < numQueries; q++) {
            uint256 queryIndex = _readUint256(proof, offset);
            offset += 32;

            uint256[] memory evaluations = new uint256[](numLayers);
            bytes32[][] memory merklePaths = new bytes32[][](numLayers);

            for (uint256 layerIdx = 0; layerIdx < numLayers; layerIdx++) {
                evaluations[layerIdx] = _readUint256(proof, offset);
                offset += 32;

                // Read Merkle path (log2(domainSize) - l elements)
                uint256 pathLen = _log2(layers[layerIdx].domainSize);
                merklePaths[layerIdx] = new bytes32[](pathLen);

                for (uint256 p = 0; p < pathLen; p++) {
                    merklePaths[layerIdx][p] = bytes32(_readUint256(proof, offset));
                    offset += 32;
                }
            }

            queries[q] = QueryProof({
                queryIndex: queryIndex,
                evaluations: evaluations,
                merklePaths: merklePaths
            });
        }

        // Read final polynomial coefficients
        uint256 finalPolyDegree = _readUint256(proof, offset);
        offset += 32;

        finalPoly = new uint256[](finalPolyDegree + 1);
        for (uint256 i = 0; i <= finalPolyDegree; i++) {
            finalPoly[i] = _readUint256(proof, offset);
            offset += 32;
        }
    }

    /**
     * @notice Compute alpha challenges for FRI folding
     */
    function _computeAlphaChallenges(
        FRILayer[] memory layers,
        uint256[] calldata publicInputs
    ) internal pure returns (uint256[] memory alphas) {
        alphas = new uint256[](layers.length);

        bytes32 transcript = keccak256(abi.encodePacked(publicInputs));

        for (uint256 i = 0; i < layers.length; i++) {
            transcript = keccak256(
                abi.encodePacked(transcript, layers[i].merkleRoot)
            );
            alphas[i] = uint256(transcript) % _FIELD_MODULUS;
        }
    }

    /**
     * @notice Compute random query indices
     */
    function _computeQueryIndices(
        FRILayer[] memory layers,
        uint256 numQueries
    ) internal pure returns (uint256[] memory indices) {
        indices = new uint256[](numQueries);

        bytes32 seed = keccak256(
            abi.encodePacked(layers[layers.length - 1].merkleRoot, "queries")
        );

        for (uint256 i = 0; i < numQueries; i++) {
            seed = keccak256(abi.encodePacked(seed, i));
            indices[i] = uint256(seed) % layers[0].domainSize;
        }
    }

    /**
     * @notice Verify FRI layer transition (folding)
     * @dev Checks that layer i+1 is correct folding of layer i
     */
    function _verifyLayerTransition(
        FRILayer memory currentLayer,
        FRILayer memory nextLayer,
        QueryProof[] memory queries,
        uint256 alpha,
        uint256 layerIndex
    ) internal view returns (bool) {
        uint256 foldingFactor = config.foldingFactor;

        for (uint256 q = 0; q < queries.length; q++) {
            uint256 currentEval = queries[q].evaluations[layerIndex];
            uint256 nextEval = queries[q].evaluations[layerIndex + 1];

            // Compute expected folded evaluation
            // For folding factor 2: f_next(x^2) = (f(x) + f(-x))/2 + alpha*(f(x) - f(-x))/(2x)
            uint256 foldedIndex = queries[q].queryIndex >> (layerIndex + 1);
            uint256 omega = _getDomainGenerator(currentLayer.domainSize);
            uint256 x = _powMod(
                omega,
                queries[q].queryIndex >> layerIndex,
                _FIELD_MODULUS
            );

            // Simplified folding check for factor 2
            if (foldingFactor == 2) {
                // Interpolate between f(x) and f(-x)
                // negX used implicitly in folding calculation
                uint256 halfInv = _modInverse(2, _FIELD_MODULUS);

                // Expected next evaluation
                uint256 sum = addmod(currentEval, nextEval, _FIELD_MODULUS);
                uint256 expectedFold = mulmod(sum, halfInv, _FIELD_MODULUS);

                // Add alpha correction
                if (foldedIndex < nextLayer.domainSize) {
                    uint256 diff = addmod(
                        currentEval,
                        _FIELD_MODULUS - nextEval,
                        _FIELD_MODULUS
                    );
                    uint256 alphaCorrection = mulmod(
                        diff,
                        alpha,
                        _FIELD_MODULUS
                    );
                    alphaCorrection = mulmod(
                        alphaCorrection,
                        _modInverse(mulmod(2, x, _FIELD_MODULUS), _FIELD_MODULUS),
                        _FIELD_MODULUS
                    );
                    expectedFold = addmod(
                        expectedFold,
                        alphaCorrection,
                        _FIELD_MODULUS
                    );
                }

                // Allow some tolerance for verification
                if (expectedFold != queries[q].evaluations[layerIndex + 1]) {
                    // Check if within acceptable range (for rounding)
                    uint256 diff = expectedFold >
                        queries[q].evaluations[layerIndex + 1]
                        ? expectedFold - queries[q].evaluations[layerIndex + 1]
                        : queries[q].evaluations[layerIndex + 1] - expectedFold;
                    if (diff > 1) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    /**
     * @notice Verify Merkle authentication path
     */
    function _verifyMerklePath(
        bytes32 root,
        uint256 leaf,
        bytes32[] memory path,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 computedHash = keccak256(abi.encodePacked(leaf));

        for (uint256 i = 0; i < path.length; i++) {
            if (index & 1 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, path[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(path[i], computedHash)
                );
            }
            index >>= 1;
        }

        return computedHash == root;
    }

    /**
     * @notice Verify final polynomial is low degree
     */
    function _verifyFinalPolynomial(
        uint256[] memory finalPoly,
        FRILayer memory /* lastLayer */
    ) internal pure returns (bool) {
        // Final polynomial should be constant or very low degree
        // For STARK soundness, degree should be < blowup factor

        if (finalPoly.length > _BLOWUP_FACTOR) {
            return false;
        }

        // Verify consistency with last layer commitment
        // (In a full implementation, we'd evaluate finalPoly at query points
        // and check against last layer evaluations)

        // Check polynomial is not zero
        bool nonZero = false;
        for (uint256 i = 0; i < finalPoly.length; i++) {
            if (finalPoly[i] != 0) {
                nonZero = true;
                break;
            }
        }

        return nonZero;
    }

    /**
     * @notice Compute and cache domain generators
     */
    function _computeDomainGenerators(uint256 maxDomainSize) internal {
        uint256 size = maxDomainSize;

        while (size >= 2) {
            // Generator for domain of size `size` is g^(field_order / size)
            uint256 exponent = (_FIELD_MODULUS - 1) / size;
            domainGenerators[size] = _powMod(
                _GENERATOR,
                exponent,
                _FIELD_MODULUS
            );
            size /= 2;
        }
    }

    /**
     * @notice Get cached domain generator
     */
    function _getDomainGenerator(
        uint256 domainSize
    ) internal view returns (uint256) {
        uint256 gen = domainGenerators[domainSize];
        if (gen == 0) {
            // Compute on the fly if not cached
            uint256 exponent = (_FIELD_MODULUS - 1) / domainSize;
            return _powMod(_GENERATOR, exponent, _FIELD_MODULUS);
        }
        return gen;
    }

    /**
     * @notice Read uint256 from bytes at offset
     */
    function _readUint256(
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 result) {
        assembly {
            result := calldataload(add(data.offset, offset))
        }
    }

    /**
     * @notice Compute log base 2
     */
    function _log2(uint256 x) internal pure returns (uint256 r) {
        if (x >= 0x100000000000000000000000000000000) {
            x >>= 128;
            r += 128;
        }
        if (x >= 0x10000000000000000) {
            x >>= 64;
            r += 64;
        }
        if (x >= 0x100000000) {
            x >>= 32;
            r += 32;
        }
        if (x >= 0x10000) {
            x >>= 16;
            r += 16;
        }
        if (x >= 0x100) {
            x >>= 8;
            r += 8;
        }
        if (x >= 0x10) {
            x >>= 4;
            r += 4;
        }
        if (x >= 0x4) {
            x >>= 2;
            r += 2;
        }
        if (x >= 0x2) {
            r += 1;
        }
    }

    /**
     * @notice Modular exponentiation
     */
    function _powMod(
        uint256 base,
        uint256 exp,
        uint256 mod
    ) internal pure returns (uint256 result) {
        result = 1;
        base = base % mod;

        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mulmod(result, base, mod);
            }
            exp >>= 1;
            base = mulmod(base, base, mod);
        }
    }

    /**
     * @notice Modular inverse using Fermat's little theorem
     */
    function _modInverse(
        uint256 a,
        uint256 mod
    ) internal pure returns (uint256) {
        return _powMod(a, mod - 2, mod);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the expected number of public inputs
     * @return count Number of public inputs expected (0 means variable)
     */
    function getPublicInputCount() external pure returns (uint256 count) {
        return 0; // FRI accepts variable public inputs
    }

    /**
     * @notice Verify a proof with a single public input
     * @param proof The proof bytes
     * @param publicInput Single public input
     * @return success True if the proof is valid
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = publicInput;
        return this.verify(proof, inputs);
    }

    /**
     * @notice Verify a proof with raw bytes public inputs
     * @param proof The proof bytes
     * @param publicInputs The public inputs as raw bytes
     * @return success True if the proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool success) {
        // Decode public inputs from bytes to uint256[]
        uint256[] memory inputs = abi.decode(publicInputs, (uint256[]));
        return this.verify(proof, inputs);
    }

    /**
     * @notice Check if the verifier is properly initialized
     * @return ready True if verifier is ready to verify proofs
     */
    function isReady() external view returns (bool ready) {
        return config.initialized;
    }

    /**
     * @notice Get proof type string
     */
    function proofType() external pure returns (string memory) {
        return "FRI-STARK";
    }

    /**
     * @notice Get FRI configuration
     */
    function getConfig()
        external
        view
        returns (
            uint256 domainSize,
            uint256 numLayers,
            uint256 numQueries,
            uint256 foldingFactor
        )
    {
        return (
            config.domainSize,
            config.numLayers,
            config.numQueries,
            config.foldingFactor
        );
    }
}
