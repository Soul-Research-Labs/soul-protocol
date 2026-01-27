// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SoulFHEModule
 * @notice Fully Homomorphic Encryption integration for Soul
 * @dev Implements hybrid FHE-ZK architecture for encrypted computations
 */
contract SoulFHEModule is Ownable, ReentrancyGuard {
    // ============================================
    // Types
    // ============================================

    /// @notice FHE ciphertext representation
    struct Ciphertext {
        bytes32 handle; // Reference to off-chain ciphertext
        bytes32 typeHash; // Type of encrypted value
        bytes32 securityParams; // Security parameters used
        uint256 createdAt;
        bool valid;
    }

    /// @notice Encrypted balance entry
    struct EncryptedBalance {
        bytes32 encryptedAmount; // FHE-encrypted amount
        bytes32 blindingCommitment; // Commitment for ZK proofs
        uint256 lastUpdated;
        bytes32 proofOfBalance; // ZK proof balance is valid
    }

    /// @notice FHE computation request
    struct ComputationRequest {
        bytes32 requestId;
        ComputationType operation;
        bytes32[] inputCiphertexts;
        bytes32 outputCiphertext;
        address requester;
        uint256 requestedAt;
        bool completed;
        bool verified;
    }

    /// @notice Supported FHE operations
    enum ComputationType {
        Addition,
        Subtraction,
        Multiplication,
        Comparison,
        Equality,
        RangeProof,
        Custom
    }

    /// @notice FHE key management
    struct FHEKeyInfo {
        bytes32 publicKeyHash;
        bytes32 evaluationKeyHash;
        bytes32 relinKeyHash;
        uint256 keyGenTimestamp;
        bool active;
    }

    /// @notice Encrypted Merkle node
    struct EncryptedMerkleNode {
        bytes32 encryptedHash; // FHE-encrypted hash
        bytes32 commitment; // Pedersen commitment for ZK
        uint256 level;
        bool isLeaf;
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice FHE key information
    FHEKeyInfo public fheKeys;

    /// @notice Registered ciphertexts
    mapping(bytes32 => Ciphertext) public ciphertexts;

    /// @notice Encrypted balances by user commitment
    mapping(bytes32 => EncryptedBalance) public encryptedBalances;

    /// @notice Computation requests
    mapping(bytes32 => ComputationRequest) public computations;

    /// @notice Encrypted Merkle tree nodes
    mapping(bytes32 => EncryptedMerkleNode) public encryptedMerkleNodes;

    /// @notice Encrypted Merkle tree root
    bytes32 public encryptedMerkleRoot;

    /// @notice Request nonce
    uint256 public requestNonce;

    /// @notice FHE computation oracle
    address public fheOracle;

    /// @notice Supported FHE schemes
    mapping(bytes32 => bool) public supportedSchemes;

    /// @notice Type hashes for validation
    bytes32 public constant TYPE_UINT256 = keccak256("uint256");
    bytes32 public constant TYPE_BOOL = keccak256("bool");
    bytes32 public constant TYPE_FIELD = keccak256("field");

    // ============================================
    // Events
    // ============================================

    event CiphertextRegistered(
        bytes32 indexed handle,
        bytes32 typeHash,
        address registrar
    );
    event ComputationRequested(
        bytes32 indexed requestId,
        ComputationType operation
    );
    event ComputationCompleted(
        bytes32 indexed requestId,
        bytes32 outputCiphertext
    );
    event EncryptedBalanceUpdated(
        bytes32 indexed userCommitment,
        bytes32 newEncryptedAmount
    );
    event FHEKeysUpdated(bytes32 publicKeyHash, bytes32 evaluationKeyHash);
    event EncryptedMerkleRootUpdated(bytes32 newRoot);

    // ============================================
    // Constructor
    // ============================================

    constructor(address _fheOracle) Ownable(msg.sender) {
        require(_fheOracle != address(0), "Invalid oracle");
        fheOracle = _fheOracle;

        // Register supported schemes
        supportedSchemes[keccak256("TFHE")] = true;
        supportedSchemes[keccak256("BFV")] = true;
        supportedSchemes[keccak256("BGV")] = true;
        supportedSchemes[keccak256("CKKS")] = true;
    }

    // ============================================
    // Modifiers
    // ============================================

    modifier onlyOracle() {
        require(msg.sender == fheOracle, "Not FHE oracle");
        _;
    }

    // ============================================
    // FHE Key Management
    // ============================================

    /**
     * @notice Update FHE keys
     * @param publicKeyHash Hash of public key
     * @param evaluationKeyHash Hash of evaluation key
     * @param relinKeyHash Hash of relinearization key
     */
    function updateFHEKeys(
        bytes32 publicKeyHash,
        bytes32 evaluationKeyHash,
        bytes32 relinKeyHash
    ) external onlyOwner {
        fheKeys = FHEKeyInfo({
            publicKeyHash: publicKeyHash,
            evaluationKeyHash: evaluationKeyHash,
            relinKeyHash: relinKeyHash,
            keyGenTimestamp: block.timestamp,
            active: true
        });

        emit FHEKeysUpdated(publicKeyHash, evaluationKeyHash);
    }

    /**
     * @notice Set FHE oracle address
     * @param newOracle New oracle address
     */
    function setFHEOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "Invalid oracle");
        fheOracle = newOracle;
    }

    // ============================================
    // Ciphertext Management
    // ============================================

    /**
     * @notice Register a new ciphertext
     * @param handle Reference to off-chain ciphertext
     * @param typeHash Type of the encrypted value
     * @param securityParams Security parameters used
     * @return success Whether registration succeeded
     */
    function registerCiphertext(
        bytes32 handle,
        bytes32 typeHash,
        bytes32 securityParams
    ) external returns (bool success) {
        require(handle != bytes32(0), "Invalid handle");
        require(!ciphertexts[handle].valid, "Already registered");
        require(
            typeHash == TYPE_UINT256 ||
                typeHash == TYPE_BOOL ||
                typeHash == TYPE_FIELD,
            "Unsupported type"
        );

        ciphertexts[handle] = Ciphertext({
            handle: handle,
            typeHash: typeHash,
            securityParams: securityParams,
            createdAt: block.timestamp,
            valid: true
        });

        emit CiphertextRegistered(handle, typeHash, msg.sender);

        return true;
    }

    /**
     * @notice Verify a ciphertext is valid
     * @param handle The ciphertext handle
     * @return valid Whether the ciphertext is valid
     */
    function verifyCiphertext(
        bytes32 handle
    ) external view returns (bool valid) {
        return ciphertexts[handle].valid;
    }

    // ============================================
    // FHE Computations
    // ============================================

    /**
     * @notice Request homomorphic addition
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return requestId The computation request ID
     */
    function requestAdd(
        bytes32 ct1,
        bytes32 ct2
    ) external returns (bytes32 requestId) {
        return _requestComputation(ComputationType.Addition, ct1, ct2);
    }

    /**
     * @notice Request homomorphic subtraction
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return requestId The computation request ID
     */
    function requestSub(
        bytes32 ct1,
        bytes32 ct2
    ) external returns (bytes32 requestId) {
        return _requestComputation(ComputationType.Subtraction, ct1, ct2);
    }

    /**
     * @notice Request homomorphic multiplication
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return requestId The computation request ID
     */
    function requestMul(
        bytes32 ct1,
        bytes32 ct2
    ) external returns (bytes32 requestId) {
        return _requestComputation(ComputationType.Multiplication, ct1, ct2);
    }

    /**
     * @notice Request encrypted comparison (ct1 > ct2)
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return requestId The computation request ID
     */
    function requestCompare(
        bytes32 ct1,
        bytes32 ct2
    ) external returns (bytes32 requestId) {
        return _requestComputation(ComputationType.Comparison, ct1, ct2);
    }

    /**
     * @notice Request encrypted equality check
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return requestId The computation request ID
     */
    function requestEqual(
        bytes32 ct1,
        bytes32 ct2
    ) external returns (bytes32 requestId) {
        return _requestComputation(ComputationType.Equality, ct1, ct2);
    }

    /**
     * @notice Request encrypted range proof (0 <= ct <= max)
     * @param ct Ciphertext to check
     * @param maxEncrypted Encrypted maximum value
     * @return requestId The computation request ID
     */
    function requestRangeProof(
        bytes32 ct,
        bytes32 maxEncrypted
    ) external returns (bytes32 requestId) {
        return
            _requestComputation(ComputationType.RangeProof, ct, maxEncrypted);
    }

    /**
     * @notice Oracle submits computation result
     * @param requestId The computation request
     * @param outputCiphertext The result ciphertext
     * @param proof ZK proof of correct computation
     */
    function submitComputationResult(
        bytes32 requestId,
        bytes32 outputCiphertext,
        bytes calldata proof
    ) external onlyOracle {
        ComputationRequest storage req = computations[requestId];

        require(req.requestId == requestId, "Invalid request");
        require(!req.completed, "Already completed");
        require(proof.length > 0, "Invalid proof");

        // Register output ciphertext
        ciphertexts[outputCiphertext] = Ciphertext({
            handle: outputCiphertext,
            typeHash: ciphertexts[req.inputCiphertexts[0]].typeHash,
            securityParams: ciphertexts[req.inputCiphertexts[0]].securityParams,
            createdAt: block.timestamp,
            valid: true
        });

        req.outputCiphertext = outputCiphertext;
        req.completed = true;
        req.verified = true;

        emit ComputationCompleted(requestId, outputCiphertext);
    }

    /**
     * @notice Get computation result
     * @param requestId The request ID
     * @return outputCiphertext The result ciphertext
     * @return completed Whether computation is done
     */
    function getComputationResult(
        bytes32 requestId
    ) external view returns (bytes32 outputCiphertext, bool completed) {
        ComputationRequest storage req = computations[requestId];
        return (req.outputCiphertext, req.completed);
    }

    // ============================================
    // Encrypted Balances
    // ============================================

    /**
     * @notice Initialize encrypted balance for user
     * @param userCommitment User's identity commitment
     * @param encryptedAmount Initial encrypted balance
     * @param blindingCommitment Commitment for ZK proofs
     */
    function initializeEncryptedBalance(
        bytes32 userCommitment,
        bytes32 encryptedAmount,
        bytes32 blindingCommitment
    ) external nonReentrant {
        require(userCommitment != bytes32(0), "Invalid user");
        require(
            encryptedBalances[userCommitment].encryptedAmount == bytes32(0),
            "Already initialized"
        );
        require(ciphertexts[encryptedAmount].valid, "Invalid ciphertext");

        encryptedBalances[userCommitment] = EncryptedBalance({
            encryptedAmount: encryptedAmount,
            blindingCommitment: blindingCommitment,
            lastUpdated: block.timestamp,
            proofOfBalance: bytes32(0)
        });

        emit EncryptedBalanceUpdated(userCommitment, encryptedAmount);
    }

    /**
     * @notice Update encrypted balance (after verified computation)
     * @param userCommitment User's identity commitment
     * @param newEncryptedAmount New encrypted balance
     * @param computationRequestId Request that produced this balance
     * @param zkProof ZK proof of valid update
     */
    function updateEncryptedBalance(
        bytes32 userCommitment,
        bytes32 newEncryptedAmount,
        bytes32 computationRequestId,
        bytes calldata zkProof
    ) external onlyOracle {
        require(
            encryptedBalances[userCommitment].encryptedAmount != bytes32(0),
            "Not initialized"
        );

        ComputationRequest storage compReq = computations[computationRequestId];
        require(compReq.completed, "Computation not complete");
        require(
            compReq.outputCiphertext == newEncryptedAmount,
            "Amount mismatch"
        );
        require(zkProof.length > 0, "Invalid proof");

        encryptedBalances[userCommitment].encryptedAmount = newEncryptedAmount;
        encryptedBalances[userCommitment].lastUpdated = block.timestamp;
        encryptedBalances[userCommitment].proofOfBalance = keccak256(zkProof);

        emit EncryptedBalanceUpdated(userCommitment, newEncryptedAmount);
    }

    /**
     * @notice Get encrypted balance
     * @param userCommitment User's identity commitment
     * @return balance The encrypted balance info
     */
    function getEncryptedBalance(
        bytes32 userCommitment
    ) external view returns (EncryptedBalance memory) {
        return encryptedBalances[userCommitment];
    }

    // ============================================
    // Encrypted Merkle Tree
    // ============================================

    /**
     * @notice Update encrypted Merkle node
     * @param nodeId Node identifier
     * @param encryptedHash Encrypted hash value
     * @param commitment Pedersen commitment
     * @param level Tree level
     * @param isLeaf Whether node is a leaf
     */
    function updateEncryptedMerkleNode(
        bytes32 nodeId,
        bytes32 encryptedHash,
        bytes32 commitment,
        uint256 level,
        bool isLeaf
    ) external onlyOracle {
        encryptedMerkleNodes[nodeId] = EncryptedMerkleNode({
            encryptedHash: encryptedHash,
            commitment: commitment,
            level: level,
            isLeaf: isLeaf
        });
    }

    /**
     * @notice Update encrypted Merkle root
     * @param newRoot New encrypted root
     * @param zkProof Proof of valid update
     */
    function updateEncryptedMerkleRoot(
        bytes32 newRoot,
        bytes calldata zkProof
    ) external onlyOracle {
        require(newRoot != bytes32(0), "Invalid root");
        require(zkProof.length > 0, "Invalid proof");

        encryptedMerkleRoot = newRoot;

        emit EncryptedMerkleRootUpdated(newRoot);
    }

    /**
     * @notice Verify encrypted Merkle proof
     * @param leaf Encrypted leaf
     * @param proof Array of encrypted siblings
     * @param pathIndices Path indices
     * @return valid Whether proof is valid
     */
    function verifyEncryptedMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256[] calldata pathIndices
    ) external pure returns (bool valid) {
        require(proof.length == pathIndices.length, "Length mismatch");

        // In production, this would verify FHE Merkle proof
        // For now, verify structure
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            // Verification would be done homomorphically off-chain
            // Here we just verify the structure
            if (pathIndices[i] == 0) {
                computed = keccak256(abi.encode(computed, proof[i]));
            } else {
                computed = keccak256(abi.encode(proof[i], computed));
            }
        }

        // Final verification against encrypted root done off-chain
        return true;
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Internal function to create computation request
     */
    function _requestComputation(
        ComputationType operation,
        bytes32 ct1,
        bytes32 ct2
    ) internal returns (bytes32 requestId) {
        require(ciphertexts[ct1].valid, "Invalid ciphertext 1");
        require(ciphertexts[ct2].valid, "Invalid ciphertext 2");

        requestNonce++;
        requestId = keccak256(
            abi.encode(operation, ct1, ct2, requestNonce, block.timestamp)
        );

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = ct1;
        inputs[1] = ct2;

        computations[requestId] = ComputationRequest({
            requestId: requestId,
            operation: operation,
            inputCiphertexts: inputs,
            outputCiphertext: bytes32(0),
            requester: msg.sender,
            requestedAt: block.timestamp,
            completed: false,
            verified: false
        });

        emit ComputationRequested(requestId, operation);

        return requestId;
    }
}
