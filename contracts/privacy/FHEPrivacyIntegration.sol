// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title FHEPrivacyIntegration
/// @notice Implements Fully Homomorphic Encryption integration for private computation
/// @dev Based on TFHE (Torus FHE) and Zama's fhEVM architecture
///      Enables computation on encrypted data without decryption
/// @custom:security-contact security@soulprotocol.io
/// @custom:research-status Research implementation
contract FHEPrivacyIntegration is AccessControl, ReentrancyGuard {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Domain separator
    bytes32 public constant FHE_DOMAIN = keccak256("Soul_FHE_V1");

    /// @notice Maximum ciphertext size (in bytes)
    uint256 public constant MAX_CIPHERTEXT_SIZE = 32768; // 32KB

    /// @notice TFHE parameter set identifier
    uint256 public constant TFHE_PARAMS_128 = 128; // 128-bit security

    /// @notice Relinearization key size
    uint256 public constant RELIN_KEY_SIZE = 4096;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant KEY_MANAGER_ROLE = keccak256("KEY_MANAGER_ROLE");

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice FHE ciphertext structure
    struct FHECiphertext {
        bytes ciphertext; // Encrypted data
        bytes32 ciphertextHash; // Hash for verification
        CiphertextType ctype; // Data type
        uint256 securityLevel; // Security parameter
        uint256 timestamp; // Creation time
    }

    /// @notice Ciphertext types supported
    enum CiphertextType {
        EUINT8, // Encrypted uint8
        EUINT16, // Encrypted uint16
        EUINT32, // Encrypted uint32
        EUINT64, // Encrypted uint64
        EUINT256, // Encrypted uint256
        EBOOL, // Encrypted bool
        EADDRESS // Encrypted address
    }

    /// @notice FHE computation request
    struct ComputationRequest {
        bytes32 requestId;
        address requester;
        Operation operation;
        bytes32[] inputCiphertextHashes;
        bytes32 resultCiphertextHash;
        ComputationStatus status;
        uint256 timestamp;
    }

    /// @notice Supported operations
    enum Operation {
        ADD,
        SUB,
        MUL,
        DIV,
        EQ,
        NE,
        LT,
        GT,
        LE,
        GE,
        AND,
        OR,
        XOR,
        NOT,
        SHL,
        SHR,
        MIN,
        MAX,
        CMUX, // Conditional multiplexer
        SELECT // Encrypted selection
    }

    /// @notice Computation status
    enum ComputationStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        FAILED
    }

    /// @notice Public key for encryption
    struct FHEPublicKey {
        bytes key;
        bytes32 keyHash;
        uint256 securityLevel;
        uint256 registrationTime;
        bool active;
    }

    /// @notice Decryption request
    struct DecryptionRequest {
        bytes32 requestId;
        bytes32 ciphertextHash;
        address requester;
        bytes32 decryptionKeyCommitment;
        bool fulfilled;
        bytes decryptedValue;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Stored ciphertexts
    mapping(bytes32 => FHECiphertext) public ciphertexts;

    /// @notice Computation requests
    mapping(bytes32 => ComputationRequest) public computationRequests;

    /// @notice Decryption requests
    mapping(bytes32 => DecryptionRequest) public decryptionRequests;

    /// @notice Network public key
    FHEPublicKey public networkPublicKey;

    /// @notice User public keys
    mapping(address => FHEPublicKey) public userPublicKeys;

    /// @notice Computation count
    uint256 public computationCount;

    /// @notice Decryption count
    uint256 public decryptionCount;

    /// @notice Ciphertext count
    uint256 public ciphertextCount;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event CiphertextStored(
        bytes32 indexed ciphertextHash,
        CiphertextType ctype,
        address indexed owner,
        uint256 timestamp
    );

    event ComputationRequested(
        bytes32 indexed requestId,
        Operation operation,
        uint256 inputCount,
        address indexed requester
    );

    event ComputationCompleted(
        bytes32 indexed requestId,
        bytes32 resultCiphertextHash,
        uint256 gasUsed
    );

    event DecryptionRequested(
        bytes32 indexed requestId,
        bytes32 ciphertextHash,
        address indexed requester
    );

    event DecryptionFulfilled(
        bytes32 indexed requestId,
        address indexed oracle
    );

    event PublicKeyRegistered(
        address indexed user,
        bytes32 keyHash,
        uint256 securityLevel
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidCiphertext();
    error CiphertextTooLarge();
    error CiphertextNotFound();
    error InvalidOperation();
    error ComputationFailed();
    error DecryptionFailed();
    error UnauthorizedOracle();
    error RequestNotFound();
    error InvalidPublicKey();
    error NotFulfilled();
    error NotRequester();
    error ProposalNotFound();
    error VotingEnded();
    error AlreadyVoted();
    error InvalidInputCount();


    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(KEY_MANAGER_ROLE, msg.sender);
    }

    // =========================================================================
    // PUBLIC KEY MANAGEMENT
    // =========================================================================

    /// @notice Register network public key
    /// @param key The serialized public key
    /// @param securityLevel Security parameter (128, 192, or 256)
    function registerNetworkPublicKey(
        bytes calldata key,
        uint256 securityLevel
    ) external onlyRole(KEY_MANAGER_ROLE) {
        if (key.length == 0) revert InvalidPublicKey();

        bytes32 keyHash = keccak256(key);

        networkPublicKey = FHEPublicKey({
            key: key,
            keyHash: keyHash,
            securityLevel: securityLevel,
            registrationTime: block.timestamp,
            active: true
        });

        emit PublicKeyRegistered(address(0), keyHash, securityLevel);
    }

    /// @notice Register user public key
    /// @param key The user's serialized public key
    function registerUserPublicKey(bytes calldata key) external {
        if (key.length == 0) revert InvalidPublicKey();

        bytes32 keyHash = keccak256(key);

        userPublicKeys[msg.sender] = FHEPublicKey({
            key: key,
            keyHash: keyHash,
            securityLevel: TFHE_PARAMS_128,
            registrationTime: block.timestamp,
            active: true
        });

        emit PublicKeyRegistered(msg.sender, keyHash, TFHE_PARAMS_128);
    }

    // =========================================================================
    // CIPHERTEXT STORAGE
    // =========================================================================

    /// @notice Store an encrypted value
    /// @param ciphertext The encrypted data
    /// @param ctype The ciphertext type
    /// @return ciphertextHash The hash identifier
    function storeCiphertext(
        bytes calldata ciphertext,
        CiphertextType ctype
    ) external returns (bytes32 ciphertextHash) {
        if (ciphertext.length == 0) revert InvalidCiphertext();
        if (ciphertext.length > MAX_CIPHERTEXT_SIZE)
            revert CiphertextTooLarge();

        ciphertextHash = keccak256(
            abi.encodePacked(
                FHE_DOMAIN,
                ciphertext,
                msg.sender,
                block.timestamp
            )
        );

        ciphertexts[ciphertextHash] = FHECiphertext({
            ciphertext: ciphertext,
            ciphertextHash: ciphertextHash,
            ctype: ctype,
            securityLevel: TFHE_PARAMS_128,
            timestamp: block.timestamp
        });

        ciphertextCount++;

        emit CiphertextStored(
            ciphertextHash,
            ctype,
            msg.sender,
            block.timestamp
        );
    }

    /// @notice Get ciphertext by hash
    function getCiphertext(
        bytes32 ciphertextHash
    ) external view returns (FHECiphertext memory) {
        FHECiphertext storage ct = ciphertexts[ciphertextHash];
        if (ct.ciphertextHash == bytes32(0)) revert CiphertextNotFound();
        return ct;
    }

    // =========================================================================
    // HOMOMORPHIC COMPUTATION
    // =========================================================================

    /// @notice Request a homomorphic computation
    /// @param operation The operation to perform
    /// @param inputHashes Hashes of input ciphertexts
    /// @return requestId The computation request ID
    function requestComputation(
        Operation operation,
        bytes32[] calldata inputHashes
    ) external returns (bytes32 requestId) {
        // Validate inputs exist
        for (uint256 i = 0; i < inputHashes.length; i++) {
            if (ciphertexts[inputHashes[i]].ciphertextHash == bytes32(0)) {
                revert CiphertextNotFound();
            }
        }

        // Validate operation has correct number of inputs
        _validateOperationInputs(operation, inputHashes.length);

        requestId = keccak256(
            abi.encodePacked(
                FHE_DOMAIN,
                "COMPUTE",
                msg.sender,
                operation,
                keccak256(abi.encodePacked(inputHashes)),
                block.timestamp
            )
        );

        computationRequests[requestId] = ComputationRequest({
            requestId: requestId,
            requester: msg.sender,
            operation: operation,
            inputCiphertextHashes: inputHashes,
            resultCiphertextHash: bytes32(0),
            status: ComputationStatus.PENDING,
            timestamp: block.timestamp
        });

        computationCount++;

        emit ComputationRequested(
            requestId,
            operation,
            inputHashes.length,
            msg.sender
        );
    }

    /// @notice Fulfill a computation request (oracle only)
    /// @param requestId The request ID
    /// @param resultCiphertext The computed result ciphertext
    function fulfillComputation(
        bytes32 requestId,
        bytes calldata resultCiphertext
    ) external onlyRole(ORACLE_ROLE) {
        ComputationRequest storage request = computationRequests[requestId];
        if (request.requestId == bytes32(0)) revert RequestNotFound();
        if (request.status != ComputationStatus.PENDING)
            revert ComputationFailed();

        // Store result ciphertext
        bytes32 resultHash = keccak256(
            abi.encodePacked(FHE_DOMAIN, resultCiphertext, requestId)
        );

        // Determine result type based on operation
        CiphertextType resultType = _getResultType(
            request.operation,
            request.inputCiphertextHashes
        );

        ciphertexts[resultHash] = FHECiphertext({
            ciphertext: resultCiphertext,
            ciphertextHash: resultHash,
            ctype: resultType,
            securityLevel: TFHE_PARAMS_128,
            timestamp: block.timestamp
        });

        request.resultCiphertextHash = resultHash;
        request.status = ComputationStatus.COMPLETED;

        uint256 gasUsed = gasleft(); // Simplified

        emit ComputationCompleted(requestId, resultHash, gasUsed);
    }

    /// @notice Validate operation has correct number of inputs
    function _validateOperationInputs(
        Operation op,
        uint256 inputCount
    ) internal pure {
        if (op == Operation.NOT) {
            if (inputCount != 1) revert InvalidInputCount();
        } else if (op == Operation.CMUX || op == Operation.SELECT) {
            if (inputCount != 3) revert InvalidInputCount();
        } else {
            if (inputCount != 2) revert InvalidInputCount();
        }
    }


    /// @notice Determine result ciphertext type
    function _getResultType(
        Operation op,
        bytes32[] storage inputHashes
    ) internal view returns (CiphertextType) {
        // Comparison operations return EBOOL
        if (
            op == Operation.EQ ||
            op == Operation.NE ||
            op == Operation.LT ||
            op == Operation.GT ||
            op == Operation.LE ||
            op == Operation.GE
        ) {
            return CiphertextType.EBOOL;
        }

        // Other operations preserve input type
        return ciphertexts[inputHashes[0]].ctype;
    }

    // =========================================================================
    // DECRYPTION
    // =========================================================================

    /// @notice Request decryption of a ciphertext
    /// @param ciphertextHash The ciphertext to decrypt
    /// @param decryptionKeyCommitment Commitment to user's decryption key
    /// @return requestId The decryption request ID
    function requestDecryption(
        bytes32 ciphertextHash,
        bytes32 decryptionKeyCommitment
    ) external returns (bytes32 requestId) {
        if (ciphertexts[ciphertextHash].ciphertextHash == bytes32(0)) {
            revert CiphertextNotFound();
        }

        requestId = keccak256(
            abi.encodePacked(
                FHE_DOMAIN,
                "DECRYPT",
                ciphertextHash,
                msg.sender,
                decryptionKeyCommitment,
                block.timestamp
            )
        );

        decryptionRequests[requestId] = DecryptionRequest({
            requestId: requestId,
            ciphertextHash: ciphertextHash,
            requester: msg.sender,
            decryptionKeyCommitment: decryptionKeyCommitment,
            fulfilled: false,
            decryptedValue: ""
        });

        decryptionCount++;

        emit DecryptionRequested(requestId, ciphertextHash, msg.sender);
    }

    /// @notice Fulfill a decryption request (oracle only)
    /// @param requestId The request ID
    /// @param decryptedValue The decrypted plaintext
    function fulfillDecryption(
        bytes32 requestId,
        bytes calldata decryptedValue
    ) external onlyRole(ORACLE_ROLE) {
        DecryptionRequest storage request = decryptionRequests[requestId];
        if (request.requestId == bytes32(0)) revert RequestNotFound();
        if (request.fulfilled) revert DecryptionFailed();

        request.decryptedValue = decryptedValue;
        request.fulfilled = true;

        emit DecryptionFulfilled(requestId, msg.sender);
    }

    /// @notice Get decrypted value
    function getDecryptedValue(
        bytes32 requestId
    ) external view returns (bytes memory) {
        DecryptionRequest storage request = decryptionRequests[requestId];
        if (!request.fulfilled) revert NotFulfilled();
        if (request.requester != msg.sender) revert NotRequester();
        return request.decryptedValue;
    }


    // =========================================================================
    // PRIVACY-PRESERVING OPERATIONS
    // =========================================================================

    /// @notice Encrypted balance check (returns encrypted bool)
    /// @param balanceHash Hash of encrypted balance
    /// @param thresholdHash Hash of encrypted threshold
    /// @return requestId Request for encrypted comparison result
    function encryptedBalanceCheck(
        bytes32 balanceHash,
        bytes32 thresholdHash
    ) external returns (bytes32 requestId) {
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = balanceHash;
        inputs[1] = thresholdHash;
        return this.requestComputation(Operation.GE, inputs);
    }

    /// @notice Encrypted transfer amount selection
    /// @param conditionHash Encrypted condition (bool)
    /// @param trueAmountHash Encrypted amount if true
    /// @param falseAmountHash Encrypted amount if false
    /// @return requestId Request for conditional selection
    function encryptedConditionalTransfer(
        bytes32 conditionHash,
        bytes32 trueAmountHash,
        bytes32 falseAmountHash
    ) external returns (bytes32 requestId) {
        bytes32[] memory inputs = new bytes32[](3);
        inputs[0] = conditionHash;
        inputs[1] = trueAmountHash;
        inputs[2] = falseAmountHash;
        return this.requestComputation(Operation.CMUX, inputs);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get computation request status
    function getComputationStatus(
        bytes32 requestId
    ) external view returns (ComputationStatus) {
        return computationRequests[requestId].status;
    }

    /// @notice Get network public key
    function getNetworkPublicKey() external view returns (bytes memory) {
        return networkPublicKey.key;
    }

    /// @notice Get statistics
    function getStats()
        external
        view
        returns (
            uint256 computations,
            uint256 decryptions,
            uint256 storedCiphertexts
        )
    {
        computations = computationCount;
        decryptions = decryptionCount;
        storedCiphertexts = ciphertextCount;
    }

    /// @notice Check if ciphertext exists
    function ciphertextExists(bytes32 hash) external view returns (bool) {
        return ciphertexts[hash].ciphertextHash != bytes32(0);
    }
}

/// @title FHEPrivateVoting
/// @notice Example: Private voting using FHE
contract FHEPrivateVoting is FHEPrivacyIntegration {
    struct Proposal {
        bytes32 proposalId;
        string description;
        bytes32 encryptedYesVotes; // Encrypted tally
        bytes32 encryptedNoVotes; // Encrypted tally
        uint256 endTime;
        bool tallied;
    }

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasVoted;

    event ProposalCreated(
        bytes32 indexed proposalId,
        string description,
        uint256 endTime
    );
    event VoteCast(bytes32 indexed proposalId, address indexed voter);

    /// @notice Create a proposal
    function createProposal(
        string calldata description,
        uint256 duration,
        bytes calldata initialZeroCiphertext
    ) external returns (bytes32 proposalId) {
        proposalId = keccak256(abi.encodePacked(description, block.timestamp));

        bytes32 zeroCiphertextHash = this.storeCiphertext(
            initialZeroCiphertext,
            CiphertextType.EUINT64
        );

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            description: description,
            encryptedYesVotes: zeroCiphertextHash,
            encryptedNoVotes: zeroCiphertextHash,
            endTime: block.timestamp + duration,
            tallied: false
        });

        emit ProposalCreated(
            proposalId,
            description,
            block.timestamp + duration
        );
    }

    /// @notice Cast an encrypted vote
    function castEncryptedVote(
        bytes32 proposalId,
        bytes calldata encryptedVote
    ) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (block.timestamp >= proposal.endTime) revert VotingEnded();
        if (hasVoted[proposalId][msg.sender]) revert AlreadyVoted();


        bytes32 voteHash = this.storeCiphertext(
            encryptedVote,
            CiphertextType.EUINT64
        );

        // Request homomorphic addition to tally
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = proposal.encryptedYesVotes;
        inputs[1] = voteHash;

        // This would be fulfilled by oracle with FHE addition
        this.requestComputation(Operation.ADD, inputs);

        hasVoted[proposalId][msg.sender] = true;

        emit VoteCast(proposalId, msg.sender);
    }
}
