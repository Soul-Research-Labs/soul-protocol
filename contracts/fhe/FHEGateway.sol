// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title FHEGateway
 * @author Soul Protocol
 * @notice Gateway contract for Full Homomorphic Encryption (FHE) coprocessor integration
 * @dev Implements fhEVM-compatible interface for TFHE-rs coprocessor
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                        FHE Gateway Architecture                      │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
 * │  │  User/dApp   │───►│  FHEGateway  │───►│  FHE Coprocessor     │  │
 * │  │              │    │  (on-chain)  │    │  (off-chain TFHE)    │  │
 * │  └──────────────┘    └──────────────┘    └──────────────────────┘  │
 * │         │                   │                       │              │
 * │         │                   ▼                       ▼              │
 * │         │           ┌──────────────┐    ┌──────────────────────┐  │
 * │         │           │  ACL Layer   │    │  Key Management      │  │
 * │         │           │  (permits)   │    │  (KMS)               │  │
 * │         │           └──────────────┘    └──────────────────────┘  │
 * │         │                                                          │
 * │         ▼                                                          │
 * │  ┌──────────────────────────────────────────────────────────────┐ │
 * │  │                    Encrypted Contracts                        │ │
 * │  │  • EncryptedERC20   • EncryptedVoting   • ConfidentialDeFi   │ │
 * │  └──────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Supported Schemes:
 * - TFHE (Torus FHE) - Boolean and integer circuits
 * - BFV (Brakerski/Fan-Vercauteren) - Integer arithmetic
 * - BGV (Brakerski-Gentry-Vaikuntanathan) - Modular arithmetic
 * - CKKS (Cheon-Kim-Kim-Song) - Approximate arithmetic (fixed-point)
 */
contract FHEGateway is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // Roles
    // ============================================

    bytes32 public constant COPROCESSOR_ROLE = keccak256("COPROCESSOR_ROLE");
    bytes32 public constant KMS_ROLE = keccak256("KMS_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // TYPES
    // ============================================

    /// @notice FHE encrypted handle (reference to ciphertext)
    /// Handles are 256-bit references to off-chain ciphertexts
    struct Handle {
        bytes32 id; // Unique identifier
        uint8 valueType; // Type of encrypted value (see FHETypes)
        bytes32 securityZone; // Security domain
        bool verified; // Whether ciphertext is verified
        uint64 createdAt; // Creation timestamp
    }

    /// @notice Decryption request for async decryption
    struct DecryptionRequest {
        bytes32 requestId;
        bytes32 handle;
        address requester;
        address callbackContract;
        bytes4 callbackSelector;
        uint256 maxTimestamp;
        bool fulfilled;
        bytes32 result; // Decrypted value (as bytes32)
    }

    /// @notice Reencryption request for sharing encrypted data
    struct ReencryptionRequest {
        bytes32 requestId;
        bytes32 handle;
        address requester;
        bytes32 targetPublicKey;
        uint256 maxTimestamp;
        bool fulfilled;
        bytes reencryptedCiphertext;
    }

    /// @notice FHE computation request
    struct ComputeRequest {
        bytes32 requestId;
        uint8 opcode; // Operation code
        bytes32[] inputs; // Input handles
        bytes32 output; // Output handle
        address requester;
        uint256 gasUsed; // Estimated FHE gas
        uint256 timestamp;
        RequestStatus status;
    }

    /// @notice Request status
    enum RequestStatus {
        Pending,
        Processing,
        Completed,
        Failed,
        Expired
    }

    /// @notice Supported FHE schemes
    enum FHEScheme {
        TFHE,
        BFV,
        BGV,
        CKKS
    }

    /// @notice Value types for encrypted handles
    /// Compatible with fhEVM type system
    enum ValueType {
        ebool, // 0: Encrypted boolean
        euint4, // 1: Encrypted 4-bit unsigned integer
        euint8, // 2: Encrypted 8-bit unsigned integer
        euint16, // 3: Encrypted 16-bit unsigned integer
        euint32, // 4: Encrypted 32-bit unsigned integer
        euint64, // 5: Encrypted 64-bit unsigned integer
        euint128, // 6: Encrypted 128-bit unsigned integer
        euint256, // 7: Encrypted 256-bit unsigned integer
        eaddress, // 8: Encrypted address (160-bit)
        ebytes64, // 9: Encrypted 64-byte value
        ebytes128, // 10: Encrypted 128-byte value
        ebytes256 // 11: Encrypted 256-byte value
    }

    /// @notice FHE Operation codes
    enum Opcode {
        // Arithmetic
        ADD, // 0: ct + ct
        SUB, // 1: ct - ct
        MUL, // 2: ct * ct
        DIV, // 3: ct / ct (integer division)
        REM, // 4: ct % ct (remainder)
        NEG, // 5: -ct
        // Comparison
        EQ, // 6: ct == ct
        NE, // 7: ct != ct
        GE, // 8: ct >= ct
        GT, // 9: ct > ct
        LE, // 10: ct <= ct
        LT, // 11: ct < ct
        // Bitwise
        AND, // 12: ct & ct
        OR, // 13: ct | ct
        XOR, // 14: ct ^ ct
        NOT, // 15: ~ct
        SHL, // 16: ct << n
        SHR, // 17: ct >> n
        ROTL, // 18: rotate left
        ROTR, // 19: rotate right
        // Min/Max
        MIN, // 20: min(ct, ct)
        MAX, // 21: max(ct, ct)
        // Conditional
        SELECT, // 22: condition ? ct1 : ct2
        CMUX, // 23: encrypted mux
        // Special
        RAND, // 24: random encrypted value
        TRIVIAL, // 25: encrypt plaintext to ciphertext
        DECRYPT, // 26: request decryption
        REENCRYPT // 27: reencrypt to new key
    }

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum request TTL (1 hour)
    uint256 public constant MAX_REQUEST_TTL = 3600;

    /// @notice Minimum request TTL (1 minute)
    uint256 public constant MIN_REQUEST_TTL = 60;

    /// @notice FHE gas multiplier for cost estimation
    uint256 public constant FHE_GAS_MULTIPLIER = 1000;

    /// @notice Maximum inputs per computation
    uint256 public constant MAX_INPUTS = 16;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Active FHE scheme
    FHEScheme public activeScheme;

    /// @notice Network public key hash
    bytes32 public networkPublicKeyHash;

    /// @notice Coprocessor address
    address public coprocessor;

    /// @notice Key Management Service address
    address public kms;

    /// @notice Request nonce
    uint256 public requestNonce;

    /// @notice Total computations processed
    uint256 public totalComputations;

    /// @notice Total decryptions processed
    uint256 public totalDecryptions;

    /// @notice Handle registry
    mapping(bytes32 => Handle) public handles;

    /// @notice Decryption requests
    mapping(bytes32 => DecryptionRequest) public decryptionRequests;

    /// @notice Reencryption requests
    mapping(bytes32 => ReencryptionRequest) public reencryptionRequests;

    /// @notice Compute requests
    mapping(bytes32 => ComputeRequest) public computeRequests;

    /// @notice Access control list: handle => user => allowed
    mapping(bytes32 => mapping(address => bool)) public acl;

    /// @notice Global ACL: handle => publicly accessible
    mapping(bytes32 => bool) public globalAcl;

    /// @notice Contract permissions: contract => handle => allowed
    mapping(address => mapping(bytes32 => bool)) public contractAcl;

    /// @notice Approved contracts for FHE operations
    mapping(address => bool) public approvedContracts;

    /// @notice FHE gas prices per operation
    mapping(Opcode => uint256) public fheGasPrices;

    /// @notice Security zones
    mapping(bytes32 => bool) public securityZones;

    // ============================================
    // EVENTS
    // ============================================

    event HandleCreated(
        bytes32 indexed handle,
        uint8 valueType,
        address creator
    );
    event HandleVerified(bytes32 indexed handle, address verifier);
    event ComputeRequested(
        bytes32 indexed requestId,
        Opcode opcode,
        bytes32[] inputs
    );
    event ComputeCompleted(bytes32 indexed requestId, bytes32 output);
    event ComputeFailed(bytes32 indexed requestId, string reason);
    event DecryptionRequested(
        bytes32 indexed requestId,
        bytes32 handle,
        address requester
    );
    event DecryptionFulfilled(bytes32 indexed requestId, bytes32 result);
    event ReencryptionRequested(
        bytes32 indexed requestId,
        bytes32 handle,
        bytes32 targetKey
    );
    event ReencryptionFulfilled(bytes32 indexed requestId);
    event ACLGranted(
        bytes32 indexed handle,
        address indexed user,
        address granter
    );
    event ACLRevoked(
        bytes32 indexed handle,
        address indexed user,
        address revoker
    );
    event ContractApproved(address indexed contractAddr, address approver);
    event ContractRevoked(address indexed contractAddr, address revoker);
    event NetworkKeyUpdated(bytes32 newKeyHash, address updater);
    event SchemeUpdated(FHEScheme newScheme, address updater);

    // ============================================
    // ERRORS
    // ============================================

    error InvalidHandle();
    error HandleAlreadyExists();
    error HandleNotVerified();
    error Unauthorized();
    error InvalidOpcode();
    error TooManyInputs();
    error TypeMismatch();
    error RequestExpired();
    error RequestAlreadyFulfilled();
    error InvalidCallback();
    error InvalidTTL();
    error ContractNotApproved();
    error SecurityZoneMismatch();

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address _coprocessor, address _kms, FHEScheme _scheme) {
        require(_coprocessor != address(0), "Invalid coprocessor");
        require(_kms != address(0), "Invalid KMS");

        coprocessor = _coprocessor;
        kms = _kms;
        activeScheme = _scheme;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COPROCESSOR_ROLE, _coprocessor);
        _grantRole(KMS_ROLE, _kms);
        _grantRole(OPERATOR_ROLE, msg.sender);

        // Initialize default security zone
        securityZones[keccak256("DEFAULT")] = true;

        // Initialize FHE gas prices (in wei units)
        _initializeFHEGasPrices();
    }

    // ============================================
    // HANDLE MANAGEMENT
    // ============================================

    /**
     * @notice Create a new encrypted handle
     * @param valueType The type of encrypted value
     * @param securityZone The security domain
     * @return handle The new handle ID
     */
    function createHandle(
        uint8 valueType,
        bytes32 securityZone
    ) external whenNotPaused returns (bytes32 handle) {
        if (!securityZones[securityZone]) revert SecurityZoneMismatch();
        if (valueType > uint8(ValueType.ebytes256)) revert InvalidHandle();

        requestNonce++;
        handle = keccak256(
            abi.encode(
                msg.sender,
                valueType,
                securityZone,
                requestNonce,
                block.timestamp,
                block.chainid
            )
        );

        if (handles[handle].id != bytes32(0)) revert HandleAlreadyExists();

        handles[handle] = Handle({
            id: handle,
            valueType: valueType,
            securityZone: securityZone,
            verified: false,
            createdAt: uint64(block.timestamp)
        });

        // Grant ACL to creator
        acl[handle][msg.sender] = true;

        emit HandleCreated(handle, valueType, msg.sender);
    }

    /**
     * @notice Verify a handle (called by coprocessor after ciphertext validation)
     * @param handle The handle to verify
     */
    function verifyHandle(bytes32 handle) external onlyRole(COPROCESSOR_ROLE) {
        if (handles[handle].id == bytes32(0)) revert InvalidHandle();

        handles[handle].verified = true;

        emit HandleVerified(handle, msg.sender);
    }

    /**
     * @notice Check if a handle is valid and verified
     * @param handle The handle to check
     * @return valid Whether the handle is valid
     * @return verified Whether the handle is verified
     */
    function checkHandle(
        bytes32 handle
    ) external view returns (bool valid, bool verified) {
        Handle storage h = handles[handle];
        valid = h.id != bytes32(0);
        verified = h.verified;
    }

    /**
     * @notice Get handle info
     * @param handle The handle
     * @return info The handle information
     */
    function getHandleInfo(
        bytes32 handle
    ) external view returns (Handle memory info) {
        return handles[handle];
    }

    // ============================================
    // FHE OPERATIONS (SYNCHRONOUS)
    // ============================================

    /**
     * @notice Trivially encrypt a plaintext value
     * @param plaintext The plaintext value to encrypt
     * @param toType The target encrypted type
     * @return handle The encrypted handle
     */
    function trivialEncrypt(
        uint256 plaintext,
        uint8 toType
    ) external whenNotPaused returns (bytes32 handle) {
        handle = _createOutputHandle(toType);

        // Request trivial encryption from coprocessor
        bytes32 requestId = _requestCompute(
            Opcode.TRIVIAL,
            new bytes32[](0),
            handle,
            abi.encode(plaintext, toType)
        );

        emit ComputeRequested(requestId, Opcode.TRIVIAL, new bytes32[](0));
    }

    /**
     * @notice Request encrypted random value
     * @param randType The type of random value
     * @param upperBound Upper bound for random (0 for max of type)
     * @return handle The encrypted random handle
     */
    function random(
        uint8 randType,
        uint256 upperBound
    ) external whenNotPaused returns (bytes32 handle) {
        handle = _createOutputHandle(randType);

        bytes32 requestId = _requestCompute(
            Opcode.RAND,
            new bytes32[](0),
            handle,
            abi.encode(randType, upperBound, block.prevrandao)
        );

        emit ComputeRequested(requestId, Opcode.RAND, new bytes32[](0));
    }

    // ============================================
    // ARITHMETIC OPERATIONS
    // ============================================

    /**
     * @notice Homomorphic addition: lhs + rhs
     * @param lhs Left operand handle
     * @param rhs Right operand handle
     * @return result Result handle
     */
    function fheAdd(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.ADD, lhs, rhs);
    }

    /**
     * @notice Homomorphic subtraction: lhs - rhs
     */
    function fheSub(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.SUB, lhs, rhs);
    }

    /**
     * @notice Homomorphic multiplication: lhs * rhs
     */
    function fheMul(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.MUL, lhs, rhs);
    }

    /**
     * @notice Homomorphic division: lhs / rhs
     */
    function fheDiv(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.DIV, lhs, rhs);
    }

    /**
     * @notice Homomorphic remainder: lhs % rhs
     */
    function fheRem(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.REM, lhs, rhs);
    }

    /**
     * @notice Homomorphic negation: -value
     */
    function fheNeg(
        bytes32 value
    ) external whenNotPaused returns (bytes32 result) {
        return _unaryOp(Opcode.NEG, value);
    }

    // ============================================
    // COMPARISON OPERATIONS
    // ============================================

    /**
     * @notice Encrypted equality: lhs == rhs
     */
    function fheEq(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(Opcode.EQ, lhs, rhs);
    }

    /**
     * @notice Encrypted not-equal: lhs != rhs
     */
    function fheNe(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(Opcode.NE, lhs, rhs);
    }

    /**
     * @notice Encrypted greater-or-equal: lhs >= rhs
     */
    function fheGe(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(Opcode.GE, lhs, rhs);
    }

    /**
     * @notice Encrypted greater-than: lhs > rhs
     */
    function fheGt(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(Opcode.GT, lhs, rhs);
    }

    /**
     * @notice Encrypted less-or-equal: lhs <= rhs
     */
    function fheLe(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(Opcode.LE, lhs, rhs);
    }

    /**
     * @notice Encrypted less-than: lhs < rhs
     */
    function fheLt(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(Opcode.LT, lhs, rhs);
    }

    /**
     * @notice Encrypted min: min(lhs, rhs)
     */
    function fheMin(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.MIN, lhs, rhs);
    }

    /**
     * @notice Encrypted max: max(lhs, rhs)
     */
    function fheMax(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.MAX, lhs, rhs);
    }

    // ============================================
    // BITWISE OPERATIONS
    // ============================================

    /**
     * @notice Encrypted AND: lhs & rhs
     */
    function fheAnd(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.AND, lhs, rhs);
    }

    /**
     * @notice Encrypted OR: lhs | rhs
     */
    function fheOr(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.OR, lhs, rhs);
    }

    /**
     * @notice Encrypted XOR: lhs ^ rhs
     */
    function fheXor(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(Opcode.XOR, lhs, rhs);
    }

    /**
     * @notice Encrypted NOT: ~value
     */
    function fheNot(
        bytes32 value
    ) external whenNotPaused returns (bytes32 result) {
        return _unaryOp(Opcode.NOT, value);
    }

    /**
     * @notice Encrypted shift left: value << bits
     */
    function fheShl(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(Opcode.SHL, value, bits);
    }

    /**
     * @notice Encrypted shift right: value >> bits
     */
    function fheShr(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(Opcode.SHR, value, bits);
    }

    /**
     * @notice Encrypted rotate left
     */
    function fheRotl(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(Opcode.ROTL, value, bits);
    }

    /**
     * @notice Encrypted rotate right
     */
    function fheRotr(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(Opcode.ROTR, value, bits);
    }

    // ============================================
    // CONDITIONAL OPERATIONS
    // ============================================

    /**
     * @notice Encrypted select: condition ? ifTrue : ifFalse
     * @param condition Encrypted boolean condition
     * @param ifTrue Value if condition is true
     * @param ifFalse Value if condition is false
     */
    function fheSelect(
        bytes32 condition,
        bytes32 ifTrue,
        bytes32 ifFalse
    ) external whenNotPaused returns (bytes32 result) {
        _validateHandle(condition);
        _validateHandle(ifTrue);
        _validateHandle(ifFalse);
        _checkACL(condition);
        _checkACL(ifTrue);
        _checkACL(ifFalse);

        // Condition must be ebool
        if (handles[condition].valueType != uint8(ValueType.ebool)) {
            revert TypeMismatch();
        }

        // ifTrue and ifFalse must have same type
        if (handles[ifTrue].valueType != handles[ifFalse].valueType) {
            revert TypeMismatch();
        }

        result = _createOutputHandle(handles[ifTrue].valueType);

        bytes32[] memory inputs = new bytes32[](3);
        inputs[0] = condition;
        inputs[1] = ifTrue;
        inputs[2] = ifFalse;

        _requestCompute(Opcode.SELECT, inputs, result, "");
    }

    // ============================================
    // DECRYPTION (ASYNC)
    // ============================================

    /**
     * @notice Request decryption of an encrypted value
     * @param handle The handle to decrypt
     * @param callbackContract Contract to call with result
     * @param callbackSelector Function selector for callback
     * @param ttl Time-to-live for request (seconds)
     * @return requestId The decryption request ID
     */
    function requestDecryption(
        bytes32 handle,
        address callbackContract,
        bytes4 callbackSelector,
        uint256 ttl
    ) external whenNotPaused nonReentrant returns (bytes32 requestId) {
        _validateHandle(handle);
        _checkACL(handle);

        if (ttl < MIN_REQUEST_TTL || ttl > MAX_REQUEST_TTL) revert InvalidTTL();
        if (callbackContract == address(0)) revert InvalidCallback();

        requestNonce++;
        requestId = keccak256(
            abi.encode(
                handle,
                msg.sender,
                callbackContract,
                callbackSelector,
                requestNonce,
                block.timestamp
            )
        );

        decryptionRequests[requestId] = DecryptionRequest({
            requestId: requestId,
            handle: handle,
            requester: msg.sender,
            callbackContract: callbackContract,
            callbackSelector: callbackSelector,
            maxTimestamp: block.timestamp + ttl,
            fulfilled: false,
            result: bytes32(0)
        });

        totalDecryptions++;

        emit DecryptionRequested(requestId, handle, msg.sender);
    }

    /**
     * @notice Fulfill decryption request (coprocessor only)
     * @param requestId The request to fulfill
     * @param result The decrypted value
     * @param proof ZK proof of correct decryption
     */
    function fulfillDecryption(
        bytes32 requestId,
        bytes32 result,
        bytes calldata proof
    ) external onlyRole(COPROCESSOR_ROLE) nonReentrant {
        DecryptionRequest storage req = decryptionRequests[requestId];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.fulfilled) revert RequestAlreadyFulfilled();
        if (block.timestamp > req.maxTimestamp) revert RequestExpired();
        require(proof.length > 0, "Invalid proof");

        req.fulfilled = true;
        req.result = result;

        // Execute callback
        (bool success, ) = req.callbackContract.call(
            abi.encodeWithSelector(req.callbackSelector, requestId, result)
        );
        require(success, "Callback failed");

        emit DecryptionFulfilled(requestId, result);
    }

    // ============================================
    // REENCRYPTION
    // ============================================

    /**
     * @notice Request reencryption to a new public key
     * @param handle The handle to reencrypt
     * @param targetPublicKey The target public key (hash)
     * @param ttl Time-to-live
     * @return requestId The request ID
     */
    function requestReencryption(
        bytes32 handle,
        bytes32 targetPublicKey,
        uint256 ttl
    ) external whenNotPaused returns (bytes32 requestId) {
        _validateHandle(handle);
        _checkACL(handle);

        if (ttl < MIN_REQUEST_TTL || ttl > MAX_REQUEST_TTL) revert InvalidTTL();

        requestNonce++;
        requestId = keccak256(
            abi.encode(
                handle,
                targetPublicKey,
                msg.sender,
                requestNonce,
                block.timestamp
            )
        );

        reencryptionRequests[requestId] = ReencryptionRequest({
            requestId: requestId,
            handle: handle,
            requester: msg.sender,
            targetPublicKey: targetPublicKey,
            maxTimestamp: block.timestamp + ttl,
            fulfilled: false,
            reencryptedCiphertext: ""
        });

        emit ReencryptionRequested(requestId, handle, targetPublicKey);
    }

    /**
     * @notice Fulfill reencryption request
     */
    function fulfillReencryption(
        bytes32 requestId,
        bytes calldata reencryptedCiphertext,
        bytes calldata proof
    ) external onlyRole(COPROCESSOR_ROLE) {
        ReencryptionRequest storage req = reencryptionRequests[requestId];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.fulfilled) revert RequestAlreadyFulfilled();
        if (block.timestamp > req.maxTimestamp) revert RequestExpired();
        require(proof.length > 0, "Invalid proof");

        req.fulfilled = true;
        req.reencryptedCiphertext = reencryptedCiphertext;

        emit ReencryptionFulfilled(requestId);
    }

    // ============================================
    // ACCESS CONTROL
    // ============================================

    /**
     * @notice Grant access to an encrypted handle
     * @param handle The handle
     * @param user The user to grant access to
     */
    function grantAccess(bytes32 handle, address user) external {
        if (!acl[handle][msg.sender]) revert Unauthorized();

        acl[handle][user] = true;

        emit ACLGranted(handle, user, msg.sender);
    }

    /**
     * @notice Revoke access to an encrypted handle
     */
    function revokeAccess(bytes32 handle, address user) external {
        if (!acl[handle][msg.sender]) revert Unauthorized();

        acl[handle][user] = false;

        emit ACLRevoked(handle, user, msg.sender);
    }

    /**
     * @notice Grant contract access to a handle
     */
    function grantContractAccess(
        bytes32 handle,
        address contractAddr
    ) external {
        if (!acl[handle][msg.sender]) revert Unauthorized();

        contractAcl[contractAddr][handle] = true;

        emit ACLGranted(handle, contractAddr, msg.sender);
    }

    /**
     * @notice Make handle globally accessible
     */
    function makeGlobal(bytes32 handle) external {
        if (!acl[handle][msg.sender]) revert Unauthorized();

        globalAcl[handle] = true;
    }

    /**
     * @notice Check if user has access to handle
     */
    function hasAccess(
        bytes32 handle,
        address user
    ) external view returns (bool) {
        return
            globalAcl[handle] || acl[handle][user] || contractAcl[user][handle];
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Update network public key
     */
    function updateNetworkKey(bytes32 newKeyHash) external onlyRole(KMS_ROLE) {
        networkPublicKeyHash = newKeyHash;
        emit NetworkKeyUpdated(newKeyHash, msg.sender);
    }

    /**
     * @notice Update active FHE scheme
     */
    function updateScheme(
        FHEScheme newScheme
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        activeScheme = newScheme;
        emit SchemeUpdated(newScheme, msg.sender);
    }

    /**
     * @notice Update coprocessor address
     */
    function updateCoprocessor(
        address newCoprocessor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCoprocessor != address(0), "Invalid address");
        _revokeRole(COPROCESSOR_ROLE, coprocessor);
        coprocessor = newCoprocessor;
        _grantRole(COPROCESSOR_ROLE, newCoprocessor);
    }

    /**
     * @notice Approve a contract for FHE operations
     */
    function approveContract(
        address contractAddr
    ) external onlyRole(OPERATOR_ROLE) {
        approvedContracts[contractAddr] = true;
        emit ContractApproved(contractAddr, msg.sender);
    }

    /**
     * @notice Revoke contract approval
     */
    function revokeContract(
        address contractAddr
    ) external onlyRole(OPERATOR_ROLE) {
        approvedContracts[contractAddr] = false;
        emit ContractRevoked(contractAddr, msg.sender);
    }

    /**
     * @notice Add security zone
     */
    function addSecurityZone(
        bytes32 zone
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        securityZones[zone] = true;
    }

    /**
     * @notice Update FHE gas price for operation
     */
    function setFHEGasPrice(
        Opcode op,
        uint256 price
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        fheGasPrices[op] = price;
    }

    /**
     * @notice Pause gateway
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause gateway
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    function _validateHandle(bytes32 handle) internal view {
        if (handles[handle].id == bytes32(0)) revert InvalidHandle();
        if (!handles[handle].verified) revert HandleNotVerified();
    }

    function _checkACL(bytes32 handle) internal view {
        if (
            !globalAcl[handle] &&
            !acl[handle][msg.sender] &&
            !contractAcl[msg.sender][handle]
        ) {
            revert Unauthorized();
        }
    }

    function _createOutputHandle(
        uint8 valueType
    ) internal returns (bytes32 handle) {
        requestNonce++;
        handle = keccak256(
            abi.encode(
                msg.sender,
                valueType,
                "OUTPUT",
                requestNonce,
                block.timestamp
            )
        );

        handles[handle] = Handle({
            id: handle,
            valueType: valueType,
            securityZone: keccak256("DEFAULT"),
            verified: false,
            createdAt: uint64(block.timestamp)
        });

        acl[handle][msg.sender] = true;
    }

    function _binaryOp(
        Opcode op,
        bytes32 lhs,
        bytes32 rhs
    ) internal returns (bytes32 result) {
        _validateHandle(lhs);
        _validateHandle(rhs);
        _checkACL(lhs);
        _checkACL(rhs);

        // Type check
        if (handles[lhs].valueType != handles[rhs].valueType) {
            revert TypeMismatch();
        }

        result = _createOutputHandle(handles[lhs].valueType);

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = lhs;
        inputs[1] = rhs;

        _requestCompute(op, inputs, result, "");
    }

    function _unaryOp(
        Opcode op,
        bytes32 value
    ) internal returns (bytes32 result) {
        _validateHandle(value);
        _checkACL(value);

        result = _createOutputHandle(handles[value].valueType);

        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = value;

        _requestCompute(op, inputs, result, "");
    }

    function _comparisonOp(
        Opcode op,
        bytes32 lhs,
        bytes32 rhs
    ) internal returns (bytes32 result) {
        _validateHandle(lhs);
        _validateHandle(rhs);
        _checkACL(lhs);
        _checkACL(rhs);

        if (handles[lhs].valueType != handles[rhs].valueType) {
            revert TypeMismatch();
        }

        // Comparison returns ebool
        result = _createOutputHandle(uint8(ValueType.ebool));

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = lhs;
        inputs[1] = rhs;

        _requestCompute(op, inputs, result, "");
    }

    function _shiftOp(
        Opcode op,
        bytes32 value,
        uint8 bits
    ) internal returns (bytes32 result) {
        _validateHandle(value);
        _checkACL(value);

        result = _createOutputHandle(handles[value].valueType);

        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = value;

        _requestCompute(op, inputs, result, abi.encode(bits));
    }

    function _requestCompute(
        Opcode op,
        bytes32[] memory inputs,
        bytes32 output,
        bytes memory extraData
    ) internal returns (bytes32 requestId) {
        if (inputs.length > MAX_INPUTS) revert TooManyInputs();

        requestNonce++;
        requestId = keccak256(
            abi.encode(op, inputs, output, requestNonce, block.timestamp)
        );

        computeRequests[requestId] = ComputeRequest({
            requestId: requestId,
            opcode: uint8(op),
            inputs: inputs,
            output: output,
            requester: msg.sender,
            gasUsed: fheGasPrices[op],
            timestamp: block.timestamp,
            status: RequestStatus.Pending
        });

        totalComputations++;

        emit ComputeRequested(requestId, op, inputs);
    }

    function _initializeFHEGasPrices() internal {
        // Arithmetic (relative costs)
        fheGasPrices[Opcode.ADD] = 50000;
        fheGasPrices[Opcode.SUB] = 50000;
        fheGasPrices[Opcode.MUL] = 150000;
        fheGasPrices[Opcode.DIV] = 300000;
        fheGasPrices[Opcode.REM] = 300000;
        fheGasPrices[Opcode.NEG] = 30000;

        // Comparison
        fheGasPrices[Opcode.EQ] = 50000;
        fheGasPrices[Opcode.NE] = 50000;
        fheGasPrices[Opcode.GE] = 80000;
        fheGasPrices[Opcode.GT] = 80000;
        fheGasPrices[Opcode.LE] = 80000;
        fheGasPrices[Opcode.LT] = 80000;

        // Bitwise
        fheGasPrices[Opcode.AND] = 30000;
        fheGasPrices[Opcode.OR] = 30000;
        fheGasPrices[Opcode.XOR] = 30000;
        fheGasPrices[Opcode.NOT] = 20000;
        fheGasPrices[Opcode.SHL] = 50000;
        fheGasPrices[Opcode.SHR] = 50000;
        fheGasPrices[Opcode.ROTL] = 70000;
        fheGasPrices[Opcode.ROTR] = 70000;

        // Min/Max
        fheGasPrices[Opcode.MIN] = 100000;
        fheGasPrices[Opcode.MAX] = 100000;

        // Conditional
        fheGasPrices[Opcode.SELECT] = 120000;
        fheGasPrices[Opcode.CMUX] = 150000;

        // Special
        fheGasPrices[Opcode.RAND] = 200000;
        fheGasPrices[Opcode.TRIVIAL] = 30000;
        fheGasPrices[Opcode.DECRYPT] = 500000;
        fheGasPrices[Opcode.REENCRYPT] = 400000;
    }
}
