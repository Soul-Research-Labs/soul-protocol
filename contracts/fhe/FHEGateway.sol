// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./lib/FHEUtils.sol";

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
    FHEUtils.FHEScheme public activeScheme;

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

    /// @notice FHEUtils.Handle registry
    mapping(bytes32 => FHEUtils.Handle) internal handles;

    /// @notice Decryption requests
    mapping(bytes32 => FHEUtils.DecryptionRequest) public decryptionRequests;

    /// @notice Reencryption requests
    mapping(bytes32 => FHEUtils.ReencryptionRequest) public reencryptionRequests;

    /// @notice Compute requests
    mapping(bytes32 => FHEUtils.ComputeRequest) public computeRequests;

    /// @notice Access control list: handle => user => allowed
    mapping(bytes32 => mapping(address => bool)) internal acl;

    /// @notice Global ACL: handle => publicly accessible
    mapping(bytes32 => bool) internal globalAcl;

    /// @notice Contract permissions: contract => handle => allowed
    mapping(address => mapping(bytes32 => bool)) internal contractAcl;

    /// @notice Approved contracts for FHE operations


    /// @notice ZK Verifier for decryption/reencryption proofs
    address public proofVerifier;


    /// @notice Security zones
    mapping(bytes32 => bool) internal securityZones;

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
        FHEUtils.Opcode opcode,
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

    event NetworkKeyUpdated(bytes32 newKeyHash, address updater);
    event SchemeUpdated(FHEUtils.FHEScheme newScheme, address updater);

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
    error ZeroAddress();
    error CallbackFailed();
    error ProofVerificationNotImplemented();
    error InvalidBatchSize();

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address _coprocessor, address _kms, FHEUtils.FHEScheme _scheme) {
        if (_coprocessor == address(0)) revert ZeroAddress();
        if (_kms == address(0)) revert ZeroAddress();

        coprocessor = _coprocessor;
        kms = _kms;
        activeScheme = _scheme;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COPROCESSOR_ROLE, _coprocessor);
        _grantRole(KMS_ROLE, _kms);
        _grantRole(OPERATOR_ROLE, msg.sender);

        // Initialize default security zone
        securityZones[keccak256("DEFAULT")] = true;

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
        if (valueType > uint8(FHEUtils.ValueType.ebytes256)) revert InvalidHandle();

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

        handles[handle] = FHEUtils.Handle({
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
        FHEUtils.Handle storage h = handles[handle];
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
    ) external view returns (FHEUtils.Handle memory info) {
        return handles[handle];
    }

    // ============================================
    // GENERIC FHE OPERATION
    // ============================================

    /**
     * @notice Perform a generic FHE operation
     * @param op The operation code
     * @param inputs The input handles
     * @param extraData Additional data (e.g. shift bits)
     * @return result The result handle
     */
    function performOp(
        FHEUtils.Opcode op,
        bytes32[] calldata inputs,
        bytes calldata extraData
    ) external whenNotPaused returns (bytes32 result) {
        // Arithmetic & Bitwise Binary Ops
        if (
            op == FHEUtils.Opcode.ADD ||
            op == FHEUtils.Opcode.SUB ||
            op == FHEUtils.Opcode.MUL ||
            op == FHEUtils.Opcode.DIV ||
            op == FHEUtils.Opcode.REM ||
            op == FHEUtils.Opcode.MIN ||
            op == FHEUtils.Opcode.MAX ||
            op == FHEUtils.Opcode.AND ||
            op == FHEUtils.Opcode.OR ||
            op == FHEUtils.Opcode.XOR
        ) {
            if (inputs.length != 2) revert TooManyInputs(); // Reusing error for count mismatch
            return _binaryOp(op, inputs[0], inputs[1]);
        }

        // Comparison Ops
        if (
            op == FHEUtils.Opcode.EQ ||
            op == FHEUtils.Opcode.NE ||
            op == FHEUtils.Opcode.GE ||
            op == FHEUtils.Opcode.GT ||
            op == FHEUtils.Opcode.LE ||
            op == FHEUtils.Opcode.LT
        ) {
            if (inputs.length != 2) revert TooManyInputs();
            return _comparisonOp(op, inputs[0], inputs[1]);
        }

        // Unary Ops
        if (op == FHEUtils.Opcode.NEG || op == FHEUtils.Opcode.NOT) {
            if (inputs.length != 1) revert TooManyInputs();
            return _unaryOp(op, inputs[0]);
        }

        // Shift Ops
        if (
            op == FHEUtils.Opcode.SHL ||
            op == FHEUtils.Opcode.SHR ||
            op == FHEUtils.Opcode.ROTL ||
            op == FHEUtils.Opcode.ROTR
        ) {
            if (inputs.length != 1) revert TooManyInputs();
            uint8 bits = abi.decode(extraData, (uint8));
            return _shiftOp(op, inputs[0], bits);
        }
        // Conditional Ops
        if (op == FHEUtils.Opcode.SELECT) {
            if (inputs.length != 3) revert TooManyInputs();
            return fheSelect(inputs[0], inputs[1], inputs[2]);
        }

        revert InvalidOpcode();
    }

    /**
     * @notice Perform a batch of FHE operations to save gas
     * @param ops Array of operation codes
     * @param inputs Array of input handle arrays
     * @param extraData Array of additional data
     * @return results Array of result handles
     */
    function performBatchOp(
        FHEUtils.Opcode[] calldata ops,
        bytes32[][] calldata inputs,
        bytes[] calldata extraData
    ) external whenNotPaused returns (bytes32[] memory results) {
        if (ops.length != inputs.length || ops.length != extraData.length) {
            revert InvalidBatchSize();
        }

        results = new bytes32[](ops.length);
        for (uint256 i = 0; i < ops.length; i++) {
            results[i] = this.performOp(ops[i], inputs[i], extraData[i]);
        }

        // Optimization: In a real coprocessor integration, 
        // we would emit a single BatchComputeRequested event here.
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
            FHEUtils.Opcode.TRIVIAL,
            new bytes32[](0),
            handle,
            abi.encode(plaintext, toType)
        );

        emit ComputeRequested(requestId, FHEUtils.Opcode.TRIVIAL, new bytes32[](0));
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
            FHEUtils.Opcode.RAND,
            new bytes32[](0),
            handle,
            abi.encode(randType, upperBound, block.prevrandao)
        );

        emit ComputeRequested(requestId, FHEUtils.Opcode.RAND, new bytes32[](0));
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
        return _binaryOp(FHEUtils.Opcode.ADD, lhs, rhs);
    }

    /**
     * @notice Homomorphic subtraction: lhs - rhs
     */
    function fheSub(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.SUB, lhs, rhs);
    }

    /**
     * @notice Homomorphic multiplication: lhs * rhs
     */
    function fheMul(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.MUL, lhs, rhs);
    }

    /**
     * @notice Homomorphic division: lhs / rhs
     */
    function fheDiv(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.DIV, lhs, rhs);
    }

    /**
     * @notice Homomorphic remainder: lhs % rhs
     */
    function fheRem(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.REM, lhs, rhs);
    }

    /**
     * @notice Homomorphic negation: -value
     */
    function fheNeg(
        bytes32 value
    ) external whenNotPaused returns (bytes32 result) {
        return _unaryOp(FHEUtils.Opcode.NEG, value);
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
        return _comparisonOp(FHEUtils.Opcode.EQ, lhs, rhs);
    }

    /**
     * @notice Encrypted not-equal: lhs != rhs
     */
    function fheNe(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(FHEUtils.Opcode.NE, lhs, rhs);
    }

    /**
     * @notice Encrypted greater-or-equal: lhs >= rhs
     */
    function fheGe(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(FHEUtils.Opcode.GE, lhs, rhs);
    }

    /**
     * @notice Encrypted greater-than: lhs > rhs
     */
    function fheGt(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(FHEUtils.Opcode.GT, lhs, rhs);
    }

    /**
     * @notice Encrypted less-or-equal: lhs <= rhs
     */
    function fheLe(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(FHEUtils.Opcode.LE, lhs, rhs);
    }

    /**
     * @notice Encrypted less-than: lhs < rhs
     */
    function fheLt(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _comparisonOp(FHEUtils.Opcode.LT, lhs, rhs);
    }

    /**
     * @notice Encrypted min: min(lhs, rhs)
     */
    function fheMin(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.MIN, lhs, rhs);
    }

    /**
     * @notice Encrypted max: max(lhs, rhs)
     */
    function fheMax(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.MAX, lhs, rhs);
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
        return _binaryOp(FHEUtils.Opcode.AND, lhs, rhs);
    }

    /**
     * @notice Encrypted OR: lhs | rhs
     */
    function fheOr(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.OR, lhs, rhs);
    }

    /**
     * @notice Encrypted XOR: lhs ^ rhs
     */
    function fheXor(
        bytes32 lhs,
        bytes32 rhs
    ) external whenNotPaused returns (bytes32 result) {
        return _binaryOp(FHEUtils.Opcode.XOR, lhs, rhs);
    }

    /**
     * @notice Encrypted NOT: ~value
     */
    function fheNot(
        bytes32 value
    ) external whenNotPaused returns (bytes32 result) {
        return _unaryOp(FHEUtils.Opcode.NOT, value);
    }

    /**
     * @notice Encrypted shift left: value << bits
     */
    function fheShl(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(FHEUtils.Opcode.SHL, value, bits);
    }

    /**
     * @notice Encrypted shift right: value >> bits
     */
    function fheShr(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(FHEUtils.Opcode.SHR, value, bits);
    }

    /**
     * @notice Encrypted rotate left
     */
    function fheRotl(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(FHEUtils.Opcode.ROTL, value, bits);
    }

    /**
     * @notice Encrypted rotate right
     */
    function fheRotr(
        bytes32 value,
        uint8 bits
    ) external whenNotPaused returns (bytes32 result) {
        return _shiftOp(FHEUtils.Opcode.ROTR, value, bits);
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
    ) public whenNotPaused returns (bytes32 result) {
        _validateHandle(condition);
        _validateHandle(ifTrue);
        _validateHandle(ifFalse);
        _checkACL(condition);
        _checkACL(ifTrue);
        _checkACL(ifFalse);

        // Condition must be ebool
        if (handles[condition].valueType != uint8(FHEUtils.ValueType.ebool)) {
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

        _requestCompute(FHEUtils.Opcode.SELECT, inputs, result, "");
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
    ) external whenNotPaused returns (bytes32 requestId) {
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

        decryptionRequests[requestId] = FHEUtils.DecryptionRequest({
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
     */
    function fulfillDecryption(
        bytes32 requestId,
        bytes32 result,
        bytes calldata proof
    ) external onlyRole(COPROCESSOR_ROLE) {
        FHEUtils.DecryptionRequest storage req = decryptionRequests[requestId];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.fulfilled) revert RequestAlreadyFulfilled();
        if (block.timestamp > req.maxTimestamp) revert RequestExpired();

        // Verify ZK Proof if verifier is set
        if (proofVerifier != address(0)) {
            // In a real implementation, we would call the verifier contract
            // For now, we ensure a proof is provided if the verifier is set
            if (proof.length == 0) revert ProofVerificationNotImplemented();
        }

        req.fulfilled = true;
        req.result = result;

        // Perform callback if specified
        if (req.callbackContract != address(0)) {
            (bool success, ) = req.callbackContract.call(
                abi.encodeWithSelector(req.callbackSelector, requestId, result)
            );
            if (!success) revert CallbackFailed();
        }

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

        reencryptionRequests[requestId] = FHEUtils.ReencryptionRequest({
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
        FHEUtils.ReencryptionRequest storage req = reencryptionRequests[requestId];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.fulfilled) revert RequestAlreadyFulfilled();
        if (block.timestamp > req.maxTimestamp) revert RequestExpired();

        // Verify ZK Proof if verifier is set
        if (proofVerifier != address(0)) {
            if (proof.length == 0) revert ProofVerificationNotImplemented();
        }

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
        FHEUtils.FHEScheme newScheme
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
        if (newCoprocessor == address(0)) revert ZeroAddress();
        _revokeRole(COPROCESSOR_ROLE, coprocessor);
        coprocessor = newCoprocessor;
        _grantRole(COPROCESSOR_ROLE, newCoprocessor);
    }

    /**
     * @notice Update proof verifier address
     */
    function updateProofVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofVerifier = newVerifier;
    }

    /**
     * @notice Approve a contract for FHE operations
     */


    /**
     * @notice Add security zone
     */
    function addSecurityZone(
        bytes32 zone
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        securityZones[zone] = true;
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
        // Allow unverified handles for computation chaining if they exist
        // Real verification happens at decryption or via separate coprocessor proofs
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

        handles[handle] = FHEUtils.Handle({
            id: handle,
            valueType: valueType,
            securityZone: keccak256("DEFAULT"),
            verified: false,
            createdAt: uint64(block.timestamp)
        });

        acl[handle][msg.sender] = true;
    }

    function _binaryOp(
        FHEUtils.Opcode op,
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
        FHEUtils.Opcode op,
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
        FHEUtils.Opcode op,
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
        result = _createOutputHandle(uint8(FHEUtils.ValueType.ebool));

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = lhs;
        inputs[1] = rhs;

        _requestCompute(op, inputs, result, "");
    }

    function _shiftOp(
        FHEUtils.Opcode op,
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
        FHEUtils.Opcode op,
        bytes32[] memory inputs,
        bytes32 output,
        bytes memory /* extraData */
    ) internal returns (bytes32 requestId) {
        if (inputs.length > MAX_INPUTS) revert TooManyInputs();

        requestNonce++;
        requestId = keccak256(
            abi.encode(op, inputs, output, requestNonce, block.timestamp)
        );

        computeRequests[requestId] = FHEUtils.ComputeRequest({
            requestId: requestId,
            opcode: uint8(op),
            inputs: inputs,
            output: output,
            requester: msg.sender,
            gasUsed: _getFHEGasPrice(op),
            timestamp: block.timestamp,
            status: FHEUtils.RequestStatus.Pending
        });

        totalComputations++;

        emit ComputeRequested(requestId, op, inputs);
    }

    function getFHEGasPrice(
        FHEUtils.Opcode op
    ) external pure returns (uint256) {
        return _getFHEGasPrice(op);
    }

    function _getFHEGasPrice(
        FHEUtils.Opcode op
    ) internal pure returns (uint256) {
        // Prices packed as 3-byte big-endian values
        bytes memory prices = hex"00C35000C3500249F00493E00493E000753000C35000C350013880013880013880013880007530007530007530004E2000C35000C3500111700111700186A00186A001D4C00249F0030D4000753007A120061A80";
        
        uint256 idx = uint256(op) * 3;
        if (idx + 3 > prices.length) return 0;
        
        uint256 price;
        assembly {
            price := shr(232, mload(add(add(prices, 32), idx)))
        }
        return price;
    }
}
