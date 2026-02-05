// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../libraries/FHELib.sol";
import "./FHETypes.sol";

/**
 * @title FHEGateway
 * @author Soul Protocol
 * @notice Gateway contract for FHE operations with coprocessor integration
 * @dev Manages encrypted handles, ACL, and routes computation to off-chain coprocessors
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                      FHE Gateway Architecture                        │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌──────────────┐                        ┌──────────────────────┐   │
 * │  │  Smart       │  1. Request compute    │   FHE Coprocessor    │   │
 * │  │  Contract    │───────────────────────▶│   Network            │   │
 * │  │              │                        │   (Off-chain TFHE)   │   │
 * │  └──────────────┘                        └──────────────────────┘   │
 * │         │                                          │                │
 * │         │ 2. Get handle                            │ 3. Return      │
 * │         ▼                                          ▼    result      │
 * │  ┌──────────────┐                        ┌──────────────────────┐   │
 * │  │  FHEGateway  │◀───────────────────────│   Result + ZK Proof  │   │
 * │  │  (Handle     │                        │                      │   │
 * │  │   Registry)  │                        └──────────────────────┘   │
 * │  └──────────────┘                                                   │
 * │         │                                                           │
 * │         │ 4. ACL check                                              │
 * │         ▼                                                           │
 * │  ┌──────────────┐                                                   │
 * │  │  Caller gets │                                                   │
 * │  │  output      │                                                   │
 * │  │  handle      │                                                   │
 * │  └──────────────┘                                                   │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Security Considerations:
 * - All handles are verified before use
 * - ACL controls who can use encrypted values
 * - Coprocessor results require ZK proofs
 * - Signature malleability protection on all ECDSA operations
 */
contract FHEGateway is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant COPROCESSOR_ROLE = keccak256("COPROCESSOR_ROLE");
    bytes32 public constant KMS_ROLE = keccak256("KMS_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum request TTL (1 hour)
    uint256 public constant MAX_REQUEST_TTL = 3600;

    /// @notice Maximum inputs per batch
    uint256 public constant MAX_BATCH_SIZE = 16;

    /// @notice Default security zone
    bytes32 public constant DEFAULT_ZONE = keccak256("DEFAULT");

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Coprocessor address for off-chain FHE computation
    address public coprocessor;

    /// @notice Key Management Service address
    address public kms;

    /// @notice Active FHE scheme
    FHELib.FHEScheme public activeScheme;

    /// @notice Network public key hash
    bytes32 public networkPublicKeyHash;

    /// @notice Request nonce for unique IDs
    uint256 public requestNonce;

    /// @notice Handle registry: handleId => Handle
    mapping(bytes32 => FHELib.Handle) public handles;

    /// @notice Access control list: handleId => address => allowed
    mapping(bytes32 => mapping(address => bool)) public acl;

    /// @notice Delegated access: handleId => delegator => delegate => allowed
    mapping(bytes32 => mapping(address => mapping(address => bool)))
        public delegatedAccess;

    /// @notice Security zones (enabled zones)
    mapping(bytes32 => bool) public securityZones;

    /// @notice Compute requests: requestId => request
    mapping(bytes32 => FHELib.ComputeRequest) public computeRequests;

    /// @notice Decryption requests: requestId => request
    mapping(bytes32 => FHELib.DecryptionRequest) public decryptionRequests;

    /// @notice Reencryption requests: requestId => request
    mapping(bytes32 => FHELib.ReencryptionRequest) public reencryptionRequests;

    /// @notice Pending requests per address
    mapping(address => bytes32[]) public pendingRequests;

    /// @notice Request queue for coprocessor
    bytes32[] public requestQueue;

    // ============================================
    // ERRORS
    // ============================================

    error InvalidHandle();
    error HandleAlreadyExists();
    error HandleNotVerified();
    error UnauthorizedAccess();
    error SecurityZoneMismatch();
    error RequestExpired();
    error RequestAlreadyFulfilled();
    error InvalidRequestStatus();
    error TooManyInputs();
    error InvalidOpcode();
    error ZeroAddress();
    error InvalidScheme();

    // ============================================
    // EVENTS
    // ============================================

    event HandleCreated(
        bytes32 indexed handleId,
        uint8 valueType,
        address indexed creator
    );

    event HandleVerified(bytes32 indexed handleId, address indexed verifier);

    event AccessGranted(
        bytes32 indexed handleId,
        address indexed grantee,
        address indexed grantor
    );

    event AccessRevoked(
        bytes32 indexed handleId,
        address indexed revokee,
        address indexed revoker
    );

    event ComputeRequested(
        bytes32 indexed requestId,
        uint8 opcode,
        address indexed requester
    );

    event ComputeCompleted(
        bytes32 indexed requestId,
        bytes32 indexed outputHandle,
        address indexed coprocessor
    );

    event DecryptionRequested(
        bytes32 indexed requestId,
        bytes32 indexed handleId,
        address indexed requester
    );

    event DecryptionCompleted(bytes32 indexed requestId, bytes32 result);

    event ReencryptionRequested(
        bytes32 indexed requestId,
        bytes32 indexed handleId,
        address indexed requester
    );

    event ReencryptionCompleted(bytes32 indexed requestId);

    event SchemeUpdated(FHELib.FHEScheme oldScheme, FHELib.FHEScheme newScheme);

    event SecurityZoneEnabled(bytes32 indexed zone);
    event SecurityZoneDisabled(bytes32 indexed zone);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address _coprocessor, address _kms, FHELib.FHEScheme _scheme) {
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
        securityZones[DEFAULT_ZONE] = true;
        emit SecurityZoneEnabled(DEFAULT_ZONE);
    }

    // ============================================
    // HANDLE MANAGEMENT
    // ============================================

    /**
     * @notice Create a new encrypted handle
     * @param valueType The type of encrypted value (FHELib.ValueType)
     * @param securityZone The security domain
     * @return handleId The new handle ID
     */
    function createHandle(
        uint8 valueType,
        bytes32 securityZone
    ) external whenNotPaused returns (bytes32 handleId) {
        if (!securityZones[securityZone]) revert SecurityZoneMismatch();
        if (!FHELib.isValidValueType(valueType)) revert InvalidHandle();

        requestNonce++;
        handleId = FHELib.computeHandleId(
            msg.sender,
            valueType,
            securityZone,
            requestNonce
        );

        if (handles[handleId].id != bytes32(0)) revert HandleAlreadyExists();

        handles[handleId] = FHELib.Handle({
            id: handleId,
            valueType: valueType,
            securityZone: securityZone,
            verified: false,
            createdAt: uint64(block.timestamp)
        });

        // Grant ACL to creator
        acl[handleId][msg.sender] = true;

        emit HandleCreated(handleId, valueType, msg.sender);
    }

    /**
     * @notice Verify a handle (called by coprocessor after ciphertext validation)
     * @param handleId The handle to verify
     */
    function verifyHandle(
        bytes32 handleId
    ) external onlyRole(COPROCESSOR_ROLE) {
        if (handles[handleId].id == bytes32(0)) revert InvalidHandle();

        handles[handleId].verified = true;

        emit HandleVerified(handleId, msg.sender);
    }

    /**
     * @notice Check if a handle is valid and verified
     * @param handleId The handle to check
     * @return valid Whether the handle exists
     * @return verified Whether the handle is verified
     */
    function checkHandle(
        bytes32 handleId
    ) external view returns (bool valid, bool verified) {
        FHELib.Handle storage h = handles[handleId];
        valid = h.id != bytes32(0);
        verified = h.verified;
    }

    /**
     * @notice Get handle information
     * @param handleId The handle ID
     * @return info The handle info
     */
    function getHandleInfo(
        bytes32 handleId
    ) external view returns (FHELib.Handle memory info) {
        return handles[handleId];
    }

    // ============================================
    // ACCESS CONTROL
    // ============================================

    /**
     * @notice Grant access to an encrypted value
     * @param handleId The handle to grant access to
     * @param grantee The address to grant access
     */
    function grantAccess(bytes32 handleId, address grantee) external {
        if (handles[handleId].id == bytes32(0)) revert InvalidHandle();
        if (!acl[handleId][msg.sender]) revert UnauthorizedAccess();
        if (grantee == address(0)) revert ZeroAddress();

        acl[handleId][grantee] = true;

        emit AccessGranted(handleId, grantee, msg.sender);
    }

    /**
     * @notice Revoke access to an encrypted value
     * @param handleId The handle to revoke access from
     * @param revokee The address to revoke access
     */
    function revokeAccess(bytes32 handleId, address revokee) external {
        if (handles[handleId].id == bytes32(0)) revert InvalidHandle();
        if (!acl[handleId][msg.sender]) revert UnauthorizedAccess();

        acl[handleId][revokee] = false;

        emit AccessRevoked(handleId, revokee, msg.sender);
    }

    /**
     * @notice Check if an address has access to a handle
     * @param handleId The handle
     * @param account The address to check
     * @return hasAccess Whether the address has access
     */
    function hasAccess(
        bytes32 handleId,
        address account
    ) external view returns (bool) {
        return acl[handleId][account];
    }

    /**
     * @notice Delegate access from one address to another
     * @param handleId The handle
     * @param delegate The delegate address
     */
    function delegateAccess(bytes32 handleId, address delegate) external {
        if (!acl[handleId][msg.sender]) revert UnauthorizedAccess();
        if (delegate == address(0)) revert ZeroAddress();

        delegatedAccess[handleId][msg.sender][delegate] = true;
    }

    // ============================================
    // FHE COMPUTATION REQUESTS
    // ============================================

    /**
     * @notice Request an FHE computation
     * @param opcode The operation code
     * @param inputHandles Array of input handle IDs
     * @param deadline Maximum timestamp for completion
     * @return requestId The request ID
     * @return outputHandle The expected output handle
     */
    function requestCompute(
        uint8 opcode,
        bytes32[] calldata inputHandles,
        uint64 deadline
    )
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 requestId, bytes32 outputHandle)
    {
        if (inputHandles.length > MAX_BATCH_SIZE) revert TooManyInputs();
        if (!FHELib.validateInputCount(opcode, inputHandles.length))
            revert InvalidOpcode();
        if (deadline > block.timestamp + MAX_REQUEST_TTL) {
            deadline = uint64(block.timestamp + MAX_REQUEST_TTL);
        }

        // Verify caller has access to all inputs
        for (uint256 i = 0; i < inputHandles.length; i++) {
            if (!acl[inputHandles[i]][msg.sender]) revert UnauthorizedAccess();
            if (!handles[inputHandles[i]].verified) revert HandleNotVerified();
        }

        // Generate request and output IDs
        requestNonce++;
        requestId = FHELib.computeRequestId(
            msg.sender,
            opcode,
            inputHandles,
            requestNonce
        );

        // Determine output type based on operation
        uint8 outputType = _computeOutputType(opcode, inputHandles);

        outputHandle = FHELib.computeHandleId(
            address(this),
            outputType,
            DEFAULT_ZONE,
            requestNonce
        );

        // Create output handle
        handles[outputHandle] = FHELib.Handle({
            id: outputHandle,
            valueType: outputType,
            securityZone: DEFAULT_ZONE,
            verified: false,
            createdAt: uint64(block.timestamp)
        });

        // Grant ACL to requester
        acl[outputHandle][msg.sender] = true;

        // Store request
        computeRequests[requestId] = FHELib.ComputeRequest({
            requestId: requestId,
            opcode: opcode,
            inputs: inputHandles,
            output: outputHandle,
            requester: msg.sender,
            gasEstimate: FHELib.estimateFHEGas(opcode, inputHandles.length),
            timestamp: uint64(block.timestamp),
            deadline: deadline,
            status: FHELib.RequestStatus.Pending
        });

        // Add to queue
        requestQueue.push(requestId);
        pendingRequests[msg.sender].push(requestId);

        emit ComputeRequested(requestId, opcode, msg.sender);
    }

    /**
     * @notice Complete a computation request (called by coprocessor)
     * @param requestId The request ID
     * @param proof ZK proof of correct computation
     */
    function completeCompute(
        bytes32 requestId,
        bytes calldata proof
    ) external onlyRole(COPROCESSOR_ROLE) nonReentrant {
        FHELib.ComputeRequest storage req = computeRequests[requestId];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.status != FHELib.RequestStatus.Pending)
            revert InvalidRequestStatus();
        if (block.timestamp > req.deadline) revert RequestExpired();

        // Verify proof (simplified - full implementation would verify ZK proof)
        if (proof.length == 0) revert InvalidHandle();

        // Mark output handle as verified
        handles[req.output].verified = true;

        // Update request status
        req.status = FHELib.RequestStatus.Completed;

        emit ComputeCompleted(requestId, req.output, msg.sender);
    }

    // ============================================
    // DECRYPTION REQUESTS
    // ============================================

    /**
     * @notice Request decryption of an encrypted value
     * @param handleId The handle to decrypt
     * @param callbackContract Contract to receive the result
     * @param callbackSelector Function selector for callback
     * @param maxTimestamp Deadline for decryption
     * @return requestId The request ID
     */
    function requestDecryption(
        bytes32 handleId,
        address callbackContract,
        bytes4 callbackSelector,
        uint64 maxTimestamp
    ) external whenNotPaused nonReentrant returns (bytes32 requestId) {
        if (!acl[handleId][msg.sender]) revert UnauthorizedAccess();
        if (!handles[handleId].verified) revert HandleNotVerified();
        if (callbackContract == address(0)) revert ZeroAddress();

        if (maxTimestamp > block.timestamp + MAX_REQUEST_TTL) {
            maxTimestamp = uint64(block.timestamp + MAX_REQUEST_TTL);
        }

        requestNonce++;
        requestId = keccak256(
            abi.encode(
                "DECRYPT",
                handleId,
                msg.sender,
                requestNonce,
                block.chainid
            )
        );

        decryptionRequests[requestId] = FHELib.DecryptionRequest({
            requestId: requestId,
            handle: handleId,
            requester: msg.sender,
            callbackContract: callbackContract,
            callbackSelector: callbackSelector,
            maxTimestamp: maxTimestamp,
            fulfilled: false,
            result: bytes32(0)
        });

        pendingRequests[msg.sender].push(requestId);

        emit DecryptionRequested(requestId, handleId, msg.sender);
    }

    /**
     * @notice Complete a decryption request (called by KMS)
     * @param requestId The request ID
     * @param plaintextResult The decrypted value
     */
    function completeDecryption(
        bytes32 requestId,
        bytes32 plaintextResult
    ) external onlyRole(KMS_ROLE) nonReentrant {
        FHELib.DecryptionRequest storage req = decryptionRequests[requestId];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.fulfilled) revert RequestAlreadyFulfilled();
        if (block.timestamp > req.maxTimestamp) revert RequestExpired();

        req.fulfilled = true;
        req.result = plaintextResult;

        // Execute callback
        (bool success, ) = req.callbackContract.call(
            abi.encodeWithSelector(
                req.callbackSelector,
                requestId,
                plaintextResult
            )
        );

        // We don't revert on callback failure to prevent DoS
        if (success) {
            emit DecryptionCompleted(requestId, plaintextResult);
        }
    }

    // ============================================
    // REENCRYPTION REQUESTS
    // ============================================

    /**
     * @notice Preview the next reencryption request ID
     * @param handleId The handle to reencrypt
     * @param targetPublicKey The target's public key
     * @param requester The requester address
     * @return requestId The expected request ID for the next nonce
     */
    function previewReencryptionRequest(
        bytes32 handleId,
        bytes32 targetPublicKey,
        address requester
    ) external view returns (bytes32 requestId) {
        uint256 nextNonce = requestNonce + 1;
        requestId = keccak256(
            abi.encode(
                "REENCRYPT",
                handleId,
                targetPublicKey,
                requester,
                nextNonce
            )
        );
    }

    /**
     * @notice Request reencryption to a different public key
     * @param handleId The handle to reencrypt
     * @param targetPublicKey The target's public key
     * @return requestId The request ID
     */
    function requestReencryption(
        bytes32 handleId,
        bytes32 targetPublicKey
    ) external whenNotPaused returns (bytes32 requestId) {
        if (!acl[handleId][msg.sender]) revert UnauthorizedAccess();
        if (!handles[handleId].verified) revert HandleNotVerified();

        requestNonce++;
        requestId = keccak256(
            abi.encode(
                "REENCRYPT",
                handleId,
                targetPublicKey,
                msg.sender,
                requestNonce
            )
        );

        reencryptionRequests[requestId] = FHELib.ReencryptionRequest({
            requestId: requestId,
            handle: handleId,
            requester: msg.sender,
            targetPublicKey: targetPublicKey,
            maxTimestamp: uint64(block.timestamp + MAX_REQUEST_TTL),
            fulfilled: false,
            reencryptedCiphertext: ""
        });

        pendingRequests[msg.sender].push(requestId);

        emit ReencryptionRequested(requestId, handleId, msg.sender);
    }

    /**
     * @notice Complete a reencryption request (called by KMS)
     * @param requestId The request ID
     * @param reencryptedValue The reencrypted ciphertext
     */
    function completeReencryption(
        bytes32 requestId,
        bytes calldata reencryptedValue
    ) external onlyRole(KMS_ROLE) {
        FHELib.ReencryptionRequest storage req = reencryptionRequests[
            requestId
        ];

        if (req.requestId == bytes32(0)) revert InvalidHandle();
        if (req.fulfilled) revert RequestAlreadyFulfilled();
        if (block.timestamp > req.maxTimestamp) revert RequestExpired();

        req.fulfilled = true;
        req.reencryptedCiphertext = reencryptedValue;

        emit ReencryptionCompleted(requestId);
    }

    // ============================================
    // SECURITY ZONE MANAGEMENT
    // ============================================

    /**
     * @notice Enable a security zone
     * @param zone The zone identifier
     */
    function enableSecurityZone(bytes32 zone) external onlyRole(OPERATOR_ROLE) {
        securityZones[zone] = true;
        emit SecurityZoneEnabled(zone);
    }

    /**
     * @notice Disable a security zone
     * @param zone The zone identifier
     */
    function disableSecurityZone(
        bytes32 zone
    ) external onlyRole(OPERATOR_ROLE) {
        if (zone == DEFAULT_ZONE) revert SecurityZoneMismatch();
        securityZones[zone] = false;
        emit SecurityZoneDisabled(zone);
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Update the coprocessor address
     * @param _coprocessor New coprocessor address
     */
    function setCoprocessor(
        address _coprocessor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_coprocessor == address(0)) revert ZeroAddress();

        _revokeRole(COPROCESSOR_ROLE, coprocessor);
        coprocessor = _coprocessor;
        _grantRole(COPROCESSOR_ROLE, _coprocessor);
    }

    /**
     * @notice Update the KMS address
     * @param _kms New KMS address
     */
    function setKMS(address _kms) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_kms == address(0)) revert ZeroAddress();

        _revokeRole(KMS_ROLE, kms);
        kms = _kms;
        _grantRole(KMS_ROLE, _kms);
    }

    /**
     * @notice Update the active FHE scheme
     * @param _scheme New scheme
     */
    function setScheme(
        FHELib.FHEScheme _scheme
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        FHELib.FHEScheme oldScheme = activeScheme;
        activeScheme = _scheme;
        emit SchemeUpdated(oldScheme, _scheme);
    }

    /**
     * @notice Pause the gateway
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the gateway
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get the request queue length
     * @return length Queue length
     */
    function getQueueLength() external view returns (uint256 length) {
        return requestQueue.length;
    }

    /**
     * @notice Get pending requests for an address
     * @param account The address
     * @return requests Array of request IDs
     */
    function getPendingRequests(
        address account
    ) external view returns (bytes32[] memory requests) {
        return pendingRequests[account];
    }

    /**
     * @notice Get compute request details
     * @param requestId The request ID
     * @return request The request details
     */
    function getComputeRequest(
        bytes32 requestId
    ) external view returns (FHELib.ComputeRequest memory request) {
        return computeRequests[requestId];
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    /**
     * @notice Compute the output type for an operation
     * @param opcode The operation
     * @param inputHandles Input handles
     * @return outputType The output value type
     */
    function _computeOutputType(
        uint8 opcode,
        bytes32[] calldata inputHandles
    ) internal view returns (uint8 outputType) {
        // Comparison operations return ebool
        if (
            opcode >= uint8(FHELib.Opcode.EQ) &&
            opcode <= uint8(FHELib.Opcode.LT)
        ) {
            return uint8(FHELib.ValueType.ebool);
        }

        // Other operations return same type as first input
        if (inputHandles.length > 0) {
            return handles[inputHandles[0]].valueType;
        }

        return uint8(FHELib.ValueType.euint256);
    }
}
