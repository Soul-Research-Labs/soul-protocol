// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title SelectiveDisclosureManager
 * @author ZASEON
 * @notice Programmable viewing permissions for institutional compliance
 * @dev Enables selective field-level disclosure while maintaining ZK privacy.
 *
 * DESIGN PRINCIPLES:
 *  1. Viewing keys are on-chain access grants — actual decryption happens
 *     off-chain with the viewer's derived key.
 *  2. Compliance proofs are verified through IProofVerifier (pluggable ZK backend).
 *  3. Audit trail is append-only and bounded per transaction.
 *  4. All state-changing external functions use nonReentrant.
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract SelectiveDisclosureManager is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant COMPLIANCE_ADMIN = keccak256("COMPLIANCE_ADMIN");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant REGULATOR_ROLE = keccak256("REGULATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Privacy level for a transaction's default visibility
    enum DisclosureLevel {
        NONE, // Fully private (default)
        COUNTERPARTY, // Counterparty can view
        AUDITOR, // Authorized auditors can view
        REGULATOR, // Regulators can view
        PUBLIC // Fully public
    }

    /// @notice Individual fields that can be selectively disclosed
    enum FieldType {
        AMOUNT,
        SENDER,
        RECEIVER,
        TIMESTAMP,
        METADATA,
        COMMITMENT,
        NULLIFIER,
        ALL
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Access grant for a specific viewer on a specific transaction
    struct ViewingKey {
        address viewer;
        DisclosureLevel level;
        uint48 grantedAt;
        uint48 expiresAt; // 0 = permanent
        FieldType[] allowedFields;
        bool isActive;
    }

    /// @notice Registered private transaction metadata
    struct PrivateTransaction {
        bytes32 commitment;
        address owner;
        DisclosureLevel defaultLevel;
        uint48 createdAt;
        uint16 viewerCount;
        bool exists;
    }

    /// @notice Immutable audit trail entry
    struct AuditEntry {
        address viewer;
        uint48 viewedAt;
        uint8 fieldCount;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice ZK proof verifier for compliance proofs
    IProofVerifier public complianceVerifier;

    /// @notice Transaction registry (txId => metadata)
    mapping(bytes32 => PrivateTransaction) internal _transactions;

    /// @notice Viewing keys (txId => viewer => key)
    mapping(bytes32 => mapping(address => ViewingKey)) internal _viewingKeys;

    /// @notice Viewer list per transaction (txId => viewers[])
    mapping(bytes32 => address[]) internal _transactionViewers;

    /// @notice Bounded audit trail (txId => entries[])
    mapping(bytes32 => AuditEntry[]) internal _auditTrail;

    /// @notice Compliance proof hashes (txId => proofHash)
    mapping(bytes32 => bytes32) public complianceProofs;

    /// @notice User default disclosure levels
    mapping(address => DisclosureLevel) public userDefaultLevel;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum viewers per transaction (prevents unbounded growth)
    uint256 public constant MAX_VIEWERS_PER_TX = 50;

    /// @notice Maximum audit entries per transaction
    uint256 public constant MAX_AUDIT_ENTRIES = 500;

    /// @notice Maximum batch size for bulk operations
    uint256 public constant MAX_BATCH_SIZE = 50;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event TransactionRegistered(
        bytes32 indexed txId,
        address indexed owner,
        DisclosureLevel defaultLevel
    );
    event ViewingKeyGranted(
        bytes32 indexed txId,
        address indexed viewer,
        DisclosureLevel level,
        uint256 expiresAt
    );
    event ViewingKeyRevoked(bytes32 indexed txId, address indexed viewer);
    event TransactionViewed(
        bytes32 indexed txId,
        address indexed viewer,
        uint256 fieldCount
    );
    event ComplianceProofVerified(bytes32 indexed txId, bytes32 proofHash);
    event ComplianceVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event AuditorAuthorized(address indexed auditor);
    event AuditorRevoked(address indexed auditor);
    event RegulatorAuthorized(address indexed regulator);
    event RegulatorRevoked(address indexed regulator);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error TransactionNotFound();
    error TransactionAlreadyExists();
    error UnauthorizedViewer();
    error ViewingKeyExpired();
    error ViewingKeyNotActive();
    error FieldNotAllowed(FieldType field);
    error NotTransactionOwner();
    error ZeroAddress();
    error MaxViewersReached();
    error MaxAuditEntriesReached();
    error BatchTooLarge();
    error InvalidProof();
    error NoVerifierConfigured();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Default admin and compliance admin
    /// @param _complianceVerifier Optional ZK verifier for compliance proofs (address(0) to skip)
    constructor(address admin, address _complianceVerifier) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(COMPLIANCE_ADMIN, admin);

        if (_complianceVerifier != address(0)) {
            complianceVerifier = IProofVerifier(_complianceVerifier);
        }
    }

    /*//////////////////////////////////////////////////////////////
                     TRANSACTION REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a private transaction for disclosure management
     * @param txId Unique identifier (typically keccak256 of commitment + chain data)
     * @param commitment State commitment from ConfidentialStateContainerV3
     * @param defaultLevel Default disclosure level
     */
    function registerTransaction(
        bytes32 txId,
        bytes32 commitment,
        DisclosureLevel defaultLevel
    ) external nonReentrant {
        if (_transactions[txId].exists) revert TransactionAlreadyExists();

        _transactions[txId] = PrivateTransaction({
            commitment: commitment,
            owner: msg.sender,
            defaultLevel: defaultLevel,
            createdAt: uint48(block.timestamp),
            viewerCount: 0,
            exists: true
        });

        emit TransactionRegistered(txId, msg.sender, defaultLevel);
    }

    /**
     * @notice Register a transaction on behalf of a user (called by integrated contracts)
     * @dev Only callable by addresses with COMPLIANCE_ADMIN role
     * @param txId Transaction identifier
     * @param commitment State commitment
     * @param owner Transaction owner
     * @param defaultLevel Disclosure level
     */
    function registerTransactionFor(
        bytes32 txId,
        bytes32 commitment,
        address owner,
        DisclosureLevel defaultLevel
    ) external nonReentrant onlyRole(COMPLIANCE_ADMIN) {
        if (owner == address(0)) revert ZeroAddress();
        if (_transactions[txId].exists) revert TransactionAlreadyExists();

        _transactions[txId] = PrivateTransaction({
            commitment: commitment,
            owner: owner,
            defaultLevel: defaultLevel,
            createdAt: uint48(block.timestamp),
            viewerCount: 0,
            exists: true
        });

        emit TransactionRegistered(txId, owner, defaultLevel);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEWING KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Grant viewing permission to an address
     * @param txId Transaction to grant access to
     * @param viewer Address to grant permission (must not be zero)
     * @param level Disclosure level for this viewer
     * @param duration Duration in seconds (0 = permanent)
     * @param allowedFields Which fields the viewer can see
     */
    function grantViewingKey(
        bytes32 txId,
        address viewer,
        DisclosureLevel level,
        uint256 duration,
        FieldType[] calldata allowedFields
    ) external nonReentrant {
        _grantViewingKeyInternal(txId, viewer, level, duration, allowedFields);
    }

    /**
     * @notice Batch grant viewing keys for an audit
     * @param txIds Transaction IDs to grant access to
     * @param viewer Address to grant permission
     * @param level Disclosure level
     * @param duration Duration in seconds
     * @param allowedFields Which fields the viewer can see
     */
    function batchGrantViewingKeys(
        bytes32[] calldata txIds,
        address viewer,
        DisclosureLevel level,
        uint256 duration,
        FieldType[] calldata allowedFields
    ) external nonReentrant {
        uint256 len = txIds.length;
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge();

        for (uint256 i; i < len; ) {
            _grantViewingKeyInternal(
                txIds[i],
                viewer,
                level,
                duration,
                allowedFields
            );
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Revoke viewing permission
     * @param txId Transaction to revoke access from
     * @param viewer Address to revoke
     */
    function revokeViewingKey(
        bytes32 txId,
        address viewer
    ) external nonReentrant {
        PrivateTransaction storage txn = _transactions[txId];
        if (!txn.exists) revert TransactionNotFound();
        if (txn.owner != msg.sender) revert NotTransactionOwner();

        _viewingKeys[txId][viewer].isActive = false;
        emit ViewingKeyRevoked(txId, viewer);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW RECORDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record that a viewer has accessed a transaction (audit trail)
     * @dev Off-chain systems decrypt data; this records the on-chain audit trail.
     *      Reverts if the viewer does not have permission for the requested fields.
     * @param txId Transaction to view
     * @param fieldsToView Which fields the viewer is accessing
     * @return authorized Whether the viewer has permission
     */
    function recordView(
        bytes32 txId,
        FieldType[] calldata fieldsToView
    ) external nonReentrant returns (bool authorized) {
        PrivateTransaction storage txn = _transactions[txId];
        if (!txn.exists) revert TransactionNotFound();

        // Validate permission (reverts if unauthorized)
        _validateViewingPermission(txId, msg.sender, fieldsToView);

        // Record in bounded audit trail
        AuditEntry[] storage trail = _auditTrail[txId];
        if (trail.length >= MAX_AUDIT_ENTRIES) revert MaxAuditEntriesReached();

        trail.push(
            AuditEntry({
                viewer: msg.sender,
                viewedAt: uint48(block.timestamp),
                fieldCount: uint8(fieldsToView.length)
            })
        );

        emit TransactionViewed(txId, msg.sender, fieldsToView.length);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                       COMPLIANCE PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a ZK proof of compliance for a transaction
     * @dev Proves AML/KYC/sanctions compliance without revealing transaction contents.
     *      Requires a configured IProofVerifier.
     * @param txId Transaction to prove compliance for
     * @param proof ZK proof bytes
     * @param publicInputs Public inputs for the proof
     * @return valid Whether the proof verified
     */
    function submitComplianceProof(
        bytes32 txId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant returns (bool valid) {
        PrivateTransaction storage txn = _transactions[txId];
        if (!txn.exists) revert TransactionNotFound();
        if (address(complianceVerifier) == address(0))
            revert NoVerifierConfigured();

        // Verify through pluggable ZK backend
        valid = complianceVerifier.verifyProof(proof, publicInputs);
        if (!valid) revert InvalidProof();

        complianceProofs[txId] = keccak256(
            abi.encodePacked(proof, publicInputs)
        );
        emit ComplianceProofVerified(txId, complianceProofs[txId]);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Authorize an auditor
        /**
     * @notice Authorize auditor
     * @param auditor The auditor
     */
function authorizeAuditor(
        address auditor
    ) external onlyRole(COMPLIANCE_ADMIN) {
        if (auditor == address(0)) revert ZeroAddress();
        _grantRole(AUDITOR_ROLE, auditor);
        emit AuditorAuthorized(auditor);
    }

    /// @notice Revoke an auditor
        /**
     * @notice Revokes auditor
     * @param auditor The auditor
     */
function revokeAuditor(
        address auditor
    ) external onlyRole(COMPLIANCE_ADMIN) {
        _revokeRole(AUDITOR_ROLE, auditor);
        emit AuditorRevoked(auditor);
    }

    /// @notice Authorize a regulator
        /**
     * @notice Authorize regulator
     * @param regulator The regulator
     */
function authorizeRegulator(
        address regulator
    ) external onlyRole(COMPLIANCE_ADMIN) {
        if (regulator == address(0)) revert ZeroAddress();
        _grantRole(REGULATOR_ROLE, regulator);
        emit RegulatorAuthorized(regulator);
    }

    /// @notice Revoke a regulator
        /**
     * @notice Revokes regulator
     * @param regulator The regulator
     */
function revokeRegulator(
        address regulator
    ) external onlyRole(COMPLIANCE_ADMIN) {
        _revokeRole(REGULATOR_ROLE, regulator);
        emit RegulatorRevoked(regulator);
    }

    /// @notice Update the compliance proof verifier
        /**
     * @notice Sets the compliance verifier
     * @param newVerifier The new Verifier value
     */
function setComplianceVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = address(complianceVerifier);
        complianceVerifier = IProofVerifier(newVerifier);
        emit ComplianceVerifierUpdated(old, newVerifier);
    }

    /// @notice Set default disclosure level for a user
        /**
     * @notice Sets the user default level
     * @param user The user
     * @param level The level value
     */
function setUserDefaultLevel(
        address user,
        DisclosureLevel level
    ) external onlyRole(COMPLIANCE_ADMIN) {
        if (user == address(0)) revert ZeroAddress();
        userDefaultLevel[user] = level;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get transaction metadata
        /**
     * @notice Returns the transaction
     * @param txId The txId identifier
     * @return The result value
     */
function getTransaction(
        bytes32 txId
    ) external view returns (PrivateTransaction memory) {
        return _transactions[txId];
    }

    /// @notice Check if a viewer has active permission
        /**
     * @notice Checks if has viewing permission
     * @param txId The txId identifier
     * @param viewer The viewer
     * @return The result value
     */
function hasViewingPermission(
        bytes32 txId,
        address viewer
    ) external view returns (bool) {
        PrivateTransaction storage txn = _transactions[txId];
        if (!txn.exists) return false;
        if (txn.owner == viewer) return true;

        ViewingKey storage key = _viewingKeys[txId][viewer];
        return
            key.isActive &&
            (key.expiresAt == 0 || block.timestamp < key.expiresAt);
    }

    /// @notice Get viewing key details
        /**
     * @notice Returns the viewing key
     * @param txId The txId identifier
     * @param viewer The viewer
     * @return The result value
     */
function getViewingKey(
        bytes32 txId,
        address viewer
    ) external view returns (ViewingKey memory) {
        return _viewingKeys[txId][viewer];
    }

    /// @notice Get all viewers for a transaction
        /**
     * @notice Returns the transaction viewers
     * @param txId The txId identifier
     * @return The result value
     */
function getTransactionViewers(
        bytes32 txId
    ) external view returns (address[] memory) {
        return _transactionViewers[txId];
    }

    /// @notice Get audit trail for a transaction
        /**
     * @notice Returns the audit trail
     * @param txId The txId identifier
     * @return The result value
     */
function getAuditTrail(
        bytes32 txId
    ) external view returns (AuditEntry[] memory) {
        return _auditTrail[txId];
    }

    /// @notice Check if transaction has valid compliance proof
        /**
     * @notice Checks if compliant
     * @param txId The txId identifier
     * @return The result value
     */
function isCompliant(bytes32 txId) external view returns (bool) {
        return complianceProofs[txId] != bytes32(0);
    }

    /// @notice Get the number of viewers for a transaction
        /**
     * @notice Returns the viewer count
     * @param txId The txId identifier
     * @return The result value
     */
function getViewerCount(bytes32 txId) external view returns (uint256) {
        return _transactions[txId].viewerCount;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _grantViewingKeyInternal(
        bytes32 txId,
        address viewer,
        DisclosureLevel level,
        uint256 duration,
        FieldType[] calldata allowedFields
    ) internal {
        if (viewer == address(0)) revert ZeroAddress();

        PrivateTransaction storage txn = _transactions[txId];
        if (!txn.exists) revert TransactionNotFound();
        if (txn.owner != msg.sender) revert NotTransactionOwner();

        // Enforce bounded viewer list (only count new viewers)
        if (
            !_viewingKeys[txId][viewer].isActive &&
            _viewingKeys[txId][viewer].grantedAt == 0
        ) {
            if (txn.viewerCount >= MAX_VIEWERS_PER_TX)
                revert MaxViewersReached();
            _transactionViewers[txId].push(viewer);
            unchecked {
                ++txn.viewerCount;
            }
        }

        uint48 expiresAt = duration == 0
            ? uint48(0)
            : uint48(block.timestamp + duration);

        _viewingKeys[txId][viewer] = ViewingKey({
            viewer: viewer,
            level: level,
            grantedAt: uint48(block.timestamp),
            expiresAt: expiresAt,
            allowedFields: allowedFields,
            isActive: true
        });

        emit ViewingKeyGranted(txId, viewer, level, expiresAt);
    }

    function _validateViewingPermission(
        bytes32 txId,
        address viewer,
        FieldType[] calldata fieldsToView
    ) internal view {
        PrivateTransaction storage txn = _transactions[txId];

        // Owner always has full access
        if (txn.owner == viewer) return;

        ViewingKey storage key = _viewingKeys[txId][viewer];

        if (!key.isActive) revert ViewingKeyNotActive();
        if (key.expiresAt != 0 && block.timestamp >= key.expiresAt)
            revert ViewingKeyExpired();

        // Check field-level permissions
        uint256 fieldsLen = fieldsToView.length;
        for (uint256 i; i < fieldsLen; ) {
            bool allowed;
            uint256 allowedLen = key.allowedFields.length;
            for (uint256 j; j < allowedLen; ) {
                if (
                    key.allowedFields[j] == FieldType.ALL ||
                    key.allowedFields[j] == fieldsToView[i]
                ) {
                    allowed = true;
                    break;
                }
                unchecked {
                    ++j;
                }
            }
            if (!allowed) revert FieldNotAllowed(fieldsToView[i]);
            unchecked {
                ++i;
            }
        }
    }
}
