// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title ViewKeyRegistry
 * @author ZASEON
 * @notice Registry for managing cryptographic view keys for selective disclosure
 * @dev Enables controlled transparency while maintaining default privacy
 *
 * VIEW KEY TYPES:
 * 1. Incoming View Key - See incoming transactions
 * 2. Outgoing View Key - See outgoing transactions
 * 3. Full View Key - See all transactions
 * 4. Balance View Key - See current balance only
 * 5. Audit View Key - Time-limited full access
 *
 * PRIVACY MODEL:
 * - View keys are derived from master secret
 * - Different keys for different access levels
 * - Time-bound keys for audits
 * - Revocable access grants
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract ViewKeyRegistry is
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 public constant MAX_GRANTS_PER_ACCOUNT = 100;
    uint256 public constant MIN_GRANT_DURATION = 1 hours;
    uint256 public constant MAX_GRANT_DURATION = 365 days;
    uint256 public constant REVOCATION_DELAY = 1 hours;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum ViewKeyType {
        INCOMING,
        OUTGOING,
        FULL,
        BALANCE,
        AUDIT
    }

    enum GrantStatus {
        ACTIVE,
        REVOKED,
        EXPIRED,
        PENDING_REVOCATION
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Public view key registration
     * @param publicKey The public portion of view key
     * @param keyType Type of view access
     * @param commitment Commitment to the private key
     * @param registrationTime When key was registered
     * @param isActive Whether key is currently active
     */
    struct ViewKey {
        bytes32 publicKey;
        ViewKeyType keyType;
        bytes32 commitment;
        uint256 registrationTime;
        bool isActive;
    }

    /**
     * @notice Grant of view access to another party
     * @param grantId Unique grant identifier
     * @param granter Account granting access
     * @param grantee Account receiving access
     * @param viewKeyHash Hash of the view key being shared
     * @param keyType Type of access granted
     * @param startTime When grant becomes active
     * @param endTime When grant expires
     * @param status Current status of grant
     * @param scope Optional scope restriction (chain ID, contract, etc.)
     */
    struct ViewGrant {
        bytes32 grantId;
        address granter;
        address grantee;
        bytes32 viewKeyHash;
        ViewKeyType keyType;
        uint256 startTime;
        uint256 endTime;
        GrantStatus status;
        bytes32 scope;
    }

    /**
     * @notice Audit trail entry
     */
    struct AuditEntry {
        bytes32 grantId;
        address accessor;
        uint256 accessTime;
        bytes32 accessProof;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    // Account -> View keys (one per type)
    mapping(address => mapping(ViewKeyType => ViewKey)) public viewKeys;

    // Account -> Active view key count
    mapping(address => uint256) public activeKeyCount;

    // Grant ID -> Grant details
    mapping(bytes32 => ViewGrant) public grants;

    // Grantee -> Array of grant IDs they have received
    mapping(address => bytes32[]) public receivedGrants;

    // Granter -> Array of grant IDs they have issued
    mapping(address => bytes32[]) public issuedGrants;

    // Grant ID -> Audit trail
    mapping(bytes32 => AuditEntry[]) public auditTrail;

    // Nonce for grant ID generation
    mapping(address => uint256) public grantNonce;

    // Statistics
    uint256 public totalKeysRegistered;
    uint256 public totalGrantsIssued;
    uint256 public totalActiveGrants;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ViewKeyRegistered(
        address indexed account,
        ViewKeyType keyType,
        bytes32 publicKey
    );
    event ViewKeyRevoked(address indexed account, ViewKeyType keyType);
    event ViewKeyRotated(
        address indexed account,
        ViewKeyType keyType,
        bytes32 oldKey,
        bytes32 newKey
    );

    event ViewGrantIssued(
        bytes32 indexed grantId,
        address indexed granter,
        address indexed grantee,
        ViewKeyType keyType,
        uint256 endTime
    );
    event ViewGrantRevoked(bytes32 indexed grantId, address indexed revoker);
    event ViewGrantExpired(bytes32 indexed grantId);
    event ViewGrantAccessed(
        bytes32 indexed grantId,
        address indexed accessor,
        bytes32 accessProof
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error KeyAlreadyRegistered();
    error KeyNotRegistered();
    error KeyNotActive();
    error InvalidKeyType();
    error InvalidDuration();
    error MaxGrantsReached();
    error GrantNotFound();
    error GrantNotActive();
    error GrantExpired();
    error UnauthorizedAccess();
    error RevocationPending();
    error InvalidScope();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

        /**
     * @notice Initializes the operation
     * @param admin The admin bound
     */
function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    // =========================================================================
    // VIEW KEY MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new view key
     * @param keyType Type of view key
     * @param publicKey Public portion of key
     * @param commitment Commitment to private key (for verification)
     */
    function registerViewKey(
        ViewKeyType keyType,
        bytes32 publicKey,
        bytes32 commitment
    ) external nonReentrant whenNotPaused {
        if (viewKeys[msg.sender][keyType].isActive)
            revert KeyAlreadyRegistered();

        viewKeys[msg.sender][keyType] = ViewKey({
            publicKey: publicKey,
            keyType: keyType,
            commitment: commitment,
            registrationTime: block.timestamp,
            isActive: true
        });

        unchecked {
            ++activeKeyCount[msg.sender];
            ++totalKeysRegistered;
        }

        emit ViewKeyRegistered(msg.sender, keyType, publicKey);
    }

    /**
     * @notice Revoke a view key
     * @param keyType Type of key to revoke
     */
    function revokeViewKey(ViewKeyType keyType) external nonReentrant {
        ViewKey storage key = viewKeys[msg.sender][keyType];
        if (!key.isActive) revert KeyNotActive();

        key.isActive = false;
        unchecked {
            --activeKeyCount[msg.sender];
        }

        // Revoke all grants using this key
        _revokeGrantsForKey(msg.sender, keyType);

        emit ViewKeyRevoked(msg.sender, keyType);
    }

    /**
     * @notice Rotate a view key
     * @param keyType Type of key to rotate
     * @param newPublicKey New public key
     * @param newCommitment New commitment
     */
    function rotateViewKey(
        ViewKeyType keyType,
        bytes32 newPublicKey,
        bytes32 newCommitment
    ) external nonReentrant whenNotPaused {
        ViewKey storage key = viewKeys[msg.sender][keyType];
        if (!key.isActive) revert KeyNotActive();

        bytes32 oldKey = key.publicKey;

        key.publicKey = newPublicKey;
        key.commitment = newCommitment;
        key.registrationTime = block.timestamp;

        // Update all active grants with new key hash
        _updateGrantsForKeyRotation(msg.sender, keyType, newPublicKey);

        emit ViewKeyRotated(msg.sender, keyType, oldKey, newPublicKey);
    }

    // =========================================================================
    // VIEW GRANT MANAGEMENT
    // =========================================================================

    /**
     * @notice Issue a view grant to another account
     * @param grantee Account to grant access to
     * @param keyType Type of access to grant
     * @param duration How long the grant lasts
     * @param scope Optional scope restriction
          * @return grantId The grant id
     */
    function issueGrant(
        address grantee,
        ViewKeyType keyType,
        uint256 duration,
        bytes32 scope
    ) external nonReentrant whenNotPaused returns (bytes32 grantId) {
        if (!viewKeys[msg.sender][keyType].isActive) revert KeyNotActive();
        if (duration < MIN_GRANT_DURATION || duration > MAX_GRANT_DURATION)
            revert InvalidDuration();
        if (issuedGrants[msg.sender].length >= MAX_GRANTS_PER_ACCOUNT)
            revert MaxGrantsReached();

        // SECURITY FIX: Changed from abi.encodePacked to abi.encode to prevent hash collision
        grantId = keccak256(
            abi.encode(msg.sender, grantee, grantNonce[msg.sender]++)
        );

        uint256 endTime = block.timestamp + duration;
        // SECURITY FIX: Use abi.encode for viewKeyHash
        bytes32 viewKeyHash = keccak256(
            abi.encode(viewKeys[msg.sender][keyType].publicKey)
        );

        grants[grantId] = ViewGrant({
            grantId: grantId,
            granter: msg.sender,
            grantee: grantee,
            viewKeyHash: viewKeyHash,
            keyType: keyType,
            startTime: block.timestamp,
            endTime: endTime,
            status: GrantStatus.ACTIVE,
            scope: scope
        });

        issuedGrants[msg.sender].push(grantId);
        receivedGrants[grantee].push(grantId);

        unchecked {
            ++totalGrantsIssued;
            ++totalActiveGrants;
        }

        emit ViewGrantIssued(grantId, msg.sender, grantee, keyType, endTime);
    }

    /**
     * @notice Issue an audit grant (time-limited full access)
     * @param auditor Auditor address
     * @param duration Audit duration
     * @param scope Audit scope (e.g., specific chain or time range)
          * @return grantId The grant id
     */
    function issueAuditGrant(
        address auditor,
        uint256 duration,
        bytes32 scope
    ) external nonReentrant whenNotPaused returns (bytes32 grantId) {
        // Audit grants require FULL view key
        if (!viewKeys[msg.sender][ViewKeyType.FULL].isActive)
            revert KeyNotActive();
        if (duration > 30 days) revert InvalidDuration(); // Max 30 days for audits
        if (issuedGrants[msg.sender].length >= MAX_GRANTS_PER_ACCOUNT)
            revert MaxGrantsReached();

        // SECURITY FIX: Changed from abi.encodePacked to abi.encode to prevent hash collision
        grantId = keccak256(
            abi.encode(msg.sender, auditor, grantNonce[msg.sender]++)
        );

        uint256 endTime = block.timestamp + duration;
        // SECURITY FIX: Use abi.encode for viewKeyHash
        bytes32 viewKeyHash = keccak256(
            abi.encode(viewKeys[msg.sender][ViewKeyType.AUDIT].publicKey)
        );

        grants[grantId] = ViewGrant({
            grantId: grantId,
            granter: msg.sender,
            grantee: auditor,
            viewKeyHash: viewKeyHash,
            keyType: ViewKeyType.AUDIT,
            startTime: block.timestamp,
            endTime: endTime,
            status: GrantStatus.ACTIVE,
            scope: scope
        });

        issuedGrants[msg.sender].push(grantId);
        receivedGrants[auditor].push(grantId);

        unchecked {
            ++totalGrantsIssued;
            ++totalActiveGrants;
        }

        emit ViewGrantIssued(
            grantId,
            msg.sender,
            auditor,
            ViewKeyType.AUDIT,
            endTime
        );
    }

    /**
     * @notice Revoke a grant
     * @param grantId Grant to revoke
     */
    function revokeGrant(bytes32 grantId) external nonReentrant {
        ViewGrant storage grant = grants[grantId];
        if (grant.grantId == bytes32(0)) revert GrantNotFound();
        if (msg.sender != grant.granter) revert UnauthorizedAccess();
        if (grant.status != GrantStatus.ACTIVE) revert GrantNotActive();

        // Start revocation delay (gives grantee notice)
        grant.status = GrantStatus.PENDING_REVOCATION;

        emit ViewGrantRevoked(grantId, msg.sender);
    }

    /**
     * @notice Complete revocation after delay
     * @param grantId Grant to finalize revocation
     */
    function finalizeRevocation(bytes32 grantId) external {
        ViewGrant storage grant = grants[grantId];
        if (grant.status != GrantStatus.PENDING_REVOCATION)
            revert GrantNotActive();

        grant.status = GrantStatus.REVOKED;
        unchecked {
            --totalActiveGrants;
        }
    }

    /**
     * @notice Record access to a grant (for audit trail)
     * @param grantId Grant being accessed
     * @param accessProof Proof of valid access
     */
    function recordAccess(
        bytes32 grantId,
        bytes32 accessProof
    ) external nonReentrant {
        ViewGrant storage grant = grants[grantId];
        if (grant.grantId == bytes32(0)) revert GrantNotFound();
        if (msg.sender != grant.grantee) revert UnauthorizedAccess();
        if (grant.status != GrantStatus.ACTIVE) revert GrantNotActive();
        if (block.timestamp > grant.endTime) {
            grant.status = GrantStatus.EXPIRED;
            unchecked {
                --totalActiveGrants;
            }
            revert GrantExpired();
        }

        auditTrail[grantId].push(
            AuditEntry({
                grantId: grantId,
                accessor: msg.sender,
                accessTime: block.timestamp,
                accessProof: accessProof
            })
        );

        emit ViewGrantAccessed(grantId, msg.sender, accessProof);
    }

    // =========================================================================
    // VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a view key disclosure proof
     * @param account Account claiming ownership
     * @param keyType Key type being verified
     * @param proof Proof of key ownership
          * @return The result value
     */
    function verifyKeyOwnership(
        address account,
        ViewKeyType keyType,
        bytes calldata proof
    ) external view returns (bool) {
        ViewKey storage key = viewKeys[account][keyType];
        if (!key.isActive) return false;

        // Verify proof against commitment
        bytes32 expectedCommitment = keccak256(proof);
        return expectedCommitment == key.commitment;
    }

    /**
     * @notice Check if a grant is currently valid
     * @param grantId Grant to check
          * @return The result value
     */
    function isGrantValid(bytes32 grantId) external view returns (bool) {
        ViewGrant storage grant = grants[grantId];
        return
            grant.status == GrantStatus.ACTIVE &&
            block.timestamp <= grant.endTime;
    }

    /**
     * @notice Get grant details
          * @param grantId The grantId identifier
     * @return granter The granter
     * @return grantee The grantee
     * @return keyType The key type
     * @return startTime The start time
     * @return endTime The end time
     * @return status The status
     * @return scope The scope
     */
    function getGrantDetails(
        bytes32 grantId
    )
        external
        view
        returns (
            address granter,
            address grantee,
            ViewKeyType keyType,
            uint256 startTime,
            uint256 endTime,
            GrantStatus status,
            bytes32 scope
        )
    {
        ViewGrant storage grant = grants[grantId];
        return (
            grant.granter,
            grant.grantee,
            grant.keyType,
            grant.startTime,
            grant.endTime,
            grant.status,
            grant.scope
        );
    }

    /**
     * @notice Get all active grants for an account (as grantee)
          * @param account The account address
     * @return The result value
     */
    function getActiveGrantsReceived(
        address account
    ) external view returns (bytes32[] memory) {
        bytes32[] storage allGrants = receivedGrants[account];
        uint256 activeCount = 0;

        // Count active grants
        for (uint256 i = 0; i < allGrants.length; ) {
            if (
                grants[allGrants[i]].status == GrantStatus.ACTIVE &&
                block.timestamp <= grants[allGrants[i]].endTime
            ) {
                unchecked {
                    ++activeCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Build active grants array
        bytes32[] memory active = new bytes32[](activeCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < allGrants.length; ) {
            if (
                grants[allGrants[i]].status == GrantStatus.ACTIVE &&
                block.timestamp <= grants[allGrants[i]].endTime
            ) {
                active[idx++] = allGrants[i];
            }
            unchecked {
                ++i;
            }
        }

        return active;
    }

    /**
     * @notice Get audit trail for a grant
          * @param grantId The grantId identifier
     * @return The result value
     */
    function getAuditTrail(
        bytes32 grantId
    ) external view returns (AuditEntry[] memory) {
        return auditTrail[grantId];
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    function _revokeGrantsForKey(
        address granter,
        ViewKeyType keyType
    ) internal {
        bytes32[] storage grantIds = issuedGrants[granter];

        for (uint256 i = 0; i < grantIds.length; ) {
            ViewGrant storage grant = grants[grantIds[i]];
            if (
                grant.keyType == keyType && grant.status == GrantStatus.ACTIVE
            ) {
                grant.status = GrantStatus.REVOKED;
                unchecked {
                    --totalActiveGrants;
                }
                emit ViewGrantRevoked(grantIds[i], granter);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _updateGrantsForKeyRotation(
        address granter,
        ViewKeyType keyType,
        bytes32 newPublicKey
    ) internal {
        bytes32[] storage grantIds = issuedGrants[granter];
        // SECURITY FIX: Changed from abi.encodePacked to abi.encode
        bytes32 newKeyHash = keccak256(abi.encode(newPublicKey));

        for (uint256 i = 0; i < grantIds.length; ) {
            ViewGrant storage grant = grants[grantIds[i]];
            if (
                grant.keyType == keyType && grant.status == GrantStatus.ACTIVE
            ) {
                grant.viewKeyHash = newKeyHash;
            }
            unchecked {
                ++i;
            }
        }
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(ADMIN_ROLE) {}
}
