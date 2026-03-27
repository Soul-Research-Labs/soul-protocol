// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IViewKeyRegistry
 * @notice Interface for managing cryptographic view keys for selective disclosure
 */
interface IViewKeyRegistry {
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

    struct ViewKey {
        bytes32 publicKey;
        ViewKeyType keyType;
        bytes32 commitment;
        uint256 registrationTime;
        bool isActive;
    }

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

    struct AuditEntry {
        bytes32 grantId;
        address accessor;
        uint256 accessTime;
        bytes32 accessProof;
    }

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
    error MaxReceivedGrantsReached();
    error GrantNotFound();
    error GrantNotActive();
    error GrantExpired();
    error UnauthorizedAccess();
    error RevocationPending();
    error InvalidScope();
    error ZeroAddress();

    // =========================================================================
    // VIEW KEY MANAGEMENT
    // =========================================================================

    function registerViewKey(
        ViewKeyType keyType,
        bytes32 publicKey,
        bytes32 commitment
    ) external;

    function revokeViewKey(ViewKeyType keyType) external;

    function rotateViewKey(
        ViewKeyType keyType,
        bytes32 newPublicKey,
        bytes32 newCommitment
    ) external;

    // =========================================================================
    // GRANT MANAGEMENT
    // =========================================================================

    function issueGrant(
        address grantee,
        ViewKeyType keyType,
        uint256 duration,
        bytes32 scope
    ) external returns (bytes32 grantId);

    function issueAuditGrant(
        address auditor,
        uint256 duration,
        bytes32 scope
    ) external returns (bytes32 grantId);

    function revokeGrant(bytes32 grantId) external;

    function finalizeRevocation(bytes32 grantId) external;

    function recordAccess(bytes32 grantId, bytes32 accessProof) external;

    // =========================================================================
    // VERIFICATION
    // =========================================================================

    function verifyKeyOwnership(
        address account,
        ViewKeyType keyType,
        bytes calldata proof
    ) external view returns (bool);

    function isGrantValid(bytes32 grantId) external view returns (bool);

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function activeKeyCount(address account) external view returns (uint256);

    function grantNonce(address account) external view returns (uint256);

    function totalKeysRegistered() external view returns (uint256);

    function totalGrantsIssued() external view returns (uint256);

    function totalActiveGrants() external view returns (uint256);

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
        );

    function getActiveGrantsReceived(
        address account
    ) external view returns (bytes32[] memory);

    function getAuditTrail(
        bytes32 grantId
    ) external view returns (AuditEntry[] memory);

    // =========================================================================
    // ADMIN
    // =========================================================================

    function pause() external;

    function unpause() external;
}
