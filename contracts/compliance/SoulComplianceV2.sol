// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title SoulComplianceV2
/// @author Soul Protocol
/// @notice KYC, AML, and compliance registry with selective disclosure and audit trails
/// @dev Implements zero-knowledge KYC verification and regulatory compliance
contract SoulComplianceV2 is Ownable, ReentrancyGuard, Pausable {
    /// @notice KYC status enum
    enum KYCStatus {
        None,
        Pending,
        Approved,
        Rejected,
        Expired
    }

    /// @notice KYC tier levels
    enum KYCTier {
        Unverified,
        Basic, // Email + Phone
        Standard, // ID verification
        Enhanced, // Full KYC + AML
        Institutional
    }

    /// @notice User KYC record
    /// @param status Current KYC status
    /// @param tier Verification tier
    /// @param provider KYC provider address
    /// @param verifiedAt Verification timestamp
    /// @param expiresAt Expiration timestamp
    /// @param credentialHash Hash of credentials (for privacy)
    /// @param jurisdiction User jurisdiction code
    struct KYCRecord {
        KYCStatus status;
        KYCTier tier;
        address provider;
        uint256 verifiedAt;
        uint256 expiresAt;
        bytes32 credentialHash;
        bytes2 jurisdiction;
    }

    /// @notice Audit trail entry
    /// @param auditor Auditor address
    /// @param user Audited user
    /// @param stateRoot State root at time of audit
    /// @param timestamp Audit timestamp
    /// @param proof Compliance proof
    /// @param result Audit result
    struct AuditTrail {
        address auditor;
        address user;
        bytes32 stateRoot;
        uint256 timestamp;
        bytes proof;
        bool result;
    }

    /// @notice User KYC records
    mapping(address => KYCRecord) public kycRecords;

    /// @notice Authorized KYC providers
    mapping(address => bool) public authorizedProviders;

    /// @notice Authorized auditors
    mapping(address => bool) public authorizedAuditors;

    /// @notice Audit trails
    mapping(bytes32 => AuditTrail) public auditTrails;

    /// @notice User audit history
    mapping(address => bytes32[]) public userAuditHistory;

    /// @notice Sanctioned addresses
    mapping(address => bool) public sanctionedAddresses;

    /// @notice Restricted jurisdictions
    mapping(bytes2 => bool) public restrictedJurisdictions;

    /// @notice Minimum KYC tier required for operations
    KYCTier public minRequiredTier = KYCTier.Basic;

    /// @notice KYC validity duration (365 days default)
    uint256 public kycValidityDuration = 365 days;

    /// @notice Events
    event KYCProviderAuthorized(address indexed provider);
    event KYCProviderRevoked(address indexed provider);
    event KYCVerified(
        address indexed user,
        KYCTier tier,
        address indexed provider
    );
    event KYCRevoked(address indexed user, string reason);
    event AuditorAuthorized(address indexed auditor);
    event AuditorRevoked(address indexed auditor);
    event AuditCompleted(
        bytes32 indexed auditId,
        address indexed user,
        bool result
    );
    event AddressSanctioned(address indexed user);
    event AddressUnsanctioned(address indexed user);
    event JurisdictionRestricted(bytes2 indexed jurisdiction);
    event JurisdictionUnrestricted(bytes2 indexed jurisdiction);
    event MinRequiredTierUpdated(KYCTier oldTier, KYCTier newTier);
    event KYCValidityDurationUpdated(uint256 oldDuration, uint256 newDuration);

    /// @notice Custom errors
    error NotAuthorizedProvider();
    error NotAuthorizedAuditor();
    error UserAlreadyVerified();
    error UserNotVerified();
    error KYCExpired();
    error AddressIsSanctioned();
    error RestrictedJurisdiction();
    error InsufficientKYCTier();
    error ZeroAddress();
    error DurationTooShort();
    error DurationTooLong();

    /// @notice Modifier for authorized providers
    modifier onlyProvider() {
        if (!authorizedProviders[msg.sender]) revert NotAuthorizedProvider();
        _;
    }

    /// @notice Modifier for authorized auditors
    modifier onlyAuditor() {
        if (!authorizedAuditors[msg.sender]) revert NotAuthorizedAuditor();
        _;
    }

    constructor() Ownable(msg.sender) {}

    /// @notice Authorizes a KYC provider
    /// @param provider The provider address
    function authorizeProvider(address provider) external onlyOwner {
        if (provider == address(0)) revert ZeroAddress();
        authorizedProviders[provider] = true;
        emit KYCProviderAuthorized(provider);
    }

    /// @notice Revokes a KYC provider
    /// @param provider The provider address
    function revokeProvider(address provider) external onlyOwner {
        if (provider == address(0)) revert ZeroAddress();
        authorizedProviders[provider] = false;
        emit KYCProviderRevoked(provider);
    }

    /// @notice Authorizes an auditor
    /// @param auditor The auditor address
    function authorizeAuditor(address auditor) external onlyOwner {
        if (auditor == address(0)) revert ZeroAddress();
        authorizedAuditors[auditor] = true;
        emit AuditorAuthorized(auditor);
    }

    /// @notice Revokes an auditor
    /// @param auditor The auditor address
    function revokeAuditor(address auditor) external onlyOwner {
        if (auditor == address(0)) revert ZeroAddress();
        authorizedAuditors[auditor] = false;
        emit AuditorRevoked(auditor);
    }

    /// @notice Verifies a user's KYC (called by provider)
    /// @param user The user address
    /// @param tier The KYC tier achieved
    /// @param credentialHash Hash of credentials
    /// @param jurisdiction User's jurisdiction
    function verifyKYC(
        address user,
        KYCTier tier,
        bytes32 credentialHash,
        bytes2 jurisdiction
    ) external onlyProvider whenNotPaused {
        if (restrictedJurisdictions[jurisdiction])
            revert RestrictedJurisdiction();
        if (sanctionedAddresses[user]) revert AddressIsSanctioned();

        kycRecords[user] = KYCRecord({
            status: KYCStatus.Approved,
            tier: tier,
            provider: msg.sender,
            verifiedAt: block.timestamp,
            expiresAt: block.timestamp + kycValidityDuration,
            credentialHash: credentialHash,
            jurisdiction: jurisdiction
        });

        emit KYCVerified(user, tier, msg.sender);
    }

    /// @notice Revokes a user's KYC
    /// @param user The user address
    /// @param reason Reason for revocation
    function revokeKYC(
        address user,
        string calldata reason
    ) external onlyProvider {
        kycRecords[user].status = KYCStatus.Rejected;
        emit KYCRevoked(user, reason);
    }

    /// @notice Checks if a user's KYC is valid
    /// @param user The user address
    /// @return valid True if KYC is valid
    function isKYCValid(address user) public view returns (bool valid) {
        KYCRecord storage record = kycRecords[user];
        return
            record.status == KYCStatus.Approved &&
            block.timestamp < record.expiresAt &&
            record.tier >= minRequiredTier;
    }

    /// @notice Checks if a user meets minimum tier requirement
    /// @param user The user address
    /// @param requiredTier The required tier
    /// @return meets True if user meets requirement
    function meetsKYCTier(
        address user,
        KYCTier requiredTier
    ) external view returns (bool meets) {
        KYCRecord storage record = kycRecords[user];
        return
            record.status == KYCStatus.Approved &&
            block.timestamp < record.expiresAt &&
            record.tier >= requiredTier;
    }

    /// @notice Records an audit
    /// @param user The audited user
    /// @param stateRoot State root at audit time
    /// @param proof Compliance proof
    /// @param result Audit result
    /// @return auditId The audit trail ID
    function recordAudit(
        address user,
        bytes32 stateRoot,
        bytes calldata proof,
        bool result
    ) external onlyAuditor returns (bytes32 auditId) {
        auditId = keccak256(
            abi.encodePacked(msg.sender, user, stateRoot, block.timestamp)
        );

        auditTrails[auditId] = AuditTrail({
            auditor: msg.sender,
            user: user,
            stateRoot: stateRoot,
            timestamp: block.timestamp,
            proof: proof,
            result: result
        });

        userAuditHistory[user].push(auditId);
        emit AuditCompleted(auditId, user, result);
    }

    /// @notice Sanctions an address
    /// @param user The address to sanction
    function sanctionAddress(address user) external onlyOwner {
        if (user == address(0)) revert ZeroAddress();
        sanctionedAddresses[user] = true;
        kycRecords[user].status = KYCStatus.Rejected;
        emit AddressSanctioned(user);
    }

    /// @notice Removes sanction from an address
    /// @param user The address to unsanction
    function unsanctionAddress(address user) external onlyOwner {
        if (user == address(0)) revert ZeroAddress();
        sanctionedAddresses[user] = false;
        emit AddressUnsanctioned(user);
    }

    /// @notice Restricts a jurisdiction
    /// @param jurisdiction The jurisdiction code
    function restrictJurisdiction(bytes2 jurisdiction) external onlyOwner {
        restrictedJurisdictions[jurisdiction] = true;
        emit JurisdictionRestricted(jurisdiction);
    }

    /// @notice Unrestricts a jurisdiction
    /// @param jurisdiction The jurisdiction code
    function unrestrictJurisdiction(bytes2 jurisdiction) external onlyOwner {
        restrictedJurisdictions[jurisdiction] = false;
        emit JurisdictionUnrestricted(jurisdiction);
    }

    /// @notice Updates minimum required KYC tier
    /// @param tier The new minimum tier
    function setMinRequiredTier(KYCTier tier) external onlyOwner {
        KYCTier oldTier = minRequiredTier;
        minRequiredTier = tier;
        emit MinRequiredTierUpdated(oldTier, tier);
    }

    /// @notice Updates KYC validity duration
    /// @param duration The new duration in seconds
    function setKYCValidityDuration(uint256 duration) external onlyOwner {
        if (duration < 1 days) revert DurationTooShort();
        if (duration > 730 days) revert DurationTooLong();
        uint256 oldDuration = kycValidityDuration;
        kycValidityDuration = duration;
        emit KYCValidityDurationUpdated(oldDuration, duration);
    }

    /// @notice Gets a user's audit history
    /// @param user The user address
    /// @return auditIds Array of audit IDs
    function getUserAuditHistory(
        address user
    ) external view returns (bytes32[] memory auditIds) {
        return userAuditHistory[user];
    }

    /// @notice Pause the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyOwner {
        _unpause();
    }
}
