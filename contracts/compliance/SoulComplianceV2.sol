// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SoulComplianceV2
 * @author Soul Protocol
 * @notice KYC, AML, and Regulatory Compliance for Privacy Protocols
 * @dev Enables compliant privacy through selective disclosure and audit trails
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    COMPLIANCE ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Privacy ≠ Anonymity
 *
 * Soul Protocol implements COMPLIANT PRIVACY:
 * - Users maintain privacy from other users
 * - Authorized auditors can verify compliance
 * - Regulatory requirements are met without mass surveillance
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    KYC TIERS
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * TIER 0: Unverified
 *   - Basic access
 *   - Small transaction limits
 *
 * TIER 1: Basic
 *   - Email verification
 *   - Moderate limits
 *
 * TIER 2: Standard
 *   - ID verification
 *   - Higher limits
 *
 * TIER 3: Enhanced
 *   - Full KYC + source of funds
 *   - Institutional limits
 *
 * TIER 4: Institutional
 *   - Corporate KYC
 *   - Unlimited (within policy)
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract SoulComplianceV2 is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant COMPLIANCE_ADMIN_ROLE =
        keccak256("COMPLIANCE_ADMIN_ROLE");
    bytes32 public constant KYC_PROVIDER_ROLE = keccak256("KYC_PROVIDER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant SANCTION_ROLE = keccak256("SANCTION_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // ============================================
    // ENUMS
    // ============================================

    /// @notice KYC verification status
    enum KYCStatus {
        None, // No KYC submitted
        Pending, // Verification in progress
        Approved, // Verified
        Rejected, // Verification failed
        Expired // Verification expired
    }

    /// @notice KYC verification tier
    enum KYCTier {
        Unverified, // No verification
        Basic, // Email only
        Standard, // ID verification
        Enhanced, // Full KYC + source of funds
        Institutional // Corporate KYC
    }

    /// @notice Audit event types
    enum AuditEventType {
        KYC_SUBMITTED, // KYC submission
        KYC_APPROVED, // KYC approved
        KYC_REJECTED, // KYC rejected
        KYC_EXPIRED, // KYC expired
        TRANSACTION, // Transaction audit
        SANCTION_CHECK, // Sanction list check
        DISCLOSURE, // Selective disclosure
        ALERT // Compliance alert
    }

    // ============================================
    // ERRORS
    // ============================================

    error AddressNotKYCd(address account);
    error KYCExpired(address account);
    error KYCPending(address account);
    error KYCRejectedError(address account);
    error InsufficientKYCTier(
        address account,
        KYCTier required,
        KYCTier actual
    );
    error AddressSanctioned(address account);
    error JurisdictionRestrictedError(address account, bytes2 jurisdiction);
    error ProviderNotAuthorized(address provider);
    error AuditorNotAuthorized(address auditor);
    error InvalidKYCDuration(uint256 duration);
    error ZeroAddress();
    error AuditTrailEmpty();
    error DuplicateSubmission();

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice KYC record
    struct KYCRecord {
        address account; // Account address
        KYCStatus status; // Current status
        KYCTier tier; // Verification tier
        address provider; // KYC provider
        bytes32 dataHash; // Hash of KYC data (stored off-chain)
        bytes2 jurisdiction; // ISO country code
        uint64 verifiedAt; // Verification timestamp
        uint64 expiresAt; // Expiration timestamp
        bytes32 disclosurePolicy; // Bound disclosure policy
    }

    /// @notice Audit trail entry
    struct AuditEntry {
        bytes32 entryId; // Unique entry ID
        address account; // Related account
        AuditEventType eventType; // Event type
        bytes32 dataHash; // Event data hash
        address auditor; // Auditor who created entry
        uint64 timestamp; // Event timestamp
        bytes signature; // Auditor signature
    }

    /// @notice Disclosure request
    struct DisclosureRequest {
        bytes32 requestId; // Unique request ID
        address requester; // Requesting entity
        address target; // Target account
        bytes32[] dataFields; // Requested data fields
        string reason; // Request reason
        bool approved; // Approval status
        uint64 requestedAt; // Request timestamp
        uint64 expiresAt; // Approval expiration
    }

    /// @notice Transaction limit per tier
    struct TierLimits {
        uint256 dailyLimit; // Daily transaction limit
        uint256 monthlyLimit; // Monthly transaction limit
        uint256 singleTxLimit; // Single transaction limit
    }

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Default KYC validity duration (1 year)
    uint256 public constant DEFAULT_KYC_VALIDITY = 365 days;

    /// @notice Minimum KYC validity (1 day)
    uint256 public constant MIN_KYC_VALIDITY = 1 days;

    /// @notice Maximum KYC validity (2 years)
    uint256 public constant MAX_KYC_VALIDITY = 730 days;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice KYC records by address
    mapping(address => KYCRecord) public kycRecords;

    /// @notice Sanctioned addresses
    mapping(address => bool) public sanctionedAddresses;

    /// @notice Restricted jurisdictions
    mapping(bytes2 => bool) public restrictedJurisdictions;

    /// @notice Authorized KYC providers
    mapping(address => bool) public authorizedProviders;

    /// @notice Authorized auditors
    mapping(address => bool) public authorizedAuditors;

    /// @notice Audit trail by account
    mapping(address => AuditEntry[]) internal _auditTrails;

    /// @notice Disclosure requests
    mapping(bytes32 => DisclosureRequest) public disclosureRequests;

    /// @notice Tier limits
    mapping(KYCTier => TierLimits) public tierLimits;

    /// @notice Daily spend tracking
    mapping(address => mapping(uint256 => uint256)) public dailySpend;

    /// @notice Monthly spend tracking
    mapping(address => mapping(uint256 => uint256)) public monthlySpend;

    /// @notice KYC validity duration
    uint256 public kycValidityDuration = DEFAULT_KYC_VALIDITY;

    /// @notice Total KYC records
    uint256 public totalKYCRecords;

    /// @notice Total audit entries
    uint256 public totalAuditEntries;

    /// @notice Total disclosure requests
    uint256 public totalDisclosureRequests;

    // ============================================
    // EVENTS
    // ============================================

    event KYCSubmitted(
        address indexed account,
        address indexed provider,
        bytes32 dataHash
    );

    event KYCApproved(
        address indexed account,
        KYCTier tier,
        bytes2 jurisdiction,
        uint64 expiresAt
    );

    event KYCRejected(
        address indexed account,
        address indexed provider,
        string reason
    );

    event KYCExpiredEvent(address indexed account);

    event SanctionAdded(address indexed account, string reason);

    event SanctionRemoved(address indexed account);

    event JurisdictionRestricted(bytes2 indexed jurisdiction, bool restricted);

    event ProviderAuthorized(address indexed provider, bool authorized);

    event AuditorAuthorized(address indexed auditor, bool authorized);

    event AuditEntryCreated(
        bytes32 indexed entryId,
        address indexed account,
        AuditEventType eventType,
        address indexed auditor
    );

    event DisclosureRequested(
        bytes32 indexed requestId,
        address indexed requester,
        address indexed target
    );

    event DisclosureApproved(
        bytes32 indexed requestId,
        address indexed approver
    );

    event TierLimitsUpdated(
        KYCTier indexed tier,
        uint256 daily,
        uint256 monthly,
        uint256 singleTx
    );

    event KYCValidityDurationUpdated(uint256 oldDuration, uint256 newDuration);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COMPLIANCE_ADMIN_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Initialize tier limits (in wei, adjust as needed)
        tierLimits[KYCTier.Unverified] = TierLimits({
            dailyLimit: 1 ether,
            monthlyLimit: 5 ether,
            singleTxLimit: 0.5 ether
        });

        tierLimits[KYCTier.Basic] = TierLimits({
            dailyLimit: 10 ether,
            monthlyLimit: 50 ether,
            singleTxLimit: 5 ether
        });

        tierLimits[KYCTier.Standard] = TierLimits({
            dailyLimit: 100 ether,
            monthlyLimit: 500 ether,
            singleTxLimit: 50 ether
        });

        tierLimits[KYCTier.Enhanced] = TierLimits({
            dailyLimit: 1000 ether,
            monthlyLimit: 5000 ether,
            singleTxLimit: 500 ether
        });

        tierLimits[KYCTier.Institutional] = TierLimits({
            dailyLimit: type(uint256).max,
            monthlyLimit: type(uint256).max,
            singleTxLimit: type(uint256).max
        });
    }

    // ============================================
    // KYC MANAGEMENT
    // ============================================

    /**
     * @notice Submit KYC for verification
     * @param account Account to verify
     * @param dataHash Hash of KYC data (stored off-chain)
     * @param jurisdiction ISO country code
     */
    function submitKYC(
        address account,
        bytes32 dataHash,
        bytes2 jurisdiction
    ) external onlyRole(KYC_PROVIDER_ROLE) whenNotPaused {
        if (account == address(0)) revert ZeroAddress();
        if (!authorizedProviders[msg.sender])
            revert ProviderNotAuthorized(msg.sender);
        if (restrictedJurisdictions[jurisdiction]) {
            revert JurisdictionRestrictedError(account, jurisdiction);
        }

        KYCRecord storage record = kycRecords[account];

        // Prevent duplicate pending submissions
        if (record.status == KYCStatus.Pending) {
            revert DuplicateSubmission();
        }

        record.account = account;
        record.status = KYCStatus.Pending;
        record.provider = msg.sender;
        record.dataHash = dataHash;
        record.jurisdiction = jurisdiction;

        _createAuditEntry(account, AuditEventType.KYC_SUBMITTED, dataHash);

        emit KYCSubmitted(account, msg.sender, dataHash);
    }

    /**
     * @notice Approve KYC verification
     * @param account Account to approve
     * @param tier Assigned KYC tier
     * @param disclosurePolicy Bound disclosure policy hash
     */
    function approveKYC(
        address account,
        KYCTier tier,
        bytes32 disclosurePolicy
    ) external onlyRole(KYC_PROVIDER_ROLE) whenNotPaused {
        if (account == address(0)) revert ZeroAddress();

        KYCRecord storage record = kycRecords[account];
        if (record.status != KYCStatus.Pending) {
            revert KYCPending(account);
        }

        record.status = KYCStatus.Approved;
        record.tier = tier;
        record.verifiedAt = uint64(block.timestamp);
        record.expiresAt = uint64(block.timestamp + kycValidityDuration);
        record.disclosurePolicy = disclosurePolicy;

        if (record.account == address(0)) {
            // New record
            unchecked {
                ++totalKYCRecords;
            }
        }

        _createAuditEntry(
            account,
            AuditEventType.KYC_APPROVED,
            bytes32(uint256(tier))
        );

        emit KYCApproved(account, tier, record.jurisdiction, record.expiresAt);
    }

    /**
     * @notice Reject KYC verification
     * @param account Account to reject
     * @param reason Rejection reason
     */
    function rejectKYC(
        address account,
        string calldata reason
    ) external onlyRole(KYC_PROVIDER_ROLE) whenNotPaused {
        if (account == address(0)) revert ZeroAddress();

        KYCRecord storage record = kycRecords[account];
        if (record.status != KYCStatus.Pending) {
            revert KYCPending(account);
        }

        record.status = KYCStatus.Rejected;

        _createAuditEntry(
            account,
            AuditEventType.KYC_REJECTED,
            keccak256(bytes(reason))
        );

        emit KYCRejected(account, msg.sender, reason);
    }

    /**
     * @notice Mark expired KYC records
     * @param accounts Accounts to check
     */
    function expireKYC(address[] calldata accounts) external {
        for (uint256 i = 0; i < accounts.length; ) {
            KYCRecord storage record = kycRecords[accounts[i]];

            if (
                record.status == KYCStatus.Approved &&
                block.timestamp > record.expiresAt
            ) {
                record.status = KYCStatus.Expired;

                _createAuditEntry(
                    accounts[i],
                    AuditEventType.KYC_EXPIRED,
                    bytes32(0)
                );

                emit KYCExpiredEvent(accounts[i]);
            }

            unchecked {
                ++i;
            }
        }
    }

    // ============================================
    // SANCTION MANAGEMENT
    // ============================================

    /**
     * @notice Add address to sanction list
     * @param account Address to sanction
     * @param reason Sanction reason
     */
    function addSanction(
        address account,
        string calldata reason
    ) external onlyRole(SANCTION_ROLE) {
        if (account == address(0)) revert ZeroAddress();

        sanctionedAddresses[account] = true;

        _createAuditEntry(
            account,
            AuditEventType.SANCTION_CHECK,
            keccak256(bytes(reason))
        );

        emit SanctionAdded(account, reason);
    }

    /**
     * @notice Remove address from sanction list
     * @param account Address to unsanction
     */
    function removeSanction(address account) external onlyRole(SANCTION_ROLE) {
        if (account == address(0)) revert ZeroAddress();

        sanctionedAddresses[account] = false;

        emit SanctionRemoved(account);
    }

    /**
     * @notice Set jurisdiction restriction
     * @param jurisdiction ISO country code
     * @param restricted Whether restricted
     */
    function setJurisdictionRestriction(
        bytes2 jurisdiction,
        bool restricted
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        restrictedJurisdictions[jurisdiction] = restricted;

        emit JurisdictionRestricted(jurisdiction, restricted);
    }

    // ============================================
    // VERIFICATION FUNCTIONS
    // ============================================

    /**
     * @notice Check if account is KYC verified
     * @param account Account to check
     * @return True if verified and not expired
     */
    function isKYCVerified(address account) public view returns (bool) {
        KYCRecord storage record = kycRecords[account];
        return
            record.status == KYCStatus.Approved &&
            block.timestamp <= record.expiresAt;
    }

    /**
     * @notice Check if account meets tier requirement
     * @param account Account to check
     * @param requiredTier Minimum required tier
     * @return True if meets requirement
     */
    function meetsTierRequirement(
        address account,
        KYCTier requiredTier
    ) public view returns (bool) {
        if (!isKYCVerified(account)) return false;
        return uint8(kycRecords[account].tier) >= uint8(requiredTier);
    }

    /**
     * @notice Check if account is sanctioned
     * @param account Account to check
     * @return True if sanctioned
     */
    function isSanctioned(address account) public view returns (bool) {
        return sanctionedAddresses[account];
    }

    /**
     * @notice Check transaction limits
     * @param account Account to check
     * @param amount Transaction amount
     * @return allowed True if within limits
     */
    function checkTransactionLimits(
        address account,
        uint256 amount
    ) public view returns (bool allowed) {
        KYCTier tier = kycRecords[account].tier;
        TierLimits storage limits = tierLimits[tier];

        // Check single transaction limit
        if (amount > limits.singleTxLimit) return false;

        // Check daily limit
        uint256 day = block.timestamp / 1 days;
        if (dailySpend[account][day] + amount > limits.dailyLimit) return false;

        // Check monthly limit
        uint256 month = block.timestamp / 30 days;
        if (monthlySpend[account][month] + amount > limits.monthlyLimit)
            return false;

        return true;
    }

    /**
     * @notice Record transaction spend (called by protocol contracts)
     * @param account Account
     * @param amount Amount spent
     */
    function recordSpend(
        address account,
        uint256 amount
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        uint256 day = block.timestamp / 1 days;
        uint256 month = block.timestamp / 30 days;

        dailySpend[account][day] += amount;
        monthlySpend[account][month] += amount;
    }

    // ============================================
    // DISCLOSURE MANAGEMENT
    // ============================================

    /**
     * @notice Request selective disclosure
     * @param target Target account
     * @param dataFields Requested data fields
     * @param reason Request reason
     * @return requestId The disclosure request ID
     */
    function requestDisclosure(
        address target,
        bytes32[] calldata dataFields,
        string calldata reason
    ) external onlyRole(AUDITOR_ROLE) returns (bytes32 requestId) {
        if (target == address(0)) revert ZeroAddress();
        if (!authorizedAuditors[msg.sender])
            revert AuditorNotAuthorized(msg.sender);

        requestId = keccak256(
            abi.encodePacked(
                msg.sender,
                target,
                block.timestamp,
                totalDisclosureRequests
            )
        );

        disclosureRequests[requestId] = DisclosureRequest({
            requestId: requestId,
            requester: msg.sender,
            target: target,
            dataFields: dataFields,
            reason: reason,
            approved: false,
            requestedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 30 days)
        });

        unchecked {
            ++totalDisclosureRequests;
        }

        _createAuditEntry(target, AuditEventType.DISCLOSURE, requestId);

        emit DisclosureRequested(requestId, msg.sender, target);
        return requestId;
    }

    /**
     * @notice Approve disclosure request
     * @param requestId Request to approve
     */
    function approveDisclosure(
        bytes32 requestId
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        DisclosureRequest storage request = disclosureRequests[requestId];

        request.approved = true;

        emit DisclosureApproved(requestId, msg.sender);
    }

    // ============================================
    // AUDIT TRAIL
    // ============================================

    /**
     * @notice Create audit trail entry
     */
    function _createAuditEntry(
        address account,
        AuditEventType eventType,
        bytes32 dataHash
    ) internal {
        bytes32 entryId = keccak256(
            abi.encodePacked(
                account,
                eventType,
                dataHash,
                block.timestamp,
                totalAuditEntries
            )
        );

        AuditEntry memory entry = AuditEntry({
            entryId: entryId,
            account: account,
            eventType: eventType,
            dataHash: dataHash,
            auditor: msg.sender,
            timestamp: uint64(block.timestamp),
            signature: ""
        });

        _auditTrails[account].push(entry);

        unchecked {
            ++totalAuditEntries;
        }

        emit AuditEntryCreated(entryId, account, eventType, msg.sender);
    }

    /**
     * @notice Get audit trail for an account
     * @param account Account to query
     * @return entries Audit entries
     */
    function getAuditTrail(
        address account
    ) external view onlyRole(AUDITOR_ROLE) returns (AuditEntry[] memory) {
        return _auditTrails[account];
    }

    /**
     * @notice Get audit trail length
     * @param account Account to query
     */
    function getAuditTrailLength(
        address account
    ) external view returns (uint256) {
        return _auditTrails[account].length;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Authorize a KYC provider
     * @param provider Provider address
     * @param authorized Authorization status
     */
    function authorizeProvider(
        address provider,
        bool authorized
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        if (provider == address(0)) revert ZeroAddress();

        authorizedProviders[provider] = authorized;

        if (authorized) {
            _grantRole(KYC_PROVIDER_ROLE, provider);
        } else {
            _revokeRole(KYC_PROVIDER_ROLE, provider);
        }

        emit ProviderAuthorized(provider, authorized);
    }

    /**
     * @notice Authorize an auditor
     * @param auditor Auditor address
     * @param authorized Authorization status
     */
    function authorizeAuditor(
        address auditor,
        bool authorized
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        if (auditor == address(0)) revert ZeroAddress();

        authorizedAuditors[auditor] = authorized;

        if (authorized) {
            _grantRole(AUDITOR_ROLE, auditor);
        } else {
            _revokeRole(AUDITOR_ROLE, auditor);
        }

        emit AuditorAuthorized(auditor, authorized);
    }

    /**
     * @notice Update tier limits
     * @param tier Tier to update
     * @param dailyLimit New daily limit
     * @param monthlyLimit New monthly limit
     * @param singleTxLimit New single tx limit
     */
    function setTierLimits(
        KYCTier tier,
        uint256 dailyLimit,
        uint256 monthlyLimit,
        uint256 singleTxLimit
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        tierLimits[tier] = TierLimits({
            dailyLimit: dailyLimit,
            monthlyLimit: monthlyLimit,
            singleTxLimit: singleTxLimit
        });

        emit TierLimitsUpdated(tier, dailyLimit, monthlyLimit, singleTxLimit);
    }

    /**
     * @notice Set KYC validity duration
     * @param duration New duration in seconds
     */
    function setKYCValidityDuration(
        uint256 duration
    ) external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        if (duration < MIN_KYC_VALIDITY || duration > MAX_KYC_VALIDITY) {
            revert InvalidKYCDuration(duration);
        }

        uint256 oldDuration = kycValidityDuration;
        kycValidityDuration = duration;

        emit KYCValidityDurationUpdated(oldDuration, duration);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(COMPLIANCE_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @notice Get KYC record
    function getKYCRecord(
        address account
    ) external view returns (KYCRecord memory) {
        return kycRecords[account];
    }

    /// @notice Get tier limits
    function getTierLimits(
        KYCTier tier
    ) external view returns (TierLimits memory) {
        return tierLimits[tier];
    }

    /// @notice Get disclosure request
    function getDisclosureRequest(
        bytes32 requestId
    ) external view returns (DisclosureRequest memory) {
        return disclosureRequests[requestId];
    }
}
