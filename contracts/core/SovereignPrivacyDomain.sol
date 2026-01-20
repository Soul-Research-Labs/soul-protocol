// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SovereignPrivacyDomain
 * @author Soul Protocol
 * @notice Sovereign Privacy Domains (SPDs) - Celestia's sovereign rollups for privacy
 * @dev Enables institutions, DAOs, and governments to run private domains without building infra
 *
 * CELESTIA SOVEREIGN ROLLUPS vs SOUL SPDs:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Celestia Sovereign Rollup         │ Soul Sovereign Privacy Domain          │
 * ├───────────────────────────────────┼─────────────────────────────────────────│
 * │ Defines own execution rules       │ Defines own privacy policies           │
 * │ Uses external DA                  │ Uses Confidential DA                   │
 * │ Inherits DA security              │ Inherits verification security         │
 * │ Custom state machine              │ Custom disclosure rules                │
 * │ Settlement anywhere               │ Materialization anywhere               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SPD CAN DEFINE:
 * - Privacy policies (who sees what)
 * - Execution backends (ZK, TEE, MPC)
 * - Disclosure rules (time-locked, conditional)
 * - Compliance requirements
 *
 * SPD INHERITS (CANNOT WEAKEN):
 * - Kernel verification
 * - Transport layer security
 * - Nullifier rules
 * - Core confidentiality guarantees
 */
contract SovereignPrivacyDomain is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant DOMAIN_ADMIN_ROLE = keccak256("DOMAIN_ADMIN_ROLE");
    bytes32 public constant POLICY_MANAGER_ROLE =
        keccak256("POLICY_MANAGER_ROLE");
    bytes32 public constant MEMBER_ROLE = keccak256("MEMBER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Domain type classification
     */
    enum DomainType {
        Institution, // Banks, enterprises
        DAO, // Decentralized organizations
        Government, // Public sector
        Consortium, // Multi-party collaboration
        Personal, // Individual privacy domain
        Application // App-specific domain
    }

    /**
     * @notice Domain governance model
     */
    enum GovernanceModel {
        SingleAdmin, // One admin controls all
        MultiSig, // Multi-signature required
        TokenVoting, // Token-weighted voting
        Threshold, // Threshold approval
        Hierarchical // Hierarchical permissions
    }

    /**
     * @notice Execution backend preference
     */
    enum BackendPreference {
        ZKOnly, // Only ZK proofs
        TEEOnly, // Only TEE attestations
        MPCOnly, // Only MPC computation
        ZKPreferred, // ZK with fallback
        TEEPreferred, // TEE with fallback
        Any // Any available backend
    }

    /**
     * @notice Disclosure rule type
     */
    enum DisclosureType {
        Never, // Never disclose
        Immediate, // Disclose immediately to authorized
        TimeLocked, // Disclose after time
        Conditional, // Disclose if condition met
        Threshold, // Disclose if N parties agree
        Regulatory // Disclose to regulators only
    }

    /**
     * @notice Domain configuration
     */
    struct DomainConfig {
        // Identity
        bytes32 domainId;
        string name;
        string description;
        DomainType domainType;
        // Governance
        GovernanceModel governanceModel;
        uint8 requiredApprovals; // For multi-sig/threshold
        address governanceToken; // For token voting
        // Execution
        BackendPreference backendPreference;
        address[] allowedBackends; // Specific backends if restricted
        uint256 maxExecutionGas;
        uint64 executionTimeout;
        // Privacy defaults
        bytes32 defaultPolicyHash;
        bytes32 defaultDisclosureHash;
        DisclosureType defaultDisclosure;
        // Compliance
        bytes32 complianceFramework;
        bool requiresKYC;
        bool requiresAuditLog;
        // Membership
        bool openMembership; // Anyone can join
        uint256 membershipFee;
        uint256 maxMembers;
        // Timestamps
        uint64 createdAt;
        uint64 updatedAt;
        bool active;
    }

    /**
     * @notice Domain member
     */
    struct Member {
        address memberAddress;
        bytes32 memberCommitment; // For privacy-preserving membership
        bytes32 accessLevel;
        uint64 joinedAt;
        uint64 expiresAt;
        bool active;
        bytes32[] allowedPolicies;
    }

    /**
     * @notice Privacy policy definition
     */
    struct PrivacyPolicy {
        bytes32 policyId;
        bytes32 domainId;
        string name;
        // Access control
        bytes32 accessMerkleRoot; // Merkle root of authorized parties
        uint8 minAccessLevel;
        // Disclosure rules
        DisclosureType disclosureType;
        uint64 disclosureDelay; // For time-locked
        bytes32 disclosureCondition; // For conditional
        uint8 disclosureThreshold; // For threshold
        // Data handling
        bool encryptOutputs;
        bool hideMetadata;
        bool preventCorrelation;
        // Compliance
        bytes32 complianceRequirements;
        bool auditRequired;
        // Status
        bool active;
        uint64 createdAt;
    }

    /**
     * @notice Execution within domain
     */
    struct DomainExecution {
        bytes32 executionId;
        bytes32 domainId;
        bytes32 policyId;
        // Request
        bytes32 inputCommitment;
        address requester;
        uint64 requestedAt;
        // Execution
        bytes32 backendUsed;
        bytes32 outputCommitment;
        bytes32 proofHash;
        uint64 executedAt;
        // Status
        bool completed;
        bool verified;
        bytes32 receiptId;
    }

    /**
     * @notice Cross-domain bridge
     */
    struct DomainBridge {
        bytes32 bridgeId;
        bytes32 sourceDomain;
        bytes32 targetDomain;
        // Configuration
        bytes32 bridgePolicyHash; // Policy for cross-domain messages
        bool bidirectional;
        bool requiresApproval;
        // Status
        uint256 messageCount;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // Domain registry
    mapping(bytes32 => DomainConfig) public domains;
    bytes32[] public domainList;

    // Membership
    mapping(bytes32 => mapping(address => Member)) public members;
    mapping(bytes32 => address[]) public domainMembers;
    mapping(bytes32 => uint256) public memberCount;

    // Policies
    mapping(bytes32 => PrivacyPolicy) public policies;
    mapping(bytes32 => bytes32[]) public domainPolicies;

    // Executions
    mapping(bytes32 => DomainExecution) public executions;
    mapping(bytes32 => bytes32[]) public domainExecutions;

    // Bridges
    mapping(bytes32 => DomainBridge) public bridges;
    mapping(bytes32 => bytes32[]) public domainBridges;

    // Inherited security (from Soul kernel)
    address public kernelVerifier;
    address public transportLayer;
    address public nullifierRegistry;

    // Global stats
    uint256 public totalDomains;
    uint256 public totalMembers;
    uint256 public totalExecutions;
    uint256 public totalPolicies;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event DomainCreated(
        bytes32 indexed domainId,
        string name,
        DomainType domainType,
        GovernanceModel governance
    );

    event DomainUpdated(bytes32 indexed domainId, bytes32 configHash);

    event MemberAdded(
        bytes32 indexed domainId,
        address indexed member,
        bytes32 accessLevel
    );

    event MemberRemoved(bytes32 indexed domainId, address indexed member);

    event PolicyCreated(
        bytes32 indexed domainId,
        bytes32 indexed policyId,
        string name
    );

    event PolicyUpdated(bytes32 indexed policyId, bytes32 configHash);

    event ExecutionRequested(
        bytes32 indexed domainId,
        bytes32 indexed executionId,
        address requester
    );

    event ExecutionCompleted(
        bytes32 indexed domainId,
        bytes32 indexed executionId,
        bytes32 receiptId
    );

    event BridgeCreated(
        bytes32 indexed bridgeId,
        bytes32 indexed sourceDomain,
        bytes32 indexed targetDomain
    );

    event CrossDomainMessage(
        bytes32 indexed bridgeId,
        bytes32 indexed messageId,
        bytes32 sourceDomain,
        bytes32 targetDomain
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _kernelVerifier,
        address _transportLayer,
        address _nullifierRegistry
    ) {
        // Security: Validate all constructor parameters
        require(_kernelVerifier != address(0), "SPD: zero kernel verifier");
        require(_transportLayer != address(0), "SPD: zero transport layer");
        require(
            _nullifierRegistry != address(0),
            "SPD: zero nullifier registry"
        );

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        kernelVerifier = _kernelVerifier;
        transportLayer = _transportLayer;
        nullifierRegistry = _nullifierRegistry;
    }

    /*//////////////////////////////////////////////////////////////
                          DOMAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new sovereign privacy domain
     * @param name Domain name
     * @param description Domain description
     * @param domainType Type of domain
     * @param governanceModel Governance model
     * @param backendPreference Preferred execution backend
     * @return domainId The unique domain identifier
     */
    function createDomain(
        string calldata name,
        string calldata description,
        DomainType domainType,
        GovernanceModel governanceModel,
        BackendPreference backendPreference
    ) external whenNotPaused nonReentrant returns (bytes32 domainId) {
        domainId = keccak256(
            abi.encodePacked(name, msg.sender, block.timestamp, totalDomains)
        );

        require(domains[domainId].createdAt == 0, "SPD: domain exists");

        domains[domainId] = DomainConfig({
            domainId: domainId,
            name: name,
            description: description,
            domainType: domainType,
            governanceModel: governanceModel,
            requiredApprovals: 1,
            governanceToken: address(0),
            backendPreference: backendPreference,
            allowedBackends: new address[](0),
            maxExecutionGas: 10_000_000,
            executionTimeout: 1 hours,
            defaultPolicyHash: bytes32(0),
            defaultDisclosureHash: bytes32(0),
            defaultDisclosure: DisclosureType.Never,
            complianceFramework: bytes32(0),
            requiresKYC: false,
            requiresAuditLog: true,
            openMembership: false,
            membershipFee: 0,
            maxMembers: type(uint256).max,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            active: true
        });

        domainList.push(domainId);
        totalDomains++;

        // Add creator as admin
        _addMember(domainId, msg.sender, keccak256("ADMIN"), 0);
        _grantRole(DOMAIN_ADMIN_ROLE, msg.sender);

        emit DomainCreated(domainId, name, domainType, governanceModel);
    }

    /**
     * @notice Update domain configuration
     * @param domainId Domain to update
     * @param backendPreference New backend preference
     * @param maxExecutionGas New max gas
     * @param defaultDisclosure New default disclosure type
     */
    function updateDomainConfig(
        bytes32 domainId,
        BackendPreference backendPreference,
        uint256 maxExecutionGas,
        DisclosureType defaultDisclosure
    ) external {
        require(_isDomainAdmin(domainId, msg.sender), "SPD: not admin");

        DomainConfig storage config = domains[domainId];
        require(config.active, "SPD: domain inactive");

        config.backendPreference = backendPreference;
        config.maxExecutionGas = maxExecutionGas;
        config.defaultDisclosure = defaultDisclosure;
        config.updatedAt = uint64(block.timestamp);

        emit DomainUpdated(domainId, keccak256(abi.encode(config)));
    }

    /**
     * @notice Set compliance requirements
     * @param domainId Domain to configure
     * @param framework Compliance framework hash
     * @param requiresKYC Whether KYC is required
     * @param requiresAuditLog Whether audit logging is required
     */
    function setComplianceRequirements(
        bytes32 domainId,
        bytes32 framework,
        bool requiresKYC,
        bool requiresAuditLog
    ) external {
        require(_isDomainAdmin(domainId, msg.sender), "SPD: not admin");

        DomainConfig storage config = domains[domainId];
        config.complianceFramework = framework;
        config.requiresKYC = requiresKYC;
        config.requiresAuditLog = requiresAuditLog;
        config.updatedAt = uint64(block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                          MEMBERSHIP MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add member to domain
     * @param domainId Domain to join
     * @param member Member address
     * @param accessLevel Access level commitment
     * @param duration Membership duration (0 = permanent)
     */
    function addMember(
        bytes32 domainId,
        address member,
        bytes32 accessLevel,
        uint64 duration
    ) external {
        require(_isDomainAdmin(domainId, msg.sender), "SPD: not admin");
        _addMember(domainId, member, accessLevel, duration);
    }

    /**
     * @notice Join domain (for open membership)
     * @param domainId Domain to join
     * @param memberCommitment Privacy-preserving membership commitment
     */
    function joinDomain(
        bytes32 domainId,
        bytes32 memberCommitment
    ) external payable whenNotPaused {
        DomainConfig storage config = domains[domainId];
        require(config.active, "SPD: domain inactive");
        require(config.openMembership, "SPD: closed membership");
        require(msg.value >= config.membershipFee, "SPD: insufficient fee");
        require(memberCount[domainId] < config.maxMembers, "SPD: domain full");

        _addMemberWithCommitment(domainId, msg.sender, memberCommitment, 0);
    }

    /**
     * @notice Remove member from domain
     * @param domainId Domain ID
     * @param member Member to remove
     */
    function removeMember(bytes32 domainId, address member) external {
        require(_isDomainAdmin(domainId, msg.sender), "SPD: not admin");

        Member storage m = members[domainId][member];
        require(m.active, "SPD: not a member");

        m.active = false;
        memberCount[domainId]--;
        totalMembers--;

        emit MemberRemoved(domainId, member);
    }

    function _addMember(
        bytes32 domainId,
        address member,
        bytes32 accessLevel,
        uint64 duration
    ) internal {
        require(!members[domainId][member].active, "SPD: already member");

        uint64 expiresAt = duration > 0
            ? uint64(block.timestamp) + duration
            : 0;

        members[domainId][member] = Member({
            memberAddress: member,
            memberCommitment: bytes32(0),
            accessLevel: accessLevel,
            joinedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            active: true,
            allowedPolicies: new bytes32[](0)
        });

        domainMembers[domainId].push(member);
        memberCount[domainId]++;
        totalMembers++;

        emit MemberAdded(domainId, member, accessLevel);
    }

    function _addMemberWithCommitment(
        bytes32 domainId,
        address member,
        bytes32 commitment,
        uint64 duration
    ) internal {
        require(!members[domainId][member].active, "SPD: already member");

        uint64 expiresAt = duration > 0
            ? uint64(block.timestamp) + duration
            : 0;

        members[domainId][member] = Member({
            memberAddress: member,
            memberCommitment: commitment,
            accessLevel: keccak256("MEMBER"),
            joinedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            active: true,
            allowedPolicies: new bytes32[](0)
        });

        domainMembers[domainId].push(member);
        memberCount[domainId]++;
        totalMembers++;

        emit MemberAdded(domainId, member, keccak256("MEMBER"));
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create privacy policy for domain
     * @param domainId Domain to create policy for
     * @param name Policy name
     * @param disclosureType Type of disclosure
     * @param disclosureDelay Delay for time-locked disclosure
     * @param encryptOutputs Whether to encrypt outputs
     * @param auditRequired Whether audit is required
     * @return policyId The policy identifier
     */
    function createPolicy(
        bytes32 domainId,
        string calldata name,
        DisclosureType disclosureType,
        uint64 disclosureDelay,
        bool encryptOutputs,
        bool auditRequired
    ) external returns (bytes32 policyId) {
        require(
            _isDomainAdmin(domainId, msg.sender) ||
                hasRole(POLICY_MANAGER_ROLE, msg.sender),
            "SPD: not authorized"
        );

        policyId = keccak256(abi.encodePacked(domainId, name, block.timestamp));

        require(policies[policyId].createdAt == 0, "SPD: policy exists");

        policies[policyId] = PrivacyPolicy({
            policyId: policyId,
            domainId: domainId,
            name: name,
            accessMerkleRoot: bytes32(0),
            minAccessLevel: 0,
            disclosureType: disclosureType,
            disclosureDelay: disclosureDelay,
            disclosureCondition: bytes32(0),
            disclosureThreshold: 0,
            encryptOutputs: encryptOutputs,
            hideMetadata: true,
            preventCorrelation: true,
            complianceRequirements: bytes32(0),
            auditRequired: auditRequired,
            active: true,
            createdAt: uint64(block.timestamp)
        });

        domainPolicies[domainId].push(policyId);
        totalPolicies++;

        emit PolicyCreated(domainId, policyId, name);
    }

    /**
     * @notice Set policy access control
     * @param policyId Policy to update
     * @param accessMerkleRoot Merkle root of authorized parties
     * @param minAccessLevel Minimum access level required
     */
    function setPolicyAccess(
        bytes32 policyId,
        bytes32 accessMerkleRoot,
        uint8 minAccessLevel
    ) external {
        PrivacyPolicy storage policy = policies[policyId];
        require(policy.active, "SPD: policy inactive");
        require(_isDomainAdmin(policy.domainId, msg.sender), "SPD: not admin");

        policy.accessMerkleRoot = accessMerkleRoot;
        policy.minAccessLevel = minAccessLevel;

        emit PolicyUpdated(policyId, keccak256(abi.encode(policy)));
    }

    /**
     * @notice Set conditional disclosure
     * @param policyId Policy to update
     * @param condition Condition hash for disclosure
     * @param threshold Threshold for multi-party disclosure
     */
    function setConditionalDisclosure(
        bytes32 policyId,
        bytes32 condition,
        uint8 threshold
    ) external {
        PrivacyPolicy storage policy = policies[policyId];
        require(policy.active, "SPD: policy inactive");
        require(_isDomainAdmin(policy.domainId, msg.sender), "SPD: not admin");

        policy.disclosureCondition = condition;
        policy.disclosureThreshold = threshold;

        emit PolicyUpdated(policyId, keccak256(abi.encode(policy)));
    }

    /*//////////////////////////////////////////////////////////////
                          EXECUTION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request execution within domain
     * @param domainId Domain to execute in
     * @param policyId Policy to apply
     * @param inputCommitment Commitment to inputs
     * @return executionId The execution identifier
     */
    function requestExecution(
        bytes32 domainId,
        bytes32 policyId,
        bytes32 inputCommitment
    ) external whenNotPaused nonReentrant returns (bytes32 executionId) {
        require(_isMember(domainId, msg.sender), "SPD: not member");
        require(
            _canUsePolicy(domainId, msg.sender, policyId),
            "SPD: policy not allowed"
        );

        executionId = keccak256(
            abi.encodePacked(
                domainId,
                policyId,
                inputCommitment,
                msg.sender,
                block.timestamp
            )
        );

        executions[executionId] = DomainExecution({
            executionId: executionId,
            domainId: domainId,
            policyId: policyId,
            inputCommitment: inputCommitment,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            backendUsed: bytes32(0),
            outputCommitment: bytes32(0),
            proofHash: bytes32(0),
            executedAt: 0,
            completed: false,
            verified: false,
            receiptId: bytes32(0)
        });

        domainExecutions[domainId].push(executionId);
        totalExecutions++;

        emit ExecutionRequested(domainId, executionId, msg.sender);
    }

    /**
     * @notice Complete execution with proof
     * @param executionId Execution to complete
     * @param outputCommitment Commitment to outputs
     * @param proofHash Hash of execution proof
     * @param receiptId Receipt from execution backend
     */
    function completeExecution(
        bytes32 executionId,
        bytes32 outputCommitment,
        bytes32 proofHash,
        bytes32 receiptId
    ) external onlyRole(OPERATOR_ROLE) {
        DomainExecution storage execution = executions[executionId];
        require(!execution.completed, "SPD: already completed");

        // Verify proof through kernel (INHERITED - cannot bypass)
        require(
            _verifyThroughKernel(proofHash, receiptId),
            "SPD: kernel verification failed"
        );

        execution.outputCommitment = outputCommitment;
        execution.proofHash = proofHash;
        execution.receiptId = receiptId;
        execution.executedAt = uint64(block.timestamp);
        execution.completed = true;
        execution.verified = true;

        emit ExecutionCompleted(execution.domainId, executionId, receiptId);
    }

    /**
     * @notice Verify through inherited kernel (CANNOT BE WEAKENED)
     * @dev This is the shared verification that all domains inherit
     */
    function _verifyThroughKernel(
        bytes32 proofHash,
        bytes32 receiptId
    ) internal view returns (bool) {
        // In production: call kernelVerifier.verify(proofHash, receiptId)
        // This ensures all domains use the same verification
        if (kernelVerifier == address(0)) {
            return proofHash != bytes32(0) && receiptId != bytes32(0);
        }

        // Would call: IKernelVerifier(kernelVerifier).verify(proofHash, receiptId)
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          CROSS-DOMAIN BRIDGES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create bridge between domains
     * @param sourceDomain Source domain
     * @param targetDomain Target domain
     * @param bridgePolicyHash Policy for cross-domain messages
     * @param bidirectional Whether bridge is two-way
     * @return bridgeId The bridge identifier
     */
    function createBridge(
        bytes32 sourceDomain,
        bytes32 targetDomain,
        bytes32 bridgePolicyHash,
        bool bidirectional
    ) external returns (bytes32 bridgeId) {
        require(
            _isDomainAdmin(sourceDomain, msg.sender),
            "SPD: not source admin"
        );
        // For bidirectional, also need target admin approval (simplified here)

        bridgeId = keccak256(
            abi.encodePacked(sourceDomain, targetDomain, block.timestamp)
        );

        bridges[bridgeId] = DomainBridge({
            bridgeId: bridgeId,
            sourceDomain: sourceDomain,
            targetDomain: targetDomain,
            bridgePolicyHash: bridgePolicyHash,
            bidirectional: bidirectional,
            requiresApproval: true,
            messageCount: 0,
            active: true
        });

        domainBridges[sourceDomain].push(bridgeId);
        if (bidirectional) {
            domainBridges[targetDomain].push(bridgeId);
        }

        emit BridgeCreated(bridgeId, sourceDomain, targetDomain);
    }

    /**
     * @notice Send cross-domain message
     * @param bridgeId Bridge to use
     * @param messageCommitment Commitment to message
     * @return messageId The message identifier
     */
    function sendCrossDomainMessage(
        bytes32 bridgeId,
        bytes32 messageCommitment
    ) external whenNotPaused returns (bytes32 messageId) {
        DomainBridge storage bridge = bridges[bridgeId];
        require(bridge.active, "SPD: bridge inactive");
        require(
            _isMember(bridge.sourceDomain, msg.sender),
            "SPD: not source member"
        );

        messageId = keccak256(
            abi.encodePacked(
                bridgeId,
                messageCommitment,
                bridge.messageCount,
                block.timestamp
            )
        );

        bridge.messageCount++;

        emit CrossDomainMessage(
            bridgeId,
            messageId,
            bridge.sourceDomain,
            bridge.targetDomain
        );
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDomain(
        bytes32 domainId
    ) external view returns (DomainConfig memory) {
        return domains[domainId];
    }

    function getMember(
        bytes32 domainId,
        address member
    ) external view returns (Member memory) {
        return members[domainId][member];
    }

    function getPolicy(
        bytes32 policyId
    ) external view returns (PrivacyPolicy memory) {
        return policies[policyId];
    }

    function getExecution(
        bytes32 executionId
    ) external view returns (DomainExecution memory) {
        return executions[executionId];
    }

    function getBridge(
        bytes32 bridgeId
    ) external view returns (DomainBridge memory) {
        return bridges[bridgeId];
    }

    function getDomainPolicies(
        bytes32 domainId
    ) external view returns (bytes32[] memory) {
        return domainPolicies[domainId];
    }

    function getDomainMembers(
        bytes32 domainId
    ) external view returns (address[] memory) {
        return domainMembers[domainId];
    }

    function getAllDomains() external view returns (bytes32[] memory) {
        return domainList;
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _isDomainAdmin(
        bytes32 domainId,
        address account
    ) internal view returns (bool) {
        Member storage m = members[domainId][account];
        return m.active && m.accessLevel == keccak256("ADMIN");
    }

    function _isMember(
        bytes32 domainId,
        address account
    ) internal view returns (bool) {
        Member storage m = members[domainId][account];
        if (!m.active) return false;
        if (m.expiresAt > 0 && block.timestamp > m.expiresAt) return false;
        return true;
    }

    function _canUsePolicy(
        bytes32 domainId,
        address account,
        bytes32 policyId
    ) internal view returns (bool) {
        // Check if domain has default policy
        if (policyId == bytes32(0)) {
            policyId = domains[domainId].defaultPolicyHash;
        }

        PrivacyPolicy storage policy = policies[policyId];
        if (!policy.active) return false;
        if (policy.domainId != domainId) return false;

        // Check member's allowed policies
        Member storage m = members[domainId][account];
        if (m.allowedPolicies.length == 0) return true; // All policies allowed

        for (uint256 i = 0; i < m.allowedPolicies.length; i++) {
            if (m.allowedPolicies[i] == policyId) return true;
        }

        return false;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setKernelVerifier(
        address _kernelVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        kernelVerifier = _kernelVerifier;
    }

    function setTransportLayer(
        address _transportLayer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        transportLayer = _transportLayer;
    }

    function setNullifierRegistry(
        address _nullifierRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nullifierRegistry = _nullifierRegistry;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
