// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SoulMultiSigGovernance
 * @author Soul Protocol
 * @notice Multi-signature governance contract for Soul protocol
 * @dev Implements operational security with role separation:
 *      - Deployer: One-time deployment operations
 *      - Admin: Configuration and upgrade management
 *      - Guardian: Emergency pause and security operations
 *      - Operator: Day-to-day protocol operations
 *
 * ROLE HIERARCHY:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    Soul GOVERNANCE STRUCTURE                            │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │                        ┌──────────────────┐                            │
 * │                        │  SUPER_ADMIN     │                            │
 * │                        │  (5-of-9 Multisig)│                           │
 * │                        └────────┬─────────┘                            │
 * │                                 │                                      │
 * │          ┌──────────────────────┼──────────────────────┐               │
 * │          │                      │                      │               │
 * │  ┌───────▼───────┐      ┌───────▼───────┐      ┌───────▼───────┐      │
 * │  │   ADMIN       │      │   GUARDIAN    │      │   OPERATOR    │      │
 * │  │ (3-of-5)      │      │ (2-of-3)      │      │ (2-of-5)      │      │
 * │  │               │      │               │      │               │      │
 * │  │ - Upgrades    │      │ - Pause       │      │ - Relay       │      │
 * │  │ - Config      │      │ - Blacklist   │      │ - Process     │      │
 * │  │ - Roles       │      │ - Emergency   │      │ - Maintain    │      │
 * │  └───────────────┘      └───────────────┘      └───────────────┘      │
 * │                                                                        │
 * │  SEPARATION OF DUTIES:                                                 │
 * │  - Deployer ≠ Admin (deployment is one-time)                          │
 * │  - Admin ≠ Operator (config vs operations)                            │
 * │  - Guardian ≠ Admin (security vs management)                          │
 * │                                                                        │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract SoulMultiSigGovernance is AccessControl {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant SUPER_ADMIN_ROLE = keccak256("SUPER_ADMIN_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RoleConfig {
        uint256 requiredSignatures;
        uint256 memberCount;
        bool active;
    }

    struct Proposal {
        bytes32 proposalId;
        address target;
        uint256 value;
        bytes data;
        string description;
        uint256 createdAt;
        uint256 expiresAt;
        bytes32 requiredRole;
        uint256 requiredSigs;
        uint256 signatureCount;
        bool executed;
        bool cancelled;
    }

    struct Signature {
        address signer;
        bytes signature;
        uint256 signedAt;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Proposal validity period
    uint256 public constant PROPOSAL_VALIDITY = 7 days;

    /// @notice Minimum execution delay
    uint256 public constant MIN_EXECUTION_DELAY = 1 hours;

    /// @notice Maximum signatures per proposal
    uint256 public constant MAX_SIGNATURES = 20;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Role configurations
    mapping(bytes32 => RoleConfig) public roleConfigs;

    /// @notice Proposals by ID
    mapping(bytes32 => Proposal) public proposals;

    /// @notice Signatures for proposals
    mapping(bytes32 => Signature[]) public proposalSignatures;

    /// @notice Has address signed proposal
    mapping(bytes32 => mapping(address => bool)) public hasSigned;

    /// @notice All proposal IDs
    bytes32[] public allProposals;

    /// @notice Nonce for proposal IDs
    uint256 public proposalNonce;

    /// @notice Contract version
    string public constant VERSION = "1.0.0";

    /// @notice Whether role separation is enforced
    bool public roleSeparationEnforced = true;

    /// @notice Blocked role combinations (role1 => role2 => blocked)
    mapping(bytes32 => mapping(bytes32 => bool)) public blockedRoleCombinations;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProposalCreated(
        bytes32 indexed proposalId,
        address indexed proposer,
        address target,
        bytes32 requiredRole,
        string description
    );

    event ProposalSigned(
        bytes32 indexed proposalId,
        address indexed signer,
        uint256 signatureCount,
        uint256 requiredSigs
    );

    event ProposalExecuted(
        bytes32 indexed proposalId,
        address indexed executor,
        bool success
    );

    event ProposalCancelled(bytes32 indexed proposalId, address indexed by);

    event RoleConfigured(
        bytes32 indexed role,
        uint256 requiredSignatures,
        bool active
    );

    event RoleSeparationSet(
        bytes32 indexed role1,
        bytes32 indexed role2,
        bool blocked
    );

    event MemberAdded(bytes32 indexed role, address indexed member);
    event MemberRemoved(bytes32 indexed role, address indexed member);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ProposalNotFound();
    error ProposalExpired();
    error ProposalAlreadyExecuted();
    error ProposalCancelledError();
    error InsufficientSignatures();
    error AlreadySigned();
    error NotRoleMember();
    error RoleSeparationViolation(bytes32 role1, bytes32 role2);
    error InvalidRoleConfig();
    error ExecutionFailed();
    error TooManySignatures();
    error NotRoleAdmin();


    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address superAdmin) {
        // Grant super admin to deployer
        _grantRole(DEFAULT_ADMIN_ROLE, superAdmin);
        _grantRole(SUPER_ADMIN_ROLE, superAdmin);
        _grantRole(DEPLOYER_ROLE, superAdmin);

        // Set role admin hierarchy
        _setRoleAdmin(ADMIN_ROLE, SUPER_ADMIN_ROLE);
        _setRoleAdmin(GUARDIAN_ROLE, SUPER_ADMIN_ROLE);
        _setRoleAdmin(OPERATOR_ROLE, ADMIN_ROLE);
        _setRoleAdmin(DEPLOYER_ROLE, SUPER_ADMIN_ROLE);

        // Default role configs
        roleConfigs[SUPER_ADMIN_ROLE] = RoleConfig({
            requiredSignatures: 5,
            memberCount: 1,
            active: true
        });

        roleConfigs[ADMIN_ROLE] = RoleConfig({
            requiredSignatures: 3,
            memberCount: 0,
            active: true
        });

        roleConfigs[GUARDIAN_ROLE] = RoleConfig({
            requiredSignatures: 2,
            memberCount: 0,
            active: true
        });

        roleConfigs[OPERATOR_ROLE] = RoleConfig({
            requiredSignatures: 2,
            memberCount: 0,
            active: true
        });

        // Set blocked role combinations for separation of duties
        blockedRoleCombinations[ADMIN_ROLE][OPERATOR_ROLE] = true;
        blockedRoleCombinations[OPERATOR_ROLE][ADMIN_ROLE] = true;
        blockedRoleCombinations[GUARDIAN_ROLE][OPERATOR_ROLE] = true;
        blockedRoleCombinations[OPERATOR_ROLE][GUARDIAN_ROLE] = true;
    }

    /*//////////////////////////////////////////////////////////////
                      PROPOSAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new proposal
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Calldata to execute
     * @param description Human-readable description
     * @param requiredRole Role required to sign
     * @return proposalId The created proposal ID
     */
    function createProposal(
        address target,
        uint256 value,
        bytes calldata data,
        string calldata description,
        bytes32 requiredRole
    ) external returns (bytes32 proposalId) {
        // Must be a member of the required role
        if (!hasRole(requiredRole, msg.sender)) {
            revert NotRoleMember();
        }

        RoleConfig storage config = roleConfigs[requiredRole];
        if (!config.active) {
            revert InvalidRoleConfig();
        }

        proposalId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                target,
                value,
                data,
                proposalNonce++
            )
        );

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            target: target,
            value: value,
            data: data,
            description: description,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + PROPOSAL_VALIDITY,
            requiredRole: requiredRole,
            requiredSigs: config.requiredSignatures,
            signatureCount: 0,
            executed: false,
            cancelled: false
        });

        allProposals.push(proposalId);

        emit ProposalCreated(
            proposalId,
            msg.sender,
            target,
            requiredRole,
            description
        );

        // Auto-sign for proposer
        _signProposal(proposalId, msg.sender);
    }

    /**
     * @notice Sign a proposal
     * @param proposalId The proposal to sign
     */
    function signProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.createdAt == 0) revert ProposalNotFound();
        if (block.timestamp > proposal.expiresAt) revert ProposalExpired();
        if (proposal.executed) revert ProposalAlreadyExecuted();
        if (proposal.cancelled) revert ProposalCancelledError();
        if (!hasRole(proposal.requiredRole, msg.sender)) revert NotRoleMember();
        if (hasSigned[proposalId][msg.sender]) revert AlreadySigned();

        _signProposal(proposalId, msg.sender);
    }

    /**
     * @notice Execute a proposal after sufficient signatures
     * @param proposalId The proposal to execute
     */
    function executeProposal(
        bytes32 proposalId
    ) external returns (bool success) {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.createdAt == 0) revert ProposalNotFound();
        if (block.timestamp > proposal.expiresAt) revert ProposalExpired();
        if (proposal.executed) revert ProposalAlreadyExecuted();
        if (proposal.cancelled) revert ProposalCancelledError();
        if (proposal.signatureCount < proposal.requiredSigs)
            revert InsufficientSignatures();

        proposal.executed = true;

        // Execute the proposal
        (success, ) = proposal.target.call{value: proposal.value}(
            proposal.data
        );

        if (!success) {
            // Revert execution status on failure
            proposal.executed = false;
            revert ExecutionFailed();
        }

        emit ProposalExecuted(proposalId, msg.sender, success);
    }

    /**
     * @notice Cancel a proposal
     * @param proposalId The proposal to cancel
     */
    function cancelProposal(bytes32 proposalId) external onlyRole(ADMIN_ROLE) {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.createdAt == 0) revert ProposalNotFound();
        if (proposal.executed) revert ProposalAlreadyExecuted();

        proposal.cancelled = true;

        emit ProposalCancelled(proposalId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      ROLE MANAGEMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a role's signature requirements
     * @param role The role to configure
     * @param requiredSignatures Number of signatures required
     * @param active Whether the role is active
     */
    function configureRole(
        bytes32 role,
        uint256 requiredSignatures,
        bool active
    ) external onlyRole(SUPER_ADMIN_ROLE) {
        if (requiredSignatures == 0) revert InvalidRoleConfig();

        roleConfigs[role] = RoleConfig({
            requiredSignatures: requiredSignatures,
            memberCount: roleConfigs[role].memberCount,
            active: active
        });

        emit RoleConfigured(role, requiredSignatures, active);
    }

    /**
     * @notice Add a member to a role with separation checks
     * @param role The role to add to
     * @param member The member to add
     */
    function addRoleMember(bytes32 role, address member) external {
        // Check caller has admin rights for this role
        if (!hasRole(getRoleAdmin(role), msg.sender)) revert NotRoleAdmin();

        // Check role separation
        if (roleSeparationEnforced) {
            _checkRoleSeparation(role, member);
        }

        _grantRole(role, member);
        roleConfigs[role].memberCount++;

        emit MemberAdded(role, member);
    }

    /**
     * @notice Remove a member from a role
     * @param role The role to remove from
     * @param member The member to remove
     */
    function removeRoleMember(bytes32 role, address member) external {
        if (!hasRole(getRoleAdmin(role), msg.sender)) revert NotRoleAdmin();

        _revokeRole(role, member);
        if (roleConfigs[role].memberCount > 0) {
            roleConfigs[role].memberCount--;
        }

        emit MemberRemoved(role, member);
    }

    /**
     * @notice Set role separation rules
     * @param role1 First role
     * @param role2 Second role
     * @param blocked Whether the combination is blocked
     */
    function setRoleSeparation(
        bytes32 role1,
        bytes32 role2,
        bool blocked
    ) external onlyRole(SUPER_ADMIN_ROLE) {
        blockedRoleCombinations[role1][role2] = blocked;
        blockedRoleCombinations[role2][role1] = blocked;

        emit RoleSeparationSet(role1, role2, blocked);
    }

    /**
     * @notice Toggle role separation enforcement
     * @param enforced Whether to enforce role separation
     */
    function setRoleSeparationEnforced(
        bool enforced
    ) external onlyRole(SUPER_ADMIN_ROLE) {
        roleSeparationEnforced = enforced;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get proposal details
     */
    function getProposal(
        bytes32 proposalId
    ) external view returns (Proposal memory) {
        return proposals[proposalId];
    }

    /**
     * @notice Get signatures for a proposal
     */
    function getProposalSignatures(
        bytes32 proposalId
    ) external view returns (Signature[] memory) {
        return proposalSignatures[proposalId];
    }

    /**
     * @notice Check if proposal is ready to execute
     */
    function isProposalReady(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];

        return
            proposal.createdAt > 0 &&
            !proposal.executed &&
            !proposal.cancelled &&
            block.timestamp <= proposal.expiresAt &&
            proposal.signatureCount >= proposal.requiredSigs;
    }

    /**
     * @notice Get all proposals count
     */
    function getProposalCount() external view returns (uint256) {
        return allProposals.length;
    }

    /**
     * @notice Get proposals in range
     */
    function getProposals(
        uint256 start,
        uint256 count
    ) external view returns (bytes32[] memory) {
        uint256 end = start + count;
        if (end > allProposals.length) {
            end = allProposals.length;
        }

        bytes32[] memory result = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = allProposals[i];
        }
        return result;
    }

    /**
     * @notice Check role separation for an address
     */
    function checkRoleSeparation(
        bytes32 newRole,
        address member
    ) external view returns (bool allowed, bytes32 conflictingRole) {
        bytes32[4] memory rolesToCheck = [
            SUPER_ADMIN_ROLE,
            ADMIN_ROLE,
            GUARDIAN_ROLE,
            OPERATOR_ROLE
        ];

        for (uint256 i = 0; i < rolesToCheck.length; i++) {
            if (
                hasRole(rolesToCheck[i], member) &&
                blockedRoleCombinations[newRole][rolesToCheck[i]]
            ) {
                return (false, rolesToCheck[i]);
            }
        }

        return (true, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _signProposal(bytes32 proposalId, address signer) internal {
        Proposal storage proposal = proposals[proposalId];

        if (proposalSignatures[proposalId].length >= MAX_SIGNATURES) {
            revert TooManySignatures();
        }

        hasSigned[proposalId][signer] = true;
        proposal.signatureCount++;

        proposalSignatures[proposalId].push(
            Signature({
                signer: signer,
                signature: "", // Using role-based auth, not signature-based
                signedAt: block.timestamp
            })
        );

        emit ProposalSigned(
            proposalId,
            signer,
            proposal.signatureCount,
            proposal.requiredSigs
        );
    }

    function _checkRoleSeparation(
        bytes32 newRole,
        address member
    ) internal view {
        bytes32[4] memory rolesToCheck = [
            SUPER_ADMIN_ROLE,
            ADMIN_ROLE,
            GUARDIAN_ROLE,
            OPERATOR_ROLE
        ];

        for (uint256 i = 0; i < rolesToCheck.length; i++) {
            if (
                hasRole(rolesToCheck[i], member) &&
                blockedRoleCombinations[newRole][rolesToCheck[i]]
            ) {
                revert RoleSeparationViolation(newRole, rolesToCheck[i]);
            }
        }
    }

    /**
     * @notice Receive ETH for proposal execution
     */
    receive() external payable {}
}
