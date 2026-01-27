// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Soulv2Orchestrator
/// @author Soul Protocol - Soul v2
/// @notice Orchestrates interactions between Soul v2 primitives
/// @dev Creates workflows that combine multiple primitives for complex operations
///
/// Integration Patterns:
/// 1. PC³ ↔ CDNA: Cross-chain container nullifiers
///    - Containers get domain-separated nullifiers
///    - Enables cross-chain container transfer with replay protection
///
/// 2. EASC ↔ PBP: Policy-bound state commitments
///    - State commitments require policy-compliant attestations
///    - Enables compliance-aware cross-backend verification
///
/// 3. Full Flow: PC³ → EASC → CDNA → PBP
///    - Container created with embedded proofs
///    - State commitment with multi-backend attestation
///    - Cross-domain nullifier for replay protection
///    - Policy-bound verification for compliance

interface IProofCarryingContainer {
    function totalContainers() external view returns (uint256);

    function consumeContainer(bytes32 containerId) external;

    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool);
}

interface IPolicyBoundProofs {
    function totalPolicies() external view returns (uint256);

    function isPolicyValid(bytes32 policyId) external view returns (bool);
}

interface IExecutionAgnosticStateCommitments {
    function totalCommitments() external view returns (uint256);

    function createCommitment(
        bytes32 stateHash,
        bytes32 transitionHash,
        bytes32 nullifier
    ) external returns (bytes32);

    function attestCommitment(
        bytes32 commitmentId,
        bytes32 backendId,
        bytes calldata attestationProof,
        bytes32 executionHash
    ) external;
}

interface ICrossDomainNullifierAlgebra {
    function totalDomains() external view returns (uint256);

    function registerNullifier(
        bytes32 domainId,
        bytes32 nullifierValue,
        bytes32 commitmentHash,
        bytes32 transitionId
    ) external returns (bytes32);

    function consumeNullifier(bytes32 nullifier) external;

    function nullifierExists(bytes32 nullifier) external view returns (bool);
}

contract Soulv2Orchestrator is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("ORCHESTRATOR_ROLE")
    bytes32 public constant ORCHESTRATOR_ROLE =
        0xe098e2e7d2d4d3ca0e3877ceaaf3cdfbd47483f6699688ad12b1d6732deef10b;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Coordinated state transition
    struct CoordinatedTransition {
        bytes32 containerId;
        bytes32 commitmentId;
        bytes32 nullifier;
        bytes32 domainId;
        bytes32 policyId;
        bool isComplete;
        uint64 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Reference to ProofCarryingContainer contract
    IProofCarryingContainer public immutable pc3;

    /// @notice Reference to PolicyBoundProofs contract
    IPolicyBoundProofs public immutable pbp;

    /// @notice Reference to ExecutionAgnosticStateCommitments contract
    IExecutionAgnosticStateCommitments public immutable easc;

    /// @notice Reference to CrossDomainNullifierAlgebra contract
    ICrossDomainNullifierAlgebra public immutable cdna;

    /// @notice Coordinated transitions by ID
    mapping(bytes32 => CoordinatedTransition) public transitions;

    /// @notice Container to domain mapping
    mapping(bytes32 => bytes32) public containerToDomain;

    /// @notice Container to commitment mapping
    mapping(bytes32 => bytes32) public containerToCommitment;

    /// @notice Total coordinated transitions
    uint256 public totalTransitions;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CrossChainTransferInitiated(
        bytes32 indexed containerId,
        bytes32 indexed sourceDomainId,
        bytes32 indexed targetDomainId
    );

    event CrossChainTransferCompleted(
        bytes32 indexed oldContainerId,
        bytes32 indexed newContainerId,
        bytes32 nullifier
    );

    event CoordinatedTransitionCreated(
        bytes32 indexed transitionId,
        bytes32 indexed containerId,
        bytes32 indexed commitmentId
    );

    event CoordinatedTransitionCompleted(bytes32 indexed transitionId);

    event PolicyCompliantAttestationAdded(
        bytes32 indexed commitmentId,
        bytes32 indexed policyId
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidContainerId();
    error InvalidDomainId();
    error InvalidPolicyId();
    error InvalidCommitmentId();
    error TransitionNotFound(bytes32 transitionId);
    error TransitionAlreadyComplete(bytes32 transitionId);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _pc3, address _pbp, address _easc, address _cdna) {
        pc3 = IProofCarryingContainer(_pc3);
        pbp = IPolicyBoundProofs(_pbp);
        easc = IExecutionAgnosticStateCommitments(_easc);
        cdna = ICrossDomainNullifierAlgebra(_cdna);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORCHESTRATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                    PC³ ↔ CDNA INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a container's nullifier in a specific domain
    /// @param containerId The container ID
    /// @param containerNullifier The container's nullifier
    /// @param stateCommitment The container's state commitment
    /// @param domainId The target domain
    /// @return nullifier The domain-bound nullifier
    function registerContainerInDomain(
        bytes32 containerId,
        bytes32 containerNullifier,
        bytes32 stateCommitment,
        bytes32 domainId
    )
        external
        whenNotPaused
        onlyRole(ORCHESTRATOR_ROLE)
        returns (bytes32 nullifier)
    {
        if (containerId == bytes32(0)) revert InvalidContainerId();
        if (domainId == bytes32(0)) revert InvalidDomainId();

        // Register nullifier in the target domain
        nullifier = cdna.registerNullifier(
            domainId,
            containerNullifier,
            stateCommitment,
            keccak256(abi.encodePacked(containerId, domainId))
        );

        containerToDomain[containerId] = domainId;

        return nullifier;
    }

    /*//////////////////////////////////////////////////////////////
                    EASC ↔ PBP INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a policy-bound commitment
    /// @param stateHash Hash of the state
    /// @param transitionHash Hash of the state transition
    /// @param nullifier Unique nullifier
    /// @param policyId The policy to bind to
    /// @return commitmentId The created commitment ID
    function createPolicyBoundCommitment(
        bytes32 stateHash,
        bytes32 transitionHash,
        bytes32 nullifier,
        bytes32 policyId
    )
        external
        whenNotPaused
        onlyRole(ORCHESTRATOR_ROLE)
        returns (bytes32 commitmentId)
    {
        if (policyId == bytes32(0)) revert InvalidPolicyId();

        // Verify policy exists and is valid
        if (!pbp.isPolicyValid(policyId)) revert InvalidPolicyId();

        // Create commitment
        commitmentId = easc.createCommitment(
            stateHash,
            transitionHash,
            nullifier
        );

        return commitmentId;
    }

    /// @notice Add attestation to a commitment with policy verification
    /// @param commitmentId The commitment to attest
    /// @param backendId The backend providing attestation
    /// @param attestationProof Proof from the backend
    /// @param executionHash Hash of execution
    /// @param policyId Policy that was verified
    function addPolicyCompliantAttestation(
        bytes32 commitmentId,
        bytes32 backendId,
        bytes calldata attestationProof,
        bytes32 executionHash,
        bytes32 policyId
    ) external whenNotPaused onlyRole(ORCHESTRATOR_ROLE) {
        if (commitmentId == bytes32(0)) revert InvalidCommitmentId();
        if (policyId == bytes32(0)) revert InvalidPolicyId();

        // Verify policy is valid
        if (!pbp.isPolicyValid(policyId)) revert InvalidPolicyId();

        // Add attestation
        easc.attestCommitment(
            commitmentId,
            backendId,
            attestationProof,
            executionHash
        );

        emit PolicyCompliantAttestationAdded(commitmentId, policyId);
    }

    /*//////////////////////////////////////////////////////////////
                    FULL FLOW ORCHESTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a coordinated state transition across all primitives
    /// @param containerId The container ID
    /// @param containerNullifier The container's nullifier
    /// @param stateHash Hash of the new state
    /// @param transitionHash Hash of the transition
    /// @param domainId Target domain for nullifier
    /// @param policyId Policy for compliance
    /// @return transitionId The coordinated transition ID
    function createCoordinatedTransition(
        bytes32 containerId,
        bytes32 containerNullifier,
        bytes32 stateHash,
        bytes32 transitionHash,
        bytes32 domainId,
        bytes32 policyId
    )
        external
        whenNotPaused
        onlyRole(ORCHESTRATOR_ROLE)
        returns (bytes32 transitionId)
    {
        if (containerId == bytes32(0)) revert InvalidContainerId();
        if (domainId == bytes32(0)) revert InvalidDomainId();

        // Verify policy if provided
        if (policyId != bytes32(0) && !pbp.isPolicyValid(policyId)) {
            revert InvalidPolicyId();
        }

        // Create commitment
        bytes32 commitmentId = easc.createCommitment(
            stateHash,
            transitionHash,
            containerNullifier
        );

        // Register nullifier in domain
        bytes32 domainNullifier = cdna.registerNullifier(
            domainId,
            containerNullifier,
            stateHash,
            transitionHash
        );

        transitionId = keccak256(
            abi.encodePacked(
                containerId,
                commitmentId,
                domainNullifier,
                block.timestamp
            )
        );

        transitions[transitionId] = CoordinatedTransition({
            containerId: containerId,
            commitmentId: commitmentId,
            nullifier: domainNullifier,
            domainId: domainId,
            policyId: policyId,
            isComplete: false,
            timestamp: uint64(block.timestamp)
        });

        containerToCommitment[containerId] = commitmentId;
        containerToDomain[containerId] = domainId;
        unchecked {
            ++totalTransitions;
        }

        emit CoordinatedTransitionCreated(
            transitionId,
            containerId,
            commitmentId
        );

        return transitionId;
    }

    /// @notice Complete a coordinated transition with attestation and consumption
    /// @param transitionId The transition ID
    /// @param backendId Backend for attestation
    /// @param attestationProof Proof from backend
    /// @param executionHash Hash of execution
    function completeCoordinatedTransition(
        bytes32 transitionId,
        bytes32 backendId,
        bytes calldata attestationProof,
        bytes32 executionHash
    ) external whenNotPaused onlyRole(ORCHESTRATOR_ROLE) {
        CoordinatedTransition storage transition = transitions[transitionId];
        if (transition.containerId == bytes32(0))
            revert TransitionNotFound(transitionId);
        if (transition.isComplete)
            revert TransitionAlreadyComplete(transitionId);

        // Add attestation to commitment
        easc.attestCommitment(
            transition.commitmentId,
            backendId,
            attestationProof,
            executionHash
        );

        // Consume container
        pc3.consumeContainer(transition.containerId);

        // Consume nullifier
        cdna.consumeNullifier(transition.nullifier);

        transition.isComplete = true;

        emit CoordinatedTransitionCompleted(transitionId);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get transition details
    /// @param transitionId The transition ID
    /// @return The coordinated transition data
    function getTransition(
        bytes32 transitionId
    ) external view returns (CoordinatedTransition memory) {
        return transitions[transitionId];
    }

    /// @notice Get container's associated domain
    /// @param containerId The container ID
    /// @return domainId The domain ID
    function getContainerDomain(
        bytes32 containerId
    ) external view returns (bytes32) {
        return containerToDomain[containerId];
    }

    /// @notice Get container's associated commitment
    /// @param containerId The container ID
    /// @return commitmentId The commitment ID
    function getContainerCommitment(
        bytes32 containerId
    ) external view returns (bytes32) {
        return containerToCommitment[containerId];
    }

    /// @notice Check if all primitive contracts are properly connected
    /// @return pc3Connected True if PC³ is accessible
    /// @return pbpConnected True if PBP is accessible
    /// @return eascConnected True if EASC is accessible
    /// @return cdnaConnected True if CDNA is accessible
    function checkConnections()
        external
        view
        returns (
            bool pc3Connected,
            bool pbpConnected,
            bool eascConnected,
            bool cdnaConnected
        )
    {
        try pc3.totalContainers() returns (uint256) {
            pc3Connected = true;
        } catch {
            pc3Connected = false;
        }

        try pbp.totalPolicies() returns (uint256) {
            pbpConnected = true;
        } catch {
            pbpConnected = false;
        }

        try easc.totalCommitments() returns (uint256) {
            eascConnected = true;
        } catch {
            eascConnected = false;
        }

        try cdna.totalDomains() returns (uint256) {
            cdnaConnected = true;
        } catch {
            cdnaConnected = false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause contract
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
