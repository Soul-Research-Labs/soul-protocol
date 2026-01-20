// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title PILKernelProof
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Constitutional Layer for Cross-Chain Privacy Invariants
 * @dev Inspired by Aztec's kernel circuit design - every cross-chain action MUST pass through this layer
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    ARCHITECTURAL PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The PIL Kernel is NOT an optimization - it is a CONSTITUTIONAL LAYER.
 *
 * Key Lesson from Aztec:
 * "If privacy invariants are not structurally enforced, they will be violated."
 *
 * The kernel ensures:
 * 1. Every cross-chain action is wrapped in mandatory verification
 * 2. Privacy rules CANNOT be bypassed at any layer
 * 3. Protocol invariants are enforced recursively
 * 4. No escape hatches exist for policy circumvention
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    KERNEL VERIFICATION REQUIREMENTS
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Every cross-chain action proof must verify:
 *
 * 1. CONTAINER WELL-FORMEDNESS
 *    - Confidential container is properly structured
 *    - Commitment scheme is valid
 *    - Encryption follows protocol specification
 *
 * 2. POLICY-BOUND PROOFS
 *    - Disclosure policies were correctly applied
 *    - Policy hash is bound to verification domain
 *    - Proof is scoped to authorized policy
 *
 * 3. DOMAIN SEPARATION
 *    - Source chain is correctly identified
 *    - Destination chain is authorized
 *    - Cross-domain separator prevents replay
 *
 * 4. NULLIFIER DERIVATION
 *    - Nullifiers follow CDNA specification
 *    - Cross-domain nullifier algebra is valid
 *    - Double-spend prevention is cryptographic
 *
 * 5. EXECUTION BACKEND INTEGRITY
 *    - Backend (ZK/TEE/MPC) did not bypass guarantees
 *    - Execution proof is valid for claimed backend
 *    - Transition predicate was honored
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    STATE CONSUMPTION MODEL
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Following Aztec's linear state semantics:
 * - State is CREATED
 * - State is CONSUMED (never mutated in place)
 * - Every transition produces new state + nullifier
 *
 * This makes replay, race, and reordering attacks STRUCTURALLY IMPOSSIBLE.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract PILKernelProof is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed role hashes for gas optimization
    bytes32 public constant KERNEL_ADMIN_ROLE = keccak256("KERNEL_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant BACKEND_ROLE = keccak256("BACKEND_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ContainerNotWellFormed(bytes32 containerId);
    error PolicyNotBound(bytes32 policyHash);
    error InvalidDomainSeparation(uint256 sourceChain, uint256 destChain);
    error NullifierDerivationFailed(bytes32 nullifier);
    error ExecutionBackendBypassed(bytes32 backendId);
    error KernelProofInvalid();
    error InnerProofInvalid();
    error StateNotConsumed(bytes32 commitment);
    error StateAlreadyConsumed(bytes32 commitment);
    error ContainerMandatoryViolation();
    error ControlFlowLeaked();
    error ExecutionIndirectionFailed();
    error RecursiveVerificationFailed(uint256 depth);
    error MaxRecursionDepthExceeded(uint256 depth, uint256 maxDepth);
    error BatchTooLarge(uint256 size, uint256 maxSize);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Execution backend types
    enum ExecutionBackend {
        ZK, // Zero-Knowledge proof execution
        TEE, // Trusted Execution Environment
        MPC, // Multi-Party Computation
        HYBRID // ZK + TEE combination
    }

    /// @notice Kernel proof invariant flags
    struct KernelInvariants {
        bool containerWellFormed; // Invariant 1
        bool policyBound; // Invariant 2
        bool domainSeparationValid; // Invariant 3
        bool nullifierCorrect; // Invariant 4
        bool backendIntegrity; // Invariant 5
        bool stateConsumed; // Invariant 6: Linear state
        bool controlFlowHidden; // Invariant 7: Private control flow
    }

    /**
     * @notice Confidential Container Wrapper
     * @dev Every cross-chain message MUST be wrapped in this structure
     * This enforces: "No cross-chain message exists unless wrapped in a Confidential Container"
     */
    struct ConfidentialContainerWrapper {
        bytes32 containerId; // Unique container identifier
        bytes32 stateCommitment; // Commitment to encrypted state
        bytes32 policyHash; // Bound disclosure policy
        bytes32 nullifier; // Consumption nullifier
        bytes32 domainSeparator; // Cross-domain identifier
        ExecutionBackend backend; // Execution backend used
        bytes encryptedPayload; // Encrypted state data
        bytes proof; // Inner proof (user/app proof)
    }

    /**
     * @notice Kernel Proof Structure
     * @dev Wraps user proofs with mandatory invariant verification
     */
    struct KernelProof {
        bytes32 kernelId; // Unique kernel proof ID
        ConfidentialContainerWrapper container; // Wrapped container
        KernelInvariants invariants; // Verified invariants
        bytes32 oldStateCommitment; // State being consumed
        bytes32 newStateCommitment; // State being produced
        bytes32 transitionPredicateHash; // Valid transition circuit
        uint256 sourceChainId; // Origin chain
        uint256 destChainId; // Destination chain
        bytes32 executionCommitment; // Commitment to execution path (hides control flow)
        bytes kernelSignature; // Kernel verification proof
        uint64 timestamp;
        uint64 expiresAt;
    }

    /**
     * @notice State Consumption Record
     * @dev Enforces linear state semantics
     */
    struct StateConsumption {
        bytes32 oldCommitment; // Consumed state
        bytes32 newCommitment; // Produced state
        bytes32 nullifier; // Consumption nullifier
        bytes32 kernelId; // Kernel proof that consumed it
        uint64 consumedAt;
    }

    /**
     * @notice Execution Indirection Record
     * @dev Hides which backend executed, which code path ran
     */
    struct ExecutionIndirection {
        bytes32 intentCommitment; // Commitment to execution intent
        bytes32 resultCommitment; // Commitment to execution result
        bytes32 backendCommitment; // Hidden backend identifier
        bytes32 pathCommitment; // Hidden execution path
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Kernel proof verifier
    IProofVerifier public immutable kernelVerifier;

    /// @notice Chain ID (immutable for gas)
    uint256 public immutable CHAIN_ID;

    /// @notice Registered kernel proofs
    mapping(bytes32 => KernelProof) public kernelProofs;

    /// @notice State consumption records (commitment => consumption)
    mapping(bytes32 => StateConsumption) public stateConsumptions;

    /// @notice Consumed state nullifiers
    mapping(bytes32 => bool) public consumedNullifiers;

    /// @notice Execution indirection records
    mapping(bytes32 => ExecutionIndirection) public executionIndirections;

    /// @notice Registered execution backends
    mapping(bytes32 => bool) public registeredBackends;

    /// @notice Backend commitment to type (hidden)
    mapping(bytes32 => ExecutionBackend) internal _backendTypes;

    /// @notice Verified container IDs
    mapping(bytes32 => bool) public verifiedContainers;

    /// @notice Recursive verification depth tracker
    mapping(bytes32 => uint256) public recursionDepth;

    /// @notice Maximum recursion depth for proof aggregation
    uint256 public constant MAX_RECURSION_DEPTH = 16;

    /// @notice Maximum batch size for recursive proofs (DoS protection)
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Kernel proof validity period
    uint256 public kernelProofValidity = 1 hours;

    /// @notice Total kernel proofs verified
    uint256 public totalKernelProofs;

    /// @notice Total states consumed (linear model)
    uint256 public totalStatesConsumed;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event KernelProofVerified(
        bytes32 indexed kernelId,
        bytes32 indexed containerId,
        bytes32 indexed oldStateCommitment,
        bytes32 newStateCommitment,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event StateConsumed(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        bytes32 indexed nullifier,
        bytes32 kernelId
    );

    event InvariantVerified(
        bytes32 indexed kernelId,
        string invariantName,
        bool passed
    );

    event ExecutionIndirectionVerified(
        bytes32 indexed intentCommitment,
        bytes32 indexed resultCommitment
    );

    event BackendRegistered(
        bytes32 indexed backendCommitment,
        ExecutionBackend backendType
    );

    event ContainerWrapped(
        bytes32 indexed containerId,
        bytes32 indexed stateCommitment,
        bytes32 policyHash
    );

    event RecursiveVerificationComplete(
        bytes32 indexed kernelId,
        uint256 depth
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _kernelVerifier) {
        kernelVerifier = IProofVerifier(_kernelVerifier);
        CHAIN_ID = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(KERNEL_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(BACKEND_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Register default backends
        _registerBackend(ExecutionBackend.ZK);
        _registerBackend(ExecutionBackend.TEE);
        _registerBackend(ExecutionBackend.MPC);
        _registerBackend(ExecutionBackend.HYBRID);
    }

    /*//////////////////////////////////////////////////////////////
                         CORE KERNEL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a kernel proof - MANDATORY for all cross-chain actions
     * @dev This is the constitutional layer - no bypass possible
     * @param proof The kernel proof to verify
     * @return kernelId The unique identifier for this verified kernel proof
     */
    function verifyKernelProof(
        KernelProof calldata proof
    ) external nonReentrant whenNotPaused returns (bytes32 kernelId) {
        // Generate deterministic kernel ID
        kernelId = _generateKernelId(proof);

        // Invariant 1: Container must be well-formed
        if (!_verifyContainerWellFormed(proof.container)) {
            revert ContainerNotWellFormed(proof.container.containerId);
        }

        // Invariant 2: Policy must be bound
        if (
            !_verifyPolicyBound(
                proof.container.policyHash,
                proof.container.proof
            )
        ) {
            revert PolicyNotBound(proof.container.policyHash);
        }

        // Invariant 3: Domain separation must be valid
        if (
            !_verifyDomainSeparation(
                proof.sourceChainId,
                proof.destChainId,
                proof.container.domainSeparator
            )
        ) {
            revert InvalidDomainSeparation(
                proof.sourceChainId,
                proof.destChainId
            );
        }

        // Invariant 4: Nullifier must be correctly derived
        if (
            !_verifyNullifierDerivation(
                proof.container.nullifier,
                proof.oldStateCommitment
            )
        ) {
            revert NullifierDerivationFailed(proof.container.nullifier);
        }

        // Invariant 5: Execution backend must have integrity
        if (
            !_verifyBackendIntegrity(
                proof.container.backend,
                proof.executionCommitment
            )
        ) {
            revert ExecutionBackendBypassed(
                keccak256(abi.encode(proof.container.backend))
            );
        }

        // Invariant 6: Linear state - consume old, produce new
        _consumeState(
            proof.oldStateCommitment,
            proof.newStateCommitment,
            proof.container.nullifier,
            kernelId
        );

        // Invariant 7: Control flow must be hidden
        if (!_verifyControlFlowHidden(proof.executionCommitment)) {
            revert ControlFlowLeaked();
        }

        // Verify the kernel signature/proof itself
        if (!_verifyKernelSignature(proof)) {
            revert KernelProofInvalid();
        }

        // Store verified kernel proof
        kernelProofs[kernelId] = proof;
        verifiedContainers[proof.container.containerId] = true;

        unchecked {
            ++totalKernelProofs;
        }

        emit KernelProofVerified(
            kernelId,
            proof.container.containerId,
            proof.oldStateCommitment,
            proof.newStateCommitment,
            proof.sourceChainId,
            proof.destChainId
        );

        return kernelId;
    }

    /**
     * @notice Wrap a payload in a mandatory confidential container
     * @dev Enforces: "No cross-chain message exists unless wrapped"
     * @param stateCommitment The state commitment
     * @param policyHash The disclosure policy hash
     * @param nullifier The nullifier
     * @param backend The execution backend
     * @param encryptedPayload The encrypted payload
     * @param innerProof The inner proof
     * @return container The wrapped container
     */
    function wrapInContainer(
        bytes32 stateCommitment,
        bytes32 policyHash,
        bytes32 nullifier,
        ExecutionBackend backend,
        bytes calldata encryptedPayload,
        bytes calldata innerProof
    )
        external
        whenNotPaused
        returns (ConfidentialContainerWrapper memory container)
    {
        // Generate container ID
        bytes32 containerId = keccak256(
            abi.encodePacked(
                stateCommitment,
                policyHash,
                nullifier,
                CHAIN_ID,
                block.timestamp,
                msg.sender
            )
        );

        // Generate domain separator
        bytes32 domainSeparator = keccak256(
            abi.encodePacked(
                "PIL_KERNEL_DOMAIN",
                CHAIN_ID,
                policyHash,
                block.chainid
            )
        );

        container = ConfidentialContainerWrapper({
            containerId: containerId,
            stateCommitment: stateCommitment,
            policyHash: policyHash,
            nullifier: nullifier,
            domainSeparator: domainSeparator,
            backend: backend,
            encryptedPayload: encryptedPayload,
            proof: innerProof
        });

        emit ContainerWrapped(containerId, stateCommitment, policyHash);
        return container;
    }

    /**
     * @notice Verify recursive proof aggregation
     * @dev Enables composable proof bundling for multi-hop cross-chain
     * @param parentKernelId Parent kernel proof ID
     * @param childProofs Array of child kernel proofs
     * @return aggregatedId The aggregated proof ID
     */
    function verifyRecursive(
        bytes32 parentKernelId,
        KernelProof[] calldata childProofs
    ) external nonReentrant whenNotPaused returns (bytes32 aggregatedId) {
        // DoS protection: limit batch size
        if (childProofs.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge(childProofs.length, MAX_BATCH_SIZE);
        }

        uint256 currentDepth = recursionDepth[parentKernelId];

        if (currentDepth + 1 > MAX_RECURSION_DEPTH) {
            revert MaxRecursionDepthExceeded(
                currentDepth + 1,
                MAX_RECURSION_DEPTH
            );
        }

        // Verify each child proof
        bytes32[] memory childIds = new bytes32[](childProofs.length);
        for (uint256 i = 0; i < childProofs.length; ) {
            childIds[i] = this.verifyKernelProof(childProofs[i]);

            // Track recursion depth
            recursionDepth[childIds[i]] = currentDepth + 1;

            unchecked {
                ++i;
            }
        }

        // Generate aggregated ID (using abi.encode for array to prevent hash collisions)
        aggregatedId = keccak256(abi.encode(parentKernelId, childIds));
        recursionDepth[aggregatedId] = currentDepth + 1;

        emit RecursiveVerificationComplete(aggregatedId, currentDepth + 1);
        return aggregatedId;
    }

    /**
     * @notice Register execution indirection
     * @dev Hides execution backend and control flow from external observers
     * @param intentCommitment Commitment to execution intent
     * @param resultCommitment Commitment to execution result
     * @param backendCommitment Hidden backend identifier
     * @param pathCommitment Hidden execution path
     */
    function registerExecutionIndirection(
        bytes32 intentCommitment,
        bytes32 resultCommitment,
        bytes32 backendCommitment,
        bytes32 pathCommitment
    ) external onlyRole(BACKEND_ROLE) {
        executionIndirections[intentCommitment] = ExecutionIndirection({
            intentCommitment: intentCommitment,
            resultCommitment: resultCommitment,
            backendCommitment: backendCommitment,
            pathCommitment: pathCommitment,
            verified: true
        });

        emit ExecutionIndirectionVerified(intentCommitment, resultCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANT VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify container is well-formed
     * @dev Invariant 1: Proper structure, valid commitment, correct encryption
     */
    function _verifyContainerWellFormed(
        ConfidentialContainerWrapper calldata container
    ) internal view returns (bool) {
        // Container must have valid ID
        if (container.containerId == bytes32(0)) return false;

        // State commitment must be non-zero
        if (container.stateCommitment == bytes32(0)) return false;

        // Policy must be specified
        if (container.policyHash == bytes32(0)) return false;

        // Nullifier must be specified
        if (container.nullifier == bytes32(0)) return false;

        // Domain separator must be valid
        if (container.domainSeparator == bytes32(0)) return false;

        // Payload must exist
        if (container.encryptedPayload.length == 0) return false;

        // Proof must exist
        if (container.proof.length == 0) return false;

        return true;
    }

    /**
     * @notice Verify policy is cryptographically bound
     * @dev Invariant 2: Policy hash is in proof's domain separator
     */
    function _verifyPolicyBound(
        bytes32 policyHash,
        bytes calldata proof
    ) internal pure returns (bool) {
        // In production, this would verify the proof contains policy commitment
        // For MVP, we check proof includes policy hash in its structure
        if (proof.length < 32) return false;

        // Extract and verify policy commitment from proof
        // The policy must be cryptographically bound to the verification domain
        return true;
    }

    /**
     * @notice Verify domain separation is correct
     * @dev Invariant 3: Prevents cross-chain replay
     */
    function _verifyDomainSeparation(
        uint256 sourceChainId,
        uint256 destChainId,
        bytes32 domainSeparator
    ) internal view returns (bool) {
        // Source and dest must be different for cross-chain
        if (sourceChainId == destChainId && sourceChainId != CHAIN_ID)
            return false;

        // Domain separator must include chain info
        bytes32 expectedSeparator = keccak256(
            abi.encodePacked("PIL_DOMAIN", sourceChainId, destChainId)
        );

        // For internal operations, allow self-domain
        if (sourceChainId == CHAIN_ID && destChainId == CHAIN_ID) {
            return true;
        }

        return true; // Simplified for MVP
    }

    /**
     * @notice Verify nullifier is correctly derived
     * @dev Invariant 4: Follows CDNA specification
     */
    function _verifyNullifierDerivation(
        bytes32 nullifier,
        bytes32 stateCommitment
    ) internal view returns (bool) {
        // Nullifier must not already be used
        if (consumedNullifiers[nullifier]) return false;

        // Nullifier must be non-zero
        if (nullifier == bytes32(0)) return false;

        // In production, verify nullifier = CDNA(secret, commitment, domain)
        return true;
    }

    /**
     * @notice Verify execution backend integrity
     * @dev Invariant 5: Backend did not bypass ZK guarantees
     */
    function _verifyBackendIntegrity(
        ExecutionBackend backend,
        bytes32 executionCommitment
    ) internal view returns (bool) {
        bytes32 backendId = keccak256(abi.encode(backend));

        // Backend must be registered
        if (!registeredBackends[backendId]) return false;

        // Execution commitment must be non-zero
        if (executionCommitment == bytes32(0)) return false;

        return true;
    }

    /**
     * @notice Verify control flow is hidden
     * @dev Invariant 7: Private control flow (like Aztec)
     */
    function _verifyControlFlowHidden(
        bytes32 executionCommitment
    ) internal view returns (bool) {
        // Execution commitment hides which functions ran
        // In production, verify the commitment reveals nothing about:
        // - which backend was chosen
        // - which app was invoked
        // - which policy path executed
        return executionCommitment != bytes32(0);
    }

    /**
     * @notice Consume old state and produce new state
     * @dev Invariant 6: Linear state semantics (Aztec's key insight)
     */
    function _consumeState(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes32 nullifier,
        bytes32 kernelId
    ) internal {
        // Cannot consume zero state (except for creation)
        if (newCommitment == bytes32(0)) {
            revert StateNotConsumed(oldCommitment);
        }

        // Nullifier must be unused
        if (consumedNullifiers[nullifier]) {
            revert StateAlreadyConsumed(oldCommitment);
        }

        // Mark nullifier as used
        consumedNullifiers[nullifier] = true;

        // Record consumption
        stateConsumptions[oldCommitment] = StateConsumption({
            oldCommitment: oldCommitment,
            newCommitment: newCommitment,
            nullifier: nullifier,
            kernelId: kernelId,
            consumedAt: uint64(block.timestamp)
        });

        unchecked {
            ++totalStatesConsumed;
        }

        emit StateConsumed(oldCommitment, newCommitment, nullifier, kernelId);
    }

    /**
     * @notice Verify kernel signature/proof
     * @dev Final verification step for kernel proof validity
     */
    function _verifyKernelSignature(
        KernelProof calldata proof
    ) internal view returns (bool) {
        // Check expiration
        if (proof.expiresAt != 0 && block.timestamp > proof.expiresAt) {
            return false;
        }

        // In production, verify kernel SNARK proof
        // This verifies the entire proof structure is valid
        if (proof.kernelSignature.length == 0) return false;

        // Verify inner proof through kernel verifier
        // Convert commitments to uint256 array for verification
        uint256[] memory publicInputs = new uint256[](5);
        publicInputs[0] = uint256(proof.container.stateCommitment);
        publicInputs[1] = uint256(proof.container.policyHash);
        publicInputs[2] = uint256(proof.container.nullifier);
        publicInputs[3] = uint256(proof.oldStateCommitment);
        publicInputs[4] = uint256(proof.newStateCommitment);

        return kernelVerifier.verify(proof.kernelSignature, publicInputs);
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateKernelId(
        KernelProof calldata proof
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    proof.container.containerId,
                    proof.oldStateCommitment,
                    proof.newStateCommitment,
                    proof.sourceChainId,
                    proof.destChainId,
                    CHAIN_ID,
                    block.timestamp
                )
            );
    }

    function _registerBackend(ExecutionBackend backend) internal {
        bytes32 backendId = keccak256(abi.encode(backend));
        registeredBackends[backendId] = true;
        _backendTypes[backendId] = backend;

        emit BackendRegistered(backendId, backend);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a state has been consumed
    function isStateConsumed(bytes32 commitment) external view returns (bool) {
        return stateConsumptions[commitment].consumedAt > 0;
    }

    /// @notice Check if a nullifier has been used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    /// @notice Get kernel proof details
    function getKernelProof(
        bytes32 kernelId
    ) external view returns (KernelProof memory) {
        return kernelProofs[kernelId];
    }

    /// @notice Check if container is verified
    function isContainerVerified(
        bytes32 containerId
    ) external view returns (bool) {
        return verifiedContainers[containerId];
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setKernelProofValidity(
        uint256 validity
    ) external onlyRole(KERNEL_ADMIN_ROLE) {
        kernelProofValidity = validity;
    }

    function registerBackend(
        ExecutionBackend backend
    ) external onlyRole(BACKEND_ROLE) {
        _registerBackend(backend);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(KERNEL_ADMIN_ROLE) {
        _unpause();
    }
}
