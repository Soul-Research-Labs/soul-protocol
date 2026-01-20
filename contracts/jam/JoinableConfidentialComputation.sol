// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title JoinableConfidentialComputation
 * @author Soul Protocol
 * @notice JAM-inspired: Multiple private executions joined into single verifiable state transition
 * @dev Core JAM insight: Standardize state transition VERIFICATION, not execution environments.
 *
 * JAM'S JOIN PRIMITIVE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Multiple independent computations:                                         │
 * │ - Possibly different languages, semantics, runtimes                        │
 * │ - Possibly different chains                                                │
 * │ - Joined into a SINGLE verifiable unit                                     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S EXTENSION (JAM + Privacy):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Multiple PRIVATE executions:                                               │
 * │ - Different backends (ZK/TEE/MPC)                                          │
 * │ - Different chains (Ethereum/Cosmos/Solana)                                │
 * │ - Joined with HIDDEN intermediate states                                   │
 * │ - Single verifiable confidential state transition                          │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * KEY PRINCIPLE: "Programs are not special. Proofs are."
 */
contract JoinableConfidentialComputation is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant JOIN_ADMIN_ROLE = keccak256("JOIN_ADMIN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execution backend type (execution-agnostic)
     */
    enum BackendType {
        Unknown,
        ZK_SNARK,
        ZK_STARK,
        ZK_PLONK,
        TEE_SGX,
        TEE_NITRO,
        MPC_THRESHOLD,
        OPTIMISTIC, // Optimistic execution with fraud proofs
        HYBRID // Multiple backends combined
    }

    /**
     * @notice Source chain type
     */
    enum ChainType {
        Unknown,
        EVM, // Ethereum, Polygon, Arbitrum, etc.
        COSMOS, // Cosmos SDK chains
        SOLANA, // Solana
        SUBSTRATE, // Polkadot parachains
        MOVE, // Aptos, Sui
        OTHER
    }

    /**
     * @notice Computation fragment - a single private execution
     * @dev JAM calls these "work packages" - we call them fragments
     */
    struct ComputationFragment {
        bytes32 fragmentId;
        // Origin
        ChainType sourceChain;
        bytes32 sourceChainId;
        bytes32 sourceContract; // Hidden via commitment if needed
        // Execution
        BackendType backend;
        bytes32 executorCommitment; // Hidden executor identity
        // State
        bytes32 inputCommitment; // Commitment to inputs
        bytes32 outputCommitment; // Commitment to outputs
        bytes32 stateTransitionProof; // Proof of correct execution
        // Policy
        bytes32 policyHash; // Policy applied
        bytes32 policyProof; // Proof policy was followed
        // Status
        FragmentStatus status;
        uint64 createdAt;
        uint64 verifiedAt;
    }

    enum FragmentStatus {
        Pending, // Awaiting verification
        Verified, // Verified individually
        Joined, // Part of a join
        Rejected // Failed verification
    }

    /**
     * @notice Join specification - how to combine fragments
     */
    struct JoinSpec {
        bytes32 joinSpecId;
        string name;
        // Fragment requirements
        uint256 minFragments;
        uint256 maxFragments;
        BackendType[] allowedBackends;
        ChainType[] allowedChains;
        // Join semantics
        JoinSemantics semantics;
        bytes32 joinCircuitHash; // Circuit for join verification
        // Policy requirements
        bool requireUniformPolicy; // All fragments same policy?
        bytes32 requiredPolicyHash; // Specific policy required?
        // Status
        bool active;
        uint64 createdAt;
    }

    enum JoinSemantics {
        Parallel, // Fragments are independent
        Sequential, // Fragments have ordering
        DAG, // Fragments form a DAG
        Aggregation, // Fragments aggregate into one
        Composition // Fragments compose functionally
    }

    /**
     * @notice Confidential Join - the core primitive
     * @dev Multiple private computations → single verifiable transition
     */
    struct ConfidentialJoin {
        bytes32 joinId;
        bytes32 joinSpecId;
        // Fragments
        bytes32[] fragmentIds;
        uint256 fragmentCount;
        // Aggregated state
        bytes32 inputAggregateCommitment; // Joined inputs
        bytes32 outputAggregateCommitment; // Joined outputs
        bytes32 stateTransitionCommitment; // Single state transition
        // Proof of correct join
        bytes32 joinProofHash;
        bytes joinProof;
        // Hidden intermediate states
        bytes32 intermediateStatesRoot; // Merkle root of hidden states
        // Policy
        bytes32 aggregatePolicyHash;
        bytes32 policyProof;
        // Verification
        JoinStatus status;
        bool verified;
        address verifier;
        uint64 createdAt;
        uint64 verifiedAt;
    }

    enum JoinStatus {
        Collecting, // Collecting fragments
        Ready, // All fragments collected
        Verifying, // Verification in progress
        Verified, // Successfully verified
        Accumulated, // Accumulated into state
        Failed // Verification failed
    }

    /**
     * @notice Join verification result
     */
    struct JoinVerificationResult {
        bytes32 joinId;
        bool valid;
        // What was verified
        bool fragmentsValid;
        bool joinLogicValid;
        bool policyCompliant;
        bool transitionValid;
        // Accumulated output
        bytes32 finalStateCommitment;
        bytes32 nullifier; // For replay protection
        // Verification metadata
        uint64 verifiedAt;
        address verifier;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Fragments: fragmentId => fragment
    mapping(bytes32 => ComputationFragment) public fragments;

    /// @notice Join specs: joinSpecId => spec
    mapping(bytes32 => JoinSpec) public joinSpecs;

    /// @notice Joins: joinId => join
    mapping(bytes32 => ConfidentialJoin) public joins;

    /// @notice Verification results: joinId => result
    mapping(bytes32 => JoinVerificationResult) public verificationResults;

    /// @notice Join fragments: joinId => fragmentId[]
    mapping(bytes32 => bytes32[]) public joinFragments;

    /// @notice Fragment to join: fragmentId => joinId
    mapping(bytes32 => bytes32) public fragmentToJoin;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Nullifier to join: nullifier => joinId
    mapping(bytes32 => bytes32) public nullifierToJoin;

    /// @notice Counters
    uint256 public totalFragments;
    uint256 public totalJoinSpecs;
    uint256 public totalJoins;
    uint256 public totalVerified;
    uint256 public totalAccumulated;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event FragmentSubmitted(
        bytes32 indexed fragmentId,
        ChainType sourceChain,
        BackendType backend,
        bytes32 inputCommitment
    );

    event FragmentVerified(bytes32 indexed fragmentId, bool valid);

    event JoinSpecCreated(
        bytes32 indexed joinSpecId,
        string name,
        JoinSemantics semantics
    );

    event JoinCreated(
        bytes32 indexed joinId,
        bytes32 indexed joinSpecId,
        uint256 fragmentCount
    );

    event FragmentJoined(
        bytes32 indexed joinId,
        bytes32 indexed fragmentId,
        uint256 currentCount
    );

    event JoinVerified(
        bytes32 indexed joinId,
        bool valid,
        bytes32 finalStateCommitment
    );

    event JoinAccumulated(
        bytes32 indexed joinId,
        bytes32 nullifier,
        bytes32 stateCommitment
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(JOIN_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        FRAGMENT SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a computation fragment
     * @dev A fragment is a single private execution from any backend/chain
     * @param sourceChain Origin chain type
     * @param sourceChainId Specific chain ID
     * @param backend Execution backend type
     * @param inputCommitment Commitment to inputs
     * @param outputCommitment Commitment to outputs
     * @param stateTransitionProof Proof of correct execution
     * @param policyHash Policy applied
     * @param policyProof Proof of policy compliance
     * @return fragmentId The fragment identifier
     */
    function submitFragment(
        ChainType sourceChain,
        bytes32 sourceChainId,
        BackendType backend,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 stateTransitionProof,
        bytes32 policyHash,
        bytes32 policyProof
    ) external whenNotPaused nonReentrant returns (bytes32 fragmentId) {
        require(backend != BackendType.Unknown, "JCC: unknown backend");
        require(inputCommitment != bytes32(0), "JCC: no input");
        require(stateTransitionProof != bytes32(0), "JCC: no proof");

        fragmentId = keccak256(
            abi.encodePacked(
                sourceChain,
                sourceChainId,
                inputCommitment,
                outputCommitment,
                block.timestamp,
                totalFragments
            )
        );

        fragments[fragmentId] = ComputationFragment({
            fragmentId: fragmentId,
            sourceChain: sourceChain,
            sourceChainId: sourceChainId,
            sourceContract: bytes32(0),
            backend: backend,
            executorCommitment: keccak256(abi.encodePacked(msg.sender)),
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            stateTransitionProof: stateTransitionProof,
            policyHash: policyHash,
            policyProof: policyProof,
            status: FragmentStatus.Pending,
            createdAt: uint64(block.timestamp),
            verifiedAt: 0
        });

        totalFragments++;

        emit FragmentSubmitted(
            fragmentId,
            sourceChain,
            backend,
            inputCommitment
        );
    }

    /**
     * @notice Verify a fragment individually
     * @param fragmentId Fragment to verify
     * @param valid Whether verification passed
     */
    function verifyFragment(
        bytes32 fragmentId,
        bool valid
    ) external onlyRole(VERIFIER_ROLE) {
        ComputationFragment storage fragment = fragments[fragmentId];
        require(fragment.fragmentId != bytes32(0), "JCC: not found");
        require(fragment.status == FragmentStatus.Pending, "JCC: not pending");

        fragment.status = valid
            ? FragmentStatus.Verified
            : FragmentStatus.Rejected;
        fragment.verifiedAt = uint64(block.timestamp);

        emit FragmentVerified(fragmentId, valid);
    }

    /*//////////////////////////////////////////////////////////////
                        JOIN SPECIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a join specification
     * @param name Human-readable name
     * @param minFragments Minimum fragments required
     * @param maxFragments Maximum fragments allowed
     * @param allowedBackends Backends that can participate
     * @param allowedChains Chains that can participate
     * @param semantics How fragments are joined
     * @param joinCircuitHash Circuit for join verification
     * @param requireUniformPolicy Whether all fragments need same policy
     * @return joinSpecId The specification identifier
     */
    function createJoinSpec(
        string calldata name,
        uint256 minFragments,
        uint256 maxFragments,
        BackendType[] calldata allowedBackends,
        ChainType[] calldata allowedChains,
        JoinSemantics semantics,
        bytes32 joinCircuitHash,
        bool requireUniformPolicy
    ) external onlyRole(JOIN_ADMIN_ROLE) returns (bytes32 joinSpecId) {
        require(minFragments > 0, "JCC: min must be > 0");
        require(maxFragments >= minFragments, "JCC: max < min");
        require(allowedBackends.length > 0, "JCC: no backends");

        joinSpecId = keccak256(
            abi.encodePacked(name, semantics, block.timestamp, totalJoinSpecs)
        );

        joinSpecs[joinSpecId] = JoinSpec({
            joinSpecId: joinSpecId,
            name: name,
            minFragments: minFragments,
            maxFragments: maxFragments,
            allowedBackends: allowedBackends,
            allowedChains: allowedChains,
            semantics: semantics,
            joinCircuitHash: joinCircuitHash,
            requireUniformPolicy: requireUniformPolicy,
            requiredPolicyHash: bytes32(0),
            active: true,
            createdAt: uint64(block.timestamp)
        });

        totalJoinSpecs++;

        emit JoinSpecCreated(joinSpecId, name, semantics);
    }

    /*//////////////////////////////////////////////////////////////
                            JOIN CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a confidential join
     * @param joinSpecId Specification to use
     * @param fragmentIds Initial fragments to include
     * @return joinId The join identifier
     */
    function createJoin(
        bytes32 joinSpecId,
        bytes32[] calldata fragmentIds
    ) external whenNotPaused nonReentrant returns (bytes32 joinId) {
        JoinSpec storage spec = joinSpecs[joinSpecId];
        require(spec.active, "JCC: spec not active");
        require(
            fragmentIds.length >= spec.minFragments,
            "JCC: too few fragments"
        );
        require(
            fragmentIds.length <= spec.maxFragments,
            "JCC: too many fragments"
        );

        // Validate all fragments
        bytes32 uniformPolicy = bytes32(0);
        for (uint256 i = 0; i < fragmentIds.length; i++) {
            ComputationFragment storage fragment = fragments[fragmentIds[i]];
            require(
                fragment.status == FragmentStatus.Verified,
                "JCC: fragment not verified"
            );
            require(
                fragmentToJoin[fragmentIds[i]] == bytes32(0),
                "JCC: fragment already joined"
            );

            // Check uniform policy if required
            if (spec.requireUniformPolicy) {
                if (i == 0) {
                    uniformPolicy = fragment.policyHash;
                } else {
                    require(
                        fragment.policyHash == uniformPolicy,
                        "JCC: policy mismatch"
                    );
                }
            }
        }

        joinId = keccak256(
            abi.encodePacked(
                joinSpecId,
                fragmentIds,
                block.timestamp,
                totalJoins
            )
        );

        // Compute aggregate commitments
        bytes32 inputAggregate = _computeAggregate(fragmentIds, true);
        bytes32 outputAggregate = _computeAggregate(fragmentIds, false);

        joins[joinId] = ConfidentialJoin({
            joinId: joinId,
            joinSpecId: joinSpecId,
            fragmentIds: fragmentIds,
            fragmentCount: fragmentIds.length,
            inputAggregateCommitment: inputAggregate,
            outputAggregateCommitment: outputAggregate,
            stateTransitionCommitment: bytes32(0),
            joinProofHash: bytes32(0),
            joinProof: "",
            intermediateStatesRoot: bytes32(0),
            aggregatePolicyHash: uniformPolicy,
            policyProof: bytes32(0),
            status: JoinStatus.Ready,
            verified: false,
            verifier: address(0),
            createdAt: uint64(block.timestamp),
            verifiedAt: 0
        });

        // Mark fragments as joined
        for (uint256 i = 0; i < fragmentIds.length; i++) {
            fragments[fragmentIds[i]].status = FragmentStatus.Joined;
            fragmentToJoin[fragmentIds[i]] = joinId;
            joinFragments[joinId].push(fragmentIds[i]);
        }

        totalJoins++;

        emit JoinCreated(joinId, joinSpecId, fragmentIds.length);
    }

    /**
     * @notice Compute aggregate commitment from fragments
     */
    function _computeAggregate(
        bytes32[] calldata fragmentIds,
        bool isInput
    ) internal view returns (bytes32) {
        bytes32 aggregate = bytes32(0);
        for (uint256 i = 0; i < fragmentIds.length; i++) {
            ComputationFragment storage fragment = fragments[fragmentIds[i]];
            bytes32 commitment = isInput
                ? fragment.inputCommitment
                : fragment.outputCommitment;
            aggregate = keccak256(abi.encodePacked(aggregate, commitment));
        }
        return aggregate;
    }

    /*//////////////////////////////////////////////////////////////
                          JOIN VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit proof for join verification
     * @param joinId Join to prove
     * @param stateTransitionCommitment Final state transition
     * @param joinProof Proof of correct join
     * @param intermediateStatesRoot Merkle root of hidden intermediate states
     * @param policyProof Proof of aggregate policy compliance
     */
    function submitJoinProof(
        bytes32 joinId,
        bytes32 stateTransitionCommitment,
        bytes calldata joinProof,
        bytes32 intermediateStatesRoot,
        bytes32 policyProof
    ) external onlyRole(EXECUTOR_ROLE) {
        ConfidentialJoin storage join = joins[joinId];
        require(join.status == JoinStatus.Ready, "JCC: not ready");
        require(joinProof.length > 0, "JCC: no proof");

        join.stateTransitionCommitment = stateTransitionCommitment;
        join.joinProofHash = keccak256(joinProof);
        join.joinProof = joinProof;
        join.intermediateStatesRoot = intermediateStatesRoot;
        join.policyProof = policyProof;
        join.status = JoinStatus.Verifying;
    }

    /**
     * @notice Verify a join
     * @param joinId Join to verify
     * @param fragmentsValid Whether all fragments are valid
     * @param joinLogicValid Whether join logic is correct
     * @param policyCompliant Whether policies are satisfied
     * @param transitionValid Whether state transition is valid
     */
    function verifyJoin(
        bytes32 joinId,
        bool fragmentsValid,
        bool joinLogicValid,
        bool policyCompliant,
        bool transitionValid
    ) external onlyRole(VERIFIER_ROLE) {
        ConfidentialJoin storage join = joins[joinId];
        require(join.status == JoinStatus.Verifying, "JCC: not verifying");

        bool valid = fragmentsValid &&
            joinLogicValid &&
            policyCompliant &&
            transitionValid;

        // Generate nullifier for replay protection
        bytes32 nullifier = keccak256(
            abi.encodePacked(
                joinId,
                join.inputAggregateCommitment,
                join.outputAggregateCommitment,
                join.stateTransitionCommitment
            )
        );

        require(!usedNullifiers[nullifier], "JCC: nullifier used");

        join.status = valid ? JoinStatus.Verified : JoinStatus.Failed;
        join.verified = valid;
        join.verifier = msg.sender;
        join.verifiedAt = uint64(block.timestamp);

        verificationResults[joinId] = JoinVerificationResult({
            joinId: joinId,
            valid: valid,
            fragmentsValid: fragmentsValid,
            joinLogicValid: joinLogicValid,
            policyCompliant: policyCompliant,
            transitionValid: transitionValid,
            finalStateCommitment: join.stateTransitionCommitment,
            nullifier: nullifier,
            verifiedAt: uint64(block.timestamp),
            verifier: msg.sender
        });

        if (valid) {
            totalVerified++;
        }

        emit JoinVerified(joinId, valid, join.stateTransitionCommitment);
    }

    /**
     * @notice Accumulate verified join into state
     * @dev JAM's "accumulate" step - fold verified result into global state
     * @param joinId Verified join to accumulate
     */
    function accumulateJoin(bytes32 joinId) external onlyRole(EXECUTOR_ROLE) {
        ConfidentialJoin storage join = joins[joinId];
        require(join.status == JoinStatus.Verified, "JCC: not verified");

        JoinVerificationResult storage result = verificationResults[joinId];
        require(!usedNullifiers[result.nullifier], "JCC: already accumulated");

        // Mark nullifier as used
        usedNullifiers[result.nullifier] = true;
        nullifierToJoin[result.nullifier] = joinId;

        // Update status
        join.status = JoinStatus.Accumulated;
        totalAccumulated++;

        emit JoinAccumulated(
            joinId,
            result.nullifier,
            result.finalStateCommitment
        );
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get fragment details
     */
    function getFragment(
        bytes32 fragmentId
    ) external view returns (ComputationFragment memory) {
        return fragments[fragmentId];
    }

    /**
     * @notice Get join details
     */
    function getJoin(
        bytes32 joinId
    ) external view returns (ConfidentialJoin memory) {
        return joins[joinId];
    }

    /**
     * @notice Get join fragments
     */
    function getJoinFragments(
        bytes32 joinId
    ) external view returns (bytes32[] memory) {
        return joinFragments[joinId];
    }

    /**
     * @notice Get verification result
     */
    function getVerificationResult(
        bytes32 joinId
    ) external view returns (JoinVerificationResult memory) {
        return verificationResults[joinId];
    }

    /**
     * @notice Check if nullifier is used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /**
     * @notice Get metrics
     */
    function getMetrics()
        external
        view
        returns (
            uint256 _totalFragments,
            uint256 _totalJoins,
            uint256 _totalVerified,
            uint256 _totalAccumulated
        )
    {
        return (totalFragments, totalJoins, totalVerified, totalAccumulated);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function deactivateJoinSpec(
        bytes32 joinSpecId
    ) external onlyRole(JOIN_ADMIN_ROLE) {
        joinSpecs[joinSpecId].active = false;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
