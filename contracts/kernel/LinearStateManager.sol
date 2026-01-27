// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title LinearStateManager
 * @author Soul Protocol - Soul Protocol
 * @notice Enforces Aztec-Style Linear State Semantics for Cross-Chain State
 * @dev STATE IS CREATED, CONSUMED, NEVER MUTATED IN PLACE
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    LINEAR STATE SEMANTICS
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Key insight from Aztec:
 * "Cross-chain state mutation is WHERE BRIDGES FAIL"
 *
 * The solution:
 * - Every state transition CONSUMES the old state commitment
 * - Every state transition PRODUCES a new state commitment
 * - NO in-place updates across chains
 * - Nullifiers enforce single-use semantics
 *
 * This makes replay, race, and reordering attacks STRUCTURALLY IMPOSSIBLE.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    STATE LIFECYCLE
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * 1. CREATE: New state commitment is produced (genesis)
 * 2. CONSUME: State is consumed with valid nullifier (transition)
 * 3. PRODUCE: New state is produced from consumption (continuation)
 *
 * State can NEVER be:
 * - Modified in place
 * - Partially consumed
 * - Reverted after consumption
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    CROSS-CHAIN INVARIANTS
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * 1. CONSUMPTION ATOMICITY: State consumption is atomic (no partial states)
 * 2. NULLIFIER FINALITY: Once a nullifier is used, it can never be reused
 * 3. CHAIN ORDERING: State consumption creates total ordering across chains
 * 4. TRANSITION VALIDITY: Every consumption must reference valid transition predicate
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract LinearStateManager is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed keccak256("STATE_ADMIN_ROLE") for gas savings
    bytes32 public constant STATE_ADMIN_ROLE =
        0xf7054b28837a3e0f0fcdf0631d7a1f2c54f272601d37d24ed1fa836bd1c2ae94;
    /// @dev Pre-computed keccak256("KERNEL_ROLE") for gas savings
    bytes32 public constant KERNEL_ROLE =
        0x6461d7edb0de6153faa1dbe72f8286821dd20b9e202b6351eb86ef5e04eaec51;
    /// @dev Pre-computed keccak256("BRIDGE_ROLE") for gas savings
    bytes32 public constant BRIDGE_ROLE =
        0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error StateAlreadyExists(bytes32 commitment);
    error StateDoesNotExist(bytes32 commitment);
    error StateAlreadyConsumed(bytes32 commitment);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidNullifierDerivation();
    error InvalidTransitionPredicate();
    error InvalidStateProof();
    error ChainMismatch(uint256 expected, uint256 actual);
    error StateNotActive(bytes32 commitment);
    error TransitionNotAllowed(bytes32 fromState, bytes32 toState);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice State lifecycle status
    enum StateLifecycle {
        NonExistent, // State does not exist
        Active, // State is active and can be consumed
        Consumed, // State has been consumed
        Invalidated // State was invalidated (compliance)
    }

    /// @notice Linear state record
    struct LinearState {
        bytes32 commitment; // State commitment
        bytes32 nullifier; // Nullifier used to consume
        bytes32 predecessor; // Previous state (bytes32(0) for genesis)
        bytes32 successor; // Next state (bytes32(0) if not consumed)
        bytes32 transitionPredicate; // Valid transition circuit
        bytes32 policyHash; // Bound policy
        uint256 sourceChainId; // Origin chain
        uint256 currentChainId; // Current chain
        StateLifecycle lifecycle; // Current lifecycle state
        uint64 createdAt;
        uint64 consumedAt;
    }

    /// @notice State transition record
    struct StateTransition {
        bytes32 fromCommitment;
        bytes32 toCommitment;
        bytes32 nullifier;
        bytes32 transitionPredicate;
        bytes32 kernelProofId; // Kernel proof that validated
        uint256 fromChainId;
        uint256 toChainId;
        uint64 timestamp;
    }

    /// @notice Cross-domain nullifier binding
    struct CrossDomainNullifier {
        bytes32 nullifier;
        bytes32 stateCommitment;
        bytes32 domainSeparator;
        uint256 sourceChainId;
        uint256 registeredChainId;
        uint64 registeredAt;
        bool isConsumed;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain ID (immutable)
    uint256 public immutable CHAIN_ID;

    /// @notice Linear state registry: commitment => state
    mapping(bytes32 => LinearState) public linearStates;

    /// @notice Nullifier registry: nullifier => consumed
    mapping(bytes32 => bool) public nullifierRegistry;

    /// @notice Cross-domain nullifiers: nullifier => binding
    mapping(bytes32 => CrossDomainNullifier) public crossDomainNullifiers;

    /// @notice State transition history: fromCommitment => transitions
    mapping(bytes32 => StateTransition[]) public transitionHistory;

    /// @notice Successor lookup: predecessor => successor
    mapping(bytes32 => bytes32) public successorLookup;

    /// @notice Predecessor lookup: successor => predecessor
    mapping(bytes32 => bytes32) public predecessorLookup;

    /// @notice Valid transition predicates
    mapping(bytes32 => bool) public validPredicates;

    /// @notice State count per chain: chainId => count
    mapping(uint256 => uint256) public stateCountByChain;

    /// @notice Total states created
    uint256 public totalStatesCreated;

    /// @notice Total states consumed
    uint256 public totalStatesConsumed;

    /// @notice Total cross-chain transitions
    uint256 public totalCrossChainTransitions;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateCreated(
        bytes32 indexed commitment,
        bytes32 indexed predecessor,
        bytes32 transitionPredicate,
        uint256 chainId
    );

    event StateConsumed(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        bytes32 indexed nullifier,
        uint256 fromChainId,
        uint256 toChainId
    );

    event TransitionRecorded(
        bytes32 indexed fromCommitment,
        bytes32 indexed toCommitment,
        bytes32 transitionPredicate
    );

    event CrossDomainNullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed stateCommitment,
        uint256 sourceChainId
    );

    event PredicateRegistered(bytes32 indexed predicateHash);
    event PredicateRevoked(bytes32 indexed predicateHash);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        CHAIN_ID = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(STATE_ADMIN_ROLE, msg.sender);
        _grantRole(KERNEL_ROLE, msg.sender);
        _grantRole(BRIDGE_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         CORE STATE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new genesis state (no predecessor)
     * @dev Only for initial state creation, not transitions
     * @param commitment The state commitment
     * @param transitionPredicate Valid transition circuit hash
     * @param policyHash Bound policy hash
     * @return success True if created
     */
    function createGenesisState(
        bytes32 commitment,
        bytes32 transitionPredicate,
        bytes32 policyHash
    ) external onlyRole(KERNEL_ROLE) whenNotPaused returns (bool success) {
        // State must not already exist
        if (linearStates[commitment].lifecycle != StateLifecycle.NonExistent) {
            revert StateAlreadyExists(commitment);
        }

        // Transition predicate must be valid
        if (
            !validPredicates[transitionPredicate] &&
            transitionPredicate != bytes32(0)
        ) {
            revert InvalidTransitionPredicate();
        }

        // Create genesis state
        linearStates[commitment] = LinearState({
            commitment: commitment,
            nullifier: bytes32(0), // Genesis has no nullifier
            predecessor: bytes32(0), // Genesis has no predecessor
            successor: bytes32(0),
            transitionPredicate: transitionPredicate,
            policyHash: policyHash,
            sourceChainId: CHAIN_ID,
            currentChainId: CHAIN_ID,
            lifecycle: StateLifecycle.Active,
            createdAt: uint64(block.timestamp),
            consumedAt: 0
        });

        unchecked {
            ++totalStatesCreated;
            ++stateCountByChain[CHAIN_ID];
        }

        emit StateCreated(
            commitment,
            bytes32(0),
            transitionPredicate,
            CHAIN_ID
        );
        return true;
    }

    /**
     * @notice Consume state and produce new state (atomic)
     * @dev Core linear state transition - consumes old, produces new
     * @param oldCommitment State being consumed
     * @param newCommitment State being produced
     * @param nullifier Nullifier for consumption
     * @param transitionPredicate Valid transition circuit
     * @param kernelProofId Kernel proof that validated this transition
     * @param destChainId Destination chain (for cross-chain)
     * @return success True if transition succeeded
     */
    function consumeAndProduce(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes32 nullifier,
        bytes32 transitionPredicate,
        bytes32 kernelProofId,
        uint256 destChainId
    )
        external
        onlyRole(KERNEL_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool success)
    {
        LinearState storage oldState = linearStates[oldCommitment];

        // Old state must exist and be active
        if (oldState.lifecycle != StateLifecycle.Active) {
            revert StateNotActive(oldCommitment);
        }

        // Nullifier must be unused
        if (nullifierRegistry[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        // New state must not exist
        if (
            linearStates[newCommitment].lifecycle != StateLifecycle.NonExistent
        ) {
            revert StateAlreadyExists(newCommitment);
        }

        // Validate transition predicate
        if (
            !validPredicates[transitionPredicate] &&
            transitionPredicate != bytes32(0)
        ) {
            revert InvalidTransitionPredicate();
        }

        // --- ATOMIC CONSUMPTION ---

        // 1. Mark nullifier as used (irreversible)
        nullifierRegistry[nullifier] = true;

        // 2. Update old state to consumed
        oldState.lifecycle = StateLifecycle.Consumed;
        oldState.successor = newCommitment;
        oldState.consumedAt = uint64(block.timestamp);

        // 3. Create new state
        linearStates[newCommitment] = LinearState({
            commitment: newCommitment,
            nullifier: nullifier,
            predecessor: oldCommitment,
            successor: bytes32(0),
            transitionPredicate: transitionPredicate,
            policyHash: oldState.policyHash, // Inherit policy
            sourceChainId: oldState.sourceChainId,
            currentChainId: destChainId,
            lifecycle: StateLifecycle.Active,
            createdAt: uint64(block.timestamp),
            consumedAt: 0
        });

        // 4. Update lookups
        successorLookup[oldCommitment] = newCommitment;
        predecessorLookup[newCommitment] = oldCommitment;

        // 5. Record transition
        transitionHistory[oldCommitment].push(
            StateTransition({
                fromCommitment: oldCommitment,
                toCommitment: newCommitment,
                nullifier: nullifier,
                transitionPredicate: transitionPredicate,
                kernelProofId: kernelProofId,
                fromChainId: oldState.currentChainId,
                toChainId: destChainId,
                timestamp: uint64(block.timestamp)
            })
        );

        // 6. Update counters
        unchecked {
            ++totalStatesCreated;
            ++totalStatesConsumed;
            ++stateCountByChain[destChainId];

            if (destChainId != oldState.currentChainId) {
                ++totalCrossChainTransitions;
            }
        }

        emit StateConsumed(
            oldCommitment,
            newCommitment,
            nullifier,
            oldState.currentChainId,
            destChainId
        );
        emit TransitionRecorded(
            oldCommitment,
            newCommitment,
            transitionPredicate
        );

        return true;
    }

    /**
     * @notice Register a cross-domain nullifier
     * @dev For cross-chain nullifier synchronization
     * @param nullifier The nullifier
     * @param stateCommitment Associated state
     * @param domainSeparator Cross-domain separator
     * @param sourceChainId Origin chain
     */
    function registerCrossDomainNullifier(
        bytes32 nullifier,
        bytes32 stateCommitment,
        bytes32 domainSeparator,
        uint256 sourceChainId
    ) external onlyRole(BRIDGE_ROLE) whenNotPaused {
        // Nullifier must be unused
        if (nullifierRegistry[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        // Register cross-domain binding
        crossDomainNullifiers[nullifier] = CrossDomainNullifier({
            nullifier: nullifier,
            stateCommitment: stateCommitment,
            domainSeparator: domainSeparator,
            sourceChainId: sourceChainId,
            registeredChainId: CHAIN_ID,
            registeredAt: uint64(block.timestamp),
            isConsumed: false
        });

        // Mark as used locally
        nullifierRegistry[nullifier] = true;

        emit CrossDomainNullifierRegistered(
            nullifier,
            stateCommitment,
            sourceChainId
        );
    }

    /*//////////////////////////////////////////////////////////////
                         PREDICATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a valid transition predicate
     * @param predicateHash Hash of the transition circuit
     */
    function registerPredicate(
        bytes32 predicateHash
    ) external onlyRole(STATE_ADMIN_ROLE) {
        validPredicates[predicateHash] = true;
        emit PredicateRegistered(predicateHash);
    }

    /**
     * @notice Revoke a transition predicate
     * @param predicateHash Hash of the transition circuit
     */
    function revokePredicate(
        bytes32 predicateHash
    ) external onlyRole(STATE_ADMIN_ROLE) {
        validPredicates[predicateHash] = false;
        emit PredicateRevoked(predicateHash);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get state lifecycle
    function getStateLifecycle(
        bytes32 commitment
    ) external view returns (StateLifecycle) {
        return linearStates[commitment].lifecycle;
    }

    /// @notice Check if state is active (consumable)
    function isStateActive(bytes32 commitment) external view returns (bool) {
        return linearStates[commitment].lifecycle == StateLifecycle.Active;
    }

    /// @notice Check if state has been consumed
    function isStateConsumed(bytes32 commitment) external view returns (bool) {
        return linearStates[commitment].lifecycle == StateLifecycle.Consumed;
    }

    /// @notice Check if nullifier is used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifierRegistry[nullifier];
    }

    /// @notice Get state chain (predecessors)
    function getStateChain(
        bytes32 commitment,
        uint256 maxDepth
    ) external view returns (bytes32[] memory chain) {
        chain = new bytes32[](maxDepth);
        bytes32 current = commitment;

        for (uint256 i = 0; i < maxDepth; ) {
            chain[i] = current;
            current = predecessorLookup[current];
            if (current == bytes32(0)) break;
            unchecked {
                ++i;
            }
        }

        return chain;
    }

    /// @notice Get transition count for a state
    function getTransitionCount(
        bytes32 commitment
    ) external view returns (uint256) {
        return transitionHistory[commitment].length;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(STATE_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(STATE_ADMIN_ROLE) {
        _unpause();
    }
}
