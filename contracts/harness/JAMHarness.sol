// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title JAMHarness
 * @notice Simplified harness for Certora verification of Joinable Confidential Computation
 * @dev Captures core JAM properties: accumulation, batching, and finalization
 */
contract JAMHarness is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ACCUMULATOR_ROLE = keccak256("ACCUMULATOR_ROLE");
    bytes32 public constant FINALIZER_ROLE = keccak256("FINALIZER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Computation state
    enum ComputationState {
        NonExistent,
        Pending,
        Accumulating,
        Finalized,
        Verified
    }

    /// @notice Simplified computation struct
    struct Computation {
        bytes32 computationId;
        bytes32 accumulatedState;
        uint256 participantCount;
        uint256 threshold;
        ComputationState state;
        uint64 createdAt;
        uint64 finalizedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Computation registry
    mapping(bytes32 => Computation) public computations;

    /// @notice Participant tracking
    mapping(bytes32 => mapping(address => bool)) public hasParticipated;

    /// @notice Counters
    uint256 public totalComputations;
    uint256 public totalFinalized;
    uint256 public totalVerified;

    /// @notice Minimum threshold
    uint256 public minThreshold = 2;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(ACCUMULATOR_ROLE, msg.sender);
        _grantRole(FINALIZER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         COMPUTATION LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function createComputation(
        bytes32 initialState,
        uint256 threshold
    ) external whenNotPaused returns (bytes32 computationId) {
        require(threshold >= minThreshold, "Threshold too low");

        computationId = keccak256(
            abi.encodePacked(msg.sender, initialState, block.timestamp)
        );

        require(
            computations[computationId].state == ComputationState.NonExistent,
            "Exists"
        );

        computations[computationId] = Computation({
            computationId: computationId,
            accumulatedState: initialState,
            participantCount: 0,
            threshold: threshold,
            state: ComputationState.Pending,
            createdAt: uint64(block.timestamp),
            finalizedAt: 0
        });

        totalComputations++;
        return computationId;
    }

    function accumulate(
        bytes32 computationId,
        bytes32 contributionHash
    ) external onlyRole(ACCUMULATOR_ROLE) nonReentrant whenNotPaused {
        Computation storage comp = computations[computationId];
        require(
            comp.state == ComputationState.Pending ||
                comp.state == ComputationState.Accumulating,
            "Invalid state"
        );
        require(
            !hasParticipated[computationId][msg.sender],
            "Already participated"
        );

        // Update accumulated state
        comp.accumulatedState = keccak256(
            abi.encodePacked(comp.accumulatedState, contributionHash)
        );
        comp.participantCount++;
        comp.state = ComputationState.Accumulating;
        hasParticipated[computationId][msg.sender] = true;
    }

    function finalize(
        bytes32 computationId
    ) external onlyRole(FINALIZER_ROLE) nonReentrant whenNotPaused {
        Computation storage comp = computations[computationId];
        require(
            comp.state == ComputationState.Accumulating,
            "Not accumulating"
        );
        require(comp.participantCount >= comp.threshold, "Threshold not met");

        comp.state = ComputationState.Finalized;
        comp.finalizedAt = uint64(block.timestamp);
        totalFinalized++;
    }

    function verify(
        bytes32 computationId
    ) external onlyRole(FINALIZER_ROLE) nonReentrant whenNotPaused {
        Computation storage comp = computations[computationId];
        require(comp.state == ComputationState.Finalized, "Not finalized");

        comp.state = ComputationState.Verified;
        totalVerified++;
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    function getComputationState(
        bytes32 computationId
    ) external view returns (ComputationState) {
        return computations[computationId].state;
    }

    function getParticipantCount(
        bytes32 computationId
    ) external view returns (uint256) {
        return computations[computationId].participantCount;
    }

    function getThreshold(
        bytes32 computationId
    ) external view returns (uint256) {
        return computations[computationId].threshold;
    }

    function hasParticipant(
        bytes32 computationId,
        address participant
    ) external view returns (bool) {
        return hasParticipated[computationId][participant];
    }
}
