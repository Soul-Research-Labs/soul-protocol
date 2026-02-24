// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {IIntentSettlementLayer} from "../interfaces/IIntentSettlementLayer.sol";

/**
 * @title IntentSettlementLayerUpgradeable
 * @author Soul Protocol
 * @notice UUPS-upgradeable version of IntentSettlementLayer for proxy deployments
 * @dev Proof service marketplace — solvers compete to deliver ZK proofs.
 *      Soul is proof middleware, NOT a bridge. See IntentSettlementLayer for full docs.
 *
 * UPGRADE NOTES:
 * - Constructor replaced with `initialize(address admin, address _intentVerifier)`
 * - All OZ base contracts replaced with upgradeable variants
 * - UUPS upgrade restricted to UPGRADER_ROLE
 * - Storage gap (`__gap[50]`) reserved for future upgrades
 *
 * @custom:oz-upgrades-from IntentSettlementLayer
 */
contract IntentSettlementLayerUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    IIntentSettlementLayer
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @dev keccak256("CHALLENGER_ROLE")
    bytes32 public constant CHALLENGER_ROLE =
        0xe752add323323eb13e36c71ee508dfd16d74e9e4c4fd78786ba97989e5e13818;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MIN_SOLVER_STAKE = 1 ether;
    uint256 public constant CLAIM_TIMEOUT = 30 minutes;
    uint256 public constant CHALLENGE_PERIOD = 1 hours;
    uint256 public constant PROTOCOL_FEE_BPS = 300;
    uint256 public constant MAX_BATCH_SIZE = 20;
    uint256 public constant MIN_DEADLINE_OFFSET = 10 minutes;
    uint256 public constant MAX_DEADLINE_OFFSET = 7 days;
    uint256 public constant SLASH_BPS = 500;
    uint256 private constant BPS = 10_000;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    IProofVerifier public intentVerifier;
    mapping(bytes32 => Intent) internal _intents;
    mapping(address => Solver) internal _solvers;
    mapping(address => uint256) internal _nonces;
    address[] public activeSolvers;
    mapping(address => uint256) internal _solverIndex;
    uint256 public protocolFees;
    uint256 public totalIntents;
    uint256 public totalFinalized;
    mapping(uint256 => bool) public supportedChains;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public contractVersion;

    /// @dev Reserved storage for future upgrades
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the upgradeable intent settlement layer
    /// @param admin Admin address (DEFAULT_ADMIN_ROLE + UPGRADER_ROLE)
    /// @param _intentVerifier ZK verifier for fulfillment proofs (address(0) to set later)
    function initialize(
        address admin,
        address _intentVerifier
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        if (_intentVerifier != address(0)) {
            intentVerifier = IProofVerifier(_intentVerifier);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          UUPS UPGRADE
    //////////////////////////////////////////////////////////////*/

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setIntentVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        intentVerifier = IProofVerifier(_verifier);
        emit IntentVerifierUpdated(_verifier);
    }

    function setSupportedChain(
        uint256 chainId,
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId();
        supportedChains[chainId] = enabled;
        emit ChainSupportUpdated(chainId, enabled);
    }

    function withdrawProtocolFees(
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = protocolFees;
        if (amount == 0) revert InvalidAmount();
        protocolFees = 0;
        _safeTransferETH(to, amount);
        emit ProtocolFeesWithdrawn(to, amount);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IIntentSettlementLayer
    function submitIntent(
        uint256 sourceChainId,
        uint256 destChainId,
        bytes32 sourceCommitment,
        bytes32 desiredStateHash,
        uint256 maxFee,
        uint256 deadline,
        bytes32 policyHash
    ) external payable nonReentrant whenNotPaused returns (bytes32 intentId) {
        if (sourceChainId == 0) revert InvalidChainId();
        if (destChainId == 0) revert InvalidChainId();
        if (sourceChainId == destChainId) revert InvalidChainId();
        if (!supportedChains[sourceChainId] || !supportedChains[destChainId])
            revert InvalidChainId();
        if (sourceCommitment == bytes32(0)) revert InvalidAmount();
        if (desiredStateHash == bytes32(0)) revert InvalidAmount();
        if (maxFee == 0) revert InvalidAmount();
        if (msg.value < maxFee) revert InsufficientFee();
        if (deadline < block.timestamp + MIN_DEADLINE_OFFSET)
            revert InvalidDeadline();
        if (deadline > block.timestamp + MAX_DEADLINE_OFFSET)
            revert InvalidDeadline();

        uint256 nonce = _nonces[msg.sender]++;
        intentId = keccak256(
            abi.encodePacked(
                msg.sender,
                sourceChainId,
                destChainId,
                sourceCommitment,
                nonce,
                block.chainid
            )
        );

        _intents[intentId] = Intent({
            user: msg.sender,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            sourceCommitment: sourceCommitment,
            desiredStateHash: desiredStateHash,
            maxFee: maxFee,
            deadline: deadline,
            policyHash: policyHash,
            status: IntentStatus.PENDING,
            solver: address(0),
            claimedAt: 0,
            fulfilledAt: 0,
            fulfillmentProofId: bytes32(0)
        });

        unchecked {
            ++totalIntents;
        }

        if (msg.value > maxFee) {
            _safeTransferETH(msg.sender, msg.value - maxFee);
        }

        emit IntentSubmitted(
            intentId,
            msg.sender,
            sourceChainId,
            destChainId,
            maxFee
        );
    }

    /// @inheritdoc IIntentSettlementLayer
    function cancelIntent(bytes32 intentId) external nonReentrant {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();
        if (intent.user != msg.sender) revert NotIntentUser();
        if (intent.status != IntentStatus.PENDING) revert IntentNotPending();

        intent.status = IntentStatus.CANCELLED;
        _safeTransferETH(msg.sender, intent.maxFee);
        emit IntentCancelled(intentId);
    }

    /*//////////////////////////////////////////////////////////////
                          SOLVER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IIntentSettlementLayer
    function registerSolver() external payable nonReentrant whenNotPaused {
        if (msg.value < MIN_SOLVER_STAKE) revert InsufficientStake();
        Solver storage solver = _solvers[msg.sender];
        if (solver.isActive) revert SolverAlreadyRegistered();

        solver.stake += msg.value;
        solver.isActive = true;
        solver.registeredAt = uint48(block.timestamp);

        _addActiveSolver(msg.sender);
        emit SolverRegistered(msg.sender, solver.stake);
    }

    /// @inheritdoc IIntentSettlementLayer
    function deactivateSolver() external nonReentrant {
        Solver storage solver = _solvers[msg.sender];
        if (!solver.isActive) revert SolverNotActive();

        solver.isActive = false;
        _removeActiveSolver(msg.sender);

        uint256 stakeToReturn = solver.stake;
        solver.stake = 0;
        _safeTransferETH(msg.sender, stakeToReturn);
        emit SolverDeactivated(msg.sender);
    }

    /// @inheritdoc IIntentSettlementLayer
    function claimIntent(bytes32 intentId) external nonReentrant whenNotPaused {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();
        if (intent.status != IntentStatus.PENDING) revert IntentNotPending();
        if (block.timestamp > intent.deadline) revert DeadlinePassed();

        Solver storage solver = _solvers[msg.sender];
        if (!solver.isActive) revert SolverNotActive();
        if (solver.stake < MIN_SOLVER_STAKE) revert InsufficientStake();

        intent.status = IntentStatus.CLAIMED;
        intent.solver = msg.sender;
        intent.claimedAt = uint48(block.timestamp);
        emit IntentClaimed(intentId, msg.sender);
    }

    /// @inheritdoc IIntentSettlementLayer
    function fulfillIntent(
        bytes32 intentId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 newCommitment
    ) external nonReentrant whenNotPaused {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();
        if (intent.status != IntentStatus.CLAIMED) revert IntentNotClaimed();
        if (intent.solver != msg.sender) revert NotAssignedSolver();
        if (block.timestamp > intent.claimedAt + CLAIM_TIMEOUT) {
            address expiredSolver = intent.solver;
            intent.status = IntentStatus.PENDING;
            intent.solver = address(0);
            intent.claimedAt = 0;
            emit IntentClaimExpired(intentId, expiredSolver);
            return;
        }
        if (block.timestamp > intent.deadline) revert DeadlinePassed();

        if (address(intentVerifier) != address(0)) {
            bool valid = intentVerifier.verifyProof(proof, publicInputs);
            if (!valid) revert InvalidProof();
        }

        bytes32 proofId = keccak256(
            abi.encodePacked(
                intentId,
                newCommitment,
                msg.sender,
                block.timestamp
            )
        );

        intent.status = IntentStatus.FULFILLED;
        intent.fulfilledAt = uint48(block.timestamp);
        intent.fulfillmentProofId = proofId;
        emit IntentFulfilled(intentId, msg.sender, proofId);
    }

    function disputeIntent(
        bytes32 intentId,
        bytes calldata disputeProof,
        bytes calldata disputeInputs
    ) external nonReentrant onlyRole(CHALLENGER_ROLE) {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();
        if (intent.status != IntentStatus.FULFILLED)
            revert IntentNotFulfilled();
        if (block.timestamp > intent.fulfilledAt + CHALLENGE_PERIOD)
            revert ChallengePeriodActive();

        if (address(intentVerifier) != address(0)) {
            bool valid = intentVerifier.verifyProof(
                disputeProof,
                disputeInputs
            );
            if (!valid) revert InvalidProof();
        }

        intent.status = IntentStatus.DISPUTED;

        Solver storage solver = _solvers[intent.solver];
        uint256 slashAmount = (solver.stake * SLASH_BPS) / BPS;
        solver.stake -= slashAmount;
        solver.failedFills++;

        if (solver.stake < MIN_SOLVER_STAKE && solver.isActive) {
            solver.isActive = false;
            _removeActiveSolver(intent.solver);
        }

        _safeTransferETH(intent.user, intent.maxFee);
        _safeTransferETH(msg.sender, slashAmount);

        emit IntentDisputed(intentId, msg.sender);
        emit SolverSlashed(intent.solver, slashAmount, "dispute");
    }

    /// @inheritdoc IIntentSettlementLayer
    function finalizeIntent(bytes32 intentId) external nonReentrant {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();
        if (intent.status != IntentStatus.FULFILLED)
            revert IntentNotFulfilled();
        if (block.timestamp < intent.fulfilledAt + CHALLENGE_PERIOD)
            revert ChallengePeriodActive();

        intent.status = IntentStatus.FINALIZED;

        Solver storage solver = _solvers[intent.solver];
        solver.successfulFills++;

        uint256 protocolCut = (intent.maxFee * PROTOCOL_FEE_BPS) / BPS;
        uint256 solverPayout = intent.maxFee - protocolCut;

        protocolFees += protocolCut;
        solver.totalEarnings += solverPayout;

        unchecked {
            ++totalFinalized;
        }

        _safeTransferETH(intent.solver, solverPayout);
        emit IntentFinalized(intentId, intent.solver, solverPayout);
    }

    function expireIntent(bytes32 intentId) external nonReentrant {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();

        bool canExpire = (intent.status == IntentStatus.PENDING &&
            block.timestamp > intent.deadline) ||
            (intent.status == IntentStatus.CLAIMED &&
                block.timestamp > intent.deadline);

        if (!canExpire) revert DeadlinePassed();

        if (
            intent.status == IntentStatus.CLAIMED && intent.solver != address(0)
        ) {
            Solver storage solver = _solvers[intent.solver];
            uint256 slashAmount = (solver.stake * SLASH_BPS) / BPS;
            if (slashAmount > 0 && solver.stake >= slashAmount) {
                solver.stake -= slashAmount;
                solver.failedFills++;
                protocolFees += slashAmount;

                if (solver.stake < MIN_SOLVER_STAKE && solver.isActive) {
                    solver.isActive = false;
                    _removeActiveSolver(intent.solver);
                }

                emit SolverSlashed(intent.solver, slashAmount, "claim_timeout");
            }
        }

        intent.status = IntentStatus.EXPIRED;
        _safeTransferETH(intent.user, intent.maxFee);
        emit IntentExpired(intentId);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IIntentSettlementLayer
    function getIntent(bytes32 intentId) external view returns (Intent memory) {
        return _intents[intentId];
    }

    /// @inheritdoc IIntentSettlementLayer
    function getSolver(address solver) external view returns (Solver memory) {
        return _solvers[solver];
    }

    /// @inheritdoc IIntentSettlementLayer
    function canFinalize(bytes32 intentId) external view returns (bool) {
        Intent storage intent = _intents[intentId];
        return
            intent.status == IntentStatus.FULFILLED &&
            block.timestamp >= intent.fulfilledAt + CHALLENGE_PERIOD;
    }

    /// @inheritdoc IIntentSettlementLayer
    function isFinalized(bytes32 intentId) external view returns (bool) {
        return _intents[intentId].status == IntentStatus.FINALIZED;
    }

    function activeSolverCount() external view returns (uint256) {
        return activeSolvers.length;
    }

    function intentStatus(
        bytes32 intentId
    ) external view returns (IntentStatus) {
        return _intents[intentId].status;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _addActiveSolver(address solver) internal {
        _solverIndex[solver] = activeSolvers.length;
        activeSolvers.push(solver);
    }

    function _removeActiveSolver(address solver) internal {
        uint256 index = _solverIndex[solver];
        uint256 lastIndex = activeSolvers.length - 1;
        if (index != lastIndex) {
            address lastSolver = activeSolvers[lastIndex];
            activeSolvers[index] = lastSolver;
            _solverIndex[lastSolver] = index;
        }
        activeSolvers.pop();
        delete _solverIndex[solver];
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    /*//////////////////////////////////////////////////////////////
                        ADDITIONAL EVENTS
    //////////////////////////////////////////////////////////////*/

    event IntentVerifierUpdated(address indexed verifier);
    event ChainSupportUpdated(uint256 indexed chainId, bool enabled);
    event ProtocolFeesWithdrawn(address indexed to, uint256 amount);
}
