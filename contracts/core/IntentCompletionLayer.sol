// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {IIntentCompletionLayer} from "../interfaces/IIntentCompletionLayer.sol";

/**
 * @title IntentCompletionLayer
 * @author ZASEON
 * @notice Proof service marketplace — solvers compete to generate and deliver ZK proofs
 * @dev ZASEON is proof middleware, NOT a bridge. This contract does NOT move tokens.
 *      Users submit intents describing desired cross-chain state transitions.
 *      Solvers compete to fulfill intents by generating valid ZK proofs.
 *      The user escrows a service fee (maxFee) — NOT the transfer amount.
 *      Actual token movement happens externally via bridges (Hyperlane, LayerZero, etc.).
 *
 * LIFECYCLE (proof-centric):
 *   User submits intent (escrows service fee) →
 *   Solver claims intent →
 *   Solver generates ZK proof and submits to CrossChainProofHubV3 →
 *   Challenge period (proof can be disputed) →
 *   Finalization (solver receives service fee, user's state committed on dest chain)
 *
 * SECURITY:
 * - All state-changing externals are nonReentrant
 * - Solver minimum stake enforced
 * - Claim timeout prevents griefing
 * - Challenge period before finalization
 * - Zero-address validation on all critical params
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract IntentCompletionLayer is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    IIntentCompletionLayer
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

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

    /// @notice Minimum solver stake required to participate
    uint256 public constant MIN_SOLVER_STAKE = 1 ether;

    /// @notice Maximum time a solver has to fulfill after claiming
    uint256 public constant CLAIM_TIMEOUT = 30 minutes;

    /// @notice Challenge period after fulfillment before finalization
    uint256 public constant CHALLENGE_PERIOD = 1 hours;

    /// @notice Protocol fee in basis points (3%)
    uint256 public constant PROTOCOL_FEE_BPS = 300;

    /// @notice Maximum batch size for batch operations
    uint256 public constant MAX_BATCH_SIZE = 20;

    /// @notice Minimum intent deadline (must be at least 10 minutes from now)
    uint256 public constant MIN_DEADLINE_OFFSET = 10 minutes;

    /// @notice Maximum intent deadline (7 days)
    uint256 public constant MAX_DEADLINE_OFFSET = 7 days;

    /// @notice Slashing percentage for failed fulfillments (5% in bps)
    uint256 public constant SLASH_BPS = 500;

    /// @notice Basis points denominator
    uint256 private constant BPS = 10_000;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice ZK proof verifier for intent fulfillment proofs
    IProofVerifier public intentVerifier;

    /// @notice Intent registry
    mapping(bytes32 => Intent) internal _intents;

    /// @notice Solver registry
    mapping(address => Solver) internal _solvers;

    /// @notice Intent nonce per user (for unique IDs)
    mapping(address => uint256) internal _nonces;

    /// @notice Active solver list
    address[] public activeSolvers;
    mapping(address => uint256) internal _solverIndex;

    /// @notice Protocol fee accumulator
    uint256 public protocolFees;

    /// @notice Total intents submitted
    uint256 public totalIntents;

    /// @notice Total intents finalized
    uint256 public totalFinalized;

    /// @notice Supported chain IDs
    mapping(uint256 => bool) public supportedChains;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Admin address (DEFAULT_ADMIN_ROLE)
    /// @param _intentVerifier ZK verifier for fulfillment proofs (address(0) to set later)
    constructor(address admin, address _intentVerifier) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);

        if (_intentVerifier != address(0)) {
            intentVerifier = IProofVerifier(_intentVerifier);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the ZK proof verifier for intent fulfillment
    /// @param _verifier New verifier address
        /**
     * @notice Sets the intent verifier
     * @param _verifier The _verifier
     */
function setIntentVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        intentVerifier = IProofVerifier(_verifier);
        emit IntentVerifierUpdated(_verifier);
    }

    /// @notice Enable or disable a chain for intents
    /// @param chainId The chain ID to configure
    /// @param enabled Whether the chain is supported
        /**
     * @notice Sets the supported chain
     * @param chainId The chain identifier
     * @param enabled Whether the feature is enabled
     */
function setSupportedChain(
        uint256 chainId,
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId();
        supportedChains[chainId] = enabled;
        emit ChainSupportUpdated(chainId, enabled);
    }

    /// @notice Withdraw accumulated protocol fees
    /// @param to Recipient address
        /**
     * @notice Withdraws protocol fees
     * @param to The destination address
     */
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

    /// @notice Emergency pause
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpause
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Submits intent
     * @param sourceChainId The source chain identifier
     * @param destChainId The destination chain identifier
     * @param sourceCommitment The source commitment
     * @param desiredStateHash The desiredStateHash hash value
     * @param maxFee The maxFee bound
     * @param deadline The deadline timestamp
     * @param policyHash The policyHash hash value
     * @return intentId The intent id
     */
function submitIntent(
        uint256 sourceChainId,
        uint256 destChainId,
        bytes32 sourceCommitment,
        bytes32 desiredStateHash,
        uint256 maxFee,
        uint256 deadline,
        bytes32 policyHash
    ) external payable nonReentrant whenNotPaused returns (bytes32 intentId) {
        // Validate inputs
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

        // Generate unique intent ID
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

        // Refund excess ETH
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

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Cancels intent
     * @param intentId The intentId identifier
     */
function cancelIntent(bytes32 intentId) external nonReentrant {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();
        if (intent.user != msg.sender) revert NotIntentUser();
        if (intent.status != IntentStatus.PENDING) revert IntentNotPending();

        intent.status = IntentStatus.CANCELLED;

        // Refund escrowed fee
        _safeTransferETH(msg.sender, intent.maxFee);

        emit IntentCancelled(intentId);
    }

    /*//////////////////////////////////////////////////////////////
                          SOLVER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Registers solver
     */
function registerSolver() external payable nonReentrant whenNotPaused {
        if (msg.value < MIN_SOLVER_STAKE) revert InsufficientStake();
        Solver storage solver = _solvers[msg.sender];
        if (solver.isActive) revert SolverAlreadyRegistered();

        // Allow reactivation with additional stake
        solver.stake += msg.value;
        solver.isActive = true;
        solver.registeredAt = uint48(block.timestamp);

        _addActiveSolver(msg.sender);

        emit SolverRegistered(msg.sender, solver.stake);
    }

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Deactivate solver
     */
function deactivateSolver() external nonReentrant {
        Solver storage solver = _solvers[msg.sender];
        if (!solver.isActive) revert SolverNotActive();

        solver.isActive = false;
        _removeActiveSolver(msg.sender);

        // Return stake
        uint256 stakeToReturn = solver.stake;
        solver.stake = 0;
        _safeTransferETH(msg.sender, stakeToReturn);

        emit SolverDeactivated(msg.sender);
    }

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Claims intent
     * @param intentId The intentId identifier
     */
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

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Fulfill intent
     * @param intentId The intentId identifier
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param newCommitment The new Commitment value
     */
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
            // Claim expired — reset to pending so another solver can take it
            address expiredSolver = intent.solver;
            intent.status = IntentStatus.PENDING;
            intent.solver = address(0);
            intent.claimedAt = 0;
            emit IntentClaimExpired(intentId, expiredSolver);
            return; // Don't revert — state change must persist
        }
        if (block.timestamp > intent.deadline) revert DeadlinePassed();

        // Verify ZK proof if verifier is set
        if (address(intentVerifier) != address(0)) {
            bool valid = intentVerifier.verifyProof(proof, publicInputs);
            if (!valid) revert InvalidProof();
        }

        // Generate fulfillment proof ID
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

    /// @notice Dispute a fulfilled intent during challenge period
    /// @param intentId The intent to dispute
    /// @param disputeProof Proof that the fulfillment is invalid
    /// @param disputeInputs Public inputs for the dispute proof
        /**
     * @notice Dispute intent
     * @param intentId The intentId identifier
     * @param disputeProof The dispute proof
     * @param disputeInputs The dispute inputs
     */
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

        // Verify dispute proof if verifier is set
        if (address(intentVerifier) != address(0)) {
            bool valid = intentVerifier.verifyProof(
                disputeProof,
                disputeInputs
            );
            if (!valid) revert InvalidProof();
        }

        // Dispute successful — slash solver and refund user
        intent.status = IntentStatus.DISPUTED;

        Solver storage solver = _solvers[intent.solver];
        uint256 slashAmount = (solver.stake * SLASH_BPS) / BPS;
        solver.stake -= slashAmount;
        solver.failedFills++;

        // Deactivate solver if stake drops below minimum
        if (solver.stake < MIN_SOLVER_STAKE && solver.isActive) {
            solver.isActive = false;
            _removeActiveSolver(intent.solver);
        }

        // Refund user fee + slash bonus to challenger
        _safeTransferETH(intent.user, intent.maxFee);
        _safeTransferETH(msg.sender, slashAmount);

        emit IntentDisputed(intentId, msg.sender);
        emit SolverSlashed(intent.solver, slashAmount, "dispute");
    }

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Finalizes intent
     * @param intentId The intentId identifier
     */
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

        // Calculate payout
        uint256 protocolCut = (intent.maxFee * PROTOCOL_FEE_BPS) / BPS;
        uint256 solverPayout = intent.maxFee - protocolCut;

        protocolFees += protocolCut;
        solver.totalEarnings += solverPayout;

        unchecked {
            ++totalFinalized;
        }

        // Pay solver
        _safeTransferETH(intent.solver, solverPayout);

        emit IntentFinalized(intentId, intent.solver, solverPayout);
    }

    /// @notice Expire an intent that passed its deadline without fulfillment
    /// @param intentId The intent to expire
        /**
     * @notice Expire intent
     * @param intentId The intentId identifier
     */
function expireIntent(bytes32 intentId) external nonReentrant {
        Intent storage intent = _intents[intentId];
        if (intent.user == address(0)) revert IntentNotFound();

        bool canExpire = (intent.status == IntentStatus.PENDING &&
            block.timestamp > intent.deadline) ||
            (intent.status == IntentStatus.CLAIMED &&
                block.timestamp > intent.deadline);

        if (!canExpire) revert DeadlinePassed();

        // If a solver claimed but didn't fulfill, slash them
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

        // Refund user
        _safeTransferETH(intent.user, intent.maxFee);

        emit IntentExpired(intentId);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Returns the intent
     * @param intentId The intentId identifier
     * @return The result value
     */
function getIntent(bytes32 intentId) external view returns (Intent memory) {
        return _intents[intentId];
    }

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Returns the solver
     * @param solver The solver
     * @return The result value
     */
function getSolver(address solver) external view returns (Solver memory) {
        return _solvers[solver];
    }

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Can finalize
     * @param intentId The intentId identifier
     * @return The result value
     */
function canFinalize(bytes32 intentId) external view returns (bool) {
        Intent storage intent = _intents[intentId];
        return
            intent.status == IntentStatus.FULFILLED &&
            block.timestamp >= intent.fulfilledAt + CHALLENGE_PERIOD;
    }

    /// @inheritdoc IIntentCompletionLayer
        /**
     * @notice Checks if finalized
     * @param intentId The intentId identifier
     * @return The result value
     */
function isFinalized(bytes32 intentId) external view returns (bool) {
        return _intents[intentId].status == IntentStatus.FINALIZED;
    }

    /// @notice Get the number of active solvers
        /**
     * @notice Active solver count
     * @return The result value
     */
function activeSolverCount() external view returns (uint256) {
        return activeSolvers.length;
    }

    /// @notice Get intent status
        /**
     * @notice Intent status
     * @param intentId The intentId identifier
     * @return The result value
     */
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

    /// @notice Emitted when the intent verifier is updated
    event IntentVerifierUpdated(address indexed verifier);

    /// @notice Emitted when chain support is toggled
    event ChainSupportUpdated(uint256 indexed chainId, bool enabled);

    /// @notice Emitted when protocol fees are withdrawn
    event ProtocolFeesWithdrawn(address indexed to, uint256 amount);
}
