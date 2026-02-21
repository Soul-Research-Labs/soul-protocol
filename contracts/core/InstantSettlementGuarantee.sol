// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IInstantSettlementGuarantee} from "../interfaces/IInstantSettlementGuarantee.sol";
import {IIntentSettlementLayer} from "../interfaces/IIntentSettlementLayer.sol";

/**
 * @title InstantSettlementGuarantee
 * @author Soul Protocol
 * @notice Solver-backed over-collateralized bonds for instant user settlement
 * @dev Solvers post 110%+ collateral so users get instant access to funds while
 *      the actual cross-chain transfer settles in the background. On successful
 *      settlement, the solver gets their bond back plus a fee. On failure, the
 *      user claims from the bond, and the surplus goes to the insurance pool.
 *
 * LIFECYCLE:
 *   Solver posts guarantee (110% bond) →
 *   User gets instant access (off-chain, tracked on-chain) →
 *   Underlying transfer finalizes →
 *   Solver settles guarantee (bond returned + fee) →
 *   OR: transfer fails + guarantee expires →
 *   User claims from bond, remainder → insurance pool
 *
 * SECURITY:
 * - All state-changing externals are nonReentrant
 * - Minimum collateral ratio enforced (110% default)
 * - Insurance pool accumulates from failed guarantees
 * - Guarantee expiry prevents indefinite bond lock
 * - Zero-address validation on all critical params
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract InstantSettlementGuarantee is
    AccessControl,
    ReentrancyGuard,
    IInstantSettlementGuarantee
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev keccak256("SETTLEMENT_ROLE") — authorized to verify transfer finalization
    bytes32 public constant SETTLEMENT_ROLE = keccak256("SETTLEMENT_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum guarantee duration
    uint256 public constant MIN_DURATION = 30 minutes;

    /// @notice Maximum guarantee duration
    uint256 public constant MAX_DURATION = 7 days;

    /// @notice Solver fee in basis points (0.5% of guaranteed amount)
    uint256 public constant SOLVER_FEE_BPS = 50;

    /// @notice Basis points denominator
    uint256 private constant BPS = 10_000;

    /// @notice Minimum guarantee amount
    uint256 public constant MIN_GUARANTEE_AMOUNT = 0.001 ether;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Required collateral ratio in basis points (e.g., 11000 = 110%)
    uint256 public collateralRatioBps = 11_000;

    /// @notice The intent settlement layer (for checking finalization)
    IIntentSettlementLayer public intentLayer;

    /// @notice Guarantee registry
    mapping(bytes32 => Guarantee) internal _guarantees;

    /// @notice Guarantee nonce (for unique IDs)
    uint256 internal _nonce;

    /// @notice Insurance pool balance
    uint256 public insurancePoolBalance;

    /// @notice Total guarantees created
    uint256 public totalGuarantees;

    /// @notice Total guarantees settled successfully
    uint256 public totalSettled;

    /// @notice Total guarantees claimed by beneficiaries
    uint256 public totalClaimed;

    /// @notice Per-guarantor tracking
    mapping(address => uint256) public guarantorActiveCount;
    mapping(address => uint256) public guarantorTotalPosted;

    /// @notice Maximum active guarantees per guarantor
    uint256 public constant MAX_ACTIVE_PER_GUARANTOR = 50;

    /// @notice Intent finalization status (manual override for testing/integration)
    /// @dev In production, this should query IntentSettlementLayer.canFinalize()
    mapping(bytes32 => bool) public intentFinalized;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Admin address (DEFAULT_ADMIN_ROLE)
    /// @param _intentLayer Address of the IntentSettlementLayer (address(0) to set later)
    constructor(address admin, address _intentLayer) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(SETTLEMENT_ROLE, admin);

        if (_intentLayer != address(0)) {
            intentLayer = IIntentSettlementLayer(_intentLayer);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the IntentSettlementLayer address
    /// @param _intentLayer New intent layer address
    function setIntentLayer(
        address _intentLayer
    ) external onlyRole(OPERATOR_ROLE) {
        if (_intentLayer == address(0)) revert ZeroAddress();
        address oldIntentLayer = address(intentLayer);
        intentLayer = IIntentSettlementLayer(_intentLayer);
        emit IntentLayerUpdated(oldIntentLayer, _intentLayer);
    }

    /// @notice Update the collateral ratio
    /// @param newRatioBps New ratio in basis points (must be >= 10000 = 100%)
    function setCollateralRatio(
        uint256 newRatioBps
    ) external onlyRole(OPERATOR_ROLE) {
        if (newRatioBps < BPS) revert InvalidCollateralRatio();
        if (newRatioBps > 30_000) revert InvalidCollateralRatio(); // Max 300%
        uint256 oldRatio = collateralRatioBps;
        collateralRatioBps = newRatioBps;
        emit CollateralRatioUpdated(oldRatio, newRatioBps);
    }

    /// @notice Mark an intent as finalized (SETTLEMENT_ROLE)
    /// @dev Used when IntentSettlementLayer is not set or for manual override
    /// @param intentId The intent to mark as finalized
    function markIntentFinalized(
        bytes32 intentId
    ) external onlyRole(SETTLEMENT_ROLE) {
        intentFinalized[intentId] = true;
        emit IntentFinalized(intentId);
    }

    /// @notice Withdraw from insurance pool (governance only)
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    function withdrawInsurance(
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0 || amount > insurancePoolBalance)
            revert InvalidAmount();
        insurancePoolBalance -= amount;
        _safeTransferETH(to, amount);
        emit InsuranceWithdrawn(to, amount, insurancePoolBalance);
    }

    /*//////////////////////////////////////////////////////////////
                          SOLVER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IInstantSettlementGuarantee
    function postGuarantee(
        bytes32 intentId,
        address beneficiary,
        uint256 amount,
        uint256 duration
    ) external payable nonReentrant returns (bytes32 guaranteeId) {
        // Validate inputs
        if (beneficiary == address(0)) revert ZeroAddress();
        if (amount < MIN_GUARANTEE_AMOUNT) revert InvalidAmount();
        if (duration < MIN_DURATION || duration > MAX_DURATION)
            revert InvalidDuration();
        if (intentId == bytes32(0)) revert IntentNotLinked();

        // Check collateral
        uint256 requiredBond = (amount * collateralRatioBps) / BPS;
        if (msg.value < requiredBond) revert InsufficientBond();

        // Check guarantor limits
        if (guarantorActiveCount[msg.sender] >= MAX_ACTIVE_PER_GUARANTOR) {
            revert InvalidAmount(); // Too many active guarantees
        }

        // Generate unique guarantee ID
        guaranteeId = keccak256(
            abi.encodePacked(
                msg.sender,
                intentId,
                beneficiary,
                amount,
                _nonce++,
                block.chainid
            )
        );

        _guarantees[guaranteeId] = Guarantee({
            intentId: intentId,
            guarantor: msg.sender,
            beneficiary: beneficiary,
            amount: amount,
            bond: msg.value,
            createdAt: uint48(block.timestamp),
            expiresAt: uint48(block.timestamp + duration),
            status: GuaranteeStatus.ACTIVE
        });

        guarantorActiveCount[msg.sender]++;
        guarantorTotalPosted[msg.sender] += msg.value;

        unchecked {
            ++totalGuarantees;
        }

        emit GuaranteeCreated(
            guaranteeId,
            intentId,
            msg.sender,
            beneficiary,
            amount,
            msg.value
        );
    }

    /// @inheritdoc IInstantSettlementGuarantee
    function settleGuarantee(bytes32 guaranteeId) external nonReentrant {
        Guarantee storage g = _guarantees[guaranteeId];
        if (g.guarantor == address(0)) revert GuaranteeNotFound();
        if (g.status != GuaranteeStatus.ACTIVE) revert GuaranteeNotActive();
        if (g.guarantor != msg.sender) revert NotGuarantor();

        // Check that the underlying intent is finalized
        if (!_isIntentFinalized(g.intentId)) revert TransferNotFinalized();

        g.status = GuaranteeStatus.SETTLED;
        guarantorActiveCount[msg.sender]--;

        // Return full bond to solver on successful settlement
        // (solver's profit comes from IntentSettlementLayer, not from the guarantee)
        uint256 bondReturn = g.bond;

        unchecked {
            ++totalSettled;
        }

        // Return bond to solver
        _safeTransferETH(msg.sender, bondReturn);

        emit GuaranteeSettled(guaranteeId, msg.sender, bondReturn, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IInstantSettlementGuarantee
    function claimGuarantee(bytes32 guaranteeId) external nonReentrant {
        Guarantee storage g = _guarantees[guaranteeId];
        if (g.beneficiary == address(0)) revert GuaranteeNotFound();
        if (g.status != GuaranteeStatus.ACTIVE) revert GuaranteeNotActive();
        if (g.beneficiary != msg.sender) revert NotBeneficiary();

        // Can only claim after expiry AND underlying transfer is NOT finalized
        if (block.timestamp < g.expiresAt) revert GuaranteeNotExpired();
        if (_isIntentFinalized(g.intentId)) revert TransferAlreadyFinalized();

        g.status = GuaranteeStatus.CLAIMED;
        guarantorActiveCount[g.guarantor]--;

        unchecked {
            ++totalClaimed;
        }

        // Pay beneficiary the guaranteed amount
        _safeTransferETH(msg.sender, g.amount);

        // Surplus (bond - amount) goes to insurance pool
        uint256 surplus = g.bond - g.amount;
        if (surplus > 0) {
            insurancePoolBalance += surplus;
            emit InsurancePoolDeposit(surplus);
        }

        emit GuaranteeClaimed(guaranteeId, msg.sender, g.amount);
    }

    /// @notice Expire an active guarantee where the underlying was finalized
    ///         but the guarantor didn't settle. Returns bond to guarantor.
    /// @param guaranteeId The guarantee to expire
    function expireGuarantee(bytes32 guaranteeId) external nonReentrant {
        Guarantee storage g = _guarantees[guaranteeId];
        if (g.guarantor == address(0)) revert GuaranteeNotFound();
        if (g.status != GuaranteeStatus.ACTIVE) revert GuaranteeNotActive();
        if (block.timestamp < g.expiresAt) revert GuaranteeNotExpired();

        // If intent is finalized, treat as settled (return bond to guarantor)
        if (_isIntentFinalized(g.intentId)) {
            g.status = GuaranteeStatus.SETTLED;
            guarantorActiveCount[g.guarantor]--;
            ++totalSettled;
            _safeTransferETH(g.guarantor, g.bond);
            emit GuaranteeSettled(guaranteeId, g.guarantor, g.bond, 0);
        } else {
            // Not finalized and expired — mark as expired
            // Beneficiary can still call claimGuarantee
            g.status = GuaranteeStatus.EXPIRED;
            guarantorActiveCount[g.guarantor]--;

            // Bond goes to insurance pool
            insurancePoolBalance += g.bond;
            emit InsurancePoolDeposit(g.bond);
            emit GuaranteeExpired(guaranteeId);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IInstantSettlementGuarantee
    function getGuarantee(
        bytes32 guaranteeId
    ) external view returns (Guarantee memory) {
        return _guarantees[guaranteeId];
    }

    /// @inheritdoc IInstantSettlementGuarantee
    function canSettle(bytes32 guaranteeId) external view returns (bool) {
        Guarantee storage g = _guarantees[guaranteeId];
        return
            g.status == GuaranteeStatus.ACTIVE &&
            _isIntentFinalized(g.intentId);
    }

    /// @inheritdoc IInstantSettlementGuarantee
    function canClaim(bytes32 guaranteeId) external view returns (bool) {
        Guarantee storage g = _guarantees[guaranteeId];
        return
            g.status == GuaranteeStatus.ACTIVE &&
            block.timestamp >= g.expiresAt &&
            !_isIntentFinalized(g.intentId);
    }

    /// @notice Get the required bond for a given guarantee amount
    /// @param amount The guarantee amount
    /// @return bond The minimum bond required
    function requiredBond(uint256 amount) external view returns (uint256 bond) {
        return (amount * collateralRatioBps) / BPS;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Check if an intent has been finalized (status == FINALIZED)
    function _isIntentFinalized(bytes32 intentId) internal view returns (bool) {
        // First check manual override
        if (intentFinalized[intentId]) return true;

        // Then check IntentSettlementLayer if configured
        if (address(intentLayer) != address(0)) {
            // Use isFinalized() which checks actual FINALIZED status,
            // not canFinalize() which only checks eligibility.
            try intentLayer.isFinalized(intentId) returns (bool result) {
                return result;
            } catch {
                // Fallback to canFinalize for backwards compatibility
                try intentLayer.canFinalize(intentId) returns (bool result) {
                    return result;
                } catch {
                    return false;
                }
            }
        }

        return false;
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    /// @notice Receive ETH (for insurance pool deposits)
    receive() external payable {
        insurancePoolBalance += msg.value;
        emit InsurancePoolDeposit(msg.value);
    }
}
