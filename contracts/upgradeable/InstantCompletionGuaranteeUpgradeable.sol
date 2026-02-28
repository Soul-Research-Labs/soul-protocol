// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IInstantCompletionGuarantee} from "../interfaces/IInstantCompletionGuarantee.sol";
import {IIntentCompletionLayer} from "../interfaces/IIntentCompletionLayer.sol";

/**
 * @title InstantCompletionGuaranteeUpgradeable
 * @author ZASEON
 * @notice UUPS-upgradeable version of InstantCompletionGuarantee for proxy deployments
 * @dev Bonded guarantees for ZK proof delivery. See InstantCompletionGuarantee for full docs.
 *
 * UPGRADE NOTES:
 * - Constructor replaced with `initialize(address admin, address _intentLayer)`
 * - All OZ base contracts replaced with upgradeable variants
 * - UUPS upgrade restricted to UPGRADER_ROLE
 * - Storage gap (`__gap[50]`) reserved for future upgrades
 *
 * @custom:oz-upgrades-from InstantCompletionGuarantee
 */
contract InstantCompletionGuaranteeUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IInstantCompletionGuarantee
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    bytes32 public constant COMPLETION_ROLE = keccak256("COMPLETION_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MIN_DURATION = 30 minutes;
    uint256 public constant MAX_DURATION = 7 days;
    uint256 public constant SOLVER_FEE_BPS = 50;
    uint256 private constant BPS = 10_000;
    uint256 public constant MIN_GUARANTEE_AMOUNT = 0.001 ether;
    uint256 public constant MAX_ACTIVE_PER_GUARANTOR = 50;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 public collateralRatioBps;
    IIntentCompletionLayer public intentLayer;
    mapping(bytes32 => Guarantee) internal _guarantees;
    uint256 internal _nonce;
    uint256 public insurancePoolBalance;
    uint256 public totalGuarantees;
    uint256 public totalSettled;
    uint256 public totalClaimed;
    mapping(address => uint256) public guarantorActiveCount;
    mapping(address => uint256) public guarantorTotalPosted;
    mapping(bytes32 => bool) public intentFinalized;

    /// @dev Reserved storage for future upgrades
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the upgradeable instant completion guarantee
    /// @param admin Admin address (DEFAULT_ADMIN_ROLE + UPGRADER_ROLE)
    /// @param _intentLayer Address of the IntentCompletionLayer (address(0) to set later)
    /**
     * @notice Initializes the operation
     * @param admin The admin bound
     * @param _intentLayer The _intent layer
     */
    function initialize(
        address admin,
        address _intentLayer
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(COMPLETION_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        collateralRatioBps = 11_000; // 110%

        if (_intentLayer != address(0)) {
            intentLayer = IIntentCompletionLayer(_intentLayer);
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

    /**
     * @notice Sets the intent layer
     * @param _intentLayer The _intent layer
     */
    function setIntentLayer(
        address _intentLayer
    ) external onlyRole(OPERATOR_ROLE) {
        if (_intentLayer == address(0)) revert ZeroAddress();
        address oldIntentLayer = address(intentLayer);
        intentLayer = IIntentCompletionLayer(_intentLayer);
        emit IntentLayerUpdated(oldIntentLayer, _intentLayer);
    }

    /**
     * @notice Sets the collateral ratio
     * @param newRatioBps The new RatioBps value
     */
    function setCollateralRatio(
        uint256 newRatioBps
    ) external onlyRole(OPERATOR_ROLE) {
        if (newRatioBps < BPS) revert InvalidCollateralRatio();
        if (newRatioBps > 30_000) revert InvalidCollateralRatio();
        uint256 oldRatio = collateralRatioBps;
        collateralRatioBps = newRatioBps;
        emit CollateralRatioUpdated(oldRatio, newRatioBps);
    }

    /**
     * @notice Mark intent finalized
     * @param intentId The intentId identifier
     */
    function markIntentFinalized(
        bytes32 intentId
    ) external onlyRole(COMPLETION_ROLE) {
        intentFinalized[intentId] = true;
        emit IntentFinalized(intentId);
    }

    /**
     * @notice Withdraws insurance
     * @param to The destination address
     * @param amount The amount to process
     */
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

    /// @inheritdoc IInstantCompletionGuarantee
    /**
     * @notice Post guarantee
     * @param intentId The intentId identifier
     * @param beneficiary The beneficiary
     * @param amount The amount to process
     * @param duration The duration in seconds
     * @return guaranteeId The guarantee id
     */
    function postGuarantee(
        bytes32 intentId,
        address beneficiary,
        uint256 amount,
        uint256 duration
    ) external payable nonReentrant returns (bytes32 guaranteeId) {
        if (beneficiary == address(0)) revert ZeroAddress();
        if (amount < MIN_GUARANTEE_AMOUNT) revert InvalidAmount();
        if (duration < MIN_DURATION || duration > MAX_DURATION)
            revert InvalidDuration();
        if (intentId == bytes32(0)) revert IntentNotLinked();

        uint256 requiredBondAmt = (amount * collateralRatioBps) / BPS;
        if (msg.value < requiredBondAmt) revert InsufficientBond();

        if (guarantorActiveCount[msg.sender] >= MAX_ACTIVE_PER_GUARANTOR) {
            revert InvalidAmount();
        }

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

    /// @inheritdoc IInstantCompletionGuarantee
    /**
     * @notice Settle guarantee
     * @param guaranteeId The guaranteeId identifier
     */
    function settleGuarantee(bytes32 guaranteeId) external nonReentrant {
        Guarantee storage g = _guarantees[guaranteeId];
        if (g.guarantor == address(0)) revert GuaranteeNotFound();
        if (g.status != GuaranteeStatus.ACTIVE) revert GuaranteeNotActive();
        if (g.guarantor != msg.sender) revert NotGuarantor();
        if (!_isIntentFinalized(g.intentId)) revert TransferNotFinalized();

        g.status = GuaranteeStatus.SETTLED;
        guarantorActiveCount[msg.sender]--;

        uint256 bondReturn = g.bond;

        unchecked {
            ++totalSettled;
        }

        _safeTransferETH(msg.sender, bondReturn);
        emit GuaranteeSettled(guaranteeId, msg.sender, bondReturn, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IInstantCompletionGuarantee
    /**
     * @notice Claims guarantee
     * @param guaranteeId The guaranteeId identifier
     */
    function claimGuarantee(bytes32 guaranteeId) external nonReentrant {
        Guarantee storage g = _guarantees[guaranteeId];
        if (g.beneficiary == address(0)) revert GuaranteeNotFound();
        if (g.status != GuaranteeStatus.ACTIVE) revert GuaranteeNotActive();
        if (g.beneficiary != msg.sender) revert NotBeneficiary();
        if (block.timestamp < g.expiresAt) revert GuaranteeNotExpired();
        if (_isIntentFinalized(g.intentId)) revert TransferAlreadyFinalized();

        g.status = GuaranteeStatus.CLAIMED;
        guarantorActiveCount[g.guarantor]--;

        unchecked {
            ++totalClaimed;
        }

        _safeTransferETH(msg.sender, g.amount);

        uint256 surplus = g.bond - g.amount;
        if (surplus > 0) {
            insurancePoolBalance += surplus;
            emit InsurancePoolDeposit(surplus);
        }

        emit GuaranteeClaimed(guaranteeId, msg.sender, g.amount);
    }

    /**
     * @notice Expire guarantee
     * @param guaranteeId The guaranteeId identifier
     */
    function expireGuarantee(bytes32 guaranteeId) external nonReentrant {
        Guarantee storage g = _guarantees[guaranteeId];
        if (g.guarantor == address(0)) revert GuaranteeNotFound();
        if (g.status != GuaranteeStatus.ACTIVE) revert GuaranteeNotActive();
        if (block.timestamp < g.expiresAt) revert GuaranteeNotExpired();

        if (_isIntentFinalized(g.intentId)) {
            g.status = GuaranteeStatus.SETTLED;
            guarantorActiveCount[g.guarantor]--;
            ++totalSettled;
            _safeTransferETH(g.guarantor, g.bond);
            emit GuaranteeSettled(guaranteeId, g.guarantor, g.bond, 0);
        } else {
            g.status = GuaranteeStatus.EXPIRED;
            guarantorActiveCount[g.guarantor]--;
            insurancePoolBalance += g.bond;
            emit InsurancePoolDeposit(g.bond);
            emit GuaranteeExpired(guaranteeId);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IInstantCompletionGuarantee
    /**
     * @notice Returns the guarantee
     * @param guaranteeId The guaranteeId identifier
     * @return The Guarantee struct for the given guarantee ID
     */
    function getGuarantee(
        bytes32 guaranteeId
    ) external view returns (Guarantee memory) {
        return _guarantees[guaranteeId];
    }

    /// @inheritdoc IInstantCompletionGuarantee
    /**
     * @notice Can settle
     * @param guaranteeId The guaranteeId identifier
     * @return True if the guarantee can be settled (active and intent finalized)
     */
    function canSettle(bytes32 guaranteeId) external view returns (bool) {
        Guarantee storage g = _guarantees[guaranteeId];
        return
            g.status == GuaranteeStatus.ACTIVE &&
            _isIntentFinalized(g.intentId);
    }

    /// @inheritdoc IInstantCompletionGuarantee
    /**
     * @notice Can claim
     * @param guaranteeId The guaranteeId identifier
     * @return True if the guarantee can be claimed (active, expired, and intent not finalized)
     */
    function canClaim(bytes32 guaranteeId) external view returns (bool) {
        Guarantee storage g = _guarantees[guaranteeId];
        return
            g.status == GuaranteeStatus.ACTIVE &&
            block.timestamp >= g.expiresAt &&
            !_isIntentFinalized(g.intentId);
    }

    /**
     * @notice Required bond
     * @param amount The amount to process
     * @return bond The bond
     */
    function requiredBond(uint256 amount) external view returns (uint256 bond) {
        return (amount * collateralRatioBps) / BPS;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _isIntentFinalized(bytes32 intentId) internal view returns (bool) {
        if (intentFinalized[intentId]) return true;

        if (address(intentLayer) != address(0)) {
            try intentLayer.isFinalized(intentId) returns (bool result) {
                return result;
            } catch {
                try intentLayer.canFinalize(intentId) returns (bool result) {
                    return result;
                } catch {
                    return false;
                }
            }
        }

        return false;
    }

    /**
     * @notice _safe transfer e t h
     * @param to The destination address
     * @param amount The amount to process
     */
    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    receive() external payable {
        insurancePoolBalance += msg.value;
        emit InsurancePoolDeposit(msg.value);
    }
}
