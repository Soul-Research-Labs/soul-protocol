// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IInstantSettlementGuarantee
 * @author Soul Protocol
 * @notice Interface for bonded proof delivery guarantees
 * @dev Guarantors bond ETH to guarantee that a ZK proof will be verified on the
 *      destination chain within a time window. Soul is proof middleware — the guarantee
 *      covers proof delivery, not token delivery. If proof delivery fails, the beneficiary
 *      claims compensation from the bond.
 */
interface IInstantSettlementGuarantee {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice State of a guarantee
    enum GuaranteeStatus {
        ACTIVE, // Bond posted, user has instant access
        SETTLED, // Underlying transfer finalized, bond returned
        CLAIMED, // Transfer failed, user claimed from bond
        EXPIRED, // Guarantee expired without resolution
        CANCELLED // Cancelled before activation
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A bonded proof delivery guarantee
    struct Guarantee {
        bytes32 intentId; // Linked intent
        address guarantor; // Solver providing the guarantee
        address beneficiary; // User receiving proof delivery guarantee
        uint256 amount; // Compensation amount if proof delivery fails
        uint256 bond; // Posted collateral (>= amount * collateralRatio / 10000)
        uint48 createdAt;
        uint48 expiresAt; // Absolute expiry
        GuaranteeStatus status;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event GuaranteeCreated(
        bytes32 indexed guaranteeId,
        bytes32 indexed intentId,
        address indexed guarantor,
        address beneficiary,
        uint256 amount,
        uint256 bond
    );

    event GuaranteeSettled(
        bytes32 indexed guaranteeId,
        address indexed guarantor,
        uint256 bondReturned,
        uint256 fee
    );

    event GuaranteeClaimed(
        bytes32 indexed guaranteeId,
        address indexed beneficiary,
        uint256 amountPaid
    );

    event GuaranteeExpired(bytes32 indexed guaranteeId);

    event CollateralRatioUpdated(uint256 oldRatio, uint256 newRatio);

    event InsurancePoolDeposit(uint256 amount);

    event IntentLayerUpdated(
        address indexed oldIntentLayer,
        address indexed newIntentLayer
    );
    event IntentFinalized(bytes32 indexed intentId);
    event InsuranceWithdrawn(
        address indexed to,
        uint256 amount,
        uint256 remainingBalance
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidAmount();
    error InsufficientBond();
    error GuaranteeNotFound();
    error GuaranteeNotActive();
    error GuaranteeNotExpired();
    error NotGuarantor();
    error NotBeneficiary();
    error TransferNotFinalized();
    error TransferAlreadyFinalized();
    error IntentNotLinked();
    error InvalidCollateralRatio();
    error InvalidDuration();

    /*//////////////////////////////////////////////////////////////
                          SOLVER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Post a guarantee for instant settlement
    /// @param intentId The intent this guarantee backs
    /// @param beneficiary The user receiving instant settlement
    /// @param amount The guaranteed settlement amount
    /// @param duration How long the guarantee is valid
    /// @return guaranteeId The unique guarantee identifier
    function postGuarantee(
        bytes32 intentId,
        address beneficiary,
        uint256 amount,
        uint256 duration
    ) external payable returns (bytes32 guaranteeId);

    /// @notice Settle a guarantee after underlying transfer finalizes
    /// @param guaranteeId The guarantee to settle
    function settleGuarantee(bytes32 guaranteeId) external;

    /*//////////////////////////////////////////////////////////////
                           USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Claim from a guarantee if transfer failed and guarantee expired
    /// @param guaranteeId The guarantee to claim from
    function claimGuarantee(bytes32 guaranteeId) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get guarantee details
    function getGuarantee(
        bytes32 guaranteeId
    ) external view returns (Guarantee memory);

    /// @notice Check if a guarantee can be settled (underlying transfer finalized)
    function canSettle(bytes32 guaranteeId) external view returns (bool);

    /// @notice Check if a guarantee can be claimed by beneficiary
    function canClaim(bytes32 guaranteeId) external view returns (bool);

    /// @notice Get the current collateral ratio in basis points
    function collateralRatioBps() external view returns (uint256);

    /// @notice Get the insurance pool balance
    function insurancePoolBalance() external view returns (uint256);
}
