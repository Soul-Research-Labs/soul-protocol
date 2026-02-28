// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPrivacyRouter
 * @author ZASEON
 * @notice Interface for the unified privacy middleware entry point
 * @dev This is the primary integration surface for dApps using ZASEON
 */
interface IPrivacyRouter {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum OperationType {
        DEPOSIT,
        WITHDRAW,
        CROSS_CHAIN_TRANSFER,
        STEALTH_PAYMENT,
        PROOF_TRANSLATION
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct WithdrawParams {
        bytes proof;
        bytes32 merkleRoot;
        bytes32 nullifier;
        address recipient;
        address relayerAddress;
        uint256 amount;
        uint256 relayerFee;
        bytes32 assetId;
        bytes32 destChainId;
    }

    struct CrossChainTransferParams {
        uint256 destChainId;
        bytes32 recipientStealth;
        uint256 amount;
        uint8 privacyLevel;
        uint8 proofSystem;
        bytes proof;
        bytes32[] publicInputs;
        bytes32 proofHash;
    }

    struct OperationReceipt {
        bytes32 operationId;
        OperationType opType;
        uint256 timestamp;
        bytes32 commitmentOrNullifier;
        bool success;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrivateDeposit(
        bytes32 indexed operationId,
        bytes32 indexed commitment,
        bytes32 assetId,
        uint256 amount
    );

    event PrivateWithdrawal(
        bytes32 indexed operationId,
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount
    );

    event CrossChainTransferInitiated(
        bytes32 indexed operationId,
        uint256 indexed destChainId,
        bytes32 recipientStealth,
        uint256 amount
    );

    event StealthPaymentSent(
        bytes32 indexed operationId,
        address indexed stealthAddress,
        uint256 amount
    );

    event ComponentUpdated(string name, address newAddress);
    event ComplianceToggled(bool enabled);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ComponentNotSet(string name);
    error ComplianceCheckFailed(address user);
    error SanctionedAddress(address user);
    error InsufficientKYCTier(address user, uint8 required, uint8 actual);
    error ZeroAddress();
    error ZeroAmount();
    error OperationFailed(string reason);
    error InvalidParams();

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function depositETH(
        bytes32 commitment
    ) external payable returns (bytes32 operationId);

    function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external returns (bytes32 operationId);

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function withdraw(
        WithdrawParams calldata params
    ) external returns (bytes32 operationId);

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function initiatePrivateTransfer(
        CrossChainTransferParams calldata params
    ) external payable returns (bytes32 operationId);

    /*//////////////////////////////////////////////////////////////
                    STEALTH ADDRESS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerStealthMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        uint8 curveType,
        uint256 schemeId
    ) external;

    function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag);

    /*//////////////////////////////////////////////////////////////
                           QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isNullifierSpent(bytes32 nullifier) external view returns (bool);

    function checkCompliance(address user) external view returns (bool passes);

    function getOperationCount(
        OperationType opType
    ) external view returns (uint256);

    function getReceipt(
        bytes32 operationId
    ) external view returns (OperationReceipt memory);

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setComponent(string calldata name, address addr) external;

    function setComplianceEnabled(bool enabled) external;

    function setMinimumKYCTier(uint8 tier) external;

    function pause() external;

    function unpause() external;
}
