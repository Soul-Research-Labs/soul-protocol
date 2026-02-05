// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../fhe/FHETypes.sol";

/**
 * @title IEncryptedERC20
 * @author Soul Protocol
 * @notice Interface for the Encrypted ERC20 token contract with FHE-based privacy
 * @dev Uses user-defined value types (euint256 is bytes32) for encrypted values
 */
interface IEncryptedERC20 {
    // ============================================
    // EVENTS
    // ============================================

    event EncryptedTransfer(
        address indexed from,
        address indexed to,
        bytes32 encryptedAmountHandle,
        uint256 indexed nonce
    );

    event EncryptedApproval(
        address indexed owner,
        address indexed spender,
        bytes32 encryptedAmountHandle
    );

    event EncryptedMint(address indexed to, bytes32 encryptedAmountHandle);

    event EncryptedBurn(address indexed from, bytes32 encryptedAmountHandle);

    event BalanceViewerAdded(address indexed account, address indexed viewer);

    event BalanceViewerRemoved(address indexed account, address indexed viewer);

    event BalanceDecrypted(
        address indexed account,
        uint256 balance,
        address indexed viewer
    );

    // ============================================
    // ERRORS
    // ============================================

    error InsufficientBalance();
    error InsufficientAllowance();
    error InvalidAmount();
    error TransferBelowMinimum();
    error TransferAboveMaximum();
    error UnauthorizedViewer();
    error ZeroAddress();

    // ============================================
    // TOKEN METADATA
    // ============================================

    /**
     * @notice Get token name
     */
    function name() external view returns (string memory);

    /**
     * @notice Get token symbol
     */
    function symbol() external view returns (string memory);

    /**
     * @notice Get token decimals
     */
    function decimals() external view returns (uint8);

    /**
     * @notice Get encrypted total supply
     * @return handle The encrypted total supply handle
     */
    function totalSupply() external view returns (euint256 handle);

    // ============================================
    // BALANCE QUERIES
    // ============================================

    /**
     * @notice Get encrypted balance for an account
     * @param account The account address
     * @return handle The encrypted balance handle
     */
    function balanceOf(address account) external view returns (euint256 handle);

    /**
     * @notice Request decryption of own balance
     * @return requestId The decryption request ID
     */
    function requestBalanceDecryption() external returns (bytes32 requestId);

    // ============================================
    // ENCRYPTED TRANSFERS
    // ============================================

    /**
     * @notice Transfer encrypted amount to recipient
     * @param to Recipient address
     * @param encryptedAmount Encrypted transfer amount
     * @return success Whether transfer was initiated
     */
    function transferEncrypted(
        address to,
        euint256 encryptedAmount
    ) external returns (bool success);

    /**
     * @notice Transfer from encrypted allowance
     * @param from Sender address
     * @param to Recipient address
     * @param encryptedAmount Encrypted transfer amount
     * @return success Whether transfer was initiated
     */
    function transferFromEncrypted(
        address from,
        address to,
        euint256 encryptedAmount
    ) external returns (bool success);

    // ============================================
    // ENCRYPTED APPROVALS
    // ============================================

    /**
     * @notice Approve encrypted spending allowance
     * @param spender Spender address
     * @param encryptedAmount Encrypted allowance amount
     * @return success Whether approval was set
     */
    function approveEncrypted(
        address spender,
        euint256 encryptedAmount
    ) external returns (bool success);

    /**
     * @notice Get encrypted allowance
     * @param owner Token owner
     * @param spender Approved spender
     * @return handle The encrypted allowance handle
     */
    function allowance(
        address owner,
        address spender
    ) external view returns (euint256 handle);

    // ============================================
    // MINTING AND BURNING
    // ============================================

    /**
     * @notice Mint encrypted tokens
     * @param to Recipient address
     * @param amount Plaintext amount to mint
     */
    function mint(address to, uint256 amount) external;

    /**
     * @notice Burn encrypted tokens
     * @param from Address to burn from
     * @param encryptedAmount Encrypted amount to burn
     */
    function burnEncrypted(address from, euint256 encryptedAmount) external;

    // ============================================
    // BALANCE VIEWING
    // ============================================

    /**
     * @notice Add a balance viewer
     * @param viewer The viewer address
     */
    function addBalanceViewer(address viewer) external;

    /**
     * @notice Remove a balance viewer
     * @param viewer The viewer address
     */
    function removeBalanceViewer(address viewer) external;

    /**
     * @notice Request decryption of someone's balance (if authorized)
     * @param account The account to view
     * @return requestId The decryption request ID
     */
    function requestBalanceView(
        address account
    ) external returns (bytes32 requestId);

    // ============================================
    // ADMIN
    // ============================================

    /**
     * @notice Set transfer limits
     * @param min Minimum transfer amount
     * @param max Maximum transfer amount
     */
    function setTransferLimits(uint256 min, uint256 max) external;

    /**
     * @notice Pause the token
     */
    function pause() external;

    /**
     * @notice Unpause the token
     */
    function unpause() external;
}
