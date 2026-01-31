// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHEGateway.sol";
import "./FHETypes.sol";
import "./FHEOperations.sol";

/**
 * @title EncryptedERC20
 * @author Soul Protocol
 * @notice Confidential ERC20 token with encrypted balances using FHE
 * @dev Implements ERC20-like interface with fully homomorphic encryption
 *
 * Features:
 * - Encrypted balances (no one can see your balance)
 * - Encrypted transfers (amount is hidden)
 * - Encrypted allowances (approval amounts are hidden)
 * - Compliance integration (range proofs for regulatory requirements)
 * - Decryption capability for authorized parties
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    Encrypted ERC20 Architecture                      │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌─────────────────────┐    ┌─────────────────────┐                │
 * │  │    User A           │    │    User B           │                │
 * │  │ balance: enc(100)   │───►│ balance: enc(50)    │                │
 * │  │                     │    │                     │                │
 * │  └─────────────────────┘    └─────────────────────┘                │
 * │            │                          │                            │
 * │            │    encrypted transfer    │                            │
 * │            └──────────────────────────┘                            │
 * │                       │                                            │
 * │              ┌────────▼────────┐                                   │
 * │              │   FHE Gateway   │                                   │
 * │              │ (homomorphic    │                                   │
 * │              │  arithmetic)    │                                   │
 * │              └─────────────────┘                                   │
 * └─────────────────────────────────────────────────────────────────────┘
 */
contract EncryptedERC20 is AccessControl, ReentrancyGuard, Pausable {
    using FHEOperations for uint256;
    using FHEOperations for euint256;

    // ============================================
    // Roles
    // ============================================

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");

    // ============================================
    // Token Metadata
    // ============================================

    string public name;
    string public symbol;
    uint8 public immutable decimals;

    // ============================================
    // State Variables
    // ============================================

    /// @notice FHE Gateway
    FHEGateway public immutable fheGateway;

    /// @notice Encrypted total supply handle
    euint256 public encryptedTotalSupply;

    /// @notice Encrypted balances: address => encrypted balance handle
    mapping(address => euint256) public encryptedBalances;

    /// @notice Encrypted allowances: owner => spender => encrypted allowance handle
    mapping(address => mapping(address => euint256)) public encryptedAllowances;

    /// @notice Decryption requests: requestId => bool
    mapping(bytes32 => bool) public pendingDecryptions;

    /// @notice Balance visibility grants: owner => viewer => allowed
    mapping(address => mapping(address => bool)) public balanceViewers;

    /// @notice Compliance range proof requests
    mapping(bytes32 => ComplianceRequest) public complianceRequests;

    /// @notice Nonce for transfers (replay protection)
    mapping(address => uint256) public transferNonces;


    // ============================================
    // Types
    // ============================================

    /// @notice Compliance range proof request
    struct ComplianceRequest {
        bytes32 requestId;
        address account;
        uint256 minAmount;
        uint256 maxAmount;
        address requester;
        uint64 deadline;
        bool completed;
        bool inRange;
    }

    /// @notice Transfer receipt (for off-chain tracking)
    struct TransferReceipt {
        bytes32 receiptId;
        address from;
        address to;
        euint256 encryptedAmount;
        uint64 timestamp;
        uint256 nonce;
    }

    // ============================================
    // Events
    // ============================================

    event EncryptedTransfer(
        address indexed from,
        address indexed to,
        euint256 encryptedAmount,
        bytes32 receiptId
    );

    event EncryptedApproval(
        address indexed owner,
        address indexed spender,
        euint256 encryptedAllowance
    );

    event EncryptedMint(address indexed to, euint256 encryptedAmount);

    event EncryptedBurn(address indexed from, euint256 encryptedAmount);

    event BalanceDecryptionRequested(
        bytes32 indexed requestId,
        address indexed account,
        address requester
    );

    event BalanceDecrypted(
        bytes32 indexed requestId,
        address indexed account,
        uint256 balance
    );

    event ComplianceCheckRequested(
        bytes32 indexed requestId,
        address indexed account,
        uint256 minAmount,
        uint256 maxAmount
    );

    event ComplianceCheckCompleted(
        bytes32 indexed requestId,
        address indexed account,
        bool inRange
    );

    event ViewerGranted(address indexed owner, address indexed viewer);

    event ViewerRevoked(address indexed owner, address indexed viewer);

    // ============================================
    // Errors
    // ============================================

    error InvalidGateway();
    error InsufficientBalance();
    error InsufficientAllowance();
    error InvalidRecipient();
    error InvalidAmount();
    error TransferFailed();
    error UnauthorizedViewer();
    error RequestNotFound();
    error RequestExpired();
    error AlreadyCompleted();

    // ============================================
    // Constructor
    // ============================================

    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        address _fheGateway
    ) {
        if (_fheGateway == address(0)) revert InvalidGateway();

        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        fheGateway = FHEGateway(_fheGateway);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(BURNER_ROLE, msg.sender);
        _grantRole(COMPLIANCE_ROLE, msg.sender);

        // Initialize encrypted total supply to 0
        encryptedTotalSupply = FHEOperations.asEuint256(0);
    }


    // ============================================
    // ERC20-like Interface (Encrypted)
    // ============================================

    /**
     * @notice Get encrypted balance of account
     * @param account The account address
     * @return handle The encrypted balance handle
     */
    function balanceOf(address account) external view returns (euint256 handle) {
        return encryptedBalances[account];
    }

    /**
     * @notice Get encrypted allowance
     * @param owner Token owner
     * @param spender Spender address
     * @return handle The encrypted allowance handle
     */
    function allowance(
        address owner,
        address spender
    ) external view returns (euint256 handle) {
        return encryptedAllowances[owner][spender];
    }

    /**
     * @notice Get encrypted total supply
     * @return handle The encrypted total supply handle
     */
    function totalSupply() external view returns (euint256 handle) {
        return encryptedTotalSupply;
    }

    // ============================================
    // Encrypted Transfers
    // ============================================

    /**
     * @notice Transfer encrypted amount to recipient
     * @param to Recipient address
     * @param encryptedAmount Encrypted amount handle
     * @return success Whether transfer was initiated
     */
    function transfer(
        address to,
        euint256 encryptedAmount
    ) external whenNotPaused nonReentrant returns (bool success) {
        return _transfer(msg.sender, to, encryptedAmount);
    }

    /**
     * @notice Transfer with plaintext amount (encrypts automatically)
     * @param to Recipient address
     * @param amount Plaintext amount (will be encrypted)
     */
    function transferPlain(
        address to,
        uint256 amount
    ) external whenNotPaused nonReentrant returns (bool success) {
        // Encrypt the amount
        euint256 encAmount = amount.asEuint256();
        return _transfer(msg.sender, to, encAmount);
    }

    /**
     * @notice Transfer from (with allowance)
     * @param from Sender address
     * @param to Recipient address
     * @param encryptedAmount Encrypted amount handle
     */
    function transferFrom(
        address from,
        address to,
        euint256 encryptedAmount
    ) external whenNotPaused nonReentrant returns (bool success) {
        // Check and update allowance
        euint256 currentAllowance = encryptedAllowances[from][msg.sender];
        if (euint256.unwrap(currentAllowance) == bytes32(0)) revert InsufficientAllowance();

        // Subtract from allowance (FHE subtraction)
        euint256 newAllowance = currentAllowance.sub(encryptedAmount);
        encryptedAllowances[from][msg.sender] = newAllowance;

        return _transfer(from, to, encryptedAmount);
    }

    /**
     * @notice Internal transfer logic
     */
    function _transfer(
        address from,
        address to,
        euint256 encryptedAmount
    ) internal returns (bool) {
        if (to == address(0)) revert InvalidRecipient();
        if (euint256.unwrap(encryptedAmount) == bytes32(0)) revert InvalidAmount();

        euint256 fromBalance = encryptedBalances[from];
        if (euint256.unwrap(fromBalance) == bytes32(0)) revert InsufficientBalance();

        // 1. Check sufficiency (encrypted)
        ebool isSufficient = fromBalance.ge(encryptedAmount);

        // 2. Conditionally subtract from sender
        euint256 newFromBalance = FHEOperations.select(
            isSufficient,
            fromBalance.sub(encryptedAmount),
            fromBalance
        );
        encryptedBalances[from] = newFromBalance;

        // 3. Conditionally add to recipient
        euint256 toBalance = encryptedBalances[to];
        euint256 newToBalance;
        
        if (euint256.unwrap(toBalance) == bytes32(0)) {
            newToBalance = FHEOperations.select(
                isSufficient,
                encryptedAmount,
                FHEOperations.asEuint256(0)
            );
        } else {
            newToBalance = FHEOperations.select(
                isSufficient,
                toBalance.add(encryptedAmount),
                toBalance
            );
        }
        encryptedBalances[to] = newToBalance;

        // Generate receipt
        transferNonces[from]++;
        bytes32 receiptId = keccak256(
            abi.encode(
                from,
                to,
                encryptedAmount,
                transferNonces[from],
                block.timestamp
            )
        );

        emit EncryptedTransfer(from, to, encryptedAmount, receiptId);

        return true;
    }


    /**
     * @notice Get encrypted allowance
     * @param owner Token owner
     * @param spender Spender address
     * @return handle The encrypted allowance handle
     */


    // ============================================
    // Encrypted Approvals
    // ============================================

    /**
     * @notice Approve spender for encrypted amount
     * @param spender Spender address
     * @param encryptedAmount Encrypted allowance
     */
    function approve(
        address spender,
        euint256 encryptedAmount
    ) external whenNotPaused returns (bool) {
        encryptedAllowances[msg.sender][spender] = encryptedAmount;

        emit EncryptedApproval(msg.sender, spender, encryptedAmount);

        return true;
    }

    /**
     * @notice Approve with plaintext amount
     * @param spender Spender address
     * @param amount Plaintext amount (will be encrypted)
     */
    function approvePlain(
        address spender,
        uint256 amount
    ) external whenNotPaused returns (bool) {
        euint256 encAmount = amount.asEuint256();
        encryptedAllowances[msg.sender][spender] = encAmount;

        emit EncryptedApproval(msg.sender, spender, encAmount);

        return true;
    }

    /**
     * @notice Increase allowance
     * @param spender Spender address
     * @param addedValue Encrypted additional allowance
     */
    function increaseAllowance(
        address spender,
        euint256 addedValue
    ) external whenNotPaused returns (bool) {
        euint256 current = encryptedAllowances[msg.sender][spender];
        euint256 newAllowance;

        if (euint256.unwrap(current) == bytes32(0)) {
            newAllowance = addedValue;
        } else {
            newAllowance = current.add(addedValue);
        }

        encryptedAllowances[msg.sender][spender] = newAllowance;

        emit EncryptedApproval(msg.sender, spender, newAllowance);

        return true;
    }

    /**
     * @notice Decrease allowance
     * @param spender Spender address
     * @param subtractedValue Encrypted value to subtract
     */
    function decreaseAllowance(
        address spender,
        euint256 subtractedValue
    ) external whenNotPaused returns (bool) {
        euint256 current = encryptedAllowances[msg.sender][spender];
        if (euint256.unwrap(current) == bytes32(0)) revert InsufficientAllowance();

        euint256 newAllowance = current.sub(subtractedValue);
        encryptedAllowances[msg.sender][spender] = newAllowance;

        emit EncryptedApproval(msg.sender, spender, newAllowance);

        return true;
    }

    // ============================================
    // Minting & Burning
    // ============================================

    /**
     * @notice Mint encrypted tokens
     * @param to Recipient address
     * @param encryptedAmount Encrypted amount to mint
     */
    function mint(
        address to,
        euint256 encryptedAmount
    ) external onlyRole(MINTER_ROLE) whenNotPaused {
        if (to == address(0)) revert InvalidRecipient();

        // Update total supply
        bool supplyExists = euint256.unwrap(encryptedTotalSupply) != bytes32(0);
        if (!supplyExists) {
             encryptedTotalSupply = encryptedAmount;
        } else {
             encryptedTotalSupply = encryptedTotalSupply.add(encryptedAmount);
        }

        // Update balance
        euint256 currentBalance = encryptedBalances[to];
        if (euint256.unwrap(currentBalance) == bytes32(0)) {
            encryptedBalances[to] = encryptedAmount;
        } else {
            encryptedBalances[to] = currentBalance.add(encryptedAmount);
        }

        emit EncryptedMint(to, encryptedAmount);
    }

    /**
     * @notice Mint with plaintext amount
     * @param to Recipient address
     * @param amount Plaintext amount to mint
     */
    function mintPlain(
        address to,
        uint256 amount
    ) external onlyRole(MINTER_ROLE) whenNotPaused {
        if (to == address(0)) revert InvalidRecipient();

        euint256 encAmount = amount.asEuint256();

        // Update total supply
        bool supplyExists = euint256.unwrap(encryptedTotalSupply) != bytes32(0);
        if (!supplyExists) {
             encryptedTotalSupply = encAmount;
        } else {
             encryptedTotalSupply = encryptedTotalSupply.add(encAmount);
        }

        euint256 currentBalance = encryptedBalances[to];
        if (euint256.unwrap(currentBalance) == bytes32(0)) {
            encryptedBalances[to] = encAmount;
        } else {
            encryptedBalances[to] = currentBalance.add(encAmount);
        }

        emit EncryptedMint(to, encAmount);
    }

    /**
     * @notice Burn encrypted tokens
     * @param from Address to burn from
     * @param encryptedAmount Encrypted amount to burn
     */
    function burn(
        address from,
        euint256 encryptedAmount
    ) external onlyRole(BURNER_ROLE) whenNotPaused {
        if (euint256.unwrap(encryptedAmount) == bytes32(0)) revert InvalidAmount();

        euint256 currentBalance = encryptedBalances[from];
        if (euint256.unwrap(currentBalance) == bytes32(0)) revert InsufficientBalance();

        // Check sufficiency (encrypted)
        ebool isSufficient = currentBalance.ge(encryptedAmount);

        // Update balance conditionally
        encryptedBalances[from] = FHEOperations.select(
            isSufficient,
            currentBalance.sub(encryptedAmount),
            currentBalance
        );

        // Update total supply conditionally
        encryptedTotalSupply = FHEOperations.select(
            isSufficient,
            encryptedTotalSupply.sub(encryptedAmount),
            encryptedTotalSupply
        );

        emit EncryptedBurn(from, encryptedAmount);
    }

    // ============================================
    // Balance Viewing (Authorized Decryption)
    // ============================================

    /**
     * @notice Grant balance viewing permission
     * @param viewer Address to grant viewing access
     */
    function grantViewer(address viewer) external {
        balanceViewers[msg.sender][viewer] = true;
        emit ViewerGranted(msg.sender, viewer);
    }

    /**
     * @notice Revoke balance viewing permission
     * @param viewer Address to revoke viewing access
     */
    function revokeViewer(address viewer) external {
        balanceViewers[msg.sender][viewer] = false;
        emit ViewerRevoked(msg.sender, viewer);
    }

    /**
     * @notice Request balance decryption
     * @param account Account to decrypt balance for
     * @param callbackContract Contract to call with result
     * @param callbackSelector Function selector for callback
     */
    function requestBalanceDecryption(
        address account,
        address callbackContract,
        bytes4 callbackSelector
    ) external returns (bytes32 requestId) {
        // Must be owner or authorized viewer
        if (msg.sender != account && !balanceViewers[account][msg.sender]) {
            revert UnauthorizedViewer();
        }

        euint256 balance = encryptedBalances[account];
        if (euint256.unwrap(balance) == bytes32(0)) revert InsufficientBalance();

        // Request decryption through gateway
        requestId = fheGateway.requestDecryption(
            euint256.unwrap(balance),
            callbackContract,
            callbackSelector,
            3600 // 1 hour TTL
        );

        pendingDecryptions[requestId] = true;

        emit BalanceDecryptionRequested(requestId, account, msg.sender);
    }

    // ============================================
    // Compliance Functions
    // ============================================

    /**
     * @notice Request compliance range check
     * @dev Checks if balance is within [minAmount, maxAmount] without revealing actual balance
     * @param account Account to check
     * @param minAmount Minimum required balance
     * @param maxAmount Maximum allowed balance
     */
    function requestComplianceCheck(
        address account,
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(COMPLIANCE_ROLE) returns (bytes32 requestId) {
        euint256 balance = encryptedBalances[account];
        if (euint256.unwrap(balance) == bytes32(0)) revert InsufficientBalance();

        requestId = keccak256(
            abi.encode(
                account,
                minAmount,
                maxAmount,
                block.timestamp,
                msg.sender
            )
        );

        complianceRequests[requestId] = ComplianceRequest({
            requestId: requestId,
            account: account,
            minAmount: minAmount,
            maxAmount: maxAmount,
            requester: msg.sender,
            deadline: uint64(block.timestamp + 3600),
            completed: false,
            inRange: false
        });

        // Optimisation: Removed unused FHE operations comparison that were ignored.
        // The compliance check is completed by the off-chain oracle.

        emit ComplianceCheckRequested(requestId, account, minAmount, maxAmount);
    }

    /**
     * @notice Complete compliance check (called by oracle callback)
     */
    function completeComplianceCheck(
        bytes32 requestId,
        bool inRange
    ) external onlyRole(COMPLIANCE_ROLE) {
        ComplianceRequest storage req = complianceRequests[requestId];

        if (req.requestId == bytes32(0)) revert RequestNotFound();
        if (block.timestamp > req.deadline) revert RequestExpired();
        if (req.completed) revert AlreadyCompleted();

        req.completed = true;
        req.inRange = inRange;

        emit ComplianceCheckCompleted(requestId, req.account, inRange);
    }

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Pause token transfers
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause token transfers
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Check if address has balance
     */
    function hasBalance(address account) external view returns (bool) {
        return euint256.unwrap(encryptedBalances[account]) != bytes32(0);
    }

    /**
     * @notice Check if viewer is authorized
     */
    function isAuthorizedViewer(
        address owner,
        address viewer
    ) external view returns (bool) {
        return owner == viewer || balanceViewers[owner][viewer];
    }

    /**
     * @notice Get compliance request info
     */
    function getComplianceRequest(
        bytes32 requestId
    ) external view returns (ComplianceRequest memory) {
        return complianceRequests[requestId];
    }
}


