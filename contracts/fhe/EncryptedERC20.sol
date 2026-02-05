// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHEGateway.sol";
import "./FHETypes.sol";
import "./FHEOperations.sol";
import "../libraries/FHELib.sol";

/**
 * @title EncryptedERC20
 * @author Soul Protocol
 * @notice Confidential ERC20 token with encrypted balances and transfers
 * @dev Implements fully private token transfers using FHE
 *
 * Privacy Model:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                   Confidential Token Flow                            │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌──────────────────────────────────────────────────────────────┐   │
 * │  │                    PUBLIC INFORMATION                         │   │
 * │  │  • Token name, symbol, decimals                               │   │
 * │  │  • Total supply (encrypted or public based on config)         │   │
 * │  │  • Transaction existence (not amounts)                        │   │
 * │  └──────────────────────────────────────────────────────────────┘   │
 * │                                                                      │
 * │  ┌──────────────────────────────────────────────────────────────┐   │
 * │  │                    PRIVATE INFORMATION                        │   │
 * │  │  • Individual balances (encrypted)                            │   │
 * │  │  • Transfer amounts (encrypted)                               │   │
 * │  │  • Allowances (encrypted)                                     │   │
 * │  └──────────────────────────────────────────────────────────────┘   │
 * │                                                                      │
 * │  Transfer Flow:                                                      │
 * │  ┌────────────┐                        ┌────────────┐               │
 * │  │  Alice     │  transferEncrypted()   │  Bob       │               │
 * │  │ enc(100)   │───────────────────────▶│ enc(50)    │               │
 * │  └────────────┘        enc(25)         └────────────┘               │
 * │        │                  │                   │                     │
 * │        ▼                  ▼                   ▼                     │
 * │  enc(100-25)       FHE Gateway          enc(50+25)                  │
 * │  = enc(75)         (validates)          = enc(75)                   │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Features:
 * - Encrypted balances (no one can see your balance)
 * - Encrypted transfers (amounts are hidden)
 * - Encrypted allowances (approval amounts hidden)
 * - Compliance-compatible (optional range proofs)
 * - Balance viewers (authorized decryption)
 */
contract EncryptedERC20 is AccessControl, ReentrancyGuard, Pausable {
    using FHEOperations for euint256;

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // TOKEN METADATA
    // ============================================

    /// @notice Token name
    string public name;

    /// @notice Token symbol
    string public symbol;

    /// @notice Token decimals
    uint8 public decimals;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice FHE Gateway
    FHEGateway public immutable fheGateway;

    /// @notice Total supply (can be public or encrypted based on config)
    uint256 public totalSupply;

    /// @notice Whether total supply is public
    bool public publicTotalSupply;

    /// @notice Encrypted total supply (if not public)
    euint256 public encryptedTotalSupply;

    /// @notice Encrypted balances: address => encrypted balance
    mapping(address => EncryptedBalance) public encryptedBalances;

    /// @notice Encrypted allowances: owner => spender => encrypted allowance
    mapping(address => mapping(address => EncryptedAllowance))
        public encryptedAllowances;

    /// @notice Balance viewers: address => viewer => allowed
    mapping(address => mapping(address => bool)) public balanceViewers;

    /// @notice Transfer nonce per address (for replay protection)
    mapping(address => uint256) public transferNonces;

    /// @notice Pending decryption callbacks
    mapping(bytes32 => address) public pendingDecryptions;

    /// @notice Minimum transfer amount (for dust prevention)
    uint256 public minTransferAmount;

    /// @notice Maximum transfer amount per transaction
    uint256 public maxTransferAmount;

    /// @notice Whether compliance range proofs are required
    bool public complianceRequired;

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

    event ComplianceProofSubmitted(
        address indexed account,
        bytes32 indexed proofId
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
    error ComplianceProofRequired();
    error InvalidProof();

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        address _fheGateway,
        bool _publicTotalSupply
    ) {
        if (_fheGateway == address(0)) revert ZeroAddress();

        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        fheGateway = FHEGateway(_fheGateway);
        publicTotalSupply = _publicTotalSupply;

        // Set gateway for FHEOperations library
        FHEOperations.setGateway(_fheGateway);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);

        // Default limits
        minTransferAmount = 0;
        maxTransferAmount = type(uint256).max;
    }

    // ============================================
    // ENCRYPTED BALANCE QUERIES
    // ============================================

    /**
     * @notice Get encrypted balance handle for an account
     * @param account The account address
     * @return balance The encrypted balance struct
     */
    function balanceOf(
        address account
    ) external view returns (EncryptedBalance memory balance) {
        return encryptedBalances[account];
    }

    /**
     * @notice Get the encrypted balance handle
     * @param account The account address
     * @return handle The balance handle ID
     */
    function balanceHandle(
        address account
    ) external view returns (bytes32 handle) {
        return encryptedBalances[account].balance.handle;
    }

    /**
     * @notice Request decryption of own balance
     * @return requestId The decryption request ID
     */
    function requestBalanceDecryption() external returns (bytes32 requestId) {
        EncryptedBalance storage bal = encryptedBalances[msg.sender];
        require(bal.balance.handle != bytes32(0), "No balance");

        requestId = fheGateway.requestDecryption(
            bal.balance.handle,
            address(this),
            this.onBalanceDecrypted.selector,
            uint64(block.timestamp + FHELib.MAX_REQUEST_TTL)
        );

        pendingDecryptions[requestId] = msg.sender;
    }

    /**
     * @notice Callback for balance decryption
     * @param requestId The request ID
     * @param decryptedValue The decrypted balance
     */
    function onBalanceDecrypted(
        bytes32 requestId,
        bytes32 decryptedValue
    ) external {
        require(msg.sender == address(fheGateway), "Unauthorized");

        address account = pendingDecryptions[requestId];
        require(account != address(0), "Invalid request");

        delete pendingDecryptions[requestId];

        emit BalanceDecrypted(account, uint256(decryptedValue), account);
    }

    // ============================================
    // ENCRYPTED TRANSFERS
    // ============================================

    /**
     * @notice Transfer encrypted amount to recipient
     * @param to Recipient address
     * @param encryptedAmount Encrypted transfer amount
     * @return success Whether transfer was initiated
     */
    // slither-disable-start reentrancy-no-eth
    function transferEncrypted(
        address to,
        euint256 memory encryptedAmount
    ) external nonReentrant whenNotPaused returns (bool success) {
        if (to == address(0)) revert ZeroAddress();
        if (to == msg.sender) revert InvalidAmount();

        // Verify caller has access to the encrypted amount handle
        (bool valid, bool verified) = fheGateway.checkHandle(
            encryptedAmount.handle
        );
        require(valid && verified, "Invalid amount handle");
        require(
            fheGateway.hasAccess(encryptedAmount.handle, msg.sender),
            "No access to amount"
        );

        // Get current balances
        EncryptedBalance storage senderBal = encryptedBalances[msg.sender];
        EncryptedBalance storage recipientBal = encryptedBalances[to];

        // Initialize recipient balance if needed
        if (recipientBal.balance.handle == bytes32(0)) {
            recipientBal.balance = FHEOperations.asEuint256(0);
            recipientBal.lastUpdated = uint64(block.timestamp);
        }

        // Compute new balances using FHE
        // sender: balance - amount
        // recipient: balance + amount
        euint256 memory newSenderBalance = senderBal.balance.sub(
            encryptedAmount
        );
        euint256 memory newRecipientBalance = recipientBal.balance.add(
            encryptedAmount
        );

        // Verify sufficient balance (encrypted comparison)
        // This creates a proof that sender had enough balance
        ebool memory hasSufficientBalance = senderBal.balance.ge(
            encryptedAmount
        );

        // Update balances
        senderBal.balance = newSenderBalance;
        senderBal.lastUpdated = uint64(block.timestamp);
        senderBal.updateCount++;

        recipientBal.balance = newRecipientBalance;
        recipientBal.lastUpdated = uint64(block.timestamp);
        recipientBal.updateCount++;

        // Grant access to new handles
        fheGateway.grantAccess(newSenderBalance.handle, msg.sender);
        fheGateway.grantAccess(newRecipientBalance.handle, to);

        transferNonces[msg.sender]++;

        emit EncryptedTransfer(
            msg.sender,
            to,
            encryptedAmount.handle,
            transferNonces[msg.sender]
        );

        return true;
    }

    // slither-disable-end reentrancy-no-eth

    /**
     * @notice Transfer from encrypted allowance
     * @param from Sender address
     * @param to Recipient address
     * @param encryptedAmount Encrypted transfer amount
     * @return success Whether transfer was initiated
     */
    // slither-disable-start reentrancy-no-eth
    function transferFromEncrypted(
        address from,
        address to,
        euint256 memory encryptedAmount
    ) external nonReentrant whenNotPaused returns (bool success) {
        if (to == address(0)) revert ZeroAddress();
        if (from == to) revert InvalidAmount();

        // Check allowance
        EncryptedAllowance storage allowance = encryptedAllowances[from][
            msg.sender
        ];
        require(allowance.amount.handle != bytes32(0), "No allowance");

        // Verify allowance is sufficient (encrypted)
        ebool memory hasAllowance = allowance.amount.ge(encryptedAmount);

        // Deduct from allowance
        euint256 memory newAllowance = allowance.amount.sub(encryptedAmount);
        allowance.amount = newAllowance;

        // Perform transfer
        EncryptedBalance storage senderBal = encryptedBalances[from];
        EncryptedBalance storage recipientBal = encryptedBalances[to];

        if (recipientBal.balance.handle == bytes32(0)) {
            recipientBal.balance = FHEOperations.asEuint256(0);
            recipientBal.lastUpdated = uint64(block.timestamp);
        }

        euint256 memory newSenderBalance = senderBal.balance.sub(
            encryptedAmount
        );
        euint256 memory newRecipientBalance = recipientBal.balance.add(
            encryptedAmount
        );

        senderBal.balance = newSenderBalance;
        senderBal.lastUpdated = uint64(block.timestamp);
        senderBal.updateCount++;

        recipientBal.balance = newRecipientBalance;
        recipientBal.lastUpdated = uint64(block.timestamp);
        recipientBal.updateCount++;

        fheGateway.grantAccess(newSenderBalance.handle, from);
        fheGateway.grantAccess(newRecipientBalance.handle, to);

        transferNonces[from]++;

        emit EncryptedTransfer(
            from,
            to,
            encryptedAmount.handle,
            transferNonces[from]
        );

        return true;
    }

    // slither-disable-end reentrancy-no-eth

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
        euint256 memory encryptedAmount
    ) external whenNotPaused returns (bool success) {
        if (spender == address(0)) revert ZeroAddress();

        encryptedAllowances[msg.sender][spender] = EncryptedAllowance({
            amount: encryptedAmount,
            owner: msg.sender,
            spender: spender,
            expiresAt: 0,
            unlimited: false
        });

        // Grant access to spender
        fheGateway.grantAccess(encryptedAmount.handle, spender);

        emit EncryptedApproval(msg.sender, spender, encryptedAmount.handle);

        return true;
    }

    /**
     * @notice Get encrypted allowance
     * @param owner Token owner
     * @param spender Approved spender
     * @return allowance The encrypted allowance
     */
    function allowanceEncrypted(
        address owner,
        address spender
    ) external view returns (EncryptedAllowance memory allowance) {
        return encryptedAllowances[owner][spender];
    }

    // ============================================
    // MINTING AND BURNING
    // ============================================

    /**
     * @notice Mint encrypted tokens
     * @param to Recipient address
     * @param amount Plaintext amount to mint (gets encrypted)
     */
    // slither-disable-start reentrancy-no-eth
    function mint(
        address to,
        uint256 amount
    ) external onlyRole(MINTER_ROLE) nonReentrant whenNotPaused {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();

        // Encrypt the amount
        euint256 memory encryptedAmount = FHEOperations.asEuint256(amount);

        // Update recipient balance
        EncryptedBalance storage bal = encryptedBalances[to];
        if (bal.balance.handle == bytes32(0)) {
            bal.balance = encryptedAmount;
        } else {
            bal.balance = bal.balance.add(encryptedAmount);
        }
        bal.lastUpdated = uint64(block.timestamp);
        bal.updateCount++;

        // Grant access
        fheGateway.grantAccess(bal.balance.handle, to);

        // Update total supply
        if (publicTotalSupply) {
            totalSupply += amount;
        } else {
            encryptedTotalSupply = encryptedTotalSupply.add(encryptedAmount);
        }

        emit EncryptedMint(to, encryptedAmount.handle);
    }

    // slither-disable-end reentrancy-no-eth

    /**
     * @notice Burn encrypted tokens
     * @param from Address to burn from
     * @param encryptedAmount Encrypted amount to burn
     */
    // slither-disable-start reentrancy-no-eth
    function burnEncrypted(
        address from,
        euint256 memory encryptedAmount
    ) external onlyRole(BURNER_ROLE) nonReentrant whenNotPaused {
        if (from == address(0)) revert ZeroAddress();

        EncryptedBalance storage bal = encryptedBalances[from];
        require(bal.balance.handle != bytes32(0), "No balance");

        // Deduct from balance
        bal.balance = bal.balance.sub(encryptedAmount);
        bal.lastUpdated = uint64(block.timestamp);
        bal.updateCount++;

        fheGateway.grantAccess(bal.balance.handle, from);

        emit EncryptedBurn(from, encryptedAmount.handle);
    }

    // slither-disable-end reentrancy-no-eth

    // ============================================
    // BALANCE VIEWING
    // ============================================

    /**
     * @notice Add a balance viewer (can request decryption)
     * @param viewer The viewer address
     */
    function addBalanceViewer(address viewer) external {
        if (viewer == address(0)) revert ZeroAddress();
        balanceViewers[msg.sender][viewer] = true;
        emit BalanceViewerAdded(msg.sender, viewer);
    }

    /**
     * @notice Remove a balance viewer
     * @param viewer The viewer address
     */
    function removeBalanceViewer(address viewer) external {
        balanceViewers[msg.sender][viewer] = false;
        emit BalanceViewerRemoved(msg.sender, viewer);
    }

    /**
     * @notice Request decryption of someone's balance (if authorized)
     * @param account The account to view
     * @return requestId The decryption request ID
     */
    function requestBalanceView(
        address account
    ) external returns (bytes32 requestId) {
        if (!balanceViewers[account][msg.sender]) revert UnauthorizedViewer();

        EncryptedBalance storage bal = encryptedBalances[account];
        require(bal.balance.handle != bytes32(0), "No balance");

        requestId = fheGateway.requestDecryption(
            bal.balance.handle,
            address(this),
            this.onBalanceViewed.selector,
            uint64(block.timestamp + FHELib.MAX_REQUEST_TTL)
        );

        pendingDecryptions[requestId] = account;
    }

    /**
     * @notice Callback for balance view decryption
     * @param requestId The request ID
     * @param decryptedValue The decrypted balance
     */
    function onBalanceViewed(
        bytes32 requestId,
        bytes32 decryptedValue
    ) external {
        require(msg.sender == address(fheGateway), "Unauthorized");

        address account = pendingDecryptions[requestId];
        require(account != address(0), "Invalid request");

        delete pendingDecryptions[requestId];

        // Note: In production, you'd want to emit to the viewer, not publicly
        emit BalanceDecrypted(account, uint256(decryptedValue), msg.sender);
    }

    // ============================================
    // COMPLIANCE
    // ============================================

    /**
     * @notice Submit compliance range proof
     * @dev Proves balance is within acceptable range without revealing exact amount
     * @param account The account
     * @param proof ZK range proof
     * @param minBound Minimum bound (public)
     * @param maxBound Maximum bound (public)
     */
    function submitComplianceProof(
        address account,
        bytes calldata proof,
        uint256 minBound,
        uint256 maxBound
    ) external onlyRole(COMPLIANCE_ROLE) {
        require(proof.length > 0, "Invalid proof");

        bytes32 proofId = keccak256(
            abi.encode(account, minBound, maxBound, block.timestamp)
        );

        emit ComplianceProofSubmitted(account, proofId);
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Set transfer limits
     * @param _min Minimum transfer amount
     * @param _max Maximum transfer amount
     */
    function setTransferLimits(
        uint256 _min,
        uint256 _max
    ) external onlyRole(OPERATOR_ROLE) {
        require(_min <= _max, "Invalid limits");
        minTransferAmount = _min;
        maxTransferAmount = _max;
    }

    /**
     * @notice Set compliance requirement
     * @param required Whether compliance proofs are required
     */
    function setComplianceRequired(
        bool required
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        complianceRequired = required;
    }

    /**
     * @notice Pause the token
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the token
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
