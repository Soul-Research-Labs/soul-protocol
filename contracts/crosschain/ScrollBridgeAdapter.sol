// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {IBridgeAdapter} from "./IBridgeAdapter.sol";

/**
 * @title ScrollBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Scroll L2 native messaging
 * @dev Integrates with Scroll's native L1<->L2 messenger and gateway contracts.
 *      Scroll uses zkEVM with validity proofs for L2→L1 finality.
 *
 * SCROLL ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      Zaseon <-> Scroll Bridge                           │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Ethereum L1      │           │   Scroll L2        │                │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │ L1 Scroll   │  │── ZKP ───│  │ L2 Scroll   │  │                │
 * │  │  │ Messenger   │  │  Verify  │  │ Messenger   │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │ L1 Gateway  │  │           │  │ L2 Gateway  │  │                │
 * │  │  │ Router      │  │           │  │ Router      │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  └───────────────────┘           └───────────────────┘                │
 * │                                                                        │
 * │  Scroll Specifics:                                                     │
 * │  - zkEVM: Bytecode-compatible ZK rollup                                │
 * │  - L1MessageQueue for L1→L2 messages                                   │
 * │  - Batch finalization via ZK proofs (~hours)                            │
 * │  - L1ScrollMessenger for L2→L1 claim with Merkle proof                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract ScrollBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Scroll mainnet chain ID
    uint256 public constant SCROLL_CHAIN_ID = 534352;

    /// @notice Scroll Sepolia chain ID
    uint256 public constant SCROLL_SEPOLIA_CHAIN_ID = 534351;

    /// @notice Default L2 gas limit
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1_000_000;

    /// @notice ZK proof finality window
    uint256 public constant ZK_FINALITY_WINDOW = 4 hours;

    /// @notice Minimum deposit
    uint256 public constant MIN_DEPOSIT = 1e15;

    /// @notice Maximum deposit
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        QUEUED,
        FINALIZED_ON_L2,
        ZK_PROVEN,
        CLAIMED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Scroll bridge configuration
    struct ScrollConfig {
        address l1Messenger; // L1ScrollMessenger
        address l1GatewayRouter; // L1GatewayRouter
        address l1MessageQueue; // L1MessageQueue
        address rollup; // ScrollChain rollup contract
        uint256 chainId;
        bool active;
    }

    /// @notice L1→L2 deposit
    struct ScrollDeposit {
        bytes32 depositId;
        address sender;
        address l2Recipient;
        address l1Token;
        uint256 amount;
        uint256 l2GasLimit;
        uint256 queueIndex; // Position in L1MessageQueue
        TransferStatus status;
        uint256 initiatedAt;
        uint256 finalizedAt;
    }

    /// @notice L2→L1 withdrawal
    struct ScrollWithdrawal {
        bytes32 withdrawalId;
        address l2Sender;
        address l1Recipient;
        address l1Token;
        uint256 amount;
        uint256 batchIndex; // Scroll batch index
        TransferStatus status;
        uint256 initiatedAt;
        uint256 provenAt;
        uint256 claimedAt;
    }

    /// @notice Scroll batch withdrawal proof
    struct ScrollWithdrawalProof {
        uint256 batchIndex;
        bytes merkleProof; // Merkle proof of withdrawal in batch
        bytes32 withdrawalRoot; // Root of withdrawal tree in finalized batch
    }

    /// @notice Token mapping
    struct TokenMapping {
        address l1Token;
        address l2Token;
        address l1Gateway; // Token-specific L1 gateway
        address l2Gateway; // Token-specific L2 gateway
        uint8 decimals;
        uint256 totalDeposited;
        uint256 totalWithdrawn;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    uint256 public bridgeFeeBps;
    address public treasury;
    uint256 public transferNonce;

    mapping(uint256 => ScrollConfig) public scrollConfigs;
    mapping(bytes32 => ScrollDeposit) public deposits;
    mapping(address => bytes32[]) public userDeposits;
    mapping(bytes32 => ScrollWithdrawal) public withdrawals;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(bytes32 => TokenMapping) public tokenMappings;
    bytes32[] public tokenMappingKeys;
    mapping(bytes32 => bool) public processedProofs;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalValueDeposited;
    uint256 public totalValueWithdrawn;
    uint256 public totalFeesCollected;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ScrollConfigured(
        uint256 indexed chainId,
        address l1Messenger,
        address l1GatewayRouter
    );
    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        address l2Recipient,
        uint256 amount
    );
    event DepositFinalized(bytes32 indexed depositId);
    event WithdrawalRegistered(
        bytes32 indexed withdrawalId,
        address l2Sender,
        address indexed l1Recipient,
        uint256 amount
    );
    event WithdrawalProven(bytes32 indexed withdrawalId, uint256 batchIndex);
    event WithdrawalClaimed(bytes32 indexed withdrawalId);
    event TokenMapped(
        address indexed l1Token,
        address l2Token,
        uint256 chainId
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error BridgeNotConfigured();
    error AmountTooLow();
    error AmountTooHigh();
    error TokenNotMapped();
    error DepositNotFound();
    error WithdrawalNotFound();
    error WithdrawalNotProven();
    error InvalidProof();
    error ProofAlreadyProcessed();
    error InsufficientFee();
    error ZeroAddress();
    error TransferFailed();
    error FeeTooHigh();
    error ScrollMessageFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        bridgeFeeBps = 10; // 0.10%
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function configureScroll(
        uint256 chainId,
        address l1Messenger,
        address l1GatewayRouter,
        address l1MessageQueue,
        address rollup
    ) external onlyRole(OPERATOR_ROLE) {
        if (l1Messenger == address(0)) revert ZeroAddress();
        if (l1GatewayRouter == address(0)) revert ZeroAddress();
        if (l1MessageQueue == address(0)) revert ZeroAddress();
        if (rollup == address(0)) revert ZeroAddress();

        scrollConfigs[chainId] = ScrollConfig({
            l1Messenger: l1Messenger,
            l1GatewayRouter: l1GatewayRouter,
            l1MessageQueue: l1MessageQueue,
            rollup: rollup,
            chainId: chainId,
            active: true
        });

        emit ScrollConfigured(chainId, l1Messenger, l1GatewayRouter);
    }

    function mapToken(
        address l1Token,
        address l2Token,
        address l1Gateway,
        address l2Gateway,
        uint256 chainId,
        uint8 decimals
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 key = keccak256(abi.encodePacked(l1Token, chainId));
        tokenMappings[key] = TokenMapping({
            l1Token: l1Token,
            l2Token: l2Token,
            l1Gateway: l1Gateway,
            l2Gateway: l2Gateway,
            decimals: decimals,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });
        tokenMappingKeys.push(key);

        emit TokenMapped(l1Token, l2Token, chainId);
    }

    /*//////////////////////////////////////////////////////////////
                        L1 → L2 DEPOSITS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit ETH/tokens from L1 to Scroll L2 via L1ScrollMessenger
     */
    function deposit(
        uint256 chainId,
        address l2Recipient,
        address l1Token,
        uint256 amount,
        uint256 l2GasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 depositId) {
        ScrollConfig storage config = scrollConfigs[chainId];
        if (!config.active) revert BridgeNotConfigured();
        if (l2Recipient == address(0)) revert ZeroAddress();

        if (amount < MIN_DEPOSIT) revert AmountTooLow();
        if (amount > MAX_DEPOSIT) revert AmountTooHigh();

        if (l2GasLimit == 0) l2GasLimit = DEFAULT_L2_GAS_LIMIT;

        uint256 fee = (amount * bridgeFeeBps) / 10000;
        uint256 depositAmount = amount - fee;
        if (msg.value < amount) revert InsufficientFee();

        depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                l2Recipient,
                l1Token,
                amount,
                chainId,
                transferNonce++,
                block.timestamp
            )
        );

        // Send message via L1ScrollMessenger
        uint256 queueIndex = _sendScrollMessage(
            config.l1Messenger,
            l2Recipient,
            depositAmount,
            l2GasLimit
        );

        deposits[depositId] = ScrollDeposit({
            depositId: depositId,
            sender: msg.sender,
            l2Recipient: l2Recipient,
            l1Token: l1Token,
            amount: amount,
            l2GasLimit: l2GasLimit,
            queueIndex: queueIndex,
            status: TransferStatus.QUEUED,
            initiatedAt: block.timestamp,
            finalizedAt: 0
        });

        userDeposits[msg.sender].push(depositId);

        if (fee > 0 && treasury != address(0)) {
            totalFeesCollected += fee;
            (bool sent, ) = treasury.call{value: fee}("");
            if (!sent) revert TransferFailed();
        }

        bytes32 mappingKey = keccak256(abi.encodePacked(l1Token, chainId));
        if (tokenMappings[mappingKey].active) {
            tokenMappings[mappingKey].totalDeposited += amount;
        }

        totalDeposits++;
        totalValueDeposited += amount;

        emit DepositInitiated(depositId, msg.sender, l2Recipient, amount);
    }

    function finalizeDeposit(
        bytes32 depositId
    ) external onlyRole(EXECUTOR_ROLE) {
        ScrollDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound();

        dep.status = TransferStatus.FINALIZED_ON_L2;
        dep.finalizedAt = block.timestamp;

        emit DepositFinalized(depositId);
    }

    /*//////////////////////////////////////////////////////////////
                        L2 → L1 WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    function registerWithdrawal(
        address l2Sender,
        address l1Recipient,
        address l1Token,
        uint256 amount,
        uint256 batchIndex
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 withdrawalId) {
        withdrawalId = keccak256(
            abi.encodePacked(l2Sender, l1Recipient, l1Token, amount, batchIndex)
        );

        withdrawals[withdrawalId] = ScrollWithdrawal({
            withdrawalId: withdrawalId,
            l2Sender: l2Sender,
            l1Recipient: l1Recipient,
            l1Token: l1Token,
            amount: amount,
            batchIndex: batchIndex,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            provenAt: 0,
            claimedAt: 0
        });

        userWithdrawals[l1Recipient].push(withdrawalId);
        totalWithdrawals++;

        emit WithdrawalRegistered(withdrawalId, l2Sender, l1Recipient, amount);
    }

    /**
     * @notice Prove withdrawal using Scroll batch Merkle proof
     */
    function proveWithdrawal(
        bytes32 withdrawalId,
        ScrollWithdrawalProof calldata proof
    ) external nonReentrant whenNotPaused {
        ScrollWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound();

        bytes32 proofHash = keccak256(abi.encode(proof));
        if (processedProofs[proofHash]) revert ProofAlreadyProcessed();

        ScrollConfig storage config = scrollConfigs[SCROLL_CHAIN_ID];
        if (!config.active) revert BridgeNotConfigured();

        bool valid = _verifyScrollBatchProof(config.rollup, proof);
        if (!valid) revert InvalidProof();

        processedProofs[proofHash] = true;
        w.status = TransferStatus.ZK_PROVEN;
        w.provenAt = block.timestamp;

        emit WithdrawalProven(withdrawalId, proof.batchIndex);
    }

    function claimWithdrawal(bytes32 withdrawalId) external nonReentrant {
        ScrollWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound();
        if (w.status != TransferStatus.ZK_PROVEN) revert WithdrawalNotProven();

        w.status = TransferStatus.CLAIMED;
        w.claimedAt = block.timestamp;
        totalValueWithdrawn += w.amount;

        (bool sent, ) = w.l1Recipient.call{value: w.amount}("");
        if (!sent) revert TransferFailed();

        emit WithdrawalClaimed(withdrawalId);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setFee(uint256 newFeeBps) external onlyRole(OPERATOR_ROLE) {
        if (newFeeBps > 100) revert FeeTooHigh();
        bridgeFeeBps = newFeeBps;
    }

    function setTreasury(address _treasury) external onlyRole(OPERATOR_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(
        bytes32 depositId
    ) external view returns (ScrollDeposit memory) {
        return deposits[depositId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ScrollWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _sendScrollMessage(
        address l1Messenger,
        address l2Recipient,
        uint256 value,
        uint256 gasLimit
    ) internal returns (uint256 queueIndex) {
        (bool success, bytes memory result) = l1Messenger.call{value: value}(
            abi.encodeWithSignature(
                "sendMessage(address,uint256,bytes,uint256)",
                l2Recipient,
                value,
                "", // empty data for ETH transfer
                gasLimit
            )
        );

        if (success && result.length >= 32) {
            queueIndex = abi.decode(result, (uint256));
        } else {
            revert ScrollMessageFailed();
        }
    }

    function _verifyScrollBatchProof(
        address rollup,
        ScrollWithdrawalProof calldata proof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = rollup.staticcall(
            abi.encodeWithSignature(
                "isBatchFinalized(uint256)",
                proof.batchIndex
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                     IBridgeAdapter COMPATIBILITY
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /*refundAddress*/
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        // Extract destination chain ID from payload (first 32 bytes)
        uint256 destChainId = abi.decode(payload[:32], (uint256));
        ScrollConfig storage config = scrollConfigs[destChainId];
        if (!config.active) revert BridgeNotConfigured();
        if (targetAddress == address(0)) revert ZeroAddress();

        // Send message via L1ScrollMessenger
        _sendScrollMessage(
            config.l1Messenger,
            targetAddress,
            msg.value,
            DEFAULT_L2_GAS_LIMIT
        );

        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                targetAddress,
                destChainId,
                transferNonce++,
                block.timestamp
            )
        );

        emit DepositInitiated(messageId, msg.sender, targetAddress, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure returns (uint256 nativeFee) {
        // Scroll fees depend on L1 message queue gas estimation
        revert("Use Scroll-specific fee estimation");
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(bytes32 messageId) external view returns (bool) {
        ScrollWithdrawal storage w = withdrawals[messageId];
        return w.status == TransferStatus.CLAIMED;
    }

    /// @notice Accept ETH from canonical bridge during L2→L1 withdrawal flow
    receive() external payable {}
}
