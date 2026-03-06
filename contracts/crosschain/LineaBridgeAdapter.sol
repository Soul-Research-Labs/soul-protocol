// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {IBridgeAdapter} from "./IBridgeAdapter.sol";

/**
 * @title LineaBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Linea L2 native messaging
 * @dev Integrates with Linea's native message service using canonical messaging bridge.
 *      Linea uses zk-rollup with validity proofs for finality.
 *
 * LINEA ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      Zaseon <-> Linea Bridge                            │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Ethereum L1      │           │   Linea L2         │               │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │ L1 Message  │  │── ZKP ───>│  │ L2 Message  │  │                │
 * │  │  │ Service     │  │           │  │ Service     │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │ L1 Token    │  │           │  │ L2 Token    │  │                │
 * │  │  │ Bridge      │  │           │  │ Bridge      │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  └───────────────────┘           └───────────────────┘                │
 * │                                                                        │
 * │  Linea Specifics:                                                      │
 * │  - lattice-based zk-SNARK prover (Vortex/gnark)                        │
 * │  - Finalization via proof submission on L1 (~hours)                     │
 * │  - L1MessageService.sendMessage() + claimMessage()                     │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract LineaBridgeAdapter is
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

    /// @notice Linea mainnet chain ID
    uint256 public constant LINEA_CHAIN_ID = 59144;

    /// @notice Linea Sepolia chain ID
    uint256 public constant LINEA_SEPOLIA_CHAIN_ID = 59141;

    /// @notice Default message fee
    uint256 public constant DEFAULT_MESSAGE_FEE = 0.001 ether;

    /// @notice Minimum deposit
    uint256 public constant MIN_DEPOSIT = 1e15;

    /// @notice Maximum deposit
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        SENT,
        ANCHORED,
        PROVEN,
        CLAIMED,
        FAILED
    }

    enum MessageDirection {
        L1_TO_L2,
        L2_TO_L1
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct LineaConfig {
        address messageService; // L1MessageService or L2MessageService
        address tokenBridge; // Token bridge (if separate)
        uint256 chainId;
        bool active;
    }

    struct LineaDeposit {
        bytes32 depositId;
        address sender;
        address l2Recipient;
        address l1Token;
        uint256 amount;
        uint256 messageNonce; // Nonce from MessageService
        TransferStatus status;
        uint256 initiatedAt;
        uint256 claimedAt;
    }

    struct LineaWithdrawal {
        bytes32 withdrawalId;
        address l2Sender;
        address l1Recipient;
        address l1Token;
        uint256 amount;
        uint256 l2BlockNumber;
        bytes32 messageHash;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 provenAt;
        uint256 claimedAt;
    }

    struct LineaClaimProof {
        bytes32 messageHash;
        uint256 nonce;
        uint256 fee;
        address sender;
        address destination;
        bytes data;
        uint256 blockNumber;
        bytes32[] merkleProof;
    }

    struct TokenMapping {
        address l1Token;
        address l2Token;
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

    mapping(uint256 => LineaConfig) public lineaConfigs;
    mapping(bytes32 => LineaDeposit) public deposits;
    mapping(address => bytes32[]) public userDeposits;
    mapping(bytes32 => LineaWithdrawal) public withdrawals;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(bytes32 => TokenMapping) public tokenMappings;
    bytes32[] public tokenMappingKeys;
    mapping(bytes32 => bool) public claimedMessages;

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

    event LineaConfigured(uint256 indexed chainId, address messageService);
    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        address l2Recipient,
        uint256 amount
    );
    event DepositClaimed(bytes32 indexed depositId);
    event WithdrawalRegistered(
        bytes32 indexed withdrawalId,
        address l2Sender,
        address indexed l1Recipient,
        uint256 amount
    );
    event WithdrawalProven(bytes32 indexed withdrawalId, bytes32 messageHash);
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
    error DepositNotFound();
    error WithdrawalNotFound();
    error WithdrawalNotProven();
    error InvalidProof();
    error MessageAlreadyClaimed();
    error InsufficientFee();
    error ZeroAddress();
    error TransferFailed();
    error FeeTooHigh();
    error LineaMessageFailed();

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

    function configureLinea(
        uint256 chainId,
        address messageService,
        address tokenBridge
    ) external onlyRole(OPERATOR_ROLE) {
        if (messageService == address(0)) revert ZeroAddress();

        lineaConfigs[chainId] = LineaConfig({
            messageService: messageService,
            tokenBridge: tokenBridge,
            chainId: chainId,
            active: true
        });

        emit LineaConfigured(chainId, messageService);
    }

    function mapToken(
        address l1Token,
        address l2Token,
        uint256 chainId,
        uint8 decimals
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 key = keccak256(abi.encodePacked(l1Token, chainId));
        tokenMappings[key] = TokenMapping({
            l1Token: l1Token,
            l2Token: l2Token,
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
     * @notice Deposit ETH from L1 to Linea L2 via L1MessageService
     */
    function deposit(
        uint256 chainId,
        address l2Recipient,
        address l1Token,
        uint256 amount,
        uint256 messageFee
    ) external payable nonReentrant whenNotPaused returns (bytes32 depositId) {
        LineaConfig storage config = lineaConfigs[chainId];
        if (!config.active) revert BridgeNotConfigured();
        if (l2Recipient == address(0)) revert ZeroAddress();

        if (amount < MIN_DEPOSIT) revert AmountTooLow();
        if (amount > MAX_DEPOSIT) revert AmountTooHigh();

        if (messageFee == 0) messageFee = DEFAULT_MESSAGE_FEE;

        uint256 fee = (amount * bridgeFeeBps) / 10000;
        uint256 depositAmount = amount - fee;
        if (msg.value < amount + messageFee) revert InsufficientFee();

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

        uint256 nonce = _sendLineaMessage(
            config.messageService,
            l2Recipient,
            depositAmount,
            messageFee
        );

        deposits[depositId] = LineaDeposit({
            depositId: depositId,
            sender: msg.sender,
            l2Recipient: l2Recipient,
            l1Token: l1Token,
            amount: amount,
            messageNonce: nonce,
            status: TransferStatus.SENT,
            initiatedAt: block.timestamp,
            claimedAt: 0
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
        LineaDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound();

        dep.status = TransferStatus.CLAIMED;
        dep.claimedAt = block.timestamp;

        emit DepositClaimed(depositId);
    }

    /*//////////////////////////////////////////////////////////////
                        L2 → L1 WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    function registerWithdrawal(
        address l2Sender,
        address l1Recipient,
        address l1Token,
        uint256 amount,
        uint256 l2BlockNumber,
        bytes32 messageHash
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 withdrawalId) {
        withdrawalId = keccak256(
            abi.encodePacked(
                l2Sender,
                l1Recipient,
                l1Token,
                amount,
                l2BlockNumber,
                messageHash
            )
        );

        withdrawals[withdrawalId] = LineaWithdrawal({
            withdrawalId: withdrawalId,
            l2Sender: l2Sender,
            l1Recipient: l1Recipient,
            l1Token: l1Token,
            amount: amount,
            l2BlockNumber: l2BlockNumber,
            messageHash: messageHash,
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
     * @notice Prove withdrawal using Linea finalization proof
     */
    function proveWithdrawal(
        bytes32 withdrawalId,
        LineaClaimProof calldata proof
    ) external nonReentrant whenNotPaused {
        LineaWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound();

        if (claimedMessages[proof.messageHash]) revert MessageAlreadyClaimed();

        LineaConfig storage config = lineaConfigs[LINEA_CHAIN_ID];
        if (!config.active) revert BridgeNotConfigured();

        bool valid = _verifyLineaProof(config.messageService, proof);
        if (!valid) revert InvalidProof();

        claimedMessages[proof.messageHash] = true;
        w.status = TransferStatus.PROVEN;
        w.provenAt = block.timestamp;

        emit WithdrawalProven(withdrawalId, proof.messageHash);
    }

    function claimWithdrawal(bytes32 withdrawalId) external nonReentrant {
        LineaWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound();
        if (w.status != TransferStatus.PROVEN) revert WithdrawalNotProven();

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
    ) external view returns (LineaDeposit memory) {
        return deposits[depositId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (LineaWithdrawal memory) {
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

    function _sendLineaMessage(
        address messageService,
        address l2Recipient,
        uint256 value,
        uint256 messageFee
    ) internal returns (uint256 nonce) {
        (bool success, bytes memory result) = messageService.call{
            value: value + messageFee
        }(
            abi.encodeWithSignature(
                "sendMessage(address,uint256,bytes)",
                l2Recipient,
                messageFee,
                "" // empty calldata for ETH transfer
            )
        );

        if (success && result.length >= 32) {
            nonce = abi.decode(result, (uint256));
        } else {
            revert LineaMessageFailed();
        }
    }

    function _verifyLineaProof(
        address messageService,
        LineaClaimProof calldata proof
    ) internal view returns (bool) {
        // Verify finalization status via Linea's message service
        (bool success, bytes memory result) = messageService.staticcall(
            abi.encodeWithSignature("isMessageClaimed(uint256)", proof.nonce)
        );

        // If message is not yet claimed on L1, check if the finalization
        // proof data is valid (block has been finalized on L1)
        if (success && result.length >= 32) {
            bool alreadyClaimed = abi.decode(result, (bool));
            if (alreadyClaimed) return false; // Already claimed

            // Check if the L2 block has been finalized
            (bool finSuccess, bytes memory finResult) = messageService
                .staticcall(
                    abi.encodeWithSignature(
                        "isBlockFinalized(uint256)",
                        proof.blockNumber
                    )
                );
            if (finSuccess && finResult.length >= 32) {
                return abi.decode(finResult, (bool));
            }
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
        // Use deposit() for full Linea-specific control
        revert("Use deposit() with explicit parameters");
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure returns (uint256 nativeFee) {
        // Linea fees depend on L1MessageService.minimumFeeInWei()
        revert("Use Linea-specific fee estimation");
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(bytes32 messageId) external view returns (bool) {
        LineaWithdrawal storage w = withdrawals[messageId];
        return w.status == TransferStatus.CLAIMED;
    }
}
