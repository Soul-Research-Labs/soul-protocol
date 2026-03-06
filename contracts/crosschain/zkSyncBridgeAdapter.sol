// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title zkSyncBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for zkSync Era native bridge
 * @dev Integrates with zkSync Era's native L1<->L2 messaging via the Diamond Proxy
 *      and Mailbox facets. Uses zkSync's validity proofs (ZK-SNARKs) for L2→L1 finality.
 *
 * ZKSYNC ERA ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     Zaseon <-> zkSync Era Bridge                         │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Ethereum L1      │           │   zkSync Era       │                │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │ Diamond      │  │── ZKP ───│  │ Bootloader  │  │                │
 * │  │  │ Proxy        │  │  Verify  │  │ + System    │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  └───────────────────┘           └───────────────────┘                │
 * │                                                                        │
 * │  Key Differences from Optimistic Rollups:                              │
 * │  - Validity proofs (ZK-SNARKs) instead of fraud proofs                 │
 * │  - ~1 hour finality (vs ~7 days for optimistic)                        │
 * │  - Native account abstraction                                          │
 * │  - L2→L1 messages proven via L2 log inclusion proofs                   │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract zkSyncBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice zkSync Era chain ID
    uint256 public constant ZKSYNC_ERA_CHAIN_ID = 324;

    /// @notice zkSync Era Sepolia chain ID
    uint256 public constant ZKSYNC_SEPOLIA_CHAIN_ID = 300;

    /// @notice Default L2 gas limit for zkSync transactions
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 2_000_000;

    /// @notice Default gas per pubdata byte
    uint256 public constant DEFAULT_GAS_PER_PUBDATA = 800;

    /// @notice ZK proof finality window (~1 hour for zkSync)
    uint256 public constant ZK_FINALITY_WINDOW = 1 hours;

    /// @notice Minimum deposit
    uint256 public constant MIN_DEPOSIT = 1e15; // 0.001 ETH

    /// @notice Maximum deposit
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        L2_REQUESTED,
        ZK_PROVEN,
        EXECUTED,
        FINALIZED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice zkSync bridge configuration
    struct BridgeConfig {
        address diamondProxy; // zkSync Diamond Proxy (main L1 contract)
        address l1Bridge; // L1 shared bridge
        address l2Bridge; // L2 shared bridge (on zkSync)
        uint256 chainId; // zkSync chain ID
        bool active;
    }

    /// @notice L1→L2 deposit
    struct ZKDeposit {
        bytes32 depositId;
        address sender;
        address l2Recipient;
        address l1Token;
        uint256 amount;
        uint256 l2GasLimit;
        uint256 gasPerPubdata;
        bytes32 l2TxHash; // Canonical L2 tx hash
        TransferStatus status;
        uint256 initiatedAt;
        uint256 finalizedAt;
    }

    /// @notice L2→L1 withdrawal
    struct ZKWithdrawal {
        bytes32 withdrawalId;
        address l2Sender;
        address l1Recipient;
        address l1Token;
        uint256 amount;
        uint256 l2BatchNumber;
        uint256 l2MessageIndex;
        uint16 l2TxNumberInBatch;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 provenAt;
        uint256 claimedAt;
    }

    /// @notice L2 log inclusion proof (for ZK-proven withdrawals)
    struct L2LogProof {
        uint256 batchNumber;
        uint256 messageIndex;
        uint16 txNumberInBatch;
        bytes32[] proof; // Merkle proof of L2 log inclusion
        bytes32 l2LogHash; // Hash of the L2 log entry
    }

    /// @notice Token mapping
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

    /// @notice Bridge fee in basis points
    uint256 public bridgeFeeBps;

    /// @notice Treasury address
    address public treasury;

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Bridge configurations
    mapping(uint256 => BridgeConfig) public bridgeConfigs;

    /// @notice Deposits
    mapping(bytes32 => ZKDeposit) public deposits;
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Withdrawals
    mapping(bytes32 => ZKWithdrawal) public withdrawals;
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Token mappings (keccak256(l1Token, chainId) => mapping)
    mapping(bytes32 => TokenMapping) public tokenMappings;
    bytes32[] public tokenMappingKeys;

    /// @notice Processed L2 log proofs (replay protection)
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

    event BridgeConfigured(
        uint256 indexed chainId,
        address diamondProxy,
        address l1Bridge
    );

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed sender,
        address l2Recipient,
        uint256 amount,
        bytes32 l2TxHash
    );
    event DepositFinalized(bytes32 indexed depositId);

    event WithdrawalRegistered(
        bytes32 indexed withdrawalId,
        address l2Sender,
        address indexed l1Recipient,
        uint256 amount
    );
    event WithdrawalProven(bytes32 indexed withdrawalId, uint256 batchNumber);
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
    error InvalidAmount();
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
    error L2TransactionFailed();

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

    /**
     * @notice Configure zkSync Era bridge
     * @param chainId zkSync chain ID (324 mainnet, 300 sepolia)
     * @param diamondProxy zkSync Diamond Proxy address on L1
     * @param l1Bridge L1 shared bridge address
     * @param l2Bridge L2 shared bridge address
     */
    function configureBridge(
        uint256 chainId,
        address diamondProxy,
        address l1Bridge,
        address l2Bridge
    ) external onlyRole(OPERATOR_ROLE) {
        if (diamondProxy == address(0)) revert ZeroAddress();

        bridgeConfigs[chainId] = BridgeConfig({
            diamondProxy: diamondProxy,
            l1Bridge: l1Bridge,
            l2Bridge: l2Bridge,
            chainId: chainId,
            active: true
        });

        emit BridgeConfigured(chainId, diamondProxy, l1Bridge);
    }

    /**
     * @notice Map L1 token to L2 token on zkSync
     */
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
     * @notice Deposit ETH/tokens from L1 to zkSync Era via the Diamond Proxy Mailbox
     * @param chainId Target zkSync chain ID
     * @param l2Recipient L2 recipient address
     * @param l1Token L1 token address (address(0) for ETH)
     * @param amount Deposit amount
     * @param l2GasLimit Gas limit for L2 execution (0 = default)
     * @return depositId Unique deposit identifier
     */
    function deposit(
        uint256 chainId,
        address l2Recipient,
        address l1Token,
        uint256 amount,
        uint256 l2GasLimit
    ) external payable nonReentrant whenNotPaused returns (bytes32 depositId) {
        BridgeConfig storage config = bridgeConfigs[chainId];
        if (!config.active) revert BridgeNotConfigured();
        if (l2Recipient == address(0)) revert ZeroAddress();

        if (amount < MIN_DEPOSIT) revert AmountTooLow();
        if (amount > MAX_DEPOSIT) revert AmountTooHigh();

        if (l2GasLimit == 0) l2GasLimit = DEFAULT_L2_GAS_LIMIT;

        // Calculate fee
        uint256 fee = (amount * bridgeFeeBps) / 10000;
        uint256 l2Value = amount - fee;
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

        // Request L2 transaction via Diamond Proxy Mailbox
        bytes32 l2TxHash = _requestL2Transaction(
            config.diamondProxy,
            l2Recipient,
            l2Value,
            l2GasLimit
        );

        deposits[depositId] = ZKDeposit({
            depositId: depositId,
            sender: msg.sender,
            l2Recipient: l2Recipient,
            l1Token: l1Token,
            amount: amount,
            l2GasLimit: l2GasLimit,
            gasPerPubdata: DEFAULT_GAS_PER_PUBDATA,
            l2TxHash: l2TxHash,
            status: TransferStatus.L2_REQUESTED,
            initiatedAt: block.timestamp,
            finalizedAt: 0
        });

        userDeposits[msg.sender].push(depositId);

        // Collect fee
        if (fee > 0 && treasury != address(0)) {
            totalFeesCollected += fee;
            (bool sent, ) = treasury.call{value: fee}("");
            if (!sent) revert TransferFailed();
        }

        // Update token stats
        bytes32 mappingKey = keccak256(abi.encodePacked(l1Token, chainId));
        if (tokenMappings[mappingKey].active) {
            tokenMappings[mappingKey].totalDeposited += amount;
        }

        totalDeposits++;
        totalValueDeposited += amount;

        emit DepositInitiated(
            depositId,
            msg.sender,
            l2Recipient,
            amount,
            l2TxHash
        );
    }

    /**
     * @notice Finalize deposit after ZK proof verification on L1
     */
    function finalizeDeposit(
        bytes32 depositId
    ) external onlyRole(EXECUTOR_ROLE) {
        ZKDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound();

        dep.status = TransferStatus.FINALIZED;
        dep.finalizedAt = block.timestamp;

        emit DepositFinalized(depositId);
    }

    /*//////////////////////////////////////////////////////////////
                        L2 → L1 WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a withdrawal from zkSync Era L2
     * @dev Called by EXECUTOR_ROLE when L2 withdrawal is detected
     */
    function registerWithdrawal(
        address l2Sender,
        address l1Recipient,
        address l1Token,
        uint256 amount,
        uint256 l2BatchNumber,
        uint256 l2MessageIndex,
        uint16 l2TxNumberInBatch
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 withdrawalId) {
        withdrawalId = keccak256(
            abi.encodePacked(
                l2Sender,
                l1Recipient,
                l1Token,
                amount,
                l2BatchNumber,
                l2MessageIndex
            )
        );

        withdrawals[withdrawalId] = ZKWithdrawal({
            withdrawalId: withdrawalId,
            l2Sender: l2Sender,
            l1Recipient: l1Recipient,
            l1Token: l1Token,
            amount: amount,
            l2BatchNumber: l2BatchNumber,
            l2MessageIndex: l2MessageIndex,
            l2TxNumberInBatch: l2TxNumberInBatch,
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
     * @notice Prove a withdrawal using L2 log inclusion proof
     * @dev zkSync uses validity proofs — once batch is proven on L1, withdrawals are final
     */
    function proveWithdrawal(
        bytes32 withdrawalId,
        L2LogProof calldata proof
    ) external nonReentrant whenNotPaused {
        ZKWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound();

        bytes32 proofHash = keccak256(abi.encode(proof));
        if (processedProofs[proofHash]) revert ProofAlreadyProcessed();

        // Verify proof against zkSync Diamond Proxy
        BridgeConfig storage config = bridgeConfigs[ZKSYNC_ERA_CHAIN_ID];
        if (!config.active) revert BridgeNotConfigured();

        bool valid = _verifyL2LogProof(config.diamondProxy, proof);
        if (!valid) revert InvalidProof();

        processedProofs[proofHash] = true;
        w.status = TransferStatus.ZK_PROVEN;
        w.provenAt = block.timestamp;

        emit WithdrawalProven(withdrawalId, proof.batchNumber);
    }

    /**
     * @notice Claim a proven withdrawal
     * @dev No challenge period needed — ZK proof provides immediate finality
     */
    function claimWithdrawal(bytes32 withdrawalId) external nonReentrant {
        ZKWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound();
        if (w.status != TransferStatus.ZK_PROVEN) revert WithdrawalNotProven();

        w.status = TransferStatus.FINALIZED;
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
    ) external view returns (ZKDeposit memory) {
        return deposits[depositId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ZKWithdrawal memory) {
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

    /**
     * @dev Request L2 transaction via zkSync Diamond Proxy Mailbox facet
     */
    function _requestL2Transaction(
        address diamondProxy,
        address l2Recipient,
        uint256 l2Value,
        uint256 l2GasLimit
    ) internal returns (bytes32 l2TxHash) {
        // Call requestL2Transaction on the Mailbox facet
        (bool success, bytes memory result) = diamondProxy.call{value: l2Value}(
            abi.encodeWithSignature(
                "requestL2Transaction(address,uint256,bytes,uint256,uint256,bytes[],address)",
                l2Recipient,
                l2Value,
                "", // empty calldata for ETH transfer
                l2GasLimit,
                DEFAULT_GAS_PER_PUBDATA,
                new bytes[](0), // no factory deps
                msg.sender // refund recipient
            )
        );

        if (success && result.length >= 32) {
            l2TxHash = abi.decode(result, (bytes32));
        } else {
            revert L2TransactionFailed();
        }
    }

    /**
     * @dev Verify L2 log inclusion proof against zkSync Diamond Proxy
     */
    function _verifyL2LogProof(
        address diamondProxy,
        L2LogProof calldata proof
    ) internal view returns (bool) {
        // Call proveL2LogInclusion on the Diamond Proxy
        (bool success, bytes memory result) = diamondProxy.staticcall(
            abi.encodeWithSignature(
                "proveL2LogInclusion(uint256,uint256,((uint8,bool,uint16,address,bytes32,bytes32)),bytes32[])",
                proof.batchNumber,
                proof.messageIndex,
                proof.l2LogHash,
                proof.proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }
}
