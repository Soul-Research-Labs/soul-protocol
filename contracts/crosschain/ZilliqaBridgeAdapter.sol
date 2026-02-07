// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IZilliqaBridgeAdapter} from "../interfaces/IZilliqaBridgeAdapter.sol";

/**
 * @title ZilliqaBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Zilliqa Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Zilliqa Network
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       Soul <-> Zilliqa Bridge                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Zilliqa Side                  │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wZIL        │  │           │  │  Scilla Contracts           │   │     │
 * │  │  │ Token       │  │           │  │  (Typed Functional Lang)    │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  pBFT + PoW Hybrid         │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~30s DS blocks)          │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Network Sharding          │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Transaction + Compute)   │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * ZILLIQA CONCEPTS:
 * - Qa: Smallest unit (1 ZIL = 1,000,000,000,000 Qa = 1e12)
 * - Scilla: Safe-by-design smart contract language (typed, functional)
 * - DS Committee: Directory Service committee managing consensus
 * - pBFT: practical Byzantine Fault Tolerance within DS committee
 * - PoW: Proof-of-Work for Sybil resistance in shard joins
 * - Sharding: Network, transaction, and computational sharding
 * - DS Block: Directory Service block (~30s, epoch marker)
 * - TX Block: Transaction block containing microblocks from shards
 * - ZRC-2: Zilliqa fungible token standard (like ERC-20)
 * - Chain ID: zilliqa-mainnet → 1
 * - Finality: 30 TX block confirmations for cross-chain safety
 */
contract ZilliqaBridgeAdapter is
    IZilliqaBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Zilliqa mainnet chain ID
    uint256 public constant ZILLIQA_CHAIN_ID = 1;

    /// @notice 1 ZIL = 1e12 Qa (12 decimals)
    uint256 public constant QA_PER_ZIL = 1_000_000_000_000;

    /// @notice Minimum deposit: 100 ZIL
    uint256 public constant MIN_DEPOSIT_QA = 100 * QA_PER_ZIL;

    /// @notice Maximum deposit: 50,000,000 ZIL
    uint256 public constant MAX_DEPOSIT_QA = 50_000_000 * QA_PER_ZIL;

    /// @notice Bridge fee: 5 BPS (0.05%)
    uint256 public constant BRIDGE_FEE_BPS = 5;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Withdrawal refund delay: 24 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Default TX block confirmations for finality
    uint256 public constant DEFAULT_TX_BLOCK_CONFIRMATIONS = 30;

    /*//////////////////////////////////////////////////////////////
                            ACCESS ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    BridgeConfig public config;

    /// @notice Treasury for fee collection
    address public treasury;

    /// @notice Deposit nonce (monotonically increasing)
    uint256 public depositNonce;

    /// @notice Withdrawal nonce (monotonically increasing)
    uint256 public withdrawalNonce;

    /// @notice Escrow nonce (monotonically increasing)
    uint256 public escrowNonce;

    /// @notice Latest verified DS block number
    uint256 public latestDSBlockNumber;

    /// @notice Current DS epoch
    uint256 public currentDSEpoch;

    /// @notice Total deposited in Qa
    uint256 public totalDeposited;

    /// @notice Total withdrawn in Qa
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated fees in Qa
    uint256 public accumulatedFees;

    /// @notice Deposits by ID
    mapping(bytes32 => ZILDeposit) private deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => ZILWithdrawal) private withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => ZILEscrow) private escrows;

    /// @notice DS blocks by number
    mapping(uint256 => ZilliqaDSBlock) private dsBlocks;

    /// @notice Used Zilliqa tx hashes (replay protection)
    mapping(bytes32 => bool) public usedZilliqaTxHashes;

    /// @notice Used nullifiers (privacy replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice User deposit IDs
    mapping(address => bytes32[]) private userDeposits;

    /// @notice User withdrawal IDs
    mapping(address => bytes32[]) private userWithdrawals;

    /// @notice User escrow IDs
    mapping(address => bytes32[]) private userEscrows;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function configure(
        address zilliqaBridgeContract,
        address wrappedZIL,
        address dsCommitteeOracle,
        uint256 minDSSignatures,
        uint256 requiredTxBlockConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (zilliqaBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedZIL == address(0)) revert ZeroAddress();
        if (dsCommitteeOracle == address(0)) revert ZeroAddress();

        config = BridgeConfig({
            zilliqaBridgeContract: zilliqaBridgeContract,
            wrappedZIL: wrappedZIL,
            dsCommitteeOracle: dsCommitteeOracle,
            minDSSignatures: minDSSignatures,
            requiredTxBlockConfirmations: requiredTxBlockConfirmations,
            active: true
        });

        emit BridgeConfigured(
            zilliqaBridgeContract,
            wrappedZIL,
            dsCommitteeOracle
        );
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                       DS BLOCK VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function submitDSBlock(
        uint256 dsBlockNumber,
        bytes32 blockHash,
        bytes32 stateRootHash,
        uint256 txBlockStart,
        uint256 txBlockEnd,
        bytes32 dsCommitteeHash,
        uint256 shardCount,
        uint256 timestamp,
        DSCommitteeAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        _verifyDSCommitteeAttestations(
            keccak256(
                abi.encodePacked(
                    dsBlockNumber,
                    blockHash,
                    stateRootHash,
                    txBlockStart,
                    txBlockEnd,
                    dsCommitteeHash,
                    shardCount,
                    timestamp
                )
            ),
            attestations
        );

        dsBlocks[dsBlockNumber] = ZilliqaDSBlock({
            dsBlockNumber: dsBlockNumber,
            blockHash: blockHash,
            stateRootHash: stateRootHash,
            txBlockStart: txBlockStart,
            txBlockEnd: txBlockEnd,
            dsCommitteeHash: dsCommitteeHash,
            shardCount: shardCount,
            timestamp: timestamp,
            verified: true
        });

        if (dsBlockNumber > latestDSBlockNumber) {
            latestDSBlockNumber = dsBlockNumber;
            currentDSEpoch = dsBlockNumber;
        }

        emit DSBlockVerified(dsBlockNumber, blockHash, shardCount);
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function initiateZILDeposit(
        bytes32 zilliqaTxHash,
        bytes32 zilliqaSender,
        address evmRecipient,
        uint256 amountQa,
        uint256 txBlockNumber,
        ZilliqaStateProof calldata txProof,
        DSCommitteeAttestation[] calldata attestations
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 depositId)
    {
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountQa < MIN_DEPOSIT_QA)
            revert AmountBelowMinimum(amountQa, MIN_DEPOSIT_QA);
        if (amountQa > MAX_DEPOSIT_QA)
            revert AmountAboveMaximum(amountQa, MAX_DEPOSIT_QA);
        if (usedZilliqaTxHashes[zilliqaTxHash])
            revert ZilliqaTxAlreadyUsed(zilliqaTxHash);

        // Verify TX block is within a verified DS epoch
        _verifyTxBlockInDSEpoch(txBlockNumber);

        _verifyDSCommitteeAttestations(
            keccak256(
                abi.encodePacked(
                    zilliqaTxHash,
                    zilliqaSender,
                    evmRecipient,
                    amountQa
                )
            ),
            attestations
        );

        usedZilliqaTxHashes[zilliqaTxHash] = true;

        uint256 fee = (amountQa * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountQa - fee;

        depositNonce++;
        depositId = keccak256(
            abi.encodePacked(
                ZILLIQA_CHAIN_ID,
                depositNonce,
                zilliqaTxHash,
                block.timestamp
            )
        );

        deposits[depositId] = ZILDeposit({
            depositId: depositId,
            zilliqaTxHash: zilliqaTxHash,
            zilliqaSender: zilliqaSender,
            evmRecipient: evmRecipient,
            amountQa: amountQa,
            netAmountQa: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            txBlockNumber: txBlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalDeposited += amountQa;
        userDeposits[evmRecipient].push(depositId);

        emit ZILDepositInitiated(
            depositId,
            zilliqaTxHash,
            zilliqaSender,
            evmRecipient,
            amountQa
        );
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function completeZILDeposit(
        bytes32 depositId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        ZILDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        IERC20(config.wrappedZIL).safeTransfer(
            dep.evmRecipient,
            dep.netAmountQa
        );

        emit ZILDepositCompleted(depositId, dep.evmRecipient, dep.netAmountQa);
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function initiateWithdrawal(
        bytes32 zilliqaRecipient,
        uint256 amountQa
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (zilliqaRecipient == bytes32(0)) revert ZeroAddress();
        if (amountQa < MIN_DEPOSIT_QA)
            revert AmountBelowMinimum(amountQa, MIN_DEPOSIT_QA);
        if (amountQa > MAX_DEPOSIT_QA)
            revert AmountAboveMaximum(amountQa, MAX_DEPOSIT_QA);

        IERC20(config.wrappedZIL).safeTransferFrom(
            msg.sender,
            address(this),
            amountQa
        );

        withdrawalNonce++;
        withdrawalId = keccak256(
            abi.encodePacked(
                ZILLIQA_CHAIN_ID,
                withdrawalNonce,
                msg.sender,
                zilliqaRecipient,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = ZILWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            zilliqaRecipient: zilliqaRecipient,
            amountQa: amountQa,
            zilliqaTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        totalWithdrawn += amountQa;
        userWithdrawals[msg.sender].push(withdrawalId);

        emit ZILWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            zilliqaRecipient,
            amountQa
        );
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 zilliqaTxHash,
        ZilliqaStateProof calldata txProof,
        DSCommitteeAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        ZILWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        _verifyDSCommitteeAttestations(
            keccak256(abi.encodePacked(withdrawalId, zilliqaTxHash)),
            attestations
        );

        w.status = WithdrawalStatus.COMPLETED;
        w.zilliqaTxHash = zilliqaTxHash;
        w.completedAt = block.timestamp;

        // Burn the held wZIL tokens
        // In production, this would call burn on the wZIL contract
        emit ZILWithdrawalCompleted(withdrawalId, zilliqaTxHash);
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        ZILWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);
        if (block.timestamp < w.initiatedAt + WITHDRAWAL_REFUND_DELAY)
            revert RefundTooEarly(
                block.timestamp,
                w.initiatedAt + WITHDRAWAL_REFUND_DELAY
            );

        w.status = WithdrawalStatus.REFUNDED;
        w.completedAt = block.timestamp;

        IERC20(config.wrappedZIL).safeTransfer(w.evmSender, w.amountQa);

        emit ZILWithdrawalRefunded(withdrawalId, w.evmSender, w.amountQa);
    }

    /*//////////////////////////////////////////////////////////////
                          ESCROW OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function createEscrow(
        bytes32 zilliqaParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (msg.value == 0) revert InvalidAmount();
        if (zilliqaParty == bytes32(0)) revert ZeroAddress();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        escrowNonce++;
        escrowId = keccak256(
            abi.encodePacked(
                ZILLIQA_CHAIN_ID,
                escrowNonce,
                msg.sender,
                zilliqaParty,
                block.timestamp
            )
        );

        escrows[escrowId] = ZILEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            zilliqaParty: zilliqaParty,
            amountQa: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        totalEscrows++;
        userEscrows[msg.sender].push(escrowId);

        emit EscrowCreated(
            escrowId,
            msg.sender,
            zilliqaParty,
            msg.value,
            hashlock
        );
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant {
        ZILEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.finishAfter) revert EscrowTimelockNotMet();

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != e.hashlock)
            revert InvalidPreimage(e.hashlock, computedHash);

        e.status = EscrowStatus.FINISHED;
        e.preimage = preimage;
        totalEscrowsFinished++;

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        ZILEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool sent, ) = e.evmParty.call{value: e.amountQa}("");
        require(sent, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVACY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata /* zkProof */
    ) external nonReentrant {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the bridge
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated fees to treasury
    function withdrawFees() external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        IERC20(config.wrappedZIL).safeTransfer(treasury, amount);

        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IZilliqaBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (ZILDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ZILWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (ZILEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function getDSBlock(
        uint256 dsBlockNumber
    ) external view returns (ZilliqaDSBlock memory) {
        return dsBlocks[dsBlockNumber];
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IZilliqaBridgeAdapter
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get aggregate bridge statistics
    function getBridgeStats()
        external
        view
        returns (
            uint256 _totalDeposited,
            uint256 _totalWithdrawn,
            uint256 _totalEscrows,
            uint256 _totalEscrowsFinished,
            uint256 _totalEscrowsCancelled,
            uint256 _accumulatedFees,
            uint256 _latestDSBlockNumber
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestDSBlockNumber
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Verify TX block falls within a verified DS epoch
    function _verifyTxBlockInDSEpoch(uint256 txBlockNumber) internal view {
        // Check that we have at least one verified DS block
        // and the TX block is within a verified DS epoch range
        if (latestDSBlockNumber == 0) revert TxBlockNotConfirmed(txBlockNumber);

        ZilliqaDSBlock storage dsBlock = dsBlocks[latestDSBlockNumber];
        if (!dsBlock.verified) revert TxBlockNotConfirmed(txBlockNumber);

        // TX block must be within the range of the latest verified DS epoch
        // or a previous verified DS epoch
        // For simplicity, we verify it's not beyond the latest known range
        if (
            txBlockNumber >
            dsBlock.txBlockEnd + config.requiredTxBlockConfirmations
        ) revert TxBlockNotConfirmed(txBlockNumber);
    }

    /// @dev Verify DS committee attestation signatures meet threshold
    function _verifyDSCommitteeAttestations(
        bytes32 messageHash,
        DSCommitteeAttestation[] calldata attestations
    ) internal view {
        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // In production: verify Schnorr multi-signature against DS committee
            // For now: verify via the DS committee oracle
            (bool valid, ) = config.dsCommitteeOracle.staticcall(
                abi.encodeWithSignature(
                    "verifyAttestation(bytes32,address,bytes)",
                    messageHash,
                    attestations[i].member,
                    attestations[i].signature
                )
            );

            if (valid) {
                // Decode the return value
                bytes memory returnData;
                (, returnData) = config.dsCommitteeOracle.staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        messageHash,
                        attestations[i].member,
                        attestations[i].signature
                    )
                );
                bool isValid = abi.decode(returnData, (bool));
                if (isValid) validCount++;
            }
        }

        if (validCount < config.minDSSignatures)
            revert InsufficientDSSignatures(validCount, config.minDSSignatures);
    }
}
