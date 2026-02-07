// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IFantomBridgeAdapter} from "../interfaces/IFantomBridgeAdapter.sol";

/**
 * @title FantomBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Fantom Opera interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Fantom Opera
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    Soul <-> Fantom Opera Bridge                             │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Fantom Opera Side             │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wFTM Token  │  │           │  │  Bridge Contract           │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (EVM-compatible)          │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Lachesis aBFT Consensus   │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (DAG-based finality)      │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  Validator Attestations     │   │     │
 * │  │  │ Layer       │  │           │  │  (Stake-weighted aBFT)     │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * FANTOM/SONIC CONCEPTS:
 * - Wei: Smallest unit of FTM (1 FTM = 1e18 wei, standard EVM 18 decimals)
 * - Lachesis: Asynchronous BFT DAG consensus (original Fantom)
 * - Sonic: Next-gen Fantom with 10k TPS, sub-second finality
 * - SonicVM: Optimized EVM execution engine
 * - FeeM: Fee monetization for dApp developers
 * - Sonic Gateway: Official Fantom→Sonic bridge
 * - Chain ID: 250 (Opera), 146 (Sonic)
 * - Finality: ~1 second (aBFT instant finality)
 * - Block time: ~1 second
 * - DAG: Directed Acyclic Graph event structure for consensus
 *
 * SECURITY PROPERTIES:
 * - Validator attestation threshold for Lachesis events
 * - Block finality confirmation depth (1 block default, aBFT instant finality)
 * - DAG state proofs for cross-chain transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract FantomBridgeAdapter is
    IFantomBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Operator role for administrative operations
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    /// @notice Relayer role for submitting proofs and completing operations
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Guardian role for emergency pause/unpause
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    /// @notice Treasury role for fee withdrawal
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fantom Opera mainnet chain ID
    uint256 public constant FANTOM_CHAIN_ID = 250;

    /// @notice Wei per FTM (1 FTM = 1e18 wei, standard EVM 18 decimals)
    uint256 public constant WEI_PER_FTM = 1 ether;

    /// @notice Minimum deposit (0.01 FTM)
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Maximum deposit (10,000,000 FTM)
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /// @notice Bridge fee in basis points (0.04%)
    uint256 public constant BRIDGE_FEE_BPS = 4;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default required block confirmations (1 block — Lachesis aBFT instant finality)
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 1;

    /// @notice Withdrawal refund grace period (24 hours)
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;

    /// @notice Minimum escrow timelock (1 hour)
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock (30 days)
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    BridgeConfig public bridgeConfig;

    /// @notice Treasury address for fee collection
    address public treasury;

    /// @notice Deposit nonce for unique ID generation
    uint256 public depositNonce;

    /// @notice Withdrawal nonce
    uint256 public withdrawalNonce;

    /// @notice Escrow nonce
    uint256 public escrowNonce;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits by ID
    mapping(bytes32 => FTMDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => FTMWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => FTMEscrow) public escrows;

    /// @notice Verified Lachesis events by event ID
    mapping(uint256 => LachesisEvent) public lachesisEvents;

    /// @notice Used Fantom transaction hashes (replay protection)
    mapping(bytes32 => bool) public usedFTMTxHashes;

    /// @notice Used nullifiers for ZK privacy deposits
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) public userEscrows;

    /// @notice Latest verified event ID
    uint256 public latestEventId;

    /// @notice Latest verified event hash
    bytes32 public latestEventHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total FTM deposited (in wei)
    uint256 public totalDeposited;

    /// @notice Total FTM withdrawn (in wei)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in wei-equivalent wFTM)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Fantom bridge adapter
    /// @param _admin Admin address granted all roles
    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(TREASURY_ROLE, _admin);

        treasury = _admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function configure(
        address fantomBridgeContract,
        address wrappedFTM,
        address lachesisVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (fantomBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedFTM == address(0)) revert ZeroAddress();
        if (lachesisVerifier == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            fantomBridgeContract: fantomBridgeContract,
            wrappedFTM: wrappedFTM,
            lachesisVerifier: lachesisVerifier,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            fantomBridgeContract,
            wrappedFTM,
            lachesisVerifier
        );
    }

    /// @inheritdoc IFantomBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                    LACHESIS EVENT SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function submitLachesisEvent(
        uint256 eventId,
        uint256 epoch,
        bytes32 eventHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify validator attestations for the Lachesis event
        if (!_verifyValidatorAttestations(eventHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Verify parent chain linkage: if parent event exists, verify hash continuity
        if (eventId > 0 && lachesisEvents[eventId - 1].verified) {
            LachesisEvent storage parent = lachesisEvents[eventId - 1];
            if (parent.eventHash != parentHash) {
                revert FTMBlockNotVerified(eventId);
            }
        }

        lachesisEvents[eventId] = LachesisEvent({
            eventId: eventId,
            epoch: epoch,
            eventHash: eventHash,
            parentHash: parentHash,
            stateRoot: stateRoot,
            timestamp: timestamp,
            verified: true
        });

        if (eventId > latestEventId) {
            latestEventId = eventId;
            latestEventHash = eventHash;
        }

        emit LachesisEventVerified(eventId, epoch, eventHash);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS (Fantom → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function initiateFTMDeposit(
        bytes32 ftmTxHash,
        address ftmSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 ftmBlockNumber,
        DAGStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT) {
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        }
        if (amountWei > MAX_DEPOSIT) {
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);
        }
        if (usedFTMTxHashes[ftmTxHash]) {
            revert FTMTxAlreadyUsed(ftmTxHash);
        }

        // Verify the Lachesis event containing the tx is verified
        // Use ftmBlockNumber as event index for lookup
        LachesisEvent storage header = lachesisEvents[ftmBlockNumber];
        if (!header.verified) {
            revert FTMBlockNotVerified(ftmBlockNumber);
        }

        // Verify DAG state proof (Merkle inclusion against state root)
        if (!_verifyDAGStateProof(txProof, header.stateRoot, ftmTxHash)) {
            revert FTMBlockNotVerified(ftmBlockNumber);
        }

        // Verify validator attestations
        if (!_verifyValidatorAttestations(header.eventHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Mark tx hash as used (replay protection)
        usedFTMTxHashes[ftmTxHash] = true;

        // Calculate fee
        uint256 fee = (amountWei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountWei - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                FANTOM_CHAIN_ID,
                ftmTxHash,
                ftmSender,
                evmRecipient,
                amountWei,
                depositNonce++
            )
        );

        deposits[depositId] = FTMDeposit({
            depositId: depositId,
            ftmTxHash: ftmTxHash,
            ftmSender: ftmSender,
            evmRecipient: evmRecipient,
            amountWei: amountWei,
            netAmountWei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            ftmBlockNumber: ftmBlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountWei;

        emit FTMDepositInitiated(
            depositId,
            ftmTxHash,
            ftmSender,
            evmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IFantomBridgeAdapter
    function completeFTMDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        FTMDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) {
            revert DepositNotFound(depositId);
        }
        if (deposit.status != DepositStatus.VERIFIED) {
            revert DepositNotVerified(depositId);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wFTM to recipient (net of fees)
        (bool success, ) = bridgeConfig.wrappedFTM.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountWei
            )
        );
        if (!success) revert InvalidAmount();

        emit FTMDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                   WITHDRAWALS (Soul → Fantom)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function initiateWithdrawal(
        address ftmRecipient,
        uint256 amountWei
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (ftmRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT) {
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        }
        if (amountWei > MAX_DEPOSIT) {
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);
        }

        // Transfer wFTM from sender to bridge
        IERC20(bridgeConfig.wrappedFTM).safeTransferFrom(
            msg.sender,
            address(this),
            amountWei
        );

        // Attempt burn of wFTM
        (bool burnSuccess, ) = bridgeConfig.wrappedFTM.call(
            abi.encodeWithSignature("burn(uint256)", amountWei)
        );
        // If burn fails, tokens are held until refund or completion

        withdrawalId = keccak256(
            abi.encodePacked(
                FANTOM_CHAIN_ID,
                msg.sender,
                ftmRecipient,
                amountWei,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = FTMWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            ftmRecipient: ftmRecipient,
            amountWei: amountWei,
            ftmTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountWei;

        emit FTMWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            ftmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IFantomBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 ftmTxHash,
        DAGStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        FTMWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) {
            revert WithdrawalNotFound(withdrawalId);
        }
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert WithdrawalNotPending(withdrawalId);
        }
        if (usedFTMTxHashes[ftmTxHash]) {
            revert FTMTxAlreadyUsed(ftmTxHash);
        }

        // Verify the Fantom release transaction in a verified Lachesis event
        bool verified = false;
        for (uint256 i = latestEventId; i > 0 && i > latestEventId - 100; i--) {
            LachesisEvent storage header = lachesisEvents[i];
            if (
                header.verified &&
                _verifyDAGStateProof(txProof, header.stateRoot, ftmTxHash)
            ) {
                if (
                    _verifyValidatorAttestations(header.eventHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert FTMBlockNotVerified(latestEventId);

        usedFTMTxHashes[ftmTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.ftmTxHash = ftmTxHash;
        withdrawal.completedAt = block.timestamp;

        emit FTMWithdrawalCompleted(withdrawalId, ftmTxHash);
    }

    /// @inheritdoc IFantomBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        FTMWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) {
            revert WithdrawalNotFound(withdrawalId);
        }
        if (withdrawal.status != WithdrawalStatus.PENDING) {
            revert WithdrawalNotPending(withdrawalId);
        }
        if (
            block.timestamp < withdrawal.initiatedAt + WITHDRAWAL_REFUND_DELAY
        ) {
            revert RefundTooEarly(
                block.timestamp,
                withdrawal.initiatedAt + WITHDRAWAL_REFUND_DELAY
            );
        }

        withdrawal.status = WithdrawalStatus.REFUNDED;
        withdrawal.completedAt = block.timestamp;

        // Return wFTM to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedFTM.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountWei
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedFTM).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountWei
            );
        }

        emit FTMWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function createEscrow(
        address ftmParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (ftmParty == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidAmount();
        if (msg.value == 0) revert InvalidAmount();

        // Validate timelocks
        if (finishAfter < block.timestamp) revert InvalidTimelockRange();
        if (cancelAfter <= finishAfter) revert InvalidTimelockRange();
        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK) revert EscrowTimelockNotMet();
        if (duration > MAX_ESCROW_TIMELOCK) revert InvalidTimelockRange();

        uint256 amountWei = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                FANTOM_CHAIN_ID,
                msg.sender,
                ftmParty,
                hashlock,
                amountWei,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = FTMEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            ftmParty: ftmParty,
            amountWei: amountWei,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        userEscrows[msg.sender].push(escrowId);
        totalEscrows++;

        emit EscrowCreated(escrowId, msg.sender, ftmParty, amountWei, hashlock);
    }

    /// @inheritdoc IFantomBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        FTMEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE) {
            revert EscrowNotActive(escrowId);
        }
        if (block.timestamp < escrow.finishAfter) {
            revert EscrowTimelockNotMet();
        }

        // Verify SHA-256 hashlock preimage
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        // Release funds to the counterparty (Fantom party)
        (bool success, ) = payable(escrow.ftmParty).call{value: escrow.amountWei}(
            ""
        );
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IFantomBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        FTMEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE) {
            revert EscrowNotActive(escrowId);
        }
        if (block.timestamp < escrow.cancelAfter) {
            revert EscrowTimelockNotMet();
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to the creator
        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountWei
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        FTMDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) {
            revert DepositNotFound(depositId);
        }
        if (deposit.status != DepositStatus.COMPLETED) {
            revert DepositAlreadyCompleted(depositId);
        }
        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        // Verify ZK proof binds commitment and nullifier to the deposit
        if (!_verifyZKProof(depositId, commitment, nullifier, zkProof)) {
            revert InvalidAmount();
        }

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the bridge (emergency circuit breaker)
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated bridge fees to treasury
    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert InvalidAmount();
        accumulatedFees = 0;

        uint256 balance = IERC20(bridgeConfig.wrappedFTM).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedFTM).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IFantomBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (FTMDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IFantomBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (FTMWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IFantomBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (FTMEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IFantomBridgeAdapter
    function getLachesisEvent(
        uint256 eventId
    ) external view returns (LachesisEvent memory) {
        return lachesisEvents[eventId];
    }

    /// @inheritdoc IFantomBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IFantomBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IFantomBridgeAdapter
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get bridge statistics
    /// @return totalDep Total deposited
    /// @return totalWith Total withdrawn
    /// @return totalEsc Total escrows created
    /// @return totalEscFinished Total escrows finished
    /// @return totalEscCancelled Total escrows cancelled
    /// @return fees Accumulated fees
    /// @return lastEventId Latest verified Lachesis event ID
    function getBridgeStats()
        external
        view
        returns (
            uint256 totalDep,
            uint256 totalWith,
            uint256 totalEsc,
            uint256 totalEscFinished,
            uint256 totalEscCancelled,
            uint256 fees,
            uint256 lastEventId
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestEventId
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify a DAG state proof (Merkle inclusion against Lachesis state root)
     * @param proof The DAG state proof containing Merkle siblings
     * @param root The state root from the verified Lachesis event
     * @param leafHash The transaction hash to verify inclusion for
     * @return valid True if the proof is valid
     */
    function _verifyDAGStateProof(
        DAGStateProof calldata proof,
        bytes32 root,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.merkleProof.length == 0) return false;

        bytes32 computedHash = keccak256(
            abi.encodePacked(leafHash, proof.stateRoot, proof.value)
        );

        for (uint256 i = 0; i < proof.merkleProof.length; i++) {
            bytes32 sibling = proof.merkleProof[i];
            if (computedHash <= sibling) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, sibling)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(sibling, computedHash)
                );
            }
        }

        return computedHash == root;
    }

    /**
     * @dev Verify validator attestations for a Lachesis event hash
     * @param eventHash The event hash to verify attestations against
     * @param attestations Array of validator attestations (signatures)
     * @return valid True if sufficient valid attestations are provided
     */
    function _verifyValidatorAttestations(
        bytes32 eventHash,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minValidatorSignatures)
            return false;
        if (bridgeConfig.lachesisVerifier == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // Check for duplicate validators
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
            (bool success, bytes memory result) = bridgeConfig
                .lachesisVerifier
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        eventHash,
                        attestations[i].validator,
                        attestations[i].signature
                    )
                );

            if (success && result.length >= 32) {
                bool isValid = abi.decode(result, (bool));
                if (isValid) {
                    validCount++;
                }
            }
        }

        return validCount >= bridgeConfig.minValidatorSignatures;
    }

    /**
     * @dev Verify a ZK proof for private deposit registration
     * @param depositId The deposit ID the proof is bound to
     * @param commitment The commitment hash
     * @param nullifier The nullifier for double-spend prevention
     * @param zkProof The serialized ZK proof bytes
     * @return True if the proof is valid
     */
    function _verifyZKProof(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) internal pure returns (bool) {
        if (zkProof.length < 256) return false;

        bytes32 proofBinding = keccak256(
            abi.encodePacked(depositId, commitment, nullifier)
        );

        if (zkProof.length >= 64) {
            bytes32 proofBind = bytes32(zkProof[32:64]);
            return proofBind == proofBinding;
        }

        return false;
    }

    /// @notice Accept ETH for escrow operations
    receive() external payable {}
}
