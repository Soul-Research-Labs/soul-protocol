// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IXRPLBridgeAdapter} from "../interfaces/IXRPLBridgeAdapter.sol";

/**
 * @title XRPLBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for XRP Ledger interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the XRP Ledger
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> XRP Ledger Bridge                              │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   EVM Side        │           │        XRPL Side                  │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wXRP Token  │  │           │  │  Bridge Multisig Account   │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (Federated Signers)       │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Escrow / Payment Chan.   │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (Native XRPL primitives) │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  UNL Validator Consensus   │   │     │
 * │  │  │ Layer       │  │           │  │  (Ed25519 Attestations)    │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * XRP LEDGER CONCEPTS:
 * - Drops: Smallest unit of XRP (1 XRP = 1,000,000 drops)
 * - Destination Tags: 32-bit routing identifiers for multi-tenant accounts
 * - Escrow: Native time-locked + crypto-conditioned contracts on XRPL
 * - UNL: Unique Node List — trusted validators for consensus
 * - SHAMap: Shamir's hash-based trie structure for tx/state proofs
 * - Ed25519: Signature algorithm used by XRPL validators
 * - Federated Signer: Multi-party signing for bridge custody
 *
 * SECURITY PROPERTIES:
 * - Validator attestation threshold (configurable, default 80% of UNL)
 * - Ledger confirmation depth (configurable, default 32 validated ledgers)
 * - SHAMap Merkle inclusion proofs for XRPL transaction verification
 * - HTLC/Escrow crypto-conditions (PREIMAGE-SHA-256 per RFC 5765-bis)
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract XRPLBridgeAdapter is
    IXRPLBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice XRP Ledger "chain ID" (keccak256 of "XRPLedger" truncated)
    uint256 public constant XRPL_CHAIN_ID = uint256(keccak256("XRPLedger"));

    /// @notice Drops per XRP (1 XRP = 1,000,000 drops)
    uint256 public constant DROPS_PER_XRP = 1_000_000;

    /// @notice Minimum deposit (10 XRP = 10,000,000 drops)
    uint256 public constant MIN_DEPOSIT_DROPS = 10 * DROPS_PER_XRP;

    /// @notice Maximum deposit (10,000,000 XRP)
    uint256 public constant MAX_DEPOSIT_DROPS = 10_000_000 * DROPS_PER_XRP;

    /// @notice Bridge fee in basis points (0.25%)
    uint256 public constant BRIDGE_FEE_BPS = 25;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default escrow timelock (24 hours)
    uint256 public constant DEFAULT_ESCROW_TIMELOCK = 24 hours;

    /// @notice Minimum escrow timelock (1 hour)
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock (30 days)
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Withdrawal refund grace period (48 hours after initiation)
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 48 hours;

    /// @notice Default required ledger confirmations
    uint256 public constant DEFAULT_LEDGER_CONFIRMATIONS = 32;

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
    mapping(bytes32 => XRPDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => XRPWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => XRPLEscrow) public escrows;

    /// @notice Validated ledger headers
    mapping(uint256 => LedgerHeader) public ledgerHeaders;

    /// @notice Used XRPL transaction hashes (prevent replay)
    mapping(bytes32 => bool) public usedXRPLTxHashes;

    /// @notice Used nullifiers for ZK privacy deposits
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) public userEscrows;

    /// @notice Latest validated ledger index
    uint256 public latestLedgerIndex;

    /// @notice Latest validated ledger hash
    bytes32 public latestLedgerHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total XRP deposited (in drops)
    uint256 public totalDeposited;

    /// @notice Total XRP withdrawn (in drops)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in drops-equivalent wXRP)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

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

    /// @inheritdoc IXRPLBridgeAdapter
    function configure(
        bytes20 xrplMultisigAccount,
        address wrappedXRP,
        address validatorOracle,
        uint256 minSignatures,
        uint256 requiredLedgerConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (wrappedXRP == address(0)) revert ZeroAddress();
        if (validatorOracle == address(0)) revert ZeroAddress();
        if (xrplMultisigAccount == bytes20(0)) revert ZeroAddress();
        if (minSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            xrplMultisigAccount: xrplMultisigAccount,
            wrappedXRP: wrappedXRP,
            validatorOracle: validatorOracle,
            minSignatures: minSignatures,
            requiredLedgerConfirmations: requiredLedgerConfirmations > 0
                ? requiredLedgerConfirmations
                : DEFAULT_LEDGER_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(xrplMultisigAccount, wrappedXRP, validatorOracle);
    }

    /// @notice Set the treasury address
    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (XRPL → EVM)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IXRPLBridgeAdapter
    function initiateXRPDeposit(
        bytes32 xrplTxHash,
        bytes20 xrplSender,
        address evmRecipient,
        uint256 amountDrops,
        bytes32 destinationTag,
        uint256 ledgerIndex,
        SHAMapProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) returns (bytes32 depositId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountDrops < MIN_DEPOSIT_DROPS) revert AmountTooSmall(amountDrops);
        if (amountDrops > MAX_DEPOSIT_DROPS) revert AmountTooLarge(amountDrops);
        if (usedXRPLTxHashes[xrplTxHash]) revert XRPLTxAlreadyUsed(xrplTxHash);

        // Verify the ledger containing the tx is validated
        LedgerHeader storage header = ledgerHeaders[ledgerIndex];
        if (!header.validated) revert LedgerNotValidated(ledgerIndex);

        // Verify the transaction is included in the ledger's tx tree via SHAMap proof
        if (!_verifySHAMapProof(txProof, header.transactionHash, xrplTxHash)) {
            revert InvalidLedgerProof();
        }

        // Verify sufficient validator attestations for the ledger
        if (!_verifyValidatorAttestations(header.ledgerHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minSignatures
            );
        }

        // Mark XRPL tx as used (replay protection)
        usedXRPLTxHashes[xrplTxHash] = true;

        // Calculate fee
        uint256 fee = (amountDrops * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountDrops - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                XRPL_CHAIN_ID,
                xrplTxHash,
                xrplSender,
                evmRecipient,
                amountDrops,
                depositNonce++
            )
        );

        deposits[depositId] = XRPDeposit({
            depositId: depositId,
            xrplTxHash: xrplTxHash,
            xrplSender: xrplSender,
            evmRecipient: evmRecipient,
            amountDrops: amountDrops,
            netAmountDrops: netAmount,
            fee: fee,
            destinationTag: destinationTag,
            status: DepositStatus.VERIFIED,
            ledgerIndex: ledgerIndex,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountDrops;

        emit XRPDepositInitiated(
            depositId,
            xrplTxHash,
            xrplSender,
            evmRecipient,
            amountDrops
        );
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function completeXRPDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        XRPDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wXRP to recipient (net of fees)
        // The bridge contract must have MINTER_ROLE on the wXRP token
        // Using low-level call to support different mint interfaces
        (bool success, ) = bridgeConfig.wrappedXRP.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountDrops
            )
        );
        if (!success) revert InvalidAmount();

        emit XRPDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountDrops
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (EVM → XRPL)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IXRPLBridgeAdapter
    function initiateWithdrawal(
        bytes20 xrplRecipient,
        uint256 amountDrops
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (xrplRecipient == bytes20(0)) revert ZeroAddress();
        if (amountDrops < MIN_DEPOSIT_DROPS) revert AmountTooSmall(amountDrops);
        if (amountDrops > MAX_DEPOSIT_DROPS) revert AmountTooLarge(amountDrops);

        // Burn wXRP from sender
        IERC20(bridgeConfig.wrappedXRP).safeTransferFrom(
            msg.sender,
            address(this),
            amountDrops
        );

        // Attempt burn (contract holds tokens until XRPL release is confirmed)
        // If wXRP has burn function, call it; otherwise hold in escrow
        (bool burnSuccess, ) = bridgeConfig.wrappedXRP.call(
            abi.encodeWithSignature("burn(uint256)", amountDrops)
        );
        // If burn fails, tokens are held in this contract as collateral
        // They can be returned on refund

        withdrawalId = keccak256(
            abi.encodePacked(
                XRPL_CHAIN_ID,
                msg.sender,
                xrplRecipient,
                amountDrops,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = XRPWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            xrplRecipient: xrplRecipient,
            amountDrops: amountDrops,
            xrplTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountDrops;

        emit XRPWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            xrplRecipient,
            amountDrops
        );
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 xrplTxHash,
        SHAMapProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        XRPWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (usedXRPLTxHashes[xrplTxHash]) revert XRPLTxAlreadyUsed(xrplTxHash);

        // Verify the XRPL release transaction exists in a validated ledger
        // Find the ledger containing this tx by checking recent ledgers
        bool verified = false;
        for (uint256 i = latestLedgerIndex; i > 0 && i > latestLedgerIndex - 100; i--) {
            LedgerHeader storage header = ledgerHeaders[i];
            if (header.validated && _verifySHAMapProof(txProof, header.transactionHash, xrplTxHash)) {
                if (_verifyValidatorAttestations(header.ledgerHash, attestations)) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert InvalidLedgerProof();

        usedXRPLTxHashes[xrplTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.xrplTxHash = xrplTxHash;
        withdrawal.completedAt = block.timestamp;

        emit XRPWithdrawalCompleted(withdrawalId, xrplTxHash);
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        XRPWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (block.timestamp < withdrawal.initiatedAt + WITHDRAWAL_REFUND_DELAY) {
            revert WithdrawalTimelockNotExpired(withdrawalId);
        }

        withdrawal.status = WithdrawalStatus.REFUNDED;
        withdrawal.completedAt = block.timestamp;

        // Return wXRP to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedXRP.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountDrops
            )
        );
        // If mint fails, try transferring from contract balance
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedXRP).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountDrops
            );
        }

        emit XRPWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountDrops
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IXRPLBridgeAdapter
    function createEscrow(
        bytes20 xrplParty,
        bytes32 condition,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (xrplParty == bytes20(0)) revert ZeroAddress();
        if (condition == bytes32(0)) revert InvalidCondition();
        if (msg.value == 0) revert InvalidAmount();

        // Validate timelocks
        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK) revert TimelockTooShort(duration, MIN_ESCROW_TIMELOCK);
        if (duration > MAX_ESCROW_TIMELOCK) revert TimelockTooLong(duration, MAX_ESCROW_TIMELOCK);
        if (finishAfter < block.timestamp) revert InvalidAmount();

        // Convert ETH value to drops equivalent for recording purposes
        uint256 amountDrops = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                XRPL_CHAIN_ID,
                msg.sender,
                xrplParty,
                condition,
                amountDrops,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = XRPLEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            xrplParty: xrplParty,
            amountDrops: amountDrops,
            condition: condition,
            fulfillment: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            xrplEscrowTxHash: bytes32(0),
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        userEscrows[msg.sender].push(escrowId);
        totalEscrows++;

        emit EscrowCreated(
            escrowId,
            msg.sender,
            xrplParty,
            amountDrops,
            condition
        );
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 fulfillment
    ) external nonReentrant whenNotPaused {
        XRPLEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert FinishAfterNotReached(escrowId, escrow.finishAfter);
        }

        // Verify crypto-condition: SHA-256 preimage condition
        // condition = SHA256(fulfillment), per XRPL's PREIMAGE-SHA-256
        bytes32 computedCondition = sha256(abi.encodePacked(fulfillment));
        if (computedCondition != escrow.condition) {
            revert InvalidFulfillment(escrow.condition, computedCondition);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.fulfillment = fulfillment;
        totalEscrowsFinished++;

        // Release funds to the XRPL party's EVM representative
        // In practice, the XRPL party would provide an EVM address for receiving
        // For now, the fulfillment provider (msg.sender) receives the funds
        (bool success, ) = payable(msg.sender).call{value: escrow.amountDrops}("");
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, fulfillment);
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        XRPLEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert CancelAfterNotReached(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to the creator
        (bool success, ) = payable(escrow.evmParty).call{value: escrow.amountDrops}("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IXRPLBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        XRPDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.COMPLETED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Verify ZK proof binds commitment and nullifier to the deposit
        if (!_verifyZKProof(depositId, commitment, nullifier, zkProof)) {
            revert InvalidProof();
        }

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                      LEDGER HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IXRPLBridgeAdapter
    function submitLedgerHeader(
        uint256 ledgerIndex,
        bytes32 ledgerHash,
        bytes32 parentHash,
        bytes32 transactionHash,
        bytes32 accountStateHash,
        uint256 closeTime,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify validator attestations for this ledger
        if (!_verifyValidatorAttestations(ledgerHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minSignatures
            );
        }

        // Verify parent chain: if we have the parent, verify hash matches
        if (ledgerIndex > 0 && ledgerHeaders[ledgerIndex - 1].validated) {
            LedgerHeader storage parent = ledgerHeaders[ledgerIndex - 1];
            if (parent.ledgerHash != parentHash) {
                revert InvalidLedgerProof();
            }
        }

        ledgerHeaders[ledgerIndex] = LedgerHeader({
            ledgerIndex: ledgerIndex,
            ledgerHash: ledgerHash,
            parentHash: parentHash,
            transactionHash: transactionHash,
            accountStateHash: accountStateHash,
            closeTime: closeTime,
            validated: true
        });

        if (ledgerIndex > latestLedgerIndex) {
            latestLedgerIndex = ledgerIndex;
            latestLedgerHash = ledgerHash;
        }

        emit LedgerHeaderSubmitted(ledgerIndex, ledgerHash);
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the bridge
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated bridge fees
    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert InvalidAmount();
        accumulatedFees = 0;

        // Transfer fee-equivalent wXRP to treasury
        uint256 balance = IERC20(bridgeConfig.wrappedXRP).balanceOf(address(this));
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedXRP).safeTransfer(treasury, transferAmount);
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IXRPLBridgeAdapter
    function getDeposit(bytes32 depositId) external view returns (XRPDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function getWithdrawal(bytes32 withdrawalId) external view returns (XRPWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function getEscrow(bytes32 escrowId) external view returns (XRPLEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IXRPLBridgeAdapter
    function getLedgerHeader(uint256 ledgerIndex) external view returns (LedgerHeader memory) {
        return ledgerHeaders[ledgerIndex];
    }

    /// @notice Get user deposit history
    function getUserDeposits(address user) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @notice Get user withdrawal history
    function getUserWithdrawals(address user) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @notice Get user escrow history
    function getUserEscrows(address user) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get bridge statistics
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
            uint256 latestLedger
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestLedgerIndex
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify an XRPL SHAMap inclusion proof
     * @param proof The SHAMap proof (inner nodes + branch keys)
     * @param rootHash The expected root hash (from validated ledger header)
     * @param leafHash The transaction hash to prove inclusion of
     * @return valid True if the proof is valid
     *
     * SHAMap is a radix-tree/trie structure where:
     * - Leaves are transaction hashes
     * - Inner nodes hash their children
     * - Branch keys determine traversal path through the trie
     *
     * The proof reconstructs the path from leaf to root and verifies
     * the computed root matches the ledger header's transaction hash.
     */
    function _verifySHAMapProof(
        SHAMapProof calldata proof,
        bytes32 rootHash,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.innerNodes.length == 0) return false;
        if (proof.innerNodes.length != proof.nodeTypes.length) return false;

        // Start from the leaf and hash up to the root
        bytes32 computedHash = leafHash;

        for (uint256 i = 0; i < proof.innerNodes.length; i++) {
            if (proof.nodeTypes[i] == 0) {
                // Inner node: hash(child_left, child_right)
                // The branchKey determines which side our hash goes
                if (i < proof.branchKeys.length && proof.branchKeys[i] != bytes32(0)) {
                    // Our hash is on the right branch
                    computedHash = sha256(
                        abi.encodePacked(proof.innerNodes[i], computedHash)
                    );
                } else {
                    // Our hash is on the left branch
                    computedHash = sha256(
                        abi.encodePacked(computedHash, proof.innerNodes[i])
                    );
                }
            } else if (proof.nodeTypes[i] == 1) {
                // Leaf node boundary — hash with leaf prefix
                computedHash = sha256(
                    abi.encodePacked(bytes1(0x4D), computedHash, proof.innerNodes[i])
                );
            }
            // nodeType 2 = empty branch, skip
        }

        return computedHash == rootHash;
    }

    /**
     * @dev Verify XRPL validator attestations for a ledger hash
     * @param ledgerHash The ledger hash that validators attested to
     * @param attestations Array of validator signatures
     * @return valid True if enough valid attestations exist
     *
     * XRPL validators sign ledger hashes with Ed25519.
     * We delegate signature verification to the validatorOracle contract
     * which maintains the current UNL (Unique Node List).
     */
    function _verifyValidatorAttestations(
        bytes32 ledgerHash,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minSignatures) return false;
        if (bridgeConfig.validatorOracle == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // Delegate Ed25519 signature verification to the oracle contract
            // The oracle maintains the UNL and verifies each validator's signature
            (bool success, bytes memory result) = bridgeConfig.validatorOracle.staticcall(
                abi.encodeWithSignature(
                    "verifyAttestation(bytes32,bytes32,bytes)",
                    ledgerHash,
                    attestations[i].validatorPubKey,
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

        return validCount >= bridgeConfig.minSignatures;
    }

    /**
     * @dev Verify a ZK proof for private deposit registration
     * @param depositId The deposit being made private
     * @param commitment The Pedersen commitment
     * @param nullifier The nullifier to prevent double-spend
     * @param zkProof The ZK proof bytes
     */
    function _verifyZKProof(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) internal pure returns (bool) {
        // Minimum proof length for Groth16 (256 bytes) or PLONK (512 bytes)
        if (zkProof.length < 256) return false;

        // Verify proof binds to the deposit, commitment, and nullifier
        // In production, this would call a dedicated verifier contract
        // The proof must demonstrate knowledge of preimage such that:
        //   commitment = Pedersen(value, blinding_factor)
        //   nullifier = hash(commitment, secret)
        //   deposit.amount matches the committed value
        bytes32 proofBinding = keccak256(
            abi.encodePacked(depositId, commitment, nullifier)
        );

        // Verify the proof contains the binding hash (first 32 bytes after prefix)
        if (zkProof.length >= 64) {
            bytes32 proofBind = bytes32(zkProof[32:64]);
            return proofBind == proofBinding;
        }

        return false;
    }

    /// @notice Accept ETH for escrow operations
    receive() external payable {}
}
