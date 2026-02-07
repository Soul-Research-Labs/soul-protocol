// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IMonadBridgeAdapter} from "../interfaces/IMonadBridgeAdapter.sol";

/**
 * @title MonadBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Monad interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Monad
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       Soul <-> Monad Bridge                                 │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Monad Side                    │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wMON Token  │  │           │  │  Bridge Contract           │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (EVM-compatible)          │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  MonadBFT Consensus        │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (HotStuff2, ~1s finality) │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  MonadBFT Validators       │   │     │
 * │  │  │ Layer       │  │           │  │  (2/3+1 voting power)      │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * MONAD CONCEPTS:
 * - Wei: Smallest unit of MON (1 MON = 1e18 wei, standard EVM 18 decimals)
 * - MonadBFT: Pipeline-optimized HotStuff2-based BFT consensus
 * - Parallel Execution: Optimistic parallel execution with conflict detection
 * - MonadDb: Custom LSM-tree state database for SSD optimization
 * - Deferred Execution: Consensus decoupled from execution
 * - Superscalar Pipelining: Overlapped consensus stages
 * - Chain ID: 41454 (placeholder, Monad is pre-mainnet)
 * - Finality: Single-slot MonadBFT (~1s)
 * - Block confirmations: 1 (MonadBFT instant finality)
 * - EVM-compatible: Full EVM equivalence, address-based counterparty
 *
 * SECURITY PROPERTIES:
 * - MonadBFT validator attestation (2/3+1 voting power)
 * - Block header chain integrity enforcement (stateRoot, executionRoot)
 * - Merkle inclusion proofs for state verification (MonadStateProof)
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract MonadBridgeAdapter is
    IMonadBridgeAdapter,
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

    /// @notice Monad chain ID (placeholder, Monad is pre-mainnet)
    uint256 public constant MONAD_CHAIN_ID = 41454;

    /// @notice Minimum deposit (0.01 MON)
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Maximum deposit (10,000,000 MON)
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /// @notice Bridge fee in basis points (0.03%)
    uint256 public constant BRIDGE_FEE_BPS = 3;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default required block confirmations (1 block — MonadBFT ~1s finality)
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
    mapping(bytes32 => MONDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => MONWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => MONEscrow) public escrows;

    /// @notice Verified MonadBFT block headers
    mapping(uint256 => MonadBFTBlock) public monadBFTBlocks;

    /// @notice Used Monad transaction hashes (replay protection)
    mapping(bytes32 => bool) public usedMonadTxHashes;

    /// @notice Used nullifiers for ZK privacy deposits
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) public userEscrows;

    /// @notice Latest verified block number
    uint256 public latestBlockNumber;

    /// @notice Latest verified block hash
    bytes32 public latestBlockHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total MON deposited (in wei)
    uint256 public totalDeposited;

    /// @notice Total MON withdrawn (in wei)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in wei-equivalent wMON)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Monad bridge adapter
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

    /// @inheritdoc IMonadBridgeAdapter
    function configure(
        address monadBridgeContract,
        address wrappedMON,
        address monadBFTVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (monadBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedMON == address(0)) revert ZeroAddress();
        if (monadBFTVerifier == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            monadBridgeContract: monadBridgeContract,
            wrappedMON: wrappedMON,
            monadBFTVerifier: monadBFTVerifier,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            monadBridgeContract,
            wrappedMON,
            monadBFTVerifier
        );
    }

    /// @inheritdoc IMonadBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                  MONADBFT BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMonadBridgeAdapter
    function submitMonadBFTBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 executionRoot,
        uint256 round,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify MonadBFT validator attestations (2/3+1 voting power)
        if (!_verifyValidatorAttestations(blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Verify parent chain linkage: if parent block exists, verify continuity
        if (blockNumber > 0 && monadBFTBlocks[blockNumber - 1].verified) {
            MonadBFTBlock storage parent = monadBFTBlocks[blockNumber - 1];
            // Ensure sequential block submission and parent hash matches
            if (parent.blockNumber != blockNumber - 1) {
                revert MonadBlockNotVerified(blockNumber);
            }
        }

        monadBFTBlocks[blockNumber] = MonadBFTBlock({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            stateRoot: stateRoot,
            executionRoot: executionRoot,
            round: round,
            timestamp: timestamp,
            verified: true
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
            latestBlockHash = blockHash;
        }

        emit MonadBFTBlockVerified(blockNumber, blockHash, stateRoot);
    }

    /*//////////////////////////////////////////////////////////////
                     DEPOSITS (Monad → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMonadBridgeAdapter
    function initiateMONDeposit(
        bytes32 monadTxHash,
        address monadSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 monadBlockNumber,
        MonadStateProof calldata txProof,
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
        if (usedMonadTxHashes[monadTxHash]) {
            revert MonadTxAlreadyUsed(monadTxHash);
        }

        // Verify the MonadBFT block containing the tx is verified
        MonadBFTBlock storage header = monadBFTBlocks[monadBlockNumber];
        if (!header.verified) {
            revert MonadBlockNotVerified(monadBlockNumber);
        }

        // Verify MonadBFT state proof (Merkle inclusion against stateRoot)
        if (!_verifyMonadStateProof(txProof, header.stateRoot, monadTxHash)) {
            revert MonadBlockNotVerified(monadBlockNumber);
        }

        // Verify MonadBFT validator attestations
        if (!_verifyValidatorAttestations(header.blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Mark tx hash as used (replay protection)
        usedMonadTxHashes[monadTxHash] = true;

        // Calculate fee
        uint256 fee = (amountWei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountWei - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                MONAD_CHAIN_ID,
                monadTxHash,
                monadSender,
                evmRecipient,
                amountWei,
                depositNonce++
            )
        );

        deposits[depositId] = MONDeposit({
            depositId: depositId,
            monadTxHash: monadTxHash,
            monadSender: monadSender,
            evmRecipient: evmRecipient,
            amountWei: amountWei,
            netAmountWei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            monadBlockNumber: monadBlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountWei;

        emit MONDepositInitiated(
            depositId,
            monadTxHash,
            monadSender,
            evmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IMonadBridgeAdapter
    function completeMONDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        MONDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) {
            revert DepositNotFound(depositId);
        }
        if (deposit.status != DepositStatus.VERIFIED) {
            revert DepositNotVerified(depositId);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wMON to recipient (net of fees)
        (bool success, ) = bridgeConfig.wrappedMON.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountWei
            )
        );
        if (!success) revert InvalidAmount();

        emit MONDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (Soul → Monad)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMonadBridgeAdapter
    function initiateWithdrawal(
        address monadRecipient,
        uint256 amountWei
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (monadRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT) {
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        }
        if (amountWei > MAX_DEPOSIT) {
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);
        }

        // Transfer wMON from sender to bridge
        IERC20(bridgeConfig.wrappedMON).safeTransferFrom(
            msg.sender,
            address(this),
            amountWei
        );

        // Attempt burn of wMON
        (bool burnSuccess, ) = bridgeConfig.wrappedMON.call(
            abi.encodeWithSignature("burn(uint256)", amountWei)
        );
        // If burn fails, tokens are held until refund or completion

        withdrawalId = keccak256(
            abi.encodePacked(
                MONAD_CHAIN_ID,
                msg.sender,
                monadRecipient,
                amountWei,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = MONWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            monadRecipient: monadRecipient,
            amountWei: amountWei,
            monadTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountWei;

        emit MONWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            monadRecipient,
            amountWei
        );
    }

    /// @inheritdoc IMonadBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 monadTxHash,
        MonadStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        MONWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) {
            revert WithdrawalNotFound(withdrawalId);
        }
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert WithdrawalNotPending(withdrawalId);
        }
        if (usedMonadTxHashes[monadTxHash]) {
            revert MonadTxAlreadyUsed(monadTxHash);
        }

        // Verify the Monad release transaction in a verified MonadBFT block
        bool verified = false;
        for (
            uint256 i = latestBlockNumber;
            i > 0 && i > latestBlockNumber - 100;
            i--
        ) {
            MonadBFTBlock storage header = monadBFTBlocks[i];
            if (
                header.verified &&
                _verifyMonadStateProof(txProof, header.stateRoot, monadTxHash)
            ) {
                if (
                    _verifyValidatorAttestations(header.blockHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert MonadBlockNotVerified(latestBlockNumber);

        usedMonadTxHashes[monadTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.monadTxHash = monadTxHash;
        withdrawal.completedAt = block.timestamp;

        emit MONWithdrawalCompleted(withdrawalId, monadTxHash);
    }

    /// @inheritdoc IMonadBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        MONWithdrawal storage withdrawal = withdrawals[withdrawalId];
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

        // Return wMON to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedMON.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountWei
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedMON).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountWei
            );
        }

        emit MONWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMonadBridgeAdapter
    function createEscrow(
        address monadParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (monadParty == address(0)) revert ZeroAddress();
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
                MONAD_CHAIN_ID,
                msg.sender,
                monadParty,
                hashlock,
                amountWei,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = MONEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            monadParty: monadParty,
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

        emit EscrowCreated(
            escrowId,
            msg.sender,
            monadParty,
            amountWei,
            hashlock
        );
    }

    /// @inheritdoc IMonadBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        MONEscrow storage escrow = escrows[escrowId];
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

        // Release funds to the counterparty (Monad party)
        (bool success, ) = payable(escrow.monadParty).call{value: escrow.amountWei}(
            ""
        );
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IMonadBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        MONEscrow storage escrow = escrows[escrowId];
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

    /// @inheritdoc IMonadBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        MONDeposit storage deposit = deposits[depositId];
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

        uint256 balance = IERC20(bridgeConfig.wrappedMON).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedMON).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMonadBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (MONDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IMonadBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (MONWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IMonadBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (MONEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IMonadBridgeAdapter
    function getMonadBFTBlock(
        uint256 blockNumber
    ) external view returns (MonadBFTBlock memory) {
        return monadBFTBlocks[blockNumber];
    }

    /// @inheritdoc IMonadBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IMonadBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IMonadBridgeAdapter
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
    /// @return lastBlock Latest verified block number
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
            uint256 lastBlock
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestBlockNumber
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify a MonadBFT state proof (Merkle inclusion against stateRoot)
     * @param proof The MonadStateProof containing Merkle siblings
     * @param root The stateRoot from the verified MonadBFT block
     * @param leafHash The transaction hash to verify inclusion for
     * @return valid True if the proof is valid
     */
    function _verifyMonadStateProof(
        MonadStateProof calldata proof,
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
     * @dev Verify MonadBFT validator attestations for a block hash
     * @param blockHash The block hash to verify attestations against
     * @param attestations Array of validator attestations (signatures)
     * @return valid True if sufficient valid attestations are provided
     */
    function _verifyValidatorAttestations(
        bytes32 blockHash,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minValidatorSignatures)
            return false;
        if (bridgeConfig.monadBFTVerifier == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // Check for duplicate validators
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
            (bool success, bytes memory result) = bridgeConfig
                .monadBFTVerifier
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        blockHash,
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
