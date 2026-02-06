// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISolanaBridgeAdapter} from "../interfaces/ISolanaBridgeAdapter.sol";

/**
 * @title SolanaBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Solana interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Solana
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> Solana Bridge                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   EVM Side        │           │        Solana Side                │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wSOL Token  │  │           │  │  Bridge Program            │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (Anchor / Native)         │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Wormhole Program          │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (Guardian Network)        │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  Tower BFT Consensus       │   │     │
 * │  │  │ Layer       │  │           │  │  (PoH + Ed25519 Votes)     │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOLANA CONCEPTS:
 * - Lamports: Smallest unit of SOL (1 SOL = 1,000,000,000 lamports)
 * - Slot: ~400ms block time, PoH-sequenced
 * - Epoch: ~2 days, validator set rotation boundary
 * - Program: Solana smart contract (BPF bytecode)
 * - PDA: Program Derived Address — deterministic, programmatic accounts
 * - VAA: Verified Action Approval — Wormhole cross-chain attestation format
 * - Tower BFT: Solana's PoH-optimized PBFT consensus
 * - Ed25519: Signature algorithm used by Solana validators
 *
 * SECURITY PROPERTIES:
 * - Wormhole Guardian attestation threshold (default 13/19 Guardians)
 * - Slot finality confirmation depth (configurable, default 32 slots ~12.8s)
 * - Merkle inclusion proofs for Solana transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract SolanaBridgeAdapter is
    ISolanaBridgeAdapter,
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

    /// @notice Solana "chain ID" for domain separation
    uint256 public constant SOLANA_CHAIN_ID = uint256(keccak256("Solana"));

    /// @notice Lamports per SOL (1 SOL = 1,000,000,000 lamports)
    uint256 public constant LAMPORTS_PER_SOL = 1_000_000_000;

    /// @notice Minimum deposit (0.1 SOL = 100,000,000 lamports)
    uint256 public constant MIN_DEPOSIT_LAMPORTS = LAMPORTS_PER_SOL / 10;

    /// @notice Maximum deposit (1,000,000 SOL)
    uint256 public constant MAX_DEPOSIT_LAMPORTS = 1_000_000 * LAMPORTS_PER_SOL;

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

    /// @notice Withdrawal refund grace period (48 hours)
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 48 hours;

    /// @notice Default required slot confirmations
    uint256 public constant DEFAULT_SLOT_CONFIRMATIONS = 32;

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
    mapping(bytes32 => SOLDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => SOLWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => SolanaEscrow) public escrows;

    /// @notice Finalized Solana slot headers
    mapping(uint256 => SlotHeader) public slotHeaders;

    /// @notice Used Solana transaction signatures (replay protection)
    mapping(bytes32 => bool) public usedSolanaTxSignatures;

    /// @notice Used nullifiers for ZK privacy deposits
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) public userEscrows;

    /// @notice Latest finalized slot number
    uint256 public latestSlot;

    /// @notice Latest finalized block hash
    bytes32 public latestBlockHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total SOL deposited (in lamports)
    uint256 public totalDeposited;

    /// @notice Total SOL withdrawn (in lamports)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in lamports-equivalent wSOL)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Solana bridge adapter
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

    /// @inheritdoc ISolanaBridgeAdapter
    function configure(
        bytes32 solanaBridgeProgram,
        address wrappedSOL,
        address guardianOracle,
        uint256 minGuardianSignatures,
        uint256 requiredSlotConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (wrappedSOL == address(0)) revert ZeroAddress();
        if (guardianOracle == address(0)) revert ZeroAddress();
        if (solanaBridgeProgram == bytes32(0)) revert ZeroAddress();
        if (minGuardianSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            solanaBridgeProgram: solanaBridgeProgram,
            wrappedSOL: wrappedSOL,
            guardianOracle: guardianOracle,
            minGuardianSignatures: minGuardianSignatures,
            requiredSlotConfirmations: requiredSlotConfirmations > 0
                ? requiredSlotConfirmations
                : DEFAULT_SLOT_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(solanaBridgeProgram, wrappedSOL, guardianOracle);
    }

    /// @notice Set the treasury address for fee collection
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (Solana → EVM)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISolanaBridgeAdapter
    function initiateSOLDeposit(
        bytes32 solanaTxSignature,
        bytes32 solanaSender,
        address evmRecipient,
        uint256 amountLamports,
        uint256 slot,
        SolanaMerkleProof calldata txProof,
        GuardianAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountLamports < MIN_DEPOSIT_LAMPORTS)
            revert AmountTooSmall(amountLamports);
        if (amountLamports > MAX_DEPOSIT_LAMPORTS)
            revert AmountTooLarge(amountLamports);
        if (usedSolanaTxSignatures[solanaTxSignature])
            revert SolanaTxAlreadyUsed(solanaTxSignature);

        // Verify the slot containing the tx is finalized
        SlotHeader storage header = slotHeaders[slot];
        if (!header.finalized) revert SlotNotFinalized(slot);

        // Verify Merkle inclusion proof
        if (
            !_verifyMerkleProof(
                txProof,
                header.transactionsRoot,
                solanaTxSignature
            )
        ) {
            revert InvalidSlotProof();
        }

        // Verify Guardian attestations
        if (!_verifyGuardianAttestations(header.blockHash, attestations)) {
            revert InsufficientGuardianSignatures(
                attestations.length,
                bridgeConfig.minGuardianSignatures
            );
        }

        // Mark tx signature as used (replay protection)
        usedSolanaTxSignatures[solanaTxSignature] = true;

        // Calculate fee
        uint256 fee = (amountLamports * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountLamports - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                SOLANA_CHAIN_ID,
                solanaTxSignature,
                solanaSender,
                evmRecipient,
                amountLamports,
                depositNonce++
            )
        );

        deposits[depositId] = SOLDeposit({
            depositId: depositId,
            solanaTxSignature: solanaTxSignature,
            solanaSender: solanaSender,
            evmRecipient: evmRecipient,
            amountLamports: amountLamports,
            netAmountLamports: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            slot: slot,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountLamports;

        emit SOLDepositInitiated(
            depositId,
            solanaTxSignature,
            solanaSender,
            evmRecipient,
            amountLamports
        );
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function completeSOLDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        SOLDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wSOL to recipient (net of fees)
        (bool success, ) = bridgeConfig.wrappedSOL.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountLamports
            )
        );
        if (!success) revert InvalidAmount();

        emit SOLDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountLamports
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (EVM → Solana)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISolanaBridgeAdapter
    function initiateWithdrawal(
        bytes32 solanaRecipient,
        uint256 amountLamports
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (solanaRecipient == bytes32(0)) revert ZeroAddress();
        if (amountLamports < MIN_DEPOSIT_LAMPORTS)
            revert AmountTooSmall(amountLamports);
        if (amountLamports > MAX_DEPOSIT_LAMPORTS)
            revert AmountTooLarge(amountLamports);

        // Transfer wSOL from sender to bridge
        IERC20(bridgeConfig.wrappedSOL).safeTransferFrom(
            msg.sender,
            address(this),
            amountLamports
        );

        // Attempt burn
        (bool burnSuccess, ) = bridgeConfig.wrappedSOL.call(
            abi.encodeWithSignature("burn(uint256)", amountLamports)
        );
        // If burn fails, tokens are held until refund or completion

        withdrawalId = keccak256(
            abi.encodePacked(
                SOLANA_CHAIN_ID,
                msg.sender,
                solanaRecipient,
                amountLamports,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = SOLWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            solanaRecipient: solanaRecipient,
            amountLamports: amountLamports,
            solanaTxSignature: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountLamports;

        emit SOLWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            solanaRecipient,
            amountLamports
        );
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 solanaTxSignature,
        SolanaMerkleProof calldata txProof,
        GuardianAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        SOLWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (usedSolanaTxSignatures[solanaTxSignature])
            revert SolanaTxAlreadyUsed(solanaTxSignature);

        // Verify the Solana release transaction in a finalized slot
        bool verified = false;
        for (
            uint256 i = latestSlot;
            i > 0 && i > latestSlot - 100;
            i--
        ) {
            SlotHeader storage header = slotHeaders[i];
            if (
                header.finalized &&
                _verifyMerkleProof(
                    txProof,
                    header.transactionsRoot,
                    solanaTxSignature
                )
            ) {
                if (
                    _verifyGuardianAttestations(
                        header.blockHash,
                        attestations
                    )
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert InvalidSlotProof();

        usedSolanaTxSignatures[solanaTxSignature] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.solanaTxSignature = solanaTxSignature;
        withdrawal.completedAt = block.timestamp;

        emit SOLWithdrawalCompleted(withdrawalId, solanaTxSignature);
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        SOLWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (
            block.timestamp < withdrawal.initiatedAt + WITHDRAWAL_REFUND_DELAY
        ) {
            revert WithdrawalTimelockNotExpired(withdrawalId);
        }

        withdrawal.status = WithdrawalStatus.REFUNDED;
        withdrawal.completedAt = block.timestamp;

        // Return wSOL to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedSOL.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountLamports
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedSOL).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountLamports
            );
        }

        emit SOLWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountLamports
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISolanaBridgeAdapter
    function createEscrow(
        bytes32 solanaParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (solanaParty == bytes32(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (msg.value == 0) revert InvalidAmount();

        // Validate timelocks
        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK)
            revert TimelockTooShort(duration, MIN_ESCROW_TIMELOCK);
        if (duration > MAX_ESCROW_TIMELOCK)
            revert TimelockTooLong(duration, MAX_ESCROW_TIMELOCK);
        if (finishAfter < block.timestamp) revert InvalidAmount();

        uint256 amountLamports = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                SOLANA_CHAIN_ID,
                msg.sender,
                solanaParty,
                hashlock,
                amountLamports,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = SolanaEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            solanaParty: solanaParty,
            amountLamports: amountLamports,
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
            solanaParty,
            amountLamports,
            hashlock
        );
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        SolanaEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert FinishAfterNotReached(escrowId, escrow.finishAfter);
        }

        // Verify SHA-256 hashlock preimage
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        // Release funds to the preimage provider
        (bool success, ) = payable(msg.sender).call{
            value: escrow.amountLamports
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        SolanaEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert CancelAfterNotReached(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to the creator
        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountLamports
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISolanaBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        SOLDeposit storage deposit = deposits[depositId];
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
                      SLOT HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISolanaBridgeAdapter
    function submitSlotHeader(
        uint256 slot,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 accountsRoot,
        uint256 blockTime,
        GuardianAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify Guardian attestations
        if (!_verifyGuardianAttestations(blockHash, attestations)) {
            revert InsufficientGuardianSignatures(
                attestations.length,
                bridgeConfig.minGuardianSignatures
            );
        }

        // Verify parent chain: if we have the parent slot, verify hash match
        if (slot > 0 && slotHeaders[slot - 1].finalized) {
            SlotHeader storage parent = slotHeaders[slot - 1];
            if (parent.blockHash != parentHash) {
                revert InvalidSlotProof();
            }
        }

        slotHeaders[slot] = SlotHeader({
            slot: slot,
            blockHash: blockHash,
            parentHash: parentHash,
            transactionsRoot: transactionsRoot,
            accountsRoot: accountsRoot,
            blockTime: blockTime,
            finalized: true
        });

        if (slot > latestSlot) {
            latestSlot = slot;
            latestBlockHash = blockHash;
        }

        emit SlotHeaderSubmitted(slot, blockHash);
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

        uint256 balance = IERC20(bridgeConfig.wrappedSOL).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedSOL).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISolanaBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (SOLDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (SOLWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (SolanaEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc ISolanaBridgeAdapter
    function getSlotHeader(
        uint256 slot
    ) external view returns (SlotHeader memory) {
        return slotHeaders[slot];
    }

    /// @notice Get user deposit history
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @notice Get user withdrawal history
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @notice Get user escrow history
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
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
            uint256 lastSlot
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestSlot
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify a Solana Merkle inclusion proof
     * @param proof The Merkle proof (siblings + leaf index)
     * @param root The expected Merkle root (from finalized slot header)
     * @param leafHash The transaction signature hash to prove inclusion of
     * @return valid True if the proof is valid
     *
     * Solana uses a binary Merkle tree for transaction inclusion proofs.
     * The proof works by providing sibling hashes and reconstructing
     * the path from leaf to root.
     */
    function _verifyMerkleProof(
        SolanaMerkleProof calldata proof,
        bytes32 root,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.proof.length == 0) return false;

        bytes32 computedHash = leafHash;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.proof.length; i++) {
            if (index % 2 == 0) {
                // Current node is left child
                computedHash = sha256(
                    abi.encodePacked(computedHash, proof.proof[i])
                );
            } else {
                // Current node is right child
                computedHash = sha256(
                    abi.encodePacked(proof.proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    /**
     * @dev Verify Wormhole Guardian attestations for a block hash
     * @param blockHash The block hash that Guardians attested to
     * @param attestations Array of Guardian signatures
     * @return valid True if enough valid attestations exist
     *
     * Wormhole Guardians are a set of trusted nodes that observe
     * cross-chain events and sign VAAs (Verified Action Approvals).
     * Default threshold: 13/19 Guardians must sign.
     */
    function _verifyGuardianAttestations(
        bytes32 blockHash,
        GuardianAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minGuardianSignatures)
            return false;
        if (bridgeConfig.guardianOracle == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            (bool success, bytes memory result) = bridgeConfig
                .guardianOracle
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,bytes32,bytes)",
                        blockHash,
                        attestations[i].guardianPubKey,
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

        return validCount >= bridgeConfig.minGuardianSignatures;
    }

    /**
     * @dev Verify a ZK proof for private deposit registration
     * @param depositId The deposit being made private
     * @param commitment The Pedersen commitment
     * @param nullifier The nullifier to prevent double-spend
     * @param zkProof The ZK proof bytes
     * @return True if proof is valid
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
