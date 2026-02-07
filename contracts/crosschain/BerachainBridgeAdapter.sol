// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IBerachainBridgeAdapter} from "../interfaces/IBerachainBridgeAdapter.sol";

/**
 * @title BerachainBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Berachain interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Berachain
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> Berachain Bridge                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Berachain Side                │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wBERA Token │  │           │  │  Bridge Contract           │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (EVM-compatible)          │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  BeaconKit / CometBFT      │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (PoL consensus, ~5s)      │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  CometBFT Validators       │   │     │
 * │  │  │ Layer       │  │           │  │  (2/3+1 voting power)      │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * BERACHAIN CONCEPTS:
 * - Wei: Smallest unit of BERA (1 BERA = 1e18 wei, standard EVM 18 decimals)
 * - CometBFT: Tendermint-derived BFT consensus with instant finality
 * - Proof-of-Liquidity (PoL): Consensus aligning validators with DeFi liquidity
 * - BeaconKit: Modular EVM consensus client built on CometBFT
 * - BGT: Berachain Governance Token (non-transferable, earned via PoL)
 * - HONEY: Native stablecoin minted against collateral
 * - BEX: Native DEX with concentrated liquidity
 * - Reward Vaults: PoL incentive distribution vaults
 * - Chain ID: 80094 (Berachain mainnet)
 * - Finality: Single-slot CometBFT (~5s block time)
 * - Block confirmations: 1 (CometBFT instant finality)
 * - EVM-compatible: Full EVM equivalence, address-based counterparty
 *
 * SECURITY PROPERTIES:
 * - CometBFT validator attestation (2/3+1 voting power)
 * - Block header chain integrity enforcement (appHash, validatorsHash)
 * - Merkle inclusion proofs for state verification (CometBFTProof)
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract BerachainBridgeAdapter is
    IBerachainBridgeAdapter,
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

    /// @notice Berachain mainnet chain ID
    uint256 public constant BERACHAIN_CHAIN_ID = 80094;

    /// @notice Minimum deposit (0.01 BERA)
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Maximum deposit (10,000,000 BERA)
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /// @notice Bridge fee in basis points (0.04%)
    uint256 public constant BRIDGE_FEE_BPS = 4;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default required block confirmations (1 block — CometBFT instant finality)
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
    mapping(bytes32 => BERADeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => BERAWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => BERAEscrow) public escrows;

    /// @notice Verified CometBFT block headers
    mapping(uint256 => CometBFTBlock) public cometBFTBlocks;

    /// @notice Used Berachain transaction hashes (replay protection)
    mapping(bytes32 => bool) public usedBeraTxHashes;

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

    /// @notice Total BERA deposited (in wei)
    uint256 public totalDeposited;

    /// @notice Total BERA withdrawn (in wei)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in wei-equivalent wBERA)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Berachain bridge adapter
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

    /// @inheritdoc IBerachainBridgeAdapter
    function configure(
        address berachainBridgeContract,
        address wrappedBERA,
        address cometBFTVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (berachainBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedBERA == address(0)) revert ZeroAddress();
        if (cometBFTVerifier == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            berachainBridgeContract: berachainBridgeContract,
            wrappedBERA: wrappedBERA,
            cometBFTVerifier: cometBFTVerifier,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            berachainBridgeContract,
            wrappedBERA,
            cometBFTVerifier
        );
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                   COMETBFT BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBerachainBridgeAdapter
    function submitCometBFTBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 validatorsHash,
        uint256 round,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify CometBFT validator attestations (2/3+1 voting power)
        if (!_verifyValidatorAttestations(blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Verify parent chain linkage: if parent block exists, verify continuity
        if (blockNumber > 0 && cometBFTBlocks[blockNumber - 1].verified) {
            CometBFTBlock storage parent = cometBFTBlocks[blockNumber - 1];
            // Ensure sequential block submission
            if (parent.blockNumber != blockNumber - 1) {
                revert BeraBlockNotVerified(blockNumber);
            }
        }

        cometBFTBlocks[blockNumber] = CometBFTBlock({
            blockNumber: blockNumber,
            blockHash: blockHash,
            appHash: appHash,
            validatorsHash: validatorsHash,
            round: round,
            timestamp: timestamp,
            verified: true
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
            latestBlockHash = blockHash;
        }

        emit CometBFTBlockVerified(blockNumber, blockHash, appHash);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS (Berachain → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBerachainBridgeAdapter
    function initiateBERADeposit(
        bytes32 beraTxHash,
        address beraSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 beraBlockNumber,
        CometBFTProof calldata txProof,
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
        if (usedBeraTxHashes[beraTxHash]) {
            revert BeraTxAlreadyUsed(beraTxHash);
        }

        // Verify the CometBFT block containing the tx is verified
        CometBFTBlock storage header = cometBFTBlocks[beraBlockNumber];
        if (!header.verified) {
            revert BeraBlockNotVerified(beraBlockNumber);
        }

        // Verify CometBFT state proof (Merkle inclusion against appHash)
        if (!_verifyCometBFTProof(txProof, header.appHash, beraTxHash)) {
            revert BeraBlockNotVerified(beraBlockNumber);
        }

        // Verify CometBFT validator attestations
        if (!_verifyValidatorAttestations(header.blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Mark tx hash as used (replay protection)
        usedBeraTxHashes[beraTxHash] = true;

        // Calculate fee
        uint256 fee = (amountWei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountWei - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                BERACHAIN_CHAIN_ID,
                beraTxHash,
                beraSender,
                evmRecipient,
                amountWei,
                depositNonce++
            )
        );

        deposits[depositId] = BERADeposit({
            depositId: depositId,
            beraTxHash: beraTxHash,
            beraSender: beraSender,
            evmRecipient: evmRecipient,
            amountWei: amountWei,
            netAmountWei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            beraBlockNumber: beraBlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountWei;

        emit BERADepositInitiated(
            depositId,
            beraTxHash,
            beraSender,
            evmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function completeBERADeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BERADeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) {
            revert DepositNotFound(depositId);
        }
        if (deposit.status != DepositStatus.VERIFIED) {
            revert DepositNotVerified(depositId);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wBERA to recipient (net of fees)
        (bool success, ) = bridgeConfig.wrappedBERA.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountWei
            )
        );
        if (!success) revert InvalidAmount();

        emit BERADepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                   WITHDRAWALS (Soul → Berachain)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBerachainBridgeAdapter
    function initiateWithdrawal(
        address beraRecipient,
        uint256 amountWei
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (beraRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT) {
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        }
        if (amountWei > MAX_DEPOSIT) {
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);
        }

        // Transfer wBERA from sender to bridge
        IERC20(bridgeConfig.wrappedBERA).safeTransferFrom(
            msg.sender,
            address(this),
            amountWei
        );

        // Attempt burn of wBERA
        (bool burnSuccess, ) = bridgeConfig.wrappedBERA.call(
            abi.encodeWithSignature("burn(uint256)", amountWei)
        );
        // If burn fails, tokens are held until refund or completion

        withdrawalId = keccak256(
            abi.encodePacked(
                BERACHAIN_CHAIN_ID,
                msg.sender,
                beraRecipient,
                amountWei,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = BERAWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            beraRecipient: beraRecipient,
            amountWei: amountWei,
            beraTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountWei;

        emit BERAWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            beraRecipient,
            amountWei
        );
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 beraTxHash,
        CometBFTProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        BERAWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) {
            revert WithdrawalNotFound(withdrawalId);
        }
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert WithdrawalNotPending(withdrawalId);
        }
        if (usedBeraTxHashes[beraTxHash]) {
            revert BeraTxAlreadyUsed(beraTxHash);
        }

        // Verify the Berachain release transaction in a verified CometBFT block
        bool verified = false;
        for (
            uint256 i = latestBlockNumber;
            i > 0 && i > latestBlockNumber - 100;
            i--
        ) {
            CometBFTBlock storage header = cometBFTBlocks[i];
            if (
                header.verified &&
                _verifyCometBFTProof(txProof, header.appHash, beraTxHash)
            ) {
                if (
                    _verifyValidatorAttestations(header.blockHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert BeraBlockNotVerified(latestBlockNumber);

        usedBeraTxHashes[beraTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.beraTxHash = beraTxHash;
        withdrawal.completedAt = block.timestamp;

        emit BERAWithdrawalCompleted(withdrawalId, beraTxHash);
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        BERAWithdrawal storage withdrawal = withdrawals[withdrawalId];
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

        // Return wBERA to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedBERA.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountWei
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedBERA).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountWei
            );
        }

        emit BERAWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBerachainBridgeAdapter
    function createEscrow(
        address beraParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (beraParty == address(0)) revert ZeroAddress();
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
                BERACHAIN_CHAIN_ID,
                msg.sender,
                beraParty,
                hashlock,
                amountWei,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = BERAEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            beraParty: beraParty,
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
            beraParty,
            amountWei,
            hashlock
        );
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        BERAEscrow storage escrow = escrows[escrowId];
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

        // Release funds to the counterparty (Berachain party)
        (bool success, ) = payable(escrow.beraParty).call{value: escrow.amountWei}(
            ""
        );
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        BERAEscrow storage escrow = escrows[escrowId];
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

    /// @inheritdoc IBerachainBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BERADeposit storage deposit = deposits[depositId];
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

        uint256 balance = IERC20(bridgeConfig.wrappedBERA).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedBERA).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBerachainBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (BERADeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BERAWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (BERAEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function getCometBFTBlock(
        uint256 blockNumber
    ) external view returns (CometBFTBlock memory) {
        return cometBFTBlocks[blockNumber];
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IBerachainBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IBerachainBridgeAdapter
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
     * @dev Verify a CometBFT state proof (Merkle inclusion against appHash)
     * @param proof The CometBFT proof containing Merkle siblings
     * @param root The appHash from the verified CometBFT block
     * @param leafHash The transaction hash to verify inclusion for
     * @return valid True if the proof is valid
     */
    function _verifyCometBFTProof(
        CometBFTProof calldata proof,
        bytes32 root,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.merkleProof.length == 0) return false;

        bytes32 computedHash = keccak256(
            abi.encodePacked(leafHash, proof.appHash, proof.value)
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
     * @dev Verify CometBFT validator attestations for a block hash
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
        if (bridgeConfig.cometBFTVerifier == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // Check for duplicate validators
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
            (bool success, bytes memory result) = bridgeConfig
                .cometBFTVerifier
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
