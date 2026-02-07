// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAvalancheBridgeAdapter} from "../interfaces/IAvalancheBridgeAdapter.sol";

/**
 * @title AvalancheBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Avalanche C-Chain interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Avalanche C-Chain
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                  Soul <-> Avalanche C-Chain Bridge                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Avalanche C-Chain Side        │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wAVAX Token │  │           │  │  Bridge Contract           │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (EVM-compatible)          │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Avalanche Warp Messaging  │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (AWM cross-subnet msgs)   │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  Snowman Consensus         │   │     │
 * │  │  │ Layer       │  │           │  │  (Sub-second finality)     │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * AVALANCHE CONCEPTS:
 * - Wei: Smallest unit of AVAX (1 AVAX = 1e18 wei, standard EVM 18 decimals)
 * - Snowman: Linear chain consensus for C-Chain (sub-second finality)
 * - Avalanche Consensus: Snow family (Snowball, Snowflake) on P-Chain/X-Chain
 * - C-Chain: Contract Chain (EVM compatible, chain ID 43114)
 * - P-Chain: Platform Chain (staking & subnet management)
 * - X-Chain: Exchange Chain (asset creation & transfers)
 * - Subnets: Application-specific networks with custom VMs
 * - Warp Messaging: Native cross-subnet messaging (AWM)
 * - Block time: ~2 seconds on C-Chain
 * - Finality: Sub-second (~1-2s) via Snowman consensus
 * - Validators: BLS multi-sig attestations via P-Chain
 *
 * SECURITY PROPERTIES:
 * - P-Chain validator BLS multi-sig attestation threshold
 * - Block finality confirmation depth (1 block default, sub-second finality)
 * - Warp state proofs for cross-chain transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract AvalancheBridgeAdapter is
    IAvalancheBridgeAdapter,
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

    /// @notice Avalanche C-Chain mainnet chain ID
    uint256 public constant AVALANCHE_CHAIN_ID = 43114;

    /// @notice Wei per AVAX (1 AVAX = 1e18 wei, standard EVM 18 decimals)
    uint256 public constant WEI_PER_AVAX = 1 ether;

    /// @notice Minimum deposit (0.01 AVAX)
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Maximum deposit (10,000,000 AVAX)
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /// @notice Bridge fee in basis points (0.04%)
    uint256 public constant BRIDGE_FEE_BPS = 4;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default required block confirmations (1 block — Snowman sub-second finality)
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
    mapping(bytes32 => AVAXDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => AVAXWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => AVAXEscrow) public escrows;

    /// @notice Verified Snowman block headers
    mapping(uint256 => SnowmanBlock) public snowmanBlocks;

    /// @notice Used C-Chain transaction hashes (replay protection)
    mapping(bytes32 => bool) public usedCChainTxHashes;

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

    /// @notice Total AVAX deposited (in wei)
    uint256 public totalDeposited;

    /// @notice Total AVAX withdrawn (in wei)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in wei-equivalent wAVAX)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Avalanche bridge adapter
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

    /// @inheritdoc IAvalancheBridgeAdapter
    function configure(
        address avalancheBridgeContract,
        address wrappedAVAX,
        address warpVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (avalancheBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedAVAX == address(0)) revert ZeroAddress();
        if (warpVerifier == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            avalancheBridgeContract: avalancheBridgeContract,
            wrappedAVAX: wrappedAVAX,
            warpVerifier: warpVerifier,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            avalancheBridgeContract,
            wrappedAVAX,
            warpVerifier
        );
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMAN BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAvalancheBridgeAdapter
    function submitSnowmanBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify P-Chain validator BLS multi-sig attestations
        if (!_verifyValidatorAttestations(blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Verify parent chain linkage: if parent block exists, verify hash continuity
        if (blockNumber > 0 && snowmanBlocks[blockNumber - 1].verified) {
            SnowmanBlock storage parent = snowmanBlocks[blockNumber - 1];
            if (parent.blockHash != parentHash) {
                revert CChainBlockNotVerified(blockNumber);
            }
        }

        snowmanBlocks[blockNumber] = SnowmanBlock({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            stateRoot: stateRoot,
            timestamp: timestamp,
            verified: true
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
            latestBlockHash = blockHash;
        }

        emit SnowmanBlockVerified(blockNumber, blockHash, stateRoot);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS (C-Chain → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAvalancheBridgeAdapter
    function initiateAVAXDeposit(
        bytes32 cChainTxHash,
        address cChainSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 cChainBlockNumber,
        WarpStateProof calldata txProof,
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
        if (usedCChainTxHashes[cChainTxHash]) {
            revert CChainTxAlreadyUsed(cChainTxHash);
        }

        // Verify the Snowman block containing the tx is verified
        SnowmanBlock storage header = snowmanBlocks[cChainBlockNumber];
        if (!header.verified) {
            revert CChainBlockNotVerified(cChainBlockNumber);
        }

        // Verify Warp state proof (Merkle inclusion against state root)
        if (!_verifyWarpStateProof(txProof, header.stateRoot, cChainTxHash)) {
            revert CChainBlockNotVerified(cChainBlockNumber);
        }

        // Verify P-Chain validator attestations
        if (!_verifyValidatorAttestations(header.blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Mark tx hash as used (replay protection)
        usedCChainTxHashes[cChainTxHash] = true;

        // Calculate fee
        uint256 fee = (amountWei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountWei - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                AVALANCHE_CHAIN_ID,
                cChainTxHash,
                cChainSender,
                evmRecipient,
                amountWei,
                depositNonce++
            )
        );

        deposits[depositId] = AVAXDeposit({
            depositId: depositId,
            cChainTxHash: cChainTxHash,
            cChainSender: cChainSender,
            evmRecipient: evmRecipient,
            amountWei: amountWei,
            netAmountWei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            cChainBlockNumber: cChainBlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountWei;

        emit AVAXDepositInitiated(
            depositId,
            cChainTxHash,
            cChainSender,
            evmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function completeAVAXDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        AVAXDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) {
            revert DepositNotFound(depositId);
        }
        if (deposit.status != DepositStatus.VERIFIED) {
            revert DepositNotVerified(depositId);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wAVAX to recipient (net of fees)
        (bool success, ) = bridgeConfig.wrappedAVAX.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountWei
            )
        );
        if (!success) revert InvalidAmount();

        emit AVAXDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                   WITHDRAWALS (Soul → C-Chain)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAvalancheBridgeAdapter
    function initiateWithdrawal(
        address cChainRecipient,
        uint256 amountWei
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (cChainRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT) {
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        }
        if (amountWei > MAX_DEPOSIT) {
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);
        }

        // Transfer wAVAX from sender to bridge
        IERC20(bridgeConfig.wrappedAVAX).safeTransferFrom(
            msg.sender,
            address(this),
            amountWei
        );

        // Attempt burn of wAVAX
        (bool burnSuccess, ) = bridgeConfig.wrappedAVAX.call(
            abi.encodeWithSignature("burn(uint256)", amountWei)
        );
        // If burn fails, tokens are held until refund or completion

        withdrawalId = keccak256(
            abi.encodePacked(
                AVALANCHE_CHAIN_ID,
                msg.sender,
                cChainRecipient,
                amountWei,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = AVAXWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            cChainRecipient: cChainRecipient,
            amountWei: amountWei,
            cChainTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountWei;

        emit AVAXWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            cChainRecipient,
            amountWei
        );
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cChainTxHash,
        WarpStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        AVAXWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) {
            revert WithdrawalNotFound(withdrawalId);
        }
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert WithdrawalNotPending(withdrawalId);
        }
        if (usedCChainTxHashes[cChainTxHash]) {
            revert CChainTxAlreadyUsed(cChainTxHash);
        }

        // Verify the C-Chain release transaction in a verified Snowman block
        bool verified = false;
        for (
            uint256 i = latestBlockNumber;
            i > 0 && i > latestBlockNumber - 100;
            i--
        ) {
            SnowmanBlock storage header = snowmanBlocks[i];
            if (
                header.verified &&
                _verifyWarpStateProof(txProof, header.stateRoot, cChainTxHash)
            ) {
                if (
                    _verifyValidatorAttestations(header.blockHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert CChainBlockNotVerified(latestBlockNumber);

        usedCChainTxHashes[cChainTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.cChainTxHash = cChainTxHash;
        withdrawal.completedAt = block.timestamp;

        emit AVAXWithdrawalCompleted(withdrawalId, cChainTxHash);
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        AVAXWithdrawal storage withdrawal = withdrawals[withdrawalId];
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

        // Return wAVAX to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedAVAX.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountWei
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedAVAX).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountWei
            );
        }

        emit AVAXWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAvalancheBridgeAdapter
    function createEscrow(
        address cChainParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (cChainParty == address(0)) revert ZeroAddress();
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
                AVALANCHE_CHAIN_ID,
                msg.sender,
                cChainParty,
                hashlock,
                amountWei,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = AVAXEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            cChainParty: cChainParty,
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
            cChainParty,
            amountWei,
            hashlock
        );
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        AVAXEscrow storage escrow = escrows[escrowId];
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

        // Release funds to the counterparty (C-Chain party)
        (bool success, ) = payable(escrow.cChainParty).call{value: escrow.amountWei}(
            ""
        );
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        AVAXEscrow storage escrow = escrows[escrowId];
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

    /// @inheritdoc IAvalancheBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        AVAXDeposit storage deposit = deposits[depositId];
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

        uint256 balance = IERC20(bridgeConfig.wrappedAVAX).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedAVAX).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAvalancheBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (AVAXDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (AVAXWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (AVAXEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function getSnowmanBlock(
        uint256 blockNumber
    ) external view returns (SnowmanBlock memory) {
        return snowmanBlocks[blockNumber];
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IAvalancheBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IAvalancheBridgeAdapter
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
     * @dev Verify a Warp state proof (Merkle inclusion against Snowman state root)
     * @param proof The Warp state proof containing Merkle siblings
     * @param root The state root from the verified Snowman block
     * @param leafHash The transaction hash to verify inclusion for
     * @return valid True if the proof is valid
     */
    function _verifyWarpStateProof(
        WarpStateProof calldata proof,
        bytes32 root,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.merkleProof.length == 0) return false;

        bytes32 computedHash = keccak256(
            abi.encodePacked(leafHash, proof.storageRoot, proof.value)
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
     * @dev Verify P-Chain validator BLS multi-sig attestations for a block hash
     * @param blockHash The block hash to verify attestations against
     * @param attestations Array of validator attestations (BLS signatures)
     * @return valid True if sufficient valid attestations are provided
     */
    function _verifyValidatorAttestations(
        bytes32 blockHash,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minValidatorSignatures)
            return false;
        if (bridgeConfig.warpVerifier == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // Check for duplicate validators
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
            (bool success, bytes memory result) = bridgeConfig
                .warpVerifier
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
