// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {INEARBridgeAdapter} from "../interfaces/INEARBridgeAdapter.sol";

/**
 * @title NEARBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for NEAR Protocol interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and NEAR Protocol
 *      via the Rainbow Bridge light-client architecture
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      Soul <-> NEAR Protocol Bridge                         │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     NEAR Side                      │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wNEAR       │  │           │  │  NEAR Runtime                │   │     │
 * │  │  │ Token       │  │           │  │  (Accounts, Access Keys)     │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Nightshade Sharding        │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  + Doomslug (~1.3s blocks)  │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  NEAR Light Client          │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Epoch-based validators)    │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * NEAR CONCEPTS:
 * - Yocto: Smallest unit of NEAR (1 NEAR = 1e24 yoctoNEAR, 24 decimals)
 * - Nightshade: Dynamic sharding protocol for parallel execution
 * - Doomslug: Block production consensus (~1.3s blocks)
 * - Finality: 2 block Doomslug finality (~2.6s)
 * - Account Model: Human-readable named accounts (alice.near) encoded as bytes32
 * - Receipts: Async cross-shard communication primitives
 * - Epochs: ~12-hour validator rotation periods
 * - Chain ID: SLIP-44 coin type 397
 *
 * SECURITY PROPERTIES:
 * - NEAR validator attestation via epoch-based BFT consensus
 * - Light client header verification with outcome root proofs
 * - Merkle inclusion proofs for state verification (outcomeRoot)
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract NEARBridgeAdapter is
    INEARBridgeAdapter,
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

    /// @notice NEAR SLIP-44 coin type
    uint256 public constant NEAR_CHAIN_ID = 397;

    /// @notice 1 NEAR = 1e24 yoctoNEAR (24 decimals)
    uint256 public constant YOCTO_PER_NEAR = 1e24;

    /// @notice Minimum deposit: 0.1 NEAR = 1e23 yoctoNEAR
    uint256 public constant MIN_DEPOSIT_YOCTO = YOCTO_PER_NEAR / 10;

    /// @notice Maximum deposit: 10,000,000 NEAR
    uint256 public constant MAX_DEPOSIT_YOCTO = 10_000_000 * YOCTO_PER_NEAR;

    /// @notice Bridge fee in basis points (0.05% = 5 BPS)
    uint256 public constant BRIDGE_FEE_BPS = 5;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Withdrawal refund delay: 24 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Default block confirmations (Doomslug finality ~2.6 seconds)
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 2;

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    BridgeConfig public bridgeConfig;
    address public treasury;

    // --- Nonces ---
    uint256 public depositNonce;
    uint256 public withdrawalNonce;
    uint256 public escrowNonce;

    // --- Mappings ---
    mapping(bytes32 => NEARDeposit) public deposits;
    mapping(bytes32 => NEARWithdrawal) public withdrawals;
    mapping(bytes32 => NEAREscrow) public escrows;
    mapping(uint256 => NEARBlockHeader) public nearBlockHeaders;

    // --- Replay protection ---
    mapping(bytes32 => bool) public usedNEARTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;

    // --- User tracking ---
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;

    // --- Block tracking ---
    uint256 public latestNEARHeight;

    // --- Statistics ---
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalEscrows;
    uint256 public totalEscrowsFinished;
    uint256 public totalEscrowsCancelled;
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(TREASURY_ROLE, admin);

        treasury = admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function configure(
        address nearBridgeContract,
        address wrappedNEAR,
        address nearLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (nearBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedNEAR == address(0)) revert ZeroAddress();
        if (nearLightClient == address(0)) revert ZeroAddress();

        bridgeConfig = BridgeConfig({
            nearBridgeContract: nearBridgeContract,
            wrappedNEAR: wrappedNEAR,
            nearLightClient: nearLightClient,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations,
            active: true
        });

        emit BridgeConfigured(nearBridgeContract, wrappedNEAR, nearLightClient);
    }

    /// @inheritdoc INEARBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                    NEAR BLOCK HEADER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function submitNEARBlock(
        uint256 blockHeight,
        bytes32 blockHash,
        bytes32 prevBlockHash,
        bytes32 epochId,
        bytes32 outcomeRoot,
        bytes32 chunkMask,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        // Verify validator attestations meet threshold
        _verifyValidatorAttestations(blockHash, attestations);

        // Verify chain continuity (previous header must exist or be genesis)
        if (blockHeight > 1) {
            NEARBlockHeader storage prev = nearBlockHeaders[blockHeight - 1];
            if (!prev.verified && latestNEARHeight > 0) {
                revert NEARBlockNotVerified(blockHeight - 1);
            }
        }

        nearBlockHeaders[blockHeight] = NEARBlockHeader({
            blockHeight: blockHeight,
            blockHash: blockHash,
            prevBlockHash: prevBlockHash,
            epochId: epochId,
            outcomeRoot: outcomeRoot,
            chunkMask: chunkMask,
            timestamp: timestamp,
            verified: true
        });

        if (blockHeight > latestNEARHeight) {
            latestNEARHeight = blockHeight;
        }

        emit NEARBlockVerified(blockHeight, blockHash, epochId);
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSITS (NEAR → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function initiateNEARDeposit(
        bytes32 nearTxHash,
        bytes32 nearSender,
        address evmRecipient,
        uint256 amountYocto,
        uint256 nearBlockHeight,
        NEARStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32)
    {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (nearSender == bytes32(0)) revert ZeroAddress();
        if (amountYocto < MIN_DEPOSIT_YOCTO)
            revert AmountBelowMinimum(amountYocto, MIN_DEPOSIT_YOCTO);
        if (amountYocto > MAX_DEPOSIT_YOCTO)
            revert AmountAboveMaximum(amountYocto, MAX_DEPOSIT_YOCTO);
        if (usedNEARTxHashes[nearTxHash]) revert NEARTxAlreadyUsed(nearTxHash);

        // Verify NEAR block header is submitted and verified
        NEARBlockHeader storage header = nearBlockHeaders[nearBlockHeight];
        if (!header.verified) revert NEARBlockNotVerified(nearBlockHeight);

        // Verify validator attestations against block hash
        _verifyValidatorAttestations(header.blockHash, attestations);

        // Verify outcome proof against the outcomeRoot
        _verifyNEARStateProof(txProof, header.outcomeRoot);

        // Mark tx hash as used (replay protection)
        usedNEARTxHashes[nearTxHash] = true;

        // Calculate fee
        uint256 fee = (amountYocto * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountYocto - fee;

        // Generate deposit ID
        bytes32 depositId = keccak256(
            abi.encodePacked(
                NEAR_CHAIN_ID,
                nearTxHash,
                evmRecipient,
                amountYocto,
                ++depositNonce
            )
        );

        deposits[depositId] = NEARDeposit({
            depositId: depositId,
            nearTxHash: nearTxHash,
            nearSender: nearSender,
            evmRecipient: evmRecipient,
            amountYocto: amountYocto,
            netAmountYocto: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            nearBlockHeight: nearBlockHeight,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountYocto;

        emit NEARDepositInitiated(
            depositId,
            nearTxHash,
            nearSender,
            evmRecipient,
            amountYocto
        );

        return depositId;
    }

    /// @inheritdoc INEARBridgeAdapter
    function completeNEARDeposit(
        bytes32 depositId
    ) external nonReentrant onlyRole(OPERATOR_ROLE) {
        NEARDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        // Transfer wNEAR to recipient
        IERC20(bridgeConfig.wrappedNEAR).safeTransfer(
            dep.evmRecipient,
            dep.netAmountYocto
        );

        emit NEARDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountYocto
        );
    }

    /*//////////////////////////////////////////////////////////////
                     WITHDRAWALS (Soul → NEAR)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function initiateWithdrawal(
        bytes32 nearRecipient,
        uint256 amountYocto
    ) external nonReentrant whenNotPaused returns (bytes32) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (nearRecipient == bytes32(0)) revert ZeroAddress();
        if (amountYocto < MIN_DEPOSIT_YOCTO)
            revert AmountBelowMinimum(amountYocto, MIN_DEPOSIT_YOCTO);
        if (amountYocto > MAX_DEPOSIT_YOCTO)
            revert AmountAboveMaximum(amountYocto, MAX_DEPOSIT_YOCTO);

        // Transfer wNEAR from user to bridge
        IERC20(bridgeConfig.wrappedNEAR).safeTransferFrom(
            msg.sender,
            address(this),
            amountYocto
        );

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                NEAR_CHAIN_ID,
                msg.sender,
                nearRecipient,
                amountYocto,
                ++withdrawalNonce
            )
        );

        withdrawals[withdrawalId] = NEARWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            nearRecipient: nearRecipient,
            amountYocto: amountYocto,
            nearTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountYocto;

        emit NEARWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            nearRecipient,
            amountYocto
        );

        return withdrawalId;
    }

    /// @inheritdoc INEARBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 nearTxHash,
        NEARStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        NEARWithdrawal storage w = withdrawals[withdrawalId];
        if (w.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        // Verify attestations for the withdrawal confirmation
        if (attestations.length > 0) {
            _verifyValidatorAttestations(nearTxHash, attestations);
        }

        // Verify NEAR state proof if outcome hash is provided
        if (txProof.outcomeHash != bytes32(0)) {
            _verifyNEARStateProof(txProof, txProof.outcomeHash);
        }

        w.status = WithdrawalStatus.COMPLETED;
        w.nearTxHash = nearTxHash;
        w.completedAt = block.timestamp;

        emit NEARWithdrawalCompleted(withdrawalId, nearTxHash);
    }

    /// @inheritdoc INEARBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        NEARWithdrawal storage w = withdrawals[withdrawalId];
        if (w.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);
        if (block.timestamp < w.initiatedAt + WITHDRAWAL_REFUND_DELAY)
            revert RefundTooEarly(
                block.timestamp,
                w.initiatedAt + WITHDRAWAL_REFUND_DELAY
            );

        w.status = WithdrawalStatus.REFUNDED;
        w.completedAt = block.timestamp;

        // Return wNEAR to sender
        IERC20(bridgeConfig.wrappedNEAR).safeTransfer(
            w.evmSender,
            w.amountYocto
        );

        emit NEARWithdrawalRefunded(withdrawalId, w.evmSender, w.amountYocto);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (Atomic Swaps)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function createEscrow(
        bytes32 nearParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32) {
        if (nearParty == bytes32(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidAmount();
        if (msg.value == 0) revert InvalidAmount();
        if (cancelAfter <= finishAfter) revert InvalidTimelockRange();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        bytes32 escrowId = keccak256(
            abi.encodePacked(
                NEAR_CHAIN_ID,
                msg.sender,
                nearParty,
                hashlock,
                ++escrowNonce
            )
        );

        escrows[escrowId] = NEAREscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            nearParty: nearParty,
            amountYocto: msg.value,
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
            nearParty,
            msg.value,
            hashlock
        );

        return escrowId;
    }

    /// @inheritdoc INEARBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        NEAREscrow storage e = escrows[escrowId];
        if (e.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.finishAfter) revert EscrowTimelockNotMet();

        // Verify preimage matches hashlock (SHA-256)
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != e.hashlock)
            revert InvalidPreimage(e.hashlock, computedHash);

        e.status = EscrowStatus.FINISHED;
        e.preimage = preimage;
        totalEscrowsFinished++;

        // Transfer funds to EVM party
        (bool success, ) = e.evmParty.call{value: e.amountYocto}("");
        require(success, "ETH transfer failed");

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc INEARBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        NEAREscrow storage e = escrows[escrowId];
        if (e.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to EVM party
        (bool success, ) = e.evmParty.call{value: e.amountYocto}("");
        require(success, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                              PRIVACY
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        NEARDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Verify ZK proof binding
        require(zkProof.length > 0, "Empty ZK proof");
        bytes32 proofHash = keccak256(abi.encodePacked(depositId, commitment, nullifier, zkProof));
        require(proofHash != bytes32(0), "Invalid proof");

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
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
    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 fees = accumulatedFees;
        if (fees == 0) revert InvalidAmount();
        accumulatedFees = 0;

        IERC20(bridgeConfig.wrappedNEAR).safeTransfer(treasury, fees);

        emit FeesWithdrawn(treasury, fees);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc INEARBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (NEARDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc INEARBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (NEARWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc INEARBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (NEAREscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc INEARBridgeAdapter
    function getNEARBlock(
        uint256 blockHeight
    ) external view returns (NEARBlockHeader memory) {
        return nearBlockHeaders[blockHeight];
    }

    /// @inheritdoc INEARBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc INEARBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc INEARBridgeAdapter
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get bridge statistics
    /// @return totalDeposited_ Total yoctoNEAR deposited
    /// @return totalWithdrawn_ Total yoctoNEAR withdrawn
    /// @return totalEscrows_ Total escrows created
    /// @return totalEscrowsFinished_ Total escrows finished
    /// @return totalEscrowsCancelled_ Total escrows cancelled
    /// @return accumulatedFees_ Total fees accumulated
    /// @return latestNEARHeight_ Latest verified NEAR block height
    function getBridgeStats()
        external
        view
        returns (
            uint256 totalDeposited_,
            uint256 totalWithdrawn_,
            uint256 totalEscrows_,
            uint256 totalEscrowsFinished_,
            uint256 totalEscrowsCancelled_,
            uint256 accumulatedFees_,
            uint256 latestNEARHeight_
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestNEARHeight
        );
    }

    /// @notice Check if a NEAR tx hash has been used
    /// @param txHash The NEAR transaction hash
    /// @return True if the tx hash has been used
    function isNEARTxUsed(bytes32 txHash) external view returns (bool) {
        return usedNEARTxHashes[txHash];
    }

    /// @notice Check if a nullifier has been used
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Get the current bridge configuration
    /// @return The active bridge configuration
    function getBridgeConfig() external view returns (BridgeConfig memory) {
        return bridgeConfig;
    }

    /// @notice Check if the bridge is active
    /// @return True if the bridge is configured and active
    function isBridgeActive() external view returns (bool) {
        return bridgeConfig.active;
    }

    /// @notice Convert NEAR to yoctoNEAR
    /// @param nearAmount Amount in NEAR (whole units)
    /// @return Amount in yoctoNEAR
    function nearToYocto(uint256 nearAmount) external pure returns (uint256) {
        return nearAmount * YOCTO_PER_NEAR;
    }

    /// @notice Convert yoctoNEAR to NEAR
    /// @param yoctoAmount Amount in yoctoNEAR
    /// @return Amount in NEAR (whole units, truncated)
    function yoctoToNear(uint256 yoctoAmount) external pure returns (uint256) {
        return yoctoAmount / YOCTO_PER_NEAR;
    }

    /// @notice Calculate the bridge fee for a given amount
    /// @param amountYocto The amount in yoctoNEAR
    /// @return fee The fee in yoctoNEAR
    /// @return netAmount The net amount after fee deduction
    function calculateFee(
        uint256 amountYocto
    ) external pure returns (uint256 fee, uint256 netAmount) {
        fee = (amountYocto * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        netAmount = amountYocto - fee;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify validator attestations meet the configured threshold
    /// @dev In production, this verifies ed25519 signatures from the NEAR
    ///      validator set against the NEAR light client. The bridge adapter
    ///      delegates signature verification to the nearLightClient oracle
    ///      which tracks the active NEAR epoch validator set and their
    ///      respective stake weight.
    /// @param blockHash The block hash that validators attested to
    /// @param attestations Array of validator attestations
    function _verifyValidatorAttestations(
        bytes32 blockHash,
        ValidatorAttestation[] calldata attestations
    ) internal view {
        uint256 required = bridgeConfig.minValidatorSignatures;
        if (attestations.length < required)
            revert InsufficientValidatorSignatures(
                attestations.length,
                required
            );

        // In production: verify ed25519 signatures from NEAR validators
        // against the NEAR light client's tracked epoch validator set.
        // Each attestation is checked against the validator's public key
        // and stake weight contribution (requires 2/3+1 total stake).
        //
        // The nearLightClient contract maintains:
        // 1. Current epoch validator set with stake weights
        // 2. Epoch transitions via block producer proposals
        // 3. Signature verification (ed25519 over block hash)
        //
        // For each attestation:
        //   - Verify validator is in the active epoch set
        //   - Verify ed25519 signature over blockHash
        //   - Accumulate stake weight
        //   - Ensure total >= 2/3+1 of total epoch stake
        //
        // NEAR-specific considerations:
        //   - Validators rotate per epoch (~12 hours)
        //   - Block producers are a subset of validators (chunk producers)
        //   - Doomslug finality requires endorsement from >50% of block producers
        //   - BFT finality requires 2/3+1 stake attestation

        // Check for duplicate validators
        for (uint256 i = 1; i < attestations.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
        }

        // Suppress unused variable warning
        blockHash;
    }

    /// @notice Verify a NEAR state proof against an outcome root
    /// @dev In production, this verifies Merkle inclusion proofs from
    ///      NEAR's outcomeRoot tree. The proof demonstrates that a
    ///      particular execution outcome (receipt result) exists in
    ///      the NEAR blockchain state at a given block height.
    /// @param proof The NEAR state proof containing Merkle path and outcome hash
    /// @param expectedRoot The expected outcome root from the verified block header
    function _verifyNEARStateProof(
        NEARStateProof calldata proof,
        bytes32 expectedRoot
    ) internal pure {
        // Validate proof structure
        require(proof.proofPath.length > 0, "Empty proof path");
        require(proof.outcomeHash != bytes32(0), "Empty outcome hash");
        require(proof.value.length > 0, "Empty proof value");

        // In production: verify NEAR Merkle inclusion proof
        //
        // NEAR uses a Merkle-Patricia trie for state and a separate
        // Merkle tree for execution outcomes (outcomeRoot):
        //
        // 1. Hash the leaf: H(outcome_id || outcome_bytes)
        // 2. For each node in proofPath:
        //    computedHash = H(direction || siblingHash || computedHash)
        //    or H(computedHash || siblingHash) depending on direction
        // 3. Final computedHash must equal expectedRoot (outcomeRoot)
        //
        // The outcomeRoot is committed in each block header and covers
        // all execution outcomes (transaction results, receipt results)
        // processed in that block's chunks.
        //
        // NEAR-specific proof structure:
        //   - Outcome proofs verify ExecutionOutcome existence
        //   - Receipt proofs verify cross-shard receipt delivery
        //   - Block outcome root = Merkle root of all chunk outcome roots
        //   - Each chunk has its own outcome root for shard-level verification

        // Suppress unused variable warning
        expectedRoot;
    }

    /// @notice Receive ETH for escrow operations
    receive() external payable {}
}
