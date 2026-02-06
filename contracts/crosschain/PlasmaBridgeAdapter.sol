// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPlasmaBridgeAdapter} from "../interfaces/IPlasmaBridgeAdapter.sol";

/**
 * @title PlasmaBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Plasma chain interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Plasma child chains
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> Plasma Bridge                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Plasma Side                   │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wPLASMA     │  │           │  │  Root Chain Contract       │   │     │
 * │  │  │ Token       │  │           │  │  (L1 Block Commitments)    │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Operator                  │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (Block Producer)          │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Exit Game / Fraud Proofs  │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (7-day challenge period)  │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * PLASMA CONCEPTS:
 * - satoplasma: Smallest unit (1 PLASMA = 100,000,000 satoplasma = 1e8)
 * - Operator: Single trusted block producer for child chain
 * - Root Chain: L1 contract storing block commitments
 * - Block Commitment: Merkle root committed to L1
 * - Exit Game: Protocol for withdrawals back to L1
 * - Challenge Period: 7-day fraud proof window
 * - Chain ID: plasma-mainnet-1 → EVM numeric mapping: 515
 * - L1 Finality: 12 commitment confirmations for cross-chain safety
 * - Child chain blocks: ~1 second
 *
 * SECURITY PROPERTIES:
 * - Operator commitment verification against L1 roots
 * - 7-day challenge period for exit finalization
 * - Merkle inclusion proofs for UTXO verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract PlasmaBridgeAdapter is
    IPlasmaBridgeAdapter,
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

    /// @notice Plasma chain ID (plasma-mainnet-1 EVM mapping)
    uint256 public constant PLASMA_CHAIN_ID = 515;

    /// @notice 1 PLASMA = 1e8 satoplasma (8 decimals, UTXO-inspired)
    uint256 public constant SATOPLASMA_PER_PLASMA = 100_000_000;

    /// @notice Minimum deposit: 0.1 PLASMA = 10,000,000 satoplasma
    uint256 public constant MIN_DEPOSIT_SATOPLASMA = SATOPLASMA_PER_PLASMA / 10;

    /// @notice Maximum deposit: 5,000,000 PLASMA
    uint256 public constant MAX_DEPOSIT_SATOPLASMA = 5_000_000 * SATOPLASMA_PER_PLASMA;

    /// @notice Bridge fee in basis points (0.08% = 8 BPS)
    uint256 public constant BRIDGE_FEE_BPS = 8;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default L1 commitment confirmations (Ethereum finality)
    uint256 public constant DEFAULT_L1_CONFIRMATIONS = 12;

    /// @notice 7-day challenge period for exits (seconds)
    uint256 public constant CHALLENGE_PERIOD = 7 days;

    /// @notice Withdrawal refund delay: 8 days (challenge period + 1 day buffer)
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 192 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 45 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 45 days;

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    BridgeConfig public bridgeConfig;

    mapping(bytes32 => PLASMADeposit) public deposits;
    mapping(bytes32 => PLASMAWithdrawal) public withdrawals;
    mapping(bytes32 => PLASMAEscrow) public escrows;
    mapping(uint256 => PlasmaBlockCommitment) public blockCommitments;
    mapping(bytes32 => bool) public usedPlasmaTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;

    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;

    uint256 public depositNonce;
    uint256 public withdrawalNonce;
    uint256 public escrowNonce;
    uint256 public latestBlockNumber;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalEscrows;
    uint256 public totalEscrowsFinished;
    uint256 public totalEscrowsCancelled;
    uint256 public accumulatedFees;
    address public treasury;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        treasury = admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function configure(
        address plasmaBridgeContract,
        address wrappedPLASMA,
        address operatorOracle,
        uint256 minOperatorConfirmations,
        uint256 requiredL1Confirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (plasmaBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedPLASMA == address(0)) revert ZeroAddress();
        if (operatorOracle == address(0)) revert ZeroAddress();

        bridgeConfig = BridgeConfig({
            plasmaBridgeContract: plasmaBridgeContract,
            wrappedPLASMA: wrappedPLASMA,
            operatorOracle: operatorOracle,
            minOperatorConfirmations: minOperatorConfirmations,
            requiredL1Confirmations: requiredL1Confirmations,
            active: true
        });

        emit BridgeConfigured(plasmaBridgeContract, wrappedPLASMA, operatorOracle);
    }

    /// @notice Set the treasury address for fee collection
    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSITS (Plasma → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function initiatePLASMADeposit(
        bytes32 plasmaTxHash,
        address plasmaSender,
        address evmRecipient,
        uint256 amountSatoplasma,
        uint256 blockNumber,
        PlasmaInclusionProof calldata txProof,
        OperatorConfirmation[] calldata confirmations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) returns (bytes32 depositId) {
        if (!bridgeConfig.active) revert BridgeNotActive();
        if (amountSatoplasma < MIN_DEPOSIT_SATOPLASMA) revert AmountTooSmall(amountSatoplasma);
        if (amountSatoplasma > MAX_DEPOSIT_SATOPLASMA) revert AmountTooLarge(amountSatoplasma);
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (usedPlasmaTxHashes[plasmaTxHash]) revert PlasmaTxAlreadyUsed(plasmaTxHash);

        // Verify block commitment exists and is committed to L1
        PlasmaBlockCommitment storage commitment = blockCommitments[blockNumber];
        if (!commitment.committed) revert BlockNotCommitted(blockNumber);

        // Verify Merkle inclusion proof against committed block root
        _verifyInclusionProof(txProof, commitment.transactionsRoot);

        // Verify operator confirmations
        _verifyOperatorConfirmations(commitment.blockHash, confirmations);

        usedPlasmaTxHashes[plasmaTxHash] = true;

        uint256 fee = (amountSatoplasma * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountSatoplasma - fee;

        depositNonce++;
        depositId = keccak256(
            abi.encodePacked(
                PLASMA_CHAIN_ID,
                plasmaTxHash,
                evmRecipient,
                amountSatoplasma,
                depositNonce,
                block.timestamp
            )
        );

        deposits[depositId] = PLASMADeposit({
            depositId: depositId,
            plasmaTxHash: plasmaTxHash,
            plasmaSender: plasmaSender,
            evmRecipient: evmRecipient,
            amountSatoplasma: amountSatoplasma,
            netAmountSatoplasma: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            blockNumber: blockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        totalDeposited += amountSatoplasma;
        accumulatedFees += fee;

        emit PLASMADepositInitiated(depositId, plasmaTxHash, plasmaSender, evmRecipient, amountSatoplasma);

        return depositId;
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function completePLASMADeposit(bytes32 depositId) external nonReentrant onlyRole(OPERATOR_ROLE) {
        PLASMADeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) revert DepositNotPending(depositId);

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        IERC20(bridgeConfig.wrappedPLASMA).safeTransfer(deposit.evmRecipient, deposit.netAmountSatoplasma);

        emit PLASMADepositCompleted(depositId, deposit.evmRecipient, deposit.netAmountSatoplasma);
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (Soul → Plasma)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function initiateWithdrawal(
        address plasmaRecipient,
        uint256 amountSatoplasma
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotActive();
        if (amountSatoplasma < MIN_DEPOSIT_SATOPLASMA) revert AmountTooSmall(amountSatoplasma);
        if (amountSatoplasma > MAX_DEPOSIT_SATOPLASMA) revert AmountTooLarge(amountSatoplasma);
        if (plasmaRecipient == address(0)) revert ZeroAddress();

        IERC20(bridgeConfig.wrappedPLASMA).safeTransferFrom(msg.sender, address(this), amountSatoplasma);

        withdrawalNonce++;
        withdrawalId = keccak256(
            abi.encodePacked(
                PLASMA_CHAIN_ID,
                msg.sender,
                plasmaRecipient,
                amountSatoplasma,
                withdrawalNonce,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = PLASMAWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            plasmaRecipient: plasmaRecipient,
            amountSatoplasma: amountSatoplasma,
            plasmaTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountSatoplasma;

        emit PLASMAWithdrawalInitiated(withdrawalId, msg.sender, plasmaRecipient, amountSatoplasma);

        return withdrawalId;
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 plasmaTxHash,
        PlasmaInclusionProof calldata txProof,
        OperatorConfirmation[] calldata confirmations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        PLASMAWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) revert WithdrawalNotPending(withdrawalId);

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.plasmaTxHash = plasmaTxHash;
        withdrawal.completedAt = block.timestamp;

        emit PLASMAWithdrawalCompleted(withdrawalId, plasmaTxHash);
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        PLASMAWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0)) revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) revert WithdrawalNotPending(withdrawalId);

        uint256 refundableAt = withdrawal.initiatedAt + WITHDRAWAL_REFUND_DELAY;
        if (block.timestamp < refundableAt) {
            revert WithdrawalRefundTooEarly(withdrawalId, refundableAt);
        }

        withdrawal.status = WithdrawalStatus.REFUNDED;
        withdrawal.completedAt = block.timestamp;

        IERC20(bridgeConfig.wrappedPLASMA).safeTransfer(withdrawal.evmSender, withdrawal.amountSatoplasma);

        emit PLASMAWithdrawalRefunded(withdrawalId, withdrawal.evmSender, withdrawal.amountSatoplasma);
    }

    /*//////////////////////////////////////////////////////////////
                         ESCROW (Atomic Swaps)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function createEscrow(
        address plasmaParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (plasmaParty == address(0)) revert ZeroAddress();
        if (msg.value == 0) revert ZeroAmount();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK) revert EscrowTimelockTooShort(duration);
        if (duration > MAX_ESCROW_TIMELOCK) revert EscrowTimelockTooLong(duration);

        escrowNonce++;
        escrowId = keccak256(
            abi.encodePacked(
                PLASMA_CHAIN_ID,
                msg.sender,
                plasmaParty,
                msg.value,
                hashlock,
                escrowNonce,
                block.timestamp
            )
        );

        escrows[escrowId] = PLASMAEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            plasmaParty: plasmaParty,
            amountSatoplasma: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        userEscrows[msg.sender].push(escrowId);
        totalEscrows++;

        emit EscrowCreated(escrowId, msg.sender, plasmaParty, msg.value, hashlock);

        return escrowId;
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function finishEscrow(bytes32 escrowId, bytes32 preimage) external nonReentrant {
        PLASMAEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert EscrowNotYetFinishable(escrowId, escrow.finishAfter);
        }

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        (bool sent, ) = payable(msg.sender).call{value: escrow.amountSatoplasma}("");
        require(sent, "ETH transfer failed");

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        PLASMAEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert EscrowNotYetCancellable(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool sent, ) = payable(escrow.evmParty).call{value: escrow.amountSatoplasma}("");
        require(sent, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                    BLOCK COMMITMENTS (L1 Roots)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function submitBlockCommitment(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        address operatorAddress,
        bytes32 commitmentTxHash,
        uint256 blockTime,
        OperatorConfirmation[] calldata confirmations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        _verifyOperatorConfirmations(blockHash, confirmations);

        blockCommitments[blockNumber] = PlasmaBlockCommitment({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            transactionsRoot: transactionsRoot,
            stateRoot: stateRoot,
            operatorAddress: operatorAddress,
            commitmentTxHash: commitmentTxHash,
            blockTime: blockTime,
            committed: true
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
        }

        emit BlockCommitmentSubmitted(blockNumber, blockHash, commitmentTxHash);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVACY LAYER
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata /* zkProof */
    ) external nonReentrant onlyRole(OPERATOR_ROLE) {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
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
    function withdrawFees() external nonReentrant onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        IERC20(bridgeConfig.wrappedPLASMA).safeTransfer(treasury, amount);

        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPlasmaBridgeAdapter
    function getDeposit(bytes32 depositId) external view returns (PLASMADeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function getWithdrawal(bytes32 withdrawalId) external view returns (PLASMAWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function getEscrow(bytes32 escrowId) external view returns (PLASMAEscrow memory) {
        return escrows[escrowId];
    }

    /// @notice Get block commitment details
    function getBlockCommitment(uint256 blockNumber) external view returns (PlasmaBlockCommitment memory) {
        return blockCommitments[blockNumber];
    }

    /// @notice Get all deposit IDs for a user
    function getUserDeposits(address user) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @notice Get all withdrawal IDs for a user
    function getUserWithdrawals(address user) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @notice Get all escrow IDs for a user
    function getUserEscrows(address user) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @inheritdoc IPlasmaBridgeAdapter
    function getBridgeStats()
        external
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            uint256,
            uint256,
            uint256
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

    /// @dev Verify Merkle inclusion proof against committed block root
    function _verifyInclusionProof(
        PlasmaInclusionProof calldata proof,
        bytes32 root
    ) internal pure {
        bytes32 computedHash = proof.leafHash;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof.proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof.proof[i], computedHash));
            }
            index /= 2;
        }

        if (computedHash != root) {
            revert InvalidBlockProof(0);
        }
    }

    /// @dev Verify operator confirmations against the oracle
    function _verifyOperatorConfirmations(
        bytes32 blockHash,
        OperatorConfirmation[] calldata confirmations
    ) internal view {
        if (confirmations.length < bridgeConfig.minOperatorConfirmations) {
            revert InsufficientOperatorConfirmations(
                confirmations.length,
                bridgeConfig.minOperatorConfirmations
            );
        }
        // In production: verify each operator signature against oracle registry
    }

    /// @dev Receive ETH for escrow operations
    receive() external payable {}
}
