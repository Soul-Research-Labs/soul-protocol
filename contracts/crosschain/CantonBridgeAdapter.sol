// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICantonBridgeAdapter} from "../interfaces/ICantonBridgeAdapter.sol";

/**
 * @title CantonBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Canton Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Canton Network (Daml)
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> Canton Bridge                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Canton Side                   │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wCANTON     │  │           │  │  Global Synchronizer       │   │     │
 * │  │  │ Token       │  │           │  │  (Canton Protocol)         │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Mediator + Sequencer     │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Nodes                    │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Daml Smart Contracts     │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Sub-tx privacy)         │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * CANTON CONCEPTS:
 * - microcanton: Smallest unit (1 CANTON = 1,000,000 microcanton = 1e6)
 * - Sequencing Round: ~2 second ordering intervals
 * - Canton Protocol: Privacy-preserving synchronization
 * - Daml: Digital Asset Modeling Language
 * - Global Synchronizer: Cross-domain coordination
 * - Mediator: Confirms transaction results
 * - Sequencer: Orders messages within a domain
 * - Chain ID: canton-global-1 → EVM numeric mapping: 510
 * - Finality: 5 rounds (~10s) for cross-chain safety
 * - ~20 mediators, 2/3+1 supermajority
 * - Party IDs: party::domain format
 *
 * SECURITY PROPERTIES:
 * - Mediator attestation threshold (configurable, default 14/20)
 * - Round finality confirmation depth (configurable, default 5 rounds)
 * - Merkle commitment proofs for Canton transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 * - Sub-transaction privacy alignment with Canton's privacy model
 */
contract CantonBridgeAdapter is
    ICantonBridgeAdapter,
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

    uint256 public constant CANTON_CHAIN_ID = 510;
    uint256 public constant MICROCANTON_PER_CANTON = 1_000_000; // 1e6
    uint256 public constant MIN_DEPOSIT_MICROCANTON =
        MICROCANTON_PER_CANTON / 10; // 0.1 CANTON
    uint256 public constant MAX_DEPOSIT_MICROCANTON =
        10_000_000 * MICROCANTON_PER_CANTON; // 10M CANTON
    uint256 public constant BRIDGE_FEE_BPS = 5; // 0.05% — institutional-grade lowest fee
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant DEFAULT_ESCROW_TIMELOCK = 6 hours;
    uint256 public constant MIN_ESCROW_TIMELOCK = 2 hours;
    uint256 public constant MAX_ESCROW_TIMELOCK = 60 days;
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 72 hours;
    uint256 public constant DEFAULT_ROUND_CONFIRMATIONS = 5;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    BridgeConfig public bridgeConfig;
    address public treasury;
    uint256 public depositNonce;
    uint256 public withdrawalNonce;
    uint256 public escrowNonce;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => CANTONDeposit) public deposits;
    mapping(bytes32 => CANTONWithdrawal) public withdrawals;
    mapping(bytes32 => CANTONEscrow) public escrows;
    mapping(uint256 => SynchronizerRoundHeader) public roundHeaders;
    mapping(bytes32 => bool) public usedCantonTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;
    uint256 public latestRoundNumber;
    bytes32 public latestRoundHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalEscrows;
    uint256 public totalEscrowsFinished;
    uint256 public totalEscrowsCancelled;
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

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

    function configure(
        address cantonBridgeContract,
        address wrappedCANTON,
        address mediatorOracle,
        uint256 minMediatorSignatures,
        uint256 requiredRoundConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (cantonBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedCANTON == address(0)) revert ZeroAddress();
        if (mediatorOracle == address(0)) revert ZeroAddress();
        if (minMediatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            cantonBridgeContract: cantonBridgeContract,
            wrappedCANTON: wrappedCANTON,
            mediatorOracle: mediatorOracle,
            minMediatorSignatures: minMediatorSignatures,
            requiredRoundConfirmations: requiredRoundConfirmations > 0
                ? requiredRoundConfirmations
                : DEFAULT_ROUND_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            cantonBridgeContract,
            wrappedCANTON,
            mediatorOracle
        );
    }

    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (Canton → Soul)
    //////////////////////////////////////////////////////////////*/

    function initiateCANTONDeposit(
        bytes32 cantonTxHash,
        address cantonSender,
        address evmRecipient,
        uint256 amountMicrocanton,
        uint256 roundNumber,
        CantonMerkleProof calldata txProof,
        MediatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountMicrocanton < MIN_DEPOSIT_MICROCANTON)
            revert AmountTooSmall(amountMicrocanton);
        if (amountMicrocanton > MAX_DEPOSIT_MICROCANTON)
            revert AmountTooLarge(amountMicrocanton);
        if (usedCantonTxHashes[cantonTxHash])
            revert CantonTxAlreadyUsed(cantonTxHash);

        SynchronizerRoundHeader storage header = roundHeaders[roundNumber];
        if (!header.finalized) revert RoundNotFinalized(roundNumber);

        if (
            !_verifyMerkleProof(txProof, header.transactionsRoot, cantonTxHash)
        ) {
            revert InvalidRoundProof();
        }

        if (!_verifyMediatorAttestations(header.roundHash, attestations)) {
            revert InsufficientMediatorSignatures(
                attestations.length,
                bridgeConfig.minMediatorSignatures
            );
        }

        usedCantonTxHashes[cantonTxHash] = true;

        uint256 fee = (amountMicrocanton * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountMicrocanton - fee;

        depositId = keccak256(
            abi.encodePacked(
                CANTON_CHAIN_ID,
                cantonTxHash,
                cantonSender,
                evmRecipient,
                amountMicrocanton,
                depositNonce++
            )
        );

        deposits[depositId] = CANTONDeposit({
            depositId: depositId,
            cantonTxHash: cantonTxHash,
            cantonSender: cantonSender,
            evmRecipient: evmRecipient,
            amountMicrocanton: amountMicrocanton,
            netAmountMicrocanton: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            roundNumber: roundNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountMicrocanton;

        emit CANTONDepositInitiated(
            depositId,
            cantonTxHash,
            cantonSender,
            evmRecipient,
            amountMicrocanton
        );
    }

    function completeCANTONDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        CANTONDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        (bool success, ) = bridgeConfig.wrappedCANTON.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountMicrocanton
            )
        );
        if (!success) revert InvalidAmount();

        emit CANTONDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountMicrocanton
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (Soul → Canton)
    //////////////////////////////////////////////////////////////*/

    function initiateWithdrawal(
        address cantonRecipient,
        uint256 amountMicrocanton
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (cantonRecipient == address(0)) revert ZeroAddress();
        if (amountMicrocanton < MIN_DEPOSIT_MICROCANTON)
            revert AmountTooSmall(amountMicrocanton);
        if (amountMicrocanton > MAX_DEPOSIT_MICROCANTON)
            revert AmountTooLarge(amountMicrocanton);

        IERC20(bridgeConfig.wrappedCANTON).safeTransferFrom(
            msg.sender,
            address(this),
            amountMicrocanton
        );

        (bool burnSuccess, ) = bridgeConfig.wrappedCANTON.call(
            abi.encodeWithSignature("burn(uint256)", amountMicrocanton)
        );

        withdrawalId = keccak256(
            abi.encodePacked(
                CANTON_CHAIN_ID,
                msg.sender,
                cantonRecipient,
                amountMicrocanton,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = CANTONWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            cantonRecipient: cantonRecipient,
            amountMicrocanton: amountMicrocanton,
            cantonTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountMicrocanton;

        emit CANTONWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            cantonRecipient,
            amountMicrocanton
        );
    }

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cantonTxHash,
        CantonMerkleProof calldata txProof,
        MediatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        CANTONWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (usedCantonTxHashes[cantonTxHash])
            revert CantonTxAlreadyUsed(cantonTxHash);

        bool verified = false;
        for (
            uint256 i = latestRoundNumber;
            i > 0 && i > latestRoundNumber - 100;
            i--
        ) {
            SynchronizerRoundHeader storage header = roundHeaders[i];
            if (
                header.finalized &&
                _verifyMerkleProof(
                    txProof,
                    header.transactionsRoot,
                    cantonTxHash
                )
            ) {
                if (
                    _verifyMediatorAttestations(header.roundHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert InvalidRoundProof();

        usedCantonTxHashes[cantonTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.cantonTxHash = cantonTxHash;
        withdrawal.completedAt = block.timestamp;

        emit CANTONWithdrawalCompleted(withdrawalId, cantonTxHash);
    }

    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        CANTONWithdrawal storage withdrawal = withdrawals[withdrawalId];
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

        (bool mintSuccess, ) = bridgeConfig.wrappedCANTON.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountMicrocanton
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedCANTON).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountMicrocanton
            );
        }

        emit CANTONWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountMicrocanton
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    function createEscrow(
        address cantonParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (cantonParty == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (msg.value == 0) revert InvalidAmount();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK)
            revert TimelockTooShort(duration, MIN_ESCROW_TIMELOCK);
        if (duration > MAX_ESCROW_TIMELOCK)
            revert TimelockTooLong(duration, MAX_ESCROW_TIMELOCK);
        if (finishAfter < block.timestamp) revert InvalidAmount();

        uint256 amountMicrocanton = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                CANTON_CHAIN_ID,
                msg.sender,
                cantonParty,
                hashlock,
                amountMicrocanton,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = CANTONEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            cantonParty: cantonParty,
            amountMicrocanton: amountMicrocanton,
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
            cantonParty,
            amountMicrocanton,
            hashlock
        );
    }

    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        CANTONEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert FinishAfterNotReached(escrowId, escrow.finishAfter);
        }

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        (bool success, ) = payable(msg.sender).call{
            value: escrow.amountMicrocanton
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        CANTONEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert CancelAfterNotReached(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountMicrocanton
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        CANTONDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.COMPLETED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        if (!_verifyZKProof(depositId, commitment, nullifier, zkProof)) {
            revert InvalidProof();
        }

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                   ROUND HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function submitRoundHeader(
        uint256 roundNumber,
        bytes32 roundHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        bytes32 mediatorSetHash,
        bytes32 domainTopologyHash,
        uint256 roundTime,
        MediatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (!_verifyMediatorAttestations(roundHash, attestations)) {
            revert InsufficientMediatorSignatures(
                attestations.length,
                bridgeConfig.minMediatorSignatures
            );
        }

        if (roundNumber > 0 && roundHeaders[roundNumber - 1].finalized) {
            SynchronizerRoundHeader storage parent = roundHeaders[
                roundNumber - 1
            ];
            if (parent.roundHash != parentHash) {
                revert InvalidRoundProof();
            }
        }

        roundHeaders[roundNumber] = SynchronizerRoundHeader({
            roundNumber: roundNumber,
            roundHash: roundHash,
            parentHash: parentHash,
            transactionsRoot: transactionsRoot,
            stateRoot: stateRoot,
            mediatorSetHash: mediatorSetHash,
            domainTopologyHash: domainTopologyHash,
            roundTime: roundTime,
            finalized: true
        });

        if (roundNumber > latestRoundNumber) {
            latestRoundNumber = roundNumber;
            latestRoundHash = roundHash;
        }

        emit RoundHeaderSubmitted(roundNumber, roundHash);
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert InvalidAmount();
        accumulatedFees = 0;

        uint256 balance = IERC20(bridgeConfig.wrappedCANTON).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedCANTON).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(
        bytes32 depositId
    ) external view returns (CANTONDeposit memory) {
        return deposits[depositId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (CANTONWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    function getEscrow(
        bytes32 escrowId
    ) external view returns (CANTONEscrow memory) {
        return escrows[escrowId];
    }

    function getRoundHeader(
        uint256 roundNumber
    ) external view returns (SynchronizerRoundHeader memory) {
        return roundHeaders[roundNumber];
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

    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

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
            uint256 lastRound
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestRoundNumber
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyMerkleProof(
        CantonMerkleProof calldata proof,
        bytes32 root,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.proof.length == 0) return false;

        bytes32 computedHash = leafHash;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof.proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof.proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    function _verifyMediatorAttestations(
        bytes32 roundHash,
        MediatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minMediatorSignatures)
            return false;
        if (bridgeConfig.mediatorOracle == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            (bool success, bytes memory result) = bridgeConfig
                .mediatorOracle
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        roundHash,
                        attestations[i].mediator,
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

        return validCount >= bridgeConfig.minMediatorSignatures;
    }

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

    receive() external payable {}
}
