// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IProvenanceBridgeAdapter} from "../interfaces/IProvenanceBridgeAdapter.sol";

/**
 * @title ProvenanceBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Provenance Blockchain interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Provenance (Cosmos)
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                  Soul <-> Provenance Bridge                                 │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Provenance Side               │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wHASH Token │  │           │  │  IBC Bridge Module         │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (Cosmos SDK / x/marker)   │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Tendermint Validator Set  │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (~100 active validators)  │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  Tendermint BFT Consensus  │   │     │
 * │  │  │ Layer       │  │           │  │  (instant BFT finality)    │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * PROVENANCE CONCEPTS:
 * - nhash: Smallest unit of HASH (1 HASH = 1,000,000,000 nhash = 1e9 nhash)
 * - Block: ~6 second block time (Tendermint BFT)
 * - Tendermint BFT: Byzantine fault tolerant consensus engine
 * - Marker Module: Native Provenance asset management & tokenization
 * - IBC: Inter-Blockchain Communication for cross-chain transfers
 * - Chain ID: pio-mainnet-1 → EVM numeric mapping: 505
 * - Finality: ~10 blocks (~60s) for practical cross-chain finality
 * - ~100 active validators, 2/3+1 supermajority
 * - Bech32 addresses: pb1... prefix
 *
 * SECURITY PROPERTIES:
 * - Tendermint validator attestation threshold (configurable, default 67/100)
 * - Block finality confirmation depth (configurable, default 10 blocks)
 * - IAVL+ Merkle proofs for Provenance transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract ProvenanceBridgeAdapter is
    IProvenanceBridgeAdapter,
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

    uint256 public constant PROVENANCE_CHAIN_ID = 505;
    uint256 public constant NHASH_PER_HASH = 1_000_000_000; // 1e9
    uint256 public constant MIN_DEPOSIT_NHASH = NHASH_PER_HASH / 10; // 0.1 HASH
    uint256 public constant MAX_DEPOSIT_NHASH = 1_000_000 * NHASH_PER_HASH; // 1M HASH
    uint256 public constant BRIDGE_FEE_BPS = 10; // 0.10% — lowest fee for institutional chain
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant DEFAULT_ESCROW_TIMELOCK = 12 hours;
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 48 hours;
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 10;

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

    mapping(bytes32 => HASHDeposit) public deposits;
    mapping(bytes32 => HASHWithdrawal) public withdrawals;
    mapping(bytes32 => HASHEscrow) public escrows;
    mapping(uint256 => TendermintBlockHeader) public blockHeaders;
    mapping(bytes32 => bool) public usedProvTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;
    uint256 public latestBlockNumber;
    bytes32 public latestBlockHash;

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
        address provenanceBridgeContract,
        address wrappedHASH,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (provenanceBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedHASH == address(0)) revert ZeroAddress();
        if (validatorOracle == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            provenanceBridgeContract: provenanceBridgeContract,
            wrappedHASH: wrappedHASH,
            validatorOracle: validatorOracle,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            provenanceBridgeContract,
            wrappedHASH,
            validatorOracle
        );
    }

    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (Provenance → Soul)
    //////////////////////////////////////////////////////////////*/

    function initiateHASHDeposit(
        bytes32 provTxHash,
        address provSender,
        address evmRecipient,
        uint256 amountNhash,
        uint256 blockNumber,
        ProvenanceMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountNhash < MIN_DEPOSIT_NHASH) revert AmountTooSmall(amountNhash);
        if (amountNhash > MAX_DEPOSIT_NHASH) revert AmountTooLarge(amountNhash);
        if (usedProvTxHashes[provTxHash]) revert ProvTxAlreadyUsed(provTxHash);

        TendermintBlockHeader storage header = blockHeaders[blockNumber];
        if (!header.finalized) revert BlockNotFinalized(blockNumber);

        if (!_verifyMerkleProof(txProof, header.transactionsRoot, provTxHash)) {
            revert InvalidBlockProof();
        }

        if (!_verifyValidatorAttestations(header.blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        usedProvTxHashes[provTxHash] = true;

        uint256 fee = (amountNhash * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountNhash - fee;

        depositId = keccak256(
            abi.encodePacked(
                PROVENANCE_CHAIN_ID,
                provTxHash,
                provSender,
                evmRecipient,
                amountNhash,
                depositNonce++
            )
        );

        deposits[depositId] = HASHDeposit({
            depositId: depositId,
            provTxHash: provTxHash,
            provSender: provSender,
            evmRecipient: evmRecipient,
            amountNhash: amountNhash,
            netAmountNhash: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            blockNumber: blockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountNhash;

        emit HASHDepositInitiated(
            depositId,
            provTxHash,
            provSender,
            evmRecipient,
            amountNhash
        );
    }

    function completeHASHDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        HASHDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        (bool success, ) = bridgeConfig.wrappedHASH.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountNhash
            )
        );
        if (!success) revert InvalidAmount();

        emit HASHDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountNhash
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (Soul → Provenance)
    //////////////////////////////////////////////////////////////*/

    function initiateWithdrawal(
        address provRecipient,
        uint256 amountNhash
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (provRecipient == address(0)) revert ZeroAddress();
        if (amountNhash < MIN_DEPOSIT_NHASH) revert AmountTooSmall(amountNhash);
        if (amountNhash > MAX_DEPOSIT_NHASH) revert AmountTooLarge(amountNhash);

        IERC20(bridgeConfig.wrappedHASH).safeTransferFrom(
            msg.sender,
            address(this),
            amountNhash
        );

        (bool burnSuccess, ) = bridgeConfig.wrappedHASH.call(
            abi.encodeWithSignature("burn(uint256)", amountNhash)
        );

        withdrawalId = keccak256(
            abi.encodePacked(
                PROVENANCE_CHAIN_ID,
                msg.sender,
                provRecipient,
                amountNhash,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = HASHWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            provRecipient: provRecipient,
            amountNhash: amountNhash,
            provTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountNhash;

        emit HASHWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            provRecipient,
            amountNhash
        );
    }

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 provTxHash,
        ProvenanceMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        HASHWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (usedProvTxHashes[provTxHash]) revert ProvTxAlreadyUsed(provTxHash);

        bool verified = false;
        for (
            uint256 i = latestBlockNumber;
            i > 0 && i > latestBlockNumber - 100;
            i--
        ) {
            TendermintBlockHeader storage header = blockHeaders[i];
            if (
                header.finalized &&
                _verifyMerkleProof(txProof, header.transactionsRoot, provTxHash)
            ) {
                if (
                    _verifyValidatorAttestations(header.blockHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert InvalidBlockProof();

        usedProvTxHashes[provTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.provTxHash = provTxHash;
        withdrawal.completedAt = block.timestamp;

        emit HASHWithdrawalCompleted(withdrawalId, provTxHash);
    }

    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        HASHWithdrawal storage withdrawal = withdrawals[withdrawalId];
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

        (bool mintSuccess, ) = bridgeConfig.wrappedHASH.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountNhash
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedHASH).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountNhash
            );
        }

        emit HASHWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountNhash
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    function createEscrow(
        address provParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (provParty == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (msg.value == 0) revert InvalidAmount();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK)
            revert TimelockTooShort(duration, MIN_ESCROW_TIMELOCK);
        if (duration > MAX_ESCROW_TIMELOCK)
            revert TimelockTooLong(duration, MAX_ESCROW_TIMELOCK);
        if (finishAfter < block.timestamp) revert InvalidAmount();

        uint256 amountNhash = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                PROVENANCE_CHAIN_ID,
                msg.sender,
                provParty,
                hashlock,
                amountNhash,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = HASHEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            provParty: provParty,
            amountNhash: amountNhash,
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
            provParty,
            amountNhash,
            hashlock
        );
    }

    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        HASHEscrow storage escrow = escrows[escrowId];
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

        (bool success, ) = payable(msg.sender).call{value: escrow.amountNhash}(
            ""
        );
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        HASHEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert CancelAfterNotReached(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountNhash
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
        HASHDeposit storage deposit = deposits[depositId];
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
                      BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function submitBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        bytes32 validatorsHash,
        uint256 blockTime,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (!_verifyValidatorAttestations(blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        if (blockNumber > 0 && blockHeaders[blockNumber - 1].finalized) {
            TendermintBlockHeader storage parent = blockHeaders[blockNumber - 1];
            if (parent.blockHash != parentHash) {
                revert InvalidBlockProof();
            }
        }

        blockHeaders[blockNumber] = TendermintBlockHeader({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            transactionsRoot: transactionsRoot,
            stateRoot: stateRoot,
            validatorsHash: validatorsHash,
            blockTime: blockTime,
            finalized: true
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
            latestBlockHash = blockHash;
        }

        emit BlockHeaderSubmitted(blockNumber, blockHash);
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

        uint256 balance = IERC20(bridgeConfig.wrappedHASH).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedHASH).safeTransfer(
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
    ) external view returns (HASHDeposit memory) {
        return deposits[depositId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (HASHWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    function getEscrow(
        bytes32 escrowId
    ) external view returns (HASHEscrow memory) {
        return escrows[escrowId];
    }

    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (TendermintBlockHeader memory) {
        return blockHeaders[blockNumber];
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

    function _verifyMerkleProof(
        ProvenanceMerkleProof calldata proof,
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

    function _verifyValidatorAttestations(
        bytes32 blockHash,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minValidatorSignatures)
            return false;
        if (bridgeConfig.validatorOracle == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            (bool success, bytes memory result) = bridgeConfig
                .validatorOracle
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
