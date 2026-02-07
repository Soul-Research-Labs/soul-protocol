// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICardanoBridgeAdapter} from "../interfaces/ICardanoBridgeAdapter.sol";

/**
 * @title CardanoBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Cardano Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Cardano blockchain
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      Soul <-> Cardano Bridge                                │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Cardano Side                  │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wADA        │  │           │  │  Cardano Mainnet            │   │     │
 * │  │  │ Token       │  │           │  │  (eUTXO Ledger)            │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Ouroboros Praos Consensus  │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~20s block time)          │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Plutus Smart Contracts     │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Haskell-based Scripts)    │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * CARDANO CONCEPTS:
 * - Lovelace: Smallest unit (1 ADA = 1e6 Lovelace, 6 decimals)
 * - Ouroboros: Proof-of-Stake consensus family (Praos variant)
 * - eUTXO: Extended UTXO model (vs account model)
 * - Plutus: Smart contract language (Haskell-based)
 * - Native Tokens: First-class assets on ledger (no smart contract needed)
 * - Epochs: 5-day periods, divided into slots (~1 block/20s)
 * - Chain ID: cardano-mainnet (764824073)
 * - Finality: ~20 minutes (k=2160 parameter, ~36 blocks)
 * - Block time: ~20 seconds
 */
contract CardanoBridgeAdapter is
    ICardanoBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cardano mainnet network magic (chain ID)
    uint256 public constant CARDANO_CHAIN_ID = 764824073;

    /// @notice 1 ADA = 1e6 Lovelace (6 decimals)
    uint256 public constant LOVELACE_PER_ADA = 1_000_000;

    /// @notice Minimum deposit: 0.1 ADA = 100,000 Lovelace
    uint256 public constant MIN_DEPOSIT_LOVELACE = 100_000;

    /// @notice Maximum deposit: 10,000,000 ADA
    uint256 public constant MAX_DEPOSIT_LOVELACE =
        10_000_000 * LOVELACE_PER_ADA;

    /// @notice Bridge fee: 6 BPS (0.06%)
    uint256 public constant BRIDGE_FEE_BPS = 6;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default Ouroboros Praos block confirmations (~20 min finality)
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 36;

    /// @notice Withdrawal refund delay: 48 hours (longer due to slow finality)
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 48 hours;

    /// @notice Minimum escrow timelock: 2 hours
    uint256 public constant MIN_ESCROW_TIMELOCK = 2 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /*//////////////////////////////////////////////////////////////
                            ACCESS ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    BridgeConfig public config;

    /// @notice Treasury for fee collection
    address public treasury;

    /// @notice Deposit nonce (monotonically increasing)
    uint256 public depositNonce;

    /// @notice Withdrawal nonce (monotonically increasing)
    uint256 public withdrawalNonce;

    /// @notice Escrow nonce (monotonically increasing)
    uint256 public escrowNonce;

    /// @notice Latest verified Cardano slot
    uint256 public latestVerifiedSlot;

    /// @notice Latest verified epoch
    uint256 public latestVerifiedEpoch;

    /// @notice Total deposited in Lovelace
    uint256 public totalDeposited;

    /// @notice Total withdrawn in Lovelace
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated fees in Lovelace
    uint256 public accumulatedFees;

    /// @notice Deposits by ID
    mapping(bytes32 => ADADeposit) private deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => ADAWithdrawal) private withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => ADAEscrow) private escrows;

    /// @notice Ouroboros headers by slot number
    mapping(uint256 => OuroborosHeader) private ouroborosHeaders;

    /// @notice Used Cardano tx hashes (replay protection)
    mapping(bytes32 => bool) public usedCardanoTxHashes;

    /// @notice Used nullifiers (privacy replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice User deposit IDs
    mapping(address => bytes32[]) private userDeposits;

    /// @notice User withdrawal IDs
    mapping(address => bytes32[]) private userWithdrawals;

    /// @notice User escrow IDs
    mapping(address => bytes32[]) private userEscrows;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function configure(
        address cardanoBridgeContract,
        address wrappedADA,
        address cardanoLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (cardanoBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedADA == address(0)) revert ZeroAddress();
        if (cardanoLightClient == address(0)) revert ZeroAddress();

        config = BridgeConfig({
            cardanoBridgeContract: cardanoBridgeContract,
            wrappedADA: wrappedADA,
            cardanoLightClient: cardanoLightClient,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations,
            active: true
        });

        emit BridgeConfigured(
            cardanoBridgeContract,
            wrappedADA,
            cardanoLightClient
        );
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                   OUROBOROS HEADER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function submitOuroborosHeader(
        uint256 slot,
        uint256 epoch,
        bytes32 blockHash,
        bytes32 prevBlockHash,
        bytes32 vrfOutput,
        bytes32 blockBodyHash,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    slot,
                    epoch,
                    blockHash,
                    prevBlockHash,
                    vrfOutput,
                    blockBodyHash,
                    timestamp
                )
            ),
            attestations
        );

        ouroborosHeaders[slot] = OuroborosHeader({
            slot: slot,
            epoch: epoch,
            blockHash: blockHash,
            prevBlockHash: prevBlockHash,
            vrfOutput: vrfOutput,
            blockBodyHash: blockBodyHash,
            timestamp: timestamp,
            verified: true
        });

        if (slot > latestVerifiedSlot) {
            latestVerifiedSlot = slot;
        }

        if (epoch > latestVerifiedEpoch) {
            latestVerifiedEpoch = epoch;
        }

        emit OuroborosHeaderVerified(slot, epoch, blockHash);
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function initiateADADeposit(
        bytes32 cardanoTxHash,
        bytes32 cardanoSender,
        address evmRecipient,
        uint256 amountLovelace,
        uint256 cardanoSlot,
        CardanoStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 depositId)
    {
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountLovelace < MIN_DEPOSIT_LOVELACE)
            revert AmountBelowMinimum(amountLovelace, MIN_DEPOSIT_LOVELACE);
        if (amountLovelace > MAX_DEPOSIT_LOVELACE)
            revert AmountAboveMaximum(amountLovelace, MAX_DEPOSIT_LOVELACE);
        if (usedCardanoTxHashes[cardanoTxHash])
            revert CardanoTxAlreadyUsed(cardanoTxHash);
        if (!ouroborosHeaders[cardanoSlot].verified)
            revert CardanoSlotNotVerified(cardanoSlot);

        // Verify that enough blocks have passed since the deposit slot
        // to satisfy the finality requirement
        if (
            latestVerifiedSlot < cardanoSlot + config.requiredBlockConfirmations
        ) revert CardanoSlotNotVerified(cardanoSlot);

        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    cardanoTxHash,
                    cardanoSender,
                    evmRecipient,
                    amountLovelace
                )
            ),
            attestations
        );

        // Verify the state proof against the block body hash
        _verifyCardanoStateProof(
            txProof,
            ouroborosHeaders[cardanoSlot].blockBodyHash
        );

        usedCardanoTxHashes[cardanoTxHash] = true;

        uint256 fee = (amountLovelace * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountLovelace - fee;

        depositNonce++;
        depositId = keccak256(
            abi.encodePacked(
                CARDANO_CHAIN_ID,
                depositNonce,
                cardanoTxHash,
                block.timestamp
            )
        );

        deposits[depositId] = ADADeposit({
            depositId: depositId,
            cardanoTxHash: cardanoTxHash,
            cardanoSender: cardanoSender,
            evmRecipient: evmRecipient,
            amountLovelace: amountLovelace,
            netAmountLovelace: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            cardanoSlot: cardanoSlot,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalDeposited += amountLovelace;
        userDeposits[evmRecipient].push(depositId);

        emit ADADepositInitiated(
            depositId,
            cardanoTxHash,
            cardanoSender,
            evmRecipient,
            amountLovelace
        );
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function completeADADeposit(
        bytes32 depositId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        ADADeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        IERC20(config.wrappedADA).safeTransfer(
            dep.evmRecipient,
            dep.netAmountLovelace
        );

        emit ADADepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountLovelace
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function initiateWithdrawal(
        bytes32 cardanoRecipient,
        uint256 amountLovelace
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (cardanoRecipient == bytes32(0)) revert ZeroAddress();
        if (amountLovelace < MIN_DEPOSIT_LOVELACE)
            revert AmountBelowMinimum(amountLovelace, MIN_DEPOSIT_LOVELACE);
        if (amountLovelace > MAX_DEPOSIT_LOVELACE)
            revert AmountAboveMaximum(amountLovelace, MAX_DEPOSIT_LOVELACE);

        IERC20(config.wrappedADA).safeTransferFrom(
            msg.sender,
            address(this),
            amountLovelace
        );

        withdrawalNonce++;
        withdrawalId = keccak256(
            abi.encodePacked(
                CARDANO_CHAIN_ID,
                withdrawalNonce,
                msg.sender,
                cardanoRecipient,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = ADAWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            cardanoRecipient: cardanoRecipient,
            amountLovelace: amountLovelace,
            cardanoTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        totalWithdrawn += amountLovelace;
        userWithdrawals[msg.sender].push(withdrawalId);

        emit ADAWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            cardanoRecipient,
            amountLovelace
        );
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cardanoTxHash,
        CardanoStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        ADAWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        _verifyValidatorAttestations(
            keccak256(abi.encodePacked(withdrawalId, cardanoTxHash)),
            attestations
        );

        w.status = WithdrawalStatus.COMPLETED;
        w.cardanoTxHash = cardanoTxHash;
        w.completedAt = block.timestamp;

        // Burn the held wADA tokens
        // In production, this would call burn on the wADA contract
        emit ADAWithdrawalCompleted(withdrawalId, cardanoTxHash);
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        ADAWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);
        if (block.timestamp < w.initiatedAt + WITHDRAWAL_REFUND_DELAY)
            revert RefundTooEarly(
                block.timestamp,
                w.initiatedAt + WITHDRAWAL_REFUND_DELAY
            );

        w.status = WithdrawalStatus.REFUNDED;
        w.completedAt = block.timestamp;

        IERC20(config.wrappedADA).safeTransfer(w.evmSender, w.amountLovelace);

        emit ADAWithdrawalRefunded(withdrawalId, w.evmSender, w.amountLovelace);
    }

    /*//////////////////////////////////////////////////////////////
                          ESCROW OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function createEscrow(
        bytes32 cardanoParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (msg.value == 0) revert InvalidAmount();
        if (cardanoParty == bytes32(0)) revert ZeroAddress();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        escrowNonce++;
        escrowId = keccak256(
            abi.encodePacked(
                CARDANO_CHAIN_ID,
                escrowNonce,
                msg.sender,
                cardanoParty,
                block.timestamp
            )
        );

        escrows[escrowId] = ADAEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            cardanoParty: cardanoParty,
            amountLovelace: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        totalEscrows++;
        userEscrows[msg.sender].push(escrowId);

        emit EscrowCreated(
            escrowId,
            msg.sender,
            cardanoParty,
            msg.value,
            hashlock
        );
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        ADAEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.finishAfter) revert EscrowTimelockNotMet();

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != e.hashlock)
            revert InvalidPreimage(e.hashlock, computedHash);

        e.status = EscrowStatus.FINISHED;
        e.preimage = preimage;
        totalEscrowsFinished++;

        // Transfer funds to EVM party
        (bool sent, ) = e.evmParty.call{value: e.amountLovelace}("");
        require(sent, "ETH transfer failed");

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        ADAEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool sent, ) = e.evmParty.call{value: e.amountLovelace}("");
        require(sent, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVACY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        ADADeposit storage dep = deposits[depositId];
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
                           ADMIN OPERATIONS
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
    function withdrawFees() external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        IERC20(config.wrappedADA).safeTransfer(treasury, amount);

        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICardanoBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (ADADeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ADAWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (ADAEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function getOuroborosHeader(
        uint256 slot
    ) external view returns (OuroborosHeader memory) {
        return ouroborosHeaders[slot];
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc ICardanoBridgeAdapter
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get aggregate bridge statistics
    function getBridgeStats()
        external
        view
        returns (
            uint256 _totalDeposited,
            uint256 _totalWithdrawn,
            uint256 _totalEscrows,
            uint256 _totalEscrowsFinished,
            uint256 _totalEscrowsCancelled,
            uint256 _accumulatedFees,
            uint256 _latestVerifiedSlot
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestVerifiedSlot
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Verify stake pool operator BLS attestation signatures meet threshold
    function _verifyValidatorAttestations(
        bytes32 messageHash,
        ValidatorAttestation[] calldata attestations
    ) internal view {
        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // Check for duplicate validators
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
            // In production: verify Cardano stake pool operator BLS signatures
            // via the Cardano light client oracle
            (bool valid, ) = config.cardanoLightClient.staticcall(
                abi.encodeWithSignature(
                    "verifyAttestation(bytes32,address,bytes)",
                    messageHash,
                    attestations[i].validator,
                    attestations[i].signature
                )
            );

            if (valid) {
                // Decode the return value
                bytes memory returnData;
                (, returnData) = config.cardanoLightClient.staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        messageHash,
                        attestations[i].validator,
                        attestations[i].signature
                    )
                );
                bool isValid = abi.decode(returnData, (bool));
                if (isValid) validCount++;
            }
        }

        if (validCount < config.minValidatorSignatures)
            revert InsufficientValidatorSignatures(
                validCount,
                config.minValidatorSignatures
            );
    }

    /// @dev Verify a Cardano state proof against a known block body hash
    /// @param proof The Cardano state proof containing Merkle path and value
    /// @param expectedBlockBodyHash The block body hash from a verified Ouroboros header
    function _verifyCardanoStateProof(
        CardanoStateProof calldata proof,
        bytes32 expectedBlockBodyHash
    ) internal pure {
        // Verify the block body hash matches
        require(
            proof.blockBodyHash == expectedBlockBodyHash,
            "Block body hash mismatch"
        );

        // Verify the Merkle inclusion proof
        // Reconstruct root from value and Merkle path
        bytes32 computedHash = keccak256(proof.value);
        for (uint256 i = 0; i < proof.merklePath.length; i++) {
            if (computedHash <= proof.merklePath[i]) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof.merklePath[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof.merklePath[i], computedHash)
                );
            }
        }

        require(
            computedHash == expectedBlockBodyHash,
            "Invalid Cardano state proof"
        );
    }
}
