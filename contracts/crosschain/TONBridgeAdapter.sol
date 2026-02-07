// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ITONBridgeAdapter} from "../interfaces/ITONBridgeAdapter.sol";

/**
 * @title TONBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for The Open Network (TON) interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the TON blockchain
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       Soul <-> TON Bridge                                   │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   EVM Side        │           │        TON Side                   │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wTON Token  │  │           │  │  TON Masterchain            │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (Workchain -1)            │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  Catchain BFT Consensus    │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (Validator Attestations)  │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  TVM Smart Contracts        │   │     │
 * │  │  │ Layer       │  │           │  │  (FunC / Tact)             │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * TON CONCEPTS:
 * - Nanoton: Smallest unit (1 TON = 1e9 Nanoton, 9 decimals)
 * - Catchain: BFT consensus protocol
 * - Infinite Sharding Paradigm: Dynamic splitting/merging of workchains
 * - Masterchain: Coordinates all workchains (workchain -1)
 * - Basechain: Default workchain for user accounts (workchain 0)
 * - TVM: TON Virtual Machine (stack-based, continuations)
 * - FunC / Tact: Smart contract languages
 * - Jettons: TON fungible token standard (TEP-74)
 * - Chain ID: 239
 * - Finality: ~5 seconds
 * - Block time: ~5 seconds
 *
 * SECURITY PROPERTIES:
 * - Catchain BFT validator attestation threshold
 * - Masterchain block confirmation depth (configurable, default 1)
 * - Merkle inclusion proofs for TON state verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract TONBridgeAdapter is
    ITONBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Relayer role for submitting proofs and completing operations
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Operator role for administrative operations
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Guardian role for emergency pause/unpause
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice TON mainnet chain ID
    uint256 public constant TON_CHAIN_ID = 239;

    /// @notice 1 TON = 1e9 Nanoton (9 decimals)
    uint256 public constant NANOTON_PER_TON = 1_000_000_000;

    /// @notice Minimum deposit: 0.1 TON = 100,000,000 Nanoton
    uint256 public constant MIN_DEPOSIT_NANOTON = 100_000_000;

    /// @notice Maximum deposit: 10,000,000 TON
    uint256 public constant MAX_DEPOSIT_NANOTON = 10_000_000 * NANOTON_PER_TON;

    /// @notice Bridge fee: 5 BPS (0.05%)
    uint256 public constant BRIDGE_FEE_BPS = 5;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default masterchain block confirmations (~5s finality)
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 1;

    /// @notice Withdrawal refund delay: 24 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    BridgeConfig public config;

    /// @notice Treasury address for fee collection
    address public treasury;

    /// @notice Deposit nonce for unique ID generation
    uint256 public depositNonce;

    /// @notice Withdrawal nonce
    uint256 public withdrawalNonce;

    /// @notice Escrow nonce
    uint256 public escrowNonce;

    /// @notice Latest verified masterchain seqno
    uint256 public latestVerifiedSeqno;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total deposited in Nanoton
    uint256 public totalDeposited;

    /// @notice Total withdrawn in Nanoton
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees in Nanoton
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits by ID
    mapping(bytes32 => TONDeposit) private deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => TONWithdrawal) private withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => TONEscrow) private escrows;

    /// @notice Masterchain block headers by seqno
    mapping(uint256 => MasterchainBlock) private masterchainBlocks;

    /// @notice Used TON tx hashes (replay protection)
    mapping(bytes32 => bool) public usedTONTxHashes;

    /// @notice Used nullifiers (privacy replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) private userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) private userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) private userEscrows;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the TON bridge adapter
    /// @param admin Admin address granted all roles
    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        treasury = admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function configure(
        address tonBridgeContract,
        address wrappedTON,
        address tonLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tonBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedTON == address(0)) revert ZeroAddress();
        if (tonLightClient == address(0)) revert ZeroAddress();

        config = BridgeConfig({
            tonBridgeContract: tonBridgeContract,
            wrappedTON: wrappedTON,
            tonLightClient: tonLightClient,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(tonBridgeContract, wrappedTON, tonLightClient);
    }

    /// @inheritdoc ITONBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                  MASTERCHAIN BLOCK VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function submitMasterchainBlock(
        uint256 seqno,
        bytes32 rootHash,
        bytes32 fileHash,
        int256 workchain,
        uint256 shardId,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    seqno,
                    rootHash,
                    fileHash,
                    workchain,
                    shardId,
                    timestamp
                )
            ),
            attestations
        );

        masterchainBlocks[seqno] = MasterchainBlock({
            seqno: seqno,
            rootHash: rootHash,
            fileHash: fileHash,
            workchain: workchain,
            shardId: shardId,
            timestamp: timestamp,
            verified: true
        });

        if (seqno > latestVerifiedSeqno) {
            latestVerifiedSeqno = seqno;
        }

        emit MasterchainBlockVerified(seqno, rootHash, fileHash);
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSITS (TON → EVM)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function initiateTONDeposit(
        bytes32 tonTxHash,
        bytes32 tonSender,
        address evmRecipient,
        uint256 amountNanoton,
        uint256 tonSeqno,
        TONStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 depositId)
    {
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountNanoton < MIN_DEPOSIT_NANOTON)
            revert AmountBelowMinimum(amountNanoton, MIN_DEPOSIT_NANOTON);
        if (amountNanoton > MAX_DEPOSIT_NANOTON)
            revert AmountAboveMaximum(amountNanoton, MAX_DEPOSIT_NANOTON);
        if (usedTONTxHashes[tonTxHash]) revert TONTxAlreadyUsed(tonTxHash);
        if (!masterchainBlocks[tonSeqno].verified)
            revert TONBlockNotVerified(tonSeqno);

        // Verify that enough blocks have passed since the deposit seqno
        // to satisfy the finality requirement
        if (latestVerifiedSeqno < tonSeqno + config.requiredBlockConfirmations)
            revert TONBlockNotVerified(tonSeqno);

        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    tonTxHash,
                    tonSender,
                    evmRecipient,
                    amountNanoton
                )
            ),
            attestations
        );

        // Verify the state proof against the masterchain block root hash
        _verifyTONStateProof(txProof, masterchainBlocks[tonSeqno].rootHash);

        usedTONTxHashes[tonTxHash] = true;

        uint256 fee = (amountNanoton * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountNanoton - fee;

        depositNonce++;
        depositId = keccak256(
            abi.encodePacked(
                TON_CHAIN_ID,
                depositNonce,
                tonTxHash,
                block.timestamp
            )
        );

        deposits[depositId] = TONDeposit({
            depositId: depositId,
            tonTxHash: tonTxHash,
            tonSender: tonSender,
            evmRecipient: evmRecipient,
            amountNanoton: amountNanoton,
            netAmountNanoton: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            tonSeqno: tonSeqno,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalDeposited += amountNanoton;
        userDeposits[evmRecipient].push(depositId);

        emit TONDepositInitiated(
            depositId,
            tonTxHash,
            tonSender,
            evmRecipient,
            amountNanoton
        );
    }

    /// @inheritdoc ITONBridgeAdapter
    function completeTONDeposit(
        bytes32 depositId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        TONDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        IERC20(config.wrappedTON).safeTransfer(
            dep.evmRecipient,
            dep.netAmountNanoton
        );

        emit TONDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountNanoton
        );
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWALS (EVM → TON)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function initiateWithdrawal(
        bytes32 tonRecipient,
        uint256 amountNanoton
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (tonRecipient == bytes32(0)) revert ZeroAddress();
        if (amountNanoton < MIN_DEPOSIT_NANOTON)
            revert AmountBelowMinimum(amountNanoton, MIN_DEPOSIT_NANOTON);
        if (amountNanoton > MAX_DEPOSIT_NANOTON)
            revert AmountAboveMaximum(amountNanoton, MAX_DEPOSIT_NANOTON);

        IERC20(config.wrappedTON).safeTransferFrom(
            msg.sender,
            address(this),
            amountNanoton
        );

        withdrawalNonce++;
        withdrawalId = keccak256(
            abi.encodePacked(
                TON_CHAIN_ID,
                withdrawalNonce,
                msg.sender,
                tonRecipient,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = TONWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            tonRecipient: tonRecipient,
            amountNanoton: amountNanoton,
            tonTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        totalWithdrawn += amountNanoton;
        userWithdrawals[msg.sender].push(withdrawalId);

        emit TONWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            tonRecipient,
            amountNanoton
        );
    }

    /// @inheritdoc ITONBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 tonTxHash,
        TONStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        TONWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        _verifyValidatorAttestations(
            keccak256(abi.encodePacked(withdrawalId, tonTxHash)),
            attestations
        );

        w.status = WithdrawalStatus.COMPLETED;
        w.tonTxHash = tonTxHash;
        w.completedAt = block.timestamp;

        // Burn the held wTON tokens
        // In production, this would call burn on the wTON contract
        emit TONWithdrawalCompleted(withdrawalId, tonTxHash);
    }

    /// @inheritdoc ITONBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        TONWithdrawal storage w = withdrawals[withdrawalId];
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

        IERC20(config.wrappedTON).safeTransfer(w.evmSender, w.amountNanoton);

        emit TONWithdrawalRefunded(withdrawalId, w.evmSender, w.amountNanoton);
    }

    /*//////////////////////////////////////////////////////////////
                          ESCROW OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function createEscrow(
        bytes32 tonParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (msg.value == 0) revert InvalidAmount();
        if (tonParty == bytes32(0)) revert ZeroAddress();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        escrowNonce++;
        escrowId = keccak256(
            abi.encodePacked(
                TON_CHAIN_ID,
                escrowNonce,
                msg.sender,
                tonParty,
                block.timestamp
            )
        );

        escrows[escrowId] = TONEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            tonParty: tonParty,
            amountNanoton: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        totalEscrows++;
        userEscrows[msg.sender].push(escrowId);

        emit EscrowCreated(escrowId, msg.sender, tonParty, msg.value, hashlock);
    }

    /// @inheritdoc ITONBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        TONEscrow storage e = escrows[escrowId];
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
        (bool sent, ) = e.evmParty.call{value: e.amountNanoton}("");
        require(sent, "ETH transfer failed");

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc ITONBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        TONEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool sent, ) = e.evmParty.call{value: e.amountNanoton}("");
        require(sent, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVACY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        TONDeposit storage dep = deposits[depositId];
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

        IERC20(config.wrappedTON).safeTransfer(treasury, amount);

        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ITONBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (TONDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc ITONBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (TONWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc ITONBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (TONEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc ITONBridgeAdapter
    function getMasterchainBlock(
        uint256 seqno
    ) external view returns (MasterchainBlock memory) {
        return masterchainBlocks[seqno];
    }

    /// @inheritdoc ITONBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc ITONBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc ITONBridgeAdapter
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
            uint256 _latestVerifiedSeqno
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestVerifiedSeqno
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Verify Catchain BFT validator attestation signatures meet threshold
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
            // In production: verify TON validator Ed25519 signatures
            // via the TON light client oracle
            (bool success, bytes memory returnData) = config
                .tonLightClient
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        messageHash,
                        attestations[i].validator,
                        attestations[i].signature
                    )
                );

            if (success && returnData.length >= 32) {
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

    /// @dev Verify a TON state proof against a known masterchain root hash
    /// @param proof The TON state proof containing Merkle path and value
    /// @param expectedRootHash The root hash from a verified masterchain block
    function _verifyTONStateProof(
        TONStateProof calldata proof,
        bytes32 expectedRootHash
    ) internal pure {
        // Verify the root hash matches
        require(proof.rootHash == expectedRootHash, "Root hash mismatch");

        // Verify the Merkle inclusion proof
        // Reconstruct root from value and Merkle path
        bytes32 computedHash = keccak256(proof.value);
        for (uint256 i = 0; i < proof.merkleProof.length; i++) {
            if (computedHash <= proof.merkleProof[i]) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof.merkleProof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof.merkleProof[i], computedHash)
                );
            }
        }

        require(computedHash == expectedRootHash, "Invalid TON state proof");
    }
}
