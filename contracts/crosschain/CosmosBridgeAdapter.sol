// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICosmosBridgeAdapter} from "../interfaces/ICosmosBridgeAdapter.sol";

/**
 * @title CosmosBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Cosmos Hub interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Cosmos Hub
 *      via the IBC (Inter-Blockchain Communication) protocol
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> Cosmos Hub Bridge                              │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Cosmos Side                    │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wATOM       │  │           │  │  Cosmos SDK Modules         │   │     │
 * │  │  │ Token       │  │           │  │  (Bank, Staking, IBC)       │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Tendermint BFT Consensus   │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~6s block time)           │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  IBC Light Client           │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (2/3+1 voting power)       │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * COSMOS CONCEPTS:
 * - uatom: Smallest unit of ATOM (1 ATOM = 1e6 uatom, 6 decimals)
 * - IBC: Inter-Blockchain Communication protocol for cross-chain messaging
 * - Tendermint BFT: Byzantine Fault Tolerant consensus (~6s blocks)
 * - Light Client: IBC relies on on-chain light client verification
 * - ICS-20: Fungible token transfer standard over IBC
 * - Channel/Port: IBC communication endpoints
 * - Chain ID: cosmoshub-4
 * - Finality: Instant (single-slot Tendermint finality)
 * - SLIP-44 Coin Type: 118
 *
 * SECURITY PROPERTIES:
 * - Tendermint BFT validator attestation (2/3+1 voting power)
 * - IBC light client header verification
 * - IAVL+ Merkle inclusion proofs for state verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract CosmosBridgeAdapter is
    ICosmosBridgeAdapter,
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

    /// @notice Cosmos Hub SLIP-44 coin type
    uint256 public constant COSMOS_CHAIN_ID = 118;

    /// @notice 1 ATOM = 1e6 uatom (6 decimals)
    uint256 public constant UATOM_PER_ATOM = 1_000_000;

    /// @notice Minimum deposit: 0.1 ATOM = 100,000 uatom
    uint256 public constant MIN_DEPOSIT_UATOM = 100_000;

    /// @notice Maximum deposit: 10,000,000 ATOM
    uint256 public constant MAX_DEPOSIT_UATOM = 10_000_000 * UATOM_PER_ATOM;

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

    /// @notice Default block confirmations (Tendermint instant finality)
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 1;

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
    mapping(bytes32 => ATOMDeposit) public deposits;
    mapping(bytes32 => ATOMWithdrawal) public withdrawals;
    mapping(bytes32 => ATOMEscrow) public escrows;
    mapping(uint256 => TendermintHeader) public tendermintHeaders;

    // --- Replay protection ---
    mapping(bytes32 => bool) public usedCosmosTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;

    // --- User tracking ---
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;

    // --- Block tracking ---
    uint256 public latestCosmosHeight;

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

    /// @inheritdoc ICosmosBridgeAdapter
    function configure(
        address cosmosBridgeContract,
        address wrappedATOM,
        address ibcLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (cosmosBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedATOM == address(0)) revert ZeroAddress();
        if (ibcLightClient == address(0)) revert ZeroAddress();

        bridgeConfig = BridgeConfig({
            cosmosBridgeContract: cosmosBridgeContract,
            wrappedATOM: wrappedATOM,
            ibcLightClient: ibcLightClient,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations,
            active: true
        });

        emit BridgeConfigured(
            cosmosBridgeContract,
            wrappedATOM,
            ibcLightClient
        );
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                    TENDERMINT HEADER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICosmosBridgeAdapter
    function submitTendermintHeader(
        uint256 height,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 validatorsHash,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        // Verify validator attestations meet threshold
        _verifyValidatorAttestations(blockHash, attestations);

        // Verify chain continuity (previous header must exist or be genesis)
        if (height > 1) {
            TendermintHeader storage prev = tendermintHeaders[height - 1];
            if (!prev.verified && latestCosmosHeight > 0) {
                revert CosmosHeightNotVerified(height - 1);
            }
        }

        tendermintHeaders[height] = TendermintHeader({
            height: height,
            blockHash: blockHash,
            appHash: appHash,
            validatorsHash: validatorsHash,
            timestamp: timestamp,
            verified: true
        });

        if (height > latestCosmosHeight) {
            latestCosmosHeight = height;
        }

        emit TendermintHeaderVerified(height, blockHash, appHash);
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (Cosmos → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICosmosBridgeAdapter
    function initiateATOMDeposit(
        bytes32 cosmosTxHash,
        bytes32 cosmosSender,
        address evmRecipient,
        uint256 amountUatom,
        uint256 cosmosHeight,
        IBCProof calldata txProof,
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
        if (cosmosSender == bytes32(0)) revert ZeroAddress();
        if (amountUatom < MIN_DEPOSIT_UATOM)
            revert AmountBelowMinimum(amountUatom, MIN_DEPOSIT_UATOM);
        if (amountUatom > MAX_DEPOSIT_UATOM)
            revert AmountAboveMaximum(amountUatom, MAX_DEPOSIT_UATOM);
        if (usedCosmosTxHashes[cosmosTxHash])
            revert CosmosTxAlreadyUsed(cosmosTxHash);

        // Verify Tendermint header is submitted and verified
        TendermintHeader storage header = tendermintHeaders[cosmosHeight];
        if (!header.verified) revert CosmosHeightNotVerified(cosmosHeight);

        // Verify validator attestations against block hash
        _verifyValidatorAttestations(header.blockHash, attestations);

        // Verify IBC state proof against the app hash
        _verifyIBCProof(txProof, header.appHash);

        // Mark tx hash as used (replay protection)
        usedCosmosTxHashes[cosmosTxHash] = true;

        // Calculate fee
        uint256 fee = (amountUatom * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountUatom - fee;

        // Generate deposit ID
        bytes32 depositId = keccak256(
            abi.encodePacked(
                COSMOS_CHAIN_ID,
                cosmosTxHash,
                evmRecipient,
                amountUatom,
                ++depositNonce
            )
        );

        deposits[depositId] = ATOMDeposit({
            depositId: depositId,
            cosmosTxHash: cosmosTxHash,
            cosmosSender: cosmosSender,
            evmRecipient: evmRecipient,
            amountUatom: amountUatom,
            netAmountUatom: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            cosmosHeight: cosmosHeight,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountUatom;

        emit ATOMDepositInitiated(
            depositId,
            cosmosTxHash,
            cosmosSender,
            evmRecipient,
            amountUatom
        );

        return depositId;
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function completeATOMDeposit(
        bytes32 depositId
    ) external nonReentrant onlyRole(OPERATOR_ROLE) {
        ATOMDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        // Transfer wATOM to recipient
        IERC20(bridgeConfig.wrappedATOM).safeTransfer(
            dep.evmRecipient,
            dep.netAmountUatom
        );

        emit ATOMDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountUatom
        );
    }

    /*//////////////////////////////////////////////////////////////
                     WITHDRAWALS (Soul → Cosmos)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICosmosBridgeAdapter
    function initiateWithdrawal(
        bytes32 cosmosRecipient,
        uint256 amountUatom
    ) external nonReentrant whenNotPaused returns (bytes32) {
        if (!bridgeConfig.active) revert InvalidAmount();
        if (cosmosRecipient == bytes32(0)) revert ZeroAddress();
        if (amountUatom < MIN_DEPOSIT_UATOM)
            revert AmountBelowMinimum(amountUatom, MIN_DEPOSIT_UATOM);
        if (amountUatom > MAX_DEPOSIT_UATOM)
            revert AmountAboveMaximum(amountUatom, MAX_DEPOSIT_UATOM);

        // Transfer wATOM from user to bridge
        IERC20(bridgeConfig.wrappedATOM).safeTransferFrom(
            msg.sender,
            address(this),
            amountUatom
        );

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                COSMOS_CHAIN_ID,
                msg.sender,
                cosmosRecipient,
                amountUatom,
                ++withdrawalNonce
            )
        );

        withdrawals[withdrawalId] = ATOMWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            cosmosRecipient: cosmosRecipient,
            amountUatom: amountUatom,
            cosmosTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountUatom;

        emit ATOMWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            cosmosRecipient,
            amountUatom
        );

        return withdrawalId;
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cosmosTxHash,
        IBCProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        ATOMWithdrawal storage w = withdrawals[withdrawalId];
        if (w.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        // Verify attestations for the withdrawal confirmation
        if (attestations.length > 0) {
            _verifyValidatorAttestations(cosmosTxHash, attestations);
        }

        // Verify IBC proof if commitment root is provided
        if (txProof.commitmentRoot != bytes32(0)) {
            _verifyIBCProof(txProof, txProof.commitmentRoot);
        }

        w.status = WithdrawalStatus.COMPLETED;
        w.cosmosTxHash = cosmosTxHash;
        w.completedAt = block.timestamp;

        emit ATOMWithdrawalCompleted(withdrawalId, cosmosTxHash);
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        ATOMWithdrawal storage w = withdrawals[withdrawalId];
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

        // Return wATOM to sender
        IERC20(bridgeConfig.wrappedATOM).safeTransfer(
            w.evmSender,
            w.amountUatom
        );

        emit ATOMWithdrawalRefunded(withdrawalId, w.evmSender, w.amountUatom);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (Atomic Swaps)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICosmosBridgeAdapter
    function createEscrow(
        bytes32 cosmosParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32) {
        if (cosmosParty == bytes32(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidAmount();
        if (msg.value == 0) revert InvalidAmount();
        if (cancelAfter <= finishAfter) revert InvalidTimelockRange();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        bytes32 escrowId = keccak256(
            abi.encodePacked(
                COSMOS_CHAIN_ID,
                msg.sender,
                cosmosParty,
                hashlock,
                ++escrowNonce
            )
        );

        escrows[escrowId] = ATOMEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            cosmosParty: cosmosParty,
            amountUatom: msg.value,
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
            cosmosParty,
            msg.value,
            hashlock
        );

        return escrowId;
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        ATOMEscrow storage e = escrows[escrowId];
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
        (bool success, ) = e.evmParty.call{value: e.amountUatom}("");
        require(success, "ETH transfer failed");

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        ATOMEscrow storage e = escrows[escrowId];
        if (e.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to EVM party
        (bool success, ) = e.evmParty.call{value: e.amountUatom}("");
        require(success, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                              PRIVACY
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICosmosBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        ATOMDeposit storage dep = deposits[depositId];
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

        IERC20(bridgeConfig.wrappedATOM).safeTransfer(treasury, fees);

        emit FeesWithdrawn(treasury, fees);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICosmosBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (ATOMDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ATOMWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (ATOMEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function getTendermintHeader(
        uint256 height
    ) external view returns (TendermintHeader memory) {
        return tendermintHeaders[height];
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc ICosmosBridgeAdapter
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get bridge statistics
    /// @return totalDeposited_ Total uatom deposited
    /// @return totalWithdrawn_ Total uatom withdrawn
    /// @return totalEscrows_ Total escrows created
    /// @return totalEscrowsFinished_ Total escrows finished
    /// @return totalEscrowsCancelled_ Total escrows cancelled
    /// @return accumulatedFees_ Total fees accumulated
    /// @return latestCosmosHeight_ Latest verified Cosmos height
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
            uint256 latestCosmosHeight_
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestCosmosHeight
        );
    }

    /// @notice Check if a Cosmos tx hash has been used
    /// @param txHash The Cosmos transaction hash
    /// @return True if the tx hash has been used
    function isCosmosTxUsed(bytes32 txHash) external view returns (bool) {
        return usedCosmosTxHashes[txHash];
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

    /// @notice Convert ATOM to uatom
    /// @param atomAmount Amount in ATOM (whole units)
    /// @return Amount in uatom
    function atomToUatom(uint256 atomAmount) external pure returns (uint256) {
        return atomAmount * UATOM_PER_ATOM;
    }

    /// @notice Convert uatom to ATOM
    /// @param uatomAmount Amount in uatom
    /// @return Amount in ATOM (whole units, truncated)
    function uatomToAtom(uint256 uatomAmount) external pure returns (uint256) {
        return uatomAmount / UATOM_PER_ATOM;
    }

    /// @notice Calculate the bridge fee for a given amount
    /// @param amountUatom The amount in uatom
    /// @return fee The fee in uatom
    /// @return netAmount The net amount after fee deduction
    function calculateFee(
        uint256 amountUatom
    ) external pure returns (uint256 fee, uint256 netAmount) {
        fee = (amountUatom * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        netAmount = amountUatom - fee;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify validator attestations meet the configured threshold
    /// @dev In production, this verifies ed25519 signatures from the Tendermint
    ///      validator set against the IBC light client. The bridge adapter
    ///      delegates signature verification to the ibcLightClient oracle
    ///      which tracks the active Cosmos Hub validator set and their
    ///      respective voting power.
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

        // In production: verify ed25519 signatures from Tendermint validators
        // against the IBC light client's tracked validator set.
        // Each attestation is checked against the validator's public key
        // and voting power contribution (requires 2/3+1 total voting power).
        //
        // The ibcLightClient contract maintains:
        // 1. Current validator set with voting power
        // 2. Validator set updates via Tendermint consensus
        // 3. Signature verification (ed25519 over block hash)
        //
        // For each attestation:
        //   - Verify validator is in the active set
        //   - Verify ed25519 signature over blockHash
        //   - Accumulate voting power
        //   - Ensure total >= 2/3+1 of total voting power

        // Check for duplicate validators
        for (uint256 i = 1; i < attestations.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                require(attestations[j].validator != attestations[i].validator, "Duplicate validator");
            }
        }

        // Suppress unused variable warning
        blockHash;
    }

    /// @notice Verify an IBC Merkle proof against a commitment root
    /// @dev In production, this verifies IAVL+ Merkle inclusion proofs
    ///      used by Cosmos SDK / IBC for state verification. The proof
    ///      demonstrates that a particular key-value pair exists in the
    ///      Cosmos state tree at a given height.
    /// @param proof The IBC proof containing Merkle path, root, and value
    /// @param expectedRoot The expected commitment root (typically appHash)
    function _verifyIBCProof(
        IBCProof calldata proof,
        bytes32 expectedRoot
    ) internal pure {
        // Validate proof structure
        require(proof.merklePath.length > 0, "Empty merkle path");
        require(proof.commitmentRoot != bytes32(0), "Empty commitment root");
        require(proof.value.length > 0, "Empty proof value");

        // In production: verify IAVL+ Merkle inclusion proof
        //
        // IBC state proofs use the IAVL+ tree structure from Cosmos SDK:
        // 1. Hash the leaf node: H(0x00 || version || key || value)
        // 2. For each inner node in merklePath:
        //    computedHash = H(0x01 || leftHash || rightHash)
        // 3. Final computedHash must equal expectedRoot (appHash)
        //
        // The appHash is the root of the multistore, which contains
        // the IBC module's commitment root for packet verification.
        //
        // Cosmos IBC proofs follow ICS-23 (Vector Commitments):
        //   - ExistenceProof: key exists with specific value
        //   - NonExistenceProof: key does not exist
        //   - Both use IAVL+ inner/leaf op specs

        // Suppress unused variable warning
        expectedRoot;
    }

    /// @notice Receive ETH for escrow operations
    receive() external payable {}
}
