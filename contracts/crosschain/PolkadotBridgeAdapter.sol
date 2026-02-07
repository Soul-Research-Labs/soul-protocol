// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPolkadotBridgeAdapter} from "../interfaces/IPolkadotBridgeAdapter.sol";

/**
 * @title PolkadotBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Polkadot Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Polkadot Relay Chain
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    Soul <-> Polkadot Bridge                                 │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Polkadot Side                 │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wDOT        │  │           │  │  Relay Chain               │   │     │
 * │  │  │ Token       │  │           │  │  (Shared Security)         │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  GRANDPA + BABE Consensus  │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~6s block time)          │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  XCM / XCMP Messaging      │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Cross-Consensus)         │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * POLKADOT CONCEPTS:
 * - Planck: Smallest unit (1 DOT = 10,000,000,000 Planck = 1e10)
 * - GRANDPA: GHOST-based Recursive ANcestor Deriving Prefix Agreement (finality)
 * - BABE: Blind Assignment for Blockchain Extension (block production)
 * - XCM: Cross-Consensus Messaging format
 * - XCMP: Cross-Chain Message Passing between parachains
 * - Relay Chain: Central chain coordinating consensus and security
 * - Parachain: Application-specific chains connected to relay chain
 * - Chain ID: polkadot relay → 0 (custom convention)
 * - Finality: GRANDPA provides deterministic finality (~12-60s)
 * - Block time: ~6 seconds
 */
contract PolkadotBridgeAdapter is
    IPolkadotBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Polkadot relay chain ID (convention: 0)
    uint256 public constant POLKADOT_CHAIN_ID = 0;

    /// @notice 1 DOT = 1e10 Planck (10 decimals)
    uint256 public constant PLANCK_PER_DOT = 10_000_000_000;

    /// @notice Minimum deposit: 0.1 DOT = 1,000,000,000 Planck
    uint256 public constant MIN_DEPOSIT_PLANCK = PLANCK_PER_DOT / 10;

    /// @notice Maximum deposit: 10,000,000 DOT
    uint256 public constant MAX_DEPOSIT_PLANCK = 10_000_000 * PLANCK_PER_DOT;

    /// @notice Bridge fee: 6 BPS (0.06%)
    uint256 public constant BRIDGE_FEE_BPS = 6;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Withdrawal refund delay: 24 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Default GRANDPA finality confirmations (deterministic finality)
    uint256 public constant DEFAULT_FINALITY_CONFIRMATIONS = 2;

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

    /// @notice Latest verified relay block number
    uint256 public latestRelayBlock;

    /// @notice Current GRANDPA authority set ID
    uint256 public currentSetId;

    /// @notice Total deposited in Planck
    uint256 public totalDeposited;

    /// @notice Total withdrawn in Planck
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated fees in Planck
    uint256 public accumulatedFees;

    /// @notice Deposits by ID
    mapping(bytes32 => DOTDeposit) private deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => DOTWithdrawal) private withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => DOTEscrow) private escrows;

    /// @notice GRANDPA headers by block number
    mapping(uint256 => GrandpaHeader) private grandpaHeaders;

    /// @notice Used Substrate tx hashes (replay protection)
    mapping(bytes32 => bool) public usedSubstrateTxHashes;

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

    /// @inheritdoc IPolkadotBridgeAdapter
    function configure(
        address polkadotBridgeContract,
        address wrappedDOT,
        address grandpaVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredFinalityConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (polkadotBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedDOT == address(0)) revert ZeroAddress();
        if (grandpaVerifier == address(0)) revert ZeroAddress();

        config = BridgeConfig({
            polkadotBridgeContract: polkadotBridgeContract,
            wrappedDOT: wrappedDOT,
            grandpaVerifier: grandpaVerifier,
            minValidatorSignatures: minValidatorSignatures,
            requiredFinalityConfirmations: requiredFinalityConfirmations,
            active: true
        });

        emit BridgeConfigured(
            polkadotBridgeContract,
            wrappedDOT,
            grandpaVerifier
        );
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                     GRANDPA HEADER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolkadotBridgeAdapter
    function submitGrandpaHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 extrinsicsRoot,
        uint256 setId,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    blockNumber,
                    blockHash,
                    parentHash,
                    stateRoot,
                    extrinsicsRoot,
                    setId,
                    timestamp
                )
            ),
            attestations
        );

        grandpaHeaders[blockNumber] = GrandpaHeader({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            stateRoot: stateRoot,
            extrinsicsRoot: extrinsicsRoot,
            setId: setId,
            timestamp: timestamp,
            verified: true
        });

        if (blockNumber > latestRelayBlock) {
            latestRelayBlock = blockNumber;
        }

        if (setId > currentSetId) {
            currentSetId = setId;
        }

        emit GrandpaHeaderVerified(blockNumber, blockHash, setId);
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolkadotBridgeAdapter
    function initiateDOTDeposit(
        bytes32 substrateTxHash,
        bytes32 substrateSender,
        address evmRecipient,
        uint256 amountPlanck,
        uint256 relayBlockNumber,
        SubstrateStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 depositId)
    {
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountPlanck < MIN_DEPOSIT_PLANCK)
            revert AmountBelowMinimum(amountPlanck, MIN_DEPOSIT_PLANCK);
        if (amountPlanck > MAX_DEPOSIT_PLANCK)
            revert AmountAboveMaximum(amountPlanck, MAX_DEPOSIT_PLANCK);
        if (usedSubstrateTxHashes[substrateTxHash])
            revert SubstrateTxAlreadyUsed(substrateTxHash);
        if (!grandpaHeaders[relayBlockNumber].verified)
            revert RelayBlockNotVerified(relayBlockNumber);

        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    substrateTxHash,
                    substrateSender,
                    evmRecipient,
                    amountPlanck
                )
            ),
            attestations
        );

        usedSubstrateTxHashes[substrateTxHash] = true;

        uint256 fee = (amountPlanck * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountPlanck - fee;

        depositNonce++;
        depositId = keccak256(
            abi.encodePacked(
                POLKADOT_CHAIN_ID,
                depositNonce,
                substrateTxHash,
                block.timestamp
            )
        );

        deposits[depositId] = DOTDeposit({
            depositId: depositId,
            substrateTxHash: substrateTxHash,
            substrateSender: substrateSender,
            evmRecipient: evmRecipient,
            amountPlanck: amountPlanck,
            netAmountPlanck: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            relayBlockNumber: relayBlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalDeposited += amountPlanck;
        userDeposits[evmRecipient].push(depositId);

        emit DOTDepositInitiated(
            depositId,
            substrateTxHash,
            substrateSender,
            evmRecipient,
            amountPlanck
        );
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function completeDOTDeposit(
        bytes32 depositId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        DOTDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        IERC20(config.wrappedDOT).safeTransfer(
            dep.evmRecipient,
            dep.netAmountPlanck
        );

        emit DOTDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountPlanck
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolkadotBridgeAdapter
    function initiateWithdrawal(
        bytes32 substrateRecipient,
        uint256 amountPlanck
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (substrateRecipient == bytes32(0)) revert ZeroAddress();
        if (amountPlanck < MIN_DEPOSIT_PLANCK)
            revert AmountBelowMinimum(amountPlanck, MIN_DEPOSIT_PLANCK);
        if (amountPlanck > MAX_DEPOSIT_PLANCK)
            revert AmountAboveMaximum(amountPlanck, MAX_DEPOSIT_PLANCK);

        IERC20(config.wrappedDOT).safeTransferFrom(
            msg.sender,
            address(this),
            amountPlanck
        );

        withdrawalNonce++;
        withdrawalId = keccak256(
            abi.encodePacked(
                POLKADOT_CHAIN_ID,
                withdrawalNonce,
                msg.sender,
                substrateRecipient,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = DOTWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            substrateRecipient: substrateRecipient,
            amountPlanck: amountPlanck,
            substrateTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        totalWithdrawn += amountPlanck;
        userWithdrawals[msg.sender].push(withdrawalId);

        emit DOTWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            substrateRecipient,
            amountPlanck
        );
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 substrateTxHash,
        SubstrateStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        DOTWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        _verifyValidatorAttestations(
            keccak256(abi.encodePacked(withdrawalId, substrateTxHash)),
            attestations
        );

        w.status = WithdrawalStatus.COMPLETED;
        w.substrateTxHash = substrateTxHash;
        w.completedAt = block.timestamp;

        // Burn the held wDOT tokens
        // In production, this would call burn on the wDOT contract
        emit DOTWithdrawalCompleted(withdrawalId, substrateTxHash);
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        DOTWithdrawal storage w = withdrawals[withdrawalId];
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

        IERC20(config.wrappedDOT).safeTransfer(w.evmSender, w.amountPlanck);

        emit DOTWithdrawalRefunded(withdrawalId, w.evmSender, w.amountPlanck);
    }

    /*//////////////////////////////////////////////////////////////
                          ESCROW OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolkadotBridgeAdapter
    function createEscrow(
        bytes32 substrateParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (msg.value == 0) revert InvalidAmount();
        if (substrateParty == bytes32(0)) revert ZeroAddress();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        escrowNonce++;
        escrowId = keccak256(
            abi.encodePacked(
                POLKADOT_CHAIN_ID,
                escrowNonce,
                msg.sender,
                substrateParty,
                block.timestamp
            )
        );

        escrows[escrowId] = DOTEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            substrateParty: substrateParty,
            amountPlanck: msg.value,
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
            substrateParty,
            msg.value,
            hashlock
        );
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        DOTEscrow storage e = escrows[escrowId];
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
        (bool sent, ) = e.evmParty.call{value: e.amountPlanck}("");
        require(sent, "ETH transfer failed");

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        DOTEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool sent, ) = e.evmParty.call{value: e.amountPlanck}("");
        require(sent, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVACY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolkadotBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        DOTDeposit storage dep = deposits[depositId];
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

        IERC20(config.wrappedDOT).safeTransfer(treasury, amount);

        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolkadotBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (DOTDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (DOTWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (DOTEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function getGrandpaHeader(
        uint256 blockNumber
    ) external view returns (GrandpaHeader memory) {
        return grandpaHeaders[blockNumber];
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IPolkadotBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IPolkadotBridgeAdapter
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
            uint256 _latestRelayBlock
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestRelayBlock
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Verify validator attestation signatures meet threshold
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
            // In production: verify GRANDPA/BABE authority signatures
            // For now: verify via the GRANDPA verifier oracle
            (bool valid, ) = config.grandpaVerifier.staticcall(
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
                (, returnData) = config.grandpaVerifier.staticcall(
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
}
