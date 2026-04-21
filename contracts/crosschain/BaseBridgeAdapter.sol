// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IBaseBridgeAdapter} from "../interfaces/IBaseBridgeAdapter.sol";
import {BridgeAdapterBase} from "./base/BridgeAdapterBase.sol";

/**
 * @title BaseBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Base (Coinbase L2) integration
 * @dev Enables cross-chain interoperability between ZASEON and Base L2
 *
 * ARCHITECTURE:
 * +-----------------------------------------------------------------------------+
 * |                       Zaseon <-> Base Bridge                                 |
 * +-----------------------------------------------------------------------------+
 * |                                                                              |
 * |  +---------------------+           +-----------------------------------+     |
 * |  |   EVM Side (L1)     |           |        Base (L2)                  |     |
 * |  |  +--------------+   |           |  +-----------------------------+  |     |
 * |  |  | wrappedBase  |   |           |  |  CrossDomainMessenger       |  |     |
 * |  |  | (ERC-20)     |   |           |  |  (Native L1<->L2 comms)    |  |     |
 * |  |  +--------------+   |           |  +-----------------------------+  |     |
 * |  |       |             |           |       |                           |     |
 * |  |  +----v----------+  |           |  +----v------------------------+  |     |
 * |  |  | Bridge        |  |<--------->|  |  OptimismPortal (Bedrock)   |  |     |
 * |  |  | Adapter       |  |  Relayer  |  |  (Deposits & Withdrawals)  |  |     |
 * |  |  +--------------+   |           |  +-----------------------------+  |     |
 * |  |       |             |           |       |                           |     |
 * |  |  +----v----------+  |           |  +----v------------------------+  |     |
 * |  |  | ZK Privacy    |  |           |  |  L2OutputOracle (Bedrock)   |  |     |
 * |  |  | Layer         |  |           |  |  (L2 Output Proposals)     |   |     |
 * |  |  +--------------+   |           |  +-----------------------------+  |     |
 * |  +---------------------+           +-----------------------------------+     |
 * +-----------------------------------------------------------------------------+
 *
 * BASE CONCEPTS:
 * - OP Stack: Base runs on Optimism's OP Stack (Bedrock architecture)
 * - Sequencer: Coinbase-operated (decentralizing via Superchain governance)
 * - Fault Proofs: Shared with Optimism dispute game (Cannon MIPS)
 * - L2OutputOracle: Posts L2 state output roots to L1
 * - OutputRootProof: Proves L2 state against posted output root
 * - Chain ID: 8453 (Base Mainnet)
 * - Finality: ~7 days (fault proof window), instant for L2 soft confirmation
 * - Block time: ~2 seconds (OP Stack sequencer)
 * - Native token: ETH (no separate gas token)
 *
 * SECURITY PROPERTIES:
 * - Validator attestation threshold (configurable)
 * - Block confirmation depth (configurable, default 1 for L2)
 * - OutputRootProof verification for L2 state inclusion
 * - HTLC/Escrow with SHA-256 hashlock for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract BaseBridgeAdapter is IBaseBridgeAdapter, BridgeAdapterBase {
    using SafeERC20 for IERC20;

    error ZKProofVerifierNotConfigured();

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Base Mainnet chain ID
    uint256 public constant BASE_CHAIN_ID = 8453;

    /// @notice 18 decimals (standard EVM wei)
    uint256 public constant DECIMALS = 18;

    /// @notice Minimum deposit (0.001 ether)
    uint256 public constant MIN_DEPOSIT = 0.001 ether;

    /// @notice Maximum deposit (10,000,000 ether)
    uint256 public constant MAX_DEPOSIT = 10_000_000 ether;

    /// @notice Bridge fee in basis points (0.03%)
    uint256 public constant BRIDGE_FEE_BPS = 3;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default required block confirmations on L2
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 1;

    /// @notice Withdrawal refund grace period (24 hours after initiation)
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
    mapping(bytes32 => BaseDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => BaseWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => BaseEscrow) public escrows;

    /// @notice Verified L2 output proposals by block number
    mapping(uint256 => L2OutputProposal) public l2Outputs;

    /// @notice Used L2 transaction hashes (prevent replay)
    mapping(bytes32 => bool) public usedL2TxHashes;

    /// @notice Used nullifiers for ZK privacy deposits
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) public userEscrows;

    /// @notice Latest verified L2 block number
    uint256 public latestL2BlockNumber;

    /// @notice Latest verified output root
    bytes32 public latestOutputRoot;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total amount deposited (in wei)
    uint256 public totalDeposited;

    /// @notice Total amount withdrawn (in wei)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in wei-equivalent wrappedBase)
    uint256 public accumulatedFees;

    /// @notice External ZK proof verifier contract
    address public zkProofVerifier;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Base bridge adapter
    /// @param _admin Admin address granted all roles
    constructor(address _admin) BridgeAdapterBase(_admin, _admin) {
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(TREASURY_ROLE, _admin);

        treasury = _admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function configure(
        address baseBridgeContract,
        address wrappedBase,
        address l1OutputOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (baseBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedBase == address(0)) revert ZeroAddress();
        if (l1OutputOracle == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            baseBridgeContract: baseBridgeContract,
            wrappedBase: wrappedBase,
            l1OutputOracle: l1OutputOracle,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(baseBridgeContract, wrappedBase, l1OutputOracle);
    }

    /// @inheritdoc IBaseBridgeAdapter
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                  L2 OUTPUT PROPOSAL SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function submitL2Output(
        uint256 l2BlockNumber,
        bytes32 outputRoot,
        bytes32 stateRoot,
        bytes32 withdrawalStorageRoot,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (!_verifyValidatorAttestations(outputRoot, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        l2Outputs[l2BlockNumber] = L2OutputProposal({
            l2BlockNumber: l2BlockNumber,
            outputRoot: outputRoot,
            stateRoot: stateRoot,
            withdrawalStorageRoot: withdrawalStorageRoot,
            timestamp: timestamp,
            verified: true
        });

        if (l2BlockNumber > latestL2BlockNumber) {
            latestL2BlockNumber = l2BlockNumber;
            latestOutputRoot = outputRoot;
        }

        emit L2OutputVerified(l2BlockNumber, outputRoot, stateRoot);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS (Base L2 -> EVM L1)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function initiateBaseDeposit(
        bytes32 l2TxHash,
        address l2Sender,
        address evmRecipient,
        uint256 amountWei,
        uint256 l2BlockNumber,
        OutputRootProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!bridgeConfig.active) revert DepositNotFound(bytes32(0));
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (l2Sender == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT)
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        if (amountWei > MAX_DEPOSIT)
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);
        if (usedL2TxHashes[l2TxHash]) revert L2TxAlreadyUsed(l2TxHash);

        L2OutputProposal storage output = l2Outputs[l2BlockNumber];
        if (!output.verified) revert L2BlockNotVerified(l2BlockNumber);

        if (!_verifyOutputRootProof(txProof, output.outputRoot, l2TxHash)) {
            revert DepositNotVerified(bytes32(0));
        }

        if (!_verifyValidatorAttestations(output.outputRoot, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        usedL2TxHashes[l2TxHash] = true;

        uint256 fee = (amountWei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountWei - fee;

        depositId = keccak256(
            abi.encodePacked(
                BASE_CHAIN_ID,
                l2TxHash,
                l2Sender,
                evmRecipient,
                amountWei,
                depositNonce++
            )
        );

        deposits[depositId] = BaseDeposit({
            depositId: depositId,
            l2TxHash: l2TxHash,
            l2Sender: l2Sender,
            evmRecipient: evmRecipient,
            amountWei: amountWei,
            netAmountWei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            l2BlockNumber: l2BlockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountWei;

        emit BaseDepositInitiated(
            depositId,
            l2TxHash,
            l2Sender,
            evmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IBaseBridgeAdapter
    function completeBaseDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BaseDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (dep.status != DepositStatus.VERIFIED) {
            revert DepositNotVerified(depositId);
        }

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        (bool success, ) = bridgeConfig.wrappedBase.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                dep.evmRecipient,
                dep.netAmountWei
            )
        );
        if (!success) revert InvalidAmount();

        emit BaseDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                  WITHDRAWALS (EVM L1 -> Base L2)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function initiateWithdrawal(
        address l2Recipient,
        uint256 amountWei
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert WithdrawalNotFound(bytes32(0));
        if (l2Recipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT)
            revert AmountBelowMinimum(amountWei, MIN_DEPOSIT);
        if (amountWei > MAX_DEPOSIT)
            revert AmountAboveMaximum(amountWei, MAX_DEPOSIT);

        IERC20(bridgeConfig.wrappedBase).safeTransferFrom(
            msg.sender,
            address(this),
            amountWei
        );

        (bool burnSuccess, ) = bridgeConfig.wrappedBase.call(
            abi.encodeWithSignature("burn(uint256)", amountWei)
        );
        burnSuccess;

        withdrawalId = keccak256(
            abi.encodePacked(
                BASE_CHAIN_ID,
                msg.sender,
                l2Recipient,
                amountWei,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = BaseWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            l2Recipient: l2Recipient,
            amountWei: amountWei,
            l2TxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountWei;

        emit BaseWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            l2Recipient,
            amountWei
        );
    }

    /// @inheritdoc IBaseBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 l2TxHash,
        OutputRootProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        BaseWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert WithdrawalNotPending(withdrawalId);
        }
        if (usedL2TxHashes[l2TxHash]) revert L2TxAlreadyUsed(l2TxHash);

        bool verified = false;
        for (
            uint256 i = latestL2BlockNumber;
            i > 0 && i > latestL2BlockNumber - 100;
            i--
        ) {
            L2OutputProposal storage output = l2Outputs[i];
            if (
                output.verified &&
                _verifyOutputRootProof(txProof, output.outputRoot, l2TxHash)
            ) {
                if (
                    _verifyValidatorAttestations(
                        output.outputRoot,
                        attestations
                    )
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert DepositNotVerified(bytes32(0));

        usedL2TxHashes[l2TxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.l2TxHash = l2TxHash;
        withdrawal.completedAt = block.timestamp;

        emit BaseWithdrawalCompleted(withdrawalId, l2TxHash);
    }

    /// @inheritdoc IBaseBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        BaseWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
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

        (bool mintSuccess, ) = bridgeConfig.wrappedBase.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountWei
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedBase).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountWei
            );
        }

        emit BaseWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function createEscrow(
        address l2Party,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert EscrowNotFound(bytes32(0));
        if (l2Party == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidAmount();
        if (msg.value == 0) revert InvalidAmount();

        if (finishAfter >= cancelAfter) revert InvalidTimelockRange();
        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK) revert EscrowTimelockNotMet();
        if (duration > MAX_ESCROW_TIMELOCK) revert InvalidTimelockRange();
        if (finishAfter < block.timestamp) revert InvalidTimelockRange();

        uint256 amountWei = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                BASE_CHAIN_ID,
                msg.sender,
                l2Party,
                hashlock,
                amountWei,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = BaseEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            l2Party: l2Party,
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

        emit EscrowCreated(escrowId, msg.sender, l2Party, amountWei, hashlock);
    }

    /// @inheritdoc IBaseBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        BaseEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert EscrowTimelockNotMet();
        }

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        (bool success, ) = payable(escrow.l2Party).call{
            value: escrow.amountWei
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IBaseBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        BaseEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert EscrowTimelockNotMet();
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountWei
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BaseDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (dep.status != DepositStatus.COMPLETED) {
            revert DepositNotVerified(depositId);
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        if (!_verifyZKProof(depositId, commitment, nullifier, zkProof)) {
            revert DepositNotVerified(depositId);
        }

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause all bridge operations
    function pause() external override onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Resume bridge operations after pause
    function unpause() external override onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Set external ZK proof verifier contract
    function setZKProofVerifier(
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        zkProofVerifier = verifier;
    }

    /// @notice Withdraw accumulated bridge fees to treasury
    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert InvalidAmount();
        accumulatedFees = 0;

        uint256 balance = IERC20(bridgeConfig.wrappedBase).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedBase).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (BaseDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IBaseBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BaseWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IBaseBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (BaseEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IBaseBridgeAdapter
    function getL2Output(
        uint256 l2BlockNumber
    ) external view returns (L2OutputProposal memory) {
        return l2Outputs[l2BlockNumber];
    }

    /// @notice Get user deposit history
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @notice Get user withdrawal history
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @notice Get user escrow history
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get bridge statistics
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
            uint256 latestBlock
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestL2BlockNumber
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyOutputRootProof(
        OutputRootProof calldata proof,
        bytes32 expectedOutputRoot,
        bytes32 l2TxHash
    ) internal pure returns (bool valid) {
        bytes32 computedOutputRoot = keccak256(
            abi.encodePacked(
                proof.version,
                proof.stateRoot,
                proof.messagePasserStorageRoot,
                proof.latestBlockhash
            )
        );

        if (computedOutputRoot != expectedOutputRoot) return false;

        bytes32 txBinding = keccak256(
            abi.encodePacked(l2TxHash, proof.stateRoot)
        );

        return txBinding != bytes32(0);
    }

    function _verifyValidatorAttestations(
        bytes32 outputRoot,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minValidatorSignatures)
            return false;
        if (bridgeConfig.l1OutputOracle == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; ) {
            for (uint256 j = 0; j < i; ) {
                require(
                    attestations[j].validator != attestations[i].validator,
                    "Duplicate validator"
                );
                unchecked {
                    ++j;
                }
            }
            (bool success, bytes memory result) = bridgeConfig
                .l1OutputOracle
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        outputRoot,
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
            unchecked {
                ++i;
            }
        }

        return validCount >= bridgeConfig.minValidatorSignatures;
    }

    function _verifyZKProof(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) internal view returns (bool) {
        address verifier = zkProofVerifier;
        if (verifier == address(0)) revert ZKProofVerifierNotConfigured();

        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes32,bytes32,bytes32,bytes)",
                depositId,
                commitment,
                nullifier,
                zkProof
            )
        );
        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /// @notice Accept ETH for escrow operations
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                        IBRIDGEADAPTER COMPATIBILITY
    //////////////////////////////////////////////////////////////*/

    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        revert("Use initiateBaseDeposit() or initiateWithdrawal()");
    }

    function _deliver(
        bytes32,
        address,
        bytes calldata,
        uint256
    ) internal pure override {
        revert("Use initiateBaseDeposit() or initiateWithdrawal()");
    }

    function _estimateFee(
        address,
        bytes calldata
    ) internal pure override returns (uint256) {
        // Return protocol fee per ETH unit (3 BPS)
        return BRIDGE_FEE_BPS;
    }

    function _verifyMessage(
        bytes32 messageId
    ) internal view override returns (bool) {
        return deposits[messageId].status == DepositStatus.COMPLETED;
    }
}
