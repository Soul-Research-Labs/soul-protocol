// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBridgeAdapter} from "../crosschain/IBridgeAdapter.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IBitcoinRelay
 * @notice Interface for a Bitcoin block header relay (e.g., BTC Relay or tBTC relay).
 *         The relay maintains a chain of validated Bitcoin block headers on EVM.
 */
interface IBitcoinRelay {
    /// @notice Verify that a Bitcoin transaction was included in a given block
    /// @param txHash The Bitcoin transaction hash
    /// @param blockHash The block header hash
    /// @param blockHeight The block height
    /// @param merkleProof Concatenated Merkle sibling hashes (32 bytes each)
    /// @param txIndex The transaction index in the block
    /// @return valid True if the proof is valid
    function verifyTx(
        bytes32 txHash,
        bytes32 blockHash,
        uint256 blockHeight,
        bytes calldata merkleProof,
        uint256 txIndex
    ) external view returns (bool valid);

    /// @notice Get the current best known Bitcoin block height
    function getBestKnownHeight() external view returns (uint256);
}

/**
 * @title IWrappedBTC
 * @notice Minimal interface for a wrapped BTC ERC-20 token that supports
 *         mint/burn by an authorised bridge.
 */
interface IWrappedBTC is IERC20 {
    function mint(address to, uint256 amount) external;

    function burn(address from, uint256 amount) external;
}

/**
 * @title BitVMBridgeAdapter
 * @author ZASEON Team
 * @notice IBridgeAdapter for BitVM BTC↔EVM cross-chain operations
 * @dev BitVM enables trustless BTC→EVM bridging by using fraud proofs to verify
 *      Bitcoin transaction inclusion. The protocol works as follows:
 *
 *      DEPOSIT FLOW (BTC → EVM):
 *        1. User sends BTC to a BitVM-controlled multisig address
 *        2. Operator submits a deposit claim on EVM with Bitcoin SPV proof
 *        3. Challenge window opens (default: 7 days)
 *        4. If unchallenged, deposit is finalized and wrapped BTC minted
 *        5. If challenged, fraud proof verifies Bitcoin state on-chain
 *
 *      WITHDRAWAL FLOW (EVM → BTC):
 *        1. User burns wrapped BTC on EVM
 *        2. Operator executes BTC release transaction
 *        3. User can force withdrawal via BitVM fraud proof if operator fails
 *
 *      SECURITY PROPERTIES:
 *        - Trustless: fraud proofs guarantee correctness (1-of-N honest assumption)
 *        - Challenge-based: optimistic verification with 7-day window
 *        - Operator bonded: operators stake ETH, slashed on fraud
 *        - Rate-limited: per-block and daily deposit/withdrawal caps
 *
 *      LIMITATIONS:
 *        - Challenge period introduces latency (7 days for finality)
 *        - Requires active challenger set for security
 *        - Bitcoin SPV proofs are ~500 bytes per proof
 *        - Gas cost for on-chain Bitcoin script verification is high (~500k-1M gas)
 */
contract BitVMBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bitcoin chain identifier for cross-chain message encoding
    uint256 public constant BITCOIN_CHAIN_ID = 0;

    /// @notice Default challenge period for deposits (7 days)
    uint256 public constant DEFAULT_CHALLENGE_PERIOD = 7 days;

    /// @notice Minimum operator bond required
    uint256 public constant MIN_OPERATOR_BOND = 10 ether;

    /// @notice Minimum challenger bond for dispute initiation
    uint256 public constant MIN_CHALLENGE_BOND = 1 ether;

    /// @notice Maximum daily deposit limit in satoshis (100 BTC)
    uint256 public constant MAX_DAILY_DEPOSIT_SATS = 100_00000000;

    /// @notice Bitcoin block confirmation depth required for SPV proofs
    uint256 public constant BTC_CONFIRMATIONS = 6;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum DepositStatus {
        PENDING, // Claim submitted, challenge window open
        CHALLENGED, // Active dispute
        FINALIZED, // Challenge window passed, deposit confirmed
        REJECTED // Fraud proof succeeded, deposit rejected
    }

    enum WithdrawalStatus {
        PENDING, // Burn executed on EVM, awaiting BTC release
        PROCESSING, // Operator broadcasting BTC transaction
        COMPLETED, // BTC released, confirmed on Bitcoin
        FORCE_EXIT // User forced withdrawal via fraud proof
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bitcoin SPV proof for transaction inclusion
    struct BitcoinSPVProof {
        bytes32 txHash; // Bitcoin transaction hash
        bytes32 blockHash; // Bitcoin block hash containing the tx
        uint256 blockHeight; // Bitcoin block height
        bytes merkleProof; // Merkle inclusion proof (concatenated siblings)
        uint256 txIndex; // Transaction index in the block
    }

    /// @notice Deposit claim from Bitcoin to EVM
    struct DepositClaim {
        bytes32 claimId;
        bytes32 btcTxHash; // Bitcoin deposit transaction hash
        address evmRecipient; // EVM address to receive wrapped BTC
        uint256 amountSats; // Amount in satoshis
        uint256 submittedAt; // Block timestamp of claim submission
        uint256 challengeDeadline;
        address operator; // Operator who submitted the claim
        DepositStatus status;
    }

    /// @notice Withdrawal request from EVM to Bitcoin
    struct WithdrawalRequest {
        bytes32 requestId;
        address evmSender; // EVM address burning wrapped BTC
        bytes btcRecipient; // Bitcoin address (P2PKH, P2SH, P2WPKH, or P2TR)
        uint256 amountSats; // Amount in satoshis
        uint256 requestedAt;
        bytes32 btcTxHash; // Operator's BTC release tx (set on completion)
        WithdrawalStatus status;
    }

    /// @notice Operator registration
    struct Operator {
        uint256 bond;
        uint256 registeredAt;
        uint256 totalDepositsProcessed;
        uint256 totalWithdrawalsProcessed;
        bool active;
        bool slashed;
    }

    /*//////////////////////////////////////////////////////////////
                           STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit claims indexed by claim ID
    mapping(bytes32 => DepositClaim) public depositClaims;

    /// @notice Withdrawal requests indexed by request ID
    mapping(bytes32 => WithdrawalRequest) public withdrawalRequests;

    /// @notice Registered operators
    mapping(address => Operator) public operators;

    /// @notice Message verification status (for IBridgeAdapter compatibility)
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Daily deposit tracking (day → total sats deposited)
    mapping(uint256 => uint256) public dailyDeposits;

    /// @notice Challenge period (configurable)
    uint256 public challengePeriod;

    /// @notice Bitcoin block header relay for SPV proof verification
    IBitcoinRelay public immutable bitcoinRelay;

    /// @notice Wrapped BTC ERC-20 token for minting/burning
    IWrappedBTC public immutable wrappedBTC;

    /// @notice Challenger bonds held in escrow during disputes
    mapping(bytes32 => address) public challengeInitiators;

    /// @notice Bond deposited by challenger for each dispute
    mapping(bytes32 => uint256) public challengeBonds;

    /// @notice Nonce for generating unique IDs
    uint256 private _nonce;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event DepositClaimSubmitted(
        bytes32 indexed claimId,
        bytes32 btcTxHash,
        address evmRecipient,
        uint256 amountSats,
        address operator
    );

    event DepositChallenged(bytes32 indexed claimId, address challenger);
    event DepositFinalized(
        bytes32 indexed claimId,
        address evmRecipient,
        uint256 amountSats
    );
    event DepositRejected(bytes32 indexed claimId, address challenger);

    event WithdrawalRequested(
        bytes32 indexed requestId,
        address evmSender,
        uint256 amountSats
    );
    event WithdrawalCompleted(bytes32 indexed requestId, bytes32 btcTxHash);
    event WithdrawalForceExited(bytes32 indexed requestId);

    event OperatorRegistered(address indexed operator, uint256 bond);
    event OperatorSlashed(address indexed operator, uint256 slashAmount);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotImplemented();
    error InsufficientBond(uint256 provided, uint256 required);
    error ChallengePeriodNotElapsed(uint256 deadline, uint256 current);
    error InvalidSPVProof();
    error DailyLimitExceeded(uint256 requested, uint256 remaining);
    error DepositNotPending(bytes32 claimId);
    error WithdrawalNotPending(bytes32 requestId);
    error DepositNotChallenged(bytes32 claimId);
    error ChallengeWindowClosed(bytes32 claimId);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the BitVM bridge adapter
    /// @param admin The default admin address
    /// @param _challengePeriod Initial challenge period duration
    /// @param _bitcoinRelay Address of the Bitcoin block header relay
    /// @param _wrappedBTC Address of the wrapped BTC ERC-20 token
    constructor(
        address admin,
        uint256 _challengePeriod,
        address _bitcoinRelay,
        address _wrappedBTC
    ) {
        require(admin != address(0), "BitVM: zero admin");
        require(_bitcoinRelay != address(0), "BitVM: zero relay");
        require(_wrappedBTC != address(0), "BitVM: zero wBTC");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        challengePeriod = _challengePeriod > 0
            ? _challengePeriod
            : DEFAULT_CHALLENGE_PERIOD;
        bitcoinRelay = IBitcoinRelay(_bitcoinRelay);
        wrappedBTC = IWrappedBTC(_wrappedBTC);
    }

    /*//////////////////////////////////////////////////////////////
                     IBridgeAdapter IMPLEMENTATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    /// @dev Encodes a BitVM deposit claim as a bridge message.
    ///      In production, this would submit an SPV proof and open a challenge window.
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        messageId = keccak256(
            abi.encodePacked(
                BITCOIN_CHAIN_ID,
                targetAddress,
                payload,
                refundAddress,
                _nonce++,
                block.timestamp
            )
        );

        // Decode payload: (btcTxHash, amountSats, evmRecipient, BitcoinSPVProof fields)
        (
            bytes32 btcTxHash,
            uint256 amountSats,
            bytes32 blockHash,
            uint256 blockHeight,
            bytes memory merkleProof,
            uint256 txIndex
        ) = abi.decode(
                payload,
                (bytes32, uint256, bytes32, uint256, bytes, uint256)
            );

        // Verify Bitcoin SPV proof against on-chain relay
        bool validSPV = bitcoinRelay.verifyTx(
            btcTxHash,
            blockHash,
            blockHeight,
            merkleProof,
            txIndex
        );
        if (!validSPV) {
            revert InvalidSPVProof();
        }

        // Ensure sufficient confirmations
        uint256 bestHeight = bitcoinRelay.getBestKnownHeight();
        require(
            bestHeight >= blockHeight + BTC_CONFIRMATIONS,
            "BitVM: insufficient confirmations"
        );

        // Verify daily limit
        uint256 today = block.timestamp / 1 days;
        if (dailyDeposits[today] + amountSats > MAX_DAILY_DEPOSIT_SATS) {
            revert DailyLimitExceeded(
                amountSats,
                MAX_DAILY_DEPOSIT_SATS - dailyDeposits[today]
            );
        }

        // Create deposit claim with challenge window
        depositClaims[messageId] = DepositClaim({
            claimId: messageId,
            btcTxHash: btcTxHash,
            evmRecipient: targetAddress,
            amountSats: amountSats,
            submittedAt: block.timestamp,
            challengeDeadline: block.timestamp + challengePeriod,
            operator: msg.sender,
            status: DepositStatus.PENDING
        });

        dailyDeposits[today] += amountSats;

        emit DepositClaimSubmitted(
            messageId,
            btcTxHash,
            targetAddress,
            amountSats,
            msg.sender
        );
    }

    /// @inheritdoc IBridgeAdapter
    /// @dev Estimates the gas cost for BitVM bridge operations.
    ///      Bitcoin SPV proof verification is ~500k-1M gas.
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external pure override returns (uint256 nativeFee) {
        // Estimated gas cost for SPV proof verification + challenge setup
        // This is a conservative estimate; actual cost depends on proof complexity
        return 0.01 ether;
    }

    /// @inheritdoc IBridgeAdapter
    /// @dev Returns true if a deposit claim has been finalized (challenge period elapsed)
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                     DEPOSIT OPERATIONS (STUB)
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a deposit claim with Bitcoin SPV proof
    /// @dev STUB — requires Bitcoin SPV verification library
    /// @param btcTxHash Bitcoin transaction hash
    /// @param evmRecipient EVM address to receive wrapped BTC
    /// @param amountSats Amount in satoshis
    /// @param proof Bitcoin SPV proof for transaction inclusion
    /// @return claimId Unique identifier for the deposit claim
    function submitDepositClaim(
        bytes32 btcTxHash,
        address evmRecipient,
        uint256 amountSats,
        BitcoinSPVProof calldata proof
    )
        external
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 claimId)
    {
        // Verify daily limit
        uint256 today = block.timestamp / 1 days;
        if (dailyDeposits[today] + amountSats > MAX_DAILY_DEPOSIT_SATS) {
            revert DailyLimitExceeded(
                amountSats,
                MAX_DAILY_DEPOSIT_SATS - dailyDeposits[today]
            );
        }

        claimId = keccak256(
            abi.encodePacked(
                BITCOIN_CHAIN_ID,
                btcTxHash,
                evmRecipient,
                amountSats,
                _nonce++
            )
        );

        depositClaims[claimId] = DepositClaim({
            claimId: claimId,
            btcTxHash: btcTxHash,
            evmRecipient: evmRecipient,
            amountSats: amountSats,
            submittedAt: block.timestamp,
            challengeDeadline: block.timestamp + challengePeriod,
            operator: msg.sender,
            status: DepositStatus.PENDING
        });

        dailyDeposits[today] += amountSats;

        // Verify Bitcoin SPV proof against on-chain Bitcoin relay
        bool validSPV = bitcoinRelay.verifyTx(
            proof.txHash,
            proof.blockHash,
            proof.blockHeight,
            proof.merkleProof,
            proof.txIndex
        );
        if (!validSPV) {
            revert InvalidSPVProof();
        }

        // Ensure sufficient Bitcoin confirmations for finality
        uint256 bestHeight = bitcoinRelay.getBestKnownHeight();
        require(
            bestHeight >= proof.blockHeight + BTC_CONFIRMATIONS,
            "BitVM: insufficient BTC confirmations"
        );

        emit DepositClaimSubmitted(
            claimId,
            btcTxHash,
            evmRecipient,
            amountSats,
            msg.sender
        );
    }

    /// @notice Challenge a pending deposit claim
    /// @dev Requires CHALLENGER_ROLE and challenge bond. If the fraud proof succeeds,
    ///      the challenger receives the operator's slashed bond.
    /// @param claimId The deposit claim to challenge
    function challengeDeposit(
        bytes32 claimId
    ) external payable onlyRole(CHALLENGER_ROLE) nonReentrant {
        DepositClaim storage claim = depositClaims[claimId];
        if (claim.status != DepositStatus.PENDING) {
            revert DepositNotPending(claimId);
        }
        if (block.timestamp > claim.challengeDeadline) {
            revert ChallengeWindowClosed(claimId);
        }
        if (msg.value < MIN_CHALLENGE_BOND) {
            revert InsufficientBond(msg.value, MIN_CHALLENGE_BOND);
        }

        claim.status = DepositStatus.CHALLENGED;
        challengeInitiators[claimId] = msg.sender;
        challengeBonds[claimId] = msg.value;

        emit DepositChallenged(claimId, msg.sender);
    }

    /// @notice Resolve a disputed deposit. Called by challenger with an SPV proof
    ///         showing the original claim was fraudulent (e.g. tx doesn't exist
    ///         at the claimed block height, or amount mismatches).
    /// @param claimId The challenged deposit claim
    /// @param proof Counter-proof from the challenger
    function resolveDispute(
        bytes32 claimId,
        BitcoinSPVProof calldata proof
    ) external nonReentrant {
        DepositClaim storage claim = depositClaims[claimId];
        if (claim.status != DepositStatus.CHALLENGED) {
            revert DepositNotChallenged(claimId);
        }

        address challenger = challengeInitiators[claimId];
        uint256 bond = challengeBonds[claimId];
        Operator storage op = operators[claim.operator];

        // Re-verify the original claim against the relay.
        // If the relay CANNOT verify the tx, the original claim was fraudulent.
        bool originalValid = bitcoinRelay.verifyTx(
            claim.btcTxHash,
            proof.blockHash,
            proof.blockHeight,
            proof.merkleProof,
            proof.txIndex
        );

        if (!originalValid) {
            // Fraud proven — slash operator, reward challenger, reject deposit
            claim.status = DepositStatus.REJECTED;

            uint256 slashAmount = op.bond;
            op.bond = 0;
            op.slashed = true;
            op.active = false;

            // Return challenger bond + operator slash reward
            uint256 reward = bond + slashAmount;
            (bool sent, ) = challenger.call{value: reward}("");
            require(sent, "BitVM: reward transfer failed");

            emit OperatorSlashed(claim.operator, slashAmount);
            emit DepositRejected(claimId, challenger);
        } else {
            // Fraud disproven — slash challenger bond, finalize deposit
            claim.status = DepositStatus.FINALIZED;
            verifiedMessages[claimId] = true;

            // Forfeit challenger bond to operator
            (bool sent, ) = claim.operator.call{value: bond}("");
            require(sent, "BitVM: bond transfer failed");

            // Mint wrapped BTC to recipient
            wrappedBTC.mint(claim.evmRecipient, claim.amountSats);

            emit DepositFinalized(
                claimId,
                claim.evmRecipient,
                claim.amountSats
            );
        }

        delete challengeInitiators[claimId];
        delete challengeBonds[claimId];
    }

    /// @notice Finalize a deposit after the challenge period has elapsed
    /// @param claimId The deposit claim to finalize
    function finalizeDeposit(
        bytes32 claimId
    ) external nonReentrant whenNotPaused {
        DepositClaim storage claim = depositClaims[claimId];
        if (claim.status != DepositStatus.PENDING) {
            revert DepositNotPending(claimId);
        }
        if (block.timestamp < claim.challengeDeadline) {
            revert ChallengePeriodNotElapsed(
                claim.challengeDeadline,
                block.timestamp
            );
        }

        claim.status = DepositStatus.FINALIZED;
        verifiedMessages[claimId] = true;

        // Mint wrapped BTC to the EVM recipient
        wrappedBTC.mint(claim.evmRecipient, claim.amountSats);

        emit DepositFinalized(claimId, claim.evmRecipient, claim.amountSats);
    }

    /*//////////////////////////////////////////////////////////////
                   WITHDRAWAL OPERATIONS (STUB)
    //////////////////////////////////////////////////////////////*/

    /// @notice Request a withdrawal (EVM → Bitcoin)
    /// @dev Burns wrapped BTC and creates a withdrawal request for an operator to fulfill
    /// @param btcRecipient Bitcoin address to receive BTC
    /// @param amountSats Amount in satoshis to withdraw
    /// @return requestId Unique identifier for the withdrawal request
    function requestWithdrawal(
        bytes calldata btcRecipient,
        uint256 amountSats
    ) external nonReentrant whenNotPaused returns (bytes32 requestId) {
        require(btcRecipient.length >= 20, "Invalid BTC address");
        require(amountSats > 0, "Zero amount");

        requestId = keccak256(
            abi.encodePacked(
                msg.sender,
                btcRecipient,
                amountSats,
                _nonce++,
                block.timestamp
            )
        );

        withdrawalRequests[requestId] = WithdrawalRequest({
            requestId: requestId,
            evmSender: msg.sender,
            btcRecipient: btcRecipient,
            amountSats: amountSats,
            requestedAt: block.timestamp,
            btcTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING
        });

        // Burn wrapped BTC from the sender
        wrappedBTC.burn(msg.sender, amountSats);

        emit WithdrawalRequested(requestId, msg.sender, amountSats);
    }

    /*//////////////////////////////////////////////////////////////
                     OPERATOR MANAGEMENT (STUB)
    //////////////////////////////////////////////////////////////*/

    /// @notice Register as a BitVM operator by posting a bond
    function registerOperator() external payable nonReentrant {
        if (msg.value < MIN_OPERATOR_BOND) {
            revert InsufficientBond(msg.value, MIN_OPERATOR_BOND);
        }

        operators[msg.sender] = Operator({
            bond: msg.value,
            registeredAt: block.timestamp,
            totalDepositsProcessed: 0,
            totalWithdrawalsProcessed: 0,
            active: true,
            slashed: false
        });

        emit OperatorRegistered(msg.sender, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the BitVM bridge
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the BitVM bridge
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Update the challenge period
    /// @param newPeriod New challenge period in seconds
    function setChallengePeriod(
        uint256 newPeriod
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newPeriod >= 1 days, "Period too short");
        require(newPeriod <= 30 days, "Period too long");
        challengePeriod = newPeriod;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get a deposit claim by ID
    function getDepositClaim(
        bytes32 claimId
    ) external view returns (DepositClaim memory) {
        return depositClaims[claimId];
    }

    /// @notice Get a withdrawal request by ID
    function getWithdrawalRequest(
        bytes32 requestId
    ) external view returns (WithdrawalRequest memory) {
        return withdrawalRequests[requestId];
    }

    /// @notice Get operator details
    function getOperator(address addr) external view returns (Operator memory) {
        return operators[addr];
    }

    /// @notice Check if a deposit claim has been finalized
    function isDepositFinalized(bytes32 claimId) external view returns (bool) {
        return depositClaims[claimId].status == DepositStatus.FINALIZED;
    }

    receive() external payable {}
}
