// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IBitcoinBridgeAdapter.sol";

/**
 * @title BitcoinBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Bitcoin network integration
 * @dev Enables cross-chain privacy-preserving operations between Bitcoin and Ethereum
 *
 * BITCOIN INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Soul <-> Bitcoin Network Bridge                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌───────────────────┐           ┌───────────────────┐                  │
 * │  │   Soul Protocol    │           │  Bitcoin Network  │                  │
 * │  │  (Ethereum L1)    │           │   (UTXO Chain)    │                  │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                  │
 * │  │  │ HTLC        │  │◄─────────►│  │ HTLC Script │  │                  │
 * │  │  │ Contract    │  │           │  │ (P2SH)      │  │                  │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                  │
 * │  │        │          │           │        │          │                  │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                  │
 * │  │  │ SPV         │  │◄─────────►│  │ Block       │  │                  │
 * │  │  │ Verifier    │  │           │  │ Headers     │  │                  │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                  │
 * │  └───────────────────┘           └───────────────────┘                  │
 * │              │                           │                               │
 * │              └───────────┬───────────────┘                               │
 * │                          │                                               │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐  │
 * │  │                   BitcoinBridgeAdapter.sol                         │  │
 * │  │  - BTC → ETH: SPV proof verification + wBTC minting               │  │
 * │  │  - ETH → BTC: HTLC-based atomic swap coordination                 │  │
 * │  │  - Privacy: Nullifier integration for private transfers            │  │
 * │  └───────────────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED OPERATIONS:
 * - Lock BTC → Mint wBTC (via SPV proofs)
 * - Burn wBTC → Release BTC (via HTLC)
 * - Atomic swaps (BTC <-> ETH/tokens)
 * - Private cross-chain transfers with nullifiers
 */
contract BitcoinBridgeAdapter is
    IBitcoinBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
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

    /// @notice Bitcoin mainnet chain ID (virtual)
    uint256 public constant BTC_MAINNET_CHAIN_ID = 0x426974636F696E; // "Bitcoin" in hex

    /// @notice Bitcoin testnet chain ID (virtual)
    uint256 public constant BTC_TESTNET_CHAIN_ID = 0x5465737442544; // "TestBTC" in hex

    /// @notice Minimum deposit in satoshis (0.001 BTC)
    uint256 public constant MIN_DEPOSIT_SATOSHIS = 100000;

    /// @notice Maximum deposit in satoshis (100 BTC)
    uint256 public constant MAX_DEPOSIT_SATOSHIS = 10000000000;

    /// @notice Satoshis per BTC
    uint256 public constant SATOSHIS_PER_BTC = 100000000;

    /// @notice HTLC default timelock (24 hours in seconds)
    uint256 public constant DEFAULT_HTLC_TIMELOCK = 24 hours;

    /// @notice Minimum HTLC timelock (1 hour)
    uint256 public constant MIN_HTLC_TIMELOCK = 1 hours;

    /// @notice Maximum HTLC timelock (7 days)
    uint256 public constant MAX_HTLC_TIMELOCK = 7 days;

    /// @notice Bridge fee in basis points (0.25% = 25 bps)
    uint256 public constant BRIDGE_FEE_BPS = 25;

    /// @notice Required confirmations for BTC deposit
    uint256 public constant REQUIRED_CONFIRMATIONS = 6;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice SPV Verifier contract address
    address public spvVerifier;

    /// @notice Wrapped BTC token address
    address public wrappedBTC;

    /// @notice Treasury address for fees
    address public treasury;

    /// @notice Bridge is configured
    bool public isConfigured;

    /// @notice Deposit nonce
    uint256 public depositNonce;

    /// @notice HTLC nonce
    uint256 public htlcNonce;

    /// @notice Latest verified Bitcoin block height
    uint256 public latestBTCBlockHeight;

    /// @notice Latest verified Bitcoin block hash
    bytes32 public latestBTCBlockHash;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice BTC deposits by ID
    mapping(bytes32 => BTCDeposit) public deposits;

    /// @notice HTLCs by ID
    mapping(bytes32 => HTLC) public htlcs;

    /// @notice BTC withdrawals by ID
    mapping(bytes32 => BTCWithdrawal) public withdrawals;

    /// @notice Used Bitcoin transaction IDs (prevent replay)
    mapping(bytes32 => bool) public usedBtcTxIds;

    /// @notice Used nullifiers for privacy proofs
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Verified Bitcoin block headers
    mapping(bytes32 => BTCBlockHeader) public verifiedBlocks;

    /// @notice User deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice User HTLC IDs
    mapping(address => bytes32[]) public userHTLCs;

    /// @notice User withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/
    error InvalidBitcoinTransaction();
    error TransferFailed();

    /// @notice Total BTC deposited (satoshis)
    uint256 public totalDeposited;

    /// @notice Total BTC withdrawn (satoshis)
    uint256 public totalWithdrawn;

    /// @notice Total HTLCs created
    uint256 public totalHTLCs;

    /// @notice Total HTLCs redeemed
    uint256 public totalHTLCsRedeemed;

    /// @notice Total HTLCs refunded
    uint256 public totalHTLCsRefunded;

    /// @notice Accumulated fees (satoshis)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(TREASURY_ROLE, _admin);

        treasury = _admin;
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure the Bitcoin bridge
     * @param _spvVerifier SPV verifier contract address
     * @param _wrappedBTC Wrapped BTC token address
     */
    function configure(
        address _spvVerifier,
        address _wrappedBTC
    ) external onlyRole(OPERATOR_ROLE) {
        if (_spvVerifier == address(0) || _wrappedBTC == address(0)) {
            revert ZeroAddress();
        }

        spvVerifier = _spvVerifier;
        wrappedBTC = _wrappedBTC;
        isConfigured = true;

        emit BridgeConfigured(_spvVerifier, _wrappedBTC);
    }

    /**
     * @notice Set treasury address
     * @param _treasury New treasury address
     */
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /*//////////////////////////////////////////////////////////////
                      BTC → ETH DEPOSITS (SPV)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a BTC deposit with SPV proof
     * @param btcTxId Bitcoin transaction ID
     * @param btcTxRaw Raw Bitcoin transaction bytes
     * @param merkleProof Merkle proof for transaction inclusion
     * @param blockHeader Bitcoin block header containing the transaction
     * @param ethRecipient Ethereum address to receive wBTC
     * @return depositId The deposit ID
     */
    function initiateBTCDeposit(
        bytes32 btcTxId,
        bytes calldata btcTxRaw,
        bytes32[] calldata merkleProof,
        bytes calldata blockHeader,
        address ethRecipient
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!isConfigured) revert BridgeNotConfigured();
        if (usedBtcTxIds[btcTxId]) revert BTCTxAlreadyUsed(btcTxId);
        if (ethRecipient == address(0)) revert ZeroAddress();

        // Parse BTC transaction to extract output amount
        (uint256 satoshis, bytes memory scriptPubKey) = _parseBTCTransaction(
            btcTxRaw
        );

        if (satoshis < MIN_DEPOSIT_SATOSHIS) revert DepositTooSmall(satoshis);
        if (satoshis > MAX_DEPOSIT_SATOSHIS) revert DepositTooLarge(satoshis);

        // Verify SPV proof
        if (!_verifySPVProof(btcTxId, merkleProof, blockHeader)) {
            revert InvalidSPVProof(btcTxId);
        }

        // Mark BTC tx as used
        usedBtcTxIds[btcTxId] = true;

        // Calculate fee
        uint256 fee = (satoshis * BRIDGE_FEE_BPS) / 10000;
        uint256 netAmount = satoshis - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                btcTxId,
                ethRecipient,
                depositNonce++,
                block.timestamp
            )
        );

        // Store deposit
        deposits[depositId] = BTCDeposit({
            depositId: depositId,
            btcTxId: btcTxId,
            scriptPubKey: scriptPubKey,
            satoshis: satoshis,
            netAmount: netAmount,
            fee: fee,
            ethRecipient: ethRecipient,
            proofHash: bytes32(0),
            status: DepositStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[ethRecipient].push(depositId);
        accumulatedFees += fee;

        emit BTCDepositInitiated(depositId, btcTxId, satoshis, ethRecipient);
    }

    /**
     * @notice Complete a BTC deposit (mint wBTC)
     * @param depositId The deposit ID to complete
     */
    function completeBTCDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BTCDeposit storage deposit = deposits[depositId];

        if (deposit.initiatedAt == 0) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.PENDING) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        totalDeposited += deposit.satoshis;

        // In production: Mint wBTC to recipient
        // IWrappedBTC(wrappedBTC).mint(deposit.ethRecipient, deposit.netAmount);

        emit BTCDepositCompleted(
            depositId,
            deposit.ethRecipient,
            deposit.netAmount
        );
    }

    /*//////////////////////////////////////////////////////////////
                      ETH → BTC WITHDRAWALS (HTLC)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate withdrawal to Bitcoin via HTLC
     * @param btcRecipientPubKeyHash Bitcoin recipient public key hash (20 bytes)
     * @param satoshis Amount in satoshis
     * @param hashlock Secret hash for HTLC
     * @param timelock Timelock duration in seconds
     * @return withdrawalId The withdrawal ID
     */
    function initiateWithdrawal(
        bytes20 btcRecipientPubKeyHash,
        uint256 satoshis,
        bytes32 hashlock,
        uint256 timelock
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 withdrawalId)
    {
        if (!isConfigured) revert BridgeNotConfigured();
        if (satoshis < MIN_DEPOSIT_SATOSHIS) revert AmountTooSmall(satoshis);
        if (satoshis > MAX_DEPOSIT_SATOSHIS) revert AmountTooLarge(satoshis);
        if (timelock < MIN_HTLC_TIMELOCK) revert TimelockTooShort(timelock);
        if (timelock > MAX_HTLC_TIMELOCK) revert TimelockTooLong(timelock);
        if (hashlock == bytes32(0)) revert InvalidHashlock();

        // In production: Burn wBTC from sender
        // IWrappedBTC(wrappedBTC).burnFrom(msg.sender, satoshis);

        // Generate withdrawal ID
        withdrawalId = keccak256(
            abi.encodePacked(
                msg.sender,
                btcRecipientPubKeyHash,
                satoshis,
                hashlock,
                block.timestamp
            )
        );

        // Calculate fee
        uint256 fee = (satoshis * BRIDGE_FEE_BPS) / 10000;
        uint256 netAmount = satoshis - fee;

        // Store withdrawal
        withdrawals[withdrawalId] = BTCWithdrawal({
            withdrawalId: withdrawalId,
            ethSender: msg.sender,
            btcRecipientPubKeyHash: btcRecipientPubKeyHash,
            satoshis: satoshis,
            netAmount: netAmount,
            fee: fee,
            hashlock: hashlock,
            timelock: block.timestamp + timelock,
            preimage: bytes32(0),
            btcTxId: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        accumulatedFees += fee;

        emit WithdrawalInitiated(
            withdrawalId,
            msg.sender,
            btcRecipientPubKeyHash,
            satoshis,
            hashlock
        );
    }

    /**
     * @notice Complete withdrawal with Bitcoin transaction proof
     * @param withdrawalId The withdrawal ID
     * @param btcTxId Bitcoin transaction ID fulfilling withdrawal
     * @param preimage HTLC preimage
     */
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 btcTxId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        BTCWithdrawal storage withdrawal = withdrawals[withdrawalId];

        if (withdrawal.initiatedAt == 0)
            revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }

        // Verify hashlock
        if (keccak256(abi.encodePacked(preimage)) != withdrawal.hashlock) {
            revert InvalidPreimage(withdrawalId);
        }

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.preimage = preimage;
        withdrawal.btcTxId = btcTxId;
        withdrawal.completedAt = block.timestamp;

        totalWithdrawn += withdrawal.satoshis;

        emit WithdrawalCompleted(withdrawalId, btcTxId, preimage);
    }

    /**
     * @notice Refund a timed-out withdrawal
     * @param withdrawalId The withdrawal ID to refund
     */
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        BTCWithdrawal storage withdrawal = withdrawals[withdrawalId];

        if (withdrawal.initiatedAt == 0)
            revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (block.timestamp < withdrawal.timelock) {
            revert TimelockNotExpired(withdrawalId, withdrawal.timelock);
        }

        withdrawal.status = WithdrawalStatus.REFUNDED;
        withdrawal.completedAt = block.timestamp;

        // In production: Refund wBTC to sender
        // IWrappedBTC(wrappedBTC).mint(withdrawal.ethSender, withdrawal.satoshis);

        emit WithdrawalRefunded(withdrawalId, withdrawal.ethSender);
    }

    /*//////////////////////////////////////////////////////////////
                         HTLC OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an HTLC for atomic swap
     * @param hashlock Secret hash
     * @param timelock Duration until refund allowed
     * @param recipient Address to receive funds on redeem
     * @return htlcId The HTLC ID
     */
    function createHTLC(
        bytes32 hashlock,
        uint256 timelock,
        address recipient
    ) external payable nonReentrant whenNotPaused returns (bytes32 htlcId) {
        if (msg.value == 0) revert InvalidAmount();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (recipient == address(0)) revert ZeroAddress();
        if (timelock < MIN_HTLC_TIMELOCK) revert TimelockTooShort(timelock);
        if (timelock > MAX_HTLC_TIMELOCK) revert TimelockTooLong(timelock);

        htlcId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                msg.value,
                hashlock,
                htlcNonce++
            )
        );

        htlcs[htlcId] = HTLC({
            htlcId: htlcId,
            sender: msg.sender,
            recipient: recipient,
            amount: msg.value,
            hashlock: hashlock,
            timelock: block.timestamp + timelock,
            preimage: bytes32(0),
            status: HTLCStatus.ACTIVE,
            createdAt: block.timestamp,
            completedAt: 0
        });

        userHTLCs[msg.sender].push(htlcId);
        totalHTLCs++;

        emit HTLCCreated(
            htlcId,
            msg.sender,
            recipient,
            msg.value,
            hashlock,
            block.timestamp + timelock
        );
    }

    /**
     * @notice Redeem an HTLC with the preimage
     * @param htlcId The HTLC ID
     * @param preimage The secret preimage
     */
    function redeemHTLC(
        bytes32 htlcId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        HTLC storage htlc = htlcs[htlcId];

        if (htlc.createdAt == 0) revert HTLCNotFound(htlcId);
        if (htlc.status != HTLCStatus.ACTIVE) revert HTLCNotActive(htlcId);

        // Verify hashlock
        if (keccak256(abi.encodePacked(preimage)) != htlc.hashlock) {
            revert InvalidPreimage(htlcId);
        }

        htlc.status = HTLCStatus.REDEEMED;
        htlc.preimage = preimage;
        htlc.completedAt = block.timestamp;

        totalHTLCsRedeemed++;

        // Transfer funds to recipient
        (bool success, ) = htlc.recipient.call{value: htlc.amount}("");
        if (!success) revert TransferFailed();

        emit HTLCRedeemed(htlcId, preimage, htlc.recipient);
    }

    /**
     * @notice Refund a timed-out HTLC
     * @param htlcId The HTLC ID to refund
     */
    function refundHTLC(bytes32 htlcId) external nonReentrant whenNotPaused {
        HTLC storage htlc = htlcs[htlcId];

        if (htlc.createdAt == 0) revert HTLCNotFound(htlcId);
        if (htlc.status != HTLCStatus.ACTIVE) revert HTLCNotActive(htlcId);
        if (block.timestamp < htlc.timelock) {
            revert TimelockNotExpired(htlcId, htlc.timelock);
        }

        htlc.status = HTLCStatus.REFUNDED;
        htlc.completedAt = block.timestamp;

        totalHTLCsRefunded++;

        // Return funds to sender
        (bool success, ) = htlc.sender.call{value: htlc.amount}("");
        if (!success) revert TransferFailed();

        emit HTLCRefunded(htlcId, htlc.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Private BTC deposit with nullifier
     * @param depositId Deposit to make private
     * @param nullifier Nullifier for the private commitment
     * @param proof ZK proof of valid nullifier derivation
     */
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 nullifier,
        bytes calldata proof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BTCDeposit storage deposit = deposits[depositId];

        if (deposit.initiatedAt == 0) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.COMPLETED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // In production: Verify ZK proof
        if (proof.length < 64) revert InvalidProof(depositId);

        usedNullifiers[nullifier] = true;
        deposit.proofHash = keccak256(proof);

        emit PrivateDepositRegistered(depositId, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                       BLOCK HEADER RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit Bitcoin block header for SPV verification
     * @param blockHash Block hash
     * @param blockHeader Raw block header (80 bytes)
     * @param height Block height
     */
    function submitBlockHeader(
        bytes32 blockHash,
        bytes calldata blockHeader,
        uint256 height
    ) external onlyRole(RELAYER_ROLE) {
        if (blockHeader.length != 80) revert InvalidBlockHeader();

        // In production: Verify block header against previous and difficulty
        verifiedBlocks[blockHash] = BTCBlockHeader({
            blockHash: blockHash,
            prevBlockHash: bytes32(0), // Would be extracted from header
            merkleRoot: bytes32(0), // Would be extracted from header
            timestamp: block.timestamp,
            height: height,
            verified: true
        });

        if (height > latestBTCBlockHeight) {
            latestBTCBlockHeight = height;
            latestBTCBlockHash = blockHash;
        }

        emit BlockHeaderSubmitted(blockHash, height);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(
        bytes32 depositId
    ) external view returns (BTCDeposit memory) {
        return deposits[depositId];
    }

    function getHTLC(bytes32 htlcId) external view returns (HTLC memory) {
        return htlcs[htlcId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BTCWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    function getUserHTLCs(
        address user
    ) external view returns (bytes32[] memory) {
        return userHTLCs[user];
    }

    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    function getBridgeStats()
        external
        view
        returns (
            uint256 deposited,
            uint256 withdrawn,
            uint256 htlcsTotal,
            uint256 htlcsRedeemed,
            uint256 htlcsRefunded,
            uint256 fees
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalHTLCs,
            totalHTLCsRedeemed,
            totalHTLCsRefunded,
            accumulatedFees
        );
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        // In production: Transfer wBTC fees to treasury
        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Parse Bitcoin transaction to extract output value
     * @param btcTxRaw Raw Bitcoin transaction
     * @return satoshis Output value in satoshis
     * @return scriptPubKey Output script
     */
    function _parseBTCTransaction(
        bytes calldata btcTxRaw
    ) internal pure returns (uint256 satoshis, bytes memory scriptPubKey) {
        // Bitcoin transaction structure:
        // [4 bytes version][varint input count][inputs...][varint output count][outputs...]
        // Output structure: [8 bytes value LE][varint script length][script...]

        if (btcTxRaw.length < 100) revert InvalidBitcoinTransaction();

        // Skip version (4 bytes)
        uint256 offset = 4;

        // Parse input count (varint)
        (uint256 inputCount, uint256 varIntLen) = _parseVarInt(
            btcTxRaw,
            offset
        );
        offset += varIntLen;

        // Skip inputs (each: 32 txid + 4 vout + varint script + script + 4 sequence)
        for (uint256 i = 0; i < inputCount; i++) {
            offset += 36; // txid + vout
            (uint256 inScriptLen, uint256 vLen) = _parseVarInt(
                btcTxRaw,
                offset
            );
            offset += vLen + inScriptLen + 4; // script + sequence
            if (offset >= btcTxRaw.length) revert InvalidBitcoinTransaction();
        }

        // Parse output count
        (uint256 outputCount, uint256 outVarLen) = _parseVarInt(
            btcTxRaw,
            offset
        );
        offset += outVarLen;

        if (outputCount == 0) revert InvalidBitcoinTransaction();

        // Parse first output value (8 bytes little-endian)
        satoshis =
            uint256(uint8(btcTxRaw[offset])) |
            (uint256(uint8(btcTxRaw[offset + 1])) << 8) |
            (uint256(uint8(btcTxRaw[offset + 2])) << 16) |
            (uint256(uint8(btcTxRaw[offset + 3])) << 24) |
            (uint256(uint8(btcTxRaw[offset + 4])) << 32) |
            (uint256(uint8(btcTxRaw[offset + 5])) << 40) |
            (uint256(uint8(btcTxRaw[offset + 6])) << 48) |
            (uint256(uint8(btcTxRaw[offset + 7])) << 56);
        offset += 8;

        // Parse script length and script
        (uint256 scriptLen, uint256 sVarLen) = _parseVarInt(btcTxRaw, offset);
        offset += sVarLen;

        scriptPubKey = new bytes(scriptLen);
        for (
            uint256 i = 0;
            i < scriptLen && (offset + i) < btcTxRaw.length;
            i++
        ) {
            scriptPubKey[i] = btcTxRaw[offset + i];
        }
    }

    /**
     * @dev Parse Bitcoin varint
     */
    function _parseVarInt(
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 value, uint256 length) {
        uint8 first = uint8(data[offset]);
        if (first < 0xFD) {
            return (first, 1);
        } else if (first == 0xFD) {
            value =
                uint256(uint8(data[offset + 1])) |
                (uint256(uint8(data[offset + 2])) << 8);
            return (value, 3);
        } else if (first == 0xFE) {
            value =
                uint256(uint8(data[offset + 1])) |
                (uint256(uint8(data[offset + 2])) << 8) |
                (uint256(uint8(data[offset + 3])) << 16) |
                (uint256(uint8(data[offset + 4])) << 24);
            return (value, 5);
        } else {
            // 0xFF - 8 byte value (unlikely for tx counts)
            return (0, 9);
        }
    }

    /**
     * @dev Verify SPV inclusion proof
     * @param btcTxId Transaction hash
     * @param merkleProof Merkle siblings
     * @param blockHeader Block header
     * @return valid Whether proof is valid
     */
    function _verifySPVProof(
        bytes32 btcTxId,
        bytes32[] calldata merkleProof,
        bytes calldata blockHeader
    ) internal view returns (bool valid) {
        // Basic validation always required
        if (btcTxId == bytes32(0)) return false;
        if (merkleProof.length == 0) return false;
        if (blockHeader.length != 80) return false;

        // If SPV verifier is configured, delegate to it
        if (spvVerifier != address(0)) {
            (bool success, bytes memory result) = spvVerifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32[],bytes)",
                    btcTxId,
                    merkleProof,
                    blockHeader
                )
            );
            if (success && result.length >= 32) {
                return abi.decode(result, (bool));
            }
            return false;
        }

        // Development mode - basic structural validation only
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          RECEIVE FUNCTION
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}
}
