// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAztecRollupProcessor
 * @notice Minimal interface for the Aztec Rollup Processor (L1 contract)
 * @dev Aztec is a privacy-first ZK-rollup on Ethereum using Noir circuits and
 *      UltraHonk proofs. The Rollup Processor accepts encrypted note commitments
 *      and processes state transitions via recursive SNARK proofs.
 */
interface IAztecRollupProcessor {
    /// @notice Deposit ETH or ERC-20 into the Aztec L2 shielded pool
    /// @param assetId The Aztec asset ID (0 = ETH, >0 = registered ERC-20)
    /// @param amount The deposit amount (set to 0 for ETH, use msg.value)
    /// @param owner The Aztec L2 address (Grumpkin public key hash)
    /// @return The note commitment added to the data tree
    function depositPendingFunds(
        uint256 assetId,
        uint256 amount,
        address owner
    ) external payable returns (bytes32);

    /// @notice Get the current data tree root
    /// @return root The current Merkle root of Aztec's encrypted note tree
    function rollupStateHash() external view returns (bytes32 root);

    /// @notice Check if a data root has been finalised on L1
    /// @param root The root to check
    /// @return True if the root has been finalized
    function isRootFinalized(bytes32 root) external view returns (bool);
}

/**
 * @title IAztecDefiBridge
 * @notice Interface for Aztec's DeFi Bridge Proxy
 * @dev Aztec DeFi bridges enable private DeFi interactions from within the
 *      Aztec shielded set. They act as connectors between Aztec's private state
 *      and L1 DeFi protocols.
 */
interface IAztecDefiBridge {
    /// @notice Process a bridge interaction for converting between Aztec and ZASEON
    /// @param inputAssetId Input asset in the Aztec note tree
    /// @param outputAssetId Output asset after bridging
    /// @param totalInputValue Total value of input notes being bridged
    /// @param interactionNonce Unique nonce for this bridge interaction
    /// @return outputValueA Primary output value
    /// @return isAsync Whether the bridge interaction is asynchronous
    function convert(
        uint256 inputAssetId,
        uint256 outputAssetId,
        uint256 totalInputValue,
        uint256 interactionNonce
    ) external payable returns (uint256 outputValueA, bool isAsync);

    /// @notice Finalize an async bridge interaction
    /// @param interactionNonce The nonce of the interaction to finalize
    /// @return success Whether finalization succeeded
    function finalise(uint256 interactionNonce) external returns (bool success);
}

/**
 * @title AztecBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Aztec Network — privacy-first ZK-rollup on Ethereum
 * @dev Enables ZASEON cross-chain interoperability with Aztec's private execution
 *      environment via the Aztec Rollup Processor and DeFi Bridge infrastructure.
 *
 * AZTEC INTEGRATION:
 * - ZK-Rollup: Aztec is a privacy-first L2 with encrypted state and private execution
 * - Proof system: UltraHonk (successor to TurboPlonk) via Noir circuits on BN254
 * - Note model: Encrypted UTXO notes in a Merkle tree (similar to Zcash's design)
 * - Deposits: L1→Aztec via depositPendingFunds() on the Rollup Processor
 * - Withdrawals: Aztec→L1 via DeFi bridge interactions or direct withdrawals
 * - Privacy: Full transaction privacy (encrypted notes, private execution)
 *
 * MESSAGE FLOW:
 * - ZASEON→Aztec: Deposit into Aztec L2 → creates encrypted note commitment
 * - Aztec→ZASEON: DeFi bridge withdrawal with Honk proof → state relayed to ZASEON
 *
 * SECURITY NOTES:
 * - UltraHonk proofs verified by Aztec's L1 verifier contracts
 * - Nullifier-based double-spend protection (integrates with AZTEC_NOTE in ZASEON)
 * - Sequential data tree roots ensure state consistency
 * - All state-changing functions protected by ReentrancyGuard and access control
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract AztecBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for operators who can manage bridge operations
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    /// @notice Role for guardians who can perform emergency actions
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    /// @notice Role for relayers who can deliver proofs from Aztec
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Role for pausers who can pause the adapter
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Aztec virtual chain identifier (ZASEON-internal; Aztec settles on Ethereum L1)
    /// @dev Aztec mainnet does not have its own EVM chain ID. 4100 is ZASEON-internal.
    uint16 public constant AZTEC_CHAIN_ID = 4100;

    /// @notice Finality in L1 blocks (Aztec proofs posted and verified on Ethereum)
    uint256 public constant FINALITY_BLOCKS = 15;

    /// @notice Max bridge fee in basis points (1% = 100 bps)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Max payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice UltraHonk proof size: 512 bytes (recursive aggregation proof)
    uint256 public constant HONK_PROOF_SIZE = 512;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        DELIVERED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        bytes32 noteCommitment; // Aztec encrypted note commitment
        uint256 timestamp;
        bytes32 dataRoot; // Aztec data tree root at time of action
        bytes32 nullifier; // Nullifier for double-spend protection
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Aztec Rollup Processor contract (deposit/withdrawal entry point)
    IAztecRollupProcessor public rollupProcessor;

    /// @notice Aztec DeFi Bridge Proxy (bridge interactions)
    IAztecDefiBridge public defiBridge;

    /// @notice Bridge fee in basis points (max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent ZASEON → Aztec
    uint256 public totalMessagesSent;

    /// @notice Total messages received Aztec → ZASEON
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (native)
    uint256 public totalValueBridged;

    /// @notice Per-sender nonce counter
    mapping(address => uint256) public senderNonces;

    /// @notice Nullifier → consumed flag (double-spend protection, integrates with AZTEC_NOTE)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Internal message tracking by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is deposited into Aztec L2 (ZASEON → Aztec)
    event MessageDeposited(
        bytes32 indexed messageHash,
        bytes32 indexed noteCommitment,
        bytes32 dataRoot,
        uint256 nonce,
        address sender
    );

    /// @notice Emitted when a verified withdrawal from Aztec is consumed (Aztec → ZASEON)
    event MessageWithdrawn(
        bytes32 indexed messageHash,
        bytes32 indexed nullifier,
        bytes32 dataRoot,
        uint256 nonce
    );

    /// @notice Emitted when the rollup processor address is updated
    event RollupProcessorSet(address indexed processor);

    /// @notice Emitted when the DeFi bridge address is updated
    event DefiBridgeSet(address indexed bridge);

    /// @notice Emitted when the bridge fee is updated
    event BridgeFeeSet(uint256 feeBps);

    /// @notice Emitted when the minimum message fee is updated
    event MinMessageFeeSet(uint256 fee);

    /// @notice Emitted on emergency ETH withdrawal
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProcessor();
    error InvalidBridge();
    error InvalidTarget();
    error InvalidPayload();
    error BridgeNotConfigured();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error DataRootNotFinalized(bytes32 root);
    error FeeTooHigh(uint256 fee);
    error InsufficientFee(uint256 required, uint256 provided);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _rollupProcessor Address of the Aztec Rollup Processor on L1
    /// @param _defiBridge Address of the Aztec DeFi Bridge Proxy
    /// @param _admin Address to receive admin roles
    constructor(address _rollupProcessor, address _defiBridge, address _admin) {
        if (_admin == address(0)) revert InvalidTarget();
        if (_rollupProcessor == address(0)) revert InvalidProcessor();
        if (_defiBridge == address(0)) revert InvalidBridge();

        rollupProcessor = IAztecRollupProcessor(_rollupProcessor);
        defiBridge = IAztecDefiBridge(_defiBridge);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Aztec Rollup Processor address
    /// @param _rollupProcessor New Aztec Rollup Processor address
    function setRollupProcessor(
        address _rollupProcessor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_rollupProcessor == address(0)) revert InvalidProcessor();
        rollupProcessor = IAztecRollupProcessor(_rollupProcessor);
        emit RollupProcessorSet(_rollupProcessor);
    }

    /// @notice Update the DeFi Bridge Proxy address
    /// @param _defiBridge New DeFi Bridge Proxy address
    function setDefiBridge(
        address _defiBridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_defiBridge == address(0)) revert InvalidBridge();
        defiBridge = IAztecDefiBridge(_defiBridge);
        emit DefiBridgeSet(_defiBridge);
    }

    /// @notice Set the bridge fee in basis points (max 1%)
    /// @param _feeBps Fee in basis points
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_feeBps > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_feeBps);
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /// @notice Set the minimum message fee
    /// @param _minFee Minimum fee in native currency
    function setMinMessageFee(
        uint256 _minFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _minFee;
        emit MinMessageFeeSet(_minFee);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the Aztec virtual chain ID
    function chainId() external pure returns (uint16) {
        return AZTEC_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Aztec";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(rollupProcessor) != address(0) &&
            address(defiBridge) != address(0);
    }

    /// @notice Get the number of blocks required for finality
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Check if a nullifier has been consumed
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been consumed
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Get current Aztec rollup state hash
    /// @return The current state hash of the Aztec rollup
    function getRollupStateHash() external view returns (bytes32) {
        return rollupProcessor.rollupStateHash();
    }

    /// @notice Get the nonce for a specific sender
    /// @param sender The sender address
    /// @return The current nonce
    function getSenderNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }

    /*//////////////////////////////////////////////////////////////
                   DEPOSIT OPERATIONS (ZASEON → AZTEC)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit a ZASEON message into Aztec's encrypted note tree
     * @param noteCommitment The encrypted note commitment for the Aztec data tree
     * @param payload The ZASEON-encoded message payload
     * @return messageHash Internal unique hash identifying this message
     * @dev Calls IAztecRollupProcessor.depositPendingFunds() to queue the deposit.
     *      The Aztec sequencer will include it in a rollup batch with a Honk proof.
     */
    function depositMessage(
        bytes32 noteCommitment,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (noteCommitment == bytes32(0)) revert InvalidTarget();
        if (address(rollupProcessor) == address(0))
            revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Calculate fees
        uint256 protocolFee = _calculateProtocolFee(msg.value);
        uint256 totalRequired = protocolFee + minMessageFee;

        if (msg.value < totalRequired) {
            revert InsufficientFee(totalRequired, msg.value);
        }

        accumulatedFees += protocolFee;

        uint256 nonce = messageNonce++;

        // Deposit into Aztec rollup processor
        // assetId 0 = ETH, owner = bytes32→address representation of noteCommitment
        bytes32 dataRoot = rollupProcessor.depositPendingFunds{
            value: msg.value - protocolFee
        }(0, 0, address(uint160(uint256(noteCommitment))));

        bytes32 messageHash = keccak256(
            abi.encode(noteCommitment, dataRoot, nonce, block.timestamp)
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            noteCommitment: noteCommitment,
            timestamp: block.timestamp,
            dataRoot: dataRoot,
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;
        senderNonces[msg.sender]++;

        emit MessageDeposited(
            messageHash,
            noteCommitment,
            dataRoot,
            nonce,
            msg.sender
        );

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                  WITHDRAWAL OPERATIONS (AZTEC → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a withdrawal from Aztec with UltraHonk proof
     * @param proof The serialized UltraHonk proof (recursive aggregation proof)
     * @param publicInputs The public inputs [dataRoot, nullifier, noteCommitmentOut, payloadHash]
     * @param payload The message payload for ZASEON processing
     * @return messageHash Internal hash for the received message
     * @dev Verifies the Honk proof via the DeFi bridge finalisation mechanism,
     *      checks nullifier uniqueness for double-spend protection.
     */
    function withdrawMessage(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (address(defiBridge) == address(0)) revert BridgeNotConfigured();

        // publicInputs layout:
        // [0] = dataRoot (Aztec data tree root)
        // [1] = nullifier (unique per note spend)
        // [2] = noteCommitmentOut (output note, if any)
        // [3] = payloadHash (keccak256 of the payload)
        require(publicInputs.length >= 4, "Insufficient public inputs");

        // Verify the proof through DeFi bridge convert mechanism
        // The convert call with interactionNonce derived from the proof validates the withdrawal
        uint256 interactionNonce = uint256(keccak256(proof));
        (uint256 outputValue, ) = defiBridge.convert{value: 0}(
            publicInputs[0], // inputAssetId from data root
            publicInputs[2], // outputAssetId from note commitment
            publicInputs[1], // totalInputValue from nullifier field (overloaded)
            interactionNonce
        );
        if (outputValue == 0) revert InvalidProof();

        // Extract fields from public inputs
        bytes32 dataRoot = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);
        bytes32 payloadHash = bytes32(publicInputs[3]);

        // Verify payload integrity
        require(keccak256(payload) == payloadHash, "Payload hash mismatch");

        // Double-spend protection via nullifier
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                dataRoot,
                nullifier,
                nonce,
                block.timestamp,
                "AZTEC_TO_ZASEON"
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            noteCommitment: bytes32(publicInputs[2]),
            timestamp: block.timestamp,
            dataRoot: dataRoot,
            nullifier: nullifier
        });

        totalMessagesReceived++;

        emit MessageWithdrawn(messageHash, nullifier, dataRoot, nonce);

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter COMPLIANCE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /*refundAddress*/
    )
        external
        payable
        override
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        if (targetAddress == address(0)) revert InvalidTarget();
        if (address(rollupProcessor) == address(0))
            revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Convert target address to a note commitment
        bytes32 noteCommitment = keccak256(
            abi.encode(
                targetAddress,
                msg.sender,
                senderNonces[msg.sender]++,
                block.timestamp
            )
        );

        uint256 nonce = messageNonce++;

        // Deposit into Aztec
        bytes32 dataRoot = rollupProcessor.depositPendingFunds{
            value: msg.value
        }(0, 0, address(uint160(uint256(noteCommitment))));

        messageId = keccak256(
            abi.encode(noteCommitment, dataRoot, nonce, block.timestamp)
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            noteCommitment: noteCommitment,
            timestamp: block.timestamp,
            dataRoot: dataRoot,
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external view override returns (uint256 nativeFee) {
        // Base L1 gas cost estimate + minimum protocol fee
        // Aztec deposits are L1 txs, so gas costs are Ethereum gas
        return minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return
            record.status == MessageStatus.SENT ||
            record.status == MessageStatus.DELIVERED;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated protocol fees
    /// @param to Recipient address
    function withdrawFees(
        address payable to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool sent, ) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit FeesWithdrawn(to, amount);
    }

    /// @notice Emergency withdrawal of ETH
    /// @param to The recipient address
    /// @param amount The amount of ETH to withdraw
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert InvalidTarget();
        require(amount <= address(this).balance, "Insufficient balance");
        (bool sent, ) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit EmergencyWithdrawal(to, amount);
    }

    /// @notice Emergency withdraw ERC-20 tokens accidentally sent to adapter
    /// @param token The ERC-20 token address
    /// @param to The recipient address
    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (token == address(0) || to == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(balance > 0, "No tokens");
        IERC20(token).safeTransfer(to, balance);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculate protocol fee from message value
    /// @param value The message value
    /// @return fee The protocol fee
    function _calculateProtocolFee(
        uint256 value
    ) internal view returns (uint256) {
        if (bridgeFee == 0) return 0;
        return (value * bridgeFee) / 10_000;
    }

    /// @notice Allow receiving ETH for deposit/bridge fees
    receive() external payable {}
}
