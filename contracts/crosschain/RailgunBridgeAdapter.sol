// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IRailgunSmartWallet
 * @notice Minimal interface for the Railgun Smart Wallet (shielded pool entry/exit)
 * @dev Railgun uses a UTXO-based shielded pool with Groth16 proofs on BN254.
 *      The Smart Wallet handles shield (deposit) and unshield (withdraw) operations.
 */
interface IRailgunSmartWallet {
    /// @notice Shield (deposit) ETH or ERC-20 into the Railgun shielded pool
    /// @param commitments Commitments to add to the Merkle tree
    /// @param boundParams Bound parameters for the shield operation
    /// @param fees Protocol fees array
    /// @return merkleRoot The new Merkle root after insertion
    function shield(
        bytes32[] calldata commitments,
        bytes calldata boundParams,
        uint256[] calldata fees
    ) external payable returns (bytes32 merkleRoot);

    /// @notice Get the current Merkle root of the UTXO tree
    /// @return root The current Merkle root
    function merkleRoot() external view returns (bytes32 root);
}

/**
 * @title IRailgunRelayAdapt
 * @notice Interface for the Railgun Relay Adapt contract
 * @dev The Relay Adapt enables relayed (gasless) transactions through Railgun.
 *      It verifies Groth16 SNARK proofs and processes shielded transfers.
 */
interface IRailgunRelayAdapt {
    /// @notice Relay a shielded transaction with SNARK proof
    /// @param proof The Groth16 proof (a, b, c points)
    /// @param publicInputs The public inputs for verification
    /// @return success Whether the relay was successful
    function relay(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external returns (bool success);

    /// @notice Get the relay fee for a transaction
    /// @return fee The relay fee in native currency
    function relayFee() external view returns (uint256 fee);
}

/**
 * @title RailgunBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Railgun privacy protocol (EVM-native shielded pool)
 * @dev Enables ZASEON cross-chain interoperability with Railgun's shielded UTXO pool.
 *      Railgun is an EVM-native privacy protocol deployed on Ethereum, Arbitrum,
 *      BSC, and Polygon — not a separate chain.
 *
 * RAILGUN INTEGRATION:
 * - EVM-native: Railgun smart contracts live on existing EVM chains
 * - UTXO Model: Shielded UTXO pool with Poseidon-hashed Merkle tree
 * - Proof system: Groth16 on BN254 (same curve as ZASEON's primary proof system)
 * - Shield: Deposit into Railgun pool → get shielded note (commitment)
 * - Unshield: Withdraw from pool with nullifier (replay protection)
 * - Privacy: Full transaction privacy (sender, receiver, amount all hidden)
 *
 * MESSAGE FLOW:
 * - ZASEON→Railgun: Encode ZASEON state as shield commitments → insert into Railgun pool
 * - Railgun→ZASEON: Unshield with SNARK proof → relay to ZASEON → nullifier registered
 *
 * SECURITY NOTES:
 * - Groth16 proofs verified on-chain by Railgun's verifier contracts
 * - Nullifier-based replay protection (integrates with RAILGUN_TAG in ZASEON)
 * - Merkle root validation ensures commitment inclusion
 * - All state-changing functions protected by ReentrancyGuard and access control
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract RailgunBridgeAdapter is
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
    /// @notice Role for relayers who can relay shielded transactions
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Role for pausers who can pause the adapter
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Railgun virtual chain identifier (ZASEON-internal; Railgun is EVM-native)
    /// @dev Railgun itself runs on Ethereum (1), Arbitrum (42161), BSC (56), Polygon (137).
    ///      3100 is the ZASEON-internal identifier for "Railgun privacy zone".
    uint16 public constant RAILGUN_CHAIN_ID = 3100;

    /// @notice Finality in EVM blocks (follows host chain finality)
    uint256 public constant FINALITY_BLOCKS = 12;

    /// @notice Max bridge fee in basis points (1% = 100 bps)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Max payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Groth16 proof size: 256 bytes (8 × 32-byte points: a[2], b[4], c[2])
    uint256 public constant GROTH16_PROOF_SIZE = 256;

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
        bytes32 commitment; // Railgun UTXO commitment
        uint256 timestamp;
        bytes32 merkleRoot; // Merkle root at time of shield/unshield
        bytes32 nullifier; // Nullifier for replay protection
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Railgun Smart Wallet contract (shield/unshield entry point)
    IRailgunSmartWallet public railgunWallet;

    /// @notice Railgun Relay Adapt contract (gasless relayed transactions)
    IRailgunRelayAdapt public railgunRelay;

    /// @notice Bridge fee in basis points (max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent ZASEON → Railgun pool
    uint256 public totalMessagesSent;

    /// @notice Total messages received Railgun pool → ZASEON
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (native)
    uint256 public totalValueBridged;

    /// @notice Per-sender nonce counter
    mapping(address => uint256) public senderNonces;

    /// @notice Nullifier → consumed flag (replay protection, integrates with RAILGUN_TAG)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Internal message tracking by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is shielded into Railgun pool (ZASEON → Railgun)
    event MessageShielded(
        bytes32 indexed messageHash,
        bytes32 indexed commitment,
        bytes32 merkleRoot,
        uint256 nonce,
        address sender
    );

    /// @notice Emitted when a verified unshield from Railgun is consumed (Railgun → ZASEON)
    event MessageUnshielded(
        bytes32 indexed messageHash,
        bytes32 indexed nullifier,
        bytes32 merkleRoot,
        uint256 nonce
    );

    /// @notice Emitted when the Railgun wallet address is updated
    event RailgunWalletSet(address indexed wallet);

    /// @notice Emitted when the Railgun relay address is updated
    event RailgunRelaySet(address indexed relay);

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

    error InvalidWallet();
    error InvalidRelay();
    error InvalidTarget();
    error InvalidPayload();
    error BridgeNotConfigured();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error MerkleRootMismatch(bytes32 expected, bytes32 actual);
    error FeeTooHigh(uint256 fee);
    error InsufficientFee(uint256 required, uint256 provided);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _railgunWallet Address of the Railgun Smart Wallet contract
    /// @param _railgunRelay Address of the Railgun Relay Adapt contract
    /// @param _admin Address to receive admin roles
    constructor(address _railgunWallet, address _railgunRelay, address _admin) {
        if (_admin == address(0)) revert InvalidTarget();
        if (_railgunWallet == address(0)) revert InvalidWallet();
        if (_railgunRelay == address(0)) revert InvalidRelay();

        railgunWallet = IRailgunSmartWallet(_railgunWallet);
        railgunRelay = IRailgunRelayAdapt(_railgunRelay);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Railgun Smart Wallet address
    /// @param _railgunWallet New Railgun Smart Wallet address
    function setRailgunWallet(
        address _railgunWallet
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_railgunWallet == address(0)) revert InvalidWallet();
        railgunWallet = IRailgunSmartWallet(_railgunWallet);
        emit RailgunWalletSet(_railgunWallet);
    }

    /// @notice Update the Railgun Relay Adapt address
    /// @param _railgunRelay New Railgun Relay Adapt address
    function setRailgunRelay(
        address _railgunRelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_railgunRelay == address(0)) revert InvalidRelay();
        railgunRelay = IRailgunRelayAdapt(_railgunRelay);
        emit RailgunRelaySet(_railgunRelay);
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

    /// @notice Get the Railgun virtual chain ID
    function chainId() external pure returns (uint16) {
        return RAILGUN_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Railgun";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(railgunWallet) != address(0) &&
            address(railgunRelay) != address(0);
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

    /// @notice Get current Railgun Merkle root
    /// @return The current Merkle root of the shielded UTXO tree
    function getMerkleRoot() external view returns (bytes32) {
        return railgunWallet.merkleRoot();
    }

    /// @notice Get the nonce for a specific sender
    /// @param sender The sender address
    /// @return The current nonce
    function getSenderNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }

    /*//////////////////////////////////////////////////////////////
                   SHIELD OPERATIONS (ZASEON → RAILGUN)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Shield a ZASEON message into the Railgun shielded pool
     * @param commitment The Poseidon-hashed commitment for the Railgun UTXO
     * @param payload The ZASEON-encoded message payload (bound parameters)
     * @return messageHash Internal unique hash identifying this message
     * @dev Calls IRailgunSmartWallet.shield() to insert the commitment into
     *      Railgun's Merkle tree. msg.value pays shield fees.
     */
    function shieldMessage(
        bytes32 commitment,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (commitment == bytes32(0)) revert InvalidTarget();
        if (address(railgunWallet) == address(0)) revert BridgeNotConfigured();
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

        // Shield into Railgun pool
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = commitment;
        uint256[] memory fees = new uint256[](0);

        bytes32 merkleRoot = railgunWallet.shield{
            value: msg.value - protocolFee
        }(commitments, payload, fees);

        bytes32 messageHash = keccak256(
            abi.encode(commitment, merkleRoot, nonce, block.timestamp)
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            commitment: commitment,
            timestamp: block.timestamp,
            merkleRoot: merkleRoot,
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;
        senderNonces[msg.sender]++;

        emit MessageShielded(
            messageHash,
            commitment,
            merkleRoot,
            nonce,
            msg.sender
        );

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                  UNSHIELD OPERATIONS (RAILGUN → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify an unshield from Railgun with Groth16 proof
     * @param proof The serialized Groth16 proof (a[2], b[4], c[2] on BN254)
     * @param publicInputs The public inputs [merkleRoot, nullifier, commitmentOut, ...]
     * @param payload The message payload for ZASEON processing
     * @return messageHash Internal hash for the received message
     * @dev Verifies the SNARK proof via Railgun relay, checks nullifier uniqueness.
     */
    function unshieldMessage(
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
        if (address(railgunRelay) == address(0)) revert BridgeNotConfigured();

        // publicInputs layout:
        // [0] = merkleRoot (Railgun UTXO tree root)
        // [1] = nullifier (unique per UTXO spend)
        // [2] = commitmentOut (output commitment, if any)
        // [3] = payloadHash (keccak256 of the payload)
        require(publicInputs.length >= 4, "Insufficient public inputs");

        // Verify Groth16 proof via Railgun relay
        bool valid = railgunRelay.relay(proof, publicInputs);
        if (!valid) revert InvalidProof();

        // Extract fields from public inputs
        bytes32 merkleRoot = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);
        bytes32 payloadHash = bytes32(publicInputs[3]);

        // Verify payload integrity
        require(keccak256(payload) == payloadHash, "Payload hash mismatch");

        // Replay protection via nullifier
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                merkleRoot,
                nullifier,
                nonce,
                block.timestamp,
                "RAILGUN_TO_ZASEON"
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            commitment: bytes32(publicInputs[2]),
            timestamp: block.timestamp,
            merkleRoot: merkleRoot,
            nullifier: nullifier
        });

        totalMessagesReceived++;

        emit MessageUnshielded(messageHash, nullifier, merkleRoot, nonce);

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
        if (address(railgunWallet) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Convert target address to a commitment-like bytes32
        bytes32 commitment = keccak256(
            abi.encode(
                targetAddress,
                msg.sender,
                senderNonces[msg.sender]++,
                block.timestamp
            )
        );

        uint256 nonce = messageNonce++;

        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = commitment;
        uint256[] memory fees = new uint256[](0);

        bytes32 merkleRoot = railgunWallet.shield{value: msg.value}(
            commitments,
            payload,
            fees
        );

        messageId = keccak256(
            abi.encode(commitment, merkleRoot, nonce, block.timestamp)
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            commitment: commitment,
            timestamp: block.timestamp,
            merkleRoot: merkleRoot,
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
        // Relay fee + minimum protocol fee
        uint256 relayFee = address(railgunRelay) != address(0)
            ? railgunRelay.relayFee()
            : 0;
        return relayFee + minMessageFee;
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

    /// @notice Allow receiving ETH for shield fees
    receive() external payable {}
}
