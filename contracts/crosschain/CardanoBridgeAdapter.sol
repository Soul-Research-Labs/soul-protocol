// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IWormholeCoreCardano
 * @notice Minimal interface for the Wormhole Core contract (Cardano bridge)
 * @dev Identical to the Wormhole Core interface used by SolanaBridgeAdapter.
 *      Separated to avoid interface collision when both adapters coexist.
 */
interface IWormholeCoreCardano {
    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    function parseAndVerifyVM(
        bytes calldata encodedVM
    )
        external
        view
        returns (
            IWormholeStructsCardano.VM memory vm,
            bool valid,
            string memory reason
        );

    function messageFee() external view returns (uint256 fee);
}

/**
 * @title IWormholeStructsCardano
 * @notice Structs used by the Wormhole Core contract
 */
interface IWormholeStructsCardano {
    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        Signature[] signatures;
        bytes32 hash;
    }

    struct Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint8 guardianIndex;
    }
}

/**
 * @title IWormholeTokenBridgeCardano
 * @notice Minimal interface for the Wormhole Token Bridge (Cardano bridge)
 */
interface IWormholeTokenBridgeCardano {
    function transferTokens(
        address token,
        uint256 amount,
        uint16 recipientChain,
        bytes32 recipient,
        uint256 arbiterFee,
        uint32 nonce
    ) external payable returns (uint64 sequence);

    function completeTransfer(bytes memory encodedVM) external;
}

/**
 * @title CardanoBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Cardano integration via Wormhole
 * @dev Enables ZASEON cross-chain interoperability with Cardano via the
 *      Wormhole guardian network. This contract is deployed on EVM (Ethereum/L2)
 *      and communicates with the ZASEON Cardano validator (Plutus script) via Wormhole VAAs.
 *
 * CARDANO INTEGRATION:
 * - Plutus VM — UTXO-based smart contract model (not account-based)
 * - Bridge protocol: Wormhole (19-guardian network)
 * - EVM→Cardano: publishMessage on WormholeCore → guardians sign → relayed to Cardano
 * - Cardano→EVM: Plutus script publishes message → guardians sign → receiveVAA on this contract
 * - Addresses are bech32-encoded (blake2b-224 hash of verification key, stored as 28-byte hash, padded to bytes32)
 * - ZK proof verification on Cardano via Plutus V3 + alt_bn128 built-ins (Groth16 compatible)
 * - UTXO references: encoded as (tx_hash, output_index) in payload
 *
 * SECURITY NOTES:
 * - VAAs are signed by a supermajority (13/19) of Wormhole guardians
 * - VAA replay protection: each VAA hash is tracked and can only be consumed once
 * - Validator whitelisting: only known Cardano Plutus scripts can send messages to this adapter
 * - Emitter chain + emitter address validation on all received VAAs
 * - All state-changing functions protected by ReentrancyGuard and access control
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract CardanoBridgeAdapter is
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
    /// @notice Role for relayers who can relay cross-chain messages
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Role for pausers who can pause the adapter
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Wormhole chain ID for Cardano
    /// @dev Assigned by Wormhole governance. Cardano mainnet = 15.
    uint16 public constant CARDANO_WORMHOLE_CHAIN_ID = 15;

    /// @notice Finality blocks (Wormhole guardian finality for Cardano ~20 blocks, ~400s)
    uint256 public constant FINALITY_BLOCKS = 20;

    /// @notice Max bridge fee in basis points (1% = 100 bps)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Max payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Wormhole consistency level: finalized
    /// @dev 200 = fully finalized (Cardano: transaction is final after ~20 blocks)
    uint8 public constant CONSISTENCY_LEVEL_FINALIZED = 200;

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
        bytes32 cardanoTarget; // 32-byte Cardano validator script hash (padded)
        uint256 timestamp;
        uint64 sequence; // Wormhole sequence number
        bytes32 vaaHash;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Wormhole Core contract on L1/L2
    IWormholeCoreCardano public wormholeCore;

    /// @notice Wormhole Token Bridge contract
    IWormholeTokenBridgeCardano public wormholeTokenBridge;

    /// @notice ZASEON Plutus validator script hash on Cardano (28-byte blake2b-224 hash, right-padded to bytes32)
    bytes32 public zaseonCardanoValidator;

    /// @notice Bridge fee in basis points (max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent EVM → Cardano
    uint256 public totalMessagesSent;

    /// @notice Total messages received Cardano → EVM
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (native)
    uint256 public totalValueBridged;

    /// @notice Per-sender nonce counter for ordering
    mapping(address => uint256) public senderNonces;

    /// @notice VAA hash → consumed flag (replay protection)
    mapping(bytes32 => bool) public usedVAAHashes;

    /// @notice Whitelisted Cardano Plutus script hashes that can send messages to this adapter
    mapping(bytes32 => bool) public whitelistedValidators;

    /// @notice Internal message tracking by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is published to Wormhole (EVM → Cardano)
    event MessageSentToCardano(
        bytes32 indexed messageHash,
        bytes32 indexed cardanoTarget,
        uint64 sequence,
        uint256 nonce,
        address sender
    );

    /// @notice Emitted when a VAA from Cardano is consumed (Cardano → EVM)
    event MessageReceivedFromCardano(
        bytes32 indexed messageHash,
        bytes32 indexed emitterAddress,
        uint64 sequence,
        bytes32 vaaHash
    );

    /// @notice Emitted when the Wormhole Core address is updated
    event WormholeCoreSet(address indexed wormholeCore);

    /// @notice Emitted when the Wormhole Token Bridge address is updated
    event WormholeTokenBridgeSet(address indexed tokenBridge);

    /// @notice Emitted when the ZASEON Cardano validator address is updated
    event ZaseonCardanoValidatorSet(bytes32 indexed validatorHash);

    /// @notice Emitted when the bridge fee is updated
    event BridgeFeeSet(uint256 feeBps);

    /// @notice Emitted when the minimum message fee is updated
    event MinMessageFeeSet(uint256 fee);

    /// @notice Emitted when a Cardano validator is added/removed from whitelist
    event ValidatorWhitelistUpdated(
        bytes32 indexed validatorHash,
        bool whitelisted
    );

    /// @notice Emitted on emergency ETH withdrawal
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidWormholeCore();
    error InvalidTokenBridge();
    error InvalidCardanoValidator();
    error InvalidTarget();
    error InvalidPayload();
    error BridgeNotConfigured();
    error VAAAlreadyConsumed(bytes32 vaaHash);
    error InvalidVAA(string reason);
    error UnauthorizedEmitter(uint16 chainId, bytes32 emitterAddress);
    error ValidatorNotWhitelisted(bytes32 validatorHash);
    error FeeTooHigh(uint256 fee);
    error InsufficientFee(uint256 required, uint256 provided);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _wormholeCore Address of the Wormhole Core contract
    /// @param _wormholeTokenBridge Address of the Wormhole Token Bridge
    /// @param _admin Address to receive admin roles
    constructor(
        address _wormholeCore,
        address _wormholeTokenBridge,
        address _admin
    ) {
        if (_admin == address(0)) revert InvalidTarget();
        if (_wormholeCore == address(0)) revert InvalidWormholeCore();
        if (_wormholeTokenBridge == address(0)) revert InvalidTokenBridge();

        wormholeCore = IWormholeCoreCardano(_wormholeCore);
        wormholeTokenBridge = IWormholeTokenBridgeCardano(_wormholeTokenBridge);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Wormhole Core contract address
    /// @param _wormholeCore New Wormhole Core contract address
    function setWormholeCore(
        address _wormholeCore
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_wormholeCore == address(0)) revert InvalidWormholeCore();
        wormholeCore = IWormholeCoreCardano(_wormholeCore);
        emit WormholeCoreSet(_wormholeCore);
    }

    /// @notice Update the Wormhole Token Bridge address
    /// @param _tokenBridge New Token Bridge contract address
    function setWormholeTokenBridge(
        address _tokenBridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_tokenBridge == address(0)) revert InvalidTokenBridge();
        wormholeTokenBridge = IWormholeTokenBridgeCardano(_tokenBridge);
        emit WormholeTokenBridgeSet(_tokenBridge);
    }

    /// @notice Set the ZASEON Cardano validator (Plutus script hash)
    /// @param _validatorHash 28-byte blake2b-224 Cardano script hash, right-padded to bytes32
    function setZaseonCardanoValidator(
        bytes32 _validatorHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_validatorHash == bytes32(0)) revert InvalidCardanoValidator();
        zaseonCardanoValidator = _validatorHash;
        emit ZaseonCardanoValidatorSet(_validatorHash);
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

    /// @notice Add or remove a Cardano validator from the whitelist
    /// @param _validatorHash 28-byte blake2b-224 Cardano script hash, right-padded to bytes32
    /// @param _whitelisted Whether to whitelist the validator
    function setWhitelistedValidator(
        bytes32 _validatorHash,
        bool _whitelisted
    ) external onlyRole(OPERATOR_ROLE) {
        whitelistedValidators[_validatorHash] = _whitelisted;
        emit ValidatorWhitelistUpdated(_validatorHash, _whitelisted);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the Wormhole chain ID for Cardano
    function chainId() external pure returns (uint16) {
        return CARDANO_WORMHOLE_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Cardano";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(wormholeCore) != address(0) &&
            address(wormholeTokenBridge) != address(0) &&
            zaseonCardanoValidator != bytes32(0);
    }

    /// @notice Get the number of blocks required for finality
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Check if a VAA hash has been consumed
    /// @param vaaHash The VAA hash to check
    /// @return True if the VAA has been consumed
    function isVAAUsed(bytes32 vaaHash) external view returns (bool) {
        return usedVAAHashes[vaaHash];
    }

    /// @notice Check if a Cardano validator is whitelisted
    /// @param validatorHash The 32-byte Cardano validator script hash
    /// @return True if the validator is whitelisted
    function isValidatorWhitelisted(
        bytes32 validatorHash
    ) external view returns (bool) {
        return whitelistedValidators[validatorHash];
    }

    /// @notice Get the nonce for a specific sender
    /// @param sender The sender address
    /// @return The current nonce
    function getSenderNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }

    /*//////////////////////////////////////////////////////////////
                     MESSAGE OPERATIONS (EVM → CARDANO)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a ZASEON message to Cardano via Wormhole
     * @param cardanoTarget The 32-byte Cardano validator/address hash to receive the message
     * @param payload The ZASEON-encoded message payload
     * @return messageHash Internal unique hash identifying this message
     * @dev Publishes a message via WormholeCore.publishMessage().
     *      msg.value pays the Wormhole message fee + optional protocol fee.
     */
    function sendMessage(
        bytes32 cardanoTarget,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (cardanoTarget == bytes32(0)) revert InvalidTarget();
        if (address(wormholeCore) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Calculate fees
        uint256 wormholeFee = wormholeCore.messageFee();
        uint256 protocolFee = _calculateProtocolFee(msg.value);
        uint256 totalRequired = wormholeFee + protocolFee + minMessageFee;

        if (msg.value < totalRequired) {
            revert InsufficientFee(totalRequired, msg.value);
        }

        accumulatedFees += protocolFee;

        // Encode ZASEON payload with metadata
        bytes memory zaseonPayload = abi.encode(
            cardanoTarget,
            msg.sender,
            senderNonces[msg.sender]++,
            block.timestamp,
            payload
        );

        uint256 nonce = messageNonce++;

        // Publish message to Wormhole
        uint64 sequence = wormholeCore.publishMessage{value: wormholeFee}(
            uint32(nonce),
            zaseonPayload,
            CONSISTENCY_LEVEL_FINALIZED
        );

        bytes32 messageHash = keccak256(
            abi.encode(cardanoTarget, sequence, nonce, block.timestamp)
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            cardanoTarget: cardanoTarget,
            timestamp: block.timestamp,
            sequence: sequence,
            vaaHash: bytes32(0) // No VAA hash for outgoing messages
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSentToCardano(
            messageHash,
            cardanoTarget,
            sequence,
            nonce,
            msg.sender
        );

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                   MESSAGE OPERATIONS (CARDANO → EVM)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a VAA from Cardano via Wormhole
     * @param encodedVAA The encoded Verified Action Approval from Wormhole guardians
     * @return messageHash Internal hash for the received message
     * @dev Parses and verifies the VAA, checks emitter chain/address,
     *      marks the VAA hash as consumed (replay protection).
     */
    function receiveVAA(
        bytes calldata encodedVAA
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (address(wormholeCore) == address(0)) revert BridgeNotConfigured();

        // Parse and verify the VAA via Wormhole Core
        (
            IWormholeStructsCardano.VM memory vm,
            bool valid,
            string memory reason
        ) = wormholeCore.parseAndVerifyVM(encodedVAA);

        if (!valid) revert InvalidVAA(reason);

        // Replay protection — each VAA can only be consumed once
        bytes32 vaaHash = vm.hash;
        if (usedVAAHashes[vaaHash]) revert VAAAlreadyConsumed(vaaHash);
        usedVAAHashes[vaaHash] = true;

        // Validate emitter chain is Cardano
        if (vm.emitterChainId != CARDANO_WORMHOLE_CHAIN_ID) {
            revert UnauthorizedEmitter(vm.emitterChainId, vm.emitterAddress);
        }

        // Validate emitter is a whitelisted Cardano validator
        if (!whitelistedValidators[vm.emitterAddress]) {
            // If zaseonCardanoValidator is set, allow it even if not explicitly whitelisted
            if (vm.emitterAddress != zaseonCardanoValidator) {
                revert ValidatorNotWhitelisted(vm.emitterAddress);
            }
        }

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                vm.emitterAddress,
                vm.sequence,
                nonce,
                block.timestamp,
                "CARDANO_TO_EVM"
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            cardanoTarget: vm.emitterAddress,
            timestamp: block.timestamp,
            sequence: vm.sequence,
            vaaHash: vaaHash
        });

        totalMessagesReceived++;

        emit MessageReceivedFromCardano(
            messageHash,
            vm.emitterAddress,
            vm.sequence,
            vaaHash
        );

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
        if (address(wormholeCore) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Calculate fees
        uint256 wormholeFee = wormholeCore.messageFee();

        // Encode ZASEON payload: target is either the configured Cardano validator
        // or the EVM address converted to bytes32, bridged via Wormhole
        bytes32 target = zaseonCardanoValidator != bytes32(0)
            ? zaseonCardanoValidator
            : bytes32(uint256(uint160(targetAddress)));

        bytes memory zaseonPayload = abi.encode(
            target,
            msg.sender,
            senderNonces[msg.sender]++,
            block.timestamp,
            payload
        );

        uint256 nonce = messageNonce++;

        uint64 sequence = wormholeCore.publishMessage{value: wormholeFee}(
            uint32(nonce),
            zaseonPayload,
            CONSISTENCY_LEVEL_FINALIZED
        );

        messageId = keccak256(
            abi.encode(target, sequence, nonce, block.timestamp)
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            cardanoTarget: target,
            timestamp: block.timestamp,
            sequence: sequence,
            vaaHash: bytes32(0)
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
        // Wormhole message fee + minimum protocol fee
        uint256 wormholeFee = address(wormholeCore) != address(0)
            ? wormholeCore.messageFee()
            : 0;
        return wormholeFee + minMessageFee;
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

    /// @notice Allow receiving ETH for Wormhole message fees
    receive() external payable {}
}
