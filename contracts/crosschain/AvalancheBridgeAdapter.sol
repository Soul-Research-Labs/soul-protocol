// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAvalancheBridge
 * @notice Minimal interface for the Avalanche–Ethereum bridge
 * @dev Avalanche is a PoS L1 using the Snowball/Avalanche consensus family.
 *      The C-Chain is EVM-compatible. Cross-chain communication uses
 *      Avalanche Warp Messaging (AWM) for subnet-to-subnet and Teleporter
 *      for higher-level message passing. The bridge supports the EVM C-Chain
 *      and can relay messages via BLS multi-sig attestations.
 */
interface IAvalancheBridge {
    /// @notice Relay a message to Avalanche C-Chain
    /// @param destinationChainId The Avalanche chain/subnet ID
    /// @param payload The bridge payload
    /// @return messageId Unique message identifier
    function relayMessage(
        bytes32 destinationChainId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Estimate the relay fee
    /// @return fee The estimated relay fee in wei
    function estimateRelayFee() external view returns (uint256 fee);

    /// @notice Get the latest verified Avalanche block height
    /// @return height The latest verified block height
    function latestVerifiedHeight() external view returns (uint256 height);
}

/**
 * @title IAvalancheWarpVerifier
 * @notice Interface for verifying Avalanche Warp Messages (AWM) on Ethereum
 * @dev AWM uses BLS aggregate signatures from Avalanche validators.
 *      The verifier checks the BLS multi-sig against the known validator set.
 */
interface IAvalancheWarpVerifier {
    /// @notice Verify an Avalanche Warp Message signature
    /// @param proof The BLS aggregate signature proof
    /// @param publicInputs The public inputs (source chain, message hash, etc.)
    /// @return valid Whether the warp message is valid
    function verifyWarpMessage(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    /// @notice Get the current validator set hash
    /// @return validatorSetHash The hash of the current validator set
    function currentValidatorSetHash()
        external
        view
        returns (bytes32 validatorSetHash);
}

/**
 * @title AvalancheBridgeAdapter
 * @notice ZASEON bridge adapter for Avalanche — PoS L1 with Snowball consensus
 * @dev Avalanche uses:
 *      - Snowball/Avalanche consensus family (sub-second finality)
 *      - C-Chain: EVM-compatible execution layer
 *      - P-Chain: Platform chain for staking & subnets
 *      - X-Chain: Exchange chain for asset transfers (DAG)
 *      - Avalanche Warp Messaging (AWM) for subnet interop
 *      - Teleporter for high-level cross-chain messaging
 *      - BLS multi-sig validator attestations
 *
 *      This adapter bridges ZASEON ↔ Avalanche C-Chain messages using
 *      AWM + BLS verification for trustless cross-chain proofs.
 */
contract AvalancheBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON internal virtual chain ID for Avalanche
    uint16 public constant AVALANCHE_CHAIN_ID = 11_100;

    /// @notice Avalanche sub-second finality (~2 seconds)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Minimum proof size for AWM BLS proofs
    uint256 public constant MIN_PROOF_SIZE = 48;

    /// @notice Maximum protocol fee (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length to prevent DoS
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Avalanche C-Chain ID
    bytes32 public constant CCHAIN_ID =
        0x0000000000000000000000000000000000000000000000000000000000043114;

    /*//////////////////////////////////////////////////////////////
                             STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Avalanche bridge relay contract
    IAvalancheBridge public avalancheBridge;

    /// @notice AWM warp message verifier
    IAvalancheWarpVerifier public warpVerifier;

    /// @notice Verified validator set hashes
    mapping(bytes32 => bool) public verifiedValidatorSets;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message hash → verified
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Sender nonces for ordering
    mapping(address => uint256) public senderNonces;

    /// @notice Protocol fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum fee per message
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (wei)
    uint256 public totalValueBridged;

    /*//////////////////////////////////////////////////////////////
                             EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 destinationChainId,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 validatorSetHash,
        bytes32 indexed nullifier,
        bytes payload
    );

    event BridgeConfigUpdated(string param, address value);
    event ValidatorSetRegistered(bytes32 indexed validatorSetHash);
    event FeeUpdated(string param, uint256 value);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidValidatorSet();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy the Avalanche bridge adapter
    /// @param _avalancheBridge Address of the Avalanche bridge relay
    /// @param _warpVerifier Address of the AWM verifier
    /// @param _admin Default admin address
    constructor(
        address _avalancheBridge,
        address _warpVerifier,
        address _admin
    ) {
        if (_avalancheBridge == address(0)) revert InvalidBridge();
        if (_warpVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        avalancheBridge = IAvalancheBridge(_avalancheBridge);
        warpVerifier = IAvalancheWarpVerifier(_warpVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                   SEND (ZASEON → AVALANCHE)
    //////////////////////////////////////////////////////////////*/

    /// @notice Send a message to Avalanche C-Chain
    /// @param destinationChainId The target Avalanche chain/subnet ID
    /// @param payload The bridge payload
    /// @return messageHash The unique message identifier
    function sendMessage(
        bytes32 destinationChainId,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (destinationChainId == bytes32(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        uint256 relayFee = avalancheBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 relayId = avalancheBridge.relayMessage{
            value: msg.value - protocolFee
        }(destinationChainId, payload);

        messageHash = keccak256(
            abi.encodePacked(
                AVALANCHE_CHAIN_ID,
                msg.sender,
                destinationChainId,
                nonce,
                relayId
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            destinationChainId,
            msg.value
        );
    }

    /*//////////////////////////////////////////////////////////////
                 RECEIVE (AVALANCHE → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /// @notice Receive and verify an Avalanche Warp Message
    /// @param proof The BLS aggregate signature proof
    /// @param publicInputs Public inputs: [validatorSetHash, nullifier, sourceChain, payloadHash]
    /// @param payload The original payload
    /// @return messageHash The verified message identifier
    function receiveMessage(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (proof.length < MIN_PROOF_SIZE) revert InvalidProof();

        bool valid = warpVerifier.verifyWarpMessage(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 validatorSetHash = bytes32(publicInputs[0]);

        messageHash = keccak256(
            abi.encodePacked(
                AVALANCHE_CHAIN_ID,
                validatorSetHash,
                nullifier,
                keccak256(payload)
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, validatorSetHash, nullifier, payload);
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter INTERFACE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
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
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        uint256 relayFee = avalancheBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 transferId = avalancheBridge.relayMessage{
            value: msg.value - protocolFee
        }(CCHAIN_ID, payload);

        messageId = keccak256(
            abi.encodePacked(
                AVALANCHE_CHAIN_ID,
                msg.sender,
                CCHAIN_ID,
                nonce,
                transferId
            )
        );

        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, CCHAIN_ID, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        nativeFee = avalancheBridge.estimateRelayFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the ZASEON chain ID for Avalanche
    function chainId() external pure returns (uint16) {
        return AVALANCHE_CHAIN_ID;
    }

    /// @notice Get the chain name
    function chainName() external pure returns (string memory) {
        return "Avalanche";
    }

    /// @notice Check if the adapter is configured
    function isConfigured() external view returns (bool) {
        return
            address(avalancheBridge) != address(0) &&
            address(warpVerifier) != address(0);
    }

    /// @notice Get the finality block count
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the current validator set hash from verifier
    function getCurrentValidatorSetHash() external view returns (bytes32) {
        return warpVerifier.currentValidatorSetHash();
    }

    /// @notice Get the latest verified Avalanche block height
    function getLatestVerifiedHeight() external view returns (uint256) {
        return avalancheBridge.latestVerifiedHeight();
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Avalanche bridge relay address
    function setAvalancheBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        avalancheBridge = IAvalancheBridge(_bridge);
        emit BridgeConfigUpdated("avalancheBridge", _bridge);
    }

    /// @notice Update the AWM warp verifier address
    function setWarpVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        warpVerifier = IAvalancheWarpVerifier(_verifier);
        emit BridgeConfigUpdated("warpVerifier", _verifier);
    }

    /// @notice Register a verified validator set hash
    function registerValidatorSet(
        bytes32 _validatorSetHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_validatorSetHash == bytes32(0)) revert InvalidValidatorSet();
        verifiedValidatorSets[_validatorSetHash] = true;
        emit ValidatorSetRegistered(_validatorSetHash);
    }

    /// @notice Set the protocol fee in basis points
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        bridgeFee = _fee;
        emit FeeUpdated("bridgeFee", _fee);
    }

    /// @notice Set the minimum fee per message
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _fee;
        emit FeeUpdated("minMessageFee", _fee);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY & FEE WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(
        address payable _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = _to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ETH
    function emergencyWithdrawETH(
        address payable _to,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        (bool ok, ) = _to.call{value: _amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ERC-20 tokens
    function emergencyWithdrawERC20(
        address _token,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_token == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(_to, balance);
    }

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Accept ETH
    receive() external payable {}
}
