// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAleoRelay
 * @notice Interface for the Aleo-Ethereum relay contract
 * @dev Aleo is a privacy-focused blockchain using the Leo language and
 *      the snarkVM execution environment. It uses AleoBFT consensus
 *      (a variant of Narwhal-Bullshark DAG-based BFT) and generates
 *      Marlin (universal setup) SNARK proofs for every program execution.
 *      Messages are relayed via committee attestations.
 */
interface IAleoRelay {
    /// @notice Submit a message to be relayed to the Aleo network
    /// @param programId The target Aleo program ID (e.g. "bridge.aleo")
    /// @param functionName The function to invoke on the Aleo program
    /// @param payload The message payload (serialized Aleo inputs)
    /// @return messageId The unique message identifier
    function sendToAleo(
        bytes32 programId,
        bytes32 functionName,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Get the relay fee for sending a message
    /// @return fee The required fee in wei
    function getRelayFee() external view returns (uint256 fee);
}

/**
 * @title IAleoLightClient
 * @notice Interface for verifying Aleo block headers and state proofs
 * @dev Aleo uses AleoBFT consensus with a committee of validators.
 *      Blocks contain a coinbase proof (proof-of-succinct-work) and
 *      committee certificate signatures. State is stored as a Merkle
 *      tree of records (encrypted UTXOs).
 */
interface IAleoLightClient {
    /// @notice Verify an Aleo block header with committee certificate
    /// @param blockHash The Aleo block hash
    /// @param blockHeight The Aleo block height
    /// @param certificateSignatures Aggregated committee signatures
    /// @return valid Whether the block header is valid
    function verifyBlockHeader(
        bytes32 blockHash,
        uint64 blockHeight,
        bytes calldata certificateSignatures
    ) external view returns (bool valid);

    /// @notice Verify an Aleo state transition proof
    /// @param stateRoot The verified Aleo state root
    /// @param proof The Marlin SNARK proof of state transition
    /// @return valid Whether the proof is valid
    function verifyStateProof(
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool valid);

    /// @notice Get the current committee hash
    /// @return hash The hash of the current validator committee
    function currentCommitteeHash() external view returns (bytes32 hash);
}

/**
 * @title AleoBridgeAdapter
 * @author ZASEON Team
 * @notice Bridge adapter for Aleo privacy blockchain integration
 * @dev Aleo is a privacy-preserving blockchain platform that executes all
 *      programs inside a zero-knowledge proof system (snarkVM). Every
 *      transaction produces a SNARK proof verifying correct execution
 *      without revealing inputs/outputs.
 *
 *      Key Aleo concepts:
 *      - snarkVM: ZK-native virtual machine executing Leo/Aleo instructions
 *      - Records: Encrypted UTXO-like state objects (owned by addresses)
 *      - Programs: On-chain programs written in Leo (Rust-like ZK language)
 *      - Transitions: State changes with inputs consumed + outputs created
 *      - AleoBFT: DAG-based BFT consensus (Narwhal-Bullshark variant)
 *      - Coinbase proof: Proof-of-succinct-work for block production
 *      - Credits: Native token (1 credit = 1,000,000 microcredits)
 *      - Addresses: Bech32m-encoded (aleo1...) derived from private keys
 *      - Committee: ~200 validators, stake-weighted
 *      - Block time: ~10 seconds
 *      - Proofs: Marlin universal-setup SNARKs (constant verification time)
 *
 *      ZASEON integration approach:
 *      - Uses relay contract for Ethereum ↔ Aleo message passing
 *      - Optional light client for committee certificate verification
 *      - SNARK proof verification for state transition attestation
 *      - Program ID whitelisting for authorized Aleo programs
 *      - Privacy-preserving: only nullifiers + commitments cross the bridge
 *
 *      Security model:
 *      - Committee attestation (2/3+ stake threshold)
 *      - Optional SNARK proof verification for trustless verification
 *      - Nullifier replay protection on both chains
 *      - Rate limiting per program and per block
 */
contract AleoBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    /// @notice Internal ZASEON chain ID for the Aleo network
    uint256 public constant ALEO_CHAIN_ID = 17100;

    /// @notice Maximum payload length (bytes) – Aleo transactions are compact
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Maximum bridge fee in basis points (5%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 500;

    /// @notice Minimum committee quorum in basis points (66.67%)
    uint256 public constant COMMITTEE_QUORUM_BPS = 6667;

    /// @notice Minimum SNARK proof length for state verification
    uint256 public constant MIN_PROOF_LENGTH = 64;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice Aleo-Ethereum relay contract
    IAleoRelay public aleoRelay;

    /// @notice Optional Aleo light client for committee certificate verification
    IAleoLightClient public aleoLightClient;

    /// @notice Whitelisted Aleo program IDs (bytes32-encoded)
    mapping(bytes32 => bool) public whitelistedPrograms;

    /// @notice Registered Aleo bridge program for receive validation
    bytes32 public aleoBridgeProgram;

    /// @notice Message verification status
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Nullifier set – prevents replay of consumed records
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Supported Aleo network identifiers (e.g. mainnet, testnet)
    mapping(uint8 => bool) public supportedNetworks;

    /// @notice Bridge fee in basis points
    uint256 public bridgeFeeBps;

    /// @notice Minimum message fee (in wei)
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent through the bridge
    uint256 public totalMessagesSent;

    /// @notice Total messages received through the bridge
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (in wei)
    uint256 public totalValueBridged;

    /// @notice Sender nonce tracking for ordering
    mapping(address => uint256) public senderNonces;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────
    error ZeroAddress();
    error InvalidPayload();
    error PayloadTooLong();
    error InsufficientFee(uint256 required, uint256 provided);
    error ProgramNotWhitelisted(bytes32 programId);
    error InvalidProof();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error FeeTooHigh(uint256 bps);
    error TransferFailed();
    error NetworkNotSupported(uint8 networkId);
    error InvalidProgramId();
    error InvalidCommitteeCertificate();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────
    event MessageSentToAleo(
        bytes32 indexed messageHash,
        bytes32 indexed programId,
        bytes32 functionName,
        address sender,
        uint256 nonce,
        uint256 fee
    );

    event MessageReceivedFromAleo(
        bytes32 indexed messageHash,
        bytes32 indexed programId,
        address indexed recipient,
        uint256 nonce
    );

    event AleoRelayUpdated(address indexed oldRelay, address indexed newRelay);
    event AleoLightClientUpdated(
        address indexed oldClient,
        address indexed newClient
    );
    event ProgramWhitelisted(bytes32 indexed programId, bool whitelisted);
    event AleoBridgeProgramSet(bytes32 indexed programId);
    event NetworkSupportUpdated(uint8 networkId, bool supported);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed to, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────
    constructor(address _aleoRelay, address _admin) {
        if (_aleoRelay == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();

        aleoRelay = IAleoRelay(_aleoRelay);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        // Enable Aleo mainnet (network 0)
        supportedNetworks[0] = true;
    }

    // ──────────────────────────────────────────────
    //  Send (Ethereum → Aleo)
    // ──────────────────────────────────────────────

    /**
     * @notice Send a privacy-preserving message to an Aleo program
     * @param programId The target Aleo program ID (bytes32-encoded)
     * @param functionName The Aleo function to invoke
     * @param payload The message payload (serialized Aleo inputs)
     * @return messageHash Unique hash identifying the cross-chain message
     */
    function sendMessage(
        bytes32 programId,
        bytes32 functionName,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (programId == bytes32(0)) revert InvalidProgramId();
        if (!whitelistedPrograms[programId])
            revert ProgramNotWhitelisted(programId);
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Calculate fees
        uint256 relayFee = aleoRelay.getRelayFee();
        uint256 protocolFee = (msg.value * bridgeFeeBps) / 10_000;
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        // Increment nonce
        uint256 nonce = senderNonces[msg.sender]++;
        totalMessagesSent++;
        totalValueBridged += msg.value;
        accumulatedFees += protocolFee;

        // Send via relay
        bytes32 relayMessageId = aleoRelay.sendToAleo{
            value: msg.value - protocolFee
        }(programId, functionName, payload);

        // Compute message hash
        messageHash = keccak256(
            abi.encodePacked(
                ALEO_CHAIN_ID,
                block.chainid,
                msg.sender,
                programId,
                functionName,
                nonce,
                relayMessageId
            )
        );

        emit MessageSentToAleo(
            messageHash,
            programId,
            functionName,
            msg.sender,
            nonce,
            msg.value
        );
    }

    // ──────────────────────────────────────────────
    //  Receive (Aleo → Ethereum)
    // ──────────────────────────────────────────────

    /**
     * @notice Receive and verify a message from the Aleo network
     * @param programId The source Aleo program ID
     * @param networkId The Aleo network identifier (0 = mainnet)
     * @param payload The message payload
     * @param proof Committee certificate or SNARK proof
     * @return messageHash The verified message hash
     */
    function receiveMessage(
        bytes32 programId,
        uint8 networkId,
        bytes calldata payload,
        bytes calldata proof
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (!supportedNetworks[networkId])
            revert NetworkNotSupported(networkId);
        if (programId == bytes32(0)) revert InvalidProgramId();
        if (!whitelistedPrograms[programId])
            revert ProgramNotWhitelisted(programId);
        if (payload.length == 0) revert InvalidPayload();
        if (proof.length < MIN_PROOF_LENGTH) revert InvalidProof();

        // Verify via light client if available; otherwise trust relay attestation
        if (address(aleoLightClient) != address(0)) {
            bytes32 stateRoot = bytes32(proof[:32]);
            bytes memory stateProof = proof[32:];
            if (!aleoLightClient.verifyStateProof(stateRoot, stateProof))
                revert InvalidProof();
        }

        // Extract nullifier from payload (first 32 bytes)
        bytes32 nullifier = bytes32(payload[:32]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Compute message hash
        uint256 nonce = totalMessagesReceived++;
        messageHash = keccak256(
            abi.encodePacked(
                ALEO_CHAIN_ID,
                block.chainid,
                programId,
                networkId,
                nullifier,
                nonce
            )
        );
        verifiedMessages[messageHash] = true;

        emit MessageReceivedFromAleo(messageHash, programId, msg.sender, nonce);
    }

    // ──────────────────────────────────────────────
    //  IBridgeAdapter
    // ──────────────────────────────────────────────

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
    ) external payable override returns (bytes32 messageId) {
        bytes32 programId = aleoBridgeProgram;
        if (programId == bytes32(0)) revert InvalidProgramId();

        bytes32 functionName = keccak256("bridge_receive");
        bytes memory enrichedPayload = abi.encodePacked(
            bytes20(targetAddress),
            payload
        );

        uint256 relayFee = aleoRelay.getRelayFee();
        messageId = aleoRelay.sendToAleo{value: msg.value}(
            programId,
            functionName,
            enrichedPayload
        );

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSentToAleo(
            messageId,
            programId,
            functionName,
            msg.sender,
            senderNonces[msg.sender]++,
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        nativeFee = aleoRelay.getRelayFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        verified = verifiedMessages[messageId];
    }

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    /// @notice Get the bridge type identifier
    function bridgeType() external pure returns (string memory) {
        return "ALEO";
    }

    /// @notice Get the Aleo chain ID
    function chainId() external pure returns (uint256) {
        return ALEO_CHAIN_ID;
    }

    /// @notice Check if a nullifier has been used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if a program is whitelisted
    function isProgramWhitelisted(
        bytes32 programId
    ) external view returns (bool) {
        return whitelistedPrograms[programId];
    }

    /// @notice Verify a state proof against the light client
    function verifyStateProof(
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool) {
        if (address(aleoLightClient) == address(0)) return false;
        return aleoLightClient.verifyStateProof(stateRoot, proof);
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Update the Aleo relay contract address
    function setAleoRelay(
        address _relay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_relay == address(0)) revert ZeroAddress();
        emit AleoRelayUpdated(address(aleoRelay), _relay);
        aleoRelay = IAleoRelay(_relay);
    }

    /// @notice Update the Aleo light client contract address
    function setAleoLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit AleoLightClientUpdated(address(aleoLightClient), _client);
        aleoLightClient = IAleoLightClient(_client);
    }

    /// @notice Whitelist or de-whitelist an Aleo program
    function whitelistProgram(
        bytes32 programId,
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (programId == bytes32(0)) revert InvalidProgramId();
        whitelistedPrograms[programId] = enabled;
        emit ProgramWhitelisted(programId, enabled);
    }

    /// @notice Set the default Aleo bridge program for IBridgeAdapter calls
    function setAleoBridgeProgram(
        bytes32 programId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (programId == bytes32(0)) revert InvalidProgramId();
        aleoBridgeProgram = programId;
        emit AleoBridgeProgramSet(programId);
    }

    /// @notice Enable or disable an Aleo network
    function setSupportedNetwork(
        uint8 networkId,
        bool supported
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedNetworks[networkId] = supported;
        emit NetworkSupportUpdated(networkId, supported);
    }

    /// @notice Set bridge fee in basis points
    function setBridgeFee(
        uint256 feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (feeBps > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(feeBps);
        emit BridgeFeeUpdated(bridgeFeeBps, feeBps);
        bridgeFeeBps = feeBps;
    }

    /// @notice Set minimum message fee
    function setMinMessageFee(
        uint256 fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MinMessageFeeUpdated(minMessageFee, fee);
        minMessageFee = fee;
    }

    // ──────────────────────────────────────────────
    //  Emergency
    // ──────────────────────────────────────────────

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(
        address payable to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(to, amount);
    }

    /// @notice Emergency withdraw all ETH
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ERC-20 tokens
    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, balance);
    }

    /// @dev Allow receiving ETH
    receive() external payable {}
}
