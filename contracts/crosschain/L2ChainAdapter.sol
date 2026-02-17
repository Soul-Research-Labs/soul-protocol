// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title L2ChainAdapter
 * @author Soul Protocol
 * @notice Adapter for connecting Soul to Layer 2 networks
 * @dev Handles chain-specific messaging and proof verification with full
 *      Merkle proof validation and oracle signature verification
 */
contract L2ChainAdapter is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /// @notice secp256k1 curve order / 2 for signature malleability protection
    uint256 private constant SECP256K1_N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // Chain configuration
    struct ChainConfig {
        uint256 chainId;
        string name;
        address bridge;
        address messenger;
        uint256 confirmations;
        bool enabled;
        uint256 gasLimit;
    }

    // Supported L2 chains
    mapping(uint256 => ChainConfig) public chainConfigs;
    uint256[] public supportedChains;

    // Message tracking
    struct Message {
        bytes32 id;
        uint256 sourceChain;
        uint256 targetChain;
        bytes payload;
        uint256 timestamp;
        MessageStatus status;
    }

    enum MessageStatus {
        PENDING,
        RELAYED,
        CONFIRMED,
        FAILED
    }

    error ChainAlreadyExists();
    error ChainNotFound();
    error ChainNotEnabled();
    error InvalidMessageStatus();
    error InvalidProof();
    error InvalidMagicBytes();
    error PayloadHashMismatch();
    error ProofExpired();
    error InvalidMerkleProof();
    error InvalidOracleSignature();
    error InsufficientOracleSignatures();
    error StateRootNotSet();
    error SignatureMalleability();
    error ZeroAddress();

    mapping(bytes32 => Message) public messages;

    /// @notice State roots from source chains (chainId => blockNumber => stateRoot)
    mapping(uint256 => mapping(uint256 => bytes32)) public stateRoots;

    /// @notice Latest known block number per chain
    mapping(uint256 => uint256) public latestBlockNumber;

    /// @notice Registered oracle addresses per chain
    mapping(uint256 => address[]) public chainOracles;

    /// @notice Minimum oracle signatures required per chain
    mapping(uint256 => uint256) public minOracleSignatures;

    // Events
    event ChainAdded(uint256 indexed chainId, string name, address bridge);
    event ChainUpdated(uint256 indexed chainId, bool enabled);
    event StateRootUpdated(
        uint256 indexed chainId,
        uint256 indexed blockNumber,
        bytes32 stateRoot
    );
    event OracleAdded(uint256 indexed chainId, address indexed oracle);
    event OracleRemoved(uint256 indexed chainId, address indexed oracle);
    event MessageSent(
        bytes32 indexed messageId,
        uint256 sourceChain,
        uint256 targetChain
    );
    event MessageReceived(bytes32 indexed messageId, uint256 sourceChain);
    event MessageConfirmed(bytes32 indexed messageId);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);

        // Initialize default L2 configurations
        _initializeDefaultChains();
    }

    function _initializeDefaultChains() internal {
        // Arbitrum One
        _addChain(
            ChainConfig({
                chainId: 42161,
                name: "Arbitrum One",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false, // Disabled until real bridge addresses are configured
                gasLimit: 1000000
            })
        );

        // Optimism
        _addChain(
            ChainConfig({
                chainId: 10,
                name: "Optimism",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false,
                gasLimit: 1000000
            })
        );

        // Base
        _addChain(
            ChainConfig({
                chainId: 8453,
                name: "Base",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false,
                gasLimit: 1000000
            })
        );

        // zkSync Era
        _addChain(
            ChainConfig({
                chainId: 324,
                name: "zkSync Era",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false,
                gasLimit: 2000000
            })
        );

        // Scroll
        _addChain(
            ChainConfig({
                chainId: 534352,
                name: "Scroll",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false,
                gasLimit: 1500000
            })
        );

        // Linea
        _addChain(
            ChainConfig({
                chainId: 59144,
                name: "Linea",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false,
                gasLimit: 1000000
            })
        );

        // Polygon zkEVM
        _addChain(
            ChainConfig({
                chainId: 1101,
                name: "Polygon zkEVM",
                bridge: address(0),
                messenger: address(0),
                confirmations: 1,
                enabled: false,
                gasLimit: 1500000
            })
        );
    }

    function _addChain(ChainConfig memory config) internal {
        chainConfigs[config.chainId] = config;
        supportedChains.push(config.chainId);
        emit ChainAdded(config.chainId, config.name, config.bridge);
    }

    /**
     * @notice Add a new L2 chain configuration
     */
    function addChain(
        uint256 chainId,
        string memory name,
        address bridge,
        address messenger,
        uint256 confirmations,
        uint256 gasLimit
    ) external onlyRole(ADMIN_ROLE) {
        if (chainConfigs[chainId].chainId != 0) revert ChainAlreadyExists();
        if (bridge == address(0) || messenger == address(0))
            revert ZeroAddress();

        _addChain(
            ChainConfig({
                chainId: chainId,
                name: name,
                bridge: bridge,
                messenger: messenger,
                confirmations: confirmations,
                enabled: true,
                gasLimit: gasLimit
            })
        );
    }

    /**
     * @notice Update chain configuration
     */
    function updateChain(
        uint256 chainId,
        address bridge,
        address messenger,
        uint256 confirmations,
        uint256 gasLimit,
        bool enabled
    ) external onlyRole(ADMIN_ROLE) {
        if (chainConfigs[chainId].chainId == 0) revert ChainNotFound();

        // Cannot enable chain with zero bridge/messenger addresses
        if (enabled && (bridge == address(0) || messenger == address(0)))
            revert ZeroAddress();

        ChainConfig storage config = chainConfigs[chainId];
        config.bridge = bridge;
        config.messenger = messenger;
        config.confirmations = confirmations;
        config.gasLimit = gasLimit;
        config.enabled = enabled;

        emit ChainUpdated(chainId, enabled);
    }

    /**
     * @notice Send a message to another chain
     */
    function sendMessage(
        uint256 targetChain,
        bytes calldata payload
    ) external nonReentrant returns (bytes32 messageId) {
        if (!chainConfigs[targetChain].enabled) revert ChainNotEnabled();

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                targetChain,
                msg.sender,
                payload,
                block.timestamp
            )
        );

        messages[messageId] = Message({
            id: messageId,
            sourceChain: block.chainid,
            targetChain: targetChain,
            payload: payload,
            timestamp: block.timestamp,
            status: MessageStatus.PENDING
        });

        // Chain-specific message sending would go here
        // This is a simplified version

        emit MessageSent(messageId, block.chainid, targetChain);

        return messageId;
    }

    /**
     * @notice Receive a message from another chain
     */
    function receiveMessage(
        bytes32 messageId,
        uint256 sourceChain,
        bytes calldata payload,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        if (messages[messageId].id != bytes32(0)) revert InvalidMessageStatus();

        // Verify the message proof (chain-specific)
        if (!_verifyMessageProof(sourceChain, messageId, payload, proof))
            revert InvalidProof();

        messages[messageId] = Message({
            id: messageId,
            sourceChain: sourceChain,
            targetChain: block.chainid,
            payload: payload,
            timestamp: block.timestamp,
            status: MessageStatus.RELAYED
        });

        emit MessageReceived(messageId, sourceChain);
    }

    /**
     * @notice Confirm message delivery
     */
    function confirmMessage(bytes32 messageId) external onlyRole(RELAYER_ROLE) {
        if (messages[messageId].status != MessageStatus.RELAYED)
            revert InvalidMessageStatus();

        messages[messageId].status = MessageStatus.CONFIRMED;
        emit MessageConfirmed(messageId);
    }

    /**
     * @dev Verify message proof with full cryptographic validation
     * @notice Implements Merkle proof verification and oracle signature validation
     * @param sourceChain The source chain ID
     * @param messageId The unique message identifier
     * @param payload The message payload
     * @param proof Encoded proof containing:
     *   - bytes32 stateRoot (32 bytes)
     *   - uint256 blockNumber (32 bytes)
     *   - bytes32[] merkleProof (variable)
     *   - bytes[] oracleSignatures (variable)
     */
    function _verifyMessageProof(
        uint256 sourceChain,
        bytes32 messageId,
        bytes calldata payload,
        bytes calldata proof
    ) internal view returns (bool) {
        // Minimum proof length: stateRoot(32) + blockNumber(32) + at least 1 merkle node(32) + signature(65)
        if (proof.length < 161) {
            revert("Message proof too short");
        }

        // Verify source chain is supported
        ChainConfig storage config = chainConfigs[sourceChain];
        if (!config.enabled) {
            return false;
        }

        // Decode proof components
        (
            bytes32 claimedStateRoot,
            uint256 blockNumber,
            bytes32[] memory merkleProof,
            bytes[] memory oracleSignatures
        ) = _decodeProof(proof);

        // 1. Verify state root is known and matches
        _verifyStateRoot(
            sourceChain,
            blockNumber,
            claimedStateRoot,
            oracleSignatures
        );

        // 2. Compute message leaf and verify Merkle proof
        {
            bytes32 messageLeaf = keccak256(
                abi.encodePacked(
                    sourceChain,
                    block.chainid,
                    messageId,
                    keccak256(payload)
                )
            );

            // 3. Verify Merkle proof against state root
            if (
                !MerkleProof.verify(merkleProof, claimedStateRoot, messageLeaf)
            ) {
                revert InvalidMerkleProof();
            }
        }

        // 4. Verify block is not too old (prevent replay of ancient proofs)
        if (
            latestBlockNumber[sourceChain] > 0 &&
            blockNumber + config.confirmations <
            latestBlockNumber[sourceChain] - 1000
        ) {
            revert ProofExpired();
        }

        return true;
    }

    /// @dev Verifies state root validity (separated to reduce stack depth)
    function _verifyStateRoot(
        uint256 sourceChain,
        uint256 blockNumber,
        bytes32 claimedStateRoot,
        bytes[] memory oracleSignatures
    ) private view {
        bytes32 knownStateRoot = stateRoots[sourceChain][blockNumber];
        if (knownStateRoot == bytes32(0)) {
            if (
                !_verifyStateRootWithOracles(
                    sourceChain,
                    blockNumber,
                    claimedStateRoot,
                    oracleSignatures
                )
            ) {
                revert InvalidOracleSignature();
            }
        } else if (knownStateRoot != claimedStateRoot) {
            revert InvalidProof();
        }
    }

    /**
     * @dev Decode proof bytes into components
     */
    function _decodeProof(
        bytes calldata proof
    )
        internal
        pure
        returns (
            bytes32 stateRoot,
            uint256 blockNumber,
            bytes32[] memory merkleProof,
            bytes[] memory oracleSignatures
        )
    {
        // First 64 bytes are stateRoot and blockNumber
        stateRoot = bytes32(proof[0:32]);
        blockNumber = uint256(bytes32(proof[32:64]));

        // Next 2 bytes indicate merkle proof length
        uint256 merkleProofLength = uint16(bytes2(proof[64:66]));
        merkleProof = new bytes32[](merkleProofLength);

        uint256 offset = 66;
        for (uint256 i = 0; i < merkleProofLength; ) {
            merkleProof[i] = bytes32(proof[offset:offset + 32]);
            offset += 32;
            unchecked {
                ++i;
            }
        }

        // Remaining bytes are oracle signatures (each 65 bytes)
        uint256 remainingBytes = proof.length - offset;
        uint256 numSignatures = remainingBytes / 65;
        oracleSignatures = new bytes[](numSignatures);

        for (uint256 i = 0; i < numSignatures; ) {
            oracleSignatures[i] = proof[offset:offset + 65];
            offset += 65;
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Verify state root using oracle signatures
     * @param sourceChain The source chain ID
     * @param blockNumber The block number
     * @param stateRoot The claimed state root
     * @param signatures Oracle signatures
     */
    function _verifyStateRootWithOracles(
        uint256 sourceChain,
        uint256 blockNumber,
        bytes32 stateRoot,
        bytes[] memory signatures
    ) internal view returns (bool) {
        uint256 minSigs = minOracleSignatures[sourceChain];
        if (minSigs == 0) minSigs = 1; // Default to at least 1 signature

        if (signatures.length < minSigs) {
            revert InsufficientOracleSignatures();
        }

        // Create the message hash that oracles should have signed
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(sourceChain, blockNumber, stateRoot))
            )
        );

        address[] memory oracles = chainOracles[sourceChain];
        uint256 validSignatures = 0;

        for (uint256 i = 0; i < signatures.length; ) {
            address signer = _recoverSigner(messageHash, signatures[i]);

            // Check if signer is a registered oracle for this chain
            for (uint256 j = 0; j < oracles.length; ) {
                if (oracles[j] == signer) {
                    validSignatures++;
                    break;
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        return validSignatures >= minSigs;
    }

    /**
     * @dev Recover signer from signature with malleability protection
     */
    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;

        // Signature malleability protection
        if (uint256(s) > SECP256K1_N_DIV_2) {
            return address(0);
        }

        return ecrecover(hash, v, r, s);
    }

    /**
     * @notice Update state root for a source chain (called by oracles)
     * @param sourceChain The source chain ID
     * @param blockNumber The block number
     * @param stateRoot The state root
     */
    function updateStateRoot(
        uint256 sourceChain,
        uint256 blockNumber,
        bytes32 stateRoot
    ) external onlyRole(ORACLE_ROLE) {
        stateRoots[sourceChain][blockNumber] = stateRoot;

        if (blockNumber > latestBlockNumber[sourceChain]) {
            latestBlockNumber[sourceChain] = blockNumber;
        }

        emit StateRootUpdated(sourceChain, blockNumber, stateRoot);
    }

    /**
     * @notice Add an oracle for a chain
     * @param chainId The chain ID
     * @param oracle The oracle address
     */
    function addOracle(
        uint256 chainId,
        address oracle
    ) external onlyRole(ADMIN_ROLE) {
        chainOracles[chainId].push(oracle);
        emit OracleAdded(chainId, oracle);
    }

    /**
     * @notice Remove an oracle for a chain
     * @param chainId The chain ID
     * @param oracle The oracle address
     */
    function removeOracle(
        uint256 chainId,
        address oracle
    ) external onlyRole(ADMIN_ROLE) {
        address[] storage oracles = chainOracles[chainId];
        for (uint256 i = 0; i < oracles.length; ) {
            if (oracles[i] == oracle) {
                oracles[i] = oracles[oracles.length - 1];
                oracles.pop();
                emit OracleRemoved(chainId, oracle);
                break;
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Set minimum oracle signatures required for a chain
     * @param chainId The chain ID
     * @param minSigs Minimum signatures required
     */
    function setMinOracleSignatures(
        uint256 chainId,
        uint256 minSigs
    ) external onlyRole(ADMIN_ROLE) {
        minOracleSignatures[chainId] = minSigs;
    }

    /**
     * @notice Get all supported chains
     * @return Array of supported chain IDs
     */
    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    /**
     * @notice Get chain configuration
     * @param chainId The chain ID to query
     * @return The ChainConfig struct for the given chain
     */
    function getChainConfig(
        uint256 chainId
    ) external view returns (ChainConfig memory) {
        return chainConfigs[chainId];
    }

    /**
     * @notice Check if a chain is supported and enabled
     * @param chainId The chain ID to check
     * @return True if the chain is supported and enabled
     */
    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].enabled;
    }

    /**
     * @notice Get message status
     * @param messageId The unique message identifier
     * @return The current MessageStatus of the message
     */
    function getMessageStatus(
        bytes32 messageId
    ) external view returns (MessageStatus) {
        return messages[messageId].status;
    }
}
