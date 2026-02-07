// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC8004IdentityRegistry} from "../interfaces/IERC8004IdentityRegistry.sol";

/**
 * @title ERC8004IdentityRegistry
 * @author Soul Protocol
 * @notice ERC-8004 Trustless Agents - Identity Registry implementation
 * @dev ERC-721 based agent identity registry with URI storage, on-chain metadata,
 *      and EIP-712 verified wallet assignment.
 *
 * Each agent is identified on-chain by:
 *   agentRegistry = "eip155:{chainId}:{address(this)}"
 *   agentId       = sequential ERC-721 tokenId
 *
 * The agentURI resolves to a registration file (IPFS, HTTPS, or data: URI)
 * containing the agent's services (MCP, A2A, ENS, DID, etc.) and trust model.
 *
 * On-chain metadata supports arbitrary key-value pairs, with the reserved
 * "agentWallet" key requiring EIP-712/ERC-1271 signature verification.
 *
 * On transfer, the agentWallet is automatically cleared and must be re-verified
 * by the new owner.
 */
contract ERC8004IdentityRegistry is
    IERC8004IdentityRegistry,
    ERC721URIStorage,
    EIP712,
    ReentrancyGuard
{
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev EIP-712 typehash for setAgentWallet
    bytes32 public constant AGENT_WALLET_TYPEHASH =
        keccak256("SetAgentWallet(uint256 agentId,address newWallet,uint256 deadline)");

    /// @dev Reserved metadata key for agent wallet
    string public constant AGENT_WALLET_KEY = "agentWallet";

    /*//////////////////////////////////////////////////////////////
                              PUBLIC VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 domain separator for external signature construction
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Next agent ID (1-indexed, incremental)
    uint256 private _nextAgentId;

    /// @notice Total registered agents
    uint256 public totalAgents;

    /// @notice On-chain metadata: agentId → key → value
    mapping(uint256 => mapping(bytes32 => bytes)) private _metadata;

    /// @notice Agent wallet addresses: agentId → wallet
    mapping(uint256 => address) private _agentWallets;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor()
        ERC721("ERC8004 Agent Identity", "AGENT")
        EIP712("ERC8004IdentityRegistry", "1")
    {
        _nextAgentId = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004IdentityRegistry
    function register(
        string calldata agentURI,
        MetadataEntry[] calldata metadata
    ) external returns (uint256 agentId) {
        agentId = _mintAgent(msg.sender, agentURI);

        // Set each metadata entry (reject reserved keys)
        for (uint256 i = 0; i < metadata.length; i++) {
            _requireNotReserved(metadata[i].metadataKey);
            _setMetadata(agentId, metadata[i].metadataKey, metadata[i].metadataValue);
        }
    }

    /// @inheritdoc IERC8004IdentityRegistry
    function register(
        string calldata agentURI
    ) external returns (uint256 agentId) {
        agentId = _mintAgent(msg.sender, agentURI);
    }

    /// @inheritdoc IERC8004IdentityRegistry
    function register() external returns (uint256 agentId) {
        agentId = _mintAgent(msg.sender, "");
    }

    /*//////////////////////////////////////////////////////////////
                           URI MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004IdentityRegistry
    function setAgentURI(
        uint256 agentId,
        string calldata newURI
    ) external {
        _requireOwnerOrOperator(agentId, msg.sender);
        _setTokenURI(agentId, newURI);
        emit URIUpdated(agentId, newURI, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        ON-CHAIN METADATA
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004IdentityRegistry
    function setMetadata(
        uint256 agentId,
        string memory metadataKey,
        bytes memory metadataValue
    ) external {
        _requireOwnerOrOperator(agentId, msg.sender);
        _requireNotReserved(metadataKey);
        _setMetadata(agentId, metadataKey, metadataValue);
    }

    /// @inheritdoc IERC8004IdentityRegistry
    function getMetadata(
        uint256 agentId,
        string memory metadataKey
    ) external view returns (bytes memory) {
        return _metadata[agentId][keccak256(abi.encodePacked(metadataKey))];
    }

    /*//////////////////////////////////////////////////////////////
                         AGENT WALLET
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IERC8004IdentityRegistry
    function setAgentWallet(
        uint256 agentId,
        address newWallet,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        _requireOwnerOrOperator(agentId, msg.sender);
        if (newWallet == address(0)) revert ZeroAddress();
        if (block.timestamp > deadline) revert SignatureExpired(deadline);

        // Build EIP-712 digest
        bytes32 structHash = keccak256(
            abi.encode(AGENT_WALLET_TYPEHASH, agentId, newWallet, deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        // Verify signature: try ERC-1271 for contracts, ECDSA for EOAs
        if (_isContract(newWallet)) {
            try IERC1271(newWallet).isValidSignature(digest, signature) returns (bytes4 magicValue) {
                if (magicValue != IERC1271.isValidSignature.selector) revert InvalidSignature();
            } catch {
                revert InvalidSignature();
            }
        } else {
            address recovered = digest.recover(signature);
            if (recovered != newWallet) revert InvalidSignature();
        }

        address oldWallet = _agentWallets[agentId];
        _agentWallets[agentId] = newWallet;

        // Store in metadata too for composability
        _metadata[agentId][keccak256(abi.encodePacked(AGENT_WALLET_KEY))] =
            abi.encodePacked(newWallet);

        emit AgentWalletUpdated(agentId, oldWallet, newWallet);
    }

    /// @inheritdoc IERC8004IdentityRegistry
    function getAgentWallet(
        uint256 agentId
    ) external view returns (address) {
        return _agentWallets[agentId];
    }

    /// @inheritdoc IERC8004IdentityRegistry
    function unsetAgentWallet(uint256 agentId) external {
        _requireOwnerOrOperator(agentId, msg.sender);
        address oldWallet = _agentWallets[agentId];
        delete _agentWallets[agentId];
        delete _metadata[agentId][keccak256(abi.encodePacked(AGENT_WALLET_KEY))];
        emit AgentWalletCleared(agentId);

        // Suppress unused variable warning
        oldWallet;
    }

    /*//////////////////////////////////////////////////////////////
                          ERC-721 OVERRIDES
    //////////////////////////////////////////////////////////////*/

    /// @dev Clear agentWallet on transfer (as per ERC-8004 spec)
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override returns (address) {
        address from = super._update(to, tokenId, auth);

        // On transfer (not mint), clear the agent wallet
        if (from != address(0) && to != address(0)) {
            delete _agentWallets[tokenId];
            delete _metadata[tokenId][keccak256(abi.encodePacked(AGENT_WALLET_KEY))];
            emit AgentWalletCleared(tokenId);
        }

        return from;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _mintAgent(
        address owner,
        string memory agentURI_
    ) internal returns (uint256 agentId) {
        agentId = _nextAgentId++;
        totalAgents++;

        _safeMint(owner, agentId);

        if (bytes(agentURI_).length > 0) {
            _setTokenURI(agentId, agentURI_);
        }

        // Set default agentWallet to owner
        _agentWallets[agentId] = owner;
        _metadata[agentId][keccak256(abi.encodePacked(AGENT_WALLET_KEY))] =
            abi.encodePacked(owner);

        emit MetadataSet(agentId, AGENT_WALLET_KEY, AGENT_WALLET_KEY, abi.encodePacked(owner));
        emit Registered(agentId, agentURI_, owner);
    }

    function _setMetadata(
        uint256 agentId,
        string memory key,
        bytes memory value
    ) internal {
        _metadata[agentId][keccak256(abi.encodePacked(key))] = value;
        emit MetadataSet(agentId, key, key, value);
    }

    function _requireOwnerOrOperator(uint256 agentId, address caller) internal view {
        address owner = ownerOf(agentId);
        if (caller != owner && !isApprovedForAll(owner, caller) && getApproved(agentId) != caller) {
            revert NotAgentOwnerOrOperator(agentId, caller);
        }
    }

    function _requireNotReserved(string memory key) internal pure {
        if (keccak256(abi.encodePacked(key)) == keccak256(abi.encodePacked(AGENT_WALLET_KEY))) {
            revert ReservedMetadataKey(key);
        }
    }

    function _isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
