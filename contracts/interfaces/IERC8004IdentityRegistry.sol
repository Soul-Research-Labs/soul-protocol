// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC8004IdentityRegistry
 * @author Soul Protocol
 * @notice Interface for ERC-8004 Trustless Agents - Identity Registry
 * @dev ERC-721 based agent identity with URI storage and on-chain metadata
 *
 * ERC-8004 IDENTITY REGISTRY:
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                   Identity Registry                         │
 *   │  ┌───────────────────────────────────────────────────────┐  │
 *   │  │  ERC-721 Agent NFTs                                   │  │
 *   │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐              │  │
 *   │  │  │ Agent 1  │  │ Agent 2  │  │ Agent N  │              │  │
 *   │  │  │ tokenId  │  │ tokenId  │  │ tokenId  │              │  │
 *   │  │  └────┬─────┘  └────┬─────┘  └────┬─────┘              │  │
 *   │  │       │              │              │                    │  │
 *   │  │  ┌────▼──────────────▼──────────────▼────┐              │  │
 *   │  │  │         agentURI → Registration File   │              │  │
 *   │  │  │  (IPFS / HTTPS / data: URI)            │              │  │
 *   │  │  └──────────────────────────────────────┘              │  │
 *   │  │                                                         │  │
 *   │  │  On-chain Metadata: key → value mappings                │  │
 *   │  │  Reserved key: "agentWallet" (EIP-712 verified)         │  │
 *   │  └───────────────────────────────────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * AGENT GLOBAL ID: {namespace}:{chainId}:{identityRegistry}#{agentId}
 *   e.g. eip155:1:0x742...#22
 *
 * Requires: EIP-155, EIP-712, EIP-721, ERC-1271
 */
interface IERC8004IdentityRegistry {
    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Metadata key-value entry for batch registration
    struct MetadataEntry {
        string metadataKey;
        bytes metadataValue;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new agent is registered
    event Registered(
        uint256 indexed agentId,
        string agentURI,
        address indexed owner
    );

    /// @notice Emitted when an agent's URI is updated
    event URIUpdated(
        uint256 indexed agentId,
        string newURI,
        address indexed updatedBy
    );

    /// @notice Emitted when on-chain metadata is set
    event MetadataSet(
        uint256 indexed agentId,
        string indexed indexedMetadataKey,
        string metadataKey,
        bytes metadataValue
    );

    /// @notice Emitted when agent wallet is updated
    event AgentWalletUpdated(
        uint256 indexed agentId,
        address indexed oldWallet,
        address indexed newWallet
    );

    /// @notice Emitted when agent wallet is cleared
    event AgentWalletCleared(uint256 indexed agentId);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error AgentNotFound(uint256 agentId);
    error NotAgentOwnerOrOperator(uint256 agentId, address caller);
    error ReservedMetadataKey(string key);
    error InvalidSignature();
    error SignatureExpired(uint256 deadline);
    error ZeroAddress();
    error WalletAlreadySet(uint256 agentId, address wallet);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a new agent with URI and metadata
    /// @param agentURI URI pointing to the agent registration file
    /// @param metadata Array of metadata key-value entries
    /// @return agentId The newly minted agent token ID
    function register(
        string calldata agentURI,
        MetadataEntry[] calldata metadata
    ) external returns (uint256 agentId);

    /// @notice Register a new agent with URI only
    /// @param agentURI URI pointing to the agent registration file
    /// @return agentId The newly minted agent token ID
    function register(
        string calldata agentURI
    ) external returns (uint256 agentId);

    /// @notice Register a new agent (URI added later)
    /// @return agentId The newly minted agent token ID
    function register() external returns (uint256 agentId);

    /// @notice Update an agent's URI
    /// @param agentId The agent token ID
    /// @param newURI The new URI
    function setAgentURI(
        uint256 agentId,
        string calldata newURI
    ) external;

    /// @notice Set on-chain metadata for an agent
    /// @param agentId The agent token ID
    /// @param metadataKey The metadata key
    /// @param metadataValue The metadata value
    function setMetadata(
        uint256 agentId,
        string memory metadataKey,
        bytes memory metadataValue
    ) external;

    /// @notice Get on-chain metadata for an agent
    /// @param agentId The agent token ID
    /// @param metadataKey The metadata key
    /// @return The metadata value
    function getMetadata(
        uint256 agentId,
        string memory metadataKey
    ) external view returns (bytes memory);

    /// @notice Set agent wallet with EIP-712/ERC-1271 signature verification
    /// @param agentId The agent token ID
    /// @param newWallet The new wallet address
    /// @param deadline Signature expiry timestamp
    /// @param signature EIP-712 or ERC-1271 signature from newWallet
    function setAgentWallet(
        uint256 agentId,
        address newWallet,
        uint256 deadline,
        bytes calldata signature
    ) external;

    /// @notice Get the agent's verified wallet address
    /// @param agentId The agent token ID
    /// @return The agent wallet address (address(0) if unset)
    function getAgentWallet(
        uint256 agentId
    ) external view returns (address);

    /// @notice Clear the agent wallet
    /// @param agentId The agent token ID
    function unsetAgentWallet(uint256 agentId) external;

    /// @notice Get the total number of registered agents
    /// @return The total agent count
    function totalAgents() external view returns (uint256);
}
