/**
 * @module chainlink-ccip
 * @description Chainlink CCIP (Cross-Chain Interoperability Protocol) adapter
 * constants, types and ABI for the ZASEON SDK.
 *
 * CCIP provides a chain-abstracted cross-chain messaging standard backed by
 * Chainlink's decentralized oracle network and Risk Management Network.
 * It uses chain selectors (uint64) instead of EVM chain IDs for routing.
 *
 * Features:
 * - EVM2AnyMessage / Any2EVMMessage encoding
 * - Token transfer alongside data (up to 5 tokens per message)
 * - Source chain and sender allowlisting
 * - Native fee payment or LINK token fees
 * - Excess fee refund mechanism
 */

// ─── Constants ─────────────────────────────────────────────────────

/** Maximum tokens per CCIP message (v1.5 limit) */
export const MAX_TOKENS_PER_MESSAGE = 5;

/** Bridge type identifier */
export const CHAINLINK_CCIP_BRIDGE_TYPE = "CCIP-DON" as const;

// ─── Types ─────────────────────────────────────────────────────────

export interface ChainlinkCCIPConfig {
  /** CCIP Router contract address */
  router: string;
  /** Default destination chain selector (uint64) */
  destinationChainSelector: bigint;
}

export interface CCIPSendParams {
  /** Target contract address on destination chain */
  targetAddress: string;
  /** Payload bytes */
  payload: string;
  /** Value to send (in wei, covers CCIP fees) */
  value: bigint;
}

export interface CCIPSendWithTokensParams extends CCIPSendParams {
  /** ERC-20 token addresses to transfer */
  tokens: string[];
  /** Corresponding amounts for each token */
  amounts: bigint[];
}

export interface CCIPMessageEvent {
  messageId: string;
  fees: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const CHAINLINK_CCIP_BRIDGE_ADAPTER_ABI = [
  // Constructor
  "constructor(address _router, uint64 _selector)",

  // IBridgeAdapter
  "function bridgeMessage(address targetAddress, bytes payload, address refundAddress) payable returns (bytes32 messageId)",
  "function estimateFee(address targetAddress, bytes payload) view returns (uint256 nativeFee)",
  "function isMessageVerified(bytes32 messageId) view returns (bool verified)",

  // Token transfers
  "function bridgeMessageWithTokens(address targetAddress, bytes payload, address[] tokens, uint256[] amounts) payable returns (bytes32 messageId)",

  // Views
  "function i_router() view returns (address)",
  "function destinationChainSelector() view returns (uint64)",
  "function verifiedMessages(bytes32) view returns (bool)",
  "function allowedSourceChains(uint64) view returns (bool)",
  "function MAX_TOKENS_PER_MESSAGE() view returns (uint256)",

  // Admin
  "function updateSourceChain(uint64 chainSelector, bool allowed)",
  "function updateSender(uint64 chainSelector, bytes32 senderHash, bool allowed)",

  // Events
  "event MessageSent(bytes32 indexed messageId, uint256 fees)",
  "event MessageReceived(bytes32 indexed messageId, uint64 indexed sourceChainSelector, bytes sender)",
  "event SourceChainUpdated(uint64 indexed chainSelector, bool allowed)",
  "event SenderUpdated(uint64 indexed chainSelector, bytes32 indexed senderHash, bool allowed)",
  "event TokenMessageSent(bytes32 indexed messageId, uint256 fees, address[] tokens, uint256[] amounts)",
] as const;

export type ChainlinkCCIPBridgeAdapterABI =
  typeof CHAINLINK_CCIP_BRIDGE_ADAPTER_ABI;
