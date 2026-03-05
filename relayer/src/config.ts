/**
 * ZASEON Relayer - Configuration
 */

export interface ChainConfig {
  name: string;
  chainId: number;
  rpcUrl: string;
  bridgeAddress?: string;
  proofHubAddress?: string;
  relayContractAddress?: string;
  confirmations: number;
}

export interface RelayerConfig {
  chains: ChainConfig[];
  redisUrl: string;
  logLevel: string;
  healthPort: number;
  privateKey?: string;
  maxRetries: number;
  retryDelayMs: number;
}

const CHAIN_DEFAULTS: Record<string, Omit<ChainConfig, "rpcUrl">> = {
  ethereum: { name: "Ethereum", chainId: 1, confirmations: 12 },
  arbitrum: { name: "Arbitrum", chainId: 42161, confirmations: 1 },
  optimism: { name: "Optimism", chainId: 10, confirmations: 1 },
  base: { name: "Base", chainId: 8453, confirmations: 1 },
  aztec: { name: "Aztec", chainId: 4100, confirmations: 1 },
  "arbitrum-sepolia": {
    name: "Arbitrum Sepolia",
    chainId: 421614,
    confirmations: 1,
  },
  "optimism-sepolia": {
    name: "Optimism Sepolia",
    chainId: 11155420,
    confirmations: 1,
  },
  sepolia: { name: "Sepolia", chainId: 11155111, confirmations: 2 },
};

export function loadConfig(): RelayerConfig {
  const chainNames = (
    process.env.CHAINS || "ethereum,arbitrum,optimism,base"
  ).split(",");

  const chains: ChainConfig[] = chainNames
    .map((name) => name.trim().toLowerCase())
    .filter((name) => CHAIN_DEFAULTS[name])
    .map((name) => {
      const envKey = name.replace(/-/g, "_").toUpperCase();
      return {
        ...CHAIN_DEFAULTS[name],
        rpcUrl: process.env[`${envKey}_RPC_URL`] || `http://localhost:8545`,
        bridgeAddress: process.env[`${envKey}_BRIDGE_ADDRESS`],
        proofHubAddress: process.env[`${envKey}_PROOF_HUB_ADDRESS`],
        relayContractAddress: process.env[`${envKey}_RELAY_CONTRACT_ADDRESS`],
      };
    });

  return {
    chains,
    redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
    logLevel: process.env.LOG_LEVEL || "info",
    healthPort: parseInt(process.env.HEALTH_PORT || "9090", 10),
    privateKey: process.env.RELAYER_PRIVATE_KEY,
    maxRetries: parseInt(process.env.MAX_RETRIES || "5", 10),
    retryDelayMs: parseInt(process.env.RETRY_DELAY_MS || "5000", 10),
  };
}
