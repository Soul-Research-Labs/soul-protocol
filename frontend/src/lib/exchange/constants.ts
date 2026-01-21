import { Token } from './hooks';

// Supported tokens configuration
export const TOKENS: Record<string, Token> = {
  ETH: {
    address: '0x0000000000000000000000000000000000000000',
    symbol: 'ETH',
    name: 'Ethereum',
    decimals: 18,
    logoUrl: '/tokens/eth.svg',
  },
  WETH: {
    address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    symbol: 'WETH',
    name: 'Wrapped Ether',
    decimals: 18,
    logoUrl: '/tokens/weth.svg',
  },
  USDC: {
    address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    symbol: 'USDC',
    name: 'USD Coin',
    decimals: 6,
    logoUrl: '/tokens/usdc.svg',
  },
  USDT: {
    address: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    symbol: 'USDT',
    name: 'Tether USD',
    decimals: 6,
    logoUrl: '/tokens/usdt.svg',
  },
  DAI: {
    address: '0x6B175474E89094C44Da98b954EescdecaD3F9564',
    symbol: 'DAI',
    name: 'Dai Stablecoin',
    decimals: 18,
    logoUrl: '/tokens/dai.svg',
  },
  WBTC: {
    address: '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
    symbol: 'WBTC',
    name: 'Wrapped Bitcoin',
    decimals: 8,
    logoUrl: '/tokens/wbtc.svg',
  },
  SOUL: {
    address: '0x0000000000000000000000000000000000000001', // Placeholder
    symbol: 'SOUL',
    name: 'Soul Network Token',
    decimals: 18,
    logoUrl: '/tokens/soul.svg',
  },
};

// Chain configurations
export const CHAINS = {
  ethereum: {
    id: 1,
    name: 'Ethereum',
    rpcUrl: 'https://eth.llamarpc.com',
    explorer: 'https://etherscan.io',
    nativeCurrency: TOKENS.ETH,
  },
  arbitrum: {
    id: 42161,
    name: 'Arbitrum One',
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    explorer: 'https://arbiscan.io',
    nativeCurrency: TOKENS.ETH,
  },
  optimism: {
    id: 10,
    name: 'Optimism',
    rpcUrl: 'https://mainnet.optimism.io',
    explorer: 'https://optimistic.etherscan.io',
    nativeCurrency: TOKENS.ETH,
  },
  polygon: {
    id: 137,
    name: 'Polygon',
    rpcUrl: 'https://polygon-rpc.com',
    explorer: 'https://polygonscan.com',
    nativeCurrency: {
      address: '0x0000000000000000000000000000000000000000' as `0x${string}`,
      symbol: 'MATIC',
      name: 'Polygon',
      decimals: 18,
    },
  },
  base: {
    id: 8453,
    name: 'Base',
    rpcUrl: 'https://mainnet.base.org',
    explorer: 'https://basescan.org',
    nativeCurrency: TOKENS.ETH,
  },
};

// Contract addresses by chain
export const CONTRACT_ADDRESSES: Record<number, {
  exchange: `0x${string}`;
  atomic_swap: `0x${string}`;
  privacy_pool: `0x${string}`;
}> = {
  1: {
    exchange: '0x0000000000000000000000000000000000000000',
    atomic_swap: '0x0000000000000000000000000000000000000000',
    privacy_pool: '0x0000000000000000000000000000000000000000',
  },
  // Add other chains as needed
};

// Pool configurations
export interface PoolConfig {
  id: `0x${string}`;
  tokenA: Token;
  tokenB: Token;
  feeRate: number;
  name: string;
}

export const POOLS: PoolConfig[] = [
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000001',
    tokenA: TOKENS.WETH,
    tokenB: TOKENS.USDC,
    feeRate: 30, // 0.3%
    name: 'WETH/USDC',
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000002',
    tokenA: TOKENS.WETH,
    tokenB: TOKENS.DAI,
    feeRate: 30,
    name: 'WETH/DAI',
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000003',
    tokenA: TOKENS.WBTC,
    tokenB: TOKENS.USDC,
    feeRate: 30,
    name: 'WBTC/USDC',
  },
  {
    id: '0x0000000000000000000000000000000000000000000000000000000000000004',
    tokenA: TOKENS.USDC,
    tokenB: TOKENS.DAI,
    feeRate: 5, // 0.05% for stableswap
    name: 'USDC/DAI',
  },
];

// Privacy settings defaults
export const DEFAULT_PRIVACY_SETTINGS = {
  useStealthAddress: true,
  hideOrderDetails: true,
  useZKProofs: true,
  encryptMetadata: true,
};

// Slippage presets
export const SLIPPAGE_PRESETS = [0.1, 0.5, 1.0, 3.0];
export const DEFAULT_SLIPPAGE = 0.5;
export const MAX_SLIPPAGE = 50;

// Order types
export enum OrderType {
  Limit = 0,
  Market = 1,
  StopLoss = 2,
  TakeProfit = 3,
}

export enum OrderSide {
  Buy = 0,
  Sell = 1,
}

export enum OrderStatus {
  Invalid = 0,
  Active = 1,
  PartiallyFilled = 2,
  Filled = 3,
  Cancelled = 4,
  Expired = 5,
}

// Time constants
export const MIN_DEADLINE_SECONDS = 60; // 1 minute
export const DEFAULT_DEADLINE_SECONDS = 3600; // 1 hour
export const MAX_DEADLINE_SECONDS = 604800; // 7 days

// Fee constants
export const MAKER_FEE_BPS = 10; // 0.1%
export const TAKER_FEE_BPS = 30; // 0.3%
export const MAX_FEE_BPS = 100; // 1%

// Format helpers
export function formatAmount(amount: bigint, decimals: number): string {
  const divisor = BigInt(10 ** decimals);
  const integerPart = amount / divisor;
  const fractionalPart = amount % divisor;
  
  const fractionalStr = fractionalPart.toString().padStart(decimals, '0').slice(0, 4);
  return `${integerPart}.${fractionalStr}`;
}

export function parseAmount(amount: string, decimals: number): bigint {
  const [integer, fractional = ''] = amount.split('.');
  const fractionalPadded = fractional.padEnd(decimals, '0').slice(0, decimals);
  return BigInt(integer + fractionalPadded);
}

export function formatUSD(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount);
}

export function formatPercent(value: number): string {
  return `${value.toFixed(2)}%`;
}

export function shortenAddress(address: string): string {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

export function getTimeRemaining(deadline: number): string {
  const now = Date.now() / 1000;
  const remaining = deadline - now;
  
  if (remaining <= 0) return 'Expired';
  
  if (remaining < 60) return `${Math.floor(remaining)}s`;
  if (remaining < 3600) return `${Math.floor(remaining / 60)}m`;
  if (remaining < 86400) return `${Math.floor(remaining / 3600)}h`;
  return `${Math.floor(remaining / 86400)}d`;
}

// Price calculation helpers
export function calculatePriceImpact(
  amountIn: bigint,
  reserveIn: bigint,
  reserveOut: bigint,
  feeRate: number
): number {
  const amountInWithFee = amountIn * BigInt(10000 - feeRate);
  const numerator = amountInWithFee * reserveOut;
  const denominator = reserveIn * BigInt(10000) + amountInWithFee;
  const amountOut = numerator / denominator;
  
  // Ideal price without impact
  const idealOutput = (amountIn * reserveOut) / reserveIn;
  
  // Price impact
  const impact = Number(idealOutput - amountOut) / Number(idealOutput) * 100;
  return impact;
}

export function calculateMinOutput(
  expectedOutput: bigint,
  slippagePercent: number
): bigint {
  const slippageBps = BigInt(Math.floor(slippagePercent * 100));
  return expectedOutput * (BigInt(10000) - slippageBps) / BigInt(10000);
}

// Privacy helpers
export function generateRandomBytes32(): `0x${string}` {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return ('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')) as `0x${string}`;
}

export function computeOrderCommitment(
  tokenIn: string,
  tokenOut: string,
  amountIn: bigint,
  minAmountOut: bigint,
  deadline: bigint,
  salt: `0x${string}`
): `0x${string}` {
  // Simplified commitment - in production use Poseidon hash
  const data = `${tokenIn}${tokenOut}${amountIn}${minAmountOut}${deadline}${salt}`;
  const encoder = new TextEncoder();
  const bytes = encoder.encode(data);
  
  // Use Web Crypto API for hashing
  return generateRandomBytes32(); // Placeholder
}
