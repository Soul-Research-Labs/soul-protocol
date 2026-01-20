import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "hardhat-gas-reporter";
import "solidity-coverage";
import * as dotenv from "dotenv";

dotenv.config();

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x" + "0".repeat(64);
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

// Note: This config is for L2 deployments and may need network type annotations for Hardhat v3
const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    // Local
    localhost: {
      type: "http",
      url: "http://127.0.0.1:8545",
    },
    hardhat: {
      type: "edr-simulated",
      chainId: 31337,
    },
    
    // Testnets
    sepolia: {
      type: "http",
      url: process.env.SEPOLIA_RPC_URL || "https://rpc.sepolia.org",
      accounts: [PRIVATE_KEY],
      chainId: 11155111,
    },
    goerli: {
      type: "http",
      url: process.env.GOERLI_RPC_URL || "https://rpc.ankr.com/eth_goerli",
      accounts: [PRIVATE_KEY],
      chainId: 5,
    },
    
    // Mainnet
    mainnet: {
      type: "http",
      url: process.env.MAINNET_RPC_URL || "https://eth.llamarpc.com",
      accounts: [PRIVATE_KEY],
      chainId: 1,
      gasPrice: "auto",
    },
    
    // L2 Networks
    arbitrum: {
      type: "http",
      url: process.env.ARBITRUM_RPC_URL || "https://arb1.arbitrum.io/rpc",
      accounts: [PRIVATE_KEY],
      chainId: 42161,
    },
    arbitrumSepolia: {
      type: "http",
      url: process.env.ARBITRUM_SEPOLIA_RPC_URL || "https://sepolia-rollup.arbitrum.io/rpc",
      accounts: [PRIVATE_KEY],
      chainId: 421614,
    },
    optimism: {
      type: "http",
      url: process.env.OPTIMISM_RPC_URL || "https://mainnet.optimism.io",
      accounts: [PRIVATE_KEY],
      chainId: 10,
    },
    optimismSepolia: {
      type: "http",
      url: process.env.OPTIMISM_SEPOLIA_RPC_URL || "https://sepolia.optimism.io",
      accounts: [PRIVATE_KEY],
      chainId: 11155420,
    },
    base: {
      type: "http",
      url: process.env.BASE_RPC_URL || "https://mainnet.base.org",
      accounts: [PRIVATE_KEY],
      chainId: 8453,
    },
    baseSepolia: {
      type: "http",
      url: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
      accounts: [PRIVATE_KEY],
      chainId: 84532,
    },
    
    // ZK Rollups
    zksync: {
      type: "http",
      url: process.env.ZKSYNC_RPC_URL || "https://mainnet.era.zksync.io",
      accounts: [PRIVATE_KEY],
      chainId: 324,
    },
    scroll: {
      type: "http",
      url: process.env.SCROLL_RPC_URL || "https://rpc.scroll.io",
      accounts: [PRIVATE_KEY],
      chainId: 534352,
    },
    linea: {
      type: "http",
      url: process.env.LINEA_RPC_URL || "https://rpc.linea.build",
      accounts: [PRIVATE_KEY],
      chainId: 59144,
    },
    polygonZkEvm: {
      type: "http",
      url: process.env.POLYGON_ZKEVM_RPC_URL || "https://zkevm-rpc.com",
      accounts: [PRIVATE_KEY],
      chainId: 1101,
    },
  },
  
  // Note: etherscan, gasReporter, mocha configs moved to plugins in Hardhat v3
  
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};

export default config;
