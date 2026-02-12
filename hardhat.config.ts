import { defineConfig } from "hardhat/config";
import hardhatMocha from "@nomicfoundation/hardhat-mocha";
import hardhatViem from "@nomicfoundation/hardhat-viem";
import "@nomicfoundation/hardhat-ethers";
import * as dotenv from "dotenv";

dotenv.config({ quiet: true } as any);

const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x0000000000000000000000000000000000000000000000000000000000000000";
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";
const POLYGONSCAN_API_KEY = process.env.POLYGONSCAN_API_KEY || "";
const ARBISCAN_API_KEY = process.env.ARBISCAN_API_KEY || "";
const BASESCAN_API_KEY = process.env.BASESCAN_API_KEY || "";
const OPTIMISM_API_KEY = process.env.OPTIMISM_API_KEY || "";

export default defineConfig({
  plugins: [
    hardhatMocha,
    hardhatViem
  ],

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
    // Exclude generated verifiers that cause YulException
    ignoreFiles: ["**/generated/**"]
  },
  
  solidity: {
    compilers: [
      {
        version: "0.8.20",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
            details: {
              yul: true,
              yulDetails: {
                stackAllocation: true,
                optimizerSteps: "dhfoDgvulfnTUtnIf"  // Minimal optimizer steps
              }
            }
          },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      {
        version: "0.8.22",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200  // Reduced from 10000 for viaIR compatibility
          },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      {
        version: "0.8.24",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200  // Reduced from 10000 to help with stack depth
          },
          viaIR: true,
          evmVersion: "cancun"  // Required for mcopy opcode
        }
      }
    ],
    // Per-file overrides for complex contracts that cause YulException
    // Use minimal optimizer runs to reduce stack complexity during optimization
    overrides: {
      // Core complex contracts - use minimal optimizer runs
      "contracts/bridge/CrossChainProofHubV3.sol": {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      "contracts/core/ConfidentialStateContainerV3.sol": {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      "contracts/core/NullifierRegistryV3.sol": {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      "contracts/primitives/ZKBoundStateLocks.sol": {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      // Verifier contracts with heavy assembly
      "contracts/verifiers/Groth16VerifierBN254.sol": {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      // Security module inherited by many contracts
      "contracts/security/SecurityModule.sol": {
        version: "0.8.20",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "paris"
        }
      },
      // Privacy contracts
      "contracts/privacy/CrossChainPrivacyHub.sol": {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "cancun"
        }
      },
      "contracts/privacy/UnifiedNullifierManager.sol": {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "cancun"
        }
      },
      // Upgradeable privacy contracts
      "contracts/upgradeable/UniversalShieldedPoolUpgradeable.sol": {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "cancun"
        }
      },
      "contracts/upgradeable/PrivacyRouterUpgradeable.sol": {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 1 },
          viaIR: true,
          evmVersion: "cancun"
        }
      },
      // Cross-chain commitment relay
      "contracts/crosschain/CrossChainCommitmentRelay.sol": {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          viaIR: true,
          evmVersion: "cancun"
        }
      }
    }
  },
  
  networks: {
    hardhat: {
      type: "edr-simulated",
      allowUnlimitedContractSize: true
    },
    
    // Testnets
    sepolia: {
      type: "http",
      url: process.env.SEPOLIA_RPC_URL || "https://rpc.sepolia.org",
      accounts: [PRIVATE_KEY],
      chainId: 11155111
    },
    arbitrumSepolia: {
      type: "http",
      url: process.env.ARBITRUM_SEPOLIA_RPC_URL || "https://sepolia-rollup.arbitrum.io/rpc",
      accounts: [PRIVATE_KEY],
      chainId: 421614
    },
    baseSepolia: {
      type: "http",
      url: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
      accounts: [PRIVATE_KEY],
      chainId: 84532
    },
    optimismSepolia: {
      type: "http",
      url: process.env.OPTIMISM_SEPOLIA_RPC_URL || "https://sepolia.optimism.io",
      accounts: [PRIVATE_KEY],
      chainId: 11155420
    },
    polygonAmoy: {
      type: "http",
      url: process.env.POLYGON_AMOY_RPC_URL || "https://rpc-amoy.polygon.technology",
      accounts: [PRIVATE_KEY],
      chainId: 80002
    },
    
    // Mainnets
    mainnet: {
      type: "http",
      url: process.env.MAINNET_RPC_URL || "https://eth.llamarpc.com",
      accounts: [PRIVATE_KEY],
      chainId: 1
    },
    polygon: {
      type: "http",
      url: process.env.POLYGON_RPC_URL || "https://polygon-rpc.com",
      accounts: [PRIVATE_KEY],
      chainId: 137
    },
    arbitrum: {
      type: "http",
      url: process.env.ARBITRUM_RPC_URL || "https://arb1.arbitrum.io/rpc",
      accounts: [PRIVATE_KEY],
      chainId: 42161
    },
    base: {
      type: "http",
      url: process.env.BASE_RPC_URL || "https://mainnet.base.org",
      accounts: [PRIVATE_KEY],
      chainId: 8453
    },
    optimism: {
      type: "http",
      url: process.env.OPTIMISM_RPC_URL || "https://mainnet.optimism.io",
      accounts: [PRIVATE_KEY],
      chainId: 10
    },

    // zkSync Era
    zkSync: {
      type: "http",
      url: process.env.ZKSYNC_RPC_URL || "https://mainnet.era.zksync.io",
      accounts: [PRIVATE_KEY],
      chainId: 324
    },
    zkSyncSepolia: {
      type: "http",
      url: process.env.ZKSYNC_SEPOLIA_RPC_URL || "https://sepolia.era.zksync.dev",
      accounts: [PRIVATE_KEY],
      chainId: 300
    },

    // Scroll
    scroll: {
      type: "http",
      url: process.env.SCROLL_RPC_URL || "https://rpc.scroll.io",
      accounts: [PRIVATE_KEY],
      chainId: 534352
    },
    scrollSepolia: {
      type: "http",
      url: process.env.SCROLL_SEPOLIA_RPC_URL || "https://sepolia-rpc.scroll.io",
      accounts: [PRIVATE_KEY],
      chainId: 534351
    },

    // Linea
    linea: {
      type: "http",
      url: process.env.LINEA_RPC_URL || "https://rpc.linea.build",
      accounts: [PRIVATE_KEY],
      chainId: 59144
    },
    lineaSepolia: {
      type: "http",
      url: process.env.LINEA_SEPOLIA_RPC_URL || "https://rpc.sepolia.linea.build",
      accounts: [PRIVATE_KEY],
      chainId: 59141
    },

    // Polygon zkEVM
    polygonZkEVM: {
      type: "http",
      url: process.env.POLYGON_ZKEVM_RPC_URL || "https://zkevm-rpc.com",
      accounts: [PRIVATE_KEY],
      chainId: 1101
    },
    polygonZkEVMTestnet: {
      type: "http",
      url: process.env.POLYGON_ZKEVM_TESTNET_RPC_URL || "https://rpc.cardona.zkevm-rpc.com",
      accounts: [PRIVATE_KEY],
      chainId: 2442
    }
  },
  
  test: {
    mocha: {
      timeout: 120000 // 2 minutes
    }
  }
});
