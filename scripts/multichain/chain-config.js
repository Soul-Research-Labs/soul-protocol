const { ethers, network, run } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Soul v2 Multi-Chain Deployment Configuration
 * 
 * Chain-specific configurations for L2 deployments:
 * - Arbitrum One / Arbitrum Sepolia
 * - Optimism / OP Sepolia
 * - Base / Base Sepolia
 * - Polygon / Polygon Mumbai
 */

const CHAIN_CONFIGS = {
    // ============================================
    // MAINNET CHAINS
    // ============================================
    
    // Arbitrum One
    42161: {
        name: "Arbitrum One",
        rpcUrl: process.env.ARBITRUM_RPC_URL,
        explorerUrl: "https://arbiscan.io",
        explorerApiUrl: "https://api.arbiscan.io/api",
        explorerApiKey: process.env.ARBISCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.1", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600, // 48 hours for mainnet
        isTestnet: false,
    },

    // Optimism
    10: {
        name: "Optimism",
        rpcUrl: process.env.OPTIMISM_RPC_URL,
        explorerUrl: "https://optimistic.etherscan.io",
        explorerApiUrl: "https://api-optimistic.etherscan.io/api",
        explorerApiKey: process.env.OPTIMISM_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.001", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.01", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // Base
    8453: {
        name: "Base",
        rpcUrl: process.env.BASE_RPC_URL,
        explorerUrl: "https://basescan.org",
        explorerApiUrl: "https://api.basescan.org/api",
        explorerApiKey: process.env.BASESCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.001", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.01", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // Polygon
    137: {
        name: "Polygon",
        rpcUrl: process.env.POLYGON_RPC_URL,
        explorerUrl: "https://polygonscan.com",
        explorerApiUrl: "https://api.polygonscan.com/api",
        explorerApiKey: process.env.POLYGONSCAN_API_KEY,
        nativeToken: "MATIC",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("30", "gwei"),
            maxFeePerGas: ethers.parseUnits("100", "gwei"),
        },
        confirmations: 10,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // zkSync Era
    324: {
        name: "zkSync Era",
        rpcUrl: process.env.ZKSYNC_RPC_URL,
        explorerUrl: "https://explorer.zksync.io",
        explorerApiUrl: "https://block-explorer-api.mainnet.zksync.io/api",
        explorerApiKey: process.env.ZKSYNC_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.25", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // Scroll
    534352: {
        name: "Scroll",
        rpcUrl: process.env.SCROLL_RPC_URL,
        explorerUrl: "https://scrollscan.com",
        explorerApiUrl: "https://api.scrollscan.com/api",
        explorerApiKey: process.env.SCROLLSCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.001", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.01", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // Linea
    59144: {
        name: "Linea",
        rpcUrl: process.env.LINEA_RPC_URL,
        explorerUrl: "https://lineascan.build",
        explorerApiUrl: "https://api.lineascan.build/api",
        explorerApiKey: process.env.LINEASCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.1", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // Polygon zkEVM
    1101: {
        name: "Polygon zkEVM",
        rpcUrl: process.env.POLYGON_ZKEVM_RPC_URL,
        explorerUrl: "https://zkevm.polygonscan.com",
        explorerApiUrl: "https://api-zkevm.polygonscan.com/api",
        explorerApiKey: process.env.POLYGON_ZKEVM_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
            maxFeePerGas: ethers.parseUnits("5", "gwei"),
        },
        confirmations: 5,
        timelockDelay: 48 * 3600,
        isTestnet: false,
    },

    // ============================================
    // TESTNET CHAINS
    // ============================================

    // Arbitrum Sepolia
    421614: {
        name: "Arbitrum Sepolia",
        rpcUrl: process.env.ARBITRUM_SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia.arbiscan.io",
        explorerApiUrl: "https://api-sepolia.arbiscan.io/api",
        explorerApiKey: process.env.ARBISCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.1", "gwei"),
            maxFeePerGas: ethers.parseUnits("1", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600, // 1 hour for testnet
        isTestnet: true,
    },

    // OP Sepolia
    11155420: {
        name: "OP Sepolia",
        rpcUrl: process.env.OP_SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia-optimism.etherscan.io",
        explorerApiUrl: "https://api-sepolia-optimistic.etherscan.io/api",
        explorerApiKey: process.env.OPTIMISM_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.1", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Base Sepolia
    84532: {
        name: "Base Sepolia",
        rpcUrl: process.env.BASE_SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia.basescan.org",
        explorerApiUrl: "https://api-sepolia.basescan.org/api",
        explorerApiKey: process.env.BASESCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.1", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Polygon Amoy (Mumbai replacement)
    80002: {
        name: "Polygon Amoy",
        rpcUrl: process.env.POLYGON_AMOY_RPC_URL,
        explorerUrl: "https://amoy.polygonscan.com",
        explorerApiUrl: "https://api-amoy.polygonscan.com/api",
        explorerApiKey: process.env.POLYGONSCAN_API_KEY,
        nativeToken: "MATIC",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("30", "gwei"),
            maxFeePerGas: ethers.parseUnits("50", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // zkSync Era Sepolia
    300: {
        name: "zkSync Sepolia",
        rpcUrl: process.env.ZKSYNC_SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia.explorer.zksync.io",
        explorerApiUrl: "https://block-explorer-api.sepolia.zksync.dev/api",
        explorerApiKey: process.env.ZKSYNC_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.25", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Scroll Sepolia
    534351: {
        name: "Scroll Sepolia",
        rpcUrl: process.env.SCROLL_SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia.scrollscan.com",
        explorerApiUrl: "https://api-sepolia.scrollscan.com/api",
        explorerApiKey: process.env.SCROLLSCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.001", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.01", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Linea Sepolia
    59141: {
        name: "Linea Sepolia",
        rpcUrl: process.env.LINEA_SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia.lineascan.build",
        explorerApiUrl: "https://api-sepolia.lineascan.build/api",
        explorerApiKey: process.env.LINEASCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("0.01", "gwei"),
            maxFeePerGas: ethers.parseUnits("0.1", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Polygon zkEVM Cardona
    2442: {
        name: "Polygon zkEVM Cardona",
        rpcUrl: process.env.POLYGON_ZKEVM_TESTNET_RPC_URL,
        explorerUrl: "https://cardona-zkevm.polygonscan.com",
        explorerApiUrl: "https://api-cardona-zkevm.polygonscan.com/api",
        explorerApiKey: process.env.POLYGON_ZKEVM_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
            maxFeePerGas: ethers.parseUnits("5", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Sepolia (Ethereum testnet)
    11155111: {
        name: "Sepolia",
        rpcUrl: process.env.SEPOLIA_RPC_URL,
        explorerUrl: "https://sepolia.etherscan.io",
        explorerApiUrl: "https://api-sepolia.etherscan.io/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY,
        nativeToken: "ETH",
        gasConfig: {
            maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
            maxFeePerGas: ethers.parseUnits("20", "gwei"),
        },
        confirmations: 2,
        timelockDelay: 1 * 3600,
        isTestnet: true,
    },

    // Localhost
    31337: {
        name: "Localhost",
        rpcUrl: "http://127.0.0.1:8545",
        explorerUrl: null,
        explorerApiUrl: null,
        explorerApiKey: null,
        nativeToken: "ETH",
        gasConfig: {},
        confirmations: 1,
        timelockDelay: 60, // 1 minute for local
        isTestnet: true,
    },
};

/**
 * Get chain configuration
 */
function getChainConfig(chainId) {
    const config = CHAIN_CONFIGS[chainId];
    if (!config) {
        throw new Error(`Unsupported chain ID: ${chainId}`);
    }
    return config;
}

/**
 * Get all supported chains
 */
function getSupportedChains() {
    return Object.entries(CHAIN_CONFIGS).map(([chainId, config]) => ({
        chainId: parseInt(chainId),
        name: config.name,
        isTestnet: config.isTestnet,
    }));
}

/**
 * Get deployment directory for chain
 */
function getDeploymentDir(chainId) {
    const config = getChainConfig(chainId);
    const dir = path.join(__dirname, "..", "deployments", `${config.name.toLowerCase().replace(/\s+/g, "-")}-${chainId}`);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
}

/**
 * Save deployment to file
 */
function saveDeployment(chainId, deployment) {
    const dir = getDeploymentDir(chainId);
    const filename = path.join(dir, "deployment.json");
    fs.writeFileSync(filename, JSON.stringify(deployment, null, 2));
    console.log(`📄 Deployment saved to: ${filename}`);
}

/**
 * Load existing deployment
 */
function loadDeployment(chainId) {
    const dir = getDeploymentDir(chainId);
    const filename = path.join(dir, "deployment.json");
    if (fs.existsSync(filename)) {
        return JSON.parse(fs.readFileSync(filename, "utf8"));
    }
    return null;
}

module.exports = {
    CHAIN_CONFIGS,
    getChainConfig,
    getSupportedChains,
    getDeploymentDir,
    saveDeployment,
    loadDeployment,
};
