# Soul Protocol — Deployments

This directory contains deployment artifacts (contract addresses, ABIs, verification status) for each network.

## Deployment Status

| Network | Chain ID | Status | File |
|---------|----------|--------|------|
| **L1 Testnets** | | | |
| Sepolia | 11155111 | ✅ Deployed | `sepolia-11155111.json` |
| **L2 Testnets** | | | |
| Arbitrum Sepolia | 421614 | 🔲 Not deployed | — |
| Base Sepolia | 84532 | 🔲 Not deployed | — |
| Optimism Sepolia | 11155420 | 🔲 Not deployed | — |
| Scroll Sepolia | 534351 | 🔲 Not deployed | — |
| Linea Sepolia | 59141 | 🔲 Not deployed | — |
| **Mainnets** | | | |
| Ethereum | 1 | 🔲 Not deployed | — |
| Arbitrum One | 42161 | 🔲 Not deployed | — |
| Optimism | 10 | 🔲 Not deployed | — |
| Base | 8453 | 🔲 Not deployed | — |

## File Format

Each deployment file is a JSON document with the following schema:

```json
{
  "network": "sepolia",
  "chainId": 11155111,
  "deployer": "0x...",
  "timestamp": "2024-...",
  "contracts": {
    "ContractName": "0x..."
  }
}
```

## Deployment Runbook

### Prerequisites

1. Copy `.env.example` to `.env` and fill in:
   - `DEPLOYER_PRIVATE_KEY` — funded EOA on all target networks
   - RPC URLs for each target network
   - Block explorer API keys for verification

2. Fund the deployer address with testnet ETH on each target L2:
   - [Arbitrum Sepolia Faucet](https://faucet.quicknode.com/arbitrum/sepolia)
   - [Base Sepolia Faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet)
   - [Optimism Sepolia Faucet](https://app.optimism.io/faucet)
   - [Scroll Sepolia Faucet](https://scroll.io/bridge)
   - [Linea Sepolia Faucet](https://faucet.goerli.linea.build/)

### Step 1: Deploy to L2 Testnets (Foundry)

Deploy to each L2 testnet using the unified Foundry script:

```bash
# Arbitrum Sepolia
forge script scripts/deploy/DeployL2Testnet.s.sol \
  --rpc-url $ARBITRUM_SEPOLIA_RPC_URL \
  --broadcast --verify \
  --etherscan-api-key $ARBISCAN_API_KEY \
  -vvv

# Base Sepolia
forge script scripts/deploy/DeployL2Testnet.s.sol \
  --rpc-url $BASE_SEPOLIA_RPC_URL \
  --broadcast --verify \
  --etherscan-api-key $BASESCAN_API_KEY \
  -vvv

# Optimism Sepolia
forge script scripts/deploy/DeployL2Testnet.s.sol \
  --rpc-url $OPTIMISM_SEPOLIA_RPC_URL \
  --broadcast --verify \
  --etherscan-api-key $OPTIMISM_API_KEY \
  -vvv

# Scroll Sepolia
forge script scripts/deploy/DeployL2Testnet.s.sol \
  --rpc-url $SCROLL_SEPOLIA_RPC_URL \
  --broadcast --verify \
  --etherscan-api-key $SCROLLSCAN_API_KEY \
  -vvv

# Linea Sepolia
forge script scripts/deploy/DeployL2Testnet.s.sol \
  --rpc-url $LINEA_SEPOLIA_RPC_URL \
  --broadcast --verify \
  --etherscan-api-key $LINEASCAN_API_KEY \
  -vvv
```

### Step 2: Configure Cross-Chain Links

After deploying to all L2s, configure the L1 proof hub and L2 nullifier registries:

```bash
# On Sepolia L1 — register L2 chains with ProofHub
PROOF_HUB_ADDRESS=0x... \
forge script scripts/deploy/ConfigureCrossChain.s.sol \
  --rpc-url $SEPOLIA_RPC_URL \
  --broadcast -vvv

# On each L2 — register peer chain domains
NULLIFIER_REGISTRY=0x... \
forge script scripts/deploy/ConfigureCrossChain.s.sol \
  --rpc-url $ARBITRUM_SEPOLIA_RPC_URL \
  --broadcast -vvv
```

### Step 3: Verify Deployment

```bash
# Run post-deploy role verification
forge script scripts/deploy/ConfirmRoleSeparation.s.sol \
  --rpc-url $SEPOLIA_RPC_URL -vvv

# Run integration tests
npx hardhat test test/integration/ --network arbitrum-sepolia
```

### Alternative: Hardhat Deployment

For multi-chain deployment via Hardhat:

```bash
npx hardhat run scripts/deploy/deploy-testnet.ts --network arbitrum-sepolia
npx hardhat run scripts/deploy/deploy-testnet.ts --network base-sepolia
npx hardhat run scripts/deploy/deploy-testnet.ts --network optimism-sepolia
```

Or use the shell orchestrator:

```bash
bash scripts/deploy/deploy-all-testnets.sh
```

## Available Deploy Scripts

| Script | Tool | Purpose |
|--------|------|---------|
| `DeployMainnet.s.sol` | Foundry | L1 mainnet core contracts |
| `DeployL2Bridges.s.sol` | Foundry | L2 mainnet bridge adapters |
| `DeployL2Testnet.s.sol` | Foundry | L2 testnet full stack |
| `ConfigureCrossChain.s.sol` | Foundry | Post-deploy cross-chain linking |
| `ConfirmRoleSeparation.s.sol` | Foundry | Post-deploy role verification |
| `deploy-v3.ts` | Hardhat | V3 contract stack |
| `deploy-cross-chain.ts` | Hardhat | Cross-chain stack |
| `deploy-testnet.ts` | Hardhat | Multi-chain testnet |
| `deploy-all-testnets.sh` | Shell | Orchestrate all testnet deploys |

## Security Notes

- **Testnet deployments** use the deployer as admin for simplicity. Set `TESTNET_ADMIN` to use a separate admin.
- **Mainnet deployments** MUST use a Gnosis Safe multisig as admin. See `DeployMainnet.s.sol`.
- Always run `ConfirmRoleSeparation.s.sol` after mainnet deploys to verify deployer has renounced all roles.
- Keep deployment JSON files committed to track deployed addresses across environments.
