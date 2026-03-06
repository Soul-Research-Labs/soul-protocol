/**
 * ZASEON — Relayer Registration Example
 *
 * Demonstrates how to register as a decentralized relayer:
 *   1. Check registration requirements (minimum stake)
 *   2. Register with stake deposit
 *   3. Query relayer status
 *   4. Monitor health and reputation
 */
import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
  formatEther,
  getContract,
} from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// --- Configuration -----------------------------------------------------------
const RELAYER_REGISTRY = process.env.RELAYER_REGISTRY as `0x${string}`;
const RELAYER_KEY = process.env.RELAYER_PRIVATE_KEY as `0x${string}`;
const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";

// Minimal ABI for DecentralizedRelayerRegistry
const RELAYER_REGISTRY_ABI = [
  {
    name: "register",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "endpoint", type: "string" },
      { name: "supportedChains", type: "uint256[]" },
    ],
    outputs: [],
  },
  {
    name: "unregister",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "getRelayer",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "relayer", type: "address" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "active", type: "bool" },
          { name: "stake", type: "uint256" },
          { name: "endpoint", type: "string" },
          { name: "registeredAt", type: "uint256" },
          { name: "successCount", type: "uint256" },
          { name: "failureCount", type: "uint256" },
          { name: "reputation", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "isRelayerActive",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "relayer", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "minimumStake",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getActiveRelayerCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "RelayerRegistered",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "stake", type: "uint256", indexed: false },
      { name: "endpoint", type: "string", indexed: false },
    ],
  },
] as const;

async function main() {
  if (!RELAYER_REGISTRY) throw new Error("Set RELAYER_REGISTRY env var");
  if (!RELAYER_KEY) throw new Error("Set RELAYER_PRIVATE_KEY env var");

  const transport = http(RPC_URL);
  const account = privateKeyToAccount(RELAYER_KEY);

  const publicClient = createPublicClient({ chain: sepolia, transport });
  const walletClient = createWalletClient({
    chain: sepolia,
    transport,
    account,
  });

  const registry = getContract({
    address: RELAYER_REGISTRY,
    abi: RELAYER_REGISTRY_ABI,
    client: { public: publicClient, wallet: walletClient },
  });

  // --- 1. Check registration requirements ----------------------------------
  console.log("1. Checking registration requirements...");

  const minStake = await registry.read.minimumStake();
  console.log(`   Minimum stake: ${formatEther(minStake)} ETH`);

  const activeCount = await registry.read.getActiveRelayerCount();
  console.log(`   Active relayers: ${activeCount}`);

  const isAlreadyActive = await registry.read.isRelayerActive([
    account.address,
  ]);
  if (isAlreadyActive) {
    console.log("   ✅ Already registered as active relayer");
    const info = await registry.read.getRelayer([account.address]);
    console.log(`   Stake: ${formatEther(info.stake)} ETH`);
    console.log(`   Endpoint: ${info.endpoint}`);
    console.log(`   Success/Fail: ${info.successCount}/${info.failureCount}`);
    console.log(`   Reputation: ${info.reputation}`);
    return;
  }

  // --- 2. Register with stake -----------------------------------------------
  console.log("\n2. Registering as relayer...");

  // Stake 10% above minimum for safety margin
  const stakeAmount = minStake + minStake / 10n;
  console.log(`   Staking: ${formatEther(stakeAmount)} ETH`);

  // Supported chains: Arbitrum (42161), Optimism (10), Base (8453)
  const supportedChains = [42161n, 10n, 8453n];
  console.log(`   Supported chains: ${supportedChains.join(", ")}`);

  const txHash = await registry.write.register(
    ["https://relayer.example.com/api/v1", supportedChains],
    { value: stakeAmount },
  );
  console.log(`   Registration tx: ${txHash}`);

  // Wait for confirmation
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: txHash,
  });
  console.log(`   Confirmed in block: ${receipt.blockNumber}`);

  // --- 3. Verify registration -----------------------------------------------
  console.log("\n3. Verifying registration...");

  const relayerInfo = await registry.read.getRelayer([account.address]);
  console.log(`   Active: ${relayerInfo.active}`);
  console.log(`   Stake: ${formatEther(relayerInfo.stake)} ETH`);
  console.log(`   Endpoint: ${relayerInfo.endpoint}`);
  console.log(`   Registered at block: ${relayerInfo.registeredAt}`);

  // --- 4. Monitor health ----------------------------------------------------
  console.log("\n4. Relayer health status:");
  console.log(`   Success count: ${relayerInfo.successCount}`);
  console.log(`   Failure count: ${relayerInfo.failureCount}`);
  console.log(`   Reputation score: ${relayerInfo.reputation}`);

  const newActiveCount = await registry.read.getActiveRelayerCount();
  console.log(`   Total active relayers: ${newActiveCount}`);

  console.log("\n✅ Relayer registration complete!");
  console.log("   Your relayer will now be eligible for task assignment.");
  console.log(
    "   Monitor your reputation and maintain uptime for best results.",
  );
}

main().catch(console.error);
