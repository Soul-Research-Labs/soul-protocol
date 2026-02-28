/**
 * ZASEON — Dynamic Routing Example
 *
 * Demonstrates the capacity-aware cross-chain routing system:
 *   1. Query the DynamicRoutingOrchestrator for optimal routes
 *   2. Check capacity availability across bridges
 *   3. Execute a routed cross-chain transfer
 *   4. Monitor bridge outcomes for reliability scoring
 */
import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// ─── Configuration ──────────────────────────────────────────────────────────
const ORCHESTRATOR_ADDRESS = process.env
  .DYNAMIC_ROUTING_ORCHESTRATOR as `0x${string}`;
const CAPACITY_ROUTER_ADDRESS = process.env
  .CAPACITY_AWARE_ROUTER as `0x${string}`;
const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;

// ─── Minimal ABIs ───────────────────────────────────────────────────────────
const OrchestratorABI = [
  {
    name: "getOptimalRoute",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "destChainId", type: "uint256" },
      { name: "amount", type: "uint256" },
      { name: "token", type: "address" },
    ],
    outputs: [
      { name: "bridgeId", type: "bytes32" },
      { name: "estimatedFee", type: "uint256" },
      { name: "estimatedTime", type: "uint256" },
      { name: "score", type: "uint256" },
    ],
  },
  {
    name: "getBridgeCapacity",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "token", type: "address" },
    ],
    outputs: [
      { name: "available", type: "uint256" },
      { name: "total", type: "uint256" },
      { name: "utilizationBps", type: "uint256" },
    ],
  },
] as const;

const RouterABI = [
  {
    name: "initiateTransfer",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "destChainId", type: "uint256" },
      { name: "recipient", type: "address" },
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "transferId", type: "bytes32" }],
  },
] as const;

async function main() {
  if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY env var");
  if (!ORCHESTRATOR_ADDRESS)
    throw new Error("Set DYNAMIC_ROUTING_ORCHESTRATOR env var");
  if (!CAPACITY_ROUTER_ADDRESS)
    throw new Error("Set CAPACITY_AWARE_ROUTER env var");

  const account = privateKeyToAccount(PRIVATE_KEY);

  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(process.env.SEPOLIA_RPC_URL),
  });

  const walletClient = createWalletClient({
    account,
    chain: sepolia,
    transport: http(process.env.SEPOLIA_RPC_URL),
  });

  const ETH_ADDRESS =
    "0x0000000000000000000000000000000000000000" as `0x${string}`;
  const DEST_CHAIN = 421614n; // Arbitrum Sepolia
  const AMOUNT = parseEther("0.5");

  // ─── 1. Query Optimal Route ─────────────────────────────────────────────
  console.log("Querying optimal route for 0.5 ETH → Arbitrum Sepolia...\n");

  const [bridgeId, estimatedFee, estimatedTime, score] =
    (await publicClient.readContract({
      address: ORCHESTRATOR_ADDRESS,
      abi: OrchestratorABI,
      functionName: "getOptimalRoute",
      args: [11155111n, DEST_CHAIN, AMOUNT, ETH_ADDRESS],
    })) as [bigint, bigint, bigint, bigint];

  console.log("Route selected:");
  console.log("  Bridge ID:      ", bridgeId.toString(16));
  console.log("  Estimated fee:  ", estimatedFee.toString(), "wei");
  console.log("  Estimated time: ", estimatedTime.toString(), "seconds");
  console.log("  Reliability:    ", score.toString(), "/ 10000");

  // ─── 2. Check Capacity ─────────────────────────────────────────────────
  console.log("\nChecking destination capacity...");

  const [available, total, utilizationBps] = (await publicClient.readContract({
    address: ORCHESTRATOR_ADDRESS,
    abi: OrchestratorABI,
    functionName: "getBridgeCapacity",
    args: [DEST_CHAIN, ETH_ADDRESS],
  })) as [bigint, bigint, bigint];

  console.log("Bridge capacity:");
  console.log("  Available:   ", available.toString(), "wei");
  console.log("  Total:       ", total.toString(), "wei");
  console.log(
    "  Utilization: ",
    (Number(utilizationBps) / 100).toFixed(1),
    "%",
  );

  // ─── 3. Execute Transfer via CapacityAwareRouter ───────────────────────
  if (available < AMOUNT) {
    console.log("\n⚠️  Insufficient capacity. Skipping transfer.");
    return;
  }

  console.log("\nInitiating routed transfer...");
  const recipient = account.address;

  const transferHash = await walletClient.writeContract({
    address: CAPACITY_ROUTER_ADDRESS,
    abi: RouterABI,
    functionName: "initiateTransfer",
    args: [DEST_CHAIN, recipient, ETH_ADDRESS, AMOUNT],
    value: AMOUNT + estimatedFee,
  });

  console.log("Transfer initiated, tx:", transferHash);
  console.log(
    "\n✅ Dynamic routing complete! Transfer will arrive on destination chain",
    "in ~" + estimatedTime.toString() + " seconds.",
  );
}

main().catch(console.error);
