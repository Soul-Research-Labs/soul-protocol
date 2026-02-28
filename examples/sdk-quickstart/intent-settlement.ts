/**
 * ZASEON — Intent Settlement Example
 *
 * Demonstrates the solver marketplace for cross-chain operations:
 *   1. Submit an intent (desired cross-chain outcome)
 *   2. Register as a solver with staked collateral
 *   3. Claim, fulfill, and finalize an intent
 *   4. (Optional) Post an instant settlement guarantee
 */
import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { sepolia, arbitrumSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// ─── Configuration ──────────────────────────────────────────────────────────
const INTENT_SETTLEMENT_ADDRESS = process.env
  .INTENT_SETTLEMENT_ADDRESS as `0x${string}`;
const INSTANT_GUARANTEE_ADDRESS = process.env
  .INSTANT_GUARANTEE_ADDRESS as `0x${string}`;
const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;

// ─── Minimal ABIs ───────────────────────────────────────────────────────────
const IntentSettlementABI = [
  {
    name: "submitIntent",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "destChainId", type: "uint256" },
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "maxFee", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
    outputs: [{ name: "intentId", type: "bytes32" }],
  },
  {
    name: "registerSolver",
    type: "function",
    stateMutability: "payable",
    inputs: [],
    outputs: [],
  },
  {
    name: "claimIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "fulfillIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "intentId", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "resultData", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "finalizeIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [],
  },
] as const;

async function main() {
  if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY env var");
  if (!INTENT_SETTLEMENT_ADDRESS)
    throw new Error("Set INTENT_SETTLEMENT_ADDRESS env var");

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

  // ─── 1. Submit an Intent ────────────────────────────────────────────────
  console.log("Submitting cross-chain intent...");

  const intentHash = await walletClient.writeContract({
    address: INTENT_SETTLEMENT_ADDRESS,
    abi: IntentSettlementABI,
    functionName: "submitIntent",
    args: [
      11155111n, // sourceChainId  (Sepolia)
      421614n, // destChainId    (Arbitrum Sepolia)
      "0x0000000000000000000000000000000000000000", // ETH
      parseEther("0.1"), // 0.1 ETH
      parseEther("0.005"), // max solver fee
      BigInt(Math.floor(Date.now() / 1000) + 3600), // 1 hour deadline
      "0x", // no extra calldata
    ],
    value: parseEther("0.105"), // amount + max fee
  });

  console.log("Intent submitted, tx:", intentHash);

  // ─── 2. Register as a Solver ────────────────────────────────────────────
  console.log("\nRegistering as solver with 1 ETH stake...");

  const registerHash = await walletClient.writeContract({
    address: INTENT_SETTLEMENT_ADDRESS,
    abi: IntentSettlementABI,
    functionName: "registerSolver",
    args: [],
    value: parseEther("1"),
  });

  console.log("Solver registered, tx:", registerHash);

  // ─── 3. Claim & Fulfill (in production, solvers run a bot) ──────────────
  // NOTE: In production the intentId comes from the IntentSubmitted event.
  // Here we use a placeholder — replace with the actual intentId from step 1.
  const intentId =
    "0x0000000000000000000000000000000000000000000000000000000000000001" as `0x${string}`;

  console.log("\nClaiming intent:", intentId);
  const claimHash = await walletClient.writeContract({
    address: INTENT_SETTLEMENT_ADDRESS,
    abi: IntentSettlementABI,
    functionName: "claimIntent",
    args: [intentId],
  });
  console.log("Intent claimed, tx:", claimHash);

  // Generate proof of fulfillment (placeholder — use NoirProver in production)
  const fulfillmentProof = "0x" as `0x${string}`;

  console.log("Fulfilling intent...");
  const fulfillHash = await walletClient.writeContract({
    address: INTENT_SETTLEMENT_ADDRESS,
    abi: IntentSettlementABI,
    functionName: "fulfillIntent",
    args: [intentId, fulfillmentProof, "0x"],
  });
  console.log("Intent fulfilled, tx:", fulfillHash);

  // After challenge period elapses:
  console.log("Finalizing intent (after challenge period)...");
  const finalizeHash = await walletClient.writeContract({
    address: INTENT_SETTLEMENT_ADDRESS,
    abi: IntentSettlementABI,
    functionName: "finalizeIntent",
    args: [intentId],
  });
  console.log("Intent finalized, tx:", finalizeHash);

  console.log("\n✅ Intent settlement lifecycle complete!");
}

main().catch(console.error);
