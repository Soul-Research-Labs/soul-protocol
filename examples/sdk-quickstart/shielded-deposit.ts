/**
 * ZASEON — Shielded Pool Deposit Example
 *
 * Demonstrates depositing ETH into the UniversalShieldedPool.
 * The pool uses a Merkle tree of commitments so that withdrawals
 * can later prove inclusion without revealing the depositor.
 */
import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { createShieldedPoolClient } from "../../sdk/src/client/ShieldedPoolClient";

// --- Configuration -----------------------------------------------------------
const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;
const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";
const SHIELDED_POOL = process.env.SHIELDED_POOL_ADDRESS as `0x${string}`;

async function main() {
  if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY env var");
  if (!SHIELDED_POOL) throw new Error("Set SHIELDED_POOL_ADDRESS env var");

  const account = privateKeyToAccount(PRIVATE_KEY);
  const transport = http(RPC_URL);

  const publicClient = createPublicClient({ chain: sepolia, transport });
  const walletClient = createWalletClient({
    chain: sepolia,
    transport,
    account,
  });

  // 1. Create the shielded pool client
  const pool = createShieldedPoolClient({
    publicClient: publicClient as any,
    walletClient: walletClient as any,
    poolAddress: SHIELDED_POOL,
  });

  // 2. Generate a deposit note (commitment + nullifier + secret)
  //    generateDepositNote(amount, asset?) returns { commitment, secret, nullifier, amount, asset }
  const depositAmount = parseEther("0.01");
  const note = pool.generateDepositNote(depositAmount);
  console.log("Deposit note generated:");
  console.log("  commitment:", note.commitment);
  console.log("  nullifier: ", note.nullifier);
  console.log("  secret:    ", note.secret);
  console.log(
    "\n⚠️  Save the secret and nullifier — they are needed to withdraw!\n",
  );

  // 3. Deposit 0.01 ETH into the pool
  console.log(`Depositing ${depositAmount} wei...`);
  const { leafIndex, txHash } = await pool.depositETH(
    note.commitment,
    depositAmount,
  );
  console.log("Deposit tx:", txHash);
  console.log("Leaf index:", leafIndex);

  // 4. Read pool stats
  const stats = await pool.getPoolStats();
  console.log("\nPool stats after deposit:");
  console.log("  total deposits:", stats.totalDeposits.toString());
  console.log("  total withdrawals:", stats.totalWithdrawals.toString());
  console.log("  next leaf index:", stats.nextLeafIndex.toString());
}

main().catch(console.error);
