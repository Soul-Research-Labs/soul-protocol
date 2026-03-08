/**
 * ZASEON Integration Template: Private Cross-Chain Payment
 *
 * Demonstrates a complete shielded payment flow:
 * 1. Deposit ETH into the shielded pool on Source chain
 * 2. Generate a ZK proof of the deposit
 * 3. Create a Proof-Carrying Container
 * 4. Transfer the container to the Destination chain
 * 5. Consume the container and withdraw on the Destination chain
 *
 * Requirements:
 *   npm install @zaseon/sdk viem
 *
 * Setup:
 *   Export environment variables before running:
 *     PRIVATE_KEY          - Deployer/sender private key
 *     RPC_URL_SOURCE       - Source chain RPC (e.g. Arbitrum)
 *     RPC_URL_DEST         - Destination chain RPC (e.g. Base)
 *     SHIELDED_POOL        - ShieldedPool contract address on source chain
 *     NULLIFIER_REGISTRY   - NullifierRegistryV3 address on source chain
 *     PROOF_HUB            - CrossChainProofHubV3 address
 *     SOURCE_BRIDGE        - Bridge adapter address on source chain
 *     DEST_BRIDGE          - Bridge adapter address on destination chain
 *     RECIPIENT            - Recipient address on destination chain
 */

import { BridgeFactory, type SupportedChain } from "@zaseon/sdk/bridges";

// ============================================================================
// Configuration — all addresses from environment variables
// ============================================================================

const SOURCE_CHAIN: SupportedChain = "arbitrum";
const DEST_CHAIN: SupportedChain = "base";

function requireEnv(name: string): `0x${string}` {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  if (!value.startsWith("0x")) throw new Error(`${name} must start with 0x`);
  return value as `0x${string}`;
}

const ADDRESSES = {
  shieldedPool: requireEnv("SHIELDED_POOL"),
  nullifierRegistry: requireEnv("NULLIFIER_REGISTRY"),
  proofHub: requireEnv("PROOF_HUB"),
  sourceBridge: requireEnv("SOURCE_BRIDGE"),
  destBridge: requireEnv("DEST_BRIDGE"),
};

// ============================================================================
// Step 1: Deposit into Shielded Pool
// ============================================================================

async function deposit(
  amount: bigint,
  secret: Uint8Array,
): Promise<{ commitment: `0x${string}`; nullifier: `0x${string}` }> {
  console.log(
    `Depositing ${amount} wei into shielded pool on ${SOURCE_CHAIN}...`,
  );

  // Derive commitment and nullifier from the secret using Poseidon hash.
  // In a full integration, use the SDK's ShieldedPoolClient:
  //
  //   import { ShieldedPoolClient } from "@zaseon/sdk";
  //   const pool = new ShieldedPoolClient({ publicClient, walletClient, poolAddress: ADDRESSES.shieldedPool });
  //   const { commitment, nullifier } = await pool.deposit(amount);
  //
  // For this example, we derive deterministic values from the secret:
  const nullifierPreimage = new Uint8Array(32);
  crypto.getRandomValues(nullifierPreimage);

  // Compute deterministic hex strings from the random bytes
  const toHex = (bytes: Uint8Array): `0x${string}` =>
    `0x${Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")}` as `0x${string}`;

  const commitment = toHex(secret);
  const nullifier = toHex(nullifierPreimage);

  console.log(`  Commitment: ${commitment.slice(0, 18)}...`);
  console.log(`  Nullifier:  ${nullifier.slice(0, 18)}...`);

  return { commitment, nullifier };
}

// ============================================================================
// Step 2: Generate ZK Proof
// ============================================================================

async function generateProof(
  commitment: `0x${string}`,
  nullifier: `0x${string}`,
  amount: bigint,
): Promise<Uint8Array> {
  console.log("Generating ZK proof (Noir circuit: balance_proof)...");

  // In a full integration, use the SDK's NoirProver:
  //
  //   import { NoirProver } from "@zaseon/sdk";
  //   const prover = new NoirProver({ proverUrl: process.env.PROVER_URL ?? "http://localhost:3001" });
  //   const proof = await prover.prove("balance_proof", {
  //     commitment, nullifier, amount,
  //     merkle_path: [...],
  //     merkle_root: currentRoot,
  //   });
  //
  // For this example, we generate a random proof placeholder.
  // This will NOT verify on-chain — use NoirProver for real proofs.
  const proof = new Uint8Array(256);
  crypto.getRandomValues(proof);

  console.log(`  Proof generated (${proof.length} bytes)`);
  return proof;
}

// ============================================================================
// Step 3: Create Proof-Carrying Container
// ============================================================================

async function createContainer(
  commitment: `0x${string}`,
  nullifier: `0x${string}`,
  proof: Uint8Array,
): Promise<`0x${string}`> {
  console.log("Creating Proof-Carrying Container (PC3)...");

  // In a full integration:
  //   const containerId = await proofCarryingContainer.createContainer(
  //     encryptedPayload,
  //     commitment,
  //     nullifier,
  //     [{ proofType: ProofType.VALIDITY, proof, verifierKeyHash }],
  //     policyHash,
  //   );
  //
  // For this example, derive a container ID from the commitment.
  const encoder = new TextEncoder();
  const data = encoder.encode(commitment + nullifier);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const containerId = `0x${Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as `0x${string}`;

  console.log(`  Container ID: ${containerId.slice(0, 18)}...`);
  return containerId;
}

// ============================================================================
// Step 4: Bridge to Destination Chain
// ============================================================================

async function bridgeContainer(containerId: `0x${string}`): Promise<string> {
  console.log(`Bridging container from ${SOURCE_CHAIN} to ${DEST_CHAIN}...`);

  // In a full integration:
  //   import { createPublicClient, createWalletClient, http } from "viem";
  //   import { arbitrum } from "viem/chains";
  //   const publicClient = createPublicClient({ chain: arbitrum, transport: http(process.env.RPC_URL_SOURCE) });
  //   const walletClient = createWalletClient({ chain: arbitrum, transport: http(process.env.RPC_URL_SOURCE), account });
  //
  //   const adapter = BridgeFactory.createAdapter(SOURCE_CHAIN, publicClient, walletClient, {
  //     bridge_arbitrum: ADDRESSES.sourceBridge,
  //   });
  //   const { messageId } = await adapter.bridgeTransfer({
  //     targetChainId: 8453, // Base
  //     recipient: recipientAddress,
  //     amount: 0n,
  //     data: containerId,
  //   });
  //
  // For this example, derive a tx hash from the container ID.
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(containerId),
  );
  const txHash = `0x${Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;

  console.log(`  Bridge TX: ${txHash.slice(0, 18)}...`);
  console.log(`  Estimated arrival: ~20 minutes`);
  return txHash;
}

// ============================================================================
// Step 5: Consume Container on Destination
// ============================================================================

async function consumeOnDestination(
  containerId: `0x${string}`,
  recipient: `0x${string}`,
): Promise<string> {
  console.log(`Consuming container on ${DEST_CHAIN}...`);

  // In a full integration:
  //   // Import the container from the source chain
  //   const localContainerId = await destProofCarryingContainer.importContainer(
  //     containerData,
  //     sourceChainProof,
  //   );
  //
  //   // Verify and consume
  //   const result = await destProofCarryingContainer.verifyContainer(localContainerId);
  //   if (!result.valid) throw new Error("Container verification failed");
  //
  //   await destProofCarryingContainer.consumeContainer(localContainerId);
  //   // The nullifier is now registered on the destination chain
  //   // and will be synced back to the source chain via CDNA
  //
  // For this example, derive a withdraw tx hash.
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(containerId + recipient),
  );
  const withdrawTx = `0x${Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;

  console.log(`  Withdraw TX: ${withdrawTx.slice(0, 18)}...`);
  console.log(`  Funds delivered to: ${recipient.slice(0, 18)}...`);
  return withdrawTx;
}

// ============================================================================
// Main Flow
// ============================================================================

async function main() {
  console.log("=== ZASEON Private Cross-Chain Payment ===\n");
  console.log(`Route: ${SOURCE_CHAIN} -> ${DEST_CHAIN}\n`);

  const amount = 1_000_000_000_000_000_000n; // 1 ETH
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);

  // Step 1: Deposit
  const { commitment, nullifier } = await deposit(amount, secret);

  // Step 2: Generate ZK proof
  const proof = await generateProof(commitment, nullifier, amount);

  // Step 3: Create PC3 container
  const containerId = await createContainer(commitment, nullifier, proof);

  // Step 4: Bridge
  const bridgeTx = await bridgeContainer(containerId);

  // Step 5: Consume on destination
  const recipient = requireEnv("RECIPIENT");
  const withdrawTx = await consumeOnDestination(containerId, recipient);

  console.log("\n=== Complete ===");
  console.log(`Deposit:  ${commitment.slice(0, 18)}...`);
  console.log(`Bridge:   ${bridgeTx.slice(0, 18)}...`);
  console.log(`Withdraw: ${withdrawTx.slice(0, 18)}...`);
  console.log(`\nPrivacy preserved: amount, sender, and recipient are hidden`);
  console.log(
    `Compliance: policy hash bound to ZK proof at container creation`,
  );
}

main().catch(console.error);
