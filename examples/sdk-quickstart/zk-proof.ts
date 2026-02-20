/**
 * Soul Protocol — ZK Proof Generation & Relay Example
 *
 * Shows how to use the SoulSDK to send encrypted private state
 * across chains and subscribe to incoming state on the receiver side.
 */
import { SoulSDK } from "../../sdk/src/client/SoulSDK";
import type { SoulConfig } from "../../sdk/src/utils/crypto";

// --- Configuration -----------------------------------------------------------
const config: SoulConfig = {
  curve: "secp256k1",
  relayerEndpoint: process.env.RELAYER_URL ?? "http://localhost:3002",
  proverUrl: process.env.PROVER_URL ?? "http://localhost:3001",
  privateKey:
    process.env.PRIVATE_KEY ??
    "0x0000000000000000000000000000000000000000000000000000000000000001",
};

const DEST_CHAIN = process.env.DEST_CHAIN ?? "arbitrum-sepolia";
const LOCAL_CHAIN = process.env.LOCAL_CHAIN ?? "sepolia";

async function main() {
  // 1. Instantiate the SDK
  const sdk = new SoulSDK(config);

  // 2. Send encrypted private state across chains
  //    sendPrivateState handles encryption, proof generation, and relaying.
  console.log("Sending private state to", DEST_CHAIN, "...");
  const receipt = await sdk.sendPrivateState({
    sourceChain: LOCAL_CHAIN,
    destChain: DEST_CHAIN,
    payload: {
      amount: "1000",
      recipient: "0x000000000000000000000000000000000000dEaD",
    },
    circuitId: "shielded_pool",
    disclosurePolicy: {
      complianceLevel: "basic",
    },
  });
  console.log("Send receipt:", receipt.txHash, "status:", receipt.status);

  // 3. Subscribe to incoming private state (receiver side)
  //    receivePrivateState(chainId, callback) returns Promise<Subscription>
  console.log("\nListening for incoming private state on", LOCAL_CHAIN, "...");
  const sub = await sdk.receivePrivateState(LOCAL_CHAIN, (state) => {
    console.log("Received private state:", state.length, "bytes");
  });

  // Clean up after 10 seconds
  setTimeout(() => {
    sub.unsubscribe();
    console.log("\n✅ Done.");
  }, 10_000);
}

main().catch(console.error);
