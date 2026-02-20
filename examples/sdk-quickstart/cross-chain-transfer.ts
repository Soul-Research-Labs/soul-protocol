/**
 * Soul Protocol — Cross-Chain Private Transfer Example
 *
 * Uses the CrossChainPrivacyOrchestrator to send a private transfer
 * from one L2 to another.  The orchestrator coordinates:
 *   1. Secret / commitment / nullifier generation
 *   2. ZK proof generation via the ProverModule
 *   3. Relaying the encrypted state to the destination chain
 */
import {
  CrossChainPrivacyOrchestrator,
  type OrchestratorConfig,
  type ChainConfig,
  type RelayerType,
} from "../../sdk/src/privacy/CrossChainPrivacyOrchestrator";

// --- Configuration -----------------------------------------------------------
const config: OrchestratorConfig = {
  // chains is a Record<number, ChainConfig> (not a Map)
  chains: {
    11155111: {
      chainId: 11155111,
      name: "Sepolia",
      rpcUrl: process.env.SEPOLIA_RPC_URL ?? "https://rpc.sepolia.org",
      privacyHub: process.env.SEPOLIA_PRIVACY_HUB as `0x${string}`,
      nullifierRegistry: process.env.SEPOLIA_NULLIFIER as `0x${string}`,
      stealthRegistry: process.env.SEPOLIA_STEALTH as `0x${string}`,
    },
    421614: {
      chainId: 421614,
      name: "Arbitrum Sepolia",
      rpcUrl:
        process.env.ARB_SEPOLIA_RPC_URL ??
        "https://sepolia-rollup.arbitrum.io/rpc",
      privacyHub: process.env.ARB_PRIVACY_HUB as `0x${string}`,
      nullifierRegistry: process.env.ARB_NULLIFIER as `0x${string}`,
      stealthRegistry: process.env.ARB_STEALTH as `0x${string}`,
    },
  },
  privateKey: process.env.PRIVATE_KEY as `0x${string}`,
  relayerType: "layerzero" as RelayerType,
  proverUrl: process.env.PROVER_URL ?? "http://localhost:3001",
  relayerUrl: process.env.RELAYER_URL ?? "http://localhost:3002",
};

async function main() {
  if (!config.privateKey) throw new Error("Set PRIVATE_KEY env var");

  const orchestrator = new CrossChainPrivacyOrchestrator(config);

  // 1. Generate cryptographic material
  const secret = orchestrator.generateSecret();
  console.log("Generated secret (32 bytes hex):", secret.slice(0, 18) + "...");

  const recipientAddress = "0x000000000000000000000000000000000000dEaD";
  const amount = BigInt(10_000); // smallest unit

  const commitment = orchestrator.computeCommitment(
    amount,
    secret,
    recipientAddress,
  );
  console.log("Commitment:", commitment);

  // deriveNullifier takes a single object param: { secret, commitment }
  const nullifier = orchestrator.deriveNullifier({ secret, commitment });
  console.log("Nullifier: ", nullifier);

  // 2. Generate ZK proof (requires a running prover server)
  //    Uncomment when the prover service is available:
  //
  // const proof = await orchestrator.generateCrossChainProof({
  //   sourceChainId: 11155111,
  //   destChainId: 421614,
  //   commitment,
  //   nullifier,
  //   amount,
  // });
  // console.log("Proof generated:", proof.proof.length, "bytes");

  console.log("\n✅ Cryptographic material ready for cross-chain transfer.");
  console.log(
    "   Next: run a prover + relayer and call orchestrator.transferPrivateState()",
  );
}

main().catch(console.error);
