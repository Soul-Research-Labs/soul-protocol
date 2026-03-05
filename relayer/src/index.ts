/**
 * ZASEON Relayer Node - Entry Point
 *
 * Starts the decentralized relayer that watches for cross-chain events,
 * queues proof relay tasks, and submits proofs to destination chains.
 */

import { createPublicClient, createWalletClient, http, type Hex, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { EventWatcher } from "./watcher.js";
import { ProofQueue } from "./queue.js";
import { HealthReporter } from "./health.js";
import { type RelayerConfig, loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { RELAYER_REGISTRY_ABI } from "./abi.js";

const logger = createLogger("relayer");

async function main(): Promise<void> {
  logger.info("Starting ZASEON Relayer Node...");

  const config = loadConfig();
  logger.info({ chains: config.chains }, "Loaded configuration");

  // Initialize components
  const queue = new ProofQueue(config);
  const watcher = new EventWatcher(config, queue);
  const health = new HealthReporter(config, queue);

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info({ signal }, "Shutting down...");
    await watcher.stop();
    await queue.drain();
    await health.stop();
    process.exit(0);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // Register on-chain if configured
  await ensureRegistered(config);

  // Start services
  await health.start();
  await queue.start();
  await watcher.start();

  logger.info("ZASEON Relayer Node is running");
}

main().catch((err) => {
  logger.fatal({ err }, "Fatal error");
  process.exit(1);
});

/**
 * Check if this relayer is registered on-chain. If not, register with MIN_STAKE.
 * Only runs if RELAYER_PRIVATE_KEY and at least one chain has registryAddress set.
 */
async function ensureRegistered(config: RelayerConfig): Promise<void> {
  if (!config.privateKey) {
    logger.warn("No RELAYER_PRIVATE_KEY — skipping on-chain registration check");
    return;
  }

  const chain = config.chains.find((c) => c.registryAddress);
  if (!chain) {
    logger.debug("No registryAddress configured — skipping registration");
    return;
  }

  const account = privateKeyToAccount(config.privateKey as Hex);
  const publicClient = createPublicClient({ transport: http(chain.rpcUrl) });
  const walletClient = createWalletClient({
    account,
    transport: http(chain.rpcUrl),
  });

  const [, , , isRegistered] = await publicClient.readContract({
    address: chain.registryAddress as Hex,
    abi: RELAYER_REGISTRY_ABI,
    functionName: "relayers",
    args: [account.address],
  });

  if (isRegistered) {
    logger.info(
      { registry: chain.registryAddress, chain: chain.name },
      "Relayer already registered",
    );
    return;
  }

  const minStake = await publicClient.readContract({
    address: chain.registryAddress as Hex,
    abi: RELAYER_REGISTRY_ABI,
    functionName: "MIN_STAKE",
  });

  const stakeOverride = process.env.RELAYER_STAKE_AMOUNT;
  const stakeValue = stakeOverride ? parseEther(stakeOverride) : minStake;

  logger.info(
    { registry: chain.registryAddress, stakeEth: Number(stakeValue) / 1e18 },
    "Registering relayer on-chain...",
  );

  const txHash = await walletClient.writeContract({
    address: chain.registryAddress as Hex,
    abi: RELAYER_REGISTRY_ABI,
    functionName: "register",
    value: stakeValue,
    chain: null,
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  if (receipt.status === "reverted") {
    throw new Error(`Relayer registration tx reverted: ${txHash}`);
  }

  logger.info({ txHash, chain: chain.name }, "Relayer registered successfully");
}
