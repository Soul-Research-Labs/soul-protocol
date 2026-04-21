/**
 * End-to-end scenario runner for the local harness.
 *
 * Exercises: deposit on L1 → cross-chain proof → withdraw on L2 via the
 * relayer, using the same SDK surface third-party integrators would use.
 *
 * Prereqs: `make deploy` in this folder must have succeeded and populated
 * `deployments/local-31337.json`.
 */
import { readFileSync } from "fs";
import { join } from "path";
import { createWalletClient, createPublicClient, http, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(__dirname, "..", "..");
const PK =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as `0x${string}`;

async function main() {
  const deployments = JSON.parse(
    readFileSync(join(ROOT, "deployments", "local-31337.json"), "utf8"),
  );
  console.log("loaded deployments:", Object.keys(deployments.phases));

  const account = privateKeyToAccount(PK);
  const wallet = createWalletClient({
    account,
    transport: http("http://localhost:8545"),
  });
  const pub = createPublicClient({ transport: http("http://localhost:8545") });

  console.log(`account: ${account.address}`);
  const bal = await pub.getBalance({ address: account.address });
  console.log(`balance: ${bal}`);

  // Scenario steps are stubs; real implementation would:
  //   1. deposit → ShieldedPool
  //   2. generate proof via SDK
  //   3. submit to ProofHub
  //   4. wait for relayer to dispatch
  //   5. assert withdrawal finalized
  console.log(
    "TODO: plug in ZaseonSDK.bridges.send(...) once deploy artifact is canonical",
  );
  console.log("scenario stub complete");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
