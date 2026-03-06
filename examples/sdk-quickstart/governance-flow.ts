/**
 * ZASEON — Governance Flow Example
 *
 * Demonstrates the on-chain governance lifecycle:
 *   1. Check voting power & delegation
 *   2. Create a proposal (e.g., update a protocol parameter)
 *   3. Cast a vote
 *   4. Queue the proposal in the timelock
 *   5. Execute after the timelock delay
 */
import {
  createGovernanceClient,
  ProposalState,
  VoteType,
} from "../../sdk/src/index";
import {
  createPublicClient,
  createWalletClient,
  http,
  encodeFunctionData,
} from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// --- Configuration -----------------------------------------------------------
const GOVERNOR_ADDRESS = process.env.GOVERNOR_ADDRESS as `0x${string}`;
const PROPOSER_KEY = process.env.PROPOSER_PRIVATE_KEY as `0x${string}`;
const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";

// Example target: update a fee parameter on MultiBridgeRouter
const MULTI_BRIDGE_ROUTER = process.env.MULTI_BRIDGE_ROUTER as `0x${string}`;

async function main() {
  if (!GOVERNOR_ADDRESS) throw new Error("Set GOVERNOR_ADDRESS env var");
  if (!PROPOSER_KEY) throw new Error("Set PROPOSER_PRIVATE_KEY env var");
  if (!MULTI_BRIDGE_ROUTER) throw new Error("Set MULTI_BRIDGE_ROUTER env var");

  const transport = http(RPC_URL);
  const account = privateKeyToAccount(PROPOSER_KEY);

  const publicClient = createPublicClient({ chain: sepolia, transport });
  const walletClient = createWalletClient({
    chain: sepolia,
    transport,
    account,
  });

  const governance = createGovernanceClient({
    contractAddress: GOVERNOR_ADDRESS,
    publicClient: publicClient as any,
    walletClient: walletClient as any,
  });

  // --- 1. Check voting power ------------------------------------------------
  console.log("1. Checking voting power...");
  const votingPower = await governance.getVotingPower(account.address);
  console.log(`   Voting power: ${votingPower}`);

  const threshold = await governance.getProposalThreshold();
  console.log(`   Proposal threshold: ${threshold}`);

  if (votingPower < threshold) {
    console.log(
      "   ⚠ Insufficient voting power to propose. Delegate tokens first.",
    );
    return;
  }

  // --- 2. Create proposal ---------------------------------------------------
  console.log("\n2. Creating proposal...");

  // Encode the calldata for the target function
  const calldata = encodeFunctionData({
    abi: [
      {
        name: "updateBridgeStatus",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
          { name: "bridgeType", type: "uint8" },
          { name: "newStatus", type: "uint8" },
        ],
        outputs: [],
      },
    ],
    functionName: "updateBridgeStatus",
    args: [1, 1], // bridgeType=1 (LayerZero), newStatus=1 (Active)
  });

  const txHash = await governance.propose(
    [MULTI_BRIDGE_ROUTER], // targets
    [0n], // values (no ETH)
    [calldata], // calldatas
    "Activate LayerZero bridge adapter for cross-chain messaging",
  );
  console.log(`   Proposal tx: ${txHash}`);

  // Compute the proposal ID (same as governor.hashProposal)
  const proposalId = await governance.hashProposal(
    [MULTI_BRIDGE_ROUTER],
    [0n],
    [calldata],
    "Activate LayerZero bridge adapter for cross-chain messaging",
  );
  console.log(`   Proposal ID: ${proposalId}`);

  // --- 3. Wait for voting period to start, then vote ------------------------
  console.log("\n3. Waiting for voting period...");
  const votingDelay = await governance.getVotingDelay();
  console.log(`   Voting delay: ${votingDelay} blocks`);
  console.log("   (In production, wait for voting delay blocks to pass)");

  // Cast vote: For
  console.log("   Casting vote: FOR");
  const voteTx = await governance.voteWithReason(
    proposalId,
    VoteType.For,
    "LayerZero provides broad chain coverage needed for phase 2 rollout",
  );
  console.log(`   Vote tx: ${voteTx}`);

  // Check if we already voted
  const hasVoted = await governance.hasVoted(proposalId, account.address);
  console.log(`   Has voted: ${hasVoted}`);

  // --- 4. Queue in timelock -------------------------------------------------
  console.log("\n4. Queueing proposal in timelock...");
  console.log(
    "   (In production, wait for voting period to end and quorum to be met)",
  );

  const state = await governance.getProposal(proposalId);
  console.log(`   Proposal state: ${ProposalState[state.state]}`);

  if (state.state === ProposalState.Succeeded) {
    const queueTx = await governance.queue(
      [MULTI_BRIDGE_ROUTER],
      [0n],
      [calldata],
      "Activate LayerZero bridge adapter for cross-chain messaging",
    );
    console.log(`   Queue tx: ${queueTx}`);
  }

  // --- 5. Execute after timelock delay --------------------------------------
  console.log("\n5. Executing proposal...");
  console.log("   (In production, wait for timelock delay to elapse)");

  const executeTx = await governance.execute(
    [MULTI_BRIDGE_ROUTER],
    [0n],
    [calldata],
    "Activate LayerZero bridge adapter for cross-chain messaging",
  );
  console.log(`   Execute tx: ${executeTx}`);
  console.log("\n✅ Governance flow complete!");
}

main().catch(console.error);
