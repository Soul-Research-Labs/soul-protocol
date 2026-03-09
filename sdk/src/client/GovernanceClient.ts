import {
  type PublicClient,
  type WalletClient,
  type Address,
  type Hash,
  type Hex,
  keccak256,
  encodePacked,
} from "viem";

// ============================================================================
// TYPES
// ============================================================================

export interface GovernanceClientConfig {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  governorAddress?: Address;
}

export enum ProposalState {
  Pending = 0,
  Active = 1,
  Canceled = 2,
  Defeated = 3,
  Succeeded = 4,
  Queued = 5,
  Expired = 6,
  Executed = 7,
}

export enum VoteType {
  Against = 0,
  For = 1,
  Abstain = 2,
}

export interface ProposalVotes {
  againstVotes: bigint;
  forVotes: bigint;
  abstainVotes: bigint;
}

// ============================================================================
// ABI FRAGMENTS
// ============================================================================

const GOVERNOR_ABI = [
  {
    name: "propose",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "calldatas", type: "bytes[]" },
      { name: "description", type: "string" },
    ],
    outputs: [{ name: "proposalId", type: "uint256" }],
  },
  {
    name: "castVote",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proposalId", type: "uint256" },
      { name: "support", type: "uint8" },
    ],
    outputs: [{ name: "balance", type: "uint256" }],
  },
  {
    name: "castVoteWithReason",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proposalId", type: "uint256" },
      { name: "support", type: "uint8" },
      { name: "reason", type: "string" },
    ],
    outputs: [{ name: "balance", type: "uint256" }],
  },
  {
    name: "queue",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "calldatas", type: "bytes[]" },
      { name: "descriptionHash", type: "bytes32" },
    ],
    outputs: [{ name: "proposalId", type: "uint256" }],
  },
  {
    name: "execute",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "calldatas", type: "bytes[]" },
      { name: "descriptionHash", type: "bytes32" },
    ],
    outputs: [{ name: "proposalId", type: "uint256" }],
  },
  {
    name: "cancel",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "calldatas", type: "bytes[]" },
      { name: "descriptionHash", type: "bytes32" },
    ],
    outputs: [{ name: "proposalId", type: "uint256" }],
  },
  {
    name: "state",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proposalId", type: "uint256" }],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "getVotes",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "account", type: "address" },
      { name: "timepoint", type: "uint256" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "proposalVotes",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proposalId", type: "uint256" }],
    outputs: [
      { name: "againstVotes", type: "uint256" },
      { name: "forVotes", type: "uint256" },
      { name: "abstainVotes", type: "uint256" },
    ],
  },
  {
    name: "hasVoted",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "proposalId", type: "uint256" },
      { name: "account", type: "address" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "proposalThreshold",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "votingDelay",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "votingPeriod",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "quorum",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "timepoint", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "proposalDeadline",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proposalId", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "proposalSnapshot",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proposalId", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "proposalProposer",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proposalId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "proposalNeedsQueuing",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "proposalId", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "hashProposal",
    type: "function",
    stateMutability: "pure",
    inputs: [
      { name: "targets", type: "address[]" },
      { name: "values", type: "uint256[]" },
      { name: "calldatas", type: "bytes[]" },
      { name: "descriptionHash", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

// ============================================================================
// CLIENT
// ============================================================================

/**
 * SDK client for the ZASEON on-chain governance system (ZaseonGovernor).
 *
 * Covers the full proposal lifecycle:
 * - Propose → Vote → Queue (timelock) → Execute
 * - Read proposal state, voting power, and governance parameters
 *
 * @example
 * ```ts
 * const client = createGovernanceClient({
 *   publicClient,
 *   walletClient,
 *   governorAddress: "0x...",
 * });
 *
 * // Create a proposal
 * const txHash = await client.propose(
 *   [targetAddress],
 *   [0n],
 *   [encodedCalldata],
 *   "Upgrade ShieldedPool to v2",
 * );
 *
 * // Vote in favor
 * await client.vote(proposalId, VoteType.For);
 *
 * // Queue and execute after timelock
 * await client.queue([targetAddress], [0n], [encodedCalldata], "Upgrade ShieldedPool to v2");
 * await client.execute([targetAddress], [0n], [encodedCalldata], "Upgrade ShieldedPool to v2");
 * ```
 */
export class GovernanceClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly governorAddress?: Address;

  constructor(config: GovernanceClientConfig) {
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this.governorAddress = config.governorAddress;
  }

  // ==========================================================================
  // PROPOSAL READS
  // ==========================================================================

  async getProposal(proposalId: bigint): Promise<{
    state: ProposalState;
    proposer: Address;
    snapshot: bigint;
    deadline: bigint;
    needsQueuing: boolean;
    votes: ProposalVotes;
  }> {
    this.requireGovernor();
    const [state, proposer, snapshot, deadline, needsQueuing, votes] =
      await Promise.all([
        this.publicClient.readContract({
          address: this.governorAddress!,
          abi: GOVERNOR_ABI,
          functionName: "state",
          args: [proposalId],
        }),
        this.publicClient.readContract({
          address: this.governorAddress!,
          abi: GOVERNOR_ABI,
          functionName: "proposalProposer",
          args: [proposalId],
        }),
        this.publicClient.readContract({
          address: this.governorAddress!,
          abi: GOVERNOR_ABI,
          functionName: "proposalSnapshot",
          args: [proposalId],
        }),
        this.publicClient.readContract({
          address: this.governorAddress!,
          abi: GOVERNOR_ABI,
          functionName: "proposalDeadline",
          args: [proposalId],
        }),
        this.publicClient.readContract({
          address: this.governorAddress!,
          abi: GOVERNOR_ABI,
          functionName: "proposalNeedsQueuing",
          args: [proposalId],
        }),
        this.publicClient.readContract({
          address: this.governorAddress!,
          abi: GOVERNOR_ABI,
          functionName: "proposalVotes",
          args: [proposalId],
        }),
      ]);

    return {
      state: state as ProposalState,
      proposer: proposer as Address,
      snapshot,
      deadline,
      needsQueuing,
      votes: {
        againstVotes: (votes as readonly [bigint, bigint, bigint])[0],
        forVotes: (votes as readonly [bigint, bigint, bigint])[1],
        abstainVotes: (votes as readonly [bigint, bigint, bigint])[2],
      },
    };
  }

  async getVotingPower(account: Address, timepoint?: bigint): Promise<bigint> {
    this.requireGovernor();
    // H27 FIX: Use latest block timestamp instead of client clock to avoid ERC5805FutureLookup
    const tp = timepoint ?? (await this.publicClient.getBlock()).timestamp;
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "getVotes",
      args: [account, tp],
    });
  }

  async hasVoted(proposalId: bigint, account: Address): Promise<boolean> {
    this.requireGovernor();
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "hasVoted",
      args: [proposalId, account],
    });
  }

  async getProposalThreshold(): Promise<bigint> {
    this.requireGovernor();
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "proposalThreshold",
    });
  }

  async getVotingDelay(): Promise<bigint> {
    this.requireGovernor();
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "votingDelay",
    });
  }

  async getVotingPeriod(): Promise<bigint> {
    this.requireGovernor();
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "votingPeriod",
    });
  }

  async getQuorum(timepoint: bigint): Promise<bigint> {
    this.requireGovernor();
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "quorum",
      args: [timepoint],
    });
  }

  async hashProposal(
    targets: Address[],
    values: bigint[],
    calldatas: Hex[],
    description: string,
  ): Promise<bigint> {
    this.requireGovernor();
    const descriptionHash = keccak256(encodePacked(["string"], [description]));
    return this.publicClient.readContract({
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "hashProposal",
      args: [targets, values, calldatas, descriptionHash],
    });
  }

  // ==========================================================================
  // PROPOSAL WRITES
  // ==========================================================================

  async propose(
    targets: Address[],
    values: bigint[],
    calldatas: Hex[],
    description: string,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireGovernor();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "propose",
      args: [targets, values, calldatas, description],
    });
  }

  async vote(proposalId: bigint, support: VoteType): Promise<Hash> {
    this.requireWallet();
    this.requireGovernor();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "castVote",
      args: [proposalId, support],
    });
  }

  async voteWithReason(
    proposalId: bigint,
    support: VoteType,
    reason: string,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireGovernor();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "castVoteWithReason",
      args: [proposalId, support, reason],
    });
  }

  async queue(
    targets: Address[],
    values: bigint[],
    calldatas: Hex[],
    description: string,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireGovernor();
    const descriptionHash = keccak256(encodePacked(["string"], [description]));
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "queue",
      args: [targets, values, calldatas, descriptionHash],
    });
  }

  async execute(
    targets: Address[],
    values: bigint[],
    calldatas: Hex[],
    description: string,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireGovernor();
    const descriptionHash = keccak256(encodePacked(["string"], [description]));
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "execute",
      args: [targets, values, calldatas, descriptionHash],
    });
  }

  async cancel(
    targets: Address[],
    values: bigint[],
    calldatas: Hex[],
    description: string,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireGovernor();
    const descriptionHash = keccak256(encodePacked(["string"], [description]));
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.governorAddress!,
      abi: GOVERNOR_ABI,
      functionName: "cancel",
      args: [targets, values, calldatas, descriptionHash],
    });
  }

  // ==========================================================================
  // HELPERS
  // ==========================================================================

  private requireWallet(): void {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
  }

  private requireGovernor(): void {
    if (!this.governorAddress) throw new Error("Governor address required");
  }
}

/**
 * Factory function to create a GovernanceClient.
 */
export function createGovernanceClient(
  config: GovernanceClientConfig,
): GovernanceClient {
  return new GovernanceClient(config);
}
