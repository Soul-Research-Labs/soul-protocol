/**
 * @deprecated Use `SoulProtocolClient` from `./SoulProtocolClient` instead.
 * This client is retained for backward compatibility and will be removed in v3.0.
 * SoulProtocolClient provides a superset of SoulClient functionality including
 * ZK locks, cross-chain transfers, and Noir prover integration.
 * @internal Not exported from the main SDK entry point. Import directly only if needed.
 */
import {
  PublicClient,
  WalletClient,
  Hex,
  Address,
  Hash,
  encodeFunctionData,
  decodeFunctionResult,
} from "viem";

export interface SoulClientOptions {
  chainId: number;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  addresses: {
    proofHub?: string;
    nullifierRegistry?: string;
    stateContainer?: string;
    atomicSwap?: string;
    complianceModule?: string;
    privacyRouter?: string;
    [key: string]: string | undefined;
  };
}

/*//////////////////////////////////////////////////////////////
                        ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

const PROOF_HUB_ABI = [
  {
    name: "submitProof",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proofType", type: "uint8" },
      { name: "stateHash", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "uint256[]" },
    ],
    outputs: [{ name: "proofId", type: "bytes32" }],
  },
] as const;

const NULLIFIER_ABI = [
  {
    name: "isSpent",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

const COMPLIANCE_ABI = [
  {
    name: "isKYCValid",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "valid", type: "bool" }],
  },
] as const;

/*//////////////////////////////////////////////////////////////
                        CLIENT CLASS
//////////////////////////////////////////////////////////////*/

export class SoulClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly addresses: SoulClientOptions["addresses"];
  public readonly chainId: number;

  constructor(public options: SoulClientOptions) {
    this.publicClient = options.publicClient;
    this.walletClient = options.walletClient;
    this.addresses = options.addresses;
    this.chainId = options.chainId;
  }

  /**
   * Register a private state by submitting a proof to CrossChainProofHubV3.
   * @param stateHash - Hash of the state to register
   * @param proofType - Proof type enum (0 = validity, 1 = policy, etc.)
   * @param proof - Serialized proof bytes
   * @param publicInputs - Array of public inputs for the proof
   * @returns Transaction hash
   */
  async registerPrivateState(
    stateHash: Hex,
    proofType: number,
    proof: Hex = "0x",
    publicInputs: bigint[] = [],
  ): Promise<Hash> {
    this._requireWallet();
    const proofHub = this._requireAddress("proofHub");

    const hash = await this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: proofHub as Address,
      abi: PROOF_HUB_ABI,
      functionName: "submitProof",
      args: [proofType, stateHash, proof, publicInputs],
    });

    return hash;
  }

  /**
   * Bridge a proof to a destination chain via the relay contract.
   * @param destChain - Destination chain ID
   * @param proof - Serialized proof bytes
   * @param nullifier - Nullifier for double-spend prevention
   * @returns Transaction hash
   */
  async bridgeProof({
    destChain,
    proof,
    nullifier,
  }: {
    destChain: number;
    proof: Hex;
    nullifier: Hex;
  }): Promise<Hash> {
    this._requireWallet();
    const proofHub = this._requireAddress("proofHub");

    const hash = await this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: proofHub as Address,
      abi: [
        {
          name: "relayProof",
          type: "function",
          stateMutability: "nonpayable",
          inputs: [
            { name: "destChainId", type: "uint256" },
            { name: "proof", type: "bytes" },
            { name: "nullifier", type: "bytes32" },
          ],
          outputs: [{ name: "relayId", type: "bytes32" }],
        },
      ] as const,
      functionName: "relayProof",
      args: [BigInt(destChain), proof, nullifier],
    });

    return hash;
  }

  /**
   * Check if a nullifier has been spent.
   */
  async isNullifierSpent(nullifier: Hex): Promise<boolean> {
    const registry = this._requireAddress("nullifierRegistry");

    return this.publicClient.readContract({
      address: registry as Address,
      abi: NULLIFIER_ABI,
      functionName: "isSpent",
      args: [nullifier],
    });
  }

  compliance = {
    /**
     * Check if an address has valid KYC.
     */
    checkKYC: async (address: string): Promise<boolean> => {
      const compliance = this.addresses.complianceModule;
      if (!compliance) {
        throw new Error("Compliance module address not configured");
      }

      return this.publicClient.readContract({
        address: compliance as Address,
        abi: COMPLIANCE_ABI,
        functionName: "isKYCValid",
        args: [address as Address],
      });
    },
  };

  /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
  //////////////////////////////////////////////////////////////*/

  private _requireWallet(): void {
    if (!this.walletClient) {
      throw new Error("WalletClient required for write operations");
    }
  }

  private _requireAddress(name: string): string {
    const addr = this.addresses[name];
    if (!addr) {
      throw new Error(`Contract address '${name}' not configured`);
    }
    return addr;
  }
}
