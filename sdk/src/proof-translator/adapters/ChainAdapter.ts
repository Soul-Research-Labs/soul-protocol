/**
 * @fileoverview Chain-specific adapters for proof translation
 * Handles differences in verification between EVM, Cosmos, and Substrate chains
 */

import { 
  keccak256, 
  encodeAbiParameters, 
  toHex,
  getContract,
  type PublicClient, 
  type WalletClient,
  type Hex,
  type Abi,
  type TransactionRequest,
  type TransactionReceipt
} from "viem";
import {
  Groth16Proof,
  CurveType,
  TranslationResult,
  toBytesBN254,
  toBytesBLS12381,
  toSolidityBN254,
  CURVE_PARAMS,
} from "../ProofTranslator";

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

export interface ChainAdapter {
  /**
   * Chain identifier
   */
  readonly chainType: ChainType;
  readonly chainId: number | string;
  readonly name: string;

  /**
   * Supported curve for this chain
   */
  readonly supportedCurve: CurveType;

  /**
   * Format proof for this chain's verifier
   */
  formatProof(proof: Groth16Proof): any;

  /**
   * Encode public signals for this chain
   */
  encodePublicSignals(signals: bigint[]): any;

  /**
   * Create verification transaction/message
   */
  createVerificationTx(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<any>;

  /**
   * Submit proof for on-chain verification
   */
  submitProof(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<VerificationResult>;

  /**
   * Check if proof was verified
   */
  checkVerification(txHash: string): Promise<boolean>;
}

export type ChainType = "evm" | "cosmos" | "substrate" | "solana";

export interface VerificationResult {
  success: boolean;
  txHash: string;
  gasUsed?: bigint;
  error?: string;
}

/*//////////////////////////////////////////////////////////////
                        EVM ADAPTER
//////////////////////////////////////////////////////////////*/

export class EVMChainAdapter implements ChainAdapter {
  readonly chainType: ChainType = "evm";
  readonly supportedCurve: CurveType = "bn254";

  constructor(
    public readonly chainId: number,
    public readonly name: string,
    private publicClient: PublicClient,
    private walletClient?: WalletClient
  ) {}

  formatProof(proof: Groth16Proof): {
    pA: [string, string];
    pB: [[string, string], [string, string]];
    pC: [string, string];
  } {
    return toSolidityBN254(proof);
  }

  encodePublicSignals(signals: bigint[]): string[] {
    return signals.map((s) => s.toString());
  }

  async createVerificationTx(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<TransactionRequest> {
    const formatted = this.formatProof(proof);
    const signals = this.encodePublicSignals(publicSignals);

    const abi = [
      {
        name: "verifyProof",
        type: "function",
        stateMutability: "view",
        inputs: [
          { name: "pA", type: "uint256[2]" },
          { name: "pB", type: "uint256[2][2]" },
          { name: "pC", type: "uint256[2]" },
          { name: "pubSignals", type: "uint256[]" }
        ],
        outputs: [{ name: "", type: "bool" }]
      }
    ] as const;

    const data = toHex(new Uint8Array()); // Placeholder for real encoding if needed manually
    // But with viem's write/read we don't usually need it this way unless for specific raw txs


    return {
      to: verifierAddress as Hex,
      data,
    };
  }

  async submitProof(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<VerificationResult> {
    if (!this.walletClient) {
      throw new Error("Wallet client required for submitting proofs");
    }

    try {
      const contract = getContract({
        address: verifierAddress as Hex,
        abi: [
          {
            name: "verifyProof",
            type: "function",
            stateMutability: "nonpayable",
            inputs: [
              { name: "pA", type: "uint256[2]" },
              { name: "pB", type: "uint256[2][2]" },
              { name: "pC", type: "uint256[2]" },
              { name: "pubSignals", type: "uint256[]" }
            ],
            outputs: [{ name: "", type: "bool" }]
          }
        ],
        client: { public: this.publicClient, wallet: this.walletClient }
      });

      const formatted = this.formatProof(proof);
      const signals = this.encodePublicSignals(publicSignals);

      const [account] = await this.walletClient.getAddresses();
      
      const hash = await contract.write.verifyProof([
        [BigInt(formatted.pA[0]), BigInt(formatted.pA[1])],
        [
          [BigInt(formatted.pB[0][0]), BigInt(formatted.pB[0][1])],
          [BigInt(formatted.pB[1][0]), BigInt(formatted.pB[1][1])]
        ],
        [BigInt(formatted.pC[0]), BigInt(formatted.pC[1])],
        signals.map(s => BigInt(s))
      ], { account, chain: this.publicClient.chain });

      const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

      return {
        success: receipt.status === 'success',
        txHash: receipt.transactionHash,
        gasUsed: receipt.gasUsed,
      };
    } catch (error: any) {
      return {
        success: false,
        txHash: "",
        error: error.message,
      };
    }
  }

  async checkVerification(txHash: string): Promise<boolean> {
    const receipt = await this.publicClient.getTransactionReceipt({ hash: txHash as Hex });
    return receipt.status === 'success';
  }

  /**
   * Static call to check proof without submitting
   */
  async verifyProofOffchain(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<boolean> {
    const formatted = this.formatProof(proof);
    const signals = this.encodePublicSignals(publicSignals);

    const contract = getContract({
      address: verifierAddress as Hex,
      abi: [
        {
          name: "verifyProof",
          type: "function",
          stateMutability: "view",
          inputs: [
            { name: "pA", type: "uint256[2]" },
            { name: "pB", type: "uint256[2][2]" },
            { name: "pC", type: "uint256[2]" },
            { name: "pubSignals", type: "uint256[]" }
          ],
          outputs: [{ name: "", type: "bool" }]
        }
      ],
      client: { public: this.publicClient }
    });

    return await contract.read.verifyProof([
      [BigInt(formatted.pA[0]), BigInt(formatted.pA[1])],
      [
        [BigInt(formatted.pB[0][0]), BigInt(formatted.pB[0][1])],
        [BigInt(formatted.pB[1][0]), BigInt(formatted.pB[1][1])]
      ],
      [BigInt(formatted.pC[0]), BigInt(formatted.pC[1])],
      signals.map(s => BigInt(s))
    ]) as boolean;
  }
}

/*//////////////////////////////////////////////////////////////
                    EVM BLS12-381 ADAPTER
//////////////////////////////////////////////////////////////*/

export class EVMBLS12381Adapter implements ChainAdapter {
  readonly chainType: ChainType = "evm";
  readonly supportedCurve: CurveType = "bls12-381";

  constructor(
    public readonly chainId: number,
    public readonly name: string,
    private publicClient: PublicClient,
    private walletClient?: WalletClient
  ) {}

  formatProof(proof: Groth16Proof): Uint8Array {
    return toBytesBLS12381(proof);
  }

  encodePublicSignals(signals: bigint[]): Uint8Array {
    const bytes = new Uint8Array(signals.length * 32);
    for (let i = 0; i < signals.length; i++) {
      const hex = signals[i].toString(16).padStart(64, "0");
      for (let j = 0; j < 32; j++) {
        bytes[i * 32 + j] = parseInt(hex.substr(j * 2, 2), 16);
      }
    }
    return bytes;
  }

  async createVerificationTx(
    _proof: Groth16Proof,
    _publicSignals: bigint[],
    _verifierAddress: string
  ): Promise<TransactionRequest> {
      // Placeholder for BLS12-381 EVM tx creation
      return {};
  }

  async submitProof(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<VerificationResult> {
    if (!this.walletClient) {
      throw new Error("Wallet client required for submitting proofs");
    }

    try {
      const contract = getContract({
        address: verifierAddress as Hex,
        abi: [
          {
            name: "verifyProof",
            type: "function",
            stateMutability: "nonpayable",
            inputs: [
              { name: "proof", type: "bytes" },
              { name: "publicInputs", type: "bytes" }
            ],
            outputs: [{ name: "", type: "bool" }]
          }
        ],
        client: { public: this.publicClient, wallet: this.walletClient }
      });

      const [account] = await this.walletClient.getAddresses();
      
      const hash = await contract.write.verifyProof([
        toHex(this.formatProof(proof)),
        toHex(this.encodePublicSignals(publicSignals))
      ], { account, chain: this.publicClient.chain });

      const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

      return {
        success: receipt.status === 'success',
        txHash: receipt.transactionHash,
        gasUsed: receipt.gasUsed,
      };
    } catch (error: any) {
      return {
        success: false,
        txHash: "",
        error: error.message,
      };
    }
  }

  async checkVerification(txHash: string): Promise<boolean> {
    const receipt = await this.publicClient.getTransactionReceipt({ hash: txHash as Hex });
    return receipt.status === 'success';
  }

  /**
   * Check if EIP-2537 precompiles are available
   */
  async isEIP2537Supported(): Promise<boolean> {
    try {
      // Try calling G1ADD precompile with identity operation
      const G1_ADD = "0x0a";
      const identityPoint = "0x" + "00".repeat(96) + "00".repeat(96); // Two zero points

      await this.publicClient.call({
        to: G1_ADD,
        data: identityPoint as Hex,
      });

      return true;
    } catch {
      return false;
    }
  }
}

/*//////////////////////////////////////////////////////////////
                      COSMOS ADAPTER
//////////////////////////////////////////////////////////////*/

export interface CosmosProofMessage {
  typeUrl: string;
  value: {
    proof: string; // base64 encoded
    publicInputs: string[]; // decimal strings
    verifierModuleAddress: string;
  };
}

export class CosmosChainAdapter implements ChainAdapter {
  readonly chainType: ChainType = "cosmos";
  readonly supportedCurve: CurveType = "bn254";

  constructor(
    public readonly chainId: string,
    public readonly name: string,
    private rpcEndpoint: string,
    private signerAddress?: string
  ) {}

  formatProof(proof: Groth16Proof): string {
    // Cosmos uses base64-encoded proof bytes
    const bytes = toBytesBN254(proof);
    return Buffer.from(bytes).toString("base64");
  }

  encodePublicSignals(signals: bigint[]): string[] {
    return signals.map((s) => s.toString());
  }

  async createVerificationTx(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<CosmosProofMessage> {
    return {
      typeUrl: "/soul.zkverifier.v1.MsgVerifyProof",
      value: {
        proof: this.formatProof(proof),
        publicInputs: this.encodePublicSignals(publicSignals),
        verifierModuleAddress: verifierAddress,
      },
    };
  }

  async submitProof(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<VerificationResult> {
    // Cosmos submission requires external signing library
    // This is a placeholder for CosmJS integration
    throw new Error(
      "Cosmos proof submission requires CosmJS. Use createVerificationTx() and sign externally."
    );
  }

  async checkVerification(txHash: string): Promise<boolean> {
    // Query Cosmos RPC for transaction result
    try {
      const response = await fetch(`${this.rpcEndpoint}/tx?hash=0x${txHash}`);
      const result = await response.json();
      return result.result?.tx_result?.code === 0;
    } catch {
      return false;
    }
  }
}

/*//////////////////////////////////////////////////////////////
                     SUBSTRATE ADAPTER
//////////////////////////////////////////////////////////////*/

export interface SubstrateProofCall {
  section: string;
  method: string;
  args: {
    proof: string; // hex encoded
    publicInputs: string[]; // hex encoded
  };
}

export class SubstrateChainAdapter implements ChainAdapter {
  readonly chainType: ChainType = "substrate";
  readonly supportedCurve: CurveType = "bls12-377"; // Substrate commonly uses BLS12-377

  constructor(
    public readonly chainId: string,
    public readonly name: string,
    private wsEndpoint: string
  ) {}

  formatProof(proof: Groth16Proof): string {
    // Substrate uses hex-encoded proof bytes
    // Note: BLS12-377 has same structure as BLS12-381 but different modulus
    const params = CURVE_PARAMS["bls12-377"];
    const bytes = new Uint8Array(params.proofSize);

    let offset = 0;
    const coordSize = 48;

    // A (96 bytes)
    offset = this.writeCoord(bytes, offset, proof.pi_a.x, coordSize);
    offset = this.writeCoord(bytes, offset, proof.pi_a.y, coordSize);

    // B (192 bytes)
    offset = this.writeCoord(bytes, offset, proof.pi_b.x[0], coordSize);
    offset = this.writeCoord(bytes, offset, proof.pi_b.x[1], coordSize);
    offset = this.writeCoord(bytes, offset, proof.pi_b.y[0], coordSize);
    offset = this.writeCoord(bytes, offset, proof.pi_b.y[1], coordSize);

    // C (96 bytes)
    offset = this.writeCoord(bytes, offset, proof.pi_c.x, coordSize);
    this.writeCoord(bytes, offset, proof.pi_c.y, coordSize);

    return "0x" + Buffer.from(bytes).toString("hex");
  }

  private writeCoord(
    bytes: Uint8Array,
    offset: number,
    value: bigint,
    size: number
  ): number {
    const hex = value.toString(16).padStart(size * 2, "0");
    for (let i = 0; i < size; i++) {
      bytes[offset + i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return offset + size;
  }

  encodePublicSignals(signals: bigint[]): string[] {
    return signals.map((s) => "0x" + s.toString(16).padStart(64, "0"));
  }

  async createVerificationTx(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<SubstrateProofCall> {
    return {
      section: "zkVerifier",
      method: "verifyProof",
      args: {
        proof: this.formatProof(proof),
        publicInputs: this.encodePublicSignals(publicSignals),
      },
    };
  }

  async submitProof(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddress: string
  ): Promise<VerificationResult> {
    // Substrate submission requires Polkadot.js API
    throw new Error(
      "Substrate proof submission requires Polkadot.js. Use createVerificationTx() and sign externally."
    );
  }

  async checkVerification(txHash: string): Promise<boolean> {
    // Query Substrate RPC for extrinsic result
    // This is a placeholder
    throw new Error("Not implemented - requires Polkadot.js API");
  }
}

/*//////////////////////////////////////////////////////////////
                      ADAPTER FACTORY
//////////////////////////////////////////////////////////////*/

export type AdapterConfig = {
  chainType: ChainType;
  chainId: number | string;
  name: string;
  publicClient: PublicClient;
  walletClient?: WalletClient;
  rpcEndpoint?: string; // Still needed for non-EVM perhaps or just keeping for compatibility
};

export function createChainAdapter(config: AdapterConfig): ChainAdapter {
  switch (config.chainType) {
    case "evm":
      return new EVMChainAdapter(
        config.chainId as number,
        config.name,
        config.publicClient,
        config.walletClient
      );

    case "cosmos":
      return new CosmosChainAdapter(
        config.chainId as string,
        config.name,
        config.rpcEndpoint || ""
      );

    case "substrate":
      return new SubstrateChainAdapter(
        config.chainId as string,
        config.name,
        config.rpcEndpoint || ""
      );

    default:
      throw new Error(`Unsupported chain type: ${config.chainType}`);
  }
}

/*//////////////////////////////////////////////////////////////
                    MULTI-CHAIN MANAGER
//////////////////////////////////////////////////////////////*/

export class MultiChainProofManager {
  private adapters: Map<string, ChainAdapter> = new Map();

  registerAdapter(key: string, adapter: ChainAdapter): void {
    this.adapters.set(key, adapter);
  }

  getAdapter(key: string): ChainAdapter {
    const adapter = this.adapters.get(key);
    if (!adapter) {
      throw new Error(`No adapter registered for: ${key}`);
    }
    return adapter;
  }

  /**
   * Submit proof to multiple chains
   */
  async submitToMultipleChains(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddresses: Record<string, string>
  ): Promise<Record<string, VerificationResult>> {
    const results: Record<string, VerificationResult> = {};

    for (const [chainKey, verifierAddress] of Object.entries(
      verifierAddresses
    )) {
      try {
        const adapter = this.getAdapter(chainKey);
        results[chainKey] = await adapter.submitProof(
          proof,
          publicSignals,
          verifierAddress
        );
      } catch (error: any) {
        results[chainKey] = {
          success: false,
          txHash: "",
          error: error.message,
        };
      }
    }

    return results;
  }

  /**
   * Verify proof across multiple chains in parallel
   */
  async verifyAcrossChains(
    proof: Groth16Proof,
    publicSignals: bigint[],
    verifierAddresses: Record<string, string>
  ): Promise<Record<string, boolean>> {
    const promises = Object.entries(verifierAddresses).map(
      async ([chainKey, verifierAddress]) => {
        const adapter = this.getAdapter(chainKey);
        if (adapter instanceof EVMChainAdapter) {
          const result = await adapter.verifyProofOffchain(
            proof,
            publicSignals,
            verifierAddress
          );
          return [chainKey, result] as const;
        }
        // Non-EVM chains require actual submission
        return [chainKey, false] as const;
      }
    );

    const results = await Promise.all(promises);
    return Object.fromEntries(results);
  }
}

export default {
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,
};
