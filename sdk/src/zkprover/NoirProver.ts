/**
 * Soul Protocol - Noir ZK Prover
 *
 * Client-side proof generation using Noir circuits and Barretenberg.
 * Supports browser (WASM) and Node.js environments.
 */

import { Hex, keccak256, encodePacked } from "viem";

/*//////////////////////////////////////////////////////////////
                        TYPES
//////////////////////////////////////////////////////////////*/

export interface ProofResult {
  /** The serialized proof bytes */
  proof: Uint8Array;
  /** Public inputs to the circuit */
  publicInputs: string[];
  /** Hex-encoded proof for contract calls */
  proofHex: Hex;
}

export interface CircuitArtifact {
  bytecode: string;
  abi: any;
}

export interface WitnessInput {
  [key: string]:
    | string
    | number
    | bigint
    | boolean
    | WitnessInput
    | WitnessInput[];
}

/*//////////////////////////////////////////////////////////////
                    PROVER MODE
//////////////////////////////////////////////////////////////*/

/**
 * Prover operating mode.
 * - `'development'` (default): Falls back to placeholder proofs when Barretenberg
 *   is unavailable. Suitable for testing and integration development.
 * - `'production'`: Throws if Barretenberg is unavailable or circuit artifacts
 *   are missing. Ensures only real cryptographic proofs are generated.
 */
export type ProverMode = "production" | "development";

/**
 * Options for configuring a NoirProver instance.
 */
export interface ProverOptions {
  /**
   * Operating mode. Defaults to `'development'`.
   * In `'production'` mode, the prover will throw instead of generating
   * placeholder proofs when the Barretenberg backend is unavailable.
   */
  mode?: ProverMode;
}

/*//////////////////////////////////////////////////////////////
                    CIRCUIT DEFINITIONS
//////////////////////////////////////////////////////////////*/

/**
 * Available Noir circuits in the Soul Protocol
 */
export enum Circuit {
  /** Commitment to a secret value */
  StateCommitment = "state_commitment",
  /** Transfer between states */
  StateTransfer = "state_transfer",
  /** Merkle inclusion proof */
  MerkleProof = "merkle_proof",
  /** Cross-chain state proof */
  CrossChainProof = "cross_chain_proof",
  /** Compliance/policy proof */
  ComplianceProof = "compliance_proof",
  /** Nullifier derivation */
  Nullifier = "nullifier",
  /** Balance proof (range proof) */
  BalanceProof = "balance_proof",
  /** Swap proof */
  SwapProof = "swap_proof",
}

/**
 * Input types for each circuit
 */
export interface StateCommitmentInputs {
  secret: Hex;
  nullifier: Hex;
  amount: bigint;
}

export interface StateTransferInputs {
  sourceCommitment: Hex;
  destinationCommitment: Hex;
  nullifier: Hex;
  amount: bigint;
  sourceChainId: number;
  destChainId: number;
}

export interface MerkleProofInputs {
  leaf: Hex;
  root: Hex;
  pathElements: Hex[];
  pathIndices: number[];
}

export interface NullifierInputs {
  secret: Hex;
  leafIndex: number;
}

export interface BalanceProofInputs {
  balance: bigint;
  minBalance: bigint;
  maxBalance: bigint;
  commitment: Hex;
  secret: Hex;
}

/*//////////////////////////////////////////////////////////////
                    NOIR PROVER
//////////////////////////////////////////////////////////////*/

/**
 * Noir ZK Prover for Soul Protocol
 *
 * Uses Barretenberg (bb) for proof generation.
 * Falls back to placeholder implementation if bb is not available.
 */
export class NoirProver {
  private initialized: boolean = false;
  private backend?: any;
  private noir?: any;
  private circuits: Map<Circuit, CircuitArtifact> = new Map();
  /** Operating mode — controls placeholder proof behavior */
  public readonly mode: ProverMode;

  constructor(options?: ProverOptions) {
    this.mode = options?.mode ?? "development";
  }

  /**
   * Initialize the prover
   *
   * In production, this loads the Barretenberg WASM backend.
   * For development, uses a placeholder that returns mock proofs.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Try to load Barretenberg
      // @ts-ignore - Dynamic import
      const { Barretenberg, Fr } = await import("@aztec/bb.js");
      this.backend = await Barretenberg.new();
      console.log("✅ Barretenberg backend initialized");
    } catch (e) {
      if (this.mode === "production") {
        throw new Error(
          "Barretenberg backend unavailable — cannot initialize prover in production mode. " +
            "Install with: npm install @aztec/bb.js",
        );
      }
      console.warn("⚠️ Barretenberg not available, using placeholder prover");
      console.warn("   Install with: npm install @aztec/bb.js");
    }

    this.initialized = true;
  }

  /**
   * Load a circuit artifact
   */
  async loadCircuit(circuit: Circuit): Promise<CircuitArtifact> {
    if (this.circuits.has(circuit)) {
      return this.circuits.get(circuit)!;
    }

    try {
      // Try to load from noir/target directory
      const fs = await import("fs/promises");
      const path = await import("path");

      const circuitPath = path.join(
        process.cwd(),
        "noir",
        circuit,
        "target",
        `${circuit}.json`,
      );
      const data = await fs.readFile(circuitPath, "utf-8");
      const artifact = JSON.parse(data) as CircuitArtifact;

      this.circuits.set(circuit, artifact);
      return artifact;
    } catch (e) {
      if (this.mode === "production") {
        throw new Error(
          `Circuit ${circuit} not found — cannot load circuits in production mode. ` +
            `Expected at: noir/${circuit}/target/${circuit}.json`,
        );
      }
      // Return placeholder artifact
      console.warn(`⚠️ Circuit ${circuit} not found, using placeholder`);
      const placeholder: CircuitArtifact = {
        bytecode: "",
        abi: { parameters: [], return_type: null },
      };
      this.circuits.set(circuit, placeholder);
      return placeholder;
    }
  }

  /**
   * Generate a proof for the given circuit and inputs
   */
  async generateProof<T extends WitnessInput>(
    circuit: Circuit,
    inputs: T,
  ): Promise<ProofResult> {
    if (!this.initialized) {
      await this.initialize();
    }

    // Load circuit artifact
    const artifact = await this.loadCircuit(circuit);

    if (this.backend && artifact.bytecode) {
      // Use real Barretenberg prover
      return await this.generateRealProof(artifact, inputs);
    } else {
      if (this.mode === "production") {
        throw new Error(
          `Cannot generate proof for ${circuit} in production mode: ` +
            (!this.backend
              ? "Barretenberg backend unavailable"
              : "circuit artifact has no bytecode") +
            ". Ensure @aztec/bb.js is installed and circuits are compiled.",
        );
      }
      // Use placeholder prover
      return this.generatePlaceholderProof(circuit, inputs);
    }
  }

  /**
   * Generate a real proof using Barretenberg
   */
  private async generateRealProof(
    artifact: CircuitArtifact,
    inputs: WitnessInput,
  ): Promise<ProofResult> {
    if (!this.backend) {
      throw new Error("Barretenberg backend not initialized");
    }

    try {
      // 1. Compile circuit bytecode into an executable program
      const acirBuffer = Buffer.from(artifact.bytecode, "base64");
      const [exact, witness] = await this.backend.acirCreateWitness(
        acirBuffer,
        this.flattenInputs(inputs),
      );

      // 2. Generate UltraPlonk proof
      const proof = await this.backend.acirCreateProof(acirBuffer, witness);

      // 3. Extract public inputs from the ABI
      const publicInputs = this.extractPublicInputsFromAbi(
        artifact.abi,
        inputs,
      );

      return {
        proof: new Uint8Array(proof),
        publicInputs,
        proofHex: `0x${Buffer.from(proof).toString("hex")}` as Hex,
      };
    } catch (e: any) {
      // SECURITY: Do NOT silently fallback to placeholder proofs.
      // Re-throw the error — callers must handle proof generation failures explicitly.
      console.error(`Real proof generation failed: ${e.message}`);
      throw new Error(
        `Proof generation failed for circuit: ${e.message}. Ensure Barretenberg and circuit artifacts are available.`,
      );
    }
  }

  /**
   * Flatten nested witness inputs into a string-keyed map for Barretenberg
   */
  private flattenInputs(
    inputs: WitnessInput,
    prefix = "",
  ): Map<string, string> {
    const flat = new Map<string, string>();
    for (const [key, val] of Object.entries(inputs)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      if (typeof val === "object" && val !== null && !Array.isArray(val)) {
        const nested = this.flattenInputs(val as WitnessInput, fullKey);
        nested.forEach((v, k) => flat.set(k, v));
      } else {
        flat.set(fullKey, String(val));
      }
    }
    return flat;
  }

  /**
   * Extract public inputs from the circuit ABI definition
   */
  private extractPublicInputsFromAbi(abi: any, inputs: WitnessInput): string[] {
    if (!abi?.parameters) return [];
    const publicParams = abi.parameters.filter(
      (p: any) => p.visibility === "public",
    );
    return publicParams.map((p: any) => String(inputs[p.name] ?? "0"));
  }

  /**
   * Generate a placeholder proof for development/testing
   *
   * WARNING: These proofs are NOT cryptographically valid!
   * Only use for testing against mock verifiers.
   */
  private generatePlaceholderProof(
    circuit: Circuit,
    inputs: WitnessInput,
  ): ProofResult {
    // Create deterministic "proof" from inputs
    const inputString = JSON.stringify(inputs, (_, v) =>
      typeof v === "bigint" ? v.toString() : v,
    );
    const inputHash = keccak256(encodePacked(["string"], [inputString]));

    // Generate mock proof bytes (256 bytes for Groth16-like)
    const proofBytes = new Uint8Array(256);
    const hashBytes = Buffer.from(inputHash.slice(2), "hex");
    for (let i = 0; i < proofBytes.length; i++) {
      proofBytes[i] = hashBytes[i % hashBytes.length] ^ (i % 256);
    }

    // Extract public inputs based on circuit type
    const publicInputs = this.extractPublicInputs(circuit, inputs);

    return {
      proof: proofBytes,
      publicInputs,
      proofHex: `0x${Buffer.from(proofBytes).toString("hex")}` as Hex,
    };
  }

  /**
   * Extract public inputs based on circuit type
   */
  private extractPublicInputs(
    circuit: Circuit,
    inputs: WitnessInput,
  ): string[] {
    switch (circuit) {
      case Circuit.StateCommitment:
        // Public: commitment (derived from secret + nullifier when available)
        const sc = inputs as unknown as StateCommitmentInputs;
        if (sc.secret && sc.nullifier) {
          const commitment = keccak256(
            encodePacked(["bytes32", "bytes32"], [sc.secret, sc.nullifier]),
          );
          return [commitment];
        }
        // Fallback: hash all inputs
        return [
          keccak256(
            encodePacked(
              ["string"],
              [
                JSON.stringify(inputs, (_, v) =>
                  typeof v === "bigint" ? v.toString() : v,
                ),
              ],
            ),
          ),
        ];

      case Circuit.Nullifier:
        // Public: nullifier hash
        const ni = inputs as unknown as NullifierInputs;
        const nullifierHash = keccak256(ni.secret);
        return [nullifierHash];

      case Circuit.MerkleProof:
        // Public: root, leaf
        const mp = inputs as unknown as MerkleProofInputs;
        return [mp.root, mp.leaf];

      default:
        // Return hash of all inputs as single public input
        const inputHash = keccak256(
          encodePacked(
            ["string"],
            [
              JSON.stringify(inputs, (_, v) =>
                typeof v === "bigint" ? v.toString() : v,
              ),
            ],
          ),
        );
        return [inputHash];
    }
  }

  /**
   * Verify a proof.
   *
   * When Barretenberg is available and the circuit is compiled, performs real
   * cryptographic verification. Otherwise falls back to structural checks
   * (proof length >= 256 bytes, public inputs present).
   *
   * NOTE: Authoritative verification always happens on-chain.
   */
  async verifyProof(
    circuit: Circuit,
    proof: ProofResult,
    publicInputs: string[],
  ): Promise<boolean> {
    if (!this.initialized) {
      await this.initialize();
    }

    // Structural validation (always enforced)
    if (!proof.proof || proof.proof.length < 256) {
      return false;
    }
    if (!publicInputs || publicInputs.length === 0) {
      return false;
    }

    if (this.backend) {
      const artifact = await this.loadCircuit(circuit);
      if (artifact.bytecode) {
        try {
          const acirBuffer = Buffer.from(artifact.bytecode, "base64");
          const verified = await this.backend.acirVerifyProof(
            acirBuffer,
            Buffer.from(proof.proof),
          );
          return verified;
        } catch (e: any) {
          console.warn(`Real verification failed: ${e.message}`);
          return false;
        }
      }
    }

    // Structural-only pass — caller is responsible for on-chain verification
    // SECURITY: Return false — off-chain verification without a real backend is unsafe.
    // Callers must verify proofs on-chain when Barretenberg is not available.
    console.warn(
      "⚠️ Barretenberg unavailable — off-chain verification disabled. Verify on-chain.",
    );
    return false;
  }

  /**
   * Generate a state commitment proof
   */
  async proveStateCommitment(
    inputs: StateCommitmentInputs,
  ): Promise<ProofResult> {
    return this.generateProof(
      Circuit.StateCommitment,
      inputs as unknown as WitnessInput,
    );
  }

  /**
   * Generate a state transfer proof
   */
  async proveStateTransfer(inputs: StateTransferInputs): Promise<ProofResult> {
    return this.generateProof(
      Circuit.StateTransfer,
      inputs as unknown as WitnessInput,
    );
  }

  /**
   * Generate a merkle inclusion proof
   */
  async proveMerkleInclusion(inputs: MerkleProofInputs): Promise<ProofResult> {
    return this.generateProof(
      Circuit.MerkleProof,
      inputs as unknown as WitnessInput,
    );
  }

  /**
   * Generate a nullifier derivation proof
   */
  async proveNullifier(inputs: NullifierInputs): Promise<ProofResult> {
    return this.generateProof(
      Circuit.Nullifier,
      inputs as unknown as WitnessInput,
    );
  }

  /**
   * Generate a balance range proof
   */
  async proveBalance(inputs: BalanceProofInputs): Promise<ProofResult> {
    return this.generateProof(
      Circuit.BalanceProof,
      inputs as unknown as WitnessInput,
    );
  }
}

/**
 * Singleton prover instance
 */
let _prover: NoirProver | null = null;

/**
 * Get the global prover instance.
 * Uses `'development'` mode by default for backward compatibility.
 * Pass `options` to create a singleton in a different mode.
 */
export async function getProver(options?: ProverOptions): Promise<NoirProver> {
  if (!_prover) {
    _prover = new NoirProver(options);
    await _prover.initialize();
  }
  return _prover;
}

/**
 * Create a new prover instance.
 * @param options - Prover configuration. Defaults to development mode.
 */
export function createProver(options?: ProverOptions): NoirProver {
  return new NoirProver(options);
}
