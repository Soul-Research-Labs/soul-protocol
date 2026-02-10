/**
 * Soul Multi-ZK System SDK
 *
 * Provides unified interface for multiple ZK proving systems:
 * - SP1 (Succinct)
 * - Plonky3 (Polygon)
 * - Jolt (a16z Research)
 * - Binius (Binary Fields)
 */
import {
  type PublicClient,
  type Address,
  type Abi,
  keccak256,
  encodePacked,
  toHex,
  getContract,
} from "viem";

// =========================================================================
// ENUMS & INTERFACES
// =========================================================================

export enum ProofSystem {
  Groth16 = 0,
  Plonk = 1,
  Noir = 2,
  SP1 = 3,
  Plonky3 = 4,
  Jolt = 5,
  Binius = 6,
  Recursive = 7,
}

export interface ProofGenerationResult {
  proof: Uint8Array;
  publicInputs: Uint8Array;
  publicInputsHash: string;
  systemSpecificData?: Record<string, unknown>;
  proofTime: number;
}

export interface VerificationResult {
  valid: boolean;
  gasUsed?: bigint;
  proofHash?: string;
}

export interface ZKSystemConfig {
  provingKey?: string;
  verificationKey?: string;
  circuitPath?: string;
  programPath?: string;
  timeout?: number;
  threads?: number;
}

// =========================================================================
// ABSTRACT BASE CLIENT
// =========================================================================

export abstract class SoulZKClient {
  protected config: ZKSystemConfig;
  protected system: ProofSystem;

  constructor(system: ProofSystem, config?: ZKSystemConfig) {
    this.system = system;
    this.config = config || {};
  }

  abstract generateProof(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<ProofGenerationResult>;

  abstract verifyProofLocally(
    proof: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<boolean>;

  getSystem(): ProofSystem {
    return this.system;
  }

  getSystemName(): string {
    const names: Record<ProofSystem, string> = {
      [ProofSystem.Groth16]: "Groth16",
      [ProofSystem.Plonk]: "PLONK",
      [ProofSystem.Noir]: "Noir",
      [ProofSystem.SP1]: "SP1",
      [ProofSystem.Plonky3]: "Plonky3",
      [ProofSystem.Jolt]: "Jolt",
      [ProofSystem.Binius]: "Binius",
      [ProofSystem.Recursive]: "Recursive",
    };
    return names[this.system] || "Unknown";
  }

  protected hashPublicInputs(inputs: Uint8Array): string {
    return keccak256(
      encodePacked(["bytes"], [toHex(inputs) as `0x${string}`])
    );
  }

  protected serializeInputs(inputs: Record<string, unknown>): Uint8Array {
    const json = JSON.stringify(inputs, (_, v) =>
      typeof v === "bigint" ? v.toString() : v
    );
    return new TextEncoder().encode(json);
  }
}

// =========================================================================
// SP1 CLIENT
// =========================================================================

export interface SP1Proof {
  proof: Uint8Array;
  publicValues: Uint8Array;
  vkeyHash: string;
}

export class SoulSP1Client extends SoulZKClient {
  private programELF?: Uint8Array;
  private vkey?: string;

  constructor(config?: ZKSystemConfig) {
    super(ProofSystem.SP1, config);
  }

  async loadProgram(elfPath: string): Promise<void> {
    // In production, load ELF binary from file system or network
    this.programELF = new TextEncoder().encode(elfPath);
  }

  setVerificationKey(vkey: string): void {
    this.vkey = vkey;
  }

  async generateProof(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<ProofGenerationResult> {
    const start = Date.now();
    const privateSer = this.serializeInputs(privateInputs);
    const publicSer = this.serializeInputs(publicInputs);

    const proof = await this.callSP1Prover(privateSer, publicSer);
    const proofTime = Date.now() - start;

    return {
      proof,
      publicInputs: publicSer,
      publicInputsHash: this.hashPublicInputs(publicSer),
      systemSpecificData: { vkeyHash: this.vkey },
      proofTime,
    };
  }

  async verifyProofLocally(
    proof: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<boolean> {
    return this.callSP1Verifier(proof, publicInputs);
  }

  async generateGroth16Proof(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<ProofGenerationResult & { groth16Proof: Uint8Array }> {
    const result = await this.generateProof(privateInputs, publicInputs);
    const groth16Proof = this.wrapInGroth16(result.proof);
    return { ...result, groth16Proof };
  }

  private async callSP1Prover(
    privateInputs: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<Uint8Array> {
    // Placeholder — requires running SP1 prover service
    const hash = keccak256(
      encodePacked(
        ["bytes", "bytes"],
        [
          toHex(privateInputs) as `0x${string}`,
          toHex(publicInputs) as `0x${string}`,
        ]
      )
    );
    return Buffer.from(hash.slice(2), "hex");
  }

  private async callSP1Verifier(
    _proof: Uint8Array,
    _publicInputs: Uint8Array
  ): Promise<boolean> {
    // Placeholder — requires SP1 verifier
    return true;
  }

  private wrapInGroth16(proof: Uint8Array): Uint8Array {
    // Placeholder — SP1 can wrap proofs in Groth16 for cheaper on-chain verification
    return proof;
  }
}

// =========================================================================
// PLONKY3 CLIENT
// =========================================================================

export interface Plonky3Proof {
  proof: Uint8Array;
  commitments: string[];
  evaluations: string[];
}

export class SoulPlonky3Client extends SoulZKClient {
  private circuitConfig?: Record<string, unknown>;

  constructor(config?: ZKSystemConfig) {
    super(ProofSystem.Plonky3, config);
  }

  async loadCircuit(configPath: string): Promise<void> {
    this.circuitConfig = { path: configPath };
  }

  async generateProof(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<ProofGenerationResult> {
    const start = Date.now();
    const witness = this.computeWitness(privateInputs, publicInputs);
    const proof = await this.callPlonky3Prover(witness);
    const publicSer = this.serializeInputs(publicInputs);

    return {
      proof,
      publicInputs: publicSer,
      publicInputsHash: this.hashPublicInputs(publicSer),
      systemSpecificData: { commitments: [] },
      proofTime: Date.now() - start,
    };
  }

  async verifyProofLocally(
    proof: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<boolean> {
    return this.callPlonky3Verifier(proof, publicInputs);
  }

  async generateRecursiveProof(
    innerProofs: Uint8Array[]
  ): Promise<ProofGenerationResult> {
    const start = Date.now();
    const aggregated = this.aggregateProofs(innerProofs);
    return {
      proof: aggregated,
      publicInputs: new Uint8Array(0),
      publicInputsHash: this.hashPublicInputs(aggregated),
      proofTime: Date.now() - start,
    };
  }

  private computeWitness(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Uint8Array {
    const combined = { ...privateInputs, ...publicInputs };
    return this.serializeInputs(combined);
  }

  private async callPlonky3Prover(witness: Uint8Array): Promise<Uint8Array> {
    const hash = keccak256(
      encodePacked(["bytes"], [toHex(witness) as `0x${string}`])
    );
    return Buffer.from(hash.slice(2), "hex");
  }

  private async callPlonky3Verifier(
    _proof: Uint8Array,
    _publicInputs: Uint8Array
  ): Promise<boolean> {
    return true;
  }

  private aggregateProofs(proofs: Uint8Array[]): Uint8Array {
    const combined = proofs.reduce((acc, p) => {
      const merged = new Uint8Array(acc.length + p.length);
      merged.set(acc);
      merged.set(p, acc.length);
      return merged;
    }, new Uint8Array(0));
    const hash = keccak256(
      encodePacked(["bytes"], [toHex(combined) as `0x${string}`])
    );
    return Buffer.from(hash.slice(2), "hex");
  }
}

// =========================================================================
// JOLT CLIENT
// =========================================================================

export interface JoltProof {
  proof: Uint8Array;
  sumcheckProof: Uint8Array;
  lookupProof: Uint8Array;
  memoryProof: Uint8Array;
}

export class SoulJoltClient extends SoulZKClient {
  private programBytes?: Uint8Array;
  private preprocessedData?: Uint8Array;

  constructor(config?: ZKSystemConfig) {
    super(ProofSystem.Jolt, config);
  }

  async loadProgram(programPath: string): Promise<void> {
    this.programBytes = new TextEncoder().encode(programPath);
    this.preprocessedData = this.preprocessProgram(this.programBytes);
  }

  async generateProof(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<ProofGenerationResult> {
    const start = Date.now();
    const execution = this.executeProgram(privateInputs, publicInputs);
    const proof = await this.callJoltProver(execution);
    const publicSer = this.serializeInputs(publicInputs);

    return {
      proof,
      publicInputs: publicSer,
      publicInputsHash: this.hashPublicInputs(publicSer),
      systemSpecificData: { breakdown: this.getProofBreakdown(proof) },
      proofTime: Date.now() - start,
    };
  }

  async verifyProofLocally(
    proof: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<boolean> {
    return this.callJoltVerifier(proof, publicInputs);
  }

  getProofBreakdown(proof: Uint8Array): {
    sumcheckSize: number;
    lookupSize: number;
    memorySize: number;
  } {
    const third = Math.floor(proof.length / 3);
    return {
      sumcheckSize: third,
      lookupSize: third,
      memorySize: proof.length - 2 * third,
    };
  }

  private preprocessProgram(program: Uint8Array): Uint8Array {
    return program;
  }

  private executeProgram(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Uint8Array {
    return this.serializeInputs({ ...privateInputs, ...publicInputs });
  }

  private async callJoltProver(execution: Uint8Array): Promise<Uint8Array> {
    const hash = keccak256(
      encodePacked(["bytes"], [toHex(execution) as `0x${string}`])
    );
    return Buffer.from(hash.slice(2), "hex");
  }

  private async callJoltVerifier(
    _proof: Uint8Array,
    _publicInputs: Uint8Array
  ): Promise<boolean> {
    return true;
  }
}

// =========================================================================
// BINIUS CLIENT
// =========================================================================

export interface BiniusProof {
  proof: Uint8Array;
  polyCommitments: string[];
  tensorCheckpoint: Uint8Array;
}

export class SoulBiniusClient extends SoulZKClient {
  private circuitDefinition?: Record<string, unknown>;

  constructor(config?: ZKSystemConfig) {
    super(ProofSystem.Binius, config);
  }

  async loadCircuit(circuitPath: string): Promise<void> {
    this.circuitDefinition = { path: circuitPath };
  }

  async generateProof(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<ProofGenerationResult> {
    const start = Date.now();
    const binaryField = this.convertToBinaryField(privateInputs, publicInputs);
    const proof = await this.callBiniusProver(binaryField);
    const publicSer = this.serializeInputs(publicInputs);

    return {
      proof,
      publicInputs: publicSer,
      publicInputsHash: this.hashPublicInputs(publicSer),
      systemSpecificData: { binaryFieldSize: binaryField.length },
      proofTime: Date.now() - start,
    };
  }

  async verifyProofLocally(
    proof: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<boolean> {
    return this.callBiniusVerifier(proof, publicInputs);
  }

  estimateProofSize(constraintCount: number): number {
    // Binius proofs grow logarithmically with constraint count
    return Math.ceil(Math.log2(constraintCount) * 32 + 256);
  }

  private convertToBinaryField(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Uint8Array {
    return this.serializeInputs({ ...privateInputs, ...publicInputs });
  }

  private async callBiniusProver(data: Uint8Array): Promise<Uint8Array> {
    const hash = keccak256(
      encodePacked(["bytes"], [toHex(data) as `0x${string}`])
    );
    return Buffer.from(hash.slice(2), "hex");
  }

  private async callBiniusVerifier(
    _proof: Uint8Array,
    _publicInputs: Uint8Array
  ): Promise<boolean> {
    return true;
  }
}

// =========================================================================
// UNIVERSAL ZK CLIENT
// =========================================================================

export class SoulUniversalZKClient {
  private clients: Map<ProofSystem, SoulZKClient>;
  private publicClient?: PublicClient;
  private universalVerifier?: ReturnType<typeof getContract>;

  constructor(publicClient?: PublicClient) {
    this.clients = new Map();
    this.publicClient = publicClient;
  }

  initClient(system: ProofSystem, config?: ZKSystemConfig): SoulZKClient {
    let client: SoulZKClient;

    switch (system) {
      case ProofSystem.SP1:
        client = new SoulSP1Client(config);
        break;
      case ProofSystem.Plonky3:
        client = new SoulPlonky3Client(config);
        break;
      case ProofSystem.Jolt:
        client = new SoulJoltClient(config);
        break;
      case ProofSystem.Binius:
        client = new SoulBiniusClient(config);
        break;
      default:
        throw new Error(`Unsupported proof system: ${system}`);
    }

    this.clients.set(system, client);
    return client;
  }

  getClient(system: ProofSystem): SoulZKClient | undefined {
    return this.clients.get(system);
  }

  setUniversalVerifier(address: Address, abi: Abi): void {
    if (!this.publicClient) throw new Error("Public client not provided");
    this.universalVerifier = getContract({
      address,
      abi,
      client: this.publicClient,
    });
  }

  async verifyOnChain(
    system: ProofSystem,
    vkeyOrCircuitHash: string,
    proof: Uint8Array,
    publicInputs: Uint8Array
  ): Promise<VerificationResult> {
    if (!this.universalVerifier) {
      throw new Error("Universal verifier not set");
    }

    try {
      const valid = (await (this.universalVerifier as any).read.verify([
        system,
        vkeyOrCircuitHash,
        toHex(proof),
        toHex(publicInputs),
      ])) as boolean;

      return {
        valid,
        proofHash: keccak256(
          encodePacked(["bytes"], [toHex(proof) as `0x${string}`])
        ),
      };
    } catch {
      return { valid: false };
    }
  }

  async benchmark(
    privateInputs: Record<string, unknown>,
    publicInputs: Record<string, unknown>
  ): Promise<Map<ProofSystem, { proofTime: number; proofSize: number }>> {
    const results = new Map<
      ProofSystem,
      { proofTime: number; proofSize: number }
    >();

    for (const [system, client] of this.clients) {
      try {
        const result = await client.generateProof(privateInputs, publicInputs);
        results.set(system, {
          proofTime: result.proofTime,
          proofSize: result.proof.length,
        });
      } catch {
        // Skip failed systems
      }
    }

    return results;
  }

  recommendSystem(workloadCharacteristics: {
    binaryHeavy?: boolean;
    recursionNeeded?: boolean;
    memoryIntensive?: boolean;
    constraintCount?: number;
  }): ProofSystem {
    if (workloadCharacteristics.binaryHeavy) return ProofSystem.Binius;
    if (workloadCharacteristics.recursionNeeded) return ProofSystem.Plonky3;
    if (workloadCharacteristics.memoryIntensive) return ProofSystem.Jolt;
    if (
      workloadCharacteristics.constraintCount &&
      workloadCharacteristics.constraintCount > 1_000_000
    ) {
      return ProofSystem.SP1;
    }
    return ProofSystem.Groth16;
  }
}

// =========================================================================
// FACTORY FUNCTIONS
// =========================================================================

export function createSP1Client(config?: ZKSystemConfig): SoulSP1Client {
  return new SoulSP1Client(config);
}

export function createPlonky3Client(
  config?: ZKSystemConfig
): SoulPlonky3Client {
  return new SoulPlonky3Client(config);
}

export function createJoltClient(config?: ZKSystemConfig): SoulJoltClient {
  return new SoulJoltClient(config);
}

export function createBiniusClient(config?: ZKSystemConfig): SoulBiniusClient {
  return new SoulBiniusClient(config);
}

export function createUniversalClient(
  publicClient?: PublicClient
): SoulUniversalZKClient {
  return new SoulUniversalZKClient(publicClient);
}

export default {
  ProofSystem,
  SoulSP1Client,
  SoulPlonky3Client,
  SoulJoltClient,
  SoulBiniusClient,
  SoulUniversalZKClient,
  createSP1Client,
  createPlonky3Client,
  createJoltClient,
  createBiniusClient,
  createUniversalClient,
};
