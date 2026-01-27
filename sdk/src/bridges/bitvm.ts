/**
 * Soul SDK - BitVM Bridge Utilities
 * 
 * Provides TypeScript interfaces and utilities for BitVM integration
 */

import { ethers } from "ethers";

// ============================================
// Types
// ============================================

export interface BitVMDeposit {
  depositId: string;
  depositor: string;
  prover: string;
  amount: bigint;
  stake: bigint;
  circuitCommitment: string;
  taprootPubKey: string;
  outputCommitment: string;
  state: DepositState;
  initiatedAt: number;
  finalizedAt: number;
  challengeDeadline: number;
}

export enum DepositState {
  PENDING = 0,
  COMMITTED = 1,
  CHALLENGED = 2,
  FINALIZED = 3,
  SLASHED = 4,
  REFUNDED = 5
}

export interface BitVMChallenge {
  challengeId: string;
  depositId: string;
  challenger: string;
  gateId: string;
  gateIndex: number;
  stake: bigint;
  deadline: number;
  responseDeadline: number;
  expectedOutput: string;
  claimedOutput: string;
  state: ChallengeState;
  createdAt: number;
  resolvedAt: number;
}

export enum ChallengeState {
  OPEN = 0,
  RESPONDED = 1,
  ESCALATED = 2,
  PROVER_WON = 3,
  CHALLENGER_WON = 4,
  EXPIRED = 5
}

export enum GateType {
  NAND = 0,
  AND = 1,
  OR = 2,
  XOR = 3,
  NOT = 4
}

export interface Gate {
  gateId: string;
  gateType: GateType;
  inputA: string;
  inputB: string;
  output: string;
  layer: number;
}

export interface BitCommitment {
  commitmentId: string;
  hash0: string;  // H(preimage || 0)
  hash1: string;  // H(preimage || 1)
  revealed: boolean;
  value?: number;
  preimage?: string;
}

export interface Circuit {
  circuitId: string;
  numInputs: number;
  numOutputs: number;
  numGates: number;
  numLayers: number;
  merkleRoot: string;
  gates: Gate[];
  compiled: boolean;
}

export interface FraudProof {
  circuitRoot: string;
  gateId: string;
  inputA: number;
  inputB: number;
  claimedOutput: number;
  expectedOutput: number;
  merkleProof: string[];
  gateIndex: number;
}

// ============================================
// BitVM Circuit Compiler
// ============================================

export class BitVMCircuitCompiler {
  private gates: Gate[] = [];
  private nextGateId = 0;
  private layers: Map<number, Gate[]> = new Map();

  /**
   * Create a new NAND gate
   */
  addNAND(inputA: string, inputB: string, layer: number): string {
    const gateId = ethers.keccak256(
      ethers.solidityPacked(
        ["string", "string", "uint256"],
        [inputA, inputB, this.nextGateId++]
      )
    );

    const gate: Gate = {
      gateId,
      gateType: GateType.NAND,
      inputA,
      inputB,
      output: `${gateId}_out`,
      layer
    };

    this.gates.push(gate);
    
    if (!this.layers.has(layer)) {
      this.layers.set(layer, []);
    }
    this.layers.get(layer)!.push(gate);

    return gate.output;
  }

  /**
   * Create AND from NAND gates (2 gates)
   */
  addAND(inputA: string, inputB: string, layer: number): string {
    const nand1 = this.addNAND(inputA, inputB, layer);
    return this.addNAND(nand1, nand1, layer + 1);
  }

  /**
   * Create OR from NAND gates (3 gates)
   */
  addOR(inputA: string, inputB: string, layer: number): string {
    const notA = this.addNAND(inputA, inputA, layer);
    const notB = this.addNAND(inputB, inputB, layer);
    return this.addNAND(notA, notB, layer + 1);
  }

  /**
   * Create XOR from NAND gates (4 gates)
   */
  addXOR(inputA: string, inputB: string, layer: number): string {
    const nandAB = this.addNAND(inputA, inputB, layer);
    const left = this.addNAND(inputA, nandAB, layer + 1);
    const right = this.addNAND(inputB, nandAB, layer + 1);
    return this.addNAND(left, right, layer + 2);
  }

  /**
   * Create NOT from NAND gate (1 gate)
   */
  addNOT(input: string, layer: number): string {
    return this.addNAND(input, input, layer);
  }

  /**
   * Compile circuit and compute Merkle root
   */
  compile(): { merkleRoot: string; gates: Gate[]; numLayers: number } {
    const leaves = this.gates.map(gate => 
      ethers.keccak256(
        ethers.solidityPacked(
          ["bytes32", "uint8", "string", "string", "string", "uint256"],
          [gate.gateId, gate.gateType, gate.inputA, gate.inputB, gate.output, gate.layer]
        )
      )
    );

    const merkleRoot = this.computeMerkleRoot(leaves);

    return {
      merkleRoot,
      gates: this.gates,
      numLayers: this.layers.size
    };
  }

  /**
   * Compute Merkle root from leaves
   */
  private computeMerkleRoot(leaves: string[]): string {
    if (leaves.length === 0) return ethers.ZeroHash;
    if (leaves.length === 1) return leaves[0];

    // Pad to power of 2
    let size = 1;
    while (size < leaves.length) size *= 2;
    
    const tree = [...leaves];
    while (tree.length < size) {
      tree.push(ethers.ZeroHash);
    }

    // Build tree bottom-up
    while (tree.length > 1) {
      const newLevel: string[] = [];
      for (let i = 0; i < tree.length; i += 2) {
        newLevel.push(
          ethers.keccak256(
            ethers.solidityPacked(["bytes32", "bytes32"], [tree[i], tree[i + 1]])
          )
        );
      }
      tree.length = 0;
      tree.push(...newLevel);
    }

    return tree[0];
  }

  /**
   * Get Merkle proof for a gate
   */
  getMerkleProof(gateIndex: number): string[] {
    const leaves = this.gates.map(gate =>
      ethers.keccak256(
        ethers.solidityPacked(
          ["bytes32", "uint8", "string", "string", "string", "uint256"],
          [gate.gateId, gate.gateType, gate.inputA, gate.inputB, gate.output, gate.layer]
        )
      )
    );

    // Pad to power of 2
    let size = 1;
    while (size < leaves.length) size *= 2;
    while (leaves.length < size) leaves.push(ethers.ZeroHash);

    const proof: string[] = [];
    let index = gateIndex;
    let levelNodes = leaves;

    while (levelNodes.length > 1) {
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
      proof.push(levelNodes[siblingIndex]);

      const newLevel: string[] = [];
      for (let i = 0; i < levelNodes.length; i += 2) {
        newLevel.push(
          ethers.keccak256(
            ethers.solidityPacked(["bytes32", "bytes32"], [levelNodes[i], levelNodes[i + 1]])
          )
        );
      }
      levelNodes = newLevel;
      index = Math.floor(index / 2);
    }

    return proof;
  }

  /**
   * Reset compiler state
   */
  reset(): void {
    this.gates = [];
    this.nextGateId = 0;
    this.layers.clear();
  }
}

// ============================================
// Bit Commitment Utilities
// ============================================

export class BitCommitmentManager {
  private commitments: Map<string, BitCommitment> = new Map();

  /**
   * Create a bit commitment pair
   */
  createCommitment(preimage: string): BitCommitment {
    const hash0 = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "uint8"], [preimage, 0])
    );
    const hash1 = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "uint8"], [preimage, 1])
    );

    const commitmentId = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "bytes32"], [hash0, hash1])
    );

    const commitment: BitCommitment = {
      commitmentId,
      hash0,
      hash1,
      revealed: false
    };

    this.commitments.set(commitmentId, commitment);
    return commitment;
  }

  /**
   * Reveal a bit commitment
   */
  revealCommitment(
    commitmentId: string,
    value: number,
    preimage: string
  ): boolean {
    const commitment = this.commitments.get(commitmentId);
    if (!commitment) return false;

    const computedHash = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "uint8"], [preimage, value])
    );

    const expectedHash = value === 0 ? commitment.hash0 : commitment.hash1;
    
    if (computedHash !== expectedHash) return false;

    commitment.revealed = true;
    commitment.value = value;
    commitment.preimage = preimage;

    return true;
  }

  /**
   * Verify a bit reveal
   */
  verifyReveal(
    hash0: string,
    hash1: string,
    value: number,
    preimage: string
  ): boolean {
    const computedHash = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "uint8"], [preimage, value])
    );
    const expectedHash = value === 0 ? hash0 : hash1;
    return computedHash === expectedHash;
  }

  /**
   * Get commitment by ID
   */
  getCommitment(commitmentId: string): BitCommitment | undefined {
    return this.commitments.get(commitmentId);
  }
}

// ============================================
// Gate Computation
// ============================================

export function computeNAND(a: number, b: number): number {
  return (a & b) === 1 ? 0 : 1;
}

export function computeAND(a: number, b: number): number {
  const nand1 = computeNAND(a, b);
  return computeNAND(nand1, nand1);
}

export function computeOR(a: number, b: number): number {
  const notA = computeNAND(a, a);
  const notB = computeNAND(b, b);
  return computeNAND(notA, notB);
}

export function computeXOR(a: number, b: number): number {
  const nandAB = computeNAND(a, b);
  const left = computeNAND(a, nandAB);
  const right = computeNAND(b, nandAB);
  return computeNAND(left, right);
}

export function computeNOT(a: number): number {
  return computeNAND(a, a);
}

// ============================================
// Fraud Proof Builder
// ============================================

export class FraudProofBuilder {
  /**
   * Build a fraud proof for an invalid gate
   */
  static buildFraudProof(
    circuit: Circuit,
    gateIndex: number,
    inputA: number,
    inputB: number,
    claimedOutput: number,
    merkleProof: string[]
  ): FraudProof {
    const gate = circuit.gates[gateIndex];
    
    // Compute expected output based on gate type
    let expectedOutput: number;
    switch (gate.gateType) {
      case GateType.NAND:
        expectedOutput = computeNAND(inputA, inputB);
        break;
      case GateType.AND:
        expectedOutput = computeAND(inputA, inputB);
        break;
      case GateType.OR:
        expectedOutput = computeOR(inputA, inputB);
        break;
      case GateType.XOR:
        expectedOutput = computeXOR(inputA, inputB);
        break;
      case GateType.NOT:
        expectedOutput = computeNOT(inputA);
        break;
      default:
        expectedOutput = 0;
    }

    return {
      circuitRoot: circuit.merkleRoot,
      gateId: gate.gateId,
      inputA,
      inputB,
      claimedOutput,
      expectedOutput,
      merkleProof,
      gateIndex
    };
  }

  /**
   * Verify a fraud proof is valid
   */
  static verifyFraudProof(proof: FraudProof): boolean {
    // Fraud exists if claimed output doesn't match expected
    return proof.claimedOutput !== proof.expectedOutput;
  }
}

// ============================================
// BitVM Bridge Client
// ============================================

export class BitVMBridgeClient {
  private provider: ethers.Provider;
  private signer?: ethers.Signer;
  private bridgeAddress: string;

  constructor(
    bridgeAddress: string,
    provider: ethers.Provider,
    signer?: ethers.Signer
  ) {
    this.bridgeAddress = bridgeAddress;
    this.provider = provider;
    this.signer = signer;
  }

  /**
   * Initiate a BitVM deposit
   */
  async initiateDeposit(
    amount: bigint,
    circuitCommitment: string,
    prover: string,
    stake: bigint
  ): Promise<string> {
    if (!this.signer) throw new Error("Signer required");

    const contract = new ethers.Contract(
      this.bridgeAddress,
      ["function initiateDeposit(uint256,bytes32,address) payable returns (bytes32)"],
      this.signer
    );

    const tx = await contract.initiateDeposit(amount, circuitCommitment, prover, {
      value: stake
    });
    const receipt = await tx.wait();

    // Extract depositId from event
    const depositId = receipt.logs[0]?.topics[1];
    return depositId || ethers.ZeroHash;
  }

  /**
   * Open a challenge
   */
  async openChallenge(
    depositId: string,
    gateId: string,
    expectedOutput: string,
    stake: bigint
  ): Promise<string> {
    if (!this.signer) throw new Error("Signer required");

    const contract = new ethers.Contract(
      this.bridgeAddress,
      ["function openChallenge(bytes32,bytes32,bytes32) payable returns (bytes32)"],
      this.signer
    );

    const tx = await contract.openChallenge(depositId, gateId, expectedOutput, {
      value: stake
    });
    const receipt = await tx.wait();

    const challengeId = receipt.logs[0]?.topics[1];
    return challengeId || ethers.ZeroHash;
  }

  /**
   * Prove fraud
   */
  async proveFraud(
    challengeId: string,
    gateId: string,
    inputA: number,
    inputB: number,
    preimageA: string,
    preimageB: string
  ): Promise<boolean> {
    if (!this.signer) throw new Error("Signer required");

    const contract = new ethers.Contract(
      this.bridgeAddress,
      ["function proveFraud(bytes32,bytes32,uint8,uint8,bytes32,bytes32)"],
      this.signer
    );

    const tx = await contract.proveFraud(
      challengeId,
      gateId,
      inputA,
      inputB,
      preimageA,
      preimageB
    );
    await tx.wait();

    return true;
  }

  /**
   * Get deposit info
   */
  async getDeposit(depositId: string): Promise<BitVMDeposit> {
    const contract = new ethers.Contract(
      this.bridgeAddress,
      ["function getDeposit(bytes32) view returns (tuple)"],
      this.provider
    );

    return await contract.getDeposit(depositId);
  }

  /**
   * Get bridge stats
   */
  async getStats(): Promise<{
    deposits: bigint;
    challenges: bigint;
    slashed: bigint;
    finalized: bigint;
  }> {
    const contract = new ethers.Contract(
      this.bridgeAddress,
      ["function getBridgeStats() view returns (uint256,uint256,uint256,uint256)"],
      this.provider
    );

    const [deposits, challenges, slashed, finalized] = await contract.getBridgeStats();
    return { deposits, challenges, slashed, finalized };
  }
}
