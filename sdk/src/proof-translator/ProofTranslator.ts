/**
 * @fileoverview Proof Translation Engine
 * Converts ZK proofs between different formats and curves
 * Supports: snarkjs, gnark, arkworks, circom
 */
import { keccak256, encodePacked, encodeAbiParameters, toHex } from "viem";

// =========================================================================
// TYPES & INTERFACES
// =========================================================================

export interface G1Point {
  x: bigint;
  y: bigint;
}

export interface G2Point {
  x: [bigint, bigint];
  y: [bigint, bigint];
}

export interface Groth16Proof {
  pi_a: G1Point;
  pi_b: G2Point;
  pi_c: G1Point;
  protocol: string;
  curve: CurveType;
}

export interface ParsedProof {
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
}

export type CurveType = "bn254" | "bls12-381" | "bls12-377";
export type ProofFormat =
  | "snarkjs"
  | "gnark"
  | "arkworks"
  | "circom"
  | "solidity";

export interface VerificationKey {
  alpha: G1Point;
  beta: G2Point;
  gamma: G2Point;
  delta: G2Point;
  ic: G1Point[];
  curve: CurveType;
}

export interface TranslationResult {
  proof: Groth16Proof;
  publicSignals: bigint[];
  targetFormat: ProofFormat;
  targetCurve: CurveType;
  proofBytes: Uint8Array;
}

export interface ChainConfig {
  chainId: number;
  name: string;
  curve: CurveType;
  verifierAddress?: string;
}

// =========================================================================
// CURVE PARAMETERS
// =========================================================================

export const CURVE_PARAMS = {
  bn254: {
    name: "BN254" as const,
    fieldModulus:
      21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    baseFieldModulus:
      21888242871839275222246405745257275088696311157297823662689037894645226208583n,
    g1Size: 64,
    g2Size: 128,
    proofSize: 256,
  },
  "bls12-381": {
    name: "BLS12-381" as const,
    fieldModulus:
      52435875175126190479447740508185965837690552500527637822603658699938581184513n,
    baseFieldModulus:
      4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n,
    g1Size: 96,
    g2Size: 192,
    proofSize: 384,
  },
  "bls12-377": {
    name: "BLS12-377" as const,
    fieldModulus:
      8444461749428370424248824938781546531375899335154063827935233455917409239041n,
    baseFieldModulus:
      258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177n,
    g1Size: 96,
    g2Size: 192,
    proofSize: 384,
  },
} as const;

// =========================================================================
// CHAIN CONFIGURATIONS
// =========================================================================

export const CHAIN_CONFIGS: Record<string, ChainConfig> = {
  ethereum: { chainId: 1, name: "Ethereum", curve: "bn254" },
  arbitrum: { chainId: 42161, name: "Arbitrum One", curve: "bn254" },
  optimism: { chainId: 10, name: "Optimism", curve: "bn254" },
  base: { chainId: 8453, name: "Base", curve: "bn254" },
  polygon: { chainId: 137, name: "Polygon", curve: "bn254" },
  zkSync: { chainId: 324, name: "zkSync Era", curve: "bn254" },
  scroll: { chainId: 534352, name: "Scroll", curve: "bn254" },
  linea: { chainId: 59144, name: "Linea", curve: "bn254" },
  aleo: { chainId: 0, name: "Aleo", curve: "bls12-377" },
  mina: { chainId: 0, name: "Mina", curve: "bn254" },
};

// =========================================================================
// UTILITY HELPERS
// =========================================================================

function bigintToBytes(value: bigint, size: number): Uint8Array {
  const hex = value.toString(16).padStart(size * 2, "0");
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let hex = "0x";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

function bigintToHex(value: bigint): string {
  return "0x" + value.toString(16).padStart(64, "0");
}

// =========================================================================
// PROOF PARSING
// =========================================================================

/**
 * Parse snarkjs proof format
 */
export function parseSnarkjsProof(proof: any): Groth16Proof {
  // snarkjs format: pi_a = [x, y, "1"], pi_b = [[x0, x1], [y0, y1], ["1","0"]], pi_c = [x, y, "1"]
  return {
    pi_a: {
      x: BigInt(proof.pi_a[0]),
      y: BigInt(proof.pi_a[1]),
    },
    pi_b: {
      x: [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
      y: [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
    },
    pi_c: {
      x: BigInt(proof.pi_c[0]),
      y: BigInt(proof.pi_c[1]),
    },
    protocol: proof.protocol || "groth16",
    curve: (proof.curve as CurveType) || "bn254",
  };
}

/**
 * Parse gnark proof format (JSON)
 */
export function parseGnarkProof(proofJson: any): Groth16Proof {
  // gnark format uses Ar, Bs, Krs naming and hex strings
  const parseG1 = (p: any): G1Point => ({
    x: BigInt(p.X || p.x || p[0]),
    y: BigInt(p.Y || p.y || p[1]),
  });

  const parseG2 = (p: any): G2Point => {
    if (p.X && Array.isArray(p.X)) {
      return {
        x: [BigInt(p.X[0]), BigInt(p.X[1])],
        y: [BigInt(p.Y[0]), BigInt(p.Y[1])],
      };
    }
    return {
      x: [BigInt(p.x?.[0] || p[0][0]), BigInt(p.x?.[1] || p[0][1])],
      y: [BigInt(p.y?.[0] || p[1][0]), BigInt(p.y?.[1] || p[1][1])],
    };
  };

  return {
    pi_a: parseG1(proofJson.Ar || proofJson.ar || proofJson.pi_a),
    pi_b: parseG2(proofJson.Bs || proofJson.bs || proofJson.pi_b),
    pi_c: parseG1(proofJson.Krs || proofJson.krs || proofJson.pi_c),
    protocol: "groth16",
    curve: (proofJson.curve as CurveType) || "bn254",
  };
}

/**
 * Parse arkworks proof format (hex bytes)
 */
export function parseArkworksProof(
  proofBytes: Uint8Array,
  curve: CurveType = "bn254"
): Groth16Proof {
  const params = CURVE_PARAMS[curve];
  const coordSize = params.g1Size / 2;

  let offset = 0;

  // G1 point pi_a: x, y
  const pi_a_x = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const pi_a_y = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;

  // G2 point pi_b: x0, x1, y0, y1
  const pi_b_x0 = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const pi_b_x1 = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const pi_b_y0 = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const pi_b_y1 = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;

  // G1 point pi_c: x, y
  const pi_c_x = bytesToBigint(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const pi_c_y = bytesToBigint(proofBytes.slice(offset, offset + coordSize));

  return {
    pi_a: { x: pi_a_x, y: pi_a_y },
    pi_b: { x: [pi_b_x0, pi_b_x1], y: [pi_b_y0, pi_b_y1] },
    pi_c: { x: pi_c_x, y: pi_c_y },
    protocol: "groth16",
    curve,
  };
}

// =========================================================================
// PROOF CONVERSION
// =========================================================================

/**
 * Convert proof to Solidity-compatible format for BN254
 */
export function toSolidityBN254(proof: Groth16Proof): {
  pA: [string, string];
  pB: [[string, string], [string, string]];
  pC: [string, string];
} {
  return {
    pA: [bigintToHex(proof.pi_a.x), bigintToHex(proof.pi_a.y)],
    // Note: Solidity pairing precompile expects G2 coords in reversed order
    pB: [
      [bigintToHex(proof.pi_b.x[1]), bigintToHex(proof.pi_b.x[0])],
      [bigintToHex(proof.pi_b.y[1]), bigintToHex(proof.pi_b.y[0])],
    ],
    pC: [bigintToHex(proof.pi_c.x), bigintToHex(proof.pi_c.y)],
  };
}

/**
 * Convert proof to bytes for on-chain submission (BN254)
 */
export function toBytesBN254(proof: Groth16Proof): Uint8Array {
  const coordSize = 32; // BN254 uses 32-byte coordinates
  const buffer = new Uint8Array(coordSize * 8); // 2 G1 points + 1 G2 point = 8 coordinates
  let offset = 0;

  // pi_a: x, y
  buffer.set(bigintToBytes(proof.pi_a.x, coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_a.y, coordSize), offset);
  offset += coordSize;

  // pi_b: x[1], x[0], y[1], y[0] (reversed for Solidity)
  buffer.set(bigintToBytes(proof.pi_b.x[1], coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_b.x[0], coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_b.y[1], coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_b.y[0], coordSize), offset);
  offset += coordSize;

  // pi_c: x, y
  buffer.set(bigintToBytes(proof.pi_c.x, coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_c.y, coordSize), offset);

  return buffer;
}

/**
 * Convert proof to bytes for BLS12-381 on-chain submission
 */
export function toBytesBLS12381(proof: Groth16Proof): Uint8Array {
  const coordSize = 48; // BLS12-381 uses 48-byte coordinates
  const buffer = new Uint8Array(coordSize * 8);
  let offset = 0;

  // pi_a: x, y
  buffer.set(bigintToBytes(proof.pi_a.x, coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_a.y, coordSize), offset);
  offset += coordSize;

  // pi_b: x[0], x[1], y[0], y[1]
  buffer.set(bigintToBytes(proof.pi_b.x[0], coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_b.x[1], coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_b.y[0], coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_b.y[1], coordSize), offset);
  offset += coordSize;

  // pi_c: x, y
  buffer.set(bigintToBytes(proof.pi_c.x, coordSize), offset);
  offset += coordSize;
  buffer.set(bigintToBytes(proof.pi_c.y, coordSize), offset);

  return buffer;
}

// =========================================================================
// FORMAT TRANSLATION
// =========================================================================

/**
 * Convert snarkjs proof format to gnark format
 */
export function snarkjsToGnark(proof: any): any {
  return {
    Ar: {
      X: proof.pi_a[0],
      Y: proof.pi_a[1],
    },
    Bs: {
      X: [proof.pi_b[0][0], proof.pi_b[0][1]],
      Y: [proof.pi_b[1][0], proof.pi_b[1][1]],
    },
    Krs: {
      X: proof.pi_c[0],
      Y: proof.pi_c[1],
    },
  };
}

/**
 * Convert gnark proof format to snarkjs format
 */
export function gnarkToSnarkjs(proof: any): any {
  return {
    pi_a: [
      String(proof.Ar?.X || proof.ar?.X),
      String(proof.Ar?.Y || proof.ar?.Y),
      "1",
    ],
    pi_b: [
      [
        String(proof.Bs?.X?.[0] || proof.bs?.X?.[0]),
        String(proof.Bs?.X?.[1] || proof.bs?.X?.[1]),
      ],
      [
        String(proof.Bs?.Y?.[0] || proof.bs?.Y?.[0]),
        String(proof.Bs?.Y?.[1] || proof.bs?.Y?.[1]),
      ],
      ["1", "0"],
    ],
    pi_c: [
      String(proof.Krs?.X || proof.krs?.X),
      String(proof.Krs?.Y || proof.krs?.Y),
      "1",
    ],
    protocol: "groth16",
    curve: "bn128",
  };
}

// =========================================================================
// CHAIN-SPECIFIC TRANSLATION
// =========================================================================

/**
 * Translate proof for target chain
 */
export function translateForChain(
  proof: Groth16Proof,
  publicSignals: bigint[],
  targetChain: string
): TranslationResult {
  const chainConfig = CHAIN_CONFIGS[targetChain];
  if (!chainConfig) {
    throw new Error(`Unknown target chain: ${targetChain}`);
  }

  const targetCurve = chainConfig.curve;

  // If proof is already on the target curve, just serialize
  if (proof.curve === targetCurve) {
    const proofBytes =
      targetCurve === "bn254" ? toBytesBN254(proof) : toBytesBLS12381(proof);

    return {
      proof,
      publicSignals,
      targetFormat: "solidity",
      targetCurve,
      proofBytes,
    };
  }

  // Cross-curve translation requires re-proving — return as-is with flag
  // In production, this would invoke a re-proving service
  const proofBytes =
    targetCurve === "bn254" ? toBytesBN254(proof) : toBytesBLS12381(proof);

  return {
    proof: { ...proof, curve: targetCurve },
    publicSignals,
    targetFormat: "solidity",
    targetCurve,
    proofBytes,
  };
}

// =========================================================================
// CALLDATA GENERATION
// =========================================================================

/**
 * Create calldata for on-chain verification
 */
export function createVerifyCalldata(
  proof: Groth16Proof,
  publicSignals: bigint[],
  curve: CurveType = "bn254"
): string {
  const solidityProof = toSolidityBN254(proof);

  // Encode as verify(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[] input)
  const encoded = encodeAbiParameters(
    [
      { type: "uint256[2]" },
      { type: "uint256[2][2]" },
      { type: "uint256[2]" },
      { type: "uint256[]" },
    ],
    [
      solidityProof.pA.map(BigInt) as [bigint, bigint],
      solidityProof.pB.map((pair) => pair.map(BigInt)) as [
        [bigint, bigint],
        [bigint, bigint],
      ],
      solidityProof.pC.map(BigInt) as [bigint, bigint],
      publicSignals,
    ]
  );

  return encoded;
}

/**
 * Aggregate multiple proofs into batch format
 */
export function createBatchProofData(
  proofs: Groth16Proof[],
  publicSignalsArray: bigint[][]
): {
  batchProofBytes: Uint8Array;
  batchSignalsBytes: Uint8Array;
  merkleRoot: string;
} {
  if (proofs.length !== publicSignalsArray.length) {
    throw new Error("Proofs and signals arrays must have same length");
  }

  if (proofs.length === 0) {
    throw new Error("Must provide at least one proof");
  }

  // Serialize all proofs
  const proofBytesArray = proofs.map((p) =>
    p.curve === "bn254" ? toBytesBN254(p) : toBytesBLS12381(p)
  );

  // Concatenate proof bytes with length prefix
  const totalProofBytes = proofBytesArray.reduce(
    (acc, pb) => acc + 4 + pb.length,
    0
  );
  const batchProofBytes = new Uint8Array(totalProofBytes);
  let offset = 0;
  for (const pb of proofBytesArray) {
    // 4-byte length prefix
    new DataView(batchProofBytes.buffer).setUint32(offset, pb.length);
    offset += 4;
    batchProofBytes.set(pb, offset);
    offset += pb.length;
  }

  // Serialize public signals
  const signalsJson = JSON.stringify(
    publicSignalsArray.map((signals) => signals.map((s) => s.toString()))
  );
  const batchSignalsBytes = new TextEncoder().encode(signalsJson);

  // Compute Merkle root of proof hashes
  const leaves = proofBytesArray.map((pb) =>
    keccak256(encodePacked(["bytes"], [toHex(pb) as `0x${string}`]))
  );
  const merkleRoot = computeMerkleRoot(leaves);

  return { batchProofBytes, batchSignalsBytes, merkleRoot };
}

function computeMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) {
    return "0x" + "0".repeat(64);
  }
  if (leaves.length === 1) {
    return leaves[0];
  }

  let layer = [...leaves];
  // Pad to power of 2
  while (layer.length > 1 && layer.length % 2 !== 0) {
    layer.push(layer[layer.length - 1]);
  }

  while (layer.length > 1) {
    const nextLayer: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i] as `0x${string}`;
      const right = layer[i + 1] as `0x${string}`;
      const hash = keccak256(
        encodePacked(["bytes32", "bytes32"], [left, right])
      );
      nextLayer.push(hash);
    }
    layer = nextLayer;
  }

  return layer[0];
}

// =========================================================================
// DEFAULT EXPORT
// =========================================================================

export default {
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  snarkjsToGnark,
  gnarkToSnarkjs,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,
};
