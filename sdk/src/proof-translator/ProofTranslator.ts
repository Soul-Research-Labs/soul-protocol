/**
 * @fileoverview Proof Translation Engine
 * Converts ZK proofs between different formats and curves
 * Supports: snarkjs, gnark, arkworks, circom
 */

import { 
  keccak256, 
  encodeFunctionData, 
  toHex, 
  concat, 
  zeroHash,
  type Hex 
} from "viem";

/*//////////////////////////////////////////////////////////////
                          TYPES
//////////////////////////////////////////////////////////////*/

export interface G1Point {
  x: bigint;
  y: bigint;
}

export interface G2Point {
  x: [bigint, bigint]; // [x_c0, x_c1] for Fp2
  y: [bigint, bigint]; // [y_c0, y_c1] for Fp2
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

/*//////////////////////////////////////////////////////////////
                        CURVE PARAMETERS
//////////////////////////////////////////////////////////////*/

export const CURVE_PARAMS = {
  bn254: {
    name: "BN254",
    fieldModulus:
      21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    baseFieldModulus:
      21888242871839275222246405745257275088696311157297823662689037894645226208583n,
    g1Size: 64, // 2 x 32 bytes
    g2Size: 128, // 4 x 32 bytes
    proofSize: 256, // 64 + 128 + 64
  },
  "bls12-381": {
    name: "BLS12-381",
    fieldModulus:
      52435875175126190479447740508185965837690552500527637822603658699938581184513n,
    baseFieldModulus:
      4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n,
    g1Size: 96, // 2 x 48 bytes
    g2Size: 192, // 4 x 48 bytes
    proofSize: 384, // 96 + 192 + 96
  },
  "bls12-377": {
    name: "BLS12-377",
    fieldModulus:
      8444461749428370424248824938781546531375899335154063827935233455917409239041n,
    baseFieldModulus:
      258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177n,
    g1Size: 96,
    g2Size: 192,
    proofSize: 384,
  },
} as const;

/*//////////////////////////////////////////////////////////////
                      FORMAT PARSERS
//////////////////////////////////////////////////////////////*/

/**
 * Parse snarkjs proof format
 */
export function parseSnarkjsProof(proof: any): Groth16Proof {
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
    protocol: "groth16",
    curve: "bn254",
  };
}

/**
 * Parse gnark proof format (JSON)
 */
export function parseGnarkProof(proofJson: any): Groth16Proof {
  // gnark uses different field names
  const ar = proofJson.Ar || proofJson.ar;
  const bs = proofJson.Bs || proofJson.bs;
  const krs = proofJson.Krs || proofJson.krs;

  return {
    pi_a: {
      x: BigInt(ar.X || ar.x),
      y: BigInt(ar.Y || ar.y),
    },
    pi_b: {
      x: [BigInt(bs.X.A0 || bs.x.a0), BigInt(bs.X.A1 || bs.x.a1)],
      y: [BigInt(bs.Y.A0 || bs.y.a0), BigInt(bs.Y.A1 || bs.y.a1)],
    },
    pi_c: {
      x: BigInt(krs.X || krs.x),
      y: BigInt(krs.Y || krs.y),
    },
    protocol: "groth16",
    curve: "bn254",
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

  // Arkworks format: A || B || C
  let offset = 0;

  // Parse A (G1)
  const aX = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const aY = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;

  // Parse B (G2) - Note: arkworks uses (c0, c1) ordering
  const bX0 = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const bX1 = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const bY0 = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const bY1 = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;

  // Parse C (G1)
  const cX = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));
  offset += coordSize;
  const cY = bytesToBigInt(proofBytes.slice(offset, offset + coordSize));

  return {
    pi_a: { x: aX, y: aY },
    pi_b: { x: [bX0, bX1], y: [bY0, bY1] },
    pi_c: { x: cX, y: cY },
    protocol: "groth16",
    curve,
  };
}

/*//////////////////////////////////////////////////////////////
                      FORMAT CONVERTERS
//////////////////////////////////////////////////////////////*/

/**
 * Convert proof to Solidity-compatible format for BN254
 */
export function toSolidityBN254(proof: Groth16Proof): {
  pA: [string, string];
  pB: [[string, string], [string, string]];
  pC: [string, string];
} {
  return {
    pA: [proof.pi_a.x.toString(), proof.pi_a.y.toString()],
    // Note: Solidity expects B in reversed order for snarkjs compatibility
    pB: [
      [proof.pi_b.x[1].toString(), proof.pi_b.x[0].toString()],
      [proof.pi_b.y[1].toString(), proof.pi_b.y[0].toString()],
    ],
    pC: [proof.pi_c.x.toString(), proof.pi_c.y.toString()],
  };
}

/**
 * Convert proof to bytes for on-chain submission (BN254)
 */
export function toBytesBN254(proof: Groth16Proof): Uint8Array {
  const bytes = new Uint8Array(256);
  let offset = 0;

  // A (64 bytes)
  offset = writeUint256(bytes, offset, proof.pi_a.x);
  offset = writeUint256(bytes, offset, proof.pi_a.y);

  // B (128 bytes) - note reversed order for snarkjs
  offset = writeUint256(bytes, offset, proof.pi_b.x[1]);
  offset = writeUint256(bytes, offset, proof.pi_b.x[0]);
  offset = writeUint256(bytes, offset, proof.pi_b.y[1]);
  offset = writeUint256(bytes, offset, proof.pi_b.y[0]);

  // C (64 bytes)
  offset = writeUint256(bytes, offset, proof.pi_c.x);
  writeUint256(bytes, offset, proof.pi_c.y);

  return bytes;
}

/**
 * Convert proof to bytes for BLS12-381 on-chain submission
 */
export function toBytesBLS12381(proof: Groth16Proof): Uint8Array {
  const bytes = new Uint8Array(384);
  let offset = 0;

  // A (96 bytes)
  offset = writeBytes48(bytes, offset, proof.pi_a.x);
  offset = writeBytes48(bytes, offset, proof.pi_a.y);

  // B (192 bytes)
  offset = writeBytes48(bytes, offset, proof.pi_b.x[0]);
  offset = writeBytes48(bytes, offset, proof.pi_b.x[1]);
  offset = writeBytes48(bytes, offset, proof.pi_b.y[0]);
  offset = writeBytes48(bytes, offset, proof.pi_b.y[1]);

  // C (96 bytes)
  offset = writeBytes48(bytes, offset, proof.pi_c.x);
  writeBytes48(bytes, offset, proof.pi_c.y);

  return bytes;
}

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
      X: { A0: proof.pi_b[0][0], A1: proof.pi_b[0][1] },
      Y: { A0: proof.pi_b[1][0], A1: proof.pi_b[1][1] },
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
  const ar = proof.Ar || proof.ar;
  const bs = proof.Bs || proof.bs;
  const krs = proof.Krs || proof.krs;

  return {
    pi_a: [ar.X || ar.x, ar.Y || ar.y, "1"],
    pi_b: [
      [bs.X.A0 || bs.x.a0, bs.X.A1 || bs.x.a1],
      [bs.Y.A0 || bs.y.a0, bs.Y.A1 || bs.y.a1],
      ["1", "0"],
    ],
    pi_c: [krs.X || krs.x, krs.Y || krs.y, "1"],
    protocol: "groth16",
    curve: "bn128",
  };
}

/*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN TRANSLATION
//////////////////////////////////////////////////////////////*/

export interface ChainConfig {
  chainId: number;
  name: string;
  curve: CurveType;
  verifierAddress?: string;
}

export const CHAIN_CONFIGS: Record<string, ChainConfig> = {
  ethereum: { chainId: 1, name: "Ethereum", curve: "bn254" },
  polygon: { chainId: 137, name: "Polygon", curve: "bn254" },
  arbitrum: { chainId: 42161, name: "Arbitrum", curve: "bn254" },
  optimism: { chainId: 10, name: "Optimism", curve: "bn254" },
  bsc: { chainId: 56, name: "BSC", curve: "bn254" },
  avalanche: { chainId: 43114, name: "Avalanche", curve: "bn254" },
  gnosis: { chainId: 100, name: "Gnosis", curve: "bn254" },
  // Future: chains with BLS12-381 support
  ethereumPectra: {
    chainId: 1,
    name: "Ethereum (Post-Pectra)",
    curve: "bls12-381",
  },
};

/**
 * Translate proof for target chain
 */
export function translateForChain(
  proof: Groth16Proof,
  publicSignals: bigint[],
  targetChain: string
): TranslationResult {
  const config = CHAIN_CONFIGS[targetChain];
  if (!config) {
    throw new Error(`Unknown chain: ${targetChain}`);
  }

  // Currently all EVM chains use BN254
  // BLS12-381 will be available post-Pectra
  if (proof.curve !== config.curve) {
    throw new Error(
      `Curve mismatch: proof is ${proof.curve}, chain requires ${config.curve}. ` +
        `Cross-curve proof translation requires recursive SNARKs.`
    );
  }

  const proofBytes =
    config.curve === "bn254" ? toBytesBN254(proof) : toBytesBLS12381(proof);

  return {
    proof,
    publicSignals,
    targetFormat: "solidity",
    targetCurve: config.curve,
    proofBytes,
  };
}

/**
 * Create calldata for on-chain verification
 */
export function createVerifyCalldata(
  proof: Groth16Proof,
  publicSignals: bigint[],
  curve: CurveType = "bn254"
): string {
  if (curve === "bn254") {
    const formatted = toSolidityBN254(proof);
    // Encode for verifyProof(uint[2] pA, uint[2][2] pB, uint[2] pC, uint[] pubSignals)
    // Encode for verifyProof(uint[2] pA, uint[2][2] pB, uint[2] pC, uint[] pubSignals)
    const abi = [{
      name: "verifyProof",
      type: "function",
      inputs: [
        { type: "uint256[2]", name: "pA" },
        { type: "uint256[2][2]", name: "pB" },
        { type: "uint256[2]", name: "pC" },
        { type: "uint256[]", name: "pubSignals" }
      ],
      outputs: [{ type: "bool" }]
    }] as const;

    return encodeFunctionData({
      abi,
      functionName: "verifyProof",
      args: [
        formatted.pA.map(BigInt),
        [
          [BigInt(formatted.pB[0][0]), BigInt(formatted.pB[0][1])],
          [BigInt(formatted.pB[1][0]), BigInt(formatted.pB[1][1])]
        ],
        formatted.pC.map(BigInt),
        publicSignals
      ]
    });
  }

  // BLS12-381: encode as raw bytes
  const proofBytes = toBytesBLS12381(proof);
  const signalsBytes = encodePublicSignals(publicSignals);

  const abi = [{
    name: "verifyProof",
    type: "function",
    inputs: [
      { type: "bytes", name: "proof" },
      { type: "bytes", name: "publicInputs" }
    ],
    outputs: [{ type: "bool" }]
  }] as const;

  return encodeFunctionData({
    abi,
    functionName: "verifyProof",
    args: [
      toHex(proofBytes),
      toHex(signalsBytes)
    ]
  });
}

/*//////////////////////////////////////////////////////////////
                      BATCH OPERATIONS
//////////////////////////////////////////////////////////////*/

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
  if (proofs.length === 0) {
    throw new Error("No proofs to batch");
  }

  const curve = proofs[0].curve;
  const proofSize = CURVE_PARAMS[curve].proofSize;

  // Concatenate all proofs
  const batchProofBytes = new Uint8Array(proofs.length * proofSize);
  const proofHashes: string[] = [];

  for (let i = 0; i < proofs.length; i++) {
    const proofBytes =
      curve === "bn254" ? toBytesBN254(proofs[i]) : toBytesBLS12381(proofs[i]);

    batchProofBytes.set(proofBytes, i * proofSize);
    proofHashes.push(keccak256(toHex(proofBytes)));
  }

  // Concatenate all public signals
  const signalsByteArrays = publicSignalsArray.map(encodePublicSignals);
  const totalSignalsLength = signalsByteArrays.reduce(
    (acc, arr) => acc + arr.length + 4,
    0
  );
  const batchSignalsBytes = new Uint8Array(totalSignalsLength);

  let offset = 0;
  for (const signals of signalsByteArrays) {
    // Write length prefix (4 bytes)
    const view = new DataView(batchSignalsBytes.buffer);
    view.setUint32(offset, signals.length, false);
    offset += 4;
    batchSignalsBytes.set(signals, offset);
    offset += signals.length;
  }

  // Compute merkle root of proof hashes
  const merkleRoot = computeMerkleRoot(proofHashes);

  return {
    batchProofBytes,
    batchSignalsBytes,
    merkleRoot,
  };
}

/*//////////////////////////////////////////////////////////////
                        UTILITIES
//////////////////////////////////////////////////////////////*/

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function writeUint256(
  bytes: Uint8Array,
  offset: number,
  value: bigint
): number {
  const hex = value.toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) {
    bytes[offset + i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return offset + 32;
}

function writeBytes48(
  bytes: Uint8Array,
  offset: number,
  value: bigint
): number {
  const hex = value.toString(16).padStart(96, "0");
  for (let i = 0; i < 48; i++) {
    bytes[offset + i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return offset + 48;
}

function encodePublicSignals(signals: bigint[]): Uint8Array {
  const bytes = new Uint8Array(signals.length * 32);
  for (let i = 0; i < signals.length; i++) {
    writeUint256(bytes, i * 32, signals[i]);
  }
  return bytes;
}

function computeMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return zeroHash;
  if (leaves.length === 1) return leaves[0];

  const nextLevel: string[] = [];
  for (let i = 0; i < leaves.length; i += 2) {
    const left = leaves[i];
    const right = leaves[i + 1] || left; // Duplicate last if odd
    nextLevel.push(keccak256(concat([left as Hex, right as Hex])));
  }

  return computeMerkleRoot(nextLevel);
}

/*//////////////////////////////////////////////////////////////
                          EXPORTS
//////////////////////////////////////////////////////////////*/

export default {
  // Parsers
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,

  // Converters
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  snarkjsToGnark,
  gnarkToSnarkjs,

  // Cross-chain
  translateForChain,
  createVerifyCalldata,

  // Batch
  createBatchProofData,

  // Constants
  CURVE_PARAMS,
  CHAIN_CONFIGS,
};
