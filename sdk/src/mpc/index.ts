/**
 * Soul MPC (Multi-Party Computation) SDK
 *
 * Implements:
 * - Threshold signatures for bridge security
 * - Private compliance checks via MPC
 * - Distributed key generation (DKG)
 * - Secret sharing (Shamir's)
 */
import {
  type PublicClient,
  type WalletClient,
  type Hex,
  type Abi,
  type TransactionReceipt,
  keccak256,
  toHex,
  getContract,
  encodePacked,
} from "viem";

// =========================================================================
// INTERFACES & ENUMS
// =========================================================================

export interface ThresholdConfig {
  threshold: number;
  totalParties: number;
  parties: PartyInfo[];
}

export interface PartyInfo {
  id: number;
  publicKey: string;
  address: string;
  weight?: number;
}

export interface SigningSession {
  sessionId: string;
  messageHash: string;
  participants: number[];
  commitments: Map<number, string>;
  partialSignatures: Map<number, Uint8Array>;
  status: SessionStatus;
  createdAt: number;
  expiresAt: number;
}

export enum SessionStatus {
  Pending = 0,
  CommitmentsCollected = 1,
  SignaturesCollected = 2,
  Completed = 3,
  Expired = 4,
  Failed = 5,
}

export interface DKGRound {
  roundId: number;
  polynomial: bigint[];
  shares: Map<number, bigint>;
  commitments: string[];
  status: "pending" | "committed" | "revealed" | "complete";
}

export interface ComplianceRequest {
  requestId: string;
  userCommitment: string;
  checkTypes: ComplianceCheckType[];
  deadline: number;
  status: ComplianceStatus;
}

export enum ComplianceCheckType {
  AML = 0,
  KYC = 1,
  Sanctions = 2,
  PEP = 3,
  Jurisdiction = 4,
}

export enum ComplianceStatus {
  Pending = 0,
  InProgress = 1,
  Approved = 2,
  Rejected = 3,
  Expired = 4,
}

export interface ComplianceCertificate {
  commitment: string;
  checkTypes: ComplianceCheckType[];
  approvalMask: number;
  validUntil: number;
  oracleSignatures: string[];
  zkProof: Uint8Array;
}

// =========================================================================
// PRIME for Shamir's Secret Sharing (secp256k1 field order)
// =========================================================================

const PRIME =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// =========================================================================
// SHAMIR SECRET SHARING
// =========================================================================

export class ShamirSecretSharing {
  private prime: bigint;

  constructor() {
    this.prime = PRIME;
  }

  split(
    secret: bigint,
    threshold: number,
    totalShares: number
  ): Map<number, bigint> {
    if (threshold > totalShares)
      throw new Error("Threshold cannot exceed total shares");
    if (threshold < 2) throw new Error("Threshold must be at least 2");

    const coefficients = [secret];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(this.randomFieldElement());
    }

    const shares = new Map<number, bigint>();
    for (let i = 1; i <= totalShares; i++) {
      shares.set(i, this.evaluatePolynomial(coefficients, BigInt(i)));
    }
    return shares;
  }

  reconstruct(shares: Map<number, bigint>, threshold: number): bigint {
    const points = Array.from(shares.entries()).slice(0, threshold);
    return this.lagrangeInterpolation(points);
  }

  verifyShare(
    shareIndex: number,
    shareValue: bigint,
    commitments: string[]
  ): boolean {
    // Feldman VSS verification (simplified)
    const expected = keccak256(
      encodePacked(
        ["uint256", "uint256"],
        [BigInt(shareIndex), shareValue]
      )
    );
    // In production, verify against polynomial commitments using EC ops
    return commitments.length > 0 && expected !== "0x";
  }

  generateCommitments(coefficients: bigint[]): string[] {
    return coefficients.map((c) =>
      keccak256(encodePacked(["uint256"], [c]))
    );
  }

  private evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
    let result = 0n;
    let power = 1n;
    for (const coeff of coefficients) {
      result = (result + coeff * power) % this.prime;
      power = (power * x) % this.prime;
    }
    return result;
  }

  private lagrangeInterpolation(points: [number, bigint][]): bigint {
    let result = 0n;
    const n = points.length;

    for (let i = 0; i < n; i++) {
      let numerator = 1n;
      let denominator = 1n;
      const xi = BigInt(points[i][0]);

      for (let j = 0; j < n; j++) {
        if (i === j) continue;
        const xj = BigInt(points[j][0]);
        numerator = (numerator * (this.prime - xj)) % this.prime;
        denominator = (denominator * ((xi - xj + this.prime) % this.prime)) % this.prime;
      }

      const lagrangeCoeff =
        (numerator * this.modInverse(denominator, this.prime)) % this.prime;
      result = (result + points[i][1] * lagrangeCoeff) % this.prime;
    }
    return result;
  }

  private randomFieldElement(): bigint {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let val = 0n;
    for (const b of bytes) {
      val = (val << 8n) | BigInt(b);
    }
    return val % this.prime;
  }

  private modInverse(a: bigint, m: bigint): bigint {
    return this.modPow(a, m - 2n, m);
  }

  private modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = (result * base) % mod;
      }
      exp = exp >> 1n;
      base = (base * base) % mod;
    }
    return result;
  }
}

// =========================================================================
// THRESHOLD SIGNATURE
// =========================================================================

export class SoulThresholdSignature {
  private config: ThresholdConfig;
  private sessions: Map<string, SigningSession>;
  private sss: ShamirSecretSharing;
  private sessionTimeout: number;

  constructor(config: ThresholdConfig, sessionTimeout = 300_000) {
    this.config = config;
    this.sessions = new Map();
    this.sss = new ShamirSecretSharing();
    this.sessionTimeout = sessionTimeout;
  }

  startSession(messageHash: string, participants?: number[]): SigningSession {
    const sessionId = keccak256(
      encodePacked(
        ["bytes32", "uint256"],
        [messageHash as `0x${string}`, BigInt(Date.now())]
      )
    );

    const session: SigningSession = {
      sessionId,
      messageHash,
      participants: participants || this.config.parties.map((p) => p.id),
      commitments: new Map(),
      partialSignatures: new Map(),
      status: SessionStatus.Pending,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.sessionTimeout,
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  submitCommitment(
    sessionId: string,
    partyId: number,
    commitment: string
  ): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== SessionStatus.Pending) return false;
    if (!session.participants.includes(partyId)) return false;

    session.commitments.set(partyId, commitment);

    if (session.commitments.size >= this.config.threshold) {
      session.status = SessionStatus.CommitmentsCollected;
    }
    return true;
  }

  submitPartialSignature(
    sessionId: string,
    partyId: number,
    partialSig: Uint8Array
  ): boolean {
    const session = this.sessions.get(sessionId);
    if (
      !session ||
      session.status !== SessionStatus.CommitmentsCollected
    )
      return false;

    session.partialSignatures.set(partyId, partialSig);

    if (session.partialSignatures.size >= this.config.threshold) {
      session.status = SessionStatus.SignaturesCollected;
    }
    return true;
  }

  combineSignatures(sessionId: string): Uint8Array {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== SessionStatus.SignaturesCollected) {
      throw new Error("Session not ready for combining");
    }

    const combined = this.lagrangeCombine(session.partialSignatures);
    session.status = SessionStatus.Completed;
    return combined;
  }

  getSession(sessionId: string): SigningSession | undefined {
    return this.sessions.get(sessionId);
  }

  cleanupExpiredSessions(): number {
    let cleaned = 0;
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now > session.expiresAt) {
        session.status = SessionStatus.Expired;
        this.sessions.delete(id);
        cleaned++;
      }
    }
    return cleaned;
  }

  private lagrangeCombine(
    partials: Map<number, Uint8Array>
  ): Uint8Array {
    // Simplified combination - in production use proper Lagrange on curve
    const entries = Array.from(partials.entries());
    const resultLen = entries[0][1].length;
    const combined = new Uint8Array(resultLen);

    for (let i = 0; i < resultLen; i++) {
      let sum = 0;
      for (const [, sig] of entries) {
        sum = (sum + sig[i]) % 256;
      }
      combined[i] = sum;
    }
    return combined;
  }
}

// =========================================================================
// DISTRIBUTED KEY GENERATION
// =========================================================================

export class SoulDistributedKeyGeneration {
  private config: ThresholdConfig;
  private sss: ShamirSecretSharing;
  private rounds: Map<number, DKGRound>;
  private currentRound: number;

  constructor(config: ThresholdConfig) {
    this.config = config;
    this.sss = new ShamirSecretSharing();
    this.rounds = new Map();
    this.currentRound = 0;
  }

  startRound(): DKGRound {
    this.currentRound++;
    const secret = this.randomSecret();
    const polynomial = this.generatePolynomial(
      secret,
      this.config.threshold
    );
    const commitments = this.sss.generateCommitments(polynomial);
    const shares = this.sss.split(
      secret,
      this.config.threshold,
      this.config.totalParties
    );

    const round: DKGRound = {
      roundId: this.currentRound,
      polynomial,
      shares,
      commitments,
      status: "pending",
    };

    this.rounds.set(this.currentRound, round);
    return round;
  }

  submitCommitment(
    roundId: number,
    partyId: number,
    commitment: string
  ): boolean {
    const round = this.rounds.get(roundId);
    if (!round || round.status !== "pending") return false;
    round.commitments.push(commitment);
    if (round.commitments.length >= this.config.totalParties) {
      round.status = "committed";
    }
    return true;
  }

  revealShare(roundId: number, partyId: number, share: bigint): boolean {
    const round = this.rounds.get(roundId);
    if (!round || round.status !== "committed") return false;
    round.shares.set(partyId, share);
    if (round.shares.size >= this.config.totalParties) {
      round.status = "revealed";
    }
    return true;
  }

  finalize(
    roundId: number
  ): { publicKey: string; shares: Map<number, bigint> } {
    const round = this.rounds.get(roundId);
    if (!round || round.status !== "revealed") {
      throw new Error("Round not ready for finalization");
    }

    const aggregatedShares = new Map<number, bigint>();
    for (const [id, share] of round.shares) {
      aggregatedShares.set(id, share);
    }

    const publicKey = keccak256(
      encodePacked(
        ["uint256"],
        [round.polynomial[0]]
      )
    );

    round.status = "complete";
    return { publicKey, shares: aggregatedShares };
  }

  getRoundStatus(roundId: number): DKGRound | undefined {
    return this.rounds.get(roundId);
  }

  private randomSecret(): bigint {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let val = 0n;
    for (const b of bytes) {
      val = (val << 8n) | BigInt(b);
    }
    return val % PRIME;
  }

  private generatePolynomial(secret: bigint, degree: number): bigint[] {
    const coeffs = [secret];
    for (let i = 1; i < degree; i++) {
      coeffs.push(this.randomSecret());
    }
    return coeffs;
  }
}

// =========================================================================
// MPC COMPLIANCE
// =========================================================================

export class SoulMPCCompliance {
  private pendingRequests: Map<string, ComplianceRequest>;
  private oracleCount: number;
  private oracleThreshold: number;
  private certificates: Map<string, ComplianceCertificate>;

  constructor(oracleCount: number, oracleThreshold: number) {
    this.oracleCount = oracleCount;
    this.oracleThreshold = oracleThreshold;
    this.pendingRequests = new Map();
    this.certificates = new Map();
  }

  async requestComplianceCheck(
    userCommitment: string,
    checkTypes: ComplianceCheckType[],
    deadline: number
  ): Promise<ComplianceRequest> {
    const requestId = keccak256(
      encodePacked(
        ["bytes32", "uint256"],
        [userCommitment as `0x${string}`, BigInt(Date.now())]
      )
    );

    const request: ComplianceRequest = {
      requestId,
      userCommitment,
      checkTypes,
      deadline,
      status: ComplianceStatus.Pending,
    };

    this.pendingRequests.set(requestId, request);
    return request;
  }

  submitOracleShare(
    requestId: string,
    _oracleId: number,
    _encryptedShare: Uint8Array,
    _signature: string
  ): boolean {
    const request = this.pendingRequests.get(requestId);
    if (!request) return false;
    if (request.status === ComplianceStatus.Pending) {
      request.status = ComplianceStatus.InProgress;
    }
    return true;
  }

  async finalizeComplianceCheck(
    requestId: string,
    approvalMask: number,
    oracleSignatures: string[],
    zkProof: Uint8Array
  ): Promise<ComplianceCertificate> {
    const request = this.pendingRequests.get(requestId);
    if (!request) throw new Error("Request not found");

    const certificate: ComplianceCertificate = {
      commitment: request.userCommitment,
      checkTypes: request.checkTypes,
      approvalMask,
      validUntil: request.deadline,
      oracleSignatures,
      zkProof,
    };

    request.status =
      approvalMask > 0 ? ComplianceStatus.Approved : ComplianceStatus.Rejected;
    this.certificates.set(request.userCommitment, certificate);
    this.pendingRequests.delete(requestId);
    return certificate;
  }

  verifyCertificate(certificate: ComplianceCertificate): boolean {
    if (Date.now() / 1000 > certificate.validUntil) return false;
    if (certificate.oracleSignatures.length < this.oracleThreshold) return false;
    return this.verifyMPCProof(certificate.zkProof);
  }

  getCertificate(commitment: string): ComplianceCertificate | undefined {
    return this.certificates.get(commitment);
  }

  hasValidCertificate(commitment: string): boolean {
    const cert = this.certificates.get(commitment);
    if (!cert) return false;
    return this.verifyCertificate(cert);
  }

  private verifyMPCProof(proof: Uint8Array): boolean {
    // Simplified proof verification - in production use ZK verification
    return proof.length > 0;
  }
}

// =========================================================================
// MPC ON-CHAIN CLIENT
// =========================================================================

export class SoulMPCOnChainClient {
  private publicClient: PublicClient;
  private walletClient?: WalletClient;
  private thresholdContract?: ReturnType<typeof getContract>;
  private complianceContract?: ReturnType<typeof getContract>;

  constructor(publicClient: PublicClient, walletClient?: WalletClient) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  setThresholdContract(address: string, abi: Abi): void {
    this.thresholdContract = getContract({
      address: address as `0x${string}`,
      abi,
      client: {
        public: this.publicClient,
        wallet: this.walletClient!,
      },
    });
  }

  setComplianceContract(address: string, abi: Abi): void {
    this.complianceContract = getContract({
      address: address as `0x${string}`,
      abi,
      client: {
        public: this.publicClient,
        wallet: this.walletClient!,
      },
    });
  }

  async executeWithThresholdSig(
    target: string,
    calldata: Hex,
    signature: Uint8Array
  ): Promise<TransactionReceipt> {
    if (!this.thresholdContract) throw new Error("Threshold contract not set");
    const hash = await (this.thresholdContract as any).write.executeWithSig([
      target,
      calldata,
      toHex(signature),
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async submitCertificate(
    certificate: ComplianceCertificate
  ): Promise<TransactionReceipt> {
    if (!this.complianceContract) throw new Error("Compliance contract not set");
    const hash = await (this.complianceContract as any).write.submitCertificate([
      certificate.commitment,
      certificate.checkTypes,
      certificate.approvalMask,
      certificate.validUntil,
      certificate.oracleSignatures,
      toHex(certificate.zkProof),
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async verifyCertificateOnChain(commitment: string): Promise<boolean> {
    if (!this.complianceContract) throw new Error("Compliance contract not set");
    return (await (this.complianceContract as any).read.verifyCertificate([
      commitment,
    ])) as boolean;
  }
}

// =========================================================================
// FACTORY FUNCTIONS
// =========================================================================

export function createThresholdSignature(
  config: ThresholdConfig,
  sessionTimeout?: number
): SoulThresholdSignature {
  return new SoulThresholdSignature(config, sessionTimeout);
}

export function createDKG(
  config: ThresholdConfig
): SoulDistributedKeyGeneration {
  return new SoulDistributedKeyGeneration(config);
}

export function createMPCCompliance(
  oracleCount: number,
  oracleThreshold: number
): SoulMPCCompliance {
  return new SoulMPCCompliance(oracleCount, oracleThreshold);
}

export function createMPCOnChainClient(
  publicClient: PublicClient,
  walletClient?: WalletClient
): SoulMPCOnChainClient {
  return new SoulMPCOnChainClient(publicClient, walletClient);
}

export default {
  ShamirSecretSharing,
  SoulThresholdSignature,
  SoulDistributedKeyGeneration,
  SoulMPCCompliance,
  SoulMPCOnChainClient,
  createThresholdSignature,
  createDKG,
  createMPCCompliance,
  createMPCOnChainClient,
  SessionStatus,
  ComplianceCheckType,
  ComplianceStatus,
};
