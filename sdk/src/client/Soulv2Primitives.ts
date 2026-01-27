/**
 * Soul v2 Primitives SDK Clients
 * TypeScript clients for interacting with Soul Protocol's novel cryptographic primitives
 */

import { ethers, Contract, Signer, Provider, TransactionReceipt, Log } from "ethers";

/** Parsed event log with fragment name */
export interface ParsedEventLog extends Log {
  fragment?: { name: string };
  args?: Record<string, unknown>;
}

/**
 * Helper to check if a value is a Signer (duck typing for ethers v6)
 */
function isSigner(value: unknown): value is Signer {
  return value !== null && typeof value === 'object' && 'getAddress' in value && 'signMessage' in value;
}

/*//////////////////////////////////////////////////////////////
                        SHARED TYPES
//////////////////////////////////////////////////////////////*/

export interface TransactionOptions {
  gasLimit?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
}

export interface ProofBundle {
  validityProof: string;
  policyProof: string;
  nullifierProof: string;
  proofHash: string;
  proofTimestamp: bigint;
  proofExpiry: bigint;
}

/*//////////////////////////////////////////////////////////////
              PROOF CARRYING CONTAINER (PC³) CLIENT
//////////////////////////////////////////////////////////////*/

export interface Container {
  encryptedPayload: string;
  stateCommitment: string;
  nullifier: string;
  proofs: ProofBundle;
  policyHash: string;
  chainId: bigint;
  createdAt: bigint;
  version: number;
  isVerified: boolean;
  isConsumed: boolean;
}

export interface ContainerCreationParams {
  encryptedPayload: string;
  stateCommitment: string;
  nullifier: string;
  validityProof: string;
  policyProof: string;
  nullifierProof: string;
  proofExpiry: number;
  policyHash: string;
}

export interface VerificationResult {
  validityValid: boolean;
  policyValid: boolean;
  nullifierValid: boolean;
  notExpired: boolean;
  notConsumed: boolean;
  failureReason: string;
}

/**
 * Client for ProofCarryingContainer (PC³) contract
 * Self-authenticating confidential containers with embedded proofs
 */
export class ProofCarryingContainerClient {
  private contract: Contract;
  private signer: Signer | null;

  constructor(
    contractAddress: string,
    providerOrSigner: Provider | Signer,
    abi?: any[]
  ) {
    const defaultABI = [
      // Read functions
      "function containers(bytes32) view returns (tuple(bytes encryptedPayload, bytes32 stateCommitment, bytes32 nullifier, tuple(bytes validityProof, bytes policyProof, bytes nullifierProof, bytes32 proofHash, uint256 proofTimestamp, uint256 proofExpiry) proofs, bytes32 policyHash, uint64 chainId, uint64 createdAt, uint32 version, bool isVerified, bool isConsumed))",
      "function consumedNullifiers(bytes32) view returns (bool)",
      "function supportedPolicies(bytes32) view returns (bool)",
      "function totalContainers() view returns (uint256)",
      "function totalVerified() view returns (uint256)",
      "function getContainerIds(uint256 offset, uint256 limit) view returns (bytes32[])",
      
      // Write functions
      "function createContainer(bytes encryptedPayload, bytes32 stateCommitment, bytes32 nullifier, bytes validityProof, bytes policyProof, bytes nullifierProof, uint256 proofExpiry, bytes32 policyHash) returns (bytes32)",
      "function verifyContainer(bytes32 containerId) returns (bool)",
      "function batchVerifyContainers(bytes32[] containerIds) returns (bool[])",
      "function consumeContainer(bytes32 containerId)",
      "function exportContainer(bytes32 containerId, uint64 targetChainId) returns (bytes)",
      "function importContainer(bytes exportedData, bytes crossChainProof) returns (bytes32)",
      "function addSupportedPolicy(bytes32 policyHash)",
      
      // Events
      "event ContainerCreated(bytes32 indexed containerId, bytes32 indexed stateCommitment, bytes32 indexed nullifier, bytes32 policyHash)",
      "event ContainerVerified(bytes32 indexed containerId, bool success)",
      "event ContainerConsumed(bytes32 indexed containerId, bytes32 indexed nullifier)",
      "event ContainerExported(bytes32 indexed containerId, uint64 indexed targetChainId)",
      "event ContainerImported(bytes32 indexed containerId, uint64 indexed sourceChainId)",
    ];

    this.contract = new ethers.Contract(
      contractAddress,
      abi || defaultABI,
      providerOrSigner
    );
    this.signer = isSigner(providerOrSigner) ? providerOrSigner : null;
  }

  /**
   * Create a new self-authenticating container
   */
  async createContainer(
    params: ContainerCreationParams,
    options?: TransactionOptions
  ): Promise<{ tx: TransactionReceipt; containerId: string }> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.createContainer(
      params.encryptedPayload,
      params.stateCommitment,
      params.nullifier,
      params.validityProof,
      params.policyProof,
      params.nullifierProof,
      params.proofExpiry,
      params.policyHash,
      options || {}
    );
    const receipt = await tx.wait();
    
    // Extract containerId from event
    const event = receipt.logs.find(
      (log: Log) => (log as ParsedEventLog).fragment?.name === "ContainerCreated"
    ) as ParsedEventLog | undefined;
    const containerId = (event?.args?.containerId as string) || "";

    return { tx: receipt, containerId };
  }

  /**
   * Verify a container's embedded proofs
   */
  async verifyContainer(
    containerId: string,
    options?: TransactionOptions
  ): Promise<boolean> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.verifyContainer(containerId, options || {});
    await tx.wait();
    return true;
  }

  /**
   * Batch verify multiple containers
   */
  async batchVerifyContainers(
    containerIds: string[],
    options?: TransactionOptions
  ): Promise<boolean[]> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.batchVerifyContainers(containerIds, options || {});
    const receipt = await tx.wait();
    return receipt;
  }

  /**
   * Consume a container (marks nullifier as used)
   */
  async consumeContainer(
    containerId: string,
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.consumeContainer(containerId, options || {});
    await tx.wait();
  }

  /**
   * Export container for cross-chain transfer
   */
  async exportContainer(
    containerId: string,
    targetChainId: bigint,
    options?: TransactionOptions
  ): Promise<string> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.exportContainer(containerId, targetChainId, options || {});
    const receipt = await tx.wait();
    return receipt;
  }

  /**
   * Get container by ID
   */
  async getContainer(containerId: string): Promise<Container | null> {
    const container = await this.contract.containers(containerId);
    if (!container || container.stateCommitment === ethers.ZeroHash) {
      return null;
    }
    return container;
  }

  /**
   * Get paginated list of container IDs
   */
  async getContainerIds(offset: number, limit: number): Promise<string[]> {
    return await this.contract.getContainerIds(offset, limit);
  }

  /**
   * Check if a nullifier has been consumed
   */
  async isNullifierConsumed(nullifier: string): Promise<boolean> {
    return await this.contract.consumedNullifiers(nullifier);
  }

  /**
   * Get total containers created
   */
  async getTotalContainers(): Promise<bigint> {
    return await this.contract.totalContainers();
  }
}

/*//////////////////////////////////////////////////////////////
              POLICY BOUND PROOFS (PBP) CLIENT
//////////////////////////////////////////////////////////////*/

export interface DisclosurePolicy {
  policyId: string;
  policyHash: string;
  name: string;
  description: string;
  requiresIdentity: boolean;
  requiresJurisdiction: boolean;
  requiresAmount: boolean;
  requiresCounterparty: boolean;
  minAmount: bigint;
  maxAmount: bigint;
  allowedAssets: string[];
  blockedCountries: string[];
  createdAt: bigint;
  expiresAt: bigint;
  isActive: boolean;
}

export interface PolicyCreationParams {
  name: string;
  description: string;
  requiresIdentity: boolean;
  requiresJurisdiction: boolean;
  requiresAmount: boolean;
  requiresCounterparty: boolean;
  minAmount: bigint;
  maxAmount: bigint;
  allowedAssets: string[];
  blockedCountries: string[];
  expiresAt: number;
}

export interface BoundProofParams {
  proof: string;
  policyHash: string;
  domainSeparator: string;
  publicInputs: string[];
  expiresAt: number;
}

/**
 * Client for PolicyBoundProofs (PBP) contract
 * Proofs cryptographically scoped by disclosure policy
 */
export class PolicyBoundProofsClient {
  private contract: Contract;
  private signer: Signer | null;

  constructor(
    contractAddress: string,
    providerOrSigner: Provider | Signer,
    abi?: any[]
  ) {
    const defaultABI = [
      // Read functions
      "function policies(bytes32) view returns (tuple(bytes32 policyId, bytes32 policyHash, string name, string description, bool requiresIdentity, bool requiresJurisdiction, bool requiresAmount, bool requiresCounterparty, uint256 minAmount, uint256 maxAmount, bytes32[] allowedAssets, bytes32[] blockedCountries, uint64 createdAt, uint64 expiresAt, bool isActive))",
      "function verificationKeys(bytes32) view returns (tuple(bytes32 vkHash, bytes32 policyHash, bytes32 domainSeparator, bool isActive, uint64 registeredAt))",
      "function totalPolicies() view returns (uint256)",
      "function totalVerifications() view returns (uint256)",
      "function getPolicyIds(uint256 offset, uint256 limit) view returns (bytes32[])",
      "function getVkHashes(uint256 offset, uint256 limit) view returns (bytes32[])",
      
      // Write functions
      "function registerPolicy(string name, string description, bool requiresIdentity, bool requiresJurisdiction, bool requiresAmount, bool requiresCounterparty, uint256 minAmount, uint256 maxAmount, bytes32[] allowedAssets, bytes32[] blockedCountries, uint64 expiresAt) returns (bytes32)",
      "function bindVerificationKey(bytes32 vkHash, bytes32 policyHash) returns (bytes32)",
      "function verifyBoundProof(bytes proof, bytes32 policyHash, bytes32 domainSeparator, bytes32[] publicInputs, uint64 expiresAt) returns (bool)",
      "function batchCheckPolicies(bytes32[] policyHashes) view returns (bool[])",
      
      // Events
      "event PolicyRegistered(bytes32 indexed policyId, bytes32 indexed policyHash, string name)",
      "event VerificationKeyBound(bytes32 indexed vkHash, bytes32 indexed policyHash, bytes32 domainSeparator)",
      "event BoundProofVerified(bytes32 indexed policyHash, bytes32 indexed domainSeparator, bool success)",
    ];

    this.contract = new ethers.Contract(
      contractAddress,
      abi || defaultABI,
      providerOrSigner
    );
    this.signer = isSigner(providerOrSigner) ? providerOrSigner : null;
  }

  /**
   * Register a new disclosure policy
   */
  async registerPolicy(
    params: PolicyCreationParams,
    options?: TransactionOptions
  ): Promise<{ tx: any; policyId: string; policyHash: string }> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.registerPolicy(
      params.name,
      params.description,
      params.requiresIdentity,
      params.requiresJurisdiction,
      params.requiresAmount,
      params.requiresCounterparty,
      params.minAmount,
      params.maxAmount,
      params.allowedAssets,
      params.blockedCountries,
      params.expiresAt,
      options || {}
    );
    const receipt = await tx.wait();
    
    const event = receipt.logs.find(
      (log: any) => log.fragment?.name === "PolicyRegistered"
    );

    return {
      tx: receipt,
      policyId: event?.args?.policyId || "",
      policyHash: event?.args?.policyHash || "",
    };
  }

  /**
   * Bind a verification key to a policy
   */
  async bindVerificationKey(
    vkHash: string,
    policyHash: string,
    options?: TransactionOptions
  ): Promise<string> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.bindVerificationKey(vkHash, policyHash, options || {});
    const receipt = await tx.wait();
    
    const event = receipt.logs.find(
      (log: any) => log.fragment?.name === "VerificationKeyBound"
    );
    return event?.args?.domainSeparator || "";
  }

  /**
   * Verify a policy-bound proof
   */
  async verifyBoundProof(
    params: BoundProofParams,
    options?: TransactionOptions
  ): Promise<boolean> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.verifyBoundProof(
      params.proof,
      params.policyHash,
      params.domainSeparator,
      params.publicInputs,
      params.expiresAt,
      options || {}
    );
    await tx.wait();
    return true;
  }

  /**
   * Check if multiple policies exist and are active
   */
  async batchCheckPolicies(policyHashes: string[]): Promise<boolean[]> {
    return await this.contract.batchCheckPolicies(policyHashes);
  }

  /**
   * Get policy by ID
   */
  async getPolicy(policyId: string): Promise<DisclosurePolicy | null> {
    const policy = await this.contract.policies(policyId);
    if (!policy || policy.policyHash === ethers.ZeroHash) {
      return null;
    }
    return policy;
  }

  /**
   * Get paginated policy IDs
   */
  async getPolicyIds(offset: number, limit: number): Promise<string[]> {
    return await this.contract.getPolicyIds(offset, limit);
  }

  /**
   * Get paginated verification key hashes
   */
  async getVkHashes(offset: number, limit: number): Promise<string[]> {
    return await this.contract.getVkHashes(offset, limit);
  }
}

/*//////////////////////////////////////////////////////////////
     EXECUTION AGNOSTIC STATE COMMITMENTS (EASC) CLIENT
//////////////////////////////////////////////////////////////*/

export enum BackendType {
  ZkVM = 0,
  TEE = 1,
  MPC = 2,
  FHE = 3,
  Native = 4,
}

export interface ExecutionBackend {
  backendId: string;
  backendType: BackendType;
  name: string;
  attestationKey: string;
  configHash: string;
  registeredAt: bigint;
  lastAttestation: bigint;
  isActive: boolean;
  trustScore: bigint;
}

export interface BackendRegistrationParams {
  backendType: BackendType;
  name: string;
  attestationKey: string;
  configHash: string;
  initialTrustScore: number;
}

export interface CommitmentParams {
  stateHash: string;
  transitionHash: string;
  nullifier: string;
  requiredAttestations: number;
}

export interface AttestationParams {
  commitmentId: string;
  backendId: string;
  attestationProof: string;
  executionHash: string;
}

export interface CommitmentStats {
  totalCommitments: bigint;
  totalAttestations: bigint;
  activeBackends: bigint;
}

/**
 * Client for ExecutionAgnosticStateCommitments (EASC) contract
 * Backend-independent state commitments with multi-attestation
 */
export class ExecutionAgnosticStateCommitmentsClient {
  private contract: Contract;
  private signer: Signer | null;

  constructor(
    contractAddress: string,
    providerOrSigner: Provider | Signer,
    abi?: any[]
  ) {
    const defaultABI = [
      // Read functions
      "function backends(bytes32) view returns (tuple(bytes32 backendId, uint8 backendType, string name, bytes32 attestationKey, bytes32 configHash, uint64 registeredAt, uint64 lastAttestation, bool isActive, uint256 trustScore))",
      "function getCommitment(bytes32) view returns (tuple(bytes32 commitmentId, bytes32 stateHash, bytes32 transitionHash, bytes32 nullifier, bytes32[] attestedBackends, address creator, uint64 createdAt, uint32 attestationCount, bool isFinalized))",
      "function consumedNullifiers(bytes32) view returns (bool)",
      "function totalCommitments() view returns (uint256)",
      "function totalAttestations() view returns (uint256)",
      "function getActiveBackends() view returns (bytes32[])",
      "function getStats() view returns (uint256, uint256, uint256)",
      
      // Write functions
      "function registerBackend(uint8 backendType, string name, bytes32 attestationKey, bytes32 configHash, uint256 initialTrustScore) returns (bytes32)",
      "function createCommitment(bytes32 stateHash, bytes32 transitionHash, bytes32 nullifier, uint32 requiredAttestations) returns (bytes32)",
      "function attestCommitment(bytes32 commitmentId, bytes32 backendId, bytes attestationProof, bytes32 executionHash)",
      "function batchCheckCommitments(bytes32[] commitmentIds) view returns (bool[])",
      "function updateTrustScore(bytes32 backendId, uint256 newScore)",
      "function deactivateBackend(bytes32 backendId)",
      
      // Events
      "event BackendRegistered(bytes32 indexed backendId, uint8 backendType, string name)",
      "event CommitmentCreated(bytes32 indexed commitmentId, bytes32 indexed stateHash, bytes32 nullifier)",
      "event CommitmentAttested(bytes32 indexed commitmentId, bytes32 indexed backendId)",
      "event CommitmentFinalized(bytes32 indexed commitmentId)",
    ];

    this.contract = new ethers.Contract(
      contractAddress,
      abi || defaultABI,
      providerOrSigner
    );
    this.signer = isSigner(providerOrSigner) ? providerOrSigner : null;
  }

  /**
   * Register a new execution backend
   */
  async registerBackend(
    params: BackendRegistrationParams,
    options?: TransactionOptions
  ): Promise<{ tx: any; backendId: string }> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.registerBackend(
      params.backendType,
      params.name,
      params.attestationKey,
      params.configHash,
      params.initialTrustScore,
      options || {}
    );
    const receipt = await tx.wait();
    
    const event = receipt.logs.find(
      (log: any) => log.fragment?.name === "BackendRegistered"
    );
    return { tx: receipt, backendId: event?.args?.backendId || "" };
  }

  /**
   * Create a new execution-agnostic commitment
   */
  async createCommitment(
    params: CommitmentParams,
    options?: TransactionOptions
  ): Promise<{ tx: any; commitmentId: string }> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.createCommitment(
      params.stateHash,
      params.transitionHash,
      params.nullifier,
      params.requiredAttestations,
      options || {}
    );
    const receipt = await tx.wait();
    
    const event = receipt.logs.find(
      (log: any) => log.fragment?.name === "CommitmentCreated"
    );
    return { tx: receipt, commitmentId: event?.args?.commitmentId || "" };
  }

  /**
   * Attest a commitment from a backend
   */
  async attestCommitment(
    params: AttestationParams,
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.attestCommitment(
      params.commitmentId,
      params.backendId,
      params.attestationProof,
      params.executionHash,
      options || {}
    );
    await tx.wait();
  }

  /**
   * Batch check if commitments are finalized
   */
  async batchCheckCommitments(commitmentIds: string[]): Promise<boolean[]> {
    return await this.contract.batchCheckCommitments(commitmentIds);
  }

  /**
   * Get backend by ID
   */
  async getBackend(backendId: string): Promise<ExecutionBackend | null> {
    const backend = await this.contract.backends(backendId);
    if (!backend || backend.backendId === ethers.ZeroHash) {
      return null;
    }
    return backend;
  }

  /**
   * Get active backend IDs
   */
  async getActiveBackends(): Promise<string[]> {
    return await this.contract.getActiveBackends();
  }

  /**
   * Get contract stats
   */
  async getStats(): Promise<CommitmentStats> {
    const [total, attestations, backends] = await this.contract.getStats();
    return {
      totalCommitments: total,
      totalAttestations: attestations,
      activeBackends: backends,
    };
  }
}

/*//////////////////////////////////////////////////////////////
       CROSS DOMAIN NULLIFIER ALGEBRA (CDNA) CLIENT
//////////////////////////////////////////////////////////////*/

export interface Domain {
  domainId: string;
  chainId: bigint;
  appId: string;
  epochStart: bigint;
  epochEnd: bigint;
  domainSeparator: string;
  isActive: boolean;
  registeredAt: bigint;
}

export interface DomainNullifier {
  nullifier: string;
  domainId: string;
  commitmentHash: string;
  transitionId: string;
  parentNullifier: string;
  childNullifiers: string[];
  registrar: string;
  registeredAt: bigint;
  epochId: bigint;
  isConsumed: boolean;
}

export interface DomainRegistrationParams {
  chainId: bigint;
  appId: string;
  epochStart: number;
  epochEnd: number;
}

export interface NullifierRegistrationParams {
  domainId: string;
  nullifier: string;
  commitmentHash: string;
  transitionId: string;
  registrationProof: string;
}

export interface DerivedNullifierParams {
  parentNullifier: string;
  childNullifier: string;
  targetDomainId: string;
  derivationProof: string;
}

export interface NullifierStats {
  totalDomains: bigint;
  totalNullifiers: bigint;
  totalConsumed: bigint;
  currentEpoch: bigint;
}

/**
 * Client for CrossDomainNullifierAlgebra (CDNA) contract
 * Domain-separated nullifiers with cross-chain double-spend prevention
 */
export class CrossDomainNullifierAlgebraClient {
  private contract: Contract;
  private signer: Signer | null;

  constructor(
    contractAddress: string,
    providerOrSigner: Provider | Signer,
    abi?: any[]
  ) {
    const defaultABI = [
      // Read functions
      "function domains(bytes32) view returns (tuple(bytes32 domainId, uint64 chainId, bytes32 appId, uint64 epochStart, uint64 epochEnd, bytes32 domainSeparator, bool isActive, uint64 registeredAt))",
      "function nullifiers(bytes32) view returns (tuple(bytes32 nullifier, bytes32 domainId, bytes32 commitmentHash, bytes32 transitionId, bytes32 parentNullifier, bytes32[] childNullifiers, address registrar, uint64 registeredAt, uint64 epochId, bool isConsumed))",
      "function nullifierExists(bytes32) view returns (bool)",
      "function totalDomains() view returns (uint256)",
      "function totalNullifiers() view returns (uint256)",
      "function currentEpoch() view returns (uint64)",
      "function getActiveDomains() view returns (bytes32[])",
      "function getStats() view returns (uint256, uint256, uint256, uint64)",
      
      // Write functions
      "function registerDomain(uint64 chainId, bytes32 appId, uint64 epochStart, uint64 epochEnd) returns (bytes32)",
      "function registerNullifier(bytes32 domainId, bytes32 nullifier, bytes32 commitmentHash, bytes32 transitionId, bytes registrationProof) returns (bytes32)",
      "function registerDerivedNullifier(bytes32 parentNullifier, bytes32 childNullifier, bytes32 targetDomainId, bytes derivationProof)",
      "function consumeNullifier(bytes32 nullifier)",
      "function batchCheckNullifiers(bytes32[] nullifierList) view returns (bool[])",
      "function batchConsumeNullifiers(bytes32[] nullifierList)",
      "function verifyCrossDomainProof(bytes32 sourceNullifier, bytes32 targetNullifier, bytes32 sourceDomainId, bytes32 targetDomainId, bytes proof) returns (bool)",
      "function finalizeEpoch()",
      
      // Events
      "event DomainRegistered(bytes32 indexed domainId, uint64 indexed chainId, bytes32 appId)",
      "event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed domainId, bytes32 commitmentHash)",
      "event DerivedNullifierRegistered(bytes32 indexed parentNullifier, bytes32 indexed childNullifier, bytes32 indexed targetDomainId)",
      "event NullifierConsumed(bytes32 indexed nullifier, bytes32 indexed domainId)",
      "event EpochFinalized(uint64 indexed epochId, bytes32 merkleRoot)",
    ];

    this.contract = new ethers.Contract(
      contractAddress,
      abi || defaultABI,
      providerOrSigner
    );
    this.signer = isSigner(providerOrSigner) ? providerOrSigner : null;
  }

  /**
   * Register a new domain for nullifier separation
   */
  async registerDomain(
    params: DomainRegistrationParams,
    options?: TransactionOptions
  ): Promise<{ tx: any; domainId: string }> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.registerDomain(
      params.chainId,
      params.appId,
      params.epochStart,
      params.epochEnd,
      options || {}
    );
    const receipt = await tx.wait();
    
    const event = receipt.logs.find(
      (log: any) => log.fragment?.name === "DomainRegistered"
    );
    return { tx: receipt, domainId: event?.args?.domainId || "" };
  }

  /**
   * Register a nullifier in a domain
   */
  async registerNullifier(
    params: NullifierRegistrationParams,
    options?: TransactionOptions
  ): Promise<{ tx: any; nullifier: string }> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.registerNullifier(
      params.domainId,
      params.nullifier,
      params.commitmentHash,
      params.transitionId,
      params.registrationProof,
      options || {}
    );
    const receipt = await tx.wait();
    
    return { tx: receipt, nullifier: params.nullifier };
  }

  /**
   * Register a derived nullifier from a parent
   */
  async registerDerivedNullifier(
    params: DerivedNullifierParams,
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.registerDerivedNullifier(
      params.parentNullifier,
      params.childNullifier,
      params.targetDomainId,
      params.derivationProof,
      options || {}
    );
    await tx.wait();
  }

  /**
   * Consume a nullifier (mark as spent)
   */
  async consumeNullifier(
    nullifier: string,
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.consumeNullifier(nullifier, options || {});
    await tx.wait();
  }

  /**
   * Batch check if nullifiers exist
   */
  async batchCheckNullifiers(nullifiers: string[]): Promise<boolean[]> {
    return await this.contract.batchCheckNullifiers(nullifiers);
  }

  /**
   * Batch consume multiple nullifiers
   */
  async batchConsumeNullifiers(
    nullifiers: string[],
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.batchConsumeNullifiers(nullifiers, options || {});
    await tx.wait();
  }

  /**
   * Verify cross-domain nullifier proof
   */
  async verifyCrossDomainProof(
    sourceNullifier: string,
    targetNullifier: string,
    sourceDomainId: string,
    targetDomainId: string,
    proof: string,
    options?: TransactionOptions
  ): Promise<boolean> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.verifyCrossDomainProof(
      sourceNullifier,
      targetNullifier,
      sourceDomainId,
      targetDomainId,
      proof,
      options || {}
    );
    await tx.wait();
    return true;
  }

  /**
   * Get domain by ID
   */
  async getDomain(domainId: string): Promise<Domain | null> {
    const domain = await this.contract.domains(domainId);
    if (!domain || domain.domainId === ethers.ZeroHash) {
      return null;
    }
    return domain;
  }

  /**
   * Get nullifier data
   */
  async getNullifier(nullifier: string): Promise<DomainNullifier | null> {
    const data = await this.contract.nullifiers(nullifier);
    if (!data || data.nullifier === ethers.ZeroHash) {
      return null;
    }
    return data;
  }

  /**
   * Check if nullifier exists
   */
  async nullifierExists(nullifier: string): Promise<boolean> {
    return await this.contract.nullifierExists(nullifier);
  }

  /**
   * Get active domain IDs
   */
  async getActiveDomains(): Promise<string[]> {
    return await this.contract.getActiveDomains();
  }

  /**
   * Get contract stats
   */
  async getStats(): Promise<NullifierStats> {
    const [domains, nullifiers, consumed, epoch] = await this.contract.getStats();
    return {
      totalDomains: domains,
      totalNullifiers: nullifiers,
      totalConsumed: consumed,
      currentEpoch: epoch,
    };
  }

  /**
   * Finalize current epoch
   */
  async finalizeEpoch(options?: TransactionOptions): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.finalizeEpoch(options || {});
    await tx.wait();
  }
}

/*//////////////////////////////////////////////////////////////
                   Soulv2 ORCHESTRATOR CLIENT
//////////////////////////////////////////////////////////////*/

export interface OperationParams {
  containerId: string;
  policyId: string;
  stateCommitment: string;
  nullifier: string;
  proof: string;
}

export interface OperationResult {
  success: boolean;
  operationId: string;
  message: string;
}

export interface SystemStatus {
  pc3Active: boolean;
  pbpActive: boolean;
  eascActive: boolean;
  cdnaActive: boolean;
  paused: boolean;
  lastUpdate: bigint;
}

/**
 * Client for Soulv2Orchestrator contract
 * Coordinates operations across all Soul v2 primitives
 */
export class Soulv2OrchestratorClient {
  private contract: Contract;
  private signer: Signer | null;

  constructor(
    contractAddress: string,
    providerOrSigner: Provider | Signer,
    abi?: any[]
  ) {
    const defaultABI = [
      // Read functions
      "function pc3() view returns (address)",
      "function pbp() view returns (address)",
      "function easc() view returns (address)",
      "function cdna() view returns (address)",
      "function isPrimitiveActive(bytes32) view returns (bool)",
      "function getSystemStatus() view returns (tuple(bool pc3Active, bool pbpActive, bool eascActive, bool cdnaActive, bool paused, uint256 lastUpdate))",
      "function totalOperations() view returns (uint256)",
      "function successfulOperations() view returns (uint256)",
      
      // Write functions
      "function executePrivateTransfer(bytes32 containerId, bytes32 policyId, bytes32 stateCommitment, bytes32 nullifier, bytes proof) returns (bool, bytes32, string)",
      "function updatePrimitive(bytes32 primitiveId, address newAddress)",
      "function setPrimitiveActive(bytes32 primitiveId, bool active)",
      "function pause()",
      "function unpause()",
      
      // Events
      "event OperationExecuted(bytes32 indexed operationId, address indexed user, bool success, string message)",
      "event PrimitiveUpdated(bytes32 indexed primitiveId, address oldAddress, address newAddress)",
      "event PrimitiveStatusChanged(bytes32 indexed primitiveId, bool active)",
    ];

    this.contract = new ethers.Contract(
      contractAddress,
      abi || defaultABI,
      providerOrSigner
    );
    this.signer = "getAddress" in providerOrSigner ? providerOrSigner as Signer : null;
  }

  /**
   * Execute a coordinated private transfer across primitives
   */
  async executePrivateTransfer(
    params: OperationParams,
    options?: TransactionOptions
  ): Promise<OperationResult> {
    if (!this.signer) throw new Error("Signer required for write operations");

    const tx = await this.contract.executePrivateTransfer(
      params.containerId,
      params.policyId,
      params.stateCommitment,
      params.nullifier,
      params.proof,
      options || {}
    );
    const receipt = await tx.wait();
    
    // Extract result from event
    const event = receipt.logs.find(
      (log: any) => log.fragment?.name === "OperationExecuted"
    );
    
    return {
      success: event?.args?.success || false,
      operationId: event?.args?.operationId || "",
      message: event?.args?.message || ""
    };
  }

  /**
   * Get system status
   */
  async getSystemStatus(): Promise<SystemStatus> {
    const status = await this.contract.getSystemStatus();
    return {
      pc3Active: status.pc3Active,
      pbpActive: status.pbpActive,
      eascActive: status.eascActive,
      cdnaActive: status.cdnaActive,
      paused: status.paused,
      lastUpdate: status.lastUpdate
    };
  }

  /**
   * Get primitive addresses
   */
  async getPrimitiveAddresses(): Promise<{
    pc3: string;
    pbp: string;
    easc: string;
    cdna: string;
  }> {
    const [pc3, pbp, easc, cdna] = await Promise.all([
      this.contract.pc3(),
      this.contract.pbp(),
      this.contract.easc(),
      this.contract.cdna()
    ]);
    return { pc3, pbp, easc, cdna };
  }

  /**
   * Get operation statistics
   */
  async getStats(): Promise<{ total: bigint; successful: bigint }> {
    const [total, successful] = await Promise.all([
      this.contract.totalOperations(),
      this.contract.successfulOperations()
    ]);
    return { total, successful };
  }

  /**
   * Check if a primitive is active
   */
  async isPrimitiveActive(primitiveId: string): Promise<boolean> {
    return await this.contract.isPrimitiveActive(primitiveId);
  }

  /**
   * Update primitive address (admin only)
   */
  async updatePrimitive(
    primitiveId: string,
    newAddress: string,
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.updatePrimitive(primitiveId, newAddress, options || {});
    await tx.wait();
  }

  /**
   * Set primitive active status (admin only)
   */
  async setPrimitiveActive(
    primitiveId: string,
    active: boolean,
    options?: TransactionOptions
  ): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.setPrimitiveActive(primitiveId, active, options || {});
    await tx.wait();
  }

  /**
   * Pause the orchestrator (admin only)
   */
  async pause(options?: TransactionOptions): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.pause(options || {});
    await tx.wait();
  }

  /**
   * Unpause the orchestrator (admin only)
   */
  async unpause(options?: TransactionOptions): Promise<void> {
    if (!this.signer) throw new Error("Signer required for write operations");
    const tx = await this.contract.unpause(options || {});
    await tx.wait();
  }

  /**
   * Subscribe to operation events
   */
  onOperationExecuted(
    callback: (operationId: string, user: string, success: boolean, message: string) => void
  ): void {
    this.contract.on("OperationExecuted", callback);
  }

  /**
   * Remove all event listeners
   */
  removeAllListeners(): void {
    this.contract.removeAllListeners();
  }
}

/*//////////////////////////////////////////////////////////////
                     UNIFIED CLIENT FACTORY
//////////////////////////////////////////////////////////////*/

export interface Soulv2Config {
  proofCarryingContainer?: string;
  policyBoundProofs?: string;
  executionAgnosticStateCommitments?: string;
  crossDomainNullifierAlgebra?: string;
  orchestrator?: string;
}

/**
 * Factory for creating Soul v2 primitive clients
 */
export class Soulv2ClientFactory {
  constructor(
    private config: Soulv2Config,
    private providerOrSigner: Provider | Signer
  ) {}

  /**
   * Create ProofCarryingContainer client
   */
  proofCarryingContainer(): ProofCarryingContainerClient {
    if (!this.config.proofCarryingContainer) {
      throw new Error("ProofCarryingContainer address not configured");
    }
    return new ProofCarryingContainerClient(
      this.config.proofCarryingContainer,
      this.providerOrSigner
    );
  }

  /**
   * Create PolicyBoundProofs client
   */
  policyBoundProofs(): PolicyBoundProofsClient {
    if (!this.config.policyBoundProofs) {
      throw new Error("PolicyBoundProofs address not configured");
    }
    return new PolicyBoundProofsClient(
      this.config.policyBoundProofs,
      this.providerOrSigner
    );
  }

  /**
   * Create ExecutionAgnosticStateCommitments client
   */
  executionAgnosticStateCommitments(): ExecutionAgnosticStateCommitmentsClient {
    if (!this.config.executionAgnosticStateCommitments) {
      throw new Error("ExecutionAgnosticStateCommitments address not configured");
    }
    return new ExecutionAgnosticStateCommitmentsClient(
      this.config.executionAgnosticStateCommitments,
      this.providerOrSigner
    );
  }

  /**
   * Create CrossDomainNullifierAlgebra client
   */
  crossDomainNullifierAlgebra(): CrossDomainNullifierAlgebraClient {
    if (!this.config.crossDomainNullifierAlgebra) {
      throw new Error("CrossDomainNullifierAlgebra address not configured");
    }
    return new CrossDomainNullifierAlgebraClient(
      this.config.crossDomainNullifierAlgebra,
      this.providerOrSigner
    );
  }

  /**
   * Create Soulv2Orchestrator client
   */
  orchestrator(): Soulv2OrchestratorClient {
    if (!this.config.orchestrator) {
      throw new Error("Orchestrator address not configured");
    }
    return new Soulv2OrchestratorClient(
      this.config.orchestrator,
      this.providerOrSigner
    );
  }

  /**
   * Create all clients at once
   */
  all(): {
    pc3: ProofCarryingContainerClient;
    pbp: PolicyBoundProofsClient;
    easc: ExecutionAgnosticStateCommitmentsClient;
    cdna: CrossDomainNullifierAlgebraClient;
    orchestrator: Soulv2OrchestratorClient;
  } {
    return {
      pc3: this.proofCarryingContainer(),
      pbp: this.policyBoundProofs(),
      easc: this.executionAgnosticStateCommitments(),
      cdna: this.crossDomainNullifierAlgebra(),
      orchestrator: this.orchestrator()
    };
  }
}
