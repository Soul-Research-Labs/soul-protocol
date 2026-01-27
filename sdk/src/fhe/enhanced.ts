/**
 * Soul FHE Enhanced TypeScript Integration
 * 
 * Comprehensive client-side library for FHE operations with Soul protocol
 * Includes coprocessor integration, gateway interaction, and oracle support
 * 
 * @module @pil/sdk/fhe
 * @version 2.0.0
 */

import { ethers, Contract, Signer, Provider, ContractTransactionReceipt } from 'ethers';

// ============================================
// Type Definitions
// ============================================

/**
 * FHE type identifiers (matching FHETypes.sol)
 */
export enum FHEType {
  EBOOL = 0,
  EUINT4 = 1,
  EUINT8 = 2,
  EUINT16 = 3,
  EUINT32 = 4,
  EUINT64 = 5,
  EUINT128 = 6,
  EUINT256 = 7,
  EADDRESS = 8,
  EBYTES64 = 9,
  EBYTES128 = 10,
  EBYTES256 = 11
}

/**
 * FHE scheme types
 */
export type FHEScheme = 'TFHE' | 'BFV' | 'BGV' | 'CKKS';

/**
 * Security levels in bits
 */
export type SecurityLevel = 128 | 192 | 256;

/**
 * FHE configuration
 */
export interface FHEConfig {
  scheme: FHEScheme;
  securityLevel: SecurityLevel;
  gatewayAddress: string;
  oracleAddress?: string;
  coprocessorEndpoint?: string;
  chainId: number;
}

/**
 * Encrypted handle (references ciphertext on-chain)
 */
export interface Handle {
  value: string;          // bytes32 handle
  fheType: FHEType;
  owner: string;          // address
  created: number;        // timestamp
}

/**
 * Ciphertext with metadata
 */
export interface Ciphertext {
  handle: Handle;
  commitment: string;     // Pedersen commitment for ZK
  proof?: Uint8Array;     // Optional validity proof
}

/**
 * Encrypted value with full context
 */
export interface EncryptedValue {
  ciphertext: Ciphertext;
  blindingFactor: string;
  serializedData?: Uint8Array;
}

/**
 * Decryption request
 */
export interface DecryptionRequest {
  requestId: string;
  handle: string;
  requester: string;
  callback: string;
  ttl: number;
  status: DecryptionStatus;
}

/**
 * Decryption status
 */
export enum DecryptionStatus {
  PENDING = 0,
  PROCESSING = 1,
  COMPLETED = 2,
  FAILED = 3,
  EXPIRED = 4
}

/**
 * Re-encryption request for cross-chain
 */
export interface ReencryptionRequest {
  requestId: string;
  sourceHandle: string;
  targetPublicKey: Uint8Array;
  destinationChain: number;
  status: DecryptionStatus;
}

/**
 * Computation task for oracle network
 */
export interface ComputationTask {
  taskId: string;
  operation: FHEOperation;
  inputs: string[];       // Handle values
  requester: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result?: string;        // Result handle
}

/**
 * FHE operation types
 */
export type FHEOperation = 
  | 'ADD' | 'SUB' | 'MUL' | 'DIV' | 'REM' | 'NEG'
  | 'AND' | 'OR' | 'XOR' | 'NOT' | 'SHL' | 'SHR'
  | 'EQ' | 'NE' | 'GE' | 'GT' | 'LE' | 'LT'
  | 'MIN' | 'MAX' | 'SELECT' | 'CMUX';

// ============================================
// ABI Fragments
// ============================================

const FHE_GATEWAY_ABI = [
  // Handle management
  'function trivialEncrypt(uint256 plaintext, uint8 fheType) external returns (bytes32)',
  'function getHandleType(bytes32 handle) external view returns (uint8)',
  'function getHandleOwner(bytes32 handle) external view returns (address)',
  'function handleExists(bytes32 handle) external view returns (bool)',
  
  // FHE Operations
  'function fheAdd(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheSub(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheMul(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheDiv(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheRem(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheNeg(bytes32 ct) external returns (bytes32)',
  'function fheAnd(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheOr(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheXor(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheNot(bytes32 ct) external returns (bytes32)',
  'function fheShl(bytes32 ct, bytes32 shift) external returns (bytes32)',
  'function fheShr(bytes32 ct, bytes32 shift) external returns (bytes32)',
  'function fheEq(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheNe(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheGe(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheGt(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheLe(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheLt(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheMin(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheMax(bytes32 lhs, bytes32 rhs) external returns (bytes32)',
  'function fheSelect(bytes32 condition, bytes32 ifTrue, bytes32 ifFalse) external returns (bytes32)',
  'function fheRand(uint8 fheType) external returns (bytes32)',
  'function fheRandBounded(uint256 upperBound, uint8 fheType) external returns (bytes32)',
  
  // ACL
  'function grantUserPermission(bytes32 handle, address user) external',
  'function revokeUserPermission(bytes32 handle, address user) external',
  'function hasPermission(bytes32 handle, address user) external view returns (bool)',
  
  // Decryption
  'function requestDecryption(bytes32 handle, address callbackAddr, bytes4 callbackSelector, uint64 ttl) external returns (bytes32)',
  'function requestReencryption(bytes32 handle, bytes32 targetPublicKey, address callbackAddr, bytes4 callbackSelector, uint64 ttl) external returns (bytes32)',
  
  // Events
  'event HandleCreated(bytes32 indexed handle, address indexed owner, uint8 fheType)',
  'event DecryptionRequested(bytes32 indexed requestId, bytes32 indexed handle, address requester)',
  'event DecryptionFulfilled(bytes32 indexed requestId, bytes32 result)',
  'event PermissionGranted(bytes32 indexed handle, address indexed user)',
  'event PermissionRevoked(bytes32 indexed handle, address indexed user)'
];

const FHE_ORACLE_ABI = [
  'function registerOracle(bytes calldata blsPublicKey) external payable',
  'function submitComputation(bytes32 taskId, bytes32 result, bytes calldata proof) external',
  'function getTaskStatus(bytes32 taskId) external view returns (uint8)',
  'function isActiveOracle(address oracle) external view returns (bool)',
  'function MIN_STAKE() external view returns (uint256)',
  'function QUORUM_BPS() external view returns (uint256)',
  
  'event OracleRegistered(address indexed oracle, bytes blsPublicKey)',
  'event ComputationSubmitted(bytes32 indexed taskId, bytes32 result)',
  'event TaskCompleted(bytes32 indexed taskId, bytes32 result)'
];

const ENCRYPTED_ERC20_ABI = [
  'function transfer(address to, bytes32 encryptedAmount) external returns (bool)',
  'function transferFrom(address from, address to, bytes32 encryptedAmount) external returns (bool)',
  'function approve(address spender, bytes32 encryptedAmount) external returns (bool)',
  'function encryptedBalanceOf(address account) external view returns (bytes32)',
  'function encryptedAllowance(address owner, address spender) external view returns (bytes32)',
  'function mintPlain(address to, uint256 amount) external',
  'function burnPlain(address from, uint256 amount) external',
  'function requestBalanceDecryption(address account) external returns (bytes32)',
  
  'event EncryptedTransfer(address indexed from, address indexed to, bytes32 encryptedAmount)',
  'event EncryptedApproval(address indexed owner, address indexed spender, bytes32 encryptedAmount)'
];

// ============================================
// FHE Gateway Client
// ============================================

/**
 * Client for interacting with FHE Gateway contract
 */
export class FHEGatewayClient {
  private gateway: Contract;
  private signer: Signer;
  private config: FHEConfig;

  constructor(signer: Signer, config: FHEConfig) {
    this.signer = signer;
    this.config = config;
    this.gateway = new Contract(config.gatewayAddress, FHE_GATEWAY_ABI, signer);
  }

  /**
   * Encrypt a plaintext value (trivial encryption)
   */
  async encrypt(plaintext: bigint, fheType: FHEType): Promise<Handle> {
    const tx = await this.gateway.trivialEncrypt(plaintext, fheType);
    const receipt = await tx.wait();
    
    // Extract handle from event
    const event = receipt.logs.find(
      (log: any) => log.topics[0] === ethers.id('HandleCreated(bytes32,address,uint8)')
    );
    
    if (!event) {
      throw new Error('HandleCreated event not found');
    }

    const handle = event.topics[1];
    const owner = await this.signer.getAddress();

    return {
      value: handle,
      fheType,
      owner,
      created: Date.now()
    };
  }

  /**
   * Create encrypted value with full metadata
   */
  async createEncryptedValue(plaintext: bigint, fheType: FHEType): Promise<EncryptedValue> {
    const handle = await this.encrypt(plaintext, fheType);
    
    // Generate blinding factor for commitment
    const blindingFactor = ethers.hexlify(ethers.randomBytes(32));
    
    // Create Pedersen commitment
    const commitment = this.computeCommitment(plaintext, blindingFactor);

    return {
      ciphertext: {
        handle,
        commitment
      },
      blindingFactor
    };
  }

  /**
   * Perform homomorphic addition
   */
  async add(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheAdd(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic subtraction
   */
  async sub(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheSub(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic multiplication
   */
  async mul(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheMul(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic division
   */
  async div(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheDiv(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic remainder
   */
  async rem(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheRem(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic negation
   */
  async neg(ct: Handle): Promise<Handle> {
    const tx = await this.gateway.fheNeg(ct.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic bitwise AND
   */
  async and(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheAnd(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic bitwise OR
   */
  async or(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheOr(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic bitwise XOR
   */
  async xor(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheXor(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic bitwise NOT
   */
  async not(ct: Handle): Promise<Handle> {
    const tx = await this.gateway.fheNot(ct.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic shift left
   */
  async shl(ct: Handle, shift: Handle): Promise<Handle> {
    const tx = await this.gateway.fheShl(ct.value, shift.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic shift right
   */
  async shr(ct: Handle, shift: Handle): Promise<Handle> {
    const tx = await this.gateway.fheShr(ct.value, shift.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic equality comparison
   */
  async eq(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheEq(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic not-equal comparison
   */
  async ne(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheNe(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic greater-or-equal comparison
   */
  async ge(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheGe(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic greater-than comparison
   */
  async gt(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheGt(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic less-or-equal comparison
   */
  async le(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheLe(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic less-than comparison
   */
  async lt(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheLt(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic minimum
   */
  async min(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheMin(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic maximum
   */
  async max(lhs: Handle, rhs: Handle): Promise<Handle> {
    const tx = await this.gateway.fheMax(lhs.value, rhs.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform conditional selection
   */
  async select(condition: Handle, ifTrue: Handle, ifFalse: Handle): Promise<Handle> {
    const tx = await this.gateway.fheSelect(condition.value, ifTrue.value, ifFalse.value);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, ifTrue.fheType);
  }

  /**
   * Generate random encrypted value
   */
  async random(fheType: FHEType): Promise<Handle> {
    const tx = await this.gateway.fheRand(fheType);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, fheType);
  }

  /**
   * Generate random encrypted value with upper bound
   */
  async randomBounded(upperBound: bigint, fheType: FHEType): Promise<Handle> {
    const tx = await this.gateway.fheRandBounded(upperBound, fheType);
    const receipt = await tx.wait();
    return this.extractHandleFromReceipt(receipt, fheType);
  }

  // ============================================
  // ACL Management
  // ============================================

  /**
   * Grant permission to access encrypted value
   */
  async grantPermission(handle: Handle, user: string): Promise<void> {
    const tx = await this.gateway.grantUserPermission(handle.value, user);
    await tx.wait();
  }

  /**
   * Revoke permission to access encrypted value
   */
  async revokePermission(handle: Handle, user: string): Promise<void> {
    const tx = await this.gateway.revokeUserPermission(handle.value, user);
    await tx.wait();
  }

  /**
   * Check if user has permission to access encrypted value
   */
  async hasPermission(handle: Handle, user: string): Promise<boolean> {
    return await this.gateway.hasPermission(handle.value, user);
  }

  // ============================================
  // Decryption
  // ============================================

  /**
   * Request decryption of encrypted value
   */
  async requestDecryption(
    handle: Handle,
    callbackAddress: string,
    callbackSelector: string,
    ttl: number = 3600
  ): Promise<DecryptionRequest> {
    const tx = await this.gateway.requestDecryption(
      handle.value,
      callbackAddress,
      callbackSelector,
      ttl
    );
    const receipt = await tx.wait();

    // Extract request ID from event
    const event = receipt.logs.find(
      (log: any) => log.topics[0] === ethers.id('DecryptionRequested(bytes32,bytes32,address)')
    );

    if (!event) {
      throw new Error('DecryptionRequested event not found');
    }

    return {
      requestId: event.topics[1],
      handle: handle.value,
      requester: await this.signer.getAddress(),
      callback: callbackAddress,
      ttl,
      status: DecryptionStatus.PENDING
    };
  }

  /**
   * Request re-encryption for another chain
   */
  async requestReencryption(
    handle: Handle,
    targetPublicKey: string,
    callbackAddress: string,
    callbackSelector: string,
    ttl: number = 3600
  ): Promise<ReencryptionRequest> {
    const tx = await this.gateway.requestReencryption(
      handle.value,
      targetPublicKey,
      callbackAddress,
      callbackSelector,
      ttl
    );
    const receipt = await tx.wait();

    return {
      requestId: ethers.hexlify(ethers.randomBytes(32)), // Placeholder
      sourceHandle: handle.value,
      targetPublicKey: ethers.getBytes(targetPublicKey),
      destinationChain: 0,
      status: DecryptionStatus.PENDING
    };
  }

  // ============================================
  // Helper Methods
  // ============================================

  private extractHandleFromReceipt(receipt: ContractTransactionReceipt, fheType: FHEType): Handle {
    const event = receipt.logs.find(
      (log: any) => log.topics[0] === ethers.id('HandleCreated(bytes32,address,uint8)')
    );

    if (!event) {
      throw new Error('HandleCreated event not found');
    }

    return {
      value: event.topics[1],
      fheType,
      owner: ethers.getAddress(ethers.dataSlice(event.topics[2], 12)),
      created: Date.now()
    };
  }

  private computeCommitment(value: bigint, blindingFactor: string): string {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ['uint256', 'bytes32'],
        [value, blindingFactor]
      )
    );
  }

  /**
   * Get handle information
   */
  async getHandleInfo(handle: string): Promise<{ exists: boolean; type: FHEType; owner: string }> {
    const exists = await this.gateway.handleExists(handle);
    if (!exists) {
      return { exists: false, type: FHEType.EBOOL, owner: ethers.ZeroAddress };
    }

    const fheType = await this.gateway.getHandleType(handle);
    const owner = await this.gateway.getHandleOwner(handle);

    return { exists: true, type: fheType, owner };
  }
}

// ============================================
// Encrypted ERC20 Client
// ============================================

/**
 * Client for interacting with EncryptedERC20 contracts
 */
export class EncryptedERC20Client {
  private token: Contract;
  private gateway: FHEGatewayClient;
  private signer: Signer;

  constructor(
    tokenAddress: string,
    signer: Signer,
    gateway: FHEGatewayClient
  ) {
    this.signer = signer;
    this.gateway = gateway;
    this.token = new Contract(tokenAddress, ENCRYPTED_ERC20_ABI, signer);
  }

  /**
   * Get encrypted balance
   */
  async balanceOf(account: string): Promise<Handle> {
    const handleValue = await this.token.encryptedBalanceOf(account);
    return {
      value: handleValue,
      fheType: FHEType.EUINT256,
      owner: account,
      created: Date.now()
    };
  }

  /**
   * Get encrypted allowance
   */
  async allowance(owner: string, spender: string): Promise<Handle> {
    const handleValue = await this.token.encryptedAllowance(owner, spender);
    return {
      value: handleValue,
      fheType: FHEType.EUINT256,
      owner,
      created: Date.now()
    };
  }

  /**
   * Transfer encrypted amount
   */
  async transfer(to: string, encryptedAmount: Handle): Promise<boolean> {
    const tx = await this.token.transfer(to, encryptedAmount.value);
    await tx.wait();
    return true;
  }

  /**
   * Transfer encrypted amount from another account
   */
  async transferFrom(
    from: string,
    to: string,
    encryptedAmount: Handle
  ): Promise<boolean> {
    const tx = await this.token.transferFrom(from, to, encryptedAmount.value);
    await tx.wait();
    return true;
  }

  /**
   * Approve encrypted amount for spender
   */
  async approve(spender: string, encryptedAmount: Handle): Promise<boolean> {
    const tx = await this.token.approve(spender, encryptedAmount.value);
    await tx.wait();
    return true;
  }

  /**
   * Transfer with plaintext amount (encrypts automatically)
   */
  async transferPlain(to: string, amount: bigint): Promise<boolean> {
    const encrypted = await this.gateway.encrypt(amount, FHEType.EUINT256);
    return this.transfer(to, encrypted);
  }

  /**
   * Approve with plaintext amount (encrypts automatically)
   */
  async approvePlain(spender: string, amount: bigint): Promise<boolean> {
    const encrypted = await this.gateway.encrypt(amount, FHEType.EUINT256);
    return this.approve(spender, encrypted);
  }

  /**
   * Request balance decryption
   */
  async requestBalanceDecryption(account: string): Promise<string> {
    const tx = await this.token.requestBalanceDecryption(account);
    const receipt = await tx.wait();
    
    const event = receipt.logs.find(
      (log: any) => log.topics[0] === ethers.id('DecryptionRequested(bytes32,bytes32,address)')
    );

    return event ? event.topics[1] : '';
  }
}

// ============================================
// FHE Coprocessor Client
// ============================================

/**
 * Client for off-chain FHE coprocessor
 */
export class FHECoprocessorClient {
  private endpoint: string;
  private apiKey?: string;

  constructor(endpoint: string, apiKey?: string) {
    this.endpoint = endpoint;
    this.apiKey = apiKey;
  }

  /**
   * Submit computation to coprocessor
   */
  async submitComputation(
    operation: FHEOperation,
    inputs: string[],
    options?: { timeout?: number }
  ): Promise<ComputationTask> {
    const response = await fetch(`${this.endpoint}/compute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
      },
      body: JSON.stringify({ operation, inputs })
    });

    if (!response.ok) {
      throw new Error(`Coprocessor error: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get computation result
   */
  async getResult(taskId: string): Promise<ComputationTask> {
    const response = await fetch(`${this.endpoint}/task/${taskId}`, {
      headers: this.apiKey ? { 'Authorization': `Bearer ${this.apiKey}` } : {}
    });

    if (!response.ok) {
      throw new Error(`Coprocessor error: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Wait for computation to complete
   */
  async waitForResult(
    taskId: string,
    options?: { timeout?: number; pollInterval?: number }
  ): Promise<ComputationTask> {
    const timeout = options?.timeout ?? 60000;
    const pollInterval = options?.pollInterval ?? 1000;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const task = await this.getResult(taskId);
      
      if (task.status === 'completed' || task.status === 'failed') {
        return task;
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error('Computation timed out');
  }
}

// ============================================
// FHE Utils
// ============================================

export const FHEUtils = {
  /**
   * Get maximum value for FHE type
   */
  maxValue(fheType: FHEType): bigint {
    switch (fheType) {
      case FHEType.EBOOL: return 1n;
      case FHEType.EUINT4: return 15n;
      case FHEType.EUINT8: return 255n;
      case FHEType.EUINT16: return 65535n;
      case FHEType.EUINT32: return 4294967295n;
      case FHEType.EUINT64: return 18446744073709551615n;
      case FHEType.EUINT128: return (1n << 128n) - 1n;
      case FHEType.EUINT256: return (1n << 256n) - 1n;
      case FHEType.EADDRESS: return (1n << 160n) - 1n;
      default: return (1n << 256n) - 1n;
    }
  },

  /**
   * Get bit width for FHE type
   */
  bitWidth(fheType: FHEType): number {
    switch (fheType) {
      case FHEType.EBOOL: return 1;
      case FHEType.EUINT4: return 4;
      case FHEType.EUINT8: return 8;
      case FHEType.EUINT16: return 16;
      case FHEType.EUINT32: return 32;
      case FHEType.EUINT64: return 64;
      case FHEType.EUINT128: return 128;
      case FHEType.EUINT256: return 256;
      case FHEType.EADDRESS: return 160;
      default: return 256;
    }
  },

  /**
   * Check if value fits in FHE type
   */
  fitsInType(value: bigint, fheType: FHEType): boolean {
    return value >= 0n && value <= this.maxValue(fheType);
  },

  /**
   * Get appropriate FHE type for value
   */
  suggestType(value: bigint): FHEType {
    if (value <= 1n) return FHEType.EBOOL;
    if (value <= 15n) return FHEType.EUINT4;
    if (value <= 255n) return FHEType.EUINT8;
    if (value <= 65535n) return FHEType.EUINT16;
    if (value <= 4294967295n) return FHEType.EUINT32;
    if (value <= 18446744073709551615n) return FHEType.EUINT64;
    if (value <= (1n << 128n) - 1n) return FHEType.EUINT128;
    return FHEType.EUINT256;
  },

  /**
   * Encode value for trivial encryption
   */
  encodeForEncryption(value: bigint, fheType: FHEType): Uint8Array {
    const max = this.maxValue(fheType);
    if (value > max) {
      throw new Error(`Value ${value} exceeds max for type ${FHEType[fheType]}`);
    }

    const bytes = ethers.toBeArray(value);
    const width = Math.ceil(this.bitWidth(fheType) / 8);
    const padded = new Uint8Array(width);
    padded.set(bytes, width - bytes.length);
    
    return padded;
  }
};

// ============================================
// Default Export
// ============================================

export default {
  FHEType,
  FHEGatewayClient,
  EncryptedERC20Client,
  FHECoprocessorClient,
  FHEUtils,
  DecryptionStatus
};
