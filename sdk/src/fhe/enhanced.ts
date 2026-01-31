/**
 * Soul FHE Enhanced TypeScript Integration
 * 
 * Comprehensive client-side library for FHE operations with Soul protocol
 * Includes coprocessor integration, gateway interaction, and oracle support
 * 
 * @module @soul/sdk/fhe
 * @version 2.0.0
 */

import { 
    keccak256, 
    toHex, 
    toBytes, 
    encodeAbiParameters, 
    getContract, 
    zeroAddress, 
    zeroHash,
    type PublicClient, 
    type WalletClient, 
    type Hex, 
    type Abi,
    decodeEventLog,
    getAddress,
    slice
} from 'viem';

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

// PROPER ABI for viem
const FHE_GATEWAY_ABI_PROPER = [
  { type: 'function', name: 'trivialEncrypt', stateMutability: 'nonpayable', inputs: [{ name: 'plaintext', type: 'uint256' }, { name: 'fheType', type: 'uint8' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheAdd', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheSub', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheMul', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheDiv', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheRem', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheNeg', stateMutability: 'nonpayable', inputs: [{ name: 'ct', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheAnd', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheOr', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheXor', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheNot', stateMutability: 'nonpayable', inputs: [{ name: 'ct', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheShl', stateMutability: 'nonpayable', inputs: [{ name: 'ct', type: 'bytes32' }, { name: 'shift', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheShr', stateMutability: 'nonpayable', inputs: [{ name: 'ct', type: 'bytes32' }, { name: 'shift', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheEq', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheNe', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheGe', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheGt', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheLe', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheLt', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheMin', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheMax', stateMutability: 'nonpayable', inputs: [{ name: 'lhs', type: 'bytes32' }, { name: 'rhs', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheSelect', stateMutability: 'nonpayable', inputs: [{ name: 'condition', type: 'bytes32' }, { name: 'ifTrue', type: 'bytes32' }, { name: 'ifFalse', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheRand', stateMutability: 'nonpayable', inputs: [{ name: 'fheType', type: 'uint8' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'fheRandBounded', stateMutability: 'nonpayable', inputs: [{ name: 'upperBound', type: 'uint256' }, { name: 'fheType', type: 'uint8' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'requestDecryption', stateMutability: 'nonpayable', inputs: [{ name: 'handle', type: 'bytes32' }, { name: 'callbackAddr', type: 'address' }, { name: 'callbackSelector', type: 'bytes4' }, { name: 'ttl', type: 'uint64' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'requestReencryption', stateMutability: 'nonpayable', inputs: [{ name: 'handle', type: 'bytes32' }, { name: 'targetPublicKey', type: 'bytes32' }, { name: 'callbackAddr', type: 'address' }, { name: 'callbackSelector', type: 'bytes4' }, { name: 'ttl', type: 'uint64' }], outputs: [{ type: 'bytes32' }] },
  { type: 'event', name: 'HandleCreated', inputs: [{ indexed: true, name: 'handle', type: 'bytes32' }, { indexed: true, name: 'owner', type: 'address' }, { name: 'fheType', type: 'uint8' }] },
  { type: 'event', name: 'DecryptionRequested', inputs: [{ indexed: true, name: 'requestId', type: 'bytes32' }, { indexed: true, name: 'handle', type: 'bytes32' }, { name: 'requester', type: 'address' }] }
] as const;

const FHE_ORACLE_ABI_PROPER = [
  { type: 'function', name: 'registerOracle', stateMutability: 'payable', inputs: [{ name: 'blsPublicKey', type: 'bytes' }], outputs: [] },
  { type: 'function', name: 'submitComputation', stateMutability: 'nonpayable', inputs: [{ name: 'taskId', type: 'bytes32' }, { name: 'result', type: 'bytes32' }, { name: 'proof', type: 'bytes' }], outputs: [] },
  { type: 'function', name: 'getTaskStatus', stateMutability: 'view', inputs: [{ name: 'taskId', type: 'bytes32' }], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'isActiveOracle', stateMutability: 'view', inputs: [{ name: 'oracle', type: 'address' }], outputs: [{ type: 'bool' }] },
  { type: 'event', name: 'OracleRegistered', inputs: [{ indexed: true, name: 'oracle', type: 'address' }, { name: 'blsPublicKey', type: 'bytes' }] },
  { type: 'event', name: 'ComputationSubmitted', inputs: [{ indexed: true, name: 'taskId', type: 'bytes32' }, { name: 'result', type: 'bytes32' }] },
  { type: 'event', name: 'TaskCompleted', inputs: [{ indexed: true, name: 'taskId', type: 'bytes32' }, { name: 'result', type: 'bytes32' }] }
] as const;

const ENCRYPTED_ERC20_ABI_PROPER = [
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'encryptedAmount', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'transferFrom', stateMutability: 'nonpayable', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'encryptedAmount', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'approve', stateMutability: 'nonpayable', inputs: [{ name: 'spender', type: 'address' }, { name: 'encryptedAmount', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'encryptedBalanceOf', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'encryptedAllowance', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'requestBalanceDecryption', stateMutability: 'nonpayable', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'bytes32' }] },
  { type: 'event', name: 'DecryptionRequested', inputs: [{ indexed: true, name: 'requestId', type: 'bytes32' }, { indexed: true, name: 'account', type: 'address' }] }
] as const;

// ============================================
// FHE Gateway Client
// ============================================

/**
 * Client for interacting with FHE Gateway contract
 */
export class FHEGatewayClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private gateway: any;
  private config: FHEConfig;

  constructor(publicClient: PublicClient, walletClient: WalletClient, config: FHEConfig) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.config = config;
    this.gateway = getContract({
      address: config.gatewayAddress as Hex,
      abi: FHE_GATEWAY_ABI_PROPER,
      client: { public: publicClient, wallet: walletClient }
    });
  }

  /**
   * Encrypt a plaintext value (trivial encryption)
   */
  async encrypt(plaintext: bigint, fheType: FHEType): Promise<Handle> {
    const hash = await this.gateway.write.trivialEncrypt([plaintext, fheType]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    
    // Extract handle from event
    let handle: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: FHE_GATEWAY_ABI_PROPER,
          data: log.data,
          topics: log.topics
        });
        if (decoded.eventName === 'HandleCreated') {
          handle = (decoded.args as any).handle;
          break;
        }
      } catch {}
    }
    
    if (handle === zeroHash) {
      throw new Error('HandleCreated event not found');
    }

    const [owner] = await this.walletClient.getAddresses();

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
    const blindingFactor = toHex(crypto.getRandomValues(new Uint8Array(32)));
    
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
    const hash = await this.gateway.write.fheAdd([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic subtraction
   */
  async sub(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheSub([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic multiplication
   */
  async mul(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheMul([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic division
   */
  async div(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheDiv([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic remainder
   */
  async rem(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheRem([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic negation
   */
  async neg(ct: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheNeg([ct.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic bitwise AND
   */
  async and(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheAnd([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic bitwise OR
   */
  async or(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheOr([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic bitwise XOR
   */
  async xor(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheXor([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic bitwise NOT
   */
  async not(ct: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheNot([ct.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic shift left
   */
  async shl(ct: Handle, shift: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheShl([ct.value as Hex, shift.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic shift right
   */
  async shr(ct: Handle, shift: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheShr([ct.value as Hex, shift.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, ct.fheType);
  }

  /**
   * Perform homomorphic equality comparison
   */
  async eq(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheEq([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic not-equal comparison
   */
  async ne(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheNe([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic greater-or-equal comparison
   */
  async ge(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheGe([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic greater-than comparison
   */
  async gt(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheGt([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic less-or-equal comparison
   */
  async le(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheLe([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic less-than comparison
   */
  async lt(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheLt([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, FHEType.EBOOL);
  }

  /**
   * Perform homomorphic minimum
   */
  async min(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheMin([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform homomorphic maximum
   */
  async max(lhs: Handle, rhs: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheMax([lhs.value as Hex, rhs.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, lhs.fheType);
  }

  /**
   * Perform conditional selection
   */
  async select(condition: Handle, ifTrue: Handle, ifFalse: Handle): Promise<Handle> {
    const hash = await this.gateway.write.fheSelect([condition.value as Hex, ifTrue.value as Hex, ifFalse.value as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, ifTrue.fheType);
  }

  /**
   * Generate random encrypted value
   */
  async random(fheType: FHEType): Promise<Handle> {
    const hash = await this.gateway.write.fheRand([fheType]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, fheType);
  }

  /**
   * Generate random encrypted value with upper bound
   */
  async randomBounded(upperBound: bigint, fheType: FHEType): Promise<Handle> {
    const hash = await this.gateway.write.fheRandBounded([upperBound, fheType]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return this.extractHandleFromReceipt(receipt, fheType);
  }

  // ============================================
  // ACL Management
  // ============================================

  /**
   * Grant permission to access encrypted value
   */
  async grantPermission(handle: Handle, user: string): Promise<void> {
    const hash = await this.gateway.write.grantUserPermission([handle.value as Hex, user as Hex]);
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Revoke permission to access encrypted value
   */
  async revokePermission(handle: Handle, user: string): Promise<void> {
    const hash = await this.gateway.write.revokeUserPermission([handle.value as Hex, user as Hex]);
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Check if user has permission to access encrypted value
   */
  async hasPermission(handle: Handle, user: string): Promise<boolean> {
    return await this.gateway.read.hasPermission([handle.value as Hex, user as Hex]);
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
    const hash = await this.gateway.write.requestDecryption([
      handle.value as Hex,
      callbackAddress as Hex,
      callbackSelector as Hex,
      BigInt(ttl)
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract request ID from event
    let requestId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: FHE_GATEWAY_ABI_PROPER,
          data: log.data,
          topics: log.topics
        });
        if (decoded.eventName === 'DecryptionRequested') {
          requestId = (decoded.args as any).requestId;
          break;
        }
      } catch {}
    }

    if (requestId === zeroHash) {
      throw new Error('DecryptionRequested event not found');
    }

    const [requester] = await this.walletClient.getAddresses();

    return {
      requestId,
      handle: handle.value,
      requester,
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
    const hash = await this.gateway.write.requestReencryption([
      handle.value as Hex,
      targetPublicKey as Hex,
      callbackAddress as Hex,
      callbackSelector as Hex,
      BigInt(ttl)
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    return {
      requestId: toHex(crypto.getRandomValues(new Uint8Array(32))), // Placeholder
      sourceHandle: handle.value,
      targetPublicKey: toBytes(targetPublicKey as Hex),
      destinationChain: 0,
      status: DecryptionStatus.PENDING
    };
  }

  // ============================================
  // Helper Methods
  // ============================================

  private extractHandleFromReceipt(receipt: any, fheType: FHEType): Handle {
    let handle: Hex = zeroHash;
    let owner: Hex = zeroAddress;
    
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: FHE_GATEWAY_ABI_PROPER,
          data: log.data,
          topics: log.topics
        });
        if (decoded.eventName === 'HandleCreated') {
          handle = (decoded.args as any).handle;
          owner = (decoded.args as any).owner;
          break;
        }
      } catch {}
    }

    if (handle === zeroHash) {
      throw new Error('HandleCreated event not found');
    }

    return {
      value: handle,
      fheType,
      owner,
      created: Date.now()
    };
  }

  private computeCommitment(value: bigint, blindingFactor: string): string {
    return keccak256(
      encodeAbiParameters(
        [{ type: 'uint256' }, { type: 'bytes32' }],
        [value, blindingFactor as Hex]
      )
    );
  }

  /**
   * Get handle information
   */
  async getHandleInfo(handle: string): Promise<{ exists: boolean; type: FHEType; owner: string }> {
    const exists = await this.gateway.read.handleExists([handle]);
    if (!exists) {
      return { exists: false, type: FHEType.EBOOL, owner: zeroAddress };
    }

    const fheType = await this.gateway.read.getHandleType([handle]);
    const owner = await this.gateway.read.getHandleOwner([handle]);

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
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private token: any;
  private gateway: FHEGatewayClient;

  constructor(
    tokenAddress: Hex,
    publicClient: PublicClient,
    walletClient: WalletClient,
    gateway: FHEGatewayClient
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.gateway = gateway;
    this.token = getContract({
      address: tokenAddress,
      abi: ENCRYPTED_ERC20_ABI_PROPER,
      client: { public: publicClient, wallet: walletClient }
    });
  }

  /**
   * Get encrypted balance
   */
  async balanceOf(account: string): Promise<Handle> {
    const handleValue = await this.token.read.encryptedBalanceOf([account as Hex]);
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
    const handleValue = await this.token.read.encryptedAllowance([owner as Hex, spender as Hex]);
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
    const hash = await this.token.write.transfer([to as Hex, encryptedAmount.value as Hex]);
    await this.publicClient.waitForTransactionReceipt({ hash });
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
    const hash = await this.token.write.transferFrom([
      from as Hex,
      to as Hex,
      encryptedAmount.value as Hex
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return true;
  }

  /**
   * Approve encrypted amount for spender
   */
  async approve(spender: string, encryptedAmount: Handle): Promise<boolean> {
    const hash = await this.token.write.approve([spender as Hex, encryptedAmount.value as Hex]);
    await this.publicClient.waitForTransactionReceipt({ hash });
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
    const hash = await this.token.write.requestBalanceDecryption([account as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    
    let requestId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: ENCRYPTED_ERC20_ABI_PROPER,
          data: log.data,
          topics: log.topics
        });
        if (decoded.eventName === 'DecryptionRequested') {
          requestId = (decoded.args as any).requestId;
          break;
        }
      } catch {}
    }

    return requestId;
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

    const hex = value.toString(16);
    const bytes = toBytes(`0x${hex.length % 2 === 0 ? hex : '0' + hex}`);
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
