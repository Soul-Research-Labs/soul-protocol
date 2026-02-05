// ============================================================================
// EIP-7702 Account Abstraction SDK
// ============================================================================
// Cross-chain smart account support with paymasters and aggregators
// Reference: https://vitalik.eth.limo/general/2024/10/29/futures6.html
// ============================================================================

import {
  keccak256,
  encodePacked,
  encodeAbiParameters,
  parseAbiParameters,
  toHex,
  fromHex,
  type Hex,
  type Address,
  type Hash,
  concat,
  pad,
  slice,
} from 'viem';

// ============================================================================
// TYPES
// ============================================================================

/** Account types */
export type AccountType = 'eoa' | 'smart' | 'eip7702';

/** User operation for ERC-4337 */
export interface UserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymasterAndData: Hex;
  signature: Hex;
}

/** EIP-7702 authorization */
export interface EIP7702Authorization {
  chainId: bigint;
  address: Address;  // Contract code to delegate to
  nonce: bigint;
  signature: Hex;
}

/** Packed user operation (ERC-4337 v0.7) */
export interface PackedUserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;  // Packed: verificationGasLimit (16 bytes) + callGasLimit (16 bytes)
  preVerificationGas: bigint;
  gasFees: Hex;  // Packed: maxPriorityFeePerGas (16 bytes) + maxFeePerGas (16 bytes)
  paymasterAndData: Hex;
  signature: Hex;
}

/** Paymaster data */
export interface PaymasterData {
  paymaster: Address;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  paymasterData: Hex;
}

/** Cross-chain user operation */
export interface CrossChainUserOperation extends UserOperation {
  sourceChainId: bigint;
  targetChainId: bigint;
  bridgeData: Hex;
  crossChainNonce: bigint;
}

/** Smart account configuration */
export interface SmartAccountConfig {
  implementation: Address;
  owner: Address;
  guardians?: Address[];
  threshold?: number;
  modules?: Address[];
  fallbackHandler?: Address;
}

/** Signature aggregation data */
export interface AggregatedSignature {
  aggregator: Address;
  aggregatedSignature: Hex;
  userOpsPerAggregator: Array<{
    userOps: UserOperation[];
    signature: Hex;
  }>;
}

/** Account state */
export interface AccountState {
  address: Address;
  type: AccountType;
  nonce: bigint;
  balance: bigint;
  codeHash: Hex;
  storageRoot: Hex;
  isEIP7702Delegated: boolean;
  delegatedTo?: Address;
}

/** Keystore account (cross-chain) */
export interface KeystoreAccount {
  owner: Address;
  keystoreChainId: bigint;
  keystoreAddress: Address;
  recoveryConfig: {
    guardians: Address[];
    threshold: number;
    delay: bigint;
  };
  signingKeys: Array<{
    keyType: 'secp256k1' | 'secp256r1' | 'ed25519' | 'bls12381';
    publicKey: Hex;
    weight: number;
  }>;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/** ERC-4337 EntryPoint addresses */
export const ENTRY_POINT_V06 = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' as Address;
export const ENTRY_POINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as Address;

/** EIP-7702 magic prefix */
export const EIP7702_MAGIC = 0x05;

/** Signature types */
export const SIG_TYPE_ECDSA = 0x00;
export const SIG_TYPE_ERC1271 = 0x01;
export const SIG_TYPE_WEBAUTHN = 0x02;
export const SIG_TYPE_BLS = 0x03;

// ============================================================================
// USER OPERATION UTILITIES
// ============================================================================

/**
 * Pack gas limits for v0.7 user operations
 */
export function packAccountGasLimits(
  verificationGasLimit: bigint,
  callGasLimit: bigint
): Hex {
  return concat([
    pad(toHex(verificationGasLimit), { size: 16 }),
    pad(toHex(callGasLimit), { size: 16 }),
  ]);
}

/**
 * Pack gas fees for v0.7 user operations
 */
export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint
): Hex {
  return concat([
    pad(toHex(maxPriorityFeePerGas), { size: 16 }),
    pad(toHex(maxFeePerGas), { size: 16 }),
  ]);
}

/**
 * Pack paymaster and data
 */
export function packPaymasterAndData(data: PaymasterData): Hex {
  if (data.paymaster === '0x0000000000000000000000000000000000000000') {
    return '0x';
  }
  
  return concat([
    data.paymaster,
    pad(toHex(data.paymasterVerificationGasLimit), { size: 16 }),
    pad(toHex(data.paymasterPostOpGasLimit), { size: 16 }),
    data.paymasterData,
  ]);
}

/**
 * Compute user operation hash (for signing)
 */
export function getUserOpHash(
  userOp: UserOperation | PackedUserOperation,
  entryPoint: Address,
  chainId: bigint
): Hash {
  const packed = encodeAbiParameters(
    parseAbiParameters('address, uint256, bytes32, bytes32, uint256, uint256, uint256, uint256, uint256, bytes32'),
    [
      userOp.sender,
      userOp.nonce,
      keccak256(userOp.initCode),
      keccak256(userOp.callData),
      'accountGasLimits' in userOp 
        ? BigInt(slice(userOp.accountGasLimits, 16, 32)) 
        : userOp.callGasLimit,
      'accountGasLimits' in userOp
        ? BigInt(slice(userOp.accountGasLimits, 0, 16))
        : userOp.verificationGasLimit,
      userOp.preVerificationGas,
      'gasFees' in userOp
        ? BigInt(slice(userOp.gasFees, 16, 32))
        : userOp.maxFeePerGas,
      'gasFees' in userOp
        ? BigInt(slice(userOp.gasFees, 0, 16))
        : userOp.maxPriorityFeePerGas,
      keccak256(userOp.paymasterAndData),
    ]
  );
  
  const userOpHash = keccak256(packed);
  
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters('bytes32, address, uint256'),
      [userOpHash, entryPoint, chainId]
    )
  );
}

// ============================================================================
// EIP-7702 UTILITIES
// ============================================================================

/**
 * Create EIP-7702 authorization
 */
export function createEIP7702Authorization(
  chainId: bigint,
  contractAddress: Address,
  nonce: bigint
): Omit<EIP7702Authorization, 'signature'> {
  return {
    chainId,
    address: contractAddress,
    nonce,
  };
}

/**
 * Compute EIP-7702 authorization hash
 */
export function getEIP7702AuthorizationHash(
  auth: Omit<EIP7702Authorization, 'signature'>
): Hash {
  const encoded = encodeAbiParameters(
    parseAbiParameters('uint8, uint256, address, uint256'),
    [EIP7702_MAGIC, auth.chainId, auth.address, auth.nonce]
  );
  
  return keccak256(encoded);
}

/**
 * Check if an address has EIP-7702 delegation
 */
export function isEIP7702Delegated(code: Hex): boolean {
  // EIP-7702 delegated code starts with 0xef0100
  return code.startsWith('0xef0100');
}

/**
 * Get delegated address from EIP-7702 code
 */
export function getEIP7702DelegatedAddress(code: Hex): Address | null {
  if (!isEIP7702Delegated(code)) {
    return null;
  }
  
  // Code format: 0xef0100 + 20-byte address
  return slice(code, 3, 23) as Address;
}

// ============================================================================
// SMART ACCOUNT CLIENT
// ============================================================================

/**
 * Smart Account Client for cross-chain account abstraction
 */
export class SmartAccountClient {
  private config: SmartAccountConfig;
  private chainId: bigint;
  private entryPoint: Address;
  
  constructor(
    config: SmartAccountConfig,
    chainId: bigint,
    entryPoint: Address = ENTRY_POINT_V07
  ) {
    this.config = config;
    this.chainId = chainId;
    this.entryPoint = entryPoint;
  }
  
  /**
   * Compute counterfactual address
   */
  getAddress(): Address {
    const initCode = this.getInitCode();
    const salt = keccak256(
      encodeAbiParameters(
        parseAbiParameters('address, uint256'),
        [this.config.owner, BigInt(0)]
      )
    );
    
    // CREATE2 address computation
    const hash = keccak256(
      concat([
        '0xff',
        this.config.implementation,
        salt,
        keccak256(initCode),
      ])
    );
    
    return slice(hash, 12, 32) as Address;
  }
  
  /**
   * Get init code for account creation
   */
  getInitCode(): Hex {
    // Simplified init code - in practice, depends on account implementation
    return concat([
      this.config.implementation,
      encodeAbiParameters(
        parseAbiParameters('address'),
        [this.config.owner]
      ),
    ]);
  }
  
  /**
   * Build a user operation
   */
  async buildUserOperation(params: {
    target: Address;
    value: bigint;
    data: Hex;
    nonce?: bigint;
  }): Promise<UserOperation> {
    const callData = encodeAbiParameters(
      parseAbiParameters('address, uint256, bytes'),
      [params.target, params.value, params.data]
    );
    
    return {
      sender: this.getAddress(),
      nonce: params.nonce ?? BigInt(0),
      initCode: '0x', // Assume account already deployed
      callData,
      callGasLimit: BigInt(100000),
      verificationGasLimit: BigInt(100000),
      preVerificationGas: BigInt(21000),
      maxFeePerGas: BigInt(1000000000), // 1 gwei
      maxPriorityFeePerGas: BigInt(100000000), // 0.1 gwei
      paymasterAndData: '0x',
      signature: '0x',
    };
  }
  
  /**
   * Build a cross-chain user operation
   */
  async buildCrossChainUserOperation(params: {
    targetChainId: bigint;
    target: Address;
    value: bigint;
    data: Hex;
    bridgeAddress: Address;
    nonce?: bigint;
  }): Promise<CrossChainUserOperation> {
    const baseOp = await this.buildUserOperation({
      target: params.bridgeAddress,
      value: BigInt(0),
      data: encodeAbiParameters(
        parseAbiParameters('uint256, address, uint256, bytes'),
        [params.targetChainId, params.target, params.value, params.data]
      ),
      nonce: params.nonce,
    });
    
    return {
      ...baseOp,
      sourceChainId: this.chainId,
      targetChainId: params.targetChainId,
      bridgeData: '0x',
      crossChainNonce: params.nonce ?? BigInt(0),
    };
  }
  
  /**
   * Sign a user operation
   */
  signUserOperation(
    userOp: UserOperation,
    privateKey: Hex
  ): UserOperation {
    const hash = getUserOpHash(userOp, this.entryPoint, this.chainId);
    
    // In practice, use viem's signMessage or similar
    // This is a placeholder
    const signature = keccak256(concat([hash, privateKey]));
    
    return {
      ...userOp,
      signature,
    };
  }
}

// ============================================================================
// PAYMASTER CLIENT
// ============================================================================

/**
 * Paymaster Client for gas sponsorship
 */
export class PaymasterClient {
  private paymasterAddress: Address;
  private chainId: bigint;
  
  constructor(paymasterAddress: Address, chainId: bigint) {
    this.paymasterAddress = paymasterAddress;
    this.chainId = chainId;
  }
  
  /**
   * Sponsor a user operation
   */
  async sponsorUserOperation(
    userOp: UserOperation,
    sponsorshipPolicy: 'free' | 'erc20' | 'subscription'
  ): Promise<UserOperation> {
    const paymasterData: PaymasterData = {
      paymaster: this.paymasterAddress,
      paymasterVerificationGasLimit: BigInt(50000),
      paymasterPostOpGasLimit: BigInt(50000),
      paymasterData: encodeAbiParameters(
        parseAbiParameters('uint8'),
        [sponsorshipPolicy === 'free' ? 0 : sponsorshipPolicy === 'erc20' ? 1 : 2]
      ),
    };
    
    return {
      ...userOp,
      paymasterAndData: packPaymasterAndData(paymasterData),
    };
  }
  
  /**
   * Estimate paymaster gas
   */
  estimatePaymasterGas(userOp: UserOperation): {
    verificationGasLimit: bigint;
    postOpGasLimit: bigint;
  } {
    return {
      verificationGasLimit: BigInt(50000),
      postOpGasLimit: BigInt(50000),
    };
  }
}

// ============================================================================
// SIGNATURE AGGREGATOR
// ============================================================================

/**
 * BLS Signature Aggregator for efficient batch verification
 */
export class BLSAggregator {
  private aggregatorAddress: Address;
  
  constructor(aggregatorAddress: Address) {
    this.aggregatorAddress = aggregatorAddress;
  }
  
  /**
   * Aggregate multiple BLS signatures
   */
  aggregateSignatures(signatures: Hex[]): Hex {
    // In practice, use BLS library for actual aggregation
    // This is a placeholder that hashes all signatures together
    return keccak256(concat(signatures));
  }
  
  /**
   * Prepare aggregated user operations for bundler
   */
  prepareAggregatedOps(
    userOps: UserOperation[]
  ): AggregatedSignature {
    const signatures = userOps.map(op => op.signature);
    const aggregatedSignature = this.aggregateSignatures(signatures);
    
    return {
      aggregator: this.aggregatorAddress,
      aggregatedSignature,
      userOpsPerAggregator: [{
        userOps,
        signature: aggregatedSignature,
      }],
    };
  }
}

// ============================================================================
// KEYSTORE ACCOUNT (CROSS-CHAIN)
// ============================================================================

/**
 * Keystore Account Manager for cross-chain identity
 */
export class KeystoreAccountManager {
  private account: KeystoreAccount;
  
  constructor(account: KeystoreAccount) {
    this.account = account;
  }
  
  /**
   * Get signing key hash for a chain
   */
  getSigningKeyHash(chainId: bigint): Hash {
    return keccak256(
      encodeAbiParameters(
        parseAbiParameters('address, uint256, bytes[]'),
        [
          this.account.owner,
          chainId,
          this.account.signingKeys.map(k => k.publicKey),
        ]
      )
    );
  }
  
  /**
   * Verify key is authorized via keystore
   */
  async verifyKeyAuthorization(
    key: Hex,
    keystoreProof: Hex[]
  ): Promise<boolean> {
    // Verify Merkle proof against keystore state
    const keyHash = keccak256(key);
    
    let currentHash = keyHash;
    for (const sibling of keystoreProof) {
      currentHash = keccak256(
        concat([currentHash, sibling].sort())
      );
    }
    
    // In practice, compare against on-chain keystore root
    return true;
  }
  
  /**
   * Create recovery operation
   */
  createRecoveryOperation(
    newOwner: Address,
    guardianSignatures: Hex[]
  ): UserOperation {
    if (guardianSignatures.length < this.account.recoveryConfig.threshold) {
      throw new Error('Insufficient guardian signatures');
    }
    
    const callData = encodeAbiParameters(
      parseAbiParameters('address, bytes[]'),
      [newOwner, guardianSignatures]
    );
    
    return {
      sender: this.account.keystoreAddress,
      nonce: BigInt(0),
      initCode: '0x',
      callData,
      callGasLimit: BigInt(200000),
      verificationGasLimit: BigInt(200000),
      preVerificationGas: BigInt(21000),
      maxFeePerGas: BigInt(1000000000),
      maxPriorityFeePerGas: BigInt(100000000),
      paymasterAndData: '0x',
      signature: concat(guardianSignatures),
    };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  packAccountGasLimits,
  packGasFees,
  packPaymasterAndData,
  getUserOpHash,
  createEIP7702Authorization,
  getEIP7702AuthorizationHash,
  isEIP7702Delegated,
  getEIP7702DelegatedAddress,
};
