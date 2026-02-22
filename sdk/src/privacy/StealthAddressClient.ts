import {
  PublicClient,
  WalletClient,
  Transport,
  Chain,
  HttpTransport,
  getContract,
  keccak256,
  toHex,
  toBytes,
  concat,
  getAddress,
  slice,
  Hex,
  ByteArray,
  Log,
  decodeEventLog,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { ViemReadonlyContract } from "../types/contracts";

// Stealth Address Schemes
export enum StealthScheme {
  SECP256K1 = 0,
  ED25519 = 1,
  BLS12_381 = 2,
  BABYJUBJUB = 3,
}

// Meta-address structure
export interface StealthMetaAddress {
  stealthId: Hex;
  spendingPubKey: Hex;
  viewingPubKey: Hex;
  scheme: StealthScheme;
}

// Computed stealth address result
export interface StealthAddressResult {
  stealthAddress: Hex;
  ephemeralPubKey: Hex;
  viewTag: Hex;
}

// Payment announcement
export interface PaymentAnnouncement {
  stealthAddress: Hex;
  ephemeralPubKey: Hex;
  metadata: Hex;
  blockNumber: number;
  transactionHash: Hex;
}

// ABI for StealthAddressRegistry
const STEALTH_REGISTRY_ABI = [
  {
    name: "registerMetaAddress",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "stealthId", type: "bytes32" },
      { name: "spendingPubKey", type: "bytes" },
      { name: "viewingPubKey", type: "bytes" },
      { name: "scheme", type: "uint8" },
    ],
  },
  {
    name: "computeStealthAddress",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "stealthId", type: "bytes32" },
      { name: "ephemeralPubKey", type: "bytes" },
    ],
    outputs: [{ type: "address" }, { type: "bytes" }],
  },
  {
    name: "announcePayment",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "stealthAddress", type: "address" },
      { name: "ephemeralPubKey", type: "bytes" },
      { name: "metadata", type: "bytes" },
    ],
  },
  {
    name: "getMetaAddress",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "stealthId", type: "bytes32" }],
    outputs: [
      { name: "spendingPubKey", type: "bytes" },
      { name: "viewingPubKey", type: "bytes" },
      { name: "scheme", type: "uint8" },
    ],
  },
  {
    name: "getAnnouncementCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "MetaAddressRegistered",
    type: "event",
    inputs: [
      { name: "stealthId", type: "bytes32", indexed: true },
      { name: "owner", type: "address", indexed: true },
      { name: "scheme", type: "uint8" },
    ],
  },
  {
    name: "PaymentAnnounced",
    type: "event",
    inputs: [
      { name: "stealthAddress", type: "address", indexed: true },
      { name: "ephemeralPubKey", type: "bytes" },
      { name: "metadata", type: "bytes" },
      { name: "blockNumber", type: "uint256", indexed: true },
    ],
  },
] as const;

export class StealthAddressClient {
  private contract: ViemReadonlyContract;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: STEALTH_REGISTRY_ABI,
      client: {
        public: publicClient,
        wallet: walletClient,
      },
    });
  }

  /**
   * Generate a new stealth meta-address keypair
   */
  static generateMetaAddress(scheme: StealthScheme = StealthScheme.SECP256K1): {
    spendingPrivKey: Hex;
    spendingPubKey: Hex;
    viewingPrivKey: Hex;
    viewingPubKey: Hex;
  } {
    // Generate random private keys
    const spendingPrivKey = toHex(crypto.getRandomValues(new Uint8Array(32)));
    const viewingPrivKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    // Derive public keys (secp256k1)
    const spendingAccount = privateKeyToAccount(spendingPrivKey);
    const viewingAccount = privateKeyToAccount(viewingPrivKey);

    return {
      spendingPrivKey,
      spendingPubKey: spendingAccount.publicKey,
      viewingPrivKey,
      viewingPubKey: viewingAccount.publicKey,
    };
  }

  /**
   * Compute stealth ID from meta-address components
   */
  static computeStealthId(spendingPubKey: Hex, viewingPubKey: Hex): Hex {
    return keccak256(concat([spendingPubKey, viewingPubKey]));
  }

  /**
   * Register a new stealth meta-address
   */
  async registerMetaAddress(
    spendingPubKey: Hex,
    viewingPubKey: Hex,
    scheme: StealthScheme = StealthScheme.SECP256K1,
  ): Promise<{ stealthId: Hex; txHash: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for registration");

    const stealthId = StealthAddressClient.computeStealthId(
      spendingPubKey,
      viewingPubKey,
    );

    const hash = await this.contract.write!.registerMetaAddress([
      stealthId,
      spendingPubKey,
      viewingPubKey,
      scheme,
    ]);

    return {
      stealthId,
      txHash: hash,
    };
  }

  /**
   * Get registered meta-address by stealth ID
   */
  async getMetaAddress(stealthId: Hex): Promise<StealthMetaAddress | null> {
    try {
      const [spendingPubKey, viewingPubKey, scheme] =
        await this.contract.read.getMetaAddress([stealthId]);

      if (spendingPubKey === "0x") return null;

      return {
        stealthId,
        spendingPubKey,
        viewingPubKey,
        scheme: scheme as StealthScheme,
      };
    } catch {
      return null;
    }
  }

  /**
   * Generate ephemeral keypair and compute stealth address
   */
  async computeStealthAddress(
    stealthId: Hex,
  ): Promise<StealthAddressResult & { ephemeralPrivKey: Hex }> {
    // Generate ephemeral keypair
    const ephemeralPrivKey = toHex(crypto.getRandomValues(new Uint8Array(32)));
    const ephemeralAccount = privateKeyToAccount(ephemeralPrivKey);
    const ephemeralPubKey = ephemeralAccount.publicKey;

    // Compute stealth address on-chain
    const [stealthAddress, viewTag] =
      await this.contract.read.computeStealthAddress([
        stealthId,
        ephemeralPubKey,
      ]);

    return {
      stealthAddress,
      ephemeralPubKey,
      viewTag,
      ephemeralPrivKey,
    };
  }

  /**
   * Announce a payment to a stealth address
   */
  async announcePayment(
    stealthAddress: string,
    ephemeralPubKey: Hex,
    metadata: Hex = "0x",
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for announcement");

    const hash = await this.contract.write!.announcePayment([
      stealthAddress,
      ephemeralPubKey,
      metadata,
    ]);
    return hash;
  }

  /**
   * Scan announcements for payments to our viewing key
   * @param viewingPrivKey - Private viewing key for scanning
   * @param fromBlock - Starting block number
   * @param toBlock - Ending block number (default: latest)
   */
  async scanAnnouncements(
    viewingPrivKey: Hex,
    spendingPubKey: Hex,
    fromBlock: bigint,
    toBlock?: bigint,
  ): Promise<
    { address: Hex; ephemeralPubKey: Hex; metadata: Hex; block: number }[]
  > {
    const paymentEvent = STEALTH_REGISTRY_ABI.find(
      (item): item is typeof item & { type: "event" } =>
        item.name === "PaymentAnnounced",
    );
    const logs = await this.publicClient.getLogs({
      address: this.contract.address,
      event: paymentEvent,
      fromBlock,
      toBlock: toBlock || "latest",
    });

    const matches: {
      address: Hex;
      ephemeralPubKey: Hex;
      metadata: Hex;
      block: number;
    }[] = [];

    for (const log of logs) {
      const decoded = decodeEventLog({
        abi: STEALTH_REGISTRY_ABI,
        data: log.data,
        topics: (log as Log).topics,
      });
      const args = decoded.args as unknown as {
        stealthAddress: Hex;
        ephemeralPubKey: Hex;
        metadata: Hex;
        blockNumber: bigint;
      };
      const { stealthAddress, ephemeralPubKey, metadata, blockNumber } = args;

      // Try to derive the stealth address with our keys
      const derivedAddress = this.deriveStealthAddressLocally(
        viewingPrivKey,
        spendingPubKey,
        ephemeralPubKey,
      );

      if (derivedAddress.toLowerCase() === stealthAddress.toLowerCase()) {
        matches.push({
          address: stealthAddress,
          ephemeralPubKey,
          metadata,
          block: Number(blockNumber),
        });
      }
    }

    return matches;
  }

  /**
   * Derive stealth address locally (for scanning)
   */
  private deriveStealthAddressLocally(
    viewingPrivKey: Hex,
    spendingPubKey: Hex,
    ephemeralPubKey: Hex,
  ): string {
    // Compute shared secret: viewingPrivKey * ephemeralPubKey
    // In a real implementation, this would use elliptic curve multiplication
    const sharedSecret = keccak256(concat([viewingPrivKey, ephemeralPubKey]));

    // Derive stealth public key: spendingPubKey + hash(sharedSecret) * G
    // Simplified: just hash for now
    const stealthPubKey = keccak256(concat([spendingPubKey, sharedSecret]));

    // Convert to address
    return getAddress(slice(stealthPubKey, -20));
  }

  /**
   * Derive stealth private key for spending
   */
  static deriveStealthPrivateKey(
    spendingPrivKey: Hex,
    viewingPrivKey: Hex,
    ephemeralPubKey: Hex,
  ): Hex {
    // Compute shared secret
    const sharedSecret = keccak256(concat([viewingPrivKey, ephemeralPubKey]));

    // Derive stealth private key: spendingPrivKey + hash(sharedSecret)
    const spendingBN = BigInt(spendingPrivKey);
    const sharedSecretBN = BigInt(sharedSecret);
    const curveOrder = BigInt(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    );

    const stealthPrivKey = (spendingBN + sharedSecretBN) % curveOrder;
    return toHex(stealthPrivKey, { size: 32 });
  }

  /**
   * Get total announcement count
   */
  async getAnnouncementCount(): Promise<number> {
    const count = await this.contract.read.getAnnouncementCount();
    return Number(count);
  }
}

export default StealthAddressClient;
