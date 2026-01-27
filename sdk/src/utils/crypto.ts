import crypto from "crypto";

export interface SoulConfig {
  curve: string;
  relayerEndpoint: string;
  proverUrl: string;
  privateKey: string;
}

/** Payload can be any JSON-serializable object */
export type SoulPayload = Record<string, unknown>;

/** Disclosure policy defines what information can be revealed */
export interface DisclosurePolicy {
  allowedFields?: string[];
  requiredProofs?: string[];
  complianceLevel?: "none" | "basic" | "enhanced";
}

/** ZK circuit inputs and witnesses */
export interface CircuitInputs {
  publicInputs: string[] | bigint[];
  privateInputs?: string[] | bigint[];
}

export interface CircuitWitnesses {
  witness: string[] | bigint[];
  auxiliaryData?: Record<string, unknown>;
}

export interface SendParams {
  sourceChain: string;
  destChain: string;
  payload: SoulPayload;
  circuitId: string;
  disclosurePolicy: DisclosurePolicy;
  inputs?: CircuitInputs;
  witnesses?: CircuitWitnesses;
  maxDelay?: number;
}

export interface Receipt {
  txHash: string;
  status: string;
}

export class CryptoModule {
  constructor(public curve: string) {}

  async encrypt(data: Buffer, destChainId: string): Promise<{ ciphertext: Buffer; ephemeralKey: Buffer; mac: Buffer }> {
    // Placeholder: AES-256-GCM encryption with random key
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Ephemeral key would be ECIES public key in production
    return { ciphertext, ephemeralKey: key, mac: tag };
  }

  async decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, tag: Buffer): Promise<Buffer> {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
}

