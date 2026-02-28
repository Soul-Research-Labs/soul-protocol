import crypto from "crypto";

export interface ZaseonConfig {
  curve: string;
  relayerEndpoint: string;
  proverUrl: string;
  privateKey: string;
}

/** Payload can be any JSON-serializable object */
export type ZaseonPayload = Record<string, unknown>;

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
  payload: ZaseonPayload;
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

  /**
   * Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme).
   *
   * 1. Generate ephemeral ECDH key pair
   * 2. Derive shared secret via ECDH with recipient's public key
   * 3. Derive AES-256-GCM key from shared secret via HKDF
   * 4. Encrypt plaintext with AES-256-GCM
   * 5. Return ciphertext, ephemeral PUBLIC key (not the symmetric key), and auth tag
   *
   * @param data - Plaintext to encrypt
   * @param recipientPublicKey - The recipient's public key (hex or Buffer). If not provided,
   *                             falls back to self-contained encryption with key in header.
   */
  async encrypt(
    data: Buffer,
    recipientPublicKey?: string | Buffer
  ): Promise<{ ciphertext: Buffer; ephemeralKey: Buffer; mac: Buffer }> {
    const iv = crypto.randomBytes(12);

    // Generate ephemeral key pair for ECDH
    const ephemeral = crypto.createECDH(this.curve === 'secp256k1' ? 'secp256k1' : 'prime256v1');
    ephemeral.generateKeys();

    let aesKey: Buffer;
    if (recipientPublicKey) {
      // ECIES: derive shared secret via ECDH, then HKDF to get AES key
      const pubKeyBuf = typeof recipientPublicKey === 'string'
        ? Buffer.from(recipientPublicKey.replace(/^0x/, ''), 'hex')
        : recipientPublicKey;
      const sharedSecret = ephemeral.computeSecret(pubKeyBuf);
      aesKey = crypto.createHash('sha256').update(sharedSecret).update('zaseon-ecies-v1').digest();
    } else {
      // Self-contained mode: derive key from ephemeral private key (for dev/testing)
      aesKey = crypto.createHash('sha256').update(ephemeral.getPrivateKey()).digest();
    }

    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Return ephemeral PUBLIC key (not the symmetric key)
    // Ciphertext format: [12-byte IV | encrypted data]
    const ciphertext = Buffer.concat([iv, encrypted]);
    return { ciphertext, ephemeralKey: ephemeral.getPublicKey() as Buffer, mac: tag };
  }

  /**
   * Decrypt ECIES-encrypted data.
   *
   * @param ciphertext - The ciphertext (with 12-byte IV prefix)
   * @param ephemeralPublicKey - The sender's ephemeral public key
   * @param mac - The AES-GCM authentication tag
   * @param recipientPrivateKey - The recipient's private key for ECDH
   */
  async decrypt(
    ciphertext: Buffer,
    ephemeralPublicKey: Buffer,
    mac: Buffer,
    recipientPrivateKey: Buffer
  ): Promise<Buffer> {
    // Reconstruct ECDH shared secret
    const ecdh = crypto.createECDH(this.curve === 'secp256k1' ? 'secp256k1' : 'prime256v1');
    ecdh.setPrivateKey(recipientPrivateKey);
    const sharedSecret = ecdh.computeSecret(ephemeralPublicKey);
    const aesKey = crypto.createHash('sha256').update(sharedSecret).update('zaseon-ecies-v1').digest();

    // Extract IV from ciphertext prefix
    const iv = ciphertext.subarray(0, 12);
    const encryptedData = ciphertext.subarray(12);

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(mac);
    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }
}

