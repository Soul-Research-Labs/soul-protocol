import { expect } from "chai";
import crypto from "crypto";
import { CryptoModule } from "../src/utils/crypto";

// ============================================================
// Helpers
// ============================================================

/**
 * Generate an ECDH key pair on the given curve.
 */
function generateKeyPair(curve: string) {
  const ecdh = crypto.createECDH(
    curve === "secp256k1" ? "secp256k1" : "prime256v1",
  );
  ecdh.generateKeys();
  return {
    privateKey: ecdh.getPrivateKey(),
    publicKey: ecdh.getPublicKey(),
  };
}

// ============================================================
// Tests
// ============================================================

describe("CryptoModule", () => {
  // ==================================================================
  // Constructor
  // ==================================================================
  describe("constructor", () => {
    it("should store the curve name", () => {
      const mod = new CryptoModule("secp256k1");
      expect(mod.curve).to.equal("secp256k1");
    });

    it("should accept p256 curve", () => {
      const mod = new CryptoModule("p256");
      expect(mod.curve).to.equal("p256");
    });
  });

  // ==================================================================
  // ECIES encrypt / decrypt round-trip (secp256k1)
  // ==================================================================
  describe("ECIES round-trip (secp256k1)", () => {
    const CURVE = "secp256k1";

    it("should encrypt and decrypt short plaintext", async () => {
      const mod = new CryptoModule(CURVE);
      const { privateKey, publicKey } = generateKeyPair(CURVE);
      const plaintext = Buffer.from("hello zaseon");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );
      const decrypted = await mod.decrypt(
        ciphertext,
        ephemeralKey,
        mac,
        privateKey,
      );

      expect(decrypted.toString()).to.equal("hello zaseon");
    });

    it("should encrypt and decrypt empty buffer", async () => {
      const mod = new CryptoModule(CURVE);
      const { privateKey, publicKey } = generateKeyPair(CURVE);
      const plaintext = Buffer.alloc(0);

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );
      const decrypted = await mod.decrypt(
        ciphertext,
        ephemeralKey,
        mac,
        privateKey,
      );

      expect(decrypted.length).to.equal(0);
    });

    it("should encrypt and decrypt 1KB payload", async () => {
      const mod = new CryptoModule(CURVE);
      const { privateKey, publicKey } = generateKeyPair(CURVE);
      const plaintext = crypto.randomBytes(1024);

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );
      const decrypted = await mod.decrypt(
        ciphertext,
        ephemeralKey,
        mac,
        privateKey,
      );

      expect(decrypted.equals(plaintext)).to.be.true;
    });

    it("should produce different ciphertext on each encryption", async () => {
      const mod = new CryptoModule(CURVE);
      const { publicKey } = generateKeyPair(CURVE);
      const plaintext = Buffer.from("determinism test");

      const result1 = await mod.encrypt(plaintext, publicKey);
      const result2 = await mod.encrypt(plaintext, publicKey);

      // Different ephemeral keys → different ciphertexts
      expect(result1.ciphertext.equals(result2.ciphertext)).to.be.false;
      expect(result1.ephemeralKey.equals(result2.ephemeralKey)).to.be.false;
    });
  });

  // ==================================================================
  // ECIES round-trip (p256 / prime256v1)
  // ==================================================================
  describe("ECIES round-trip (p256)", () => {
    const CURVE = "p256";

    it("should encrypt and decrypt with p256 curve", async () => {
      const mod = new CryptoModule(CURVE);
      const { privateKey, publicKey } = generateKeyPair(CURVE);
      const plaintext = Buffer.from("cross-chain privacy");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );
      const decrypted = await mod.decrypt(
        ciphertext,
        ephemeralKey,
        mac,
        privateKey,
      );

      expect(decrypted.toString()).to.equal("cross-chain privacy");
    });
  });

  // ==================================================================
  // Ciphertext structure
  // ==================================================================
  describe("ciphertext structure", () => {
    it("ciphertext should start with 12-byte IV", async () => {
      const mod = new CryptoModule("secp256k1");
      const { publicKey } = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("iv test");

      const { ciphertext } = await mod.encrypt(plaintext, publicKey);

      // Ciphertext = [12-byte IV | encrypted data]
      expect(ciphertext.length).to.be.greaterThan(12);
    });

    it("ciphertext length should be 12 (IV) + plaintext length (with GCM no padding)", async () => {
      const mod = new CryptoModule("secp256k1");
      const { publicKey } = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("exact length test!!");

      const { ciphertext } = await mod.encrypt(plaintext, publicKey);

      // AES-GCM is a stream cipher: ciphertext length = IV (12) + plaintext length
      expect(ciphertext.length).to.equal(12 + plaintext.length);
    });

    it("mac should be 16 bytes (AES-GCM auth tag)", async () => {
      const mod = new CryptoModule("secp256k1");
      const { publicKey } = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("tag test");

      const { mac } = await mod.encrypt(plaintext, publicKey);

      expect(mac.length).to.equal(16);
    });

    it("ephemeralKey should be a valid EC public key", async () => {
      const mod = new CryptoModule("secp256k1");
      const { publicKey } = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("key test");

      const { ephemeralKey } = await mod.encrypt(plaintext, publicKey);

      // Uncompressed secp256k1 public key is 65 bytes (04 || x || y)
      expect(ephemeralKey.length).to.equal(65);
      expect(ephemeralKey[0]).to.equal(0x04); // uncompressed prefix
    });
  });

  // ==================================================================
  // Self-contained mode (no recipient key)
  // ==================================================================
  describe("self-contained mode", () => {
    it("should encrypt without recipient key", async () => {
      const mod = new CryptoModule("secp256k1");
      const plaintext = Buffer.from("self-contained");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(plaintext);

      expect(ciphertext.length).to.be.greaterThan(12);
      expect(ephemeralKey.length).to.equal(65);
      expect(mac.length).to.equal(16);
    });

    it("different encryptions in self-contained mode produce different outputs", async () => {
      const mod = new CryptoModule("secp256k1");
      const plaintext = Buffer.from("variance");

      const r1 = await mod.encrypt(plaintext);
      const r2 = await mod.encrypt(plaintext);

      expect(r1.ciphertext.equals(r2.ciphertext)).to.be.false;
    });
  });

  // ==================================================================
  // Hex-string public key
  // ==================================================================
  describe("hex-string public key", () => {
    it("should accept hex-encoded public key as string", async () => {
      const mod = new CryptoModule("secp256k1");
      const { privateKey, publicKey } = generateKeyPair("secp256k1");
      const pubKeyHex = "0x" + publicKey.toString("hex");
      const plaintext = Buffer.from("hex key test");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        pubKeyHex,
      );
      const decrypted = await mod.decrypt(
        ciphertext,
        ephemeralKey,
        mac,
        privateKey,
      );

      expect(decrypted.toString()).to.equal("hex key test");
    });

    it("should accept hex-encoded public key without 0x prefix", async () => {
      const mod = new CryptoModule("secp256k1");
      const { privateKey, publicKey } = generateKeyPair("secp256k1");
      const pubKeyHex = publicKey.toString("hex");
      const plaintext = Buffer.from("no prefix");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        pubKeyHex,
      );
      const decrypted = await mod.decrypt(
        ciphertext,
        ephemeralKey,
        mac,
        privateKey,
      );

      expect(decrypted.toString()).to.equal("no prefix");
    });
  });

  // ==================================================================
  // Error handling
  // ==================================================================
  describe("error handling", () => {
    it("should fail decryption with wrong private key", async () => {
      const mod = new CryptoModule("secp256k1");
      const { publicKey } = generateKeyPair("secp256k1");
      const wrongKey = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("wrong key");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );

      try {
        await mod.decrypt(ciphertext, ephemeralKey, mac, wrongKey.privateKey);
        expect.fail("should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("Unsupported state");
      }
    });

    it("should fail decryption with tampered ciphertext", async () => {
      const mod = new CryptoModule("secp256k1");
      const { privateKey, publicKey } = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("tamper test");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );

      // Tamper with ciphertext
      const tampered = Buffer.from(ciphertext);
      tampered[15] ^= 0xff;

      try {
        await mod.decrypt(tampered, ephemeralKey, mac, privateKey);
        expect.fail("should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("Unsupported state");
      }
    });

    it("should fail decryption with tampered auth tag", async () => {
      const mod = new CryptoModule("secp256k1");
      const { privateKey, publicKey } = generateKeyPair("secp256k1");
      const plaintext = Buffer.from("tag tamper");

      const { ciphertext, ephemeralKey, mac } = await mod.encrypt(
        plaintext,
        publicKey,
      );

      // Tamper with mac
      const badMac = Buffer.from(mac);
      badMac[0] ^= 0xff;

      try {
        await mod.decrypt(ciphertext, ephemeralKey, badMac, privateKey);
        expect.fail("should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("Unsupported state");
      }
    });
  });

  // ==================================================================
  // Types / exports
  // ==================================================================
  describe("type exports", () => {
    it("CryptoModule should be a constructable class", () => {
      expect(typeof CryptoModule).to.equal("function");
      const instance = new CryptoModule("secp256k1");
      expect(instance).to.be.instanceOf(CryptoModule);
    });

    it("encrypt should return Promise", () => {
      const mod = new CryptoModule("secp256k1");
      const result = mod.encrypt(Buffer.from("test"));
      expect(result).to.be.instanceOf(Promise);
      // Clean up
      result.catch(() => {});
    });

    it("decrypt should return Promise", () => {
      const mod = new CryptoModule("secp256k1");
      const result = mod.decrypt(
        Buffer.alloc(16),
        Buffer.alloc(65),
        Buffer.alloc(16),
        Buffer.alloc(32),
      );
      expect(result).to.be.instanceOf(Promise);
      // Clean up (will reject due to invalid input)
      result.catch(() => {});
    });
  });
});
