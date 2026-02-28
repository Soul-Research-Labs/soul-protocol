import { expect } from "chai";
import { keccak256, concat, toHex, Hex, stringToBytes } from "viem";
import {
  NullifierClient,
  NullifierType,
  CHAIN_DOMAINS,
  type ChainDomain,
} from "../src/privacy/NullifierClient";

describe("NullifierClient", () => {
  const MOCK_ADDRESS = ("0x" + "ab".repeat(20)) as Hex;

  const makeClient = (opts?: { withWallet?: boolean }) => {
    const publicClient = {
      watchContractEvent: () => () => {},
    } as any;

    const walletClient = opts?.withWallet
      ? { writeContract: async () => "0xdeadbeef" as Hex }
      : undefined;

    return new NullifierClient(
      MOCK_ADDRESS,
      publicClient as any,
      walletClient as any,
    );
  };

  // ================================================================
  // Static Derivation Methods
  // ================================================================

  describe("deriveNullifier()", () => {
    it("should derive a 32-byte nullifier", () => {
      const secret = ("0x" + "aa".repeat(32)) as Hex;
      const commitment = ("0x" + "bb".repeat(32)) as Hex;
      const result = NullifierClient.deriveNullifier(secret, commitment, 1);
      expect(result).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should be deterministic", () => {
      const secret = ("0x" + "11".repeat(32)) as Hex;
      const commitment = ("0x" + "22".repeat(32)) as Hex;
      const a = NullifierClient.deriveNullifier(secret, commitment, 42);
      const b = NullifierClient.deriveNullifier(secret, commitment, 42);
      expect(a).to.equal(b);
    });

    it("should differ by chain ID", () => {
      const secret = ("0x" + "11".repeat(32)) as Hex;
      const commitment = ("0x" + "22".repeat(32)) as Hex;
      const nf1 = NullifierClient.deriveNullifier(secret, commitment, 1);
      const nf42 = NullifierClient.deriveNullifier(secret, commitment, 42);
      expect(nf1).to.not.equal(nf42);
    });

    it("should differ by secret", () => {
      const commitHash = ("0x" + "cc".repeat(32)) as Hex;
      const nfA = NullifierClient.deriveNullifier(
        ("0x" + "aa".repeat(32)) as Hex,
        commitHash,
        1,
      );
      const nfB = NullifierClient.deriveNullifier(
        ("0x" + "bb".repeat(32)) as Hex,
        commitHash,
        1,
      );
      expect(nfA).to.not.equal(nfB);
    });
  });

  describe("deriveFromMoneroKeyImage()", () => {
    it("should return a 32-byte hash", () => {
      const keyImage = ("0x" + "ff".repeat(32)) as Hex;
      const result = NullifierClient.deriveFromMoneroKeyImage(keyImage);
      expect(result).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should be deterministic", () => {
      const keyImage = ("0x" + "dd".repeat(32)) as Hex;
      const a = NullifierClient.deriveFromMoneroKeyImage(keyImage);
      const b = NullifierClient.deriveFromMoneroKeyImage(keyImage);
      expect(a).to.equal(b);
    });
  });

  describe("deriveFromZcashNullifier()", () => {
    it("should return a 32-byte hash", () => {
      const note = ("0x" + "ee".repeat(32)) as Hex;
      const anchor = ("0x" + "ff".repeat(32)) as Hex;
      const result = NullifierClient.deriveFromZcashNullifier(note, anchor);
      expect(result).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should differ by anchor", () => {
      const note = ("0x" + "11".repeat(32)) as Hex;
      const anchorA = ("0x" + "aa".repeat(32)) as Hex;
      const anchorB = ("0x" + "bb".repeat(32)) as Hex;
      const nfA = NullifierClient.deriveFromZcashNullifier(note, anchorA);
      const nfB = NullifierClient.deriveFromZcashNullifier(note, anchorB);
      expect(nfA).to.not.equal(nfB);
    });
  });

  describe("deriveCrossDomainNullifierLocal()", () => {
    it("should produce a cross-domain nullifier", () => {
      const source = ("0x" + "11".repeat(32)) as Hex;
      const result = NullifierClient.deriveCrossDomainNullifierLocal(
        source,
        CHAIN_DOMAINS.ETHEREUM,
        CHAIN_DOMAINS.ARBITRUM,
      );
      expect(result).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should differ for different source/target domains", () => {
      const source = ("0x" + "22".repeat(32)) as Hex;
      const a = NullifierClient.deriveCrossDomainNullifierLocal(
        source,
        CHAIN_DOMAINS.ETHEREUM,
        CHAIN_DOMAINS.ARBITRUM,
      );
      const b = NullifierClient.deriveCrossDomainNullifierLocal(
        source,
        CHAIN_DOMAINS.ETHEREUM,
        CHAIN_DOMAINS.OPTIMISM,
      );
      expect(a).to.not.equal(b);
    });

    it("should be non-symmetric (src→dst ≠ dst→src)", () => {
      const source = ("0x" + "33".repeat(32)) as Hex;
      const forward = NullifierClient.deriveCrossDomainNullifierLocal(
        source,
        CHAIN_DOMAINS.ETHEREUM,
        CHAIN_DOMAINS.BASE,
      );
      const reverse = NullifierClient.deriveCrossDomainNullifierLocal(
        source,
        CHAIN_DOMAINS.BASE,
        CHAIN_DOMAINS.ETHEREUM,
      );
      expect(forward).to.not.equal(reverse);
    });
  });

  describe("deriveZaseonBindingLocal()", () => {
    it("should derive a Zaseon binding from a nullifier", () => {
      const nf = ("0x" + "44".repeat(32)) as Hex;
      const result = NullifierClient.deriveZaseonBindingLocal(nf);
      expect(result).to.match(/^0x[0-9a-f]{64}$/i);
    });

    it("should be deterministic", () => {
      const nf = ("0x" + "55".repeat(32)) as Hex;
      const a = NullifierClient.deriveZaseonBindingLocal(nf);
      const b = NullifierClient.deriveZaseonBindingLocal(nf);
      expect(a).to.equal(b);
    });

    it("should differ for different nullifiers", () => {
      const a = NullifierClient.deriveZaseonBindingLocal(
        ("0x" + "66".repeat(32)) as Hex,
      );
      const b = NullifierClient.deriveZaseonBindingLocal(
        ("0x" + "77".repeat(32)) as Hex,
      );
      expect(a).to.not.equal(b);
    });
  });

  // ================================================================
  // Chain Domains
  // ================================================================

  describe("CHAIN_DOMAINS", () => {
    it("should contain expected chains", () => {
      expect(CHAIN_DOMAINS.ETHEREUM).to.exist;
      expect(CHAIN_DOMAINS.ARBITRUM).to.exist;
      expect(CHAIN_DOMAINS.OPTIMISM).to.exist;
      expect(CHAIN_DOMAINS.BASE).to.exist;
      expect(CHAIN_DOMAINS.MONERO).to.exist;
      expect(CHAIN_DOMAINS.ZCASH).to.exist;
      expect(CHAIN_DOMAINS.AZTEC).to.exist;
    });

    it("should have correct Arbitrum chain ID", () => {
      expect(CHAIN_DOMAINS.ARBITRUM.chainId).to.equal(42161);
    });

    it("should have correct Optimism chain ID", () => {
      expect(CHAIN_DOMAINS.OPTIMISM.chainId).to.equal(10);
    });

    it("should have correct Base chain ID", () => {
      expect(CHAIN_DOMAINS.BASE.chainId).to.equal(8453);
    });

    it("each domain should have chainId, domainTag, and name", () => {
      for (const [key, domain] of Object.entries(CHAIN_DOMAINS)) {
        expect(domain.chainId).to.be.a("number");
        expect(domain.domainTag)
          .to.be.a("string")
          .and.to.have.length.greaterThan(0);
        expect(domain.name).to.be.a("string").and.to.have.length.greaterThan(0);
      }
    });
  });

  // ================================================================
  // NullifierType Enum
  // ================================================================

  describe("NullifierType enum", () => {
    it("should have expected values", () => {
      expect(NullifierType.Zaseon_NATIVE).to.equal(0);
      expect(NullifierType.MONERO_KEY_IMAGE).to.equal(1);
      expect(NullifierType.ZCASH_NOTE).to.equal(2);
      expect(NullifierType.AZTEC_NOTE).to.equal(7);
    });
  });

  // ================================================================
  // Instance Methods — Validation
  // ================================================================

  describe("registerDomain()", () => {
    it("should throw without wallet client", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.registerDomain(CHAIN_DOMAINS.ETHEREUM);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  describe("registerNullifier()", () => {
    it("should throw without wallet client", async () => {
      const client = makeClient({ withWallet: false });
      try {
        await client.registerNullifier(("0x" + "aa".repeat(32)) as Hex, 1);
        expect.fail("should have thrown");
      } catch (e: any) {
        expect(e.message).to.include("Wallet client required");
      }
    });
  });

  // ================================================================
  // Event Listeners
  // ================================================================

  describe("onNullifierRegistered()", () => {
    it("should return an unwatch function", () => {
      const client = makeClient();
      const unwatch = client.onNullifierRegistered(() => {});
      expect(unwatch).to.be.a("function");
    });
  });

  describe("onCrossDomainDerived()", () => {
    it("should return an unwatch function", () => {
      const client = makeClient();
      const unwatch = client.onCrossDomainDerived(() => {});
      expect(unwatch).to.be.a("function");
    });
  });
});
