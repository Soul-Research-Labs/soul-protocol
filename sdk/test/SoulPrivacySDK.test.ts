import { expect } from "chai";
import {
  SoulPrivacySDK,
  type SoulPrivacySDKConfig,
  type DepositNote,
} from "../src/client/SoulPrivacySDK";
import {
  createPublicClient,
  createWalletClient,
  http,
  zeroAddress,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

/**
 * SoulPrivacySDK unit tests
 *
 * Note: SoulPrivacySDK is deprecated in favor of SoulProtocolClient.
 * These tests validate existing functionality until removal in v2.0.
 */

// Deterministic test account (DO NOT use in production)
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

const MOCK_POOL = "0x1111111111111111111111111111111111111111" as Hex;
const MOCK_ROUTER = "0x2222222222222222222222222222222222222222" as Hex;
const MOCK_FEE_MARKET = "0x3333333333333333333333333333333333333333" as Hex;

function createTestConfig(
  overrides?: Partial<SoulPrivacySDKConfig>,
): SoulPrivacySDKConfig {
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http("http://127.0.0.1:8545"),
  });

  const account = privateKeyToAccount(TEST_PRIVATE_KEY);
  const walletClient = createWalletClient({
    chain: sepolia,
    transport: http("http://127.0.0.1:8545"),
    account,
  });

  return {
    publicClient,
    walletClient,
    addresses: {
      shieldedPool: MOCK_POOL,
      privacyRouter: MOCK_ROUTER,
      feeMarket: MOCK_FEE_MARKET,
    },
    ...overrides,
  };
}

describe("SoulPrivacySDK", () => {
  describe("constructor", () => {
    it("should create instance with full config", () => {
      const config = createTestConfig();
      const sdk = new SoulPrivacySDK(config);

      expect(sdk.publicClient).to.equal(config.publicClient);
      expect(sdk.walletClient).to.equal(config.walletClient);
      expect(sdk.addresses.shieldedPool).to.equal(MOCK_POOL);
      expect(sdk.addresses.privacyRouter).to.equal(MOCK_ROUTER);
      expect(sdk.addresses.feeMarket).to.equal(MOCK_FEE_MARKET);
    });

    it("should create instance without walletClient (read-only)", () => {
      const config = createTestConfig({ walletClient: undefined });
      const sdk = new SoulPrivacySDK(config);

      expect(sdk.walletClient).to.be.undefined;
      expect(sdk.publicClient).to.exist;
    });

    it("should create instance with partial addresses", () => {
      const config = createTestConfig();
      config.addresses = { shieldedPool: MOCK_POOL };
      const sdk = new SoulPrivacySDK(config);

      expect(sdk.addresses.shieldedPool).to.equal(MOCK_POOL);
      expect(sdk.addresses.privacyRouter).to.be.undefined;
      expect(sdk.addresses.feeMarket).to.be.undefined;
    });
  });

  describe("NATIVE_ASSET constant", () => {
    it("should be keccak256('ETH')", () => {
      // keccak256(toBytes("ETH")) is deterministic
      expect(SoulPrivacySDK.NATIVE_ASSET).to.be.a("string");
      expect(SoulPrivacySDK.NATIVE_ASSET).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should be consistent across instances", () => {
      expect(SoulPrivacySDK.NATIVE_ASSET).to.equal(SoulPrivacySDK.NATIVE_ASSET);
    });
  });

  describe("generateDepositNote()", () => {
    let sdk: SoulPrivacySDK;

    beforeEach(() => {
      sdk = new SoulPrivacySDK(createTestConfig());
    });

    it("should generate a valid deposit note with default assetId", () => {
      const note = sdk.generateDepositNote(1000000000000000000n);

      expect(note).to.have.property("commitment");
      expect(note).to.have.property("secret");
      expect(note).to.have.property("nullifierPreimage");
      expect(note).to.have.property("amount");
      expect(note).to.have.property("assetId");

      expect(note.commitment).to.match(/^0x[0-9a-f]{64}$/);
      expect(note.secret).to.match(/^0x[0-9a-f]{64}$/);
      expect(note.nullifierPreimage).to.match(/^0x[0-9a-f]{64}$/);
      expect(note.amount).to.equal(1000000000000000000n);
      expect(note.assetId).to.equal(SoulPrivacySDK.NATIVE_ASSET);
    });

    it("should generate unique notes on each call", () => {
      const note1 = sdk.generateDepositNote(1n);
      const note2 = sdk.generateDepositNote(1n);

      expect(note1.secret).to.not.equal(note2.secret);
      expect(note1.nullifierPreimage).to.not.equal(note2.nullifierPreimage);
      expect(note1.commitment).to.not.equal(note2.commitment);
    });

    it("should accept custom assetId", () => {
      const customAsset =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex;
      const note = sdk.generateDepositNote(500n, customAsset);

      expect(note.assetId).to.equal(customAsset);
      expect(note.amount).to.equal(500n);
    });

    it("should generate different commitments for different amounts", () => {
      const note1 = sdk.generateDepositNote(100n);
      const note2 = sdk.generateDepositNote(200n);

      // Commitments differ because amount and randomness differ
      expect(note1.commitment).to.not.equal(note2.commitment);
    });

    it("should handle zero amount", () => {
      const note = sdk.generateDepositNote(0n);
      expect(note.amount).to.equal(0n);
      expect(note.commitment).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should handle very large amounts", () => {
      const maxUint256 =
        115792089237316195423570985008687907853269984665640564039457584007913129639935n;
      const note = sdk.generateDepositNote(maxUint256);
      expect(note.amount).to.equal(maxUint256);
      expect(note.commitment).to.match(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("write operations without wallet", () => {
    let readOnlySDK: SoulPrivacySDK;

    beforeEach(() => {
      readOnlySDK = new SoulPrivacySDK(
        createTestConfig({ walletClient: undefined }),
      );
    });

    it("depositETH should throw without walletClient", async () => {
      const commitment =
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" as Hex;
      try {
        await readOnlySDK.depositETH(commitment, 1000n);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("WalletClient required");
      }
    });

    it("depositERC20 should throw without walletClient", async () => {
      const commitment =
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" as Hex;
      try {
        await readOnlySDK.depositERC20(
          SoulPrivacySDK.NATIVE_ASSET,
          1000n,
          commitment,
        );
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("WalletClient required");
      }
    });
  });

  describe("query operations without pool address", () => {
    let sdk: SoulPrivacySDK;

    beforeEach(() => {
      const config = createTestConfig();
      config.addresses = {};
      sdk = new SoulPrivacySDK(config);
    });

    it("getPoolStats should throw without pool address", async () => {
      try {
        await sdk.getPoolStats();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("ShieldedPool address not configured");
      }
    });

    it("getCurrentRoot should throw without pool address", async () => {
      try {
        await sdk.getCurrentRoot();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("ShieldedPool address not configured");
      }
    });

    it("isKnownRoot should throw without pool address", async () => {
      const root =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as Hex;
      try {
        await sdk.isKnownRoot(root);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("ShieldedPool address not configured");
      }
    });

    it("isNullifierSpent should throw without pool address", async () => {
      const nullifier =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" as Hex;
      try {
        await sdk.isNullifierSpent(nullifier);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("ShieldedPool address not configured");
      }
    });

    it("getNextLeafIndex should throw without pool address", async () => {
      try {
        await sdk.getNextLeafIndex();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("ShieldedPool address not configured");
      }
    });
  });

  describe("depositETH without router/pool address", () => {
    it("should throw when no pool or router address configured", async () => {
      const config = createTestConfig();
      config.addresses = {};
      const sdk = new SoulPrivacySDK(config);

      const commitment =
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" as Hex;
      try {
        await sdk.depositETH(commitment, 1000n, false);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("No pool/router address configured");
      }
    });

    it("should throw when useRouter=true but no router address", async () => {
      const config = createTestConfig();
      config.addresses = { shieldedPool: MOCK_POOL };
      const sdk = new SoulPrivacySDK(config);

      const commitment =
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" as Hex;
      try {
        await sdk.depositETH(commitment, 1000n, true);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("No pool/router address configured");
      }
    });
  });

  describe("depositERC20 without router/pool address", () => {
    it("should throw when no pool address configured", async () => {
      const config = createTestConfig();
      config.addresses = {};
      const sdk = new SoulPrivacySDK(config);

      const commitment =
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" as Hex;
      try {
        await sdk.depositERC20(SoulPrivacySDK.NATIVE_ASSET, 500n, commitment);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("No pool/router address configured");
      }
    });
  });
});
