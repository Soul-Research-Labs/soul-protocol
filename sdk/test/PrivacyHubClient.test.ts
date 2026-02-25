import { expect } from "chai";
import { zeroHash, zeroAddress, type Hex } from "viem";
import {
  PrivacyHubClient,
  RequestStatus,
  type PrivacyHubConfig,
  type TransferParams,
} from "../src/privacy/PrivacyHubClient";

// ============================================================
// Helpers
// ============================================================

const MOCK_HUB = ("0x" + "aa".repeat(20)) as Hex;
const MOCK_STEALTH = ("0x" + "bb".repeat(20)) as Hex;
const MOCK_RINGCT = ("0x" + "cc".repeat(20)) as Hex;
const MOCK_NULLIFIER = ("0x" + "dd".repeat(20)) as Hex;
const MOCK_TRANSFER_ID = ("0x" + "11".repeat(32)) as Hex;
const MOCK_TX_HASH = ("0x" + "ff".repeat(32)) as Hex;

function makeConfig(): PrivacyHubConfig {
  return {
    hubAddress: MOCK_HUB,
    stealthRegistryAddress: MOCK_STEALTH,
    ringCTAddress: MOCK_RINGCT,
    nullifierManagerAddress: MOCK_NULLIFIER,
  };
}

/**
 * Build a PrivacyHubClient with mock publicClient/walletClient.
 * `hubReadStubs` maps functionName -> handler for hubContract.read.*.
 * `hubWriteStubs` maps functionName -> handler for hubContract.write.*.
 */
function makeClient(opts?: {
  withWallet?: boolean;
  hubReadStubs?: Record<string, (...args: any[]) => any>;
  hubWriteStubs?: Record<string, (...args: any[]) => any>;
}) {
  const readStubs = opts?.hubReadStubs ?? {};
  const writeStubs = opts?.hubWriteStubs ?? {};

  // Minimal public client that routes readContract to stubs
  const publicClient = {
    readContract: async (call: any) => {
      const fn = call.functionName;
      if (readStubs[fn]) return readStubs[fn](call);
      return undefined;
    },
    waitForTransactionReceipt: async () => ({
      transactionHash: MOCK_TX_HASH,
      logs: [],
    }),
    getChainId: async () => 11155111,
    watchContractEvent: () => () => {}, // returns unwatch fn
  } as any;

  const walletClient = opts?.withWallet
    ? {
        chain: null,
        account: { address: "0x" + "ee".repeat(20) },
        writeContract: async () => MOCK_TX_HASH,
      }
    : undefined;

  // We need to patch the inner getContract result. Since PrivacyHubClient
  // calls getContract internally, we'll construct it directly and then
  // override the hubContract via prototype access. Instead, we use a
  // slightly different approach: mock the publicClient to respond to
  // readContract calls targeting the hub address.
  const client = new PrivacyHubClient(
    makeConfig(),
    publicClient,
    walletClient as any,
  );

  // Override the hubContract's read/write proxies for testing
  const hubRead: Record<string, any> = {};
  for (const [name, fn] of Object.entries(readStubs)) {
    hubRead[name] = fn;
  }

  const hubWrite: Record<string, any> = {};
  for (const [name, fn] of Object.entries(writeStubs)) {
    hubWrite[name] = fn;
  }

  // Patch internal hub contract (it's private, so use cast)
  (client as any).hubContract = {
    address: MOCK_HUB,
    read: new Proxy(hubRead, {
      get: (target, prop: string) => target[prop] ?? (async () => undefined),
    }),
    write: new Proxy(hubWrite, {
      get: (target, prop: string) => target[prop] ?? (async () => MOCK_TX_HASH),
    }),
  };

  return client;
}

// ============================================================
// Tests
// ============================================================

describe("PrivacyHubClient", () => {
  // ==================================================================
  // RequestStatus Enum
  // ==================================================================
  describe("RequestStatus enum", () => {
    it("should define NONE=0", () => {
      expect(RequestStatus.NONE).to.equal(0);
    });

    it("should define PENDING=1", () => {
      expect(RequestStatus.PENDING).to.equal(1);
    });

    it("should define RELAYED=2", () => {
      expect(RequestStatus.RELAYED).to.equal(2);
    });

    it("should define COMPLETED=3", () => {
      expect(RequestStatus.COMPLETED).to.equal(3);
    });

    it("should define FAILED=4", () => {
      expect(RequestStatus.FAILED).to.equal(4);
    });

    it("should define REFUNDED=5", () => {
      expect(RequestStatus.REFUNDED).to.equal(5);
    });
  });

  // ==================================================================
  // Constructor
  // ==================================================================
  describe("constructor", () => {
    it("should create client without wallet (read-only)", () => {
      const client = makeClient();
      expect(client).to.be.instanceOf(PrivacyHubClient);
    });

    it("should create client with wallet", () => {
      const client = makeClient({ withWallet: true });
      expect(client).to.be.instanceOf(PrivacyHubClient);
    });

    it("should expose sub-client getters", () => {
      const client = makeClient();
      expect(client.stealth).to.exist;
      expect(client.ringCT).to.exist;
      expect(client.nullifier).to.exist;
    });
  });

  // ==================================================================
  // Transfer Status Operations (read)
  // ==================================================================
  describe("getRequestStatus", () => {
    it("should return PENDING for a pending transfer", async () => {
      const client = makeClient({
        hubReadStubs: {
          getRequestStatus: async () => RequestStatus.PENDING,
        },
      });
      const status = await client.getRequestStatus(MOCK_TRANSFER_ID);
      expect(status).to.equal(RequestStatus.PENDING);
    });

    it("should return COMPLETED for a completed transfer", async () => {
      const client = makeClient({
        hubReadStubs: {
          getRequestStatus: async () => RequestStatus.COMPLETED,
        },
      });
      const status = await client.getRequestStatus(MOCK_TRANSFER_ID);
      expect(status).to.equal(RequestStatus.COMPLETED);
    });

    it("should return NONE for unknown transfer", async () => {
      const client = makeClient({
        hubReadStubs: {
          getRequestStatus: async () => RequestStatus.NONE,
        },
      });
      const status = await client.getRequestStatus(zeroHash);
      expect(status).to.equal(RequestStatus.NONE);
    });
  });

  describe("getTransferDetails", () => {
    it("should return transfer details", async () => {
      const client = makeClient({
        hubReadStubs: {
          getTransferDetails: async () => ({
            sender: "0x" + "aa".repeat(20),
            sourceChain: 11155111n,
            targetChain: 84532n,
            commitment: "0x" + "22".repeat(32),
            nullifier: "0x" + "33".repeat(32),
            status: 1,
            timestamp: 1700000000n,
          }),
        },
      });
      const details = await client.getTransferDetails(MOCK_TRANSFER_ID);
      expect(details).to.not.be.null;
      expect(details!.requestId).to.equal(MOCK_TRANSFER_ID);
      expect(details!.sourceDomain.chainId).to.equal(11155111);
      expect(details!.targetDomain.chainId).to.equal(84532);
      expect(details!.status).to.equal(RequestStatus.PENDING);
      expect(details!.timestamp).to.equal(1700000000);
    });

    it("should return null on error", async () => {
      const client = makeClient({
        hubReadStubs: {
          getTransferDetails: async () => {
            throw new Error("Not found");
          },
        },
      });
      const details = await client.getTransferDetails(MOCK_TRANSFER_ID);
      expect(details).to.be.null;
    });
  });

  // ==================================================================
  // Bridge Management (read)
  // ==================================================================
  describe("isChainSupported", () => {
    it("should return true for supported chain", async () => {
      const client = makeClient({
        hubReadStubs: {
          isBridgeRegistered: async () => true,
        },
      });
      expect(await client.isChainSupported(84532)).to.be.true;
    });

    it("should return false for unsupported chain", async () => {
      const client = makeClient({
        hubReadStubs: {
          isBridgeRegistered: async () => false,
        },
      });
      expect(await client.isChainSupported(999999)).to.be.false;
    });
  });

  describe("getSupportedChains", () => {
    it("should return list of chain IDs as numbers", async () => {
      const client = makeClient({
        hubReadStubs: {
          supportedChains: async () => [11155111n, 84532n, 421614n],
        },
      });
      const chains = await client.getSupportedChains();
      expect(chains).to.deep.equal([11155111, 84532, 421614]);
    });

    it("should return empty array when no chains", async () => {
      const client = makeClient({
        hubReadStubs: {
          supportedChains: async () => [],
        },
      });
      const chains = await client.getSupportedChains();
      expect(chains).to.deep.equal([]);
    });
  });

  describe("getBridgeAdapter", () => {
    it("should return adapter address", async () => {
      const expected = ("0x" + "99".repeat(20)) as Hex;
      const client = makeClient({
        hubReadStubs: {
          getBridgeAdapter: async () => expected,
        },
      });
      const adapter = await client.getBridgeAdapter(84532);
      expect(adapter).to.equal(expected);
    });
  });

  // ==================================================================
  // Write Operations — wallet-required guards
  // ==================================================================
  describe("wallet-required guards", () => {
    it("relayProof should throw without wallet", async () => {
      const client = makeClient();
      try {
        await client.relayProof(MOCK_TRANSFER_ID, "0xdeadbeef");
        expect.fail("should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("Wallet client required");
      }
    });

    it("completeRelay should throw without wallet", async () => {
      const client = makeClient();
      try {
        await client.completeRelay(MOCK_TRANSFER_ID, "0xdeadbeef");
        expect.fail("should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("Wallet client required");
      }
    });

    it("refundRelay should throw without wallet", async () => {
      const client = makeClient();
      try {
        await client.refundRelay(MOCK_TRANSFER_ID);
        expect.fail("should have thrown");
      } catch (err: any) {
        expect(err.message).to.include("Wallet client required");
      }
    });
  });

  // ==================================================================
  // Write Operations — with wallet
  // ==================================================================
  describe("relayProof", () => {
    it("should return tx hash on success", async () => {
      const client = makeClient({
        withWallet: true,
        hubWriteStubs: {
          relayPrivateTransfer: async () => MOCK_TX_HASH,
        },
      });
      const hash = await client.relayProof(MOCK_TRANSFER_ID, "0xproof");
      expect(hash).to.equal(MOCK_TX_HASH);
    });
  });

  describe("completeRelay", () => {
    it("should return tx hash on success", async () => {
      const client = makeClient({
        withWallet: true,
        hubWriteStubs: {
          completePrivateTransfer: async () => MOCK_TX_HASH,
        },
      });
      const hash = await client.completeRelay(MOCK_TRANSFER_ID, "0xproof");
      expect(hash).to.equal(MOCK_TX_HASH);
    });
  });

  describe("refundRelay", () => {
    it("should return tx hash on success", async () => {
      const client = makeClient({
        withWallet: true,
        hubWriteStubs: {
          refundRelay: async () => MOCK_TX_HASH,
        },
      });
      const hash = await client.refundRelay(MOCK_TRANSFER_ID);
      expect(hash).to.equal(MOCK_TX_HASH);
    });
  });

  // ==================================================================
  // Event Listeners
  // ==================================================================
  describe("event listeners", () => {
    it("onTransferInitiated should return unwatch function", () => {
      const client = makeClient();
      const unwatch = client.onTransferInitiated(() => {});
      expect(typeof unwatch).to.equal("function");
    });

    it("onTransferCompleted should return unwatch function", () => {
      const client = makeClient();
      const unwatch = client.onTransferCompleted(() => {});
      expect(typeof unwatch).to.equal("function");
    });

    it("onTransferFailed should return unwatch function", () => {
      const client = makeClient();
      const unwatch = client.onTransferFailed(() => {});
      expect(typeof unwatch).to.equal("function");
    });
  });

  // ==================================================================
  // Sub-client access
  // ==================================================================
  describe("sub-client getters", () => {
    it("stealth getter returns StealthAddressClient", () => {
      const client = makeClient();
      expect(client.stealth).to.exist;
      expect(client.stealth.constructor.name).to.equal("StealthAddressClient");
    });

    it("ringCT getter returns RingCTClient", () => {
      const client = makeClient();
      expect(client.ringCT).to.exist;
      expect(client.ringCT.constructor.name).to.equal("RingCTClient");
    });

    it("nullifier getter returns NullifierClient", () => {
      const client = makeClient();
      expect(client.nullifier).to.exist;
      expect(client.nullifier.constructor.name).to.equal("NullifierClient");
    });
  });
});
