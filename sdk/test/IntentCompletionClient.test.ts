/**
 * @title IntentCompletionClient Tests
 * @description Unit tests for IntentCompletionClient SDK module
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { type Address, type Hex } from "viem";
import {
  IntentCompletionClient,
  createIntentCompletionClient,
} from "../src/client/IntentCompletionClient";

const INTENT_ADDRESS = "0x1111111111111111111111111111111111111111" as Address;
const GUARANTEE_ADDRESS =
  "0x2222222222222222222222222222222222222222" as Address;

// Stub clients matching the project's test convention (as any)
const publicClient = { readContract: vi.fn() } as any;
const walletClient = { writeContract: vi.fn() } as any;

describe("IntentCompletionClient", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("constructor", () => {
    it("should create client with minimal config", () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });
      expect(client.intentLayerAddress).toBe(INTENT_ADDRESS);
      expect(client.walletClient).toBeUndefined();
      expect(client.guaranteeAddress).toBeUndefined();
    });

    it("should create client with full config", () => {
      const client = new IntentCompletionClient({
        publicClient,
        walletClient,
        intentLayerAddress: INTENT_ADDRESS,
        guaranteeAddress: GUARANTEE_ADDRESS,
      });
      expect(client.walletClient).toBeDefined();
      expect(client.guaranteeAddress).toBe(GUARANTEE_ADDRESS);
    });
  });

  describe("createIntentCompletionClient factory", () => {
    it("should return an IntentCompletionClient instance", () => {
      const client = createIntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });
      expect(client).toBeInstanceOf(IntentCompletionClient);
    });
  });

  describe("read methods", () => {
    it("getIntent should call readContract with correct args", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      const intentId = ("0x" + "ab".repeat(32)) as Hex;
      const mockIntent = {
        submitter: "0x1234",
        sourceChainId: 1n,
        destChainId: 42161n,
        status: 0,
      };

      const spy = vi
        .spyOn(publicClient, "readContract")
        .mockResolvedValue(mockIntent as any);

      const intent = await client.getIntent(intentId);
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          address: INTENT_ADDRESS,
          functionName: "getIntent",
          args: [intentId],
        }),
      );
    });

    it("getSolver should retrieve solver info", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      const solverAddr =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" as Address;
      const mockSolver = {
        isRegistered: true,
        stake: 10n ** 18n,
        reputation: 100n,
      };

      vi.spyOn(publicClient, "readContract").mockResolvedValue(
        mockSolver as any,
      );

      const solver = await client.getSolver(solverAddr);
      expect(solver).toBeDefined();
    });

    it("canFinalize should return boolean", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      vi.spyOn(publicClient, "readContract").mockResolvedValue(true);

      const result = await client.canFinalize(("0x" + "01".repeat(32)) as Hex);
      expect(result).toBe(true);
    });

    it("isFinalized should return boolean", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      vi.spyOn(publicClient, "readContract").mockResolvedValue(false);

      const result = await client.isFinalized(("0x" + "01".repeat(32)) as Hex);
      expect(result).toBe(false);
    });
  });

  describe("write methods", () => {
    it("submitIntent should throw without wallet", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      await expect(
        client.submitIntent({
          sourceChainId: 1n,
          destChainId: 42161n,
          sourceCommitment: ("0x" + "aa".repeat(32)) as Hex,
          desiredStateHash: ("0x" + "bb".repeat(32)) as Hex,
          maxFee: 10n ** 16n,
          deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
          value: 10n ** 16n,
        }),
      ).rejects.toThrow("Wallet client required");
    });

    it("registerSolver should throw without wallet", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      await expect(client.registerSolver(10n ** 18n)).rejects.toThrow(
        "Wallet client required",
      );
    });
  });

  describe("intent lifecycle", () => {
    it("should support reading intent and checking finalization status", async () => {
      const client = new IntentCompletionClient({
        publicClient,
        intentLayerAddress: INTENT_ADDRESS,
      });

      const intentId = ("0x" + "ff".repeat(32)) as Hex;
      const readSpy = vi.spyOn(publicClient, "readContract");

      readSpy
        .mockResolvedValueOnce({
          submitter: "0x1234",
          sourceChainId: 1n,
          destChainId: 42161n,
          status: 0,
        } as any)
        .mockResolvedValueOnce(false);

      const intent = await client.getIntent(intentId);
      expect(intent).toBeDefined();

      const finalized = await client.isFinalized(intentId);
      expect(finalized).toBe(false);
    });
  });
});
