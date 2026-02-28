/**
 * @title DynamicRoutingClient Tests
 * @description Unit tests for DynamicRoutingClient SDK module
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { type Address } from "viem";
import {
  DynamicRoutingClient,
  createDynamicRoutingClient,
} from "../src/client/DynamicRoutingClient";

// Mock addresses
const ROUTER_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678" as Address;
const WALLET_ADDRESS = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd" as Address;

// Stub clients matching the project's test convention (as any)
const publicClient = { readContract: vi.fn() } as any;
const walletClient = { writeContract: vi.fn() } as any;

describe("DynamicRoutingClient", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("constructor", () => {
    it("should create client with public client only", () => {
      const client = new DynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });
      expect(client.publicClient).toBeDefined();
      expect(client.routerAddress).toBe(ROUTER_ADDRESS);
      expect(client.walletClient).toBeUndefined();
    });

    it("should create client with wallet client", () => {
      const client = new DynamicRoutingClient({
        publicClient,
        walletClient,
        routerAddress: ROUTER_ADDRESS,
      });
      expect(client.walletClient).toBeDefined();
    });
  });

  describe("createDynamicRoutingClient factory", () => {
    it("should return a DynamicRoutingClient instance", () => {
      const client = createDynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });
      expect(client).toBeInstanceOf(DynamicRoutingClient);
    });
  });

  describe("read methods", () => {
    it("findOptimalRoute should call readContract", async () => {
      const client = new DynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });

      const mockRoute = {
        sourceChainId: 1n,
        destChainId: 42161n,
        amount: 10n ** 18n,
        maxSlippage: 50n,
        preferredBridges: [],
      };

      // Mock readContract — in a real test env this would use a forked chain
      const spy = vi.spyOn(publicClient, "readContract").mockResolvedValue({
        routeId: "0x01",
        adapters: [],
        estimatedFee: 1000n,
        estimatedTime: 300n,
        confidence: 9500n,
      } as any);

      const route = await client.findOptimalRoute(mockRoute as any);
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          address: ROUTER_ADDRESS,
          functionName: "findOptimalRoute",
        }),
      );
    });

    it("estimateFee should return a bigint", async () => {
      const client = new DynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });

      vi.spyOn(publicClient, "readContract").mockResolvedValue(1000n);

      const fee = await client.estimateFee(1n, 42161n, 10n ** 18n);
      expect(typeof fee).toBe("bigint");
    });

    it("predictCompletionTime should return time and confidence", async () => {
      const client = new DynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });

      vi.spyOn(publicClient, "readContract").mockResolvedValue([300n, 9500n]);

      const prediction = await client.predictCompletionTime(
        1n,
        42161n,
        10n ** 18n,
      );
      expect(prediction.time).toBe(300);
      expect(prediction.confidenceBps).toBe(9500);
    });
  });

  describe("write methods", () => {
    it("executeRoute should throw without wallet", async () => {
      const client = new DynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });

      await expect(client.executeRoute("0x01" as any, 0n)).rejects.toThrow(
        "Wallet client required",
      );
    });
  });

  describe("getRouteRecommendation", () => {
    it("should aggregate route, fee, and time in one call", async () => {
      const client = new DynamicRoutingClient({
        publicClient,
        routerAddress: ROUTER_ADDRESS,
      });

      const mockRoute = { routeId: "0x01", adapters: [] };
      const readSpy = vi.spyOn(publicClient, "readContract");

      readSpy
        .mockResolvedValueOnce(mockRoute as any) // findOptimalRoute
        .mockResolvedValueOnce(500n) // estimateFee
        .mockResolvedValueOnce([120n, 9800n]); // predictCompletionTime

      const rec = await client.getRouteRecommendation({
        sourceChainId: 1n,
        destChainId: 42161n,
        amount: 10n ** 18n,
      } as any);

      expect(rec.route).toBeDefined();
      expect(rec.estimatedFee).toBe(500n);
      expect(rec.completionTime.time).toBe(120);
      expect(rec.completionTime.confidenceBps).toBe(9800);
    });
  });
});
