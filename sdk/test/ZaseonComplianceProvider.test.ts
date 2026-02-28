import { expect } from "chai";
import { type Address, type Hex } from "viem";
import {
  ZaseonComplianceProvider,
  type ComplianceConfig,
  type CredentialData,
} from "../src/compliance/ZaseonComplianceProvider";

// ============================================================
// Helpers
// ============================================================

const MOCK_CONTRACT = ("0x" + "cc".repeat(20)) as Address;
const MOCK_USER = ("0x" + "aa".repeat(20)) as Address;
const MOCK_PROVIDER_ADDR = ("0x" + "bb".repeat(20)) as Address;
const MOCK_CRED_ID = ("0x" + "dd".repeat(32)) as `0x${string}`;

function makeConfig(): ComplianceConfig {
  return {
    rpcUrl: "http://localhost:8545",
    contractAddress: MOCK_CONTRACT,
    providerId: "test-provider",
  };
}

/**
 * Monkey-patch the internal publicClient to intercept contract calls.
 */
function patchClient(
  provider: ZaseonComplianceProvider,
  stubs: {
    simulate?: (call: any) => Promise<any>;
    read?: (call: any) => Promise<any>;
  },
) {
  const pc = (provider as any).publicClient;
  if (stubs.simulate) pc.simulateContract = stubs.simulate;
  if (stubs.read) pc.readContract = stubs.read;
}

// ============================================================
// Tests
// ============================================================

describe("ZaseonComplianceProvider", () => {
  describe("constructor", () => {
    it("should create an instance with valid config", () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      expect(provider).to.be.instanceOf(ZaseonComplianceProvider);
    });
  });

  describe("registerProvider", () => {
    it("should call simulateContract with registerProvider", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      let capturedCall: any;
      patchClient(provider, {
        simulate: async (call: any) => {
          capturedCall = call;
          return { result: undefined };
        },
      });

      await provider.registerProvider("MyProvider");
      expect(capturedCall.functionName).to.equal("registerProvider");
      expect(capturedCall.args[0]).to.equal("MyProvider");
      expect(capturedCall.address).to.equal(MOCK_CONTRACT);
    });

    it("should generate a schema hash when not provided", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      let schema: string;
      patchClient(provider, {
        simulate: async (call: any) => {
          schema = call.args[1];
          return { result: undefined };
        },
      });

      await provider.registerProvider();
      // Default schema: hex(zaseon:compliance:test-provider:v1), padded to 64 hex chars
      expect(schema!).to.match(/^0x[0-9a-f]{64}$/);
    });

    it("should use provided schemaHash when given", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      const customSchema = ("0x" + "ff".repeat(32)) as `0x${string}`;
      let captured: string;
      patchClient(provider, {
        simulate: async (call: any) => {
          captured = call.args[1];
          return { result: undefined };
        },
      });

      await provider.registerProvider("P", customSchema);
      expect(captured!).to.equal(customSchema);
    });
  });

  describe("issueCredential", () => {
    it("should call with computed credentialHash and default 1-year expiry", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      let capturedCall: any;
      patchClient(provider, {
        simulate: async (call: any) => {
          capturedCall = call;
          return { result: MOCK_CRED_ID };
        },
      });

      const data: CredentialData = {
        level: "standard",
        jurisdiction: "US",
      };

      const before = Math.floor(Date.now() / 1000);
      const result = await provider.issueCredential(MOCK_USER, data);

      expect(result).to.equal(MOCK_CRED_ID);
      expect(capturedCall.functionName).to.equal("issueCredential");
      expect(capturedCall.args[0]).to.equal(MOCK_USER);
      // Credential hash is 0x-prefixed 64-hex-char string
      expect(capturedCall.args[1]).to.match(/^0x[0-9a-f]{64}$/);
      // Expiry should be roughly 1 year from now
      const expiry = Number(capturedCall.args[2]);
      expect(expiry).to.be.greaterThanOrEqual(before + 364 * 24 * 3600);
      // Default proof is empty 0x
      expect(capturedCall.args[3]).to.equal("0x");
    });

    it("should use custom expiry and proof when provided", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      let capturedCall: any;
      patchClient(provider, {
        simulate: async (call: any) => {
          capturedCall = call;
          return { result: MOCK_CRED_ID };
        },
      });

      const data: CredentialData = {
        level: "enhanced",
        jurisdiction: "EU",
        expiry: 1700000000,
        proof: "0xdeadbeef" as Hex,
      };

      await provider.issueCredential(MOCK_USER, data);
      expect(Number(capturedCall.args[2])).to.equal(1700000000);
      expect(capturedCall.args[3]).to.equal("0xdeadbeef");
    });
  });

  describe("revokeCredential", () => {
    it("should call revokeCredential with credentialId", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      let fn: string;
      patchClient(provider, {
        simulate: async (call: any) => {
          fn = call.functionName;
          return { result: undefined };
        },
      });

      await provider.revokeCredential(MOCK_CRED_ID);
      expect(fn!).to.equal("revokeCredential");
    });
  });

  describe("checkCompliance", () => {
    it("should return true for compliant user", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      patchClient(provider, {
        read: async () => true,
      });

      const result = await provider.checkCompliance(MOCK_USER);
      expect(result).to.be.true;
    });

    it("should return false for non-compliant user", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      patchClient(provider, {
        read: async () => false,
      });

      const result = await provider.checkCompliance(MOCK_USER);
      expect(result).to.be.false;
    });
  });

  describe("getCredential", () => {
    it("should parse tuple response into Credential object", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      patchClient(provider, {
        read: async () => [
          MOCK_PROVIDER_ADDR, // issuer
          MOCK_USER, // subject
          MOCK_CRED_ID, // credentialHash
          1000000n, // issuedAt
          2000000n, // expiresAt
          false, // revoked
        ],
      });

      const cred = await provider.getCredential(MOCK_CRED_ID);
      expect(cred.credentialId).to.equal(MOCK_CRED_ID);
      expect(cred.issuer).to.equal(MOCK_PROVIDER_ADDR);
      expect(cred.subject).to.equal(MOCK_USER);
      expect(cred.issuedAt).to.equal(1000000n);
      expect(cred.expiresAt).to.equal(2000000n);
      expect(cred.revoked).to.be.false;
    });
  });

  describe("getProviderInfo", () => {
    it("should parse tuple response into ProviderInfo", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      patchClient(provider, {
        read: async () => [
          "TestProvider", // name
          ("0x" + "ab".repeat(32)) as Hex, // schemaHash
          42n, // credentialsIssued
          true, // isActive
        ],
      });

      const info = await provider.getProviderInfo(MOCK_PROVIDER_ADDR);
      expect(info.name).to.equal("TestProvider");
      expect(info.credentialsIssued).to.equal(42n);
      expect(info.isActive).to.be.true;
    });
  });

  describe("getUserCredentialCount", () => {
    it("should return credential count", async () => {
      const provider = new ZaseonComplianceProvider(makeConfig());
      patchClient(provider, {
        read: async () => 5n,
      });

      const count = await provider.getUserCredentialCount(MOCK_USER);
      expect(count).to.equal(5n);
    });
  });
});
