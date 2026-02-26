/**
 * Mock SDK module for React hook testing.
 * Provides a minimal Soulv2ClientFactory stub that hooks can call.
 */

export interface Container {
  containerId: string;
  creator: string;
  status: string;
}

export interface ContainerCreationParams {
  proof: Uint8Array;
  publicInputs: string[];
}

export interface DisclosurePolicy {
  policyId: string;
  rules: string[];
}

export interface Domain {
  name: string;
  chainId: number;
}

export interface Soulv2Config {
  rpcUrl: string;
  chainId: number;
  contracts: Record<string, string>;
}

export class Soulv2ClientFactory {
  private config: Soulv2Config;
  private publicClient: any;
  private walletClient: any;

  constructor(config: Soulv2Config, publicClient: any, walletClient: any) {
    this.config = config;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  getPC3() {
    return {
      getContainer: jest.fn().mockResolvedValue({
        containerId: "0xabc",
        creator: "0x123",
        status: "active",
      } as Container),
      getContainerIds: jest.fn().mockResolvedValue(["0xabc", "0xdef"]),
      createContainer: jest.fn().mockResolvedValue({
        containerId: "0xnew",
        txHash: "0xtx1",
      }),
      consumeContainer: jest.fn().mockResolvedValue(undefined),
      on: jest.fn().mockReturnValue({ unsubscribe: jest.fn() }),
    };
  }

  getCDNA() {
    return {
      batchCheckNullifiers: jest.fn().mockResolvedValue([false]),
    };
  }

  getPBP() {
    return {
      verifyBoundProof: jest.fn().mockResolvedValue(true),
    };
  }

  getPublicClient() {
    return this.publicClient;
  }

  estimateGas(_method: string, _params: unknown[]) {
    return Promise.resolve(BigInt(50000));
  }
}
