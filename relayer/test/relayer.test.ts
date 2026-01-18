import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  RelayerService,
  RelayerConfig,
  Packet,
  DecoyTrafficEngine,
  TimingObfuscator,
  ReputationSystem,
} from "../src/network/RelayerService";
import { StakingManager, StakingConfig } from "../src/staking/StakingManager";
import { BridgeMessageHandler, BridgeMessage } from "../src/bridge/BridgeMessageHandler";

describe("RelayerService", () => {
  let service: RelayerService;
  const defaultConfig: RelayerConfig = {
    stake: 1000,
    endpoints: ["http://localhost:8545", "http://localhost:8546"],
    chains: ["ethereum", "polygon"],
    decoyTrafficRatio: 0.2,
    minDelay: 100,
    maxDelay: 1000,
  };

  beforeEach(() => {
    service = new RelayerService(defaultConfig);
  });

  describe("initialization", () => {
    it("should initialize with config", () => {
      expect(service.config).toEqual(defaultConfig);
    });

    it("should accept custom config", () => {
      const customConfig: RelayerConfig = {
        ...defaultConfig,
        stake: 5000,
        decoyTrafficRatio: 0.5,
      };
      const customService = new RelayerService(customConfig);
      expect(customService.config.stake).toBe(5000);
      expect(customService.config.decoyTrafficRatio).toBe(0.5);
    });
  });

  describe("packet handling", () => {
    it("should queue packets for relay", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("test-state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: { valid: true },
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      await service.queuePacket(packet);
      const pending = service.getPendingPackets();
      expect(pending.length).toBe(1);
      expect(pending[0].sourceChain).toBe("ethereum");
    });

    it("should validate packet before queuing", async () => {
      const invalidPacket: Packet = {
        encryptedState: Buffer.from(""),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: null,
        sourceChain: "",
        destChain: "",
        timestamp: 0,
      };

      await expect(service.queuePacket(invalidPacket)).rejects.toThrow();
    });
  });
});

describe("DecoyTrafficEngine", () => {
  it("should generate correct number of decoys based on ratio", () => {
    const engine = new DecoyTrafficEngine(0.2);
    const decoys = engine.generateDecoyPackets(10);
    expect(decoys.length).toBe(2);
  });

  it("should generate decoys with decoy marker", () => {
    const engine = new DecoyTrafficEngine(0.5);
    const decoys = engine.generateDecoyPackets(4);
    expect(decoys.length).toBe(2);
    expect(decoys[0].sourceChain).toBe("decoy");
    expect(decoys[0].destChain).toBe("decoy");
  });

  it("should handle zero ratio", () => {
    const engine = new DecoyTrafficEngine(0);
    const decoys = engine.generateDecoyPackets(100);
    expect(decoys.length).toBe(0);
  });

  it("should handle 100% ratio", () => {
    const engine = new DecoyTrafficEngine(1.0);
    const decoys = engine.generateDecoyPackets(5);
    expect(decoys.length).toBe(5);
  });
});

describe("TimingObfuscator", () => {
  it("should generate delay within range", () => {
    const obfuscator = new TimingObfuscator(100, 1000);
    
    for (let i = 0; i < 100; i++) {
      const delay = obfuscator.getDelay();
      expect(delay).toBeGreaterThanOrEqual(100);
      // Max could be exceeded slightly due to exponential distribution
      expect(delay).toBeLessThan(5000);
    }
  });

  it("should have variability in delays", () => {
    const obfuscator = new TimingObfuscator(100, 1000);
    const delays = Array.from({ length: 50 }, () => obfuscator.getDelay());
    const unique = new Set(delays);
    
    // Should have some variability
    expect(unique.size).toBeGreaterThan(10);
  });
});

describe("ReputationSystem", () => {
  let reputation: ReputationSystem;

  beforeEach(() => {
    reputation = new ReputationSystem();
  });

  it("should start with no reputations", () => {
    expect(reputation.getAllReputations()).toHaveLength(0);
  });

  it("should track successful relays", () => {
    reputation.update("node-1", true);
    reputation.update("node-1", true);
    reputation.update("node-1", true);
    
    const rep = reputation.getReputation("node-1");
    expect(rep).toBeDefined();
    expect(rep!.successCount).toBe(3);
    expect(rep!.score).toBeGreaterThan(100);
  });

  it("should penalize failed relays", () => {
    reputation.update("node-1", true);
    reputation.update("node-1", false);
    
    const rep = reputation.getReputation("node-1");
    expect(rep!.failCount).toBe(1);
    expect(rep!.score).toBeLessThan(100);
  });

  it("should not exceed score bounds", () => {
    // Max out score
    for (let i = 0; i < 200; i++) {
      reputation.update("node-1", true);
    }
    expect(reputation.getReputation("node-1")!.score).toBeLessThanOrEqual(100);

    // Bottom out score
    for (let i = 0; i < 200; i++) {
      reputation.update("node-2", false);
    }
    expect(reputation.getReputation("node-2")!.score).toBeGreaterThanOrEqual(0);
  });
});

describe("StakingManager", () => {
  let staking: StakingManager;
  const defaultStakingConfig: StakingConfig = {
    minStake: 100,
    slashingRate: 0.1,
    rewardRate: 0.01,
  };

  beforeEach(() => {
    staking = new StakingManager(defaultStakingConfig);
  });

  describe("staking", () => {
    it("should accept valid stake", async () => {
      const result = await staking.stake("relayer-1", 500);
      expect(result).toBe(true);
      
      const stake = staking.getStake("relayer-1");
      expect(stake).toBeDefined();
      expect(stake!.amount).toBe(500);
    });

    it("should reject stake below minimum", async () => {
      await expect(staking.stake("relayer-1", 50)).rejects.toThrow("Minimum stake is 100");
    });

    it("should accumulate stake", async () => {
      await staking.stake("relayer-1", 200);
      await staking.stake("relayer-1", 300);
      
      const stake = staking.getStake("relayer-1");
      expect(stake!.amount).toBe(500);
    });

    it("should set lock period", async () => {
      await staking.stake("relayer-1", 200);
      const stake = staking.getStake("relayer-1");
      expect(stake!.lockedUntil).toBeGreaterThan(Date.now());
    });
  });

  describe("slashing", () => {
    it("should slash percentage of stake", async () => {
      await staking.stake("relayer-1", 1000);
      const slashed = await staking.slash("relayer-1", "malicious behavior");
      
      expect(slashed).toBe(100); // 10% of 1000
      
      const stake = staking.getStake("relayer-1");
      expect(stake!.amount).toBe(900);
    });

    it("should return 0 for non-existent relayer", async () => {
      const slashed = await staking.slash("unknown", "test");
      expect(slashed).toBe(0);
    });
  });

  describe("rewards", () => {
    it("should reward based on success count", async () => {
      await staking.stake("relayer-1", 1000);
      const reward = await staking.reward("relayer-1", 100);
      
      expect(reward).toBe(1); // 100 * 0.01
      
      const stake = staking.getStake("relayer-1");
      expect(stake!.amount).toBe(1001);
    });

    it("should return 0 for non-existent relayer", async () => {
      const reward = await staking.reward("unknown", 100);
      expect(reward).toBe(0);
    });
  });
});

describe("BridgeMessageHandler", () => {
  let handler: BridgeMessageHandler;

  beforeEach(() => {
    handler = new BridgeMessageHandler();
  });

  describe("message creation", () => {
    it("should create message from packet", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: {},
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      const message = await handler.createMessage(packet);
      
      expect(message.id).toBeDefined();
      expect(message.sourceChain).toBe("ethereum");
      expect(message.destChain).toBe("polygon");
      expect(message.status).toBe("pending");
    });

    it("should generate unique IDs", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: {},
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      const msg1 = await handler.createMessage(packet);
      const msg2 = await handler.createMessage(packet);
      
      expect(msg1.id).not.toBe(msg2.id);
    });
  });

  describe("status updates", () => {
    it("should mark message as relayed", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: {},
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      const message = await handler.createMessage(packet);
      await handler.markRelayed(message.id);
      
      const updated = handler.getMessage(message.id);
      expect(updated!.status).toBe("relayed");
      expect(updated!.relayedAt).toBeDefined();
    });

    it("should mark message as failed", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: {},
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      const message = await handler.createMessage(packet);
      await handler.markFailed(message.id);
      
      const updated = handler.getMessage(message.id);
      expect(updated!.status).toBe("failed");
    });
  });

  describe("message queries", () => {
    it("should return pending messages", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: {},
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      const msg1 = await handler.createMessage(packet);
      const msg2 = await handler.createMessage(packet);
      await handler.markRelayed(msg1.id);
      
      const pending = handler.getPendingMessages();
      expect(pending.length).toBe(1);
      expect(pending[0].id).toBe(msg2.id);
    });

    it("should get message by ID", async () => {
      const packet: Packet = {
        encryptedState: Buffer.from("state"),
        ephemeralKey: Buffer.alloc(32),
        mac: Buffer.alloc(16),
        proof: {},
        sourceChain: "ethereum",
        destChain: "polygon",
        timestamp: Date.now(),
      };

      const created = await handler.createMessage(packet);
      const retrieved = handler.getMessage(created.id);
      
      expect(retrieved).toEqual(created);
    });

    it("should return undefined for unknown ID", () => {
      const retrieved = handler.getMessage("unknown-id");
      expect(retrieved).toBeUndefined();
    });
  });
});

describe("Integration Tests", () => {
  it("should handle full relay flow", async () => {
    const config: RelayerConfig = {
      stake: 1000,
      endpoints: ["http://localhost:8545"],
      chains: ["ethereum", "polygon"],
      decoyTrafficRatio: 0.2,
      minDelay: 10,
      maxDelay: 50,
    };

    const service = new RelayerService(config);
    const handler = new BridgeMessageHandler();
    const staking = new StakingManager({ minStake: 100, slashingRate: 0.1, rewardRate: 0.01 });

    // Stake as relayer
    await staking.stake("relayer-1", 500);

    // Create packet
    const packet: Packet = {
      encryptedState: Buffer.from("private-state"),
      ephemeralKey: Buffer.alloc(32),
      mac: Buffer.alloc(16),
      proof: { valid: true },
      sourceChain: "ethereum",
      destChain: "polygon",
      timestamp: Date.now(),
    };

    // Create message
    const message = await handler.createMessage(packet);
    expect(message.status).toBe("pending");

    // Simulate relay success
    await handler.markRelayed(message.id);
    await staking.reward("relayer-1", 1);

    // Verify final state
    const finalMessage = handler.getMessage(message.id);
    expect(finalMessage!.status).toBe("relayed");

    const stake = staking.getStake("relayer-1");
    expect(stake!.amount).toBeGreaterThan(500);
  });

  it("should handle relay failure with slashing", async () => {
    const staking = new StakingManager({ minStake: 100, slashingRate: 0.1, rewardRate: 0.01 });
    const reputation = new ReputationSystem();
    const handler = new BridgeMessageHandler();

    // Stake as relayer
    await staking.stake("relayer-1", 1000);

    // Create message
    const packet: Packet = {
      encryptedState: Buffer.from("state"),
      ephemeralKey: Buffer.alloc(32),
      mac: Buffer.alloc(16),
      proof: {},
      sourceChain: "ethereum",
      destChain: "polygon",
      timestamp: Date.now(),
    };
    const message = await handler.createMessage(packet);

    // Simulate failure
    await handler.markFailed(message.id);
    reputation.update("relayer-1", false);
    await staking.slash("relayer-1", "failed to relay");

    // Verify penalties applied
    const stake = staking.getStake("relayer-1");
    expect(stake!.amount).toBe(900);

    const rep = reputation.getReputation("relayer-1");
    expect(rep!.score).toBeLessThan(100);
    expect(rep!.failCount).toBe(1);
  });
});
