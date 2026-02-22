/**
 * @title EnhancedKillSwitchClient
 * @description TypeScript SDK client for the EnhancedKillSwitch contract.
 * Provides multi-level emergency management with escalation, recovery, and guardian flows.
 */

import {
  type PublicClient,
  type WalletClient,
  type Hex,
  type Address,
  getContract,
} from "viem";

// ────────────────────────────────────────────────────────
//  ABI (minimal, typed)
// ────────────────────────────────────────────────────────

const ENHANCED_KILL_SWITCH_ABI = [
  // ─── Write ───
  {
    name: "escalateEmergency",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_newLevel", type: "uint8" }],
    outputs: [],
  },
  {
    name: "confirmEscalation",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "executeEscalation",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "cancelEscalation",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "initiateRecovery",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_targetLevel", type: "uint8" }],
    outputs: [],
  },
  {
    name: "confirmRecovery",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "executeRecovery",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "cancelRecovery",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "addGuardian",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_guardian", type: "address" }],
    outputs: [],
  },
  {
    name: "removeGuardian",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_guardian", type: "address" }],
    outputs: [],
  },
  {
    name: "setProtectedContract",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_contract", type: "address" },
      { name: "_protected", type: "bool" },
    ],
    outputs: [],
  },
  {
    name: "setContractOverride",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_contract", type: "address" },
      { name: "_level", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "setActionRestriction",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_level", type: "uint8" },
      { name: "_action", type: "uint8" },
      { name: "_allowed", type: "bool" },
    ],
    outputs: [],
  },
  // ─── Read ───
  {
    name: "isActionAllowed",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "_action", type: "uint8" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getProtocolState",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "currentLevel", type: "uint8" },
          { name: "previousLevel", type: "uint8" },
          { name: "levelSetAt", type: "uint256" },
          { name: "guardianCount", type: "uint256" },
          { name: "incidentCount", type: "uint256" },
          { name: "hasPendingEscalation", type: "bool" },
          { name: "hasPendingRecovery", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "getIncidents",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "tuple[]",
        components: [
          { name: "level", type: "uint8" },
          { name: "previousLevel", type: "uint8" },
          { name: "initiator", type: "address" },
          { name: "timestamp", type: "uint256" },
          { name: "resolved", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "getGuardians",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address[]" }],
  },
  {
    name: "currentLevel",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "previousLevel",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "levelSetAt",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ─── Events ───
  {
    name: "EmergencyLevelChanged",
    type: "event",
    inputs: [
      { name: "previousLevel", type: "uint8", indexed: false },
      { name: "newLevel", type: "uint8", indexed: false },
      { name: "initiator", type: "address", indexed: true },
    ],
  },
  {
    name: "EscalationInitiated",
    type: "event",
    inputs: [
      { name: "newLevel", type: "uint8", indexed: false },
      { name: "initiator", type: "address", indexed: true },
    ],
  },
  {
    name: "EscalationConfirmed",
    type: "event",
    inputs: [
      { name: "confirmer", type: "address", indexed: true },
      { name: "confirmations", type: "uint256", indexed: false },
    ],
  },
  {
    name: "EscalationExecuted",
    type: "event",
    inputs: [
      { name: "executor", type: "address", indexed: true },
      { name: "level", type: "uint8", indexed: false },
    ],
  },
  {
    name: "EscalationCancelled",
    type: "event",
    inputs: [{ name: "canceller", type: "address", indexed: true }],
  },
  {
    name: "RecoveryInitiated",
    type: "event",
    inputs: [
      { name: "targetLevel", type: "uint8", indexed: false },
      { name: "initiator", type: "address", indexed: true },
    ],
  },
  {
    name: "RecoveryExecuted",
    type: "event",
    inputs: [
      { name: "executor", type: "address", indexed: true },
      { name: "targetLevel", type: "uint8", indexed: false },
    ],
  },
  {
    name: "RecoveryCancelled",
    type: "event",
    inputs: [{ name: "canceller", type: "address", indexed: true }],
  },
  {
    name: "GuardianAdded",
    type: "event",
    inputs: [{ name: "guardian", type: "address", indexed: true }],
  },
  {
    name: "GuardianRemoved",
    type: "event",
    inputs: [{ name: "guardian", type: "address", indexed: true }],
  },
  {
    name: "ActionRestrictionUpdated",
    type: "event",
    inputs: [
      { name: "level", type: "uint8", indexed: false },
      { name: "action", type: "uint8", indexed: false },
      { name: "allowed", type: "bool", indexed: false },
    ],
  },
] as const;

// ────────────────────────────────────────────────────────
//  Enums & Types
// ────────────────────────────────────────────────────────

/** Maps to the on-chain EmergencyLevel enum */
export enum EmergencyLevel {
  NONE = 0,
  WARNING = 1,
  DEGRADED = 2,
  HALTED = 3,
  LOCKED = 4,
  PERMANENT = 5,
}

/** Maps to the on-chain ActionType enum */
export enum ActionType {
  DEPOSIT = 0,
  WITHDRAWAL = 1,
  BRIDGE = 2,
  GOVERNANCE = 3,
  UPGRADE = 4,
  EMERGENCY_WITHDRAWAL = 5,
}

/** Protocol state snapshot */
export interface ProtocolState {
  currentLevel: EmergencyLevel;
  previousLevel: EmergencyLevel;
  levelSetAt: bigint;
  guardianCount: bigint;
  incidentCount: bigint;
  hasPendingEscalation: boolean;
  hasPendingRecovery: boolean;
}

/** Historical emergency incident */
export interface EmergencyIncident {
  level: EmergencyLevel;
  previousLevel: EmergencyLevel;
  initiator: Address;
  timestamp: bigint;
  resolved: boolean;
}

/** Write operation result */
export interface TxResult {
  hash: Hex;
}

// ────────────────────────────────────────────────────────
//  Client
// ────────────────────────────────────────────────────────

export class EnhancedKillSwitchClient {
  private publicClient: PublicClient;
  private walletClient?: WalletClient;
  private contract: ReturnType<typeof getContract>;
  public readonly address: Address;

  constructor(
    address: Address,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.address = address;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address,
      abi: ENHANCED_KILL_SWITCH_ABI,
      client: { public: publicClient, wallet: walletClient },
    });
  }

  // ─────────── Escalation ───────────

  /**
   * Initiate an emergency escalation to a higher level (Guardian only)
   */
  async escalateEmergency(newLevel: EmergencyLevel): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.escalateEmergency([
      newLevel,
    ]);
    return { hash };
  }

  /**
   * Confirm a pending escalation (Guardian only)
   */
  async confirmEscalation(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.confirmEscalation();
    return { hash };
  }

  /**
   * Execute a confirmed escalation after cooldown (Guardian only)
   */
  async executeEscalation(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.executeEscalation();
    return { hash };
  }

  /**
   * Cancel a pending escalation (Admin only)
   */
  async cancelEscalation(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.cancelEscalation();
    return { hash };
  }

  // ─────────── Recovery ───────────

  /**
   * Initiate recovery to a lower emergency level (RECOVERY_ROLE)
   */
  async initiateRecovery(targetLevel: EmergencyLevel): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.initiateRecovery([
      targetLevel,
    ]);
    return { hash };
  }

  /**
   * Confirm a pending recovery (Guardian only)
   */
  async confirmRecovery(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.confirmRecovery();
    return { hash };
  }

  /**
   * Execute a confirmed recovery (RECOVERY_ROLE)
   */
  async executeRecovery(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.executeRecovery();
    return { hash };
  }

  /**
   * Cancel a pending recovery (Admin only)
   */
  async cancelRecovery(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.cancelRecovery();
    return { hash };
  }

  // ─────────── Guardian Management ───────────

  /**
   * Add a guardian (Admin only)
   */
  async addGuardian(guardian: Address): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.addGuardian([guardian]);
    return { hash };
  }

  /**
   * Remove a guardian (Admin only)
   */
  async removeGuardian(guardian: Address): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.removeGuardian([guardian]);
    return { hash };
  }

  // ─────────── Contract Protection & Action Restrictions ───────────

  /**
   * Set a contract as protected/unprotected (Admin only)
   */
  async setProtectedContract(
    contractAddr: Address,
    isProtected: boolean,
  ): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.setProtectedContract([
      contractAddr,
      isProtected,
    ]);
    return { hash };
  }

  /**
   * Set a per-contract emergency level override (Admin only)
   */
  async setContractOverride(
    contractAddr: Address,
    level: EmergencyLevel,
  ): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.setContractOverride([
      contractAddr,
      level,
    ]);
    return { hash };
  }

  /**
   * Set whether an action is allowed at a specific emergency level (Admin only)
   */
  async setActionRestriction(
    level: EmergencyLevel,
    action: ActionType,
    allowed: boolean,
  ): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.setActionRestriction([
      level,
      action,
      allowed,
    ]);
    return { hash };
  }

  // ─────────── Read Operations ───────────

  /**
   * Check if a specific action is currently allowed at the current emergency level
   */
  async isActionAllowed(action: ActionType): Promise<boolean> {
    return (await (this.contract as any).read.isActionAllowed([
      action,
    ])) as boolean;
  }

  /**
   * Get the full protocol state
   */
  async getProtocolState(): Promise<ProtocolState> {
    const raw = await (this.contract as any).read.getProtocolState();
    return {
      currentLevel: Number(raw.currentLevel) as EmergencyLevel,
      previousLevel: Number(raw.previousLevel) as EmergencyLevel,
      levelSetAt: raw.levelSetAt as bigint,
      guardianCount: raw.guardianCount as bigint,
      incidentCount: raw.incidentCount as bigint,
      hasPendingEscalation: raw.hasPendingEscalation as boolean,
      hasPendingRecovery: raw.hasPendingRecovery as boolean,
    };
  }

  /**
   * Get the current emergency level
   */
  async getCurrentLevel(): Promise<EmergencyLevel> {
    const level = await (this.contract as any).read.currentLevel();
    return Number(level) as EmergencyLevel;
  }

  /**
   * Get the previous emergency level
   */
  async getPreviousLevel(): Promise<EmergencyLevel> {
    const level = await (this.contract as any).read.previousLevel();
    return Number(level) as EmergencyLevel;
  }

  /**
   * Get the timestamp when the current level was set
   */
  async getLevelSetAt(): Promise<bigint> {
    return (await (this.contract as any).read.levelSetAt()) as bigint;
  }

  /**
   * Get all historical incidents
   */
  async getIncidents(): Promise<EmergencyIncident[]> {
    const raw = await (this.contract as any).read.getIncidents();
    return (raw as any[]).map((i: any) => ({
      level: Number(i.level) as EmergencyLevel,
      previousLevel: Number(i.previousLevel) as EmergencyLevel,
      initiator: i.initiator as Address,
      timestamp: i.timestamp as bigint,
      resolved: i.resolved as boolean,
    }));
  }

  /**
   * Get all guardian addresses
   */
  async getGuardians(): Promise<Address[]> {
    return (await (this.contract as any).read.getGuardians()) as Address[];
  }

  // ─────────── Event Watchers ───────────

  /**
   * Watch for EmergencyLevelChanged events
   */
  watchLevelChanges(
    callback: (
      previousLevel: EmergencyLevel,
      newLevel: EmergencyLevel,
      initiator: Address,
    ) => void,
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: ENHANCED_KILL_SWITCH_ABI,
      eventName: "EmergencyLevelChanged",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(
            Number(args.previousLevel) as EmergencyLevel,
            Number(args.newLevel) as EmergencyLevel,
            args.initiator as Address,
          );
        }
      },
    });
  }

  /**
   * Watch for escalation-related events
   */
  watchEscalationEvents(
    callback: (event: string, initiator: Address, data: any) => void,
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: ENHANCED_KILL_SWITCH_ABI,
      eventName: "EscalationExecuted",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback("EscalationExecuted", args.executor as Address, {
            level: Number(args.level) as EmergencyLevel,
          });
        }
      },
    });
  }

  /**
   * Watch for recovery-related events
   */
  watchRecoveryEvents(
    callback: (event: string, initiator: Address, data: any) => void,
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: ENHANCED_KILL_SWITCH_ABI,
      eventName: "RecoveryExecuted",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback("RecoveryExecuted", args.executor as Address, {
            targetLevel: Number(args.targetLevel) as EmergencyLevel,
          });
        }
      },
    });
  }

  // ─────────── Internal ───────────

  private requireWallet(): void {
    if (!this.walletClient) {
      throw new Error("Wallet client required for write operations");
    }
  }
}
