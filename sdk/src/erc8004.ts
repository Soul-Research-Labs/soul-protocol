/**
 * @module ERC8004TrustlessAgents
 * @description SDK module for ERC-8004 Trustless Agents standard
 *
 * Provides TypeScript utilities for interacting with Identity, Reputation,
 * and Validation registries on-chain.
 */

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  encodePacked,
  keccak256,
  hashTypedData,
} from 'viem';

// ─────────── Constants ───────────

export const ERC8004_VERSION = '1';

export const AGENT_WALLET_TYPEHASH = keccak256(
  encodePacked(['string'], ['SetAgentWallet(uint256 agentId,address newWallet,uint256 deadline)'])
);

export const AGENT_WALLET_KEY = 'agentWallet';

/** Maximum value decimals allowed by the Reputation Registry */
export const MAX_FEEDBACK_DECIMALS = 18;

/** Validation response range */
export const VALIDATION_MIN_RESPONSE = 0;
export const VALIDATION_MAX_RESPONSE = 100;

// ─────────── Types ───────────

export interface MetadataEntry {
  metadataKey: string;
  metadataValue: Hex;
}

export interface AgentIdentity {
  agentId: bigint;
  agentURI: string;
  owner: Address;
  wallet: Address;
}

export interface FeedbackEntry {
  value: bigint;
  valueDecimals: number;
  tag1: string;
  tag2: string;
  isRevoked: boolean;
}

export interface FeedbackParams {
  agentId: bigint;
  value: bigint;
  valueDecimals: number;
  tag1?: string;
  tag2?: string;
  endpoint?: string;
  feedbackURI?: string;
  feedbackHash?: Hex;
}

export interface ValidationRequestParams {
  validatorAddress: Address;
  agentId: bigint;
  requestURI: string;
  requestHash: Hex;
}

export interface ValidationResponseParams {
  requestHash: Hex;
  response: number;
  responseURI?: string;
  responseHash?: Hex;
  tag?: string;
}

export interface ValidationStatus {
  validatorAddress: Address;
  agentId: bigint;
  response: number;
  responseHash: Hex;
  tag: string;
  lastUpdate: bigint;
}

export interface ReputationSummary {
  count: bigint;
  summaryValue: bigint;
  summaryValueDecimals: number;
}

export interface ValidationSummary {
  count: bigint;
  averageResponse: number;
}

// ─────────── Agent Global ID ───────────

/**
 * Construct the ERC-8004 agent global identifier
 * Format: eip155:{chainId}:{registryAddress}#{agentId}
 */
export function buildAgentGlobalId(
  chainId: number,
  registryAddress: Address,
  agentId: bigint
): string {
  return `eip155:${chainId}:${registryAddress}#${agentId}`;
}

/**
 * Parse an agent global identifier
 */
export function parseAgentGlobalId(globalId: string): {
  namespace: string;
  chainId: number;
  registryAddress: Address;
  agentId: bigint;
} {
  const match = globalId.match(/^(eip155):(\d+):(0x[0-9a-fA-F]{40})#(\d+)$/);
  if (!match) throw new Error(`Invalid agent global ID: ${globalId}`);
  return {
    namespace: match[1],
    chainId: parseInt(match[2]),
    registryAddress: match[3] as Address,
    agentId: BigInt(match[4]),
  };
}

// ─────────── EIP-712 Utilities ───────────

/**
 * Build the EIP-712 typed data for setAgentWallet
 */
export function buildSetAgentWalletTypedData(
  chainId: number,
  registryAddress: Address,
  agentId: bigint,
  newWallet: Address,
  deadline: bigint
) {
  return {
    domain: {
      name: 'ERC8004IdentityRegistry',
      version: ERC8004_VERSION,
      chainId,
      verifyingContract: registryAddress,
    },
    types: {
      SetAgentWallet: [
        { name: 'agentId', type: 'uint256' },
        { name: 'newWallet', type: 'address' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'SetAgentWallet' as const,
    message: {
      agentId,
      newWallet,
      deadline,
    },
  };
}

/**
 * Hash the EIP-712 typed data for setAgentWallet
 */
export function hashSetAgentWalletData(
  chainId: number,
  registryAddress: Address,
  agentId: bigint,
  newWallet: Address,
  deadline: bigint
): Hex {
  const typedData = buildSetAgentWalletTypedData(
    chainId,
    registryAddress,
    agentId,
    newWallet,
    deadline
  );
  return hashTypedData(typedData);
}

// ─────────── Validation Helpers ───────────

/**
 * Check if a validation response score is valid (0-100)
 */
export function isValidResponse(response: number): boolean {
  return Number.isInteger(response) && response >= VALIDATION_MIN_RESPONSE && response <= VALIDATION_MAX_RESPONSE;
}

/**
 * Check if feedback value decimals are valid (0-18)
 */
export function isValidFeedbackDecimals(decimals: number): boolean {
  return Number.isInteger(decimals) && decimals >= 0 && decimals <= MAX_FEEDBACK_DECIMALS;
}

/**
 * Format a feedback value with its decimals into a human-readable string
 */
export function formatFeedbackValue(value: bigint, decimals: number): string {
  const isNegative = value < 0n;
  const absValue = isNegative ? -value : value;
  const str = absValue.toString().padStart(decimals + 1, '0');
  const intPart = str.slice(0, str.length - decimals) || '0';
  const fracPart = decimals > 0 ? '.' + str.slice(str.length - decimals) : '';
  return (isNegative ? '-' : '') + intPart + fracPart;
}

/**
 * Parse a decimal string into value + decimals for feedback
 */
export function parseFeedbackValue(input: string): { value: bigint; decimals: number } {
  const parts = input.split('.');
  const intPart = parts[0];
  const fracPart = parts[1] || '';
  const decimals = fracPart.length;

  if (decimals > MAX_FEEDBACK_DECIMALS) {
    throw new Error(`Exceeded max decimals: ${decimals} > ${MAX_FEEDBACK_DECIMALS}`);
  }

  const combined = intPart + fracPart;
  return { value: BigInt(combined), decimals };
}

// ─────────── SDK Class ───────────

/**
 * ERC-8004 Trustless Agents SDK
 * High-level wrapper for Identity, Reputation, and Validation registries
 */
export class ERC8004SDK {
  constructor(
    public readonly identityRegistryAddress: Address,
    public readonly reputationRegistryAddress: Address,
    public readonly validationRegistryAddress: Address,
    public readonly chainId: number
  ) {}

  /**
   * Build an agent global ID for this registry
   */
  agentGlobalId(agentId: bigint): string {
    return buildAgentGlobalId(this.chainId, this.identityRegistryAddress, agentId);
  }

  /**
   * Build EIP-712 typed data for setAgentWallet
   */
  buildWalletSignatureData(agentId: bigint, newWallet: Address, deadline: bigint) {
    return buildSetAgentWalletTypedData(
      this.chainId,
      this.identityRegistryAddress,
      agentId,
      newWallet,
      deadline
    );
  }

  /**
   * Validate feedback parameters before submission
   */
  validateFeedbackParams(params: FeedbackParams): void {
    if (!isValidFeedbackDecimals(params.valueDecimals)) {
      throw new Error(`Invalid decimals: ${params.valueDecimals}. Must be 0-${MAX_FEEDBACK_DECIMALS}.`);
    }
  }

  /**
   * Validate a response score
   */
  validateResponse(response: number): void {
    if (!isValidResponse(response)) {
      throw new Error(`Invalid response: ${response}. Must be ${VALIDATION_MIN_RESPONSE}-${VALIDATION_MAX_RESPONSE}.`);
    }
  }
}
