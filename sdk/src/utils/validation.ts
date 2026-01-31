/**
 * Soul SDK Input Validation
 * 
 * Comprehensive input validation with type-safe validators,
 * sanitization, and detailed error messages.
 */

import { isAddress, getAddress } from "viem";
import {
  ValidationError,
  SoulErrorCode,
} from "./errors";

/**
 * Validation result type
 */
export interface ValidationResult<T = unknown> {
  valid: boolean;
  value?: T;
  error?: string;
}

/**
 * Validator function type
 */
export type Validator<T> = (value: unknown) => ValidationResult<T>;

/**
 * Validate Ethereum address
 */
export function validateAddress(value: unknown): ValidationResult<string> {
  if (typeof value !== "string") {
    return { valid: false, error: "Address must be a string" };
  }

  if (!value || value.trim() === "") {
    return { valid: false, error: "Address cannot be empty" };
  }

  // Check for valid Ethereum address format
  if (!isAddress(value)) {
    return { valid: false, error: `Invalid Ethereum address: ${value}` };
  }

  // Return checksummed address
  return { valid: true, value: getAddress(value) };
}

/**
 * Validate bytes32 value
 */
export function validateBytes32(value: unknown): ValidationResult<string> {
  if (typeof value !== "string") {
    return { valid: false, error: "Bytes32 must be a string" };
  }

  // Allow without 0x prefix
  const normalized = value.startsWith("0x") ? value : `0x${value}`;

  // Check length (66 chars including 0x)
  if (normalized.length !== 66) {
    return {
      valid: false,
      error: `Invalid bytes32 length: expected 66 characters, got ${normalized.length}`,
    };
  }

  // Check hex format
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return { valid: false, error: "Invalid bytes32 format: must be hex string" };
  }

  return { valid: true, value: normalized.toLowerCase() };
}

/**
 * Validate bytes value (variable length)
 */
export function validateBytes(value: unknown): ValidationResult<string> {
  if (typeof value !== "string") {
    return { valid: false, error: "Bytes must be a string" };
  }

  const normalized = value.startsWith("0x") ? value : `0x${value}`;

  // Check even length (each byte is 2 hex chars)
  if ((normalized.length - 2) % 2 !== 0) {
    return { valid: false, error: "Invalid bytes: must have even number of hex characters" };
  }

  // Check hex format
  if (!/^0x[0-9a-fA-F]*$/.test(normalized)) {
    return { valid: false, error: "Invalid bytes format: must be hex string" };
  }

  return { valid: true, value: normalized.toLowerCase() };
}

/**
 * Validate uint256 value
 */
export function validateUint256(value: unknown): ValidationResult<bigint> {
  if (value === null || value === undefined) {
    return { valid: false, error: "Value cannot be null or undefined" };
  }

  try {
    let bigIntValue: bigint;

    if (typeof value === "bigint") {
      bigIntValue = value;
    } else if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 0) {
        return { valid: false, error: "Number must be a non-negative integer" };
      }
      bigIntValue = BigInt(value);
    } else if (typeof value === "string") {
      bigIntValue = BigInt(value);
    } else {
      return { valid: false, error: "Value must be a number, string, or bigint" };
    }

    // Check range
    if (bigIntValue < 0n) {
      return { valid: false, error: "Value must be non-negative" };
    }

    const MAX_UINT256 = 2n ** 256n - 1n;
    if (bigIntValue > MAX_UINT256) {
      return { valid: false, error: "Value exceeds uint256 max" };
    }

    return { valid: true, value: bigIntValue };
  } catch {
    return { valid: false, error: "Invalid numeric value" };
  }
}

/**
 * Validate timestamp (unix timestamp in seconds)
 */
export function validateTimestamp(value: unknown): ValidationResult<number> {
  const result = validateUint256(value);
  if (!result.valid) {
    return { valid: false, error: result.error };
  }

  const timestamp = Number(result.value);
  
  // Reasonable timestamp range (1970 to 2200)
  if (timestamp > 7258118400) {
    return { valid: false, error: "Timestamp too far in future" };
  }

  return { valid: true, value: timestamp };
}

/**
 * Validate chain ID
 */
export function validateChainId(value: unknown): ValidationResult<number> {
  const result = validateUint256(value);
  if (!result.valid) {
    return { valid: false, error: result.error };
  }

  const chainId = Number(result.value);

  // Known chain ID validation
  const knownChains = [
    1, // Ethereum Mainnet
    10, // Optimism
    137, // Polygon
    42161, // Arbitrum One
    8453, // Base
    11155111, // Sepolia
    421614, // Arbitrum Sepolia
    11155420, // OP Sepolia
    84532, // Base Sepolia
    80002, // Polygon Amoy
    31337, // Localhost
  ];

  if (!knownChains.includes(chainId)) {
    // Warning but still valid
    console.warn(`Unknown chain ID: ${chainId}`);
  }

  return { valid: true, value: chainId };
}

/**
 * Validate proof structure
 */
export interface ProofData {
  proof: string;
  publicInputs: string[];
  verificationKey?: string;
}

export function validateProof(value: unknown): ValidationResult<ProofData> {
  if (!value || typeof value !== "object") {
    return { valid: false, error: "Proof must be an object" };
  }

  const obj = value as Record<string, unknown>;

  // Validate proof bytes
  if (!obj.proof) {
    return { valid: false, error: "Proof is required" };
  }
  const proofResult = validateBytes(obj.proof);
  if (!proofResult.valid) {
    return { valid: false, error: `Invalid proof: ${proofResult.error}` };
  }

  // Validate public inputs
  if (!Array.isArray(obj.publicInputs)) {
    return { valid: false, error: "publicInputs must be an array" };
  }

  const validatedInputs: string[] = [];
  for (let i = 0; i < obj.publicInputs.length; i++) {
    const inputResult = validateBytes32(obj.publicInputs[i]);
    if (!inputResult.valid) {
      return {
        valid: false,
        error: `Invalid public input at index ${i}: ${inputResult.error}`,
      };
    }
    validatedInputs.push(inputResult.value!);
  }

  // Validate optional verification key
  let vk: string | undefined;
  if (obj.verificationKey !== undefined) {
    const vkResult = validateBytes(obj.verificationKey);
    if (!vkResult.valid) {
      return { valid: false, error: `Invalid verification key: ${vkResult.error}` };
    }
    vk = vkResult.value;
  }

  return {
    valid: true,
    value: {
      proof: proofResult.value!,
      publicInputs: validatedInputs,
      verificationKey: vk,
    },
  };
}

/**
 * Validate policy configuration
 */
export interface PolicyConfig {
  name: string;
  description?: string;
  expiresAt: number;
  requiresIdentity?: boolean;
  requiresJurisdiction?: boolean;
  requiresAmount?: boolean;
  minAmount?: bigint;
  maxAmount?: bigint;
  allowedAssets?: string[];
  blockedCountries?: string[];
}

export function validatePolicyConfig(value: unknown): ValidationResult<PolicyConfig> {
  if (!value || typeof value !== "object") {
    return { valid: false, error: "Policy config must be an object" };
  }

  const obj = value as Record<string, unknown>;

  // Validate name
  if (typeof obj.name !== "string" || obj.name.trim() === "") {
    return { valid: false, error: "Policy name is required and must be non-empty" };
  }

  if (obj.name.length > 100) {
    return { valid: false, error: "Policy name must be 100 characters or less" };
  }

  // Validate expiry
  const expiryResult = validateTimestamp(obj.expiresAt);
  if (!expiryResult.valid) {
    return { valid: false, error: `Invalid expiresAt: ${expiryResult.error}` };
  }

  if (expiryResult.value! <= Math.floor(Date.now() / 1000)) {
    return { valid: false, error: "expiresAt must be in the future" };
  }

  // Validate optional amount constraints
  let minAmount: bigint | undefined;
  let maxAmount: bigint | undefined;

  if (obj.minAmount !== undefined) {
    const minResult = validateUint256(obj.minAmount);
    if (!minResult.valid) {
      return { valid: false, error: `Invalid minAmount: ${minResult.error}` };
    }
    minAmount = minResult.value;
  }

  if (obj.maxAmount !== undefined) {
    const maxResult = validateUint256(obj.maxAmount);
    if (!maxResult.valid) {
      return { valid: false, error: `Invalid maxAmount: ${maxResult.error}` };
    }
    maxAmount = maxResult.value;
  }

  if (minAmount !== undefined && maxAmount !== undefined && minAmount > maxAmount) {
    return { valid: false, error: "minAmount cannot exceed maxAmount" };
  }

  // Validate allowed assets
  const allowedAssets: string[] = [];
  if (obj.allowedAssets !== undefined) {
    if (!Array.isArray(obj.allowedAssets)) {
      return { valid: false, error: "allowedAssets must be an array" };
    }
    for (const asset of obj.allowedAssets) {
      const assetResult = validateBytes32(asset);
      if (!assetResult.valid) {
        return { valid: false, error: `Invalid asset: ${assetResult.error}` };
      }
      allowedAssets.push(assetResult.value!);
    }
  }

  // Validate blocked countries (ISO 3166-1 alpha-2)
  const blockedCountries: string[] = [];
  if (obj.blockedCountries !== undefined) {
    if (!Array.isArray(obj.blockedCountries)) {
      return { valid: false, error: "blockedCountries must be an array" };
    }
    for (const country of obj.blockedCountries) {
      if (typeof country !== "string" || !/^[A-Z]{2}$/.test(country)) {
        return {
          valid: false,
          error: `Invalid country code: ${country} (expected ISO 3166-1 alpha-2)`,
        };
      }
      blockedCountries.push(country);
    }
  }

  return {
    valid: true,
    value: {
      name: obj.name.trim(),
      description: typeof obj.description === "string" ? obj.description : undefined,
      expiresAt: expiryResult.value!,
      requiresIdentity: obj.requiresIdentity === true,
      requiresJurisdiction: obj.requiresJurisdiction === true,
      requiresAmount: obj.requiresAmount === true,
      minAmount,
      maxAmount,
      allowedAssets: allowedAssets.length > 0 ? allowedAssets : undefined,
      blockedCountries: blockedCountries.length > 0 ? blockedCountries : undefined,
    },
  };
}

/**
 * Validation helper - throws on invalid
 */
export function validate<T>(
  value: unknown,
  validator: Validator<T>,
  fieldName: string
): T {
  const result = validator(value);
  if (!result.valid) {
    throw new ValidationError(
      `Validation failed for ${fieldName}: ${result.error}`,
      SoulErrorCode.INVALID_INPUT,
      { field: fieldName, value, error: result.error }
    );
  }
  return result.value!;
}

/**
 * Batch validation
 */
export function validateAll(
  validations: Array<{ value: unknown; validator: Validator<unknown>; field: string }>
): Record<string, unknown> {
  const errors: string[] = [];
  const values: Record<string, unknown> = {};

  for (const { value, validator, field } of validations) {
    const result = validator(value);
    if (!result.valid) {
      errors.push(`${field}: ${result.error}`);
    } else {
      values[field] = result.value;
    }
  }

  if (errors.length > 0) {
    throw new ValidationError(
      `Validation failed:\n${errors.join("\n")}`,
      SoulErrorCode.SCHEMA_VALIDATION_FAILED,
      { errors }
    );
  }

  return values;
}
