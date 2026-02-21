import { Hex } from "viem";

/**
 * Type alias for viem contract instances with read/write access.
 *
 * viem's `getContract()` returns a highly generic type whose `.read` and `.write`
 * properties only resolve when the ABI const-type flows through to the generic
 * parameter. When inline ABI fragments are used (as in this SDK), TypeScript
 * loses the narrowed type and defaults to `{ address; abi }` without
 * `.read`/`.write`.
 *
 * This structural type captures the shape we actually use at runtime while
 * avoiding bare `any` on every contract property.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ViemContract = {
  address: Hex;
  abi: readonly unknown[];
  read: Record<string, (...args: any[]) => Promise<any>>;
  write: Record<string, (...args: any[]) => Promise<Hex>>;
};

/**
 * Decoded event args from `decodeEventLog`.
 * Provides string-keyed access without bare `any`.
 */
export type DecodedEventArgs = Record<string, unknown>;
