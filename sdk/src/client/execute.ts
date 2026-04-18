/**
 * `ZaseonClient.execute()` — unified high-level facade over deposit / transfer
 * / withdraw. Consumers use one entry point; the facade selects the right
 * subclient and proof backend, applies retry+recovery, and surfaces a
 * uniform `ExecutionResult`.
 *
 * Design: pure composition over existing SDK surfaces. No new on-chain
 * behavior. Lives next to `ZaseonSDK` so it is trivially importable.
 */
import { ZaseonError, ZaseonErrorCode } from "../utils/errors.js";
import { withRecovery } from "../utils/recovery.js";

export type ZaseonAction = "deposit" | "transfer" | "withdraw";

export interface BaseExecuteParams {
  action: ZaseonAction;
  chainId: number;
  /** Amount in smallest native unit (wei, etc). */
  amount: bigint;
  /** Optional override of proof backend. Auto-selected if omitted. */
  backend?: "bb.js" | "wasm" | "server";
}

export interface DepositParams extends BaseExecuteParams {
  action: "deposit";
  token: `0x${string}`;
}

export interface TransferParams extends BaseExecuteParams {
  action: "transfer";
  recipient: `0x${string}` | string; // stealth address allowed
  destChainId: number;
}

export interface WithdrawParams extends BaseExecuteParams {
  action: "withdraw";
  recipient: `0x${string}`;
}

export type ExecuteParams = DepositParams | TransferParams | WithdrawParams;

export interface ExecutionResult {
  action: ZaseonAction;
  txHash?: `0x${string}`;
  proofId?: string;
  attempts: number;
  durationMs: number;
}

type ExecuteFallbackResult = {
  txHash?: `0x${string}`;
  proofId?: string;
};

/**
 * Minimal capability interfaces — the facade only needs these three
 * methods, implemented by the existing `ZaseonSDK.privacy` / `.bridges` /
 * `.shieldedPool` clients. Interfaces keep this file decoupled.
 */
export interface DepositCapable {
  deposit(p: DepositParams): Promise<{ txHash: `0x${string}` }>;
}
export interface TransferCapable {
  send(p: TransferParams): Promise<{ txHash: `0x${string}`; proofId: string }>;
}
export interface WithdrawCapable {
  withdraw(
    p: WithdrawParams,
  ): Promise<{ txHash: `0x${string}`; proofId: string }>;
}

export interface ExecuteRouter {
  deposit: DepositCapable;
  transfer: TransferCapable;
  withdraw: WithdrawCapable;
  fallback?: (
    params: ExecuteParams,
    error: ZaseonError,
  ) => ExecuteFallbackResult | Promise<ExecuteFallbackResult>;
}

/**
 * Run any ZASEON action through a single entry with automatic recovery.
 */
export async function execute(
  router: ExecuteRouter,
  params: ExecuteParams,
): Promise<ExecutionResult> {
  const start = Date.now();
  let attempts = 0;
  const wrapped = async () => {
    attempts += 1;
    switch (params.action) {
      case "deposit":
        return router.deposit.deposit(params);
      case "transfer":
        return router.transfer.send(params);
      case "withdraw":
        return router.withdraw.withdraw(params);
      default:
        throw new ZaseonError(
          `Unknown action: ${(params as ExecuteParams).action}`,
          ZaseonErrorCode.INVALID_INPUT,
        );
    }
  };
  const out = await withRecovery(wrapped, {
    onFallback: router.fallback
      ? (error) => router.fallback!(params, error)
      : undefined,
  });
  return {
    action: params.action,
    txHash: (out as { txHash?: `0x${string}` }).txHash,
    proofId: (out as { proofId?: string }).proofId,
    attempts,
    durationMs: Date.now() - start,
  };
}
