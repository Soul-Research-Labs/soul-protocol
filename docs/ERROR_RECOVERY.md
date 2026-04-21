# Error Recovery Guide (SDK)

The ZASEON SDK ships with a declarative **recovery table** that maps every
`ZaseonErrorCode` to a recovery strategy. Wrap any SDK call with
`withRecovery()` to get automatic retry/resync/fallback/escalate behavior.

## Quick example

```ts
import { withRecovery, ZaseonSDK } from "@zaseon/sdk";

const sdk = new ZaseonSDK({
  /* ... */
});

const result = await withRecovery(
  () => sdk.bridges.send({ to: chainId, amount }),
  { onAttempt: (n, err) => console.warn(`attempt ${n}:`, err?.code) },
);
```

## Strategies

| Strategy   | Meaning                                    | Example codes                                       |
| ---------- | ------------------------------------------ | --------------------------------------------------- |
| `retry`    | Idempotent, transient — back off and retry | `RPC_TIMEOUT`, `NETWORK_ERROR`                      |
| `resync`   | Refresh state before retrying              | `NONCE_TOO_LOW`, `STATE_ROOT_MISMATCH`              |
| `fallback` | Try alternative (different bridge/relayer) | `RELAY_TIMEOUT`, `BRIDGE_UNAVAILABLE`               |
| `escalate` | Non-recoverable — surface to user          | `PROOF_VERIFICATION_FAILED`, `COMPLIANCE_VIOLATION` |
| `refund`   | Trigger on-chain refund path               | `DESTINATION_UNREACHABLE`, `DEADLINE_EXPIRED`       |

## Consulting the table directly

```ts
import { recoveryFor, ZaseonErrorCode } from "@zaseon/sdk";

const spec = recoveryFor(ZaseonErrorCode.NONCE_TOO_LOW);
// { strategy: "resync", maxAttempts: 3, backoffBaseMs: 0, hint: "Refresh on-chain nonce and retry." }
```

## Overriding per call

```ts
await withRecovery(fn, {
  maxAttempts: 5,
  backoffBaseMs: 500,
  strategyOverride: { [ZaseonErrorCode.RELAY_TIMEOUT]: "fallback" },
});
```

## Integration with NonceManager

`NonceManager.next()` automatically emits a `NONCE_TOO_LOW` error when the
broadcast fails; the `withRecovery` wrapper catches it, calls
`NonceManager.reset()`, then retries. Client code never sees the drift.

## Full mapping

The authoritative mapping lives in
[`sdk/src/utils/recovery.ts`](../sdk/src/utils/recovery.ts). Run:

```bash
cd sdk && npm run docs:recovery
```

to regenerate the full markdown table from `RECOVERY_TABLE`.
