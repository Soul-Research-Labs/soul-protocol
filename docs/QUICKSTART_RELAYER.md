# Quickstart — Run a ZASEON relayer (5 min)

## Prerequisites

- Docker & docker compose v2
- ≥ 0.1 ETH (or destination chain gas token) in your relayer hot wallet
- Registered relayer stake in `DecentralizedRelayerRegistry`

## 1. Clone + configure

```bash
git clone https://github.com/manish0907/ZASEON.git
cd ZASEON/relayer
cp .env.example .env
```

Edit `.env`:

```dotenv
RELAYER_PRIVATE_KEY=0x...
L1_RPC_URL=https://eth.llamarpc.com
L2_RPC_URLS=optimism=https://mainnet.optimism.io,arbitrum=https://arb1.arbitrum.io/rpc
HUB_ADDRESS=0x...                  # from deployments/mainnet-1.json
PROOF_QUEUE_REDIS_URL=redis://redis:6379
METRICS_PORT=9100
```

## 2. Start

```bash
docker compose up -d
docker compose logs -f relayer
```

You should see:

```
[relayer] event-watcher connected (block 19_000_000)
[relayer] registered with registry (stake=100 ETH)
[relayer] listening for ProofRequested events
```

## 3. Verify health

```bash
curl http://localhost:9100/metrics | grep zaseon_relayer
# zaseon_relayer_tasks_total 0
# zaseon_relayer_tasks_succeeded 0
# zaseon_relayer_tasks_failed 0
```

## 4. Monitoring

Import `monitoring/grafana/relayer-dashboard.json` into Grafana. Panels:
tasks/sec, success rate, P50/P95 latency, active tasks, stake utilization.

## 5. Graceful shutdown

```bash
docker compose exec relayer kill -TERM 1   # drains in-flight tasks first
docker compose down
```

## Kubernetes

See [`charts/relayer/`](../charts/relayer/) for the Helm chart:

```bash
helm install zaseon-relayer ./charts/relayer \
  --set privateKey=$RELAYER_PRIVATE_KEY \
  --set hub.address=0x...
```

## Troubleshooting

| Symptom                            | Fix                                                               |
| ---------------------------------- | ----------------------------------------------------------------- |
| `nonce too low` repeatedly         | Restart — on-chain nonce drifted. The `NonceManager` will resync. |
| Slashed — missed deadline          | Increase `PROOF_TIMEOUT_SEC`, check prover perf in metrics.       |
| `relay timeout` for specific chain | Check that RPC is healthy; add a backup RPC to `L2_RPC_URLS`.     |

See [RELAYER_RESILIENCE.md](./RELAYER_RESILIENCE.md) for full operational guide.
