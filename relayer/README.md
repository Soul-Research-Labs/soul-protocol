# ZASEON Relayer Node

Decentralized relayer for cross-chain proof relay and privacy event processing across Ethereum, Arbitrum, Optimism, Base, and Aztec.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   ZASEON Relayer                      │
├──────────────────────────────────────────────────────┤
│  EventWatcher    →  ProofQueue    →  ProofSubmitter  │
│  (multi-chain)      (Redis-backed)   (destination)   │
├──────────────────────────────────────────────────────┤
│  HealthReporter  (Prometheus /metrics, /health)      │
└──────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your RPC URLs and private key

# Development
npm run dev

# Production (Docker)
docker-compose up -d
```

## Configuration

| Variable              | Description                 | Default                           |
| --------------------- | --------------------------- | --------------------------------- |
| `CHAINS`              | Comma-separated chain names | `ethereum,arbitrum,optimism,base` |
| `ETHEREUM_RPC_URL`    | Ethereum RPC endpoint       | `http://localhost:8545`           |
| `ARBITRUM_RPC_URL`    | Arbitrum RPC endpoint       | `http://localhost:8545`           |
| `OPTIMISM_RPC_URL`    | Optimism RPC endpoint       | `http://localhost:8545`           |
| `BASE_RPC_URL`        | Base RPC endpoint           | `http://localhost:8545`           |
| `RELAYER_PRIVATE_KEY` | Relayer signing key         | -                                 |
| `REDIS_URL`           | Redis connection URL        | `redis://localhost:6379`          |
| `LOG_LEVEL`           | Logging level               | `info`                            |
| `HEALTH_PORT`         | Health check port           | `9090`                            |

## Monitoring

- **Health**: `GET http://localhost:9090/health`
- **Metrics**: `GET http://localhost:9090/metrics` (Prometheus format)

## Docker

```bash
docker-compose up -d
docker-compose logs -f relayer
```
