# Docker Deployment Guide

## Quick Start

### Prerequisites

- Docker 24+
- Docker Compose 2+
- At least 8GB RAM available for Docker

### Start All Services

```bash
# Copy environment file
cp .env.example .env

# Start all services
docker compose up -d

# View logs
docker compose logs -f
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| hardhat-node | 8545 | Local Ethereum node |
| frontend | 3000 | Next.js frontend application |
| graph-node | 8000 | GraphQL endpoint for subgraph |
| relayer | 4000 | Transaction relay service |
| prometheus | 9090 | Metrics collection |
| grafana | 3001 | Monitoring dashboards |
| ipfs | 5001 | IPFS for subgraph data |
| postgres | 5432 | Database for graph-node |
| redis | 6379 | Caching layer |

### Access Points

- **Frontend**: http://localhost:3000
- **GraphQL**: http://localhost:8000/subgraphs/name/pil/pil-subgraph
- **Grafana**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Relayer API**: http://localhost:4000

### Management Commands

```bash
# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v

# Rebuild specific service
docker compose build frontend

# View service logs
docker compose logs frontend -f

# Execute command in container
docker compose exec hardhat-node sh
```

### Health Checks

```bash
# Check all service health
docker compose ps

# Check specific service
curl http://localhost:8545 -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Check relayer health
curl http://localhost:4000/health

# Check frontend
curl http://localhost:3000
```

### Troubleshooting

#### Graph Node Not Syncing

```bash
# Check graph-node logs
docker compose logs graph-node

# Restart graph-node
docker compose restart graph-node
```

#### Contract Deployment Failed

```bash
# Re-run deployer
docker compose up deployer

# Check deployer logs
docker compose logs deployer
```

#### Frontend Build Issues

```bash
# Rebuild frontend
docker compose build --no-cache frontend
docker compose up -d frontend
```

### Production Deployment

For production deployment:

1. Update `.env` with secure credentials
2. Configure proper SSL/TLS termination
3. Set up proper database backups
4. Configure horizontal scaling as needed

```bash
# Production mode
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Architecture

```
                    ┌─────────────┐
                    │   Frontend  │
                    │   (Next.js) │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │   Relayer   │ │ Graph Node  │ │  Hardhat    │
    │   (Express) │ │  (GraphQL)  │ │   Node      │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                    ┌──────▼──────┐
                    │  PostgreSQL │
                    └─────────────┘
```
