# PIL v2 Subgraph

The Graph Protocol subgraph for indexing Privacy Interoperability Layer v2 (PIL v2) smart contract events. This subgraph enables efficient querying of privacy-preserving operations across all PIL v2 primitives.

## Overview

This subgraph indexes events from the following PIL v2 contracts:

| Contract | Description |
|----------|-------------|
| **ProofCarryingContainer (PC³)** | Self-verifying cryptographic containers |
| **PolicyBoundProofs (PBP)** | Policy compliance verification |
| **ExecutionAgnosticStateCommitments (EASC)** | Cross-chain state management |
| **CrossDomainNullifierAlgebra (CDNA)** | Double-spend prevention |
| **PILv2Orchestrator** | System coordination and operations |

## Prerequisites

- Node.js >= 18
- Yarn or npm
- Access to The Graph Studio or a local Graph Node
- PIL v2 contracts deployed on a supported network

## Installation

```bash
cd subgraph
npm install
```

## Configuration

### Update Contract Addresses

Before deploying, update the contract addresses in `subgraph.yaml`:

```yaml
dataSources:
  - kind: ethereum/contract
    name: ProofCarryingContainer
    source:
      address: "0xYOUR_PC3_ADDRESS"
      startBlock: YOUR_START_BLOCK
```

### Generate Types

After updating addresses, generate TypeScript types:

```bash
npm run codegen
```

### Build

```bash
npm run build
```

## Deployment

### The Graph Studio (Hosted Service)

1. Create a subgraph on [The Graph Studio](https://thegraph.com/studio/)

2. Authenticate:
```bash
graph auth --studio YOUR_DEPLOY_KEY
```

3. Deploy:
```bash
graph deploy --studio pil-v2
```

### Local Development (Graph Node)

1. Start a local Graph Node:
```bash
docker-compose up
```

2. Create and deploy:
```bash
npm run create-local
npm run deploy-local
```

## Entities

### Container
Proof-carrying containers created via PC³.

```graphql
type Container @entity {
  id: ID!
  stateCommitment: Bytes!
  nullifier: Bytes!
  policyHash: Bytes!
  chainId: BigInt!
  creator: Bytes!
  status: ContainerStatus!
  createdAt: BigInt!
  consumedAt: BigInt
  consumer: Bytes
  verifications: [ContainerVerification!]! @derivedFrom(field: "container")
}
```

### Policy
Policy definitions from PolicyBoundProofs.

```graphql
type Policy @entity {
  id: ID!
  policyHash: Bytes!
  creator: Bytes!
  jurisdictions: [BigInt!]!
  expiry: BigInt!
  active: Boolean!
  createdAt: BigInt!
  deactivatedAt: BigInt
  totalVerifications: BigInt!
}
```

### StateCommitment
State commitments from EASC.

```graphql
type StateCommitment @entity {
  id: ID!
  commitment: Bytes!
  stateRoot: Bytes!
  creator: Bytes!
  chainId: BigInt!
  timestamp: BigInt!
  transitions: [StateTransition!]! @derivedFrom(field: "fromCommitment")
}
```

### NullifierConsumption
Nullifier consumption events from CDNA.

```graphql
type NullifierConsumption @entity {
  id: ID!
  nullifier: Bytes!
  domain: Domain!
  consumer: Bytes!
  timestamp: BigInt!
  blockNumber: BigInt!
}
```

### Operation
Orchestrated operations.

```graphql
type Operation @entity {
  id: ID!
  user: User!
  success: Boolean!
  message: String
  timestamp: BigInt!
}
```

### SystemStats
Aggregated system statistics (singleton).

```graphql
type SystemStats @entity {
  id: ID!
  totalContainers: BigInt!
  totalVerified: BigInt!
  totalConsumed: BigInt!
  totalPolicies: BigInt!
  activePolicies: BigInt!
  totalCommitments: BigInt!
  totalNullifiers: BigInt!
  totalOperations: BigInt!
  successfulOperations: BigInt!
  totalUsers: BigInt!
  lastUpdated: BigInt!
}
```

## Example Queries

### Get All Containers for a User

```graphql
{
  containers(where: { creator: "0x..." }) {
    id
    stateCommitment
    status
    createdAt
    verifications {
      success
      verifier
    }
  }
}
```

### Get System Statistics

```graphql
{
  systemStats(id: "stats") {
    totalContainers
    totalVerified
    totalOperations
    successfulOperations
    totalUsers
    lastUpdated
  }
}
```

### Get Active Policies

```graphql
{
  policies(where: { active: true }, orderBy: createdAt, orderDirection: desc) {
    id
    policyHash
    creator
    jurisdictions
    expiry
    totalVerifications
  }
}
```

### Get Recent Operations

```graphql
{
  operations(first: 10, orderBy: timestamp, orderDirection: desc) {
    id
    user {
      id
      totalOperations
      successfulOperations
    }
    success
    message
    timestamp
  }
}
```

### Get Cross-Domain Nullifiers

```graphql
{
  nullifierConsumptions(orderBy: timestamp, orderDirection: desc) {
    id
    nullifier
    domain {
      id
      name
      chainId
    }
    consumer
    timestamp
  }
}
```

### Get User Statistics

```graphql
{
  user(id: "0x...") {
    totalOperations
    successfulOperations
    failedOperations
    firstOperationAt
    lastOperationAt
    containersCreated {
      id
      status
    }
  }
}
```

## Development

### Project Structure

```
subgraph/
├── abis/                    # Contract ABIs
├── src/
│   ├── proof-carrying-container.ts  # PC³ event handlers
│   ├── policy-bound-proofs.ts       # PBP event handlers
│   ├── state-commitments.ts         # EASC event handlers
│   ├── cross-domain-nullifier.ts    # CDNA event handlers
│   └── orchestrator.ts              # Orchestrator event handlers
├── schema.graphql           # Entity definitions
├── subgraph.yaml           # Subgraph manifest
└── package.json
```

### Adding New Event Handlers

1. Update `schema.graphql` with new entities
2. Add event sources to `subgraph.yaml`
3. Implement handlers in the appropriate `src/*.ts` file
4. Run `npm run codegen` to regenerate types
5. Run `npm run build` to compile

### Testing

Use [Matchstick](https://thegraph.com/docs/en/developing/unit-testing-framework/) for unit testing:

```bash
npm run test
```

## Networks

The subgraph can be deployed to any EVM-compatible network supported by The Graph:

- **Ethereum Mainnet**: Production deployment
- **Sepolia**: Testnet deployment
- **Polygon**: L2 deployment
- **Arbitrum One**: L2 deployment
- **Base**: L2 deployment

Update the `network` field in `subgraph.yaml` accordingly.

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Resources

- [PIL v2 Documentation](../docs/)
- [The Graph Documentation](https://thegraph.com/docs/)
- [AssemblyScript Documentation](https://www.assemblyscript.org/introduction.html)
