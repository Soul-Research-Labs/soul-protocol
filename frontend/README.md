# PIL v2 Demo Frontend

A React/Next.js frontend for interacting with PIL v2 (Privacy Interoperability Layer) smart contracts.

## Features

- 🔗 **Wallet Connection**: Connect with MetaMask, WalletConnect, and other popular wallets via RainbowKit
- 📦 **PC³ (Proof Carrying Containers)**: Create and verify self-authenticating confidential containers
- 📋 **PBP (Policy Bound Proofs)**: Create and manage privacy-preserving compliance policies
- 🔄 **EASC (Execution Agnostic State)**: Create state commitments that work across execution environments
- 🌐 **CDNA (Cross-Domain Nullifiers)**: Check nullifier status and view consumption history
- 🎛️ **Orchestrator**: Execute private transfers using all PIL primitives

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
cd frontend
npm install
```

### Environment Setup

Create a `.env.local` file:

```env
NEXT_PUBLIC_WALLET_CONNECT_ID=your_wallet_connect_project_id
```

Get a WalletConnect Project ID from [cloud.walletconnect.com](https://cloud.walletconnect.com)

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

```bash
npm run build
npm start
```

## Project Structure

```
frontend/
├── src/
│   ├── app/
│   │   ├── globals.css      # Global styles with Tailwind
│   │   ├── layout.tsx       # Root layout with providers
│   │   ├── page.tsx         # Main page component
│   │   └── providers.tsx    # Wagmi/RainbowKit providers
│   ├── components/
│   │   ├── Dashboard.tsx    # Main dashboard with tabs
│   │   ├── Header.tsx       # Navigation header
│   │   ├── LandingHero.tsx  # Landing page for non-connected users
│   │   └── panels/
│   │       ├── ContainerPanel.tsx   # PC³ operations
│   │       ├── PolicyPanel.tsx      # PBP operations
│   │       ├── NullifierPanel.tsx   # CDNA operations
│   │       ├── StatePanel.tsx       # EASC operations
│   │       └── OrchestratorPanel.tsx # Full workflow
│   └── lib/
│       ├── abis.ts          # Contract ABIs
│       └── contracts.ts     # Contract addresses per network
├── package.json
├── tailwind.config.js
└── next.config.js
```

## Supported Networks

- **Sepolia** (Testnet) - Chain ID: 11155111
- **Mumbai** (Polygon Testnet) - Chain ID: 80001
- **Localhost** (Hardhat) - Chain ID: 31337

## Contract Addresses

After deploying the contracts, update the addresses in `src/lib/contracts.ts`:

```typescript
const CONTRACT_ADDRESSES: Record<number, ContractAddresses> = {
  11155111: {  // Sepolia
    verifierRegistry: '0x...',
    proofCarryingContainer: '0x...',
    // ... other addresses
  },
};
```

## Technologies

- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Utility-first styling
- **RainbowKit** - Wallet connection UI
- **Wagmi v2** - React hooks for Ethereum
- **Viem** - TypeScript-first Ethereum library

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run lint` to check for issues
5. Submit a pull request

## License

MIT
