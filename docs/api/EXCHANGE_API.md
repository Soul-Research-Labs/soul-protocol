# PIL Private Exchange API Documentation

## Overview

The PIL Private Exchange provides a privacy-preserving decentralized exchange (DEX) with support for:
- **Private Deposits/Withdrawals** - Using commitment schemes
- **Private Order Book** - Encrypted limit orders
- **AMM Pools** - Privacy-preserving automated market making
- **Cross-Chain Swaps** - Via Proof Carrying Containers (PC³)
- **Stealth Addresses** - Unlinkable payment destinations

## Table of Contents

1. [Smart Contract API](#smart-contract-api)
2. [REST API](#rest-api)
3. [WebSocket API](#websocket-api)
4. [SDK Usage](#sdk-usage)
5. [Error Codes](#error-codes)

---

## Smart Contract API

### PILPrivateExchange.sol

#### Core Functions

##### `deposit(address token, uint256 amount) → bytes32 commitment`

Deposit tokens into the exchange with a privacy-preserving commitment.

```solidity
// Parameters
- token: ERC20 token address to deposit
- amount: Amount to deposit (in token's smallest unit)

// Returns
- commitment: The deposit commitment hash

// Events Emitted
- Deposited(address indexed user, address indexed token, bytes32 commitment)

// Requirements
- Token must be supported
- Amount must be within min/max limits
- User must have approved the exchange
```

**Example (ethers.js):**
```typescript
const commitment = await exchange.deposit(tokenAddress, ethers.parseEther("100"));
console.log("Deposit commitment:", commitment);
```

---

##### `withdraw(address token, uint256 amount, bytes32 nullifier, bytes proof) → bool`

Withdraw tokens using a ZK proof.

```solidity
// Parameters
- token: ERC20 token address to withdraw
- amount: Amount to withdraw
- nullifier: Prevents double-spending
- proof: ZK proof of valid withdrawal

// Returns
- success: Whether withdrawal succeeded

// Events Emitted
- Withdrawn(address indexed user, address indexed token, bytes32 nullifier)
```

---

##### `createOrder(...) → bytes32 orderId`

Create a private limit or market order.

```solidity
function createOrder(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,
    uint256 deadline,
    uint8 orderType,     // 0 = Market, 1 = Limit
    uint8 side,          // 0 = Buy, 1 = Sell
    bytes calldata proof
) external returns (bytes32 orderId);
```

---

##### `swapPrivate(address tokenIn, address tokenOut, uint256 amountIn, uint256 minAmountOut, bytes proof) → uint256 amountOut`

Execute a private swap through AMM pools.

```solidity
// Parameters
- tokenIn: Token to swap from
- tokenOut: Token to swap to
- amountIn: Input amount
- minAmountOut: Minimum acceptable output (slippage protection)
- proof: ZK proof of balance ownership

// Returns
- amountOut: Actual output amount

// Events Emitted
- PrivateSwap(bytes32 indexed swapId, address tokenIn, address tokenOut)
```

---

##### `createPool(address tokenA, address tokenB, uint256 amountA, uint256 amountB, bytes proof) → bytes32 poolId`

Create a new liquidity pool.

```solidity
// Parameters
- tokenA: First token in pair
- tokenB: Second token in pair
- amountA: Initial liquidity for tokenA
- amountB: Initial liquidity for tokenB
- proof: ZK proof of balance ownership

// Returns
- poolId: Unique pool identifier

// Events Emitted
- PoolCreated(bytes32 indexed poolId, address tokenA, address tokenB)
```

---

### StealthAddressRegistry.sol

#### Functions

##### `registerMetaAddress(...)`

Register a stealth meta-address for receiving private payments.

```solidity
function registerMetaAddress(
    uint256 spendingPubKeyX,
    uint256 spendingPubKeyY,
    uint256 viewingPubKeyX,
    uint256 viewingPubKeyY
) external payable;

// Fee: 0.001 ETH (covers announcement costs)
```

---

##### `announcePayment(...)`

Announce a payment to a stealth address (for senders).

```solidity
function announcePayment(
    address stealthAddress,
    address token,
    uint256 amount,
    uint256 ephemeralPubKeyX,
    uint256 ephemeralPubKeyY,
    uint8 viewTag
) external payable;
```

---

## REST API

### Base URL

```
Production: https://api.pil.network/exchange/v1
Testnet:    https://testnet-api.pil.network/exchange/v1
```

### Endpoints

#### GET `/pools`

List all liquidity pools.

**Response:**
```json
{
  "pools": [
    {
      "poolId": "0x...",
      "tokenA": {
        "address": "0x...",
        "symbol": "ETH",
        "decimals": 18
      },
      "tokenB": {
        "address": "0x...",
        "symbol": "USDC",
        "decimals": 6
      },
      "reserveA": "1000000000000000000000",
      "reserveB": "2000000000000",
      "fee": 30,
      "volume24h": "50000000000000000000"
    }
  ],
  "pagination": {
    "page": 1,
    "pageSize": 20,
    "total": 42
  }
}
```

---

#### GET `/pools/:poolId`

Get detailed pool information.

**Parameters:**
- `poolId`: Pool identifier (bytes32)

**Response:**
```json
{
  "poolId": "0x...",
  "tokenA": {...},
  "tokenB": {...},
  "reserveA": "1000000000000000000000",
  "reserveB": "2000000000000",
  "totalLiquidity": "1414213562373095048801",
  "apr": 12.5,
  "volume24h": "50000000000000000000",
  "fee": 30,
  "createdAt": "2024-01-15T10:30:00Z"
}
```

---

#### GET `/quote`

Get a swap quote.

**Query Parameters:**
- `tokenIn`: Input token address
- `tokenOut`: Output token address  
- `amountIn`: Input amount (in wei)

**Response:**
```json
{
  "amountOut": "990000000000000000",
  "priceImpact": 0.15,
  "fee": "3000000000000000",
  "route": ["0x...pool1", "0x...pool2"],
  "estimatedGas": 150000
}
```

---

#### POST `/orders`

Submit a private order (relayer endpoint).

**Request:**
```json
{
  "orderData": "0x...",      // Encoded order data
  "signature": "0x...",       // User signature
  "proof": "0x..."           // ZK proof
}
```

**Response:**
```json
{
  "orderId": "0x...",
  "status": "pending",
  "estimatedMatch": "2024-01-15T10:35:00Z"
}
```

---

#### GET `/orders/:orderId`

Get order status.

**Response:**
```json
{
  "orderId": "0x...",
  "status": "filled",        // pending, partial, filled, cancelled
  "filledAmount": "100000000000000000",
  "remainingAmount": "0",
  "fills": [
    {
      "amount": "100000000000000000",
      "price": "2000000000",
      "timestamp": "2024-01-15T10:32:00Z",
      "txHash": "0x..."
    }
  ]
}
```

---

#### GET `/user/:address/balances`

Get user's private balances (requires authentication).

**Headers:**
```
Authorization: Bearer <token>
X-Signature: <message-signature>
```

**Response:**
```json
{
  "balances": [
    {
      "token": "0x...",
      "symbol": "ETH",
      "commitment": "0x...",
      "available": true
    }
  ]
}
```

---

#### POST `/stealth/scan`

Scan for stealth payments (requires viewing key).

**Request:**
```json
{
  "viewingKey": "0x...",
  "fromBlock": 1000000,
  "toBlock": "latest"
}
```

**Response:**
```json
{
  "payments": [
    {
      "stealthAddress": "0x...",
      "token": "0x...",
      "amount": "1000000000000000000",
      "ephemeralPubKey": {
        "x": "0x...",
        "y": "0x..."
      },
      "blockNumber": 1000500,
      "txHash": "0x..."
    }
  ]
}
```

---

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('wss://api.pil.network/exchange/v1/ws');

ws.onopen = () => {
  // Subscribe to channels
  ws.send(JSON.stringify({
    type: 'subscribe',
    channels: ['trades', 'orders', 'pools']
  }));
};
```

### Channels

#### `trades`

Real-time trade updates.

```json
{
  "channel": "trades",
  "data": {
    "poolId": "0x...",
    "tokenIn": "0x...",
    "tokenOut": "0x...",
    "amountIn": "1000000000000000000",
    "amountOut": "990000000000000000",
    "timestamp": 1705315200
  }
}
```

#### `orders`

Order book updates.

```json
{
  "channel": "orders",
  "data": {
    "type": "new",           // new, cancel, fill
    "orderId": "0x...",
    "pair": "ETH/USDC",
    "side": "buy",
    "price": "2000.00",
    "amount": "1.5"
  }
}
```

#### `pools`

Pool state updates.

```json
{
  "channel": "pools",
  "data": {
    "poolId": "0x...",
    "reserveA": "1000000000000000000000",
    "reserveB": "2000000000000",
    "lastUpdate": 1705315200
  }
}
```

---

## SDK Usage

### Installation

```bash
npm install @pil/exchange-sdk
```

### Basic Usage

```typescript
import { PILExchange } from '@pil/exchange-sdk';
import { ethers } from 'ethers';

// Initialize
const provider = new ethers.JsonRpcProvider('https://sepolia.infura.io/v3/...');
const signer = new ethers.Wallet(privateKey, provider);
const exchange = new PILExchange({
  provider,
  signer,
  network: 'sepolia'
});

// Deposit
const commitment = await exchange.deposit('0x...tokenAddress', '100');
console.log('Deposit commitment:', commitment);

// Private swap
const result = await exchange.swapPrivate({
  tokenIn: '0x...tokenA',
  tokenOut: '0x...tokenB',
  amountIn: ethers.parseEther('1'),
  slippage: 0.5, // 0.5%
});
console.log('Swap result:', result);

// Create limit order
const order = await exchange.createOrder({
  tokenIn: '0x...tokenA',
  tokenOut: '0x...tokenB',
  amountIn: ethers.parseEther('10'),
  price: ethers.parseUnits('2000', 6), // Price in USDC
  side: 'sell',
  type: 'limit',
  deadline: Math.floor(Date.now() / 1000) + 86400,
});
console.log('Order ID:', order.orderId);
```

### Stealth Address Usage

```typescript
import { StealthClient } from '@pil/exchange-sdk';

const stealth = new StealthClient({ signer });

// Generate stealth meta-address
const metaAddress = await stealth.generateMetaAddress();
console.log('Share this with senders:', metaAddress.encoded);

// Register on-chain
await stealth.register(metaAddress);

// Send to stealth address (as sender)
const payment = await stealth.sendToStealth(
  recipientMetaAddress,
  '0x...tokenAddress',
  ethers.parseEther('10')
);

// Scan for payments (as recipient)
const payments = await stealth.scan({
  viewingKey: metaAddress.viewingKey,
  fromBlock: 'latest-1000'
});
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| `E001` | `InsufficientBalance` | User doesn't have enough balance |
| `E002` | `InvalidProof` | ZK proof verification failed |
| `E003` | `NullifierUsed` | Nullifier already spent |
| `E004` | `OrderExpired` | Order deadline passed |
| `E005` | `SlippageExceeded` | Output below minimum |
| `E006` | `InvalidToken` | Token not supported |
| `E007` | `PoolNotFound` | Pool doesn't exist |
| `E008` | `InsufficientLiquidity` | Not enough pool liquidity |
| `E009` | `Paused` | Exchange is paused |
| `E010` | `Unauthorized` | Caller not authorized |

---

## Rate Limits

| Endpoint | Rate Limit |
|----------|------------|
| REST API | 100 req/min |
| WebSocket | 50 msg/sec |
| Order submission | 10 req/min |

---

## Support

- **Documentation**: https://docs.pil.network
- **Discord**: https://discord.gg/pil-network
- **GitHub**: https://github.com/soul-network/pil

---

*Last updated: 2024*
