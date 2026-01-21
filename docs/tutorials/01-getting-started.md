# PIL Exchange Tutorial: Getting Started

Welcome to the Privacy Interoperability Layer (PIL) Exchange tutorial! This guide will walk you through using the privacy-preserving decentralized exchange.

## Prerequisites

- Node.js 18+
- npm or yarn
- Basic understanding of Ethereum and smart contracts
- A wallet with testnet ETH (Sepolia)

## Table of Contents

1. [Setup](#1-setup)
2. [Connect Your Wallet](#2-connect-your-wallet)
3. [Make a Private Deposit](#3-make-a-private-deposit)
4. [Execute a Private Swap](#4-execute-a-private-swap)
5. [Create a Limit Order](#5-create-a-limit-order)
6. [Provide Liquidity](#6-provide-liquidity)
7. [Use Stealth Addresses](#7-use-stealth-addresses)
8. [Withdraw Funds](#8-withdraw-funds)

---

## 1. Setup

First, install the PIL Exchange SDK:

```bash
npm install @pil/exchange-sdk ethers
```

Or with yarn:

```bash
yarn add @pil/exchange-sdk ethers
```

### Environment Setup

Create a `.env` file:

```env
# Network RPC URLs
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY

# Optional: For automated testing
PRIVATE_KEY=your_private_key_here
```

---

## 2. Connect Your Wallet

### Browser (MetaMask)

```typescript
import { PILExchange } from '@pil/exchange-sdk';
import { ethers } from 'ethers';

async function connectWallet() {
  // Request account access
  const accounts = await window.ethereum.request({
    method: 'eth_requestAccounts'
  });

  // Create provider and signer
  const provider = new ethers.BrowserProvider(window.ethereum);
  const signer = await provider.getSigner();

  // Initialize PIL Exchange
  const exchange = new PILExchange({
    provider,
    signer,
    network: 'sepolia'
  });

  console.log('Connected:', accounts[0]);
  return exchange;
}
```

### Node.js

```typescript
import { PILExchange } from '@pil/exchange-sdk';
import { ethers } from 'ethers';

async function initExchange() {
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

  const exchange = new PILExchange({
    provider,
    signer,
    network: 'sepolia'
  });

  return exchange;
}
```

---

## 3. Make a Private Deposit

Deposits use commitment schemes to hide the exact amount on-chain.

```typescript
async function deposit(exchange: PILExchange) {
  const tokenAddress = '0x...'; // Token contract address
  const amount = ethers.parseEther('100'); // 100 tokens

  // Step 1: Approve token spending (first time only)
  const token = await exchange.getToken(tokenAddress);
  const approveTx = await token.approve(
    exchange.contractAddress,
    ethers.MaxUint256
  );
  await approveTx.wait();
  console.log('Token approved');

  // Step 2: Make the deposit
  const result = await exchange.deposit(tokenAddress, amount);
  
  console.log('Deposit successful!');
  console.log('Commitment:', result.commitment);
  console.log('Transaction:', result.txHash);

  // IMPORTANT: Save your commitment!
  // You'll need it for withdrawals
  localStorage.setItem('lastDeposit', JSON.stringify({
    commitment: result.commitment,
    amount: amount.toString(),
    token: tokenAddress,
    timestamp: Date.now()
  }));

  return result;
}
```

### Understanding Commitments

When you deposit, the exchange creates a "commitment" - a cryptographic hash that represents your deposit without revealing the amount:

```
commitment = hash(amount, secret, nullifier)
```

- **Amount**: How much you deposited
- **Secret**: A random value only you know
- **Nullifier**: Used later to prevent double-spending

---

## 4. Execute a Private Swap

Swap tokens through privacy-preserving AMM pools:

```typescript
async function privateSwap(exchange: PILExchange) {
  const tokenIn = '0x...'; // Token you're selling
  const tokenOut = '0x...'; // Token you're buying
  const amountIn = ethers.parseEther('10');
  const slippagePercent = 0.5; // 0.5%

  // Step 1: Get a quote
  const quote = await exchange.getQuote({
    tokenIn,
    tokenOut,
    amountIn
  });

  console.log('Quote:');
  console.log('  Amount Out:', ethers.formatEther(quote.amountOut));
  console.log('  Price Impact:', quote.priceImpact, '%');
  console.log('  Fee:', ethers.formatEther(quote.fee));

  // Step 2: Calculate minimum output with slippage
  const minAmountOut = quote.amountOut * BigInt(1000 - slippagePercent * 10) / 1000n;

  // Step 3: Execute the swap
  const result = await exchange.swapPrivate({
    tokenIn,
    tokenOut,
    amountIn,
    minAmountOut
  });

  console.log('Swap successful!');
  console.log('  Received:', ethers.formatEther(result.amountOut));
  console.log('  Transaction:', result.txHash);

  return result;
}
```

### How Private Swaps Work

1. Your swap is submitted with a ZK proof proving you have sufficient balance
2. The actual amounts are hidden from observers
3. Only the pool state change is visible on-chain
4. Your balance is updated using encrypted commitments

---

## 5. Create a Limit Order

Place private limit orders that are matched off-chain:

```typescript
async function createLimitOrder(exchange: PILExchange) {
  const order = await exchange.createOrder({
    tokenIn: '0x...ETH',
    tokenOut: '0x...USDC',
    amountIn: ethers.parseEther('1'), // 1 ETH
    price: ethers.parseUnits('2000', 6), // $2000 per ETH
    side: 'sell',
    type: 'limit',
    deadline: Math.floor(Date.now() / 1000) + 86400, // 24 hours
  });

  console.log('Order created!');
  console.log('  Order ID:', order.orderId);
  console.log('  Status:', order.status);

  // Monitor order status
  const status = await exchange.getOrderStatus(order.orderId);
  console.log('Current status:', status);

  return order;
}
```

### Order Types

- **Market Order**: Execute immediately at current price
- **Limit Order**: Execute only when price reaches target
- **Stop-Loss**: Sell if price drops below threshold
- **Take-Profit**: Sell if price rises above threshold

---

## 6. Provide Liquidity

Earn fees by providing liquidity to pools:

```typescript
async function provideLiquidity(exchange: PILExchange) {
  const tokenA = '0x...ETH';
  const tokenB = '0x...USDC';
  const amountA = ethers.parseEther('1'); // 1 ETH
  const amountB = ethers.parseUnits('2000', 6); // 2000 USDC

  // Step 1: Check if pool exists
  const pool = await exchange.getPool(tokenA, tokenB);
  
  if (!pool) {
    // Create new pool
    const result = await exchange.createPool({
      tokenA,
      tokenB,
      amountA,
      amountB
    });
    console.log('Pool created:', result.poolId);
  } else {
    // Add to existing pool
    const result = await exchange.addLiquidity({
      tokenA,
      tokenB,
      amountA,
      amountB,
      slippage: 0.5
    });
    console.log('Liquidity added!');
    console.log('  LP Tokens:', result.lpTokens);
  }

  // Check your position
  const position = await exchange.getLiquidityPosition(tokenA, tokenB);
  console.log('Your position:');
  console.log('  Share:', position.share, '%');
  console.log('  Value:', position.valueUSD);
}
```

### Removing Liquidity

```typescript
async function removeLiquidity(exchange: PILExchange) {
  const tokenA = '0x...ETH';
  const tokenB = '0x...USDC';
  const percentToRemove = 50; // Remove 50%

  const result = await exchange.removeLiquidity({
    tokenA,
    tokenB,
    percent: percentToRemove
  });

  console.log('Liquidity removed!');
  console.log('  Received Token A:', ethers.formatEther(result.amountA));
  console.log('  Received Token B:', ethers.formatUnits(result.amountB, 6));
}
```

---

## 7. Use Stealth Addresses

Receive payments without revealing your identity:

### Generate Your Stealth Meta-Address

```typescript
import { StealthClient } from '@pil/exchange-sdk';

async function setupStealth(signer: ethers.Signer) {
  const stealth = new StealthClient({ signer });

  // Generate meta-address (do this once)
  const metaAddress = await stealth.generateMetaAddress();

  // IMPORTANT: Back up your keys securely!
  console.log('Your Stealth Meta-Address:', metaAddress.encoded);
  console.log('Spending Key (KEEP SECRET!):', metaAddress.spendingKey);
  console.log('Viewing Key:', metaAddress.viewingKey);

  // Register on-chain so others can pay you
  const tx = await stealth.register(metaAddress);
  await tx.wait();

  console.log('Stealth address registered!');
  console.log('Share your meta-address with senders.');

  return metaAddress;
}
```

### Send to a Stealth Address

```typescript
async function sendToStealth(
  stealth: StealthClient,
  recipientMetaAddress: string,
  tokenAddress: string,
  amount: bigint
) {
  const result = await stealth.sendToStealth(
    recipientMetaAddress,
    tokenAddress,
    amount
  );

  console.log('Sent to stealth address!');
  console.log('  Stealth Address:', result.stealthAddress);
  console.log('  Transaction:', result.txHash);

  // The recipient will find this payment when they scan
}
```

### Scan for Payments

```typescript
async function scanPayments(
  stealth: StealthClient,
  viewingKey: string
) {
  // Scan recent blocks for payments to you
  const payments = await stealth.scan({
    viewingKey,
    fromBlock: 'latest-10000'
  });

  console.log(`Found ${payments.length} payments:`);

  for (const payment of payments) {
    console.log('  Address:', payment.stealthAddress);
    console.log('  Token:', payment.token);
    console.log('  Amount:', ethers.formatEther(payment.amount));
    console.log('  Block:', payment.blockNumber);

    // Derive spending key to claim
    const privateKey = await stealth.deriveSpendingKey(
      payment,
      viewingKey
    );

    // Use privateKey to create wallet and claim funds
  }

  return payments;
}
```

---

## 8. Withdraw Funds

Withdraw your funds using ZK proofs:

```typescript
async function withdraw(exchange: PILExchange) {
  const tokenAddress = '0x...';
  const amount = ethers.parseEther('50');
  const recipientAddress = '0x...'; // Can be a stealth address!

  // Generate withdrawal proof
  const result = await exchange.withdraw({
    token: tokenAddress,
    amount,
    recipient: recipientAddress
  });

  console.log('Withdrawal successful!');
  console.log('  Transaction:', result.txHash);
  console.log('  Recipient:', recipientAddress);

  return result;
}
```

### Withdraw to Stealth Address

```typescript
async function withdrawToStealth(exchange: PILExchange) {
  const tokenAddress = '0x...';
  const amount = ethers.parseEther('50');

  // Generate one-time stealth address
  const stealthAddress = await exchange.generateStealthWithdrawalAddress();

  const result = await exchange.withdrawToStealth({
    token: tokenAddress,
    amount,
    stealthAddress
  });

  console.log('Private withdrawal complete!');
  console.log('  Stealth Address:', stealthAddress);

  // Save stealth address info for later claiming
  return result;
}
```

---

## Next Steps

- **[Advanced Trading Tutorial](./02-advanced-trading.md)**: Complex order types, MEV protection
- **[Cross-Chain Swaps](./03-cross-chain.md)**: Swap across different blockchains
- **[Integration Guide](./04-integration.md)**: Integrate PIL Exchange into your dApp
- **[Security Best Practices](./05-security.md)**: Keep your funds safe

---

## Troubleshooting

### Common Issues

**"Insufficient Balance"**
- Check your deposit commitment is stored
- Ensure you're using the correct secret/nullifier

**"Invalid Proof"**
- Regenerate your ZK proof
- Check that circuit inputs match on-chain state

**"Transaction Reverted"**
- Check slippage settings
- Verify token approvals

### Getting Help

- **Discord**: [discord.gg/pil-network](https://discord.gg/pil-network)
- **GitHub Issues**: [github.com/soul-network/pil/issues](https://github.com/soul-network/pil/issues)
- **Documentation**: [docs.pil.network](https://docs.pil.network)

---

*Happy private trading! 🔐*
