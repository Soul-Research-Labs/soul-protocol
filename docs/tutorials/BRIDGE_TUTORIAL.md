# PIL Bridge Adapters Tutorial

This tutorial walks through creating a cross-chain private transfer using PIL bridge adapters.

## Prerequisites

- Node.js 18+
- Foundry installed
- Test ETH on Sepolia
- PIL SDK installed

## Step 1: Setup

```bash
# Create new project
mkdir pil-bridge-demo && cd pil-bridge-demo
npm init -y

# Install dependencies
npm install @pil/sdk ethers dotenv
```

Create `.env`:

```env
PRIVATE_KEY=0x...
SEPOLIA_RPC=https://eth-sepolia.g.alchemy.com/v2/...
PIL_PRIVACY_POOL=0x...
PIL_BRIDGE_ROUTER=0x...
```

## Step 2: Initialize SDK

```typescript
// src/index.ts
import { PILClient, ChainId } from '@pil/sdk';
import { ethers } from 'ethers';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  // Initialize provider and signer
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC);
  const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

  // Initialize PIL client
  const pil = new PILClient({
    provider,
    signer,
    privacyPoolAddress: process.env.PIL_PRIVACY_POOL!,
    bridgeRouterAddress: process.env.PIL_BRIDGE_ROUTER!
  });

  console.log('PIL Client initialized');
  console.log('Address:', await signer.getAddress());
}

main().catch(console.error);
```

## Step 3: Create Private Deposit

```typescript
async function createPrivateDeposit(pil: PILClient, amount: bigint) {
  console.log('\n=== Creating Private Deposit ===');
  
  // Generate a random secret for the deposit
  const secret = ethers.randomBytes(32);
  console.log('Secret generated (save this!)');

  // Compute commitment from secret and amount
  const commitment = pil.computeCommitment(secret, amount);
  console.log('Commitment:', ethers.hexlify(commitment));

  // Make the deposit
  const tx = await pil.deposit(commitment, { value: amount });
  console.log('Deposit TX:', tx.hash);

  // Wait for confirmation
  const receipt = await tx.wait();
  console.log('Deposit confirmed in block:', receipt.blockNumber);

  // Get the leaf index from events
  const depositEvent = receipt.logs.find(
    log => log.topics[0] === pil.depositEventTopic
  );
  const leafIndex = BigInt(depositEvent.topics[2]);
  console.log('Leaf index:', leafIndex);

  return {
    secret,
    commitment,
    leafIndex,
    amount
  };
}
```

## Step 4: Generate Withdrawal Proof

```typescript
async function generateWithdrawalProof(
  pil: PILClient,
  depositNote: {
    secret: Uint8Array;
    commitment: Uint8Array;
    leafIndex: bigint;
    amount: bigint;
  },
  recipient: string
) {
  console.log('\n=== Generating Withdrawal Proof ===');

  // Get the current merkle root
  const root = await pil.getMerkleRoot();
  console.log('Current root:', ethers.hexlify(root));

  // Get merkle path for our deposit
  const merklePath = await pil.getMerklePath(depositNote.leafIndex);
  console.log('Merkle path obtained');

  // Compute nullifier from secret
  const nullifier = pil.computeNullifier(depositNote.secret);
  console.log('Nullifier:', ethers.hexlify(nullifier));

  // Generate ZK proof
  console.log('Generating ZK proof (this may take a minute)...');
  const proof = await pil.generateWithdrawProof({
    secret: depositNote.secret,
    amount: depositNote.amount,
    nullifier,
    root,
    pathElements: merklePath.pathElements,
    pathIndices: merklePath.pathIndices,
    recipient
  });
  console.log('Proof generated');

  return {
    proof,
    nullifier,
    root
  };
}
```

## Step 5: Execute Private Withdrawal

```typescript
async function executeWithdrawal(
  pil: PILClient,
  proofData: {
    proof: Uint8Array;
    nullifier: Uint8Array;
    root: Uint8Array;
  },
  recipient: string,
  amount: bigint
) {
  console.log('\n=== Executing Private Withdrawal ===');

  // Execute withdrawal
  const tx = await pil.withdraw(
    proofData.proof,
    proofData.nullifier,
    recipient,
    amount
  );
  console.log('Withdrawal TX:', tx.hash);

  // Wait for confirmation
  const receipt = await tx.wait();
  console.log('Withdrawal confirmed in block:', receipt.blockNumber);

  // Check recipient balance
  const balance = await pil.provider.getBalance(recipient);
  console.log('Recipient balance:', ethers.formatEther(balance), 'ETH');

  return receipt;
}
```

## Step 6: Cross-Chain Private Transfer

```typescript
async function crossChainPrivateTransfer(
  pil: PILClient,
  depositNote: any,
  targetChain: ChainId,
  recipient: string
) {
  console.log('\n=== Cross-Chain Private Transfer ===');
  console.log('Target chain:', ChainId[targetChain]);

  // Generate cross-chain proof
  const crossChainProof = await pil.generateCrossChainProof({
    secret: depositNote.secret,
    amount: depositNote.amount,
    targetChain,
    recipient
  });
  console.log('Cross-chain proof generated');

  // Get required bridge adapter
  const adapter = pil.getBridgeAdapter(targetChain);
  console.log('Using adapter:', adapter.name);

  // Estimate bridge fees
  const fees = await adapter.estimateFees(depositNote.amount);
  console.log('Bridge fees:', ethers.formatEther(fees.total), 'ETH');

  // Execute bridge transfer
  const tx = await pil.bridgeTransfer({
    targetChain,
    recipient,
    amount: depositNote.amount,
    proof: crossChainProof
  });
  console.log('Bridge TX:', tx.hash);

  // Wait for confirmation
  const receipt = await tx.wait();
  console.log('Bridge initiated in block:', receipt.blockNumber);

  // Get transfer ID from events
  const bridgeEvent = receipt.logs.find(
    log => log.topics[0] === pil.bridgeEventTopic
  );
  const transferId = bridgeEvent.topics[1];
  console.log('Transfer ID:', transferId);

  return {
    transferId,
    receipt
  };
}
```

## Step 7: Monitor Bridge Status

```typescript
async function monitorBridgeTransfer(
  pil: PILClient,
  transferId: string
) {
  console.log('\n=== Monitoring Bridge Transfer ===');
  console.log('Transfer ID:', transferId);

  // Poll for status updates
  let status = await pil.getBridgeStatus(transferId);
  console.log('Initial status:', status);

  while (status.state !== 'completed' && status.state !== 'failed') {
    await new Promise(resolve => setTimeout(resolve, 10000)); // 10 seconds
    status = await pil.getBridgeStatus(transferId);
    
    console.log(`Status: ${status.state}`);
    if (status.confirmations) {
      console.log(`  Confirmations: ${status.confirmations}/${status.requiredConfirmations}`);
    }
    if (status.estimatedCompletion) {
      console.log(`  ETA: ${new Date(status.estimatedCompletion).toISOString()}`);
    }
  }

  if (status.state === 'completed') {
    console.log('\n✅ Bridge transfer completed!');
    console.log('Destination TX:', status.destinationTx);
  } else {
    console.log('\n❌ Bridge transfer failed');
    console.log('Error:', status.error);
  }

  return status;
}
```

## Step 8: Complete Example

```typescript
// src/complete-example.ts
import { PILClient, ChainId } from '@pil/sdk';
import { ethers } from 'ethers';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  // Setup
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC);
  const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
  
  const pil = new PILClient({
    provider,
    signer,
    privacyPoolAddress: process.env.PIL_PRIVACY_POOL!,
    bridgeRouterAddress: process.env.PIL_BRIDGE_ROUTER!
  });

  const amount = ethers.parseEther('0.1');
  const recipient = '0x...'; // Target address

  try {
    // 1. Make private deposit
    console.log('Step 1: Creating private deposit...');
    const depositNote = await createPrivateDeposit(pil, amount);
    
    // 2. Generate withdrawal proof
    console.log('\nStep 2: Generating proof...');
    const proofData = await generateWithdrawalProof(pil, depositNote, recipient);
    
    // 3. Execute withdrawal
    console.log('\nStep 3: Executing withdrawal...');
    await executeWithdrawal(pil, proofData, recipient, amount);

    console.log('\n✅ Private transfer complete!');

  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

main();
```

## Step 9: Cross-Chain Example

```typescript
// src/cross-chain-example.ts
async function crossChainExample() {
  // Setup (same as above)
  const pil = new PILClient({ /* ... */ });

  const amount = ethers.parseEther('0.1');
  const polygonRecipient = '0x...';

  try {
    // 1. Make private deposit on Ethereum
    const depositNote = await createPrivateDeposit(pil, amount);
    
    // 2. Bridge to Polygon with privacy
    const { transferId } = await crossChainPrivateTransfer(
      pil,
      depositNote,
      ChainId.POLYGON,
      polygonRecipient
    );
    
    // 3. Monitor completion
    const status = await monitorBridgeTransfer(pil, transferId);

    if (status.state === 'completed') {
      console.log('\n✅ Cross-chain private transfer complete!');
      console.log('Funds available on Polygon at:', polygonRecipient);
    }

  } catch (error) {
    console.error('Error:', error);
  }
}
```

## Troubleshooting

### Common Issues

1. **Proof generation fails**
   - Ensure you have the correct circuit files
   - Check that the secret and amount match the original deposit

2. **Transaction reverts with "Invalid proof"**
   - Verify the merkle root hasn't changed
   - Ensure the nullifier hasn't been used

3. **Bridge transfer stuck**
   - Check source chain finality
   - Verify relayer is operational
   - Check destination chain gas prices

### Debug Mode

```typescript
const pil = new PILClient({
  // ...
  debug: true,
  logLevel: 'verbose'
});
```

## Next Steps

- [API Reference](./api/README.md) - Full API documentation
- [Bridge Integration](./BRIDGE_INTEGRATION.md) - Chain-specific guides
- [Security Best Practices](./SECURITY_AUDIT.md) - Security guidelines
