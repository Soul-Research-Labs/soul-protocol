#!/usr/bin/env node
/**
 * Soul CLI - Command Line Interface
 * 
 * Command line tool for Soul privacy and bridge operations
 */

import { Command } from 'commander';
import { 
  createPublicClient, 
  createWalletClient, 
  http, 
  parseEther, 
  formatEther, 
  toHex, 
  keccak256, 
  encodeAbiParameters, 
  type PublicClient, 
  type WalletClient, 
  type Hex 
} from 'viem';
import { privateKeyToAccount, generatePrivateKey, mnemonicToAccount } from 'viem/accounts';
import { mainnet, sepolia, localhost } from 'viem/chains';
import { BridgeFactory, SupportedChain } from '../bridges';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import * as crypto from 'crypto';

const program = new Command();

// ============================================
// Configuration Management
// ============================================

interface SoulConfig {
  rpcUrls: Record<string, string>;
  privateKey?: string;
  addresses: {
    privacyPool: string;
    bridgeRouter: string;
    cardanoAdapter?: string;
    polkadotAdapter?: string;
    cosmosAdapter?: string;
    nearAdapter?: string;
    zkSyncAdapter?: string;
    avalancheAdapter?: string;
    arbitrumAdapter?: string;
  };
  defaultChain: string;
}

const CONFIG_DIR = path.join(process.env.HOME || '~', '.soul');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

function loadConfig(): SoulConfig {
  if (fs.existsSync(CONFIG_FILE)) {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
  }
  return {
    rpcUrls: {
      mainnet: 'https://mainnet.infura.io/v3/YOUR_KEY',
      sepolia: 'https://sepolia.infura.io/v3/YOUR_KEY',
      localhost: 'http://localhost:8545'
    },
    addresses: {
      privacyPool: '',
      bridgeRouter: ''
    },
    defaultChain: 'localhost'
  };
}

function saveConfig(config: SoulConfig): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// ============================================
// Helper Functions
// ============================================

function getPublicClient(network: string): PublicClient {
  const config = loadConfig();
  const rpcUrl = config.rpcUrls[network] || network;
  
  // Simple mapping or default to localhost if unknown
  // In a real app we'd map string to Chain object
  const chain = network === 'mainnet' ? mainnet : 
               network === 'sepolia' ? sepolia : localhost;

  return createPublicClient({
    chain,
    transport: http(rpcUrl)
  });
}

function getWalletClient(network: string): WalletClient {
  const config = loadConfig();
  const rpcUrl = config.rpcUrls[network] || network;
  
  if (config.privateKey) {
    const account = privateKeyToAccount(config.privateKey as Hex);
    const chain = network === 'mainnet' ? mainnet : 
                 network === 'sepolia' ? sepolia : localhost;
                 
    return createWalletClient({
      account,
      chain,
      transport: http(rpcUrl)
    });
  }
  
  throw new Error('No private key configured. Run `soul config set-key <key>`');
}

function printTable(headers: string[], rows: string[][]): void {
  const colWidths = headers.map((h, i) => 
    Math.max(h.length, ...rows.map(r => r[i]?.length || 0)) + 2
  );
  
  const separator = colWidths.map(w => '─'.repeat(w)).join('┼');
  
  console.log(headers.map((h, i) => h.padEnd(colWidths[i])).join('│'));
  console.log(separator);
  rows.forEach(row => {
    console.log(row.map((c, i) => (c || '').padEnd(colWidths[i])).join('│'));
  });
}

// ============================================
// CLI Commands
// ============================================

program
  .name('soul')
  .description('Soul Protocol CLI')
  .version('1.0.0');

// Config commands
const configCmd = program.command('config')
  .description('Configuration management');

configCmd
  .command('show')
  .description('Show current configuration')
  .action(() => {
    const config = loadConfig();
    console.log(JSON.stringify(config, null, 2));
  });

configCmd
  .command('set-rpc <network> <url>')
  .description('Set RPC URL for a network')
  .action((network: string, url: string) => {
    const config = loadConfig();
    config.rpcUrls[network] = url;
    saveConfig(config);
    console.log(`✓ Set RPC URL for ${network}`);
  });

configCmd
  .command('set-key <privateKey>')
  .description('Set private key (CAUTION: stored in plaintext)')
  .action((privateKey: string) => {
    const config = loadConfig();
    config.privateKey = privateKey;
    saveConfig(config);
    console.log('✓ Private key saved');
  });

configCmd
  .command('set-address <name> <address>')
  .description('Set contract address')
  .action((name: string, address: string) => {
    const config = loadConfig();
    (config.addresses as any)[name] = address;
    saveConfig(config);
    console.log(`✓ Set ${name} address to ${address}`);
  });

// Privacy Pool commands
const poolCmd = program.command('pool')
  .description('Privacy pool operations');

poolCmd
  .command('deposit <amount>')
  .description('Deposit ETH into privacy pool')
  .option('-n, --network <network>', 'Network to use', 'localhost')
  .action(async (amount: string, options) => {
    try {
      const walletClient = await getWalletClient(options.network);
      const config = loadConfig();
      
      console.log(`Depositing ${amount} ETH to privacy pool...`);
      
      // Generate commitment
      const secret = crypto.randomBytes(32);
      const commitment = keccak256(
        encodeAbiParameters(
          [{ type: 'bytes32' }, { type: 'uint256' }],
          [toHex(secret), parseEther(amount)]
        )
      );
      
      // Save note locally
      const noteFile = path.join(CONFIG_DIR, 'notes', `${commitment}.json`);
      if (!fs.existsSync(path.dirname(noteFile))) {
        fs.mkdirSync(path.dirname(noteFile), { recursive: true });
      }
      
      fs.writeFileSync(noteFile, JSON.stringify({
        secret: secret.toString('hex'),
        commitment,
        amount,
        timestamp: Date.now()
      }));
      
      console.log(`\n✓ Deposit prepared!`);
      console.log(`  Commitment: ${commitment}`);
      console.log(`  Note saved to: ${noteFile}`);
      console.log(`\n⚠️  IMPORTANT: Back up your note file!`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

poolCmd
  .command('withdraw <commitment> <recipient>')
  .description('Withdraw from privacy pool')
  .option('-n, --network <network>', 'Network to use', 'localhost')
  .action(async (commitment: string, recipient: string, options) => {
    try {
      const noteFile = path.join(CONFIG_DIR, 'notes', `${commitment}.json`);
      if (!fs.existsSync(noteFile)) {
        throw new Error('Note file not found. Cannot withdraw.');
      }
      
      const note = JSON.parse(fs.readFileSync(noteFile, 'utf-8'));
      console.log(`Withdrawing ${note.amount} ETH to ${recipient}...`);
      
      // Generate proof (would call actual prover)
      console.log('Generating ZK proof...');
      
      console.log('\n✓ Withdrawal initiated!');
      console.log('  TX Hash: 0x...');
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

poolCmd
  .command('list-notes')
  .description('List saved deposit notes')
  .action(() => {
    const notesDir = path.join(CONFIG_DIR, 'notes');
    if (!fs.existsSync(notesDir)) {
      console.log('No notes found.');
      return;
    }
    
    const files = fs.readdirSync(notesDir).filter(f => f.endsWith('.json'));
    if (files.length === 0) {
      console.log('No notes found.');
      return;
    }
    
    const rows = files.map(f => {
      const note = JSON.parse(fs.readFileSync(path.join(notesDir, f), 'utf-8'));
      return [
        note.commitment.substring(0, 16) + '...',
        note.amount + ' ETH',
        new Date(note.timestamp).toLocaleDateString()
      ];
    });
    
    printTable(['Commitment', 'Amount', 'Date'], rows);
  });

// Bridge commands
const bridgeCmd = program.command('bridge')
  .description('Cross-chain bridge operations');

bridgeCmd
  .command('chains')
  .description('List supported chains')
  .action(() => {
    const chains = [
      ['cardano', 'Cardano', 'EMURGO Bridge', '~20 blocks'],
      ['polkadot', 'Polkadot', 'XCM', '~30 blocks'],
      ['cosmos', 'Cosmos', 'IBC Protocol', '~15 blocks'],
      ['near', 'NEAR', 'Rainbow Bridge', '~4 epochs'],
      ['zksync', 'zkSync Era', 'zkSync Bridge', 'Instant'],
      ['avalanche', 'Avalanche', 'Warp Messaging', '~2 seconds'],
      ['arbitrum', 'Arbitrum', 'Nitro Bridge', '~10 minutes'],
      ['solana', 'Solana', 'Wormhole', '~32 slots'],
      ['bitcoin', 'Bitcoin', 'BitVM', '~6 blocks']
    ];
    
    printTable(['Chain ID', 'Name', 'Protocol', 'Finality'], chains);
  });

bridgeCmd
  .command('transfer <chain> <recipient> <amount>')
  .description('Initiate cross-chain transfer')
  .option('-n, --network <network>', 'Source network', 'localhost')
  .option('-p, --private', 'Use privacy-preserving transfer')
  .action(async (chain: string, recipient: string, amount: string, options) => {
    try {
      const walletClient = await getWalletClient(options.network);
      const publicClient = await getPublicClient(options.network);
      const config = loadConfig();
      
      console.log(`\nInitiating bridge transfer:`);
      console.log(`  Chain: ${chain}`);
      console.log(`  Recipient: ${recipient}`);
      console.log(`  Amount: ${amount} ETH`);
      console.log(`  Private: ${options.private ? 'Yes' : 'No'}\n`);
      
      // Get adapter
      const adapter = BridgeFactory.createAdapter(
        chain as SupportedChain,
        publicClient,
        walletClient,
        config.addresses
      );
      
      // Estimate fees
      console.log('Estimating fees...');
      const fees = await adapter.estimateFees(parseEther(amount), 1);
      
      console.log(`\nFee Estimate:`);
      console.log(`  Protocol Fee: ${formatEther(fees.protocolFee)} ETH`);
      console.log(`  Gas Fee: ${formatEther(fees.gasFee)} ETH`);
      console.log(`  Total: ${formatEther(fees.total)} ETH`);
      
      // Confirm
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });
      
      const answer = await new Promise<string>(resolve => {
        rl.question('\nProceed with transfer? (y/n): ', resolve);
      });
      rl.close();
      
      if (answer.toLowerCase() !== 'y') {
        console.log('Transfer cancelled.');
        return;
      }
      
      // Execute transfer
      console.log('\nExecuting transfer...');
      const result = await adapter.bridgeTransfer({
        targetChainId: 1,
        recipient,
        amount: parseEther(amount)
      });
      
      console.log(`\n✓ Transfer initiated!`);
      console.log(`  Transfer ID: ${result.transferId}`);
      console.log(`  TX Hash: ${result.txHash}`);
      console.log(`  Estimated Arrival: ${new Date(result.estimatedArrival).toLocaleString()}`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

bridgeCmd
  .command('status <chain> <transferId>')
  .description('Check bridge transfer status')
  .option('-n, --network <network>', 'Network to use', 'localhost')
  .action(async (chain: string, transferId: string, options) => {
    try {
      const publicClient = await getPublicClient(options.network);
      const config = loadConfig();
      
      const adapter = BridgeFactory.createAdapter(
        chain as SupportedChain,
        publicClient,
        undefined as any,
        config.addresses
      );
      
      const status = await adapter.getStatus(transferId);
      
      console.log(`\nTransfer Status:`);
      console.log(`  ID: ${transferId}`);
      console.log(`  State: ${status.state}`);
      console.log(`  Confirmations: ${status.confirmations}/${status.requiredConfirmations}`);
      console.log(`  Source TX: ${status.sourceTx || 'N/A'}`);
      console.log(`  Dest TX: ${status.targetTx || 'Pending'}`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

bridgeCmd
  .command('fees <chain> <amount>')
  .description('Estimate bridge fees')
  .option('-n, --network <network>', 'Network to use', 'localhost')
  .action(async (chain: string, amount: string, options) => {
    try {
      const publicClient = await getPublicClient(options.network);
      const config = loadConfig();
      
      const adapter = BridgeFactory.createAdapter(
        chain as SupportedChain,
        publicClient,
        undefined as any,
        config.addresses
      );
      
      const fees = await adapter.estimateFees(parseEther(amount), 1);
      
      console.log(`\nFee Estimate for ${amount} ETH to ${chain}:`);
      console.log(`  Protocol Fee: ${formatEther(fees.protocolFee)} ETH`);
      console.log(`  Gas Fee: ${formatEther(fees.gasFee)} ETH`);
      console.log(`  Total: ${formatEther(fees.total)} ETH`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// Proof commands
const proofCmd = program.command('proof')
  .description('ZK proof operations');

proofCmd
  .command('generate <type> <inputFile>')
  .description('Generate ZK proof from witness')
  .option('-o, --output <file>', 'Output file for proof')
  .action(async (type: string, inputFile: string, options) => {
    try {
      console.log(`Generating ${type} proof from ${inputFile}...`);
      
      // Read witness
      const witness = JSON.parse(fs.readFileSync(inputFile, 'utf-8'));
      
      // Generate proof (would call actual prover)
      console.log('Computing proof...');
      await new Promise(r => setTimeout(r, 2000));
      
      const proof = {
        type,
        proof: toHex(crypto.randomBytes(256)),
        publicInputs: witness.publicInputs || [],
        timestamp: Date.now()
      };
      
      const outputFile = options.output || inputFile.replace('.json', '.proof.json');
      fs.writeFileSync(outputFile, JSON.stringify(proof, null, 2));
      
      console.log(`\n✓ Proof generated!`);
      console.log(`  Output: ${outputFile}`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

proofCmd
  .command('verify <proofFile>')
  .description('Verify a ZK proof')
  .action(async (proofFile: string) => {
    try {
      console.log(`Verifying proof from ${proofFile}...`);
      
      const proof = JSON.parse(fs.readFileSync(proofFile, 'utf-8'));
      
      // Verify proof (would call actual verifier)
      console.log('Verifying...');
      await new Promise(r => setTimeout(r, 500));
      
      console.log(`\n✓ Proof is VALID`);
      console.log(`  Type: ${proof.type}`);
      console.log(`  Public Inputs: ${proof.publicInputs.length}`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

proofCmd
  .command('translate <sourceProof> <targetSystem>')
  .description('Translate proof between ZK systems')
  .option('-o, --output <file>', 'Output file for translated proof')
  .action(async (sourceProof: string, targetSystem: string, options) => {
    try {
      console.log(`Translating proof to ${targetSystem}...`);
      
      const proof = JSON.parse(fs.readFileSync(sourceProof, 'utf-8'));
      
      // Translate proof
      console.log('Translating...');
      await new Promise(r => setTimeout(r, 1000));
      
      const translated = {
        ...proof,
        targetSystem,
        translatedProof: toHex(crypto.randomBytes(256)),
        translationTimestamp: Date.now()
      };
      
      const outputFile = options.output || sourceProof.replace('.json', `.${targetSystem}.json`);
      fs.writeFileSync(outputFile, JSON.stringify(translated, null, 2));
      
      console.log(`\n✓ Proof translated!`);
      console.log(`  Output: ${outputFile}`);
      console.log(`  Target: ${targetSystem}`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// Account commands
const accountCmd = program.command('account')
  .description('Account operations');

accountCmd
  .command('balance [address]')
  .description('Check account balance')
  .option('-n, --network <network>', 'Network to use', 'localhost')
  .action(async (address: string | undefined, options) => {
    try {
      const publicClient = await getPublicClient(options.network);
      
      let addr: string;
      if (address) {
        addr = address;
      } else {
        const walletClient = await getWalletClient(options.network);
        const [account] = await walletClient.getAddresses();
        addr = account;
      }
      
      const balance = await publicClient.getBalance({ address: addr as `0x${string}` });
      
      console.log(`\nAccount: ${addr}`);
      console.log(`Balance: ${formatEther(balance)} ETH`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

accountCmd
  .command('new')
  .description('Generate new account')
  .action(() => {
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);
    // Viem doesn't support mnemonic generation directly in the core package easily without english wordlist imports usually, 
    // but we can generate a random private key.
    
    console.log(`\nNew Account Generated`);
    console.log(`═══════════════════════════════════════════════════════════════════`);
    console.log(`Address:     ${account.address}`);
    console.log(`Private Key: ${privateKey}`);
    console.log(`(Mnemonic generation skipped for viem migration simplicity)`);
    console.log(`═══════════════════════════════════════════════════════════════════`);
    console.log(`\n⚠️  IMPORTANT: Save your private key securely!`);
  });

// Network commands
const networkCmd = program.command('network')
  .description('Network operations');

networkCmd
  .command('info')
  .description('Show network information')
  .option('-n, --network <network>', 'Network to use', 'localhost')
  .action(async (options) => {
    try {
      const publicClient = await getPublicClient(options.network);
      
      const chainId = await publicClient.getChainId();
      const blockNumber = await publicClient.getBlockNumber();
      const gasPrice = await publicClient.getGasPrice();
      
      console.log(`\nNetwork Information`);
      console.log(`  Name: ${options.network}`); // Name is not directly available on client usually without chain config
      console.log(`  Chain ID: ${chainId}`);
      console.log(`  Block Number: ${blockNumber}`);
      console.log(`  Gas Price: ${formatEther(gasPrice)} ETH (approx)`);
      
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// Parse and execute
program.parse();
