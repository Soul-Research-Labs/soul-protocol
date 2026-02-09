import * as fs from 'fs';
import * as path from 'path';

/**
 * Soul Protocol - Post-Deploy SDK Address Populator
 *
 * Reads deployed contract addresses from `deployments/<network>.json`
 * and generates an updated `sdk/src/config/mainnet-addresses.ts`.
 *
 * Usage:
 *   npx ts-node scripts/deploy/populate-sdk-addresses.ts --network mainnet
 *   npx ts-node scripts/deploy/populate-sdk-addresses.ts --network sepolia --dry-run
 *   npx ts-node scripts/deploy/populate-sdk-addresses.ts --network mainnet --network arbitrum --network base --network optimism
 *
 * Flags:
 *   --network <name>    Network(s) to populate (mainnet, arbitrum, base, optimism, sepolia)
 *   --dry-run           Print output to stdout instead of writing file
 *   --verify            Run verifyAddressesConfigured() after populating
 */

interface DeploymentInfo {
    [key: string]: string;
}

// Mapping from deployment JSON keys to SDK address keys
const FIELD_MAPPING: Record<string, string> = {
    zkBoundStateLocks: 'zkBoundStateLocks',
    zkSLockIntegration: 'zkBoundStateLocks',
    nullifierRegistry: 'nullifierRegistry',
    proofHub: 'proofHub',
    atomicSwap: 'atomicSwap',
    proofCarryingContainer: 'proofCarryingContainer',
    policyBoundProofs: 'policyBoundProofs',
    easc: 'executionAgnosticStateCommitments',
    cdna: 'crossDomainNullifierAlgebra',
    crossDomainNullifierAlgebra: 'crossDomainNullifierAlgebra',
    groth16Verifier: 'groth16Verifier',
    verifier: 'groth16Verifier',
    plonkVerifier: 'plonkVerifier',
    friVerifier: 'friVerifier',
    emergencyRecovery: 'emergencyRecovery',
    teeAttestation: 'teeAttestation',
    timelock: 'timelock',
    multisig: 'multisig',
};

// Network name to chain ID
const CHAIN_IDS: Record<string, number> = {
    mainnet: 1,
    arbitrum: 42161,
    base: 8453,
    optimism: 10,
    sepolia: 11155111,
};

// Network name to SDK constant name
const SDK_CONST_NAMES: Record<string, string> = {
    mainnet: 'MAINNET_ADDRESSES',
    arbitrum: 'ARBITRUM_ADDRESSES',
    base: 'BASE_ADDRESSES',
    optimism: 'OPTIMISM_ADDRESSES',
};

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

function loadDeployments(network: string): DeploymentInfo {
    const chainId = CHAIN_IDS[network];
    const patterns = [
        `deployments/${network}.json`,
        `deployments/${network}-${chainId}.json`,
        `deployments/undefined-${chainId}.json`,
    ];

    for (const pattern of patterns) {
        const filePath = path.join(process.cwd(), pattern);
        if (fs.existsSync(filePath)) {
            console.log(`  Loading: ${pattern}`);
            const raw = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(raw);
            if (data.contracts) {
                const result: DeploymentInfo = {};
                for (const [name, info] of Object.entries(data.contracts)) {
                    result[name] = typeof info === 'string' ? info : (info as any).address;
                }
                return result;
            }
            return data;
        }
    }

    console.log(`  No deployment file found for ${network}`);
    return {};
}

function mapDeploymentToSDK(deployment: DeploymentInfo): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [deployKey, address] of Object.entries(deployment)) {
        const sdkKey = FIELD_MAPPING[deployKey];
        if (sdkKey && address && address !== ZERO_ADDRESS) {
            result[sdkKey] = address;
        }
    }
    return result;
}

const SDK_FIELDS = [
    'zkBoundStateLocks',
    'nullifierRegistry',
    'proofHub',
    'atomicSwap',
    'proofCarryingContainer',
    'policyBoundProofs',
    'executionAgnosticStateCommitments',
    'crossDomainNullifierAlgebra',
    'groth16Verifier',
    'plonkVerifier',
    'friVerifier',
    'emergencyRecovery',
    'teeAttestation',
    'timelock',
    'multisig',
];

function generateAddressBlock(
    constName: string,
    addresses: Record<string, string>,
    useConst: boolean = false
): string {
    const lines = SDK_FIELDS.map((field) => {
        const addr = addresses[field] || ZERO_ADDRESS;
        const value = addr === ZERO_ADDRESS && useConst ? 'ZERO_ADDRESS' : `'${addr}'`;
        return `  ${field}: ${value},`;
    });

    return `export const ${constName} = {\n${lines.join('\n')}\n};`;
}

function main() {
    const args = process.argv.slice(2);
    const networks: string[] = [];
    let dryRun = false;
    let verify = false;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--network' && args[i + 1]) {
            networks.push(args[++i]);
        } else if (args[i] === '--dry-run') {
            dryRun = true;
        } else if (args[i] === '--verify') {
            verify = true;
        }
    }

    if (networks.length === 0) {
        console.error('Usage: npx ts-node scripts/deploy/populate-sdk-addresses.ts --network <name>');
        console.error('Networks: mainnet, arbitrum, base, optimism, sepolia');
        process.exit(1);
    }

    console.log('=== Soul Protocol SDK Address Populator ===\n');

    // Load all network deployments
    const networkAddresses: Record<string, Record<string, string>> = {};
    for (const network of networks) {
        console.log(`Loading ${network} deployment...`);
        const deployment = loadDeployments(network);
        const mapped = mapDeploymentToSDK(deployment);
        networkAddresses[network] = mapped;

        const populated = Object.keys(mapped).length;
        const total = SDK_FIELDS.length;
        console.log(`  Mapped ${populated}/${total} addresses\n`);
    }

    // Generate output
    const header = `/**
 * Soul Protocol - Mainnet Address Configuration
 *
 * Auto-generated by scripts/deploy/populate-sdk-addresses.ts
 * Last updated: ${new Date().toISOString()}
 *
 * DO NOT EDIT MANUALLY — re-run the populate script after deployment.
 */

`;

    const zeroConst = `const ZERO_ADDRESS = '${ZERO_ADDRESS}';\n\n`;

    const blocks: string[] = [];
    for (const [constName, sdkConst] of Object.entries(SDK_CONST_NAMES)) {
        const addresses = networkAddresses[constName] || {};
        const isMainnet = constName === 'mainnet';
        blocks.push(generateAddressBlock(sdkConst, addresses, !isMainnet));
    }

    const chainMapping = `
// Chain ID to addresses mapping
export const CHAIN_ADDRESSES: Record<number, typeof MAINNET_ADDRESSES> = {
  1: MAINNET_ADDRESSES,
  42161: ARBITRUM_ADDRESSES,
  8453: BASE_ADDRESSES,
  10: OPTIMISM_ADDRESSES,
};

/**
 * Get addresses for a specific chain
 */
export function getAddressesForChain(chainId: number): typeof MAINNET_ADDRESSES | null {
  return CHAIN_ADDRESSES[chainId] ?? null;
}

/**
 * Verify all addresses are set (not zero address)
 */
export function verifyAddressesConfigured(
  addresses: typeof MAINNET_ADDRESSES
): { valid: boolean; missing: string[] } {
  const zeroAddress = '${ZERO_ADDRESS}';
  const missing: string[] = [];
  
  for (const [key, value] of Object.entries(addresses)) {
    if (value === zeroAddress) {
      missing.push(key);
    }
  }
  
  return {
    valid: missing.length === 0,
    missing,
  };
}
`;

    const output = header + zeroConst + blocks.join('\n\n') + '\n' + chainMapping;

    if (dryRun) {
        console.log('=== DRY RUN OUTPUT ===\n');
        console.log(output);
    } else {
        const outPath = path.join(process.cwd(), 'sdk', 'src', 'config', 'mainnet-addresses.ts');
        fs.writeFileSync(outPath, output, 'utf8');
        console.log(`Written to: ${outPath}`);
    }

    if (verify) {
        console.log('\n=== Address Verification ===');
        for (const [network, addresses] of Object.entries(networkAddresses)) {
            const fullAddresses: Record<string, string> = {};
            for (const field of SDK_FIELDS) {
                fullAddresses[field] = addresses[field] || ZERO_ADDRESS;
            }
            const populated = Object.values(fullAddresses).filter(
                (a) => a !== ZERO_ADDRESS
            ).length;
            const missing = Object.entries(fullAddresses)
                .filter(([, a]) => a === ZERO_ADDRESS)
                .map(([k]) => k);

            console.log(`\n${network}: ${populated}/${SDK_FIELDS.length} configured`);
            if (missing.length > 0) {
                console.log(`  Missing: ${missing.join(', ')}`);
            }
        }
    }

    console.log('\nDone.');
}

main();
