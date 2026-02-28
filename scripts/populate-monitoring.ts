import * as fs from 'fs';
import * as path from 'path';

/**
 * ZASEON - Monitoring Address Populator
 *
 * After deployment, run this script to populate contract addresses
 * into Tenderly and Defender monitoring configurations.
 *
 * Usage:
 *   npx ts-node scripts/populate-monitoring.ts --network mainnet
 *   npx ts-node scripts/populate-monitoring.ts --network sepolia
 */

interface DeploymentInfo {
    [key: string]: string; // contract name -> address
}

function loadDeployments(network: string): DeploymentInfo {
    const patterns = [
        `deployments/${network}.json`,
        `deployments/${network}-${network === 'sepolia' ? '11155111' : '1'}.json`,
        `deployments/localhost-31337.json`,
    ];

    for (const pattern of patterns) {
        const filePath = path.join(process.cwd(), pattern);
        if (fs.existsSync(filePath)) {
            const raw = fs.readFileSync(filePath, 'utf8');
            const data = JSON.parse(raw);
            // Handle both { contractName: address } and { contracts: { name: { address } } } formats
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

    console.log('No deployment file found. Using empty addresses.');
    return {};
}

function populateDefenderConfig(deployments: DeploymentInfo, network: string): void {
    const configPath = path.join(process.cwd(), 'monitoring', 'defender.config.json');
    if (!fs.existsSync(configPath)) {
        console.log('defender.config.json not found, skipping.');
        return;
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // Map contract names to addresses
    const contractMapping: Record<string, string[]> = {
        'ZKBoundStateLocks': ['ZKBoundStateLocks'],
        'CrossChainProofHub': ['CrossChainProofHubV3'],
        'NullifierRegistry': ['NullifierRegistryV3'],
        'ConfidentialState': ['ConfidentialStateContainerV3'],
        'AtomicSwap': ['ZaseonAtomicSwapV2'],
        'Compliance': ['ZaseonComplianceV2'],
    };

    let addressesPopulated = 0;

    // Populate monitors with addresses
    if (config.monitors) {
        for (const monitor of config.monitors) {
            if (monitor.addresses && monitor.addresses.length === 0) {
                // Auto-populate based on monitor name
                const allAddresses: string[] = [];
                for (const [key, contractNames] of Object.entries(contractMapping)) {
                    if (monitor.name?.toLowerCase().includes(key.toLowerCase())) {
                        for (const name of contractNames) {
                            if (deployments[name]) {
                                allAddresses.push(deployments[name]);
                            }
                        }
                    }
                }

                // If no specific match, add all deployed addresses for critical monitors
                if (allAddresses.length === 0 && monitor.severity === 'critical') {
                    allAddresses.push(...Object.values(deployments));
                }

                if (allAddresses.length > 0) {
                    monitor.addresses = allAddresses;
                    addressesPopulated += allAddresses.length;
                }
            }
        }
    }

    // Update network
    if (config.network) {
        config.network = network;
    }

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    console.log(`✅ Defender config updated: ${addressesPopulated} addresses populated`);
}

function populateTenderlyConfig(deployments: DeploymentInfo, network: string): void {
    const configPath = path.join(process.cwd(), 'monitoring', 'tenderly.config.json');
    if (!fs.existsSync(configPath)) {
        console.log('tenderly.config.json not found, skipping.');
        return;
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    let addressesPopulated = 0;

    // Populate contracts arrays in alert targets
    if (config.alerts) {
        for (const alert of config.alerts) {
            if (alert.contracts && alert.contracts.length === 0) {
                const contracts = Object.entries(deployments).map(([name, address]) => ({
                    name,
                    address,
                    network: network === 'mainnet' ? 1 : network === 'sepolia' ? 11155111 : 31337,
                }));
                alert.contracts = contracts;
                addressesPopulated += contracts.length;
            }
        }
    }

    // Update project network
    if (config.project) {
        config.project.network = network;
    }

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    console.log(`✅ Tenderly config updated: ${addressesPopulated} addresses populated`);
}

function generateAlertChannels(network: string): void {
    const channelsPath = path.join(process.cwd(), 'monitoring', 'alert-channels.json');
    
    const channels = {
        network,
        generated: new Date().toISOString(),
        channels: {
            critical: {
                pagerduty: {
                    routingKey: process.env.PAGERDUTY_ROUTING_KEY || 'TODO: Set PAGERDUTY_ROUTING_KEY',
                    severity: 'critical',
                    responseTime: '< 5 minutes',
                },
                telegram: {
                    chatId: process.env.TELEGRAM_CHAT_ID || 'TODO: Set TELEGRAM_CHAT_ID',
                    botToken: process.env.TELEGRAM_BOT_TOKEN || 'TODO: Set TELEGRAM_BOT_TOKEN',
                },
                slack: {
                    webhookUrl: process.env.SLACK_CRITICAL_WEBHOOK || 'TODO: Set SLACK_CRITICAL_WEBHOOK',
                    channel: '#zaseon-critical-alerts',
                },
            },
            high: {
                slack: {
                    webhookUrl: process.env.SLACK_HIGH_WEBHOOK || 'TODO: Set SLACK_HIGH_WEBHOOK',
                    channel: '#zaseon-high-alerts',
                },
                email: process.env.ALERT_EMAIL || 'security@zaseonprotocol.io',
            },
            medium: {
                slack: {
                    webhookUrl: process.env.SLACK_MEDIUM_WEBHOOK || 'TODO: Set SLACK_MEDIUM_WEBHOOK',
                    channel: '#zaseon-monitoring',
                },
            },
            low: {
                slack: {
                    webhookUrl: process.env.SLACK_LOW_WEBHOOK || 'TODO: Set SLACK_LOW_WEBHOOK',
                    channel: '#zaseon-monitoring',
                },
            },
        },
        thresholds: {
            largeTransfer: '1000000000000000000000', // 1000 ETH in wei
            failedProofRate: 5,                      // per hour
            circuitBreakerTrigger: 10,               // events per hour
            gasPrice: '100000000000',                // 100 gwei
        },
    };

    fs.writeFileSync(channelsPath, JSON.stringify(channels, null, 2));
    console.log(`✅ Alert channels config written to ${channelsPath}`);
}

// Main
const network = process.argv.includes('--network')
    ? process.argv[process.argv.indexOf('--network') + 1]
    : 'sepolia';

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║      ZASEON PROTOCOL - MONITORING CONFIG POPULATOR           ║');
console.log('╚══════════════════════════════════════════════════════════════╝\n');
console.log(`Network: ${network}\n`);

const deployments = loadDeployments(network);
console.log(`Loaded ${Object.keys(deployments).length} deployed contract addresses\n`);

populateDefenderConfig(deployments, network);
populateTenderlyConfig(deployments, network);
generateAlertChannels(network);

console.log('\n✅ Monitoring configuration complete.');
console.log('Next steps:');
console.log('  1. Set notification environment variables (PAGERDUTY_ROUTING_KEY, etc.)');
console.log('  2. Deploy Defender monitors: npx defender-client deploy');
console.log('  3. Import Tenderly config: tenderly push');
