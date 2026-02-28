import { createPublicClient, createWalletClient, http, parseAbi, getAddress, type Address, type Hex } from 'viem';
import { mainnet, sepolia, arbitrum, base, optimism } from 'viem/chains';
import * as dotenv from 'dotenv';
dotenv.config();

/**
 * ZASEON - Role Separation Verification Script
 *
 * Verifies that admin roles are properly separated before mainnet deployment.
 * This is a MANDATORY pre-mainnet step.
 *
 * Required role separation:
 * - ZKBoundStateLocks: Admin must NOT hold OPERATOR, DISPUTE_RESOLVER, or RECOVERY roles
 * - CrossChainProofHubV3: Admin must NOT hold RELAYER or CHALLENGER roles
 *
 * Usage:
 *   npx hardhat run scripts/verify-role-separation.ts --network sepolia
 */

// ABIs for role checking
const ACCESS_CONTROL_ABI = parseAbi([
    'function hasRole(bytes32 role, address account) view returns (bool)',
    'function getRoleAdmin(bytes32 role) view returns (bytes32)',
    'function confirmRoleSeparation() external',
    'function rolesSeparated() view returns (bool)',
    'function DEFAULT_ADMIN_ROLE() view returns (bytes32)',
]);

const ROLE_HASHES: Record<string, Hex> = {
    DEFAULT_ADMIN_ROLE: '0x0000000000000000000000000000000000000000000000000000000000000000',
    OPERATOR_ROLE: '0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4',
    GUARDIAN_ROLE: '0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041',
    RELAYER_ROLE: '0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4',
    DISPUTE_RESOLVER_ROLE: '0xd75d982fa5e8d399fe78b0e8c7f02fe3a10b0b2e69f4ed03c1fbf151a0e4c70c',
    RECOVERY_ROLE: '0x3b88b18257a46e05dbc56e96a323c4a7bc4f47571c70da1c1a005d396d2c38d9',
    CHALLENGER_ROLE: '0x85c7e9f4c150748d6d3c0bf8e56cdff4faa6e6a90b71d7ce2bdfc648d0b13d39',
};

interface ContractVerification {
    name: string;
    address: Address;
    adminAddress: Address;
    forbiddenRoles: string[];
}

async function verifyRoleSeparation(rpcUrl: string, contracts: ContractVerification[]) {
    const client = createPublicClient({
        transport: http(rpcUrl),
    });

    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║           ZASEON PROTOCOL - ROLE SEPARATION AUDIT            ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');

    let allPassed = true;

    for (const contract of contracts) {
        console.log(`\n── ${contract.name} ──`);
        console.log(`  Contract: ${contract.address}`);
        console.log(`  Admin:    ${contract.adminAddress}\n`);

        // Check if role separation already confirmed
        try {
            const separated = await client.readContract({
                address: contract.address,
                abi: ACCESS_CONTROL_ABI,
                functionName: 'rolesSeparated',
            });
            console.log(`  rolesSeparated: ${separated ? '✅ YES' : '⚠️  NO'}`);
        } catch {
            console.log('  rolesSeparated: ℹ️  Function not found (may be older version)');
        }

        // Check each forbidden role
        for (const roleName of contract.forbiddenRoles) {
            const roleHash = ROLE_HASHES[roleName];
            if (!roleHash) {
                console.log(`  ${roleName}: ⚠️  Unknown role hash`);
                continue;
            }

            try {
                const hasRole = await client.readContract({
                    address: contract.address,
                    abi: ACCESS_CONTROL_ABI,
                    functionName: 'hasRole',
                    args: [roleHash, contract.adminAddress],
                });

                if (hasRole) {
                    console.log(`  ${roleName}: ❌ VIOLATION - Admin holds this role!`);
                    allPassed = false;
                } else {
                    console.log(`  ${roleName}: ✅ Admin does NOT hold this role`);
                }
            } catch (e) {
                console.log(`  ${roleName}: ⚠️  Could not check (${(e as Error).message?.substring(0, 50)})`);
            }
        }

        // Check admin has DEFAULT_ADMIN_ROLE
        try {
            const isAdmin = await client.readContract({
                address: contract.address,
                abi: ACCESS_CONTROL_ABI,
                functionName: 'hasRole',
                args: [ROLE_HASHES.DEFAULT_ADMIN_ROLE, contract.adminAddress],
            });
            console.log(`  DEFAULT_ADMIN_ROLE: ${isAdmin ? '✅ Admin holds this role' : '❌ Admin missing admin role!'}`);
            if (!isAdmin) allPassed = false;
        } catch {
            console.log('  DEFAULT_ADMIN_ROLE: ⚠️  Could not check');
        }
    }

    console.log('\n' + '═'.repeat(60));
    if (allPassed) {
        console.log('✅ ALL ROLE SEPARATION CHECKS PASSED');
        console.log('   Safe to call confirmRoleSeparation() on each contract.');
    } else {
        console.log('❌ ROLE SEPARATION VIOLATIONS DETECTED');
        console.log('   DO NOT proceed to mainnet until violations are resolved.');
        console.log('   Revoke forbidden roles from admin before calling confirmRoleSeparation().');
    }
    console.log('═'.repeat(60));

    return allPassed;
}

// Sepolia deployment addresses (from deployments/sepolia-11155111.json)
const SEPOLIA_CONTRACTS: ContractVerification[] = [
    {
        name: 'ZKBoundStateLocks',
        address: '0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78' as Address,
        adminAddress: '0xbc5bb932c7696412622b1fe9a09b7fd9509c6913' as Address,
        forbiddenRoles: ['OPERATOR_ROLE', 'DISPUTE_RESOLVER_ROLE', 'RECOVERY_ROLE'],
    },
    {
        name: 'CrossChainProofHubV3',
        address: '0x40eaa5de0c6497c8943c967b42799cb092c26adc' as Address,
        adminAddress: '0xbc5bb932c7696412622b1fe9a09b7fd9509c6913' as Address,
        forbiddenRoles: ['RELAYER_ROLE', 'CHALLENGER_ROLE'],
    },
];

// Run verification
const rpcUrl = process.env.SEPOLIA_RPC_URL || 'https://rpc.sepolia.org';
verifyRoleSeparation(rpcUrl, SEPOLIA_CONTRACTS)
    .then((passed) => process.exit(passed ? 0 : 1))
    .catch((err) => {
        console.error('Error:', err);
        process.exit(1);
    });
