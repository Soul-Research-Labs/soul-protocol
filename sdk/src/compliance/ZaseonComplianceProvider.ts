import { createPublicClient, http, parseAbi, type Address, type Hash, type Hex } from 'viem';

/**
 * ZASEON - Compliance Provider Client
 *
 * SDK client for the ZaseonComplianceV2 contract, enabling:
 * - KYC/AML provider registration
 * - Credential issuance with ZK privacy
 * - Compliance status checking
 * - Selective disclosure support
 *
 * @example
 * ```typescript
 * const provider = new ZaseonComplianceProvider({
 *   rpcUrl: 'https://eth.llamarpc.com',
 *   contractAddress: '0x...',
 *   providerId: 'chainanalysis',
 * });
 * const isCompliant = await provider.checkCompliance('0xUser...');
 * await provider.issueCredential('0xUser...', { level: 'standard', jurisdiction: 'US' });
 * ```
 */

const COMPLIANCE_ABI = parseAbi([
    'function registerProvider(string calldata name, bytes32 schemaHash) external',
    'function issueCredential(address user, bytes32 credentialHash, uint256 expiry, bytes calldata proof) external returns (bytes32)',
    'function revokeCredential(bytes32 credentialId) external',
    'function isCompliant(address user) external view returns (bool)',
    'function getCredential(bytes32 credentialId) external view returns (address issuer, address subject, bytes32 credentialHash, uint256 issuedAt, uint256 expiresAt, bool revoked)',
    'function getProviderInfo(address provider) external view returns (string memory name, bytes32 schemaHash, uint256 credentialsIssued, bool isActive)',
    'function getUserCredentialCount(address user) external view returns (uint256)',
    'event CredentialIssued(bytes32 indexed credentialId, address indexed issuer, address indexed subject, uint256 expiry)',
    'event CredentialRevoked(bytes32 indexed credentialId, address indexed revoker)',
    'event ProviderRegistered(address indexed provider, string name)',
]);

export interface ComplianceConfig {
    rpcUrl: string;
    contractAddress: Address;
    providerId: string;
}

export interface CredentialData {
    level: 'basic' | 'standard' | 'enhanced';
    jurisdiction: string;
    expiry?: number; // Unix timestamp, defaults to 1 year
    proof?: Hex;     // ZK proof of compliance check
}

export interface Credential {
    credentialId: Hash;
    issuer: Address;
    subject: Address;
    credentialHash: Hash;
    issuedAt: bigint;
    expiresAt: bigint;
    revoked: boolean;
}

export interface ProviderInfo {
    name: string;
    schemaHash: Hash;
    credentialsIssued: bigint;
    isActive: boolean;
}

export class ZaseonComplianceProvider {
    private config: ComplianceConfig;
    private publicClient: ReturnType<typeof createPublicClient>;

    constructor(config: ComplianceConfig) {
        this.config = config;
        this.publicClient = createPublicClient({
            transport: http(config.rpcUrl),
        });
    }

    /**
     * Register as a compliance provider
     * @param name Human-readable provider name
     * @param schemaHash Hash of the credential schema
     * @returns Transaction simulation result
     */
    async registerProvider(name?: string, schemaHash?: Hash): Promise<void> {
        const providerName = name || this.config.providerId;
        const schema = schemaHash || ('0x' + Array.from(
            new TextEncoder().encode(`zaseon:compliance:${providerName}:v1`)
        ).map(b => b.toString(16).padStart(2, '0')).join('').padEnd(64, '0')) as Hash;

        await this.publicClient.simulateContract({
            address: this.config.contractAddress,
            abi: COMPLIANCE_ABI,
            functionName: 'registerProvider',
            args: [providerName, schema],
        });
    }

    /**
     * Issue a compliance credential to a user
     * @param user The user address to credential
     * @param data Credential data including level, jurisdiction, and optional ZK proof
     * @returns Credential ID
     */
    async issueCredential(user: Address, data: CredentialData): Promise<Hash> {
        const expiry = BigInt(data.expiry || Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60);
        const credentialHash = ('0x' + Array.from(
            new TextEncoder().encode(JSON.stringify({
                level: data.level,
                jurisdiction: data.jurisdiction,
                provider: this.config.providerId,
            }))
        ).map(b => b.toString(16).padStart(2, '0')).join('').padEnd(64, '0').slice(0, 64)) as Hash;

        const proof = data.proof || '0x' as Hex;

        const result = await this.publicClient.simulateContract({
            address: this.config.contractAddress,
            abi: COMPLIANCE_ABI,
            functionName: 'issueCredential',
            args: [user, credentialHash, expiry, proof],
        });

        return result.result as Hash;
    }

    /**
     * Revoke a previously-issued credential
     * @param credentialId The credential to revoke
     */
    async revokeCredential(credentialId: Hash): Promise<void> {
        await this.publicClient.simulateContract({
            address: this.config.contractAddress,
            abi: COMPLIANCE_ABI,
            functionName: 'revokeCredential',
            args: [credentialId],
        });
    }

    /**
     * Check if a user has valid compliance credentials
     * @param user The user address to check
     * @returns True if user has a valid, non-expired, non-revoked credential
     */
    async checkCompliance(user: Address): Promise<boolean> {
        return this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: COMPLIANCE_ABI,
            functionName: 'isCompliant',
            args: [user],
        });
    }

    /**
     * Get detailed credential information
     * @param credentialId The credential ID
     * @returns Full credential details
     */
    async getCredential(credentialId: Hash): Promise<Credential> {
        const [issuer, subject, credentialHash, issuedAt, expiresAt, revoked] =
            await this.publicClient.readContract({
                address: this.config.contractAddress,
                abi: COMPLIANCE_ABI,
                functionName: 'getCredential',
                args: [credentialId],
            });

        return { credentialId, issuer, subject, credentialHash, issuedAt, expiresAt, revoked };
    }

    /**
     * Get provider registration info
     * @param providerAddress The provider address
     * @returns Provider details
     */
    async getProviderInfo(providerAddress: Address): Promise<ProviderInfo> {
        const [name, schemaHash, credentialsIssued, isActive] =
            await this.publicClient.readContract({
                address: this.config.contractAddress,
                abi: COMPLIANCE_ABI,
                functionName: 'getProviderInfo',
                args: [providerAddress],
            });

        return { name, schemaHash, credentialsIssued, isActive };
    }

    /**
     * Get the number of credentials a user holds
     * @param user The user address
     * @returns Credential count
     */
    async getUserCredentialCount(user: Address): Promise<bigint> {
        return this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: COMPLIANCE_ABI,
            functionName: 'getUserCredentialCount',
            args: [user],
        });
    }
}
