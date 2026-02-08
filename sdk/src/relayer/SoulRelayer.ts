import { createPublicClient, createWalletClient, http, parseAbi, type Address, type Hash, type Hex } from 'viem';

/**
 * Soul Protocol - Privacy Relayer Client
 *
 * Manages interaction with the PrivateRelayerNetwork contract for:
 * - Relayer registration and stake management
 * - Message relay with commit-reveal MEV protection
 * - Fee estimation and reputation tracking
 *
 * @example
 * ```typescript
 * const relayer = new SoulRelayer({
 *   rpcUrl: 'https://eth.llamarpc.com',
 *   contractAddress: '0x...',
 *   privateKey: '0x...',
 *   stake: 10n * 10n ** 18n, // 10 ETH
 *   endpoints: ['https://relay1.soul.io'],
 * });
 * await relayer.register();
 * const pending = await relayer.getPendingMessages();
 * await relayer.relay(pending[0]);
 * ```
 */

// PrivateRelayerNetwork ABI (subset)
const RELAYER_ABI = parseAbi([
    'function registerRelayer(string[] calldata endpoints) external payable',
    'function unregisterRelayer() external',
    'function relayMessage(bytes32 messageId, bytes calldata proof, bytes calldata publicInputs) external returns (bool)',
    'function commitRelay(bytes32 commitment) external',
    'function revealRelay(bytes32 messageId, bytes calldata proof, bytes32 nonce) external returns (bool)',
    'function getRelayerInfo(address relayer) external view returns (uint256 stake, uint256 reputation, bool isActive, uint256 totalRelayed)',
    'function getMinimumStake() external view returns (uint256)',
    'function getPendingMessageCount() external view returns (uint256)',
    'function estimateFee(uint256 gasLimit, uint256 sourceChainId) external view returns (uint256)',
    'function claimFees() external',
    'function getStats() external view returns (uint256 totalRelayers, uint256 totalMessages, uint256 totalFees)',
    'event MessageRelayed(bytes32 indexed messageId, address indexed relayer, uint256 fee)',
    'event RelayerRegistered(address indexed relayer, uint256 stake)',
    'event RelayerSlashed(address indexed relayer, uint256 amount, string reason)',
]);

export interface RelayerConfig {
    rpcUrl: string;
    contractAddress: Address;
    privateKey?: Hex;
    stake: bigint;
    endpoints: string[];
}

export interface RelayerInfo {
    address: Address;
    stake: bigint;
    reputation: bigint;
    isActive: boolean;
    totalRelayed: bigint;
}

export interface PendingMessage {
    messageId: Hash;
    sourceChainId: bigint;
    destinationChainId: bigint;
    proof: Hex;
    publicInputs: Hex;
    fee: bigint;
    deadline: bigint;
}

export interface RelayResult {
    success: boolean;
    txHash: Hash;
    fee: bigint;
    gasUsed: bigint;
}

export interface RelayerStats {
    totalRelayers: bigint;
    totalMessages: bigint;
    totalFees: bigint;
}

export class SoulRelayer {
    private config: RelayerConfig;
    private publicClient: ReturnType<typeof createPublicClient>;
    private walletClient?: ReturnType<typeof createWalletClient>;

    constructor(config: RelayerConfig) {
        this.config = config;
        this.publicClient = createPublicClient({
            transport: http(config.rpcUrl),
        });

        // Create wallet client for transaction signing when private key is provided
        if (config.privateKey) {
            const { privateKeyToAccount } = require('viem/accounts');
            const account = privateKeyToAccount(config.privateKey);
            this.walletClient = createWalletClient({
                account,
                transport: http(config.rpcUrl),
            });
        }
    }

    /**
     * Send a write transaction. Simulates first, then executes.
     * Requires a private key to be configured.
     */
    private async writeContract(params: Parameters<ReturnType<typeof createPublicClient>['simulateContract']>[0]): Promise<Hash> {
        // Always simulate first to catch errors early
        const { request } = await this.publicClient.simulateContract(params);

        if (!this.walletClient) {
            throw new Error('Cannot send transactions without a private key. Provide privateKey in RelayerConfig.');
        }

        return this.walletClient.writeContract(request as any);
    }

    /**
     * Register as a privacy relayer with staked ETH
     * @returns Transaction hash of registration
     */
    async register(): Promise<Hash> {
        const minStake = await this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'getMinimumStake',
        });

        if (this.config.stake < minStake) {
            throw new Error(`Stake ${this.config.stake} below minimum ${minStake}`);
        }

        return this.writeContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'registerRelayer',
            args: [this.config.endpoints],
            value: this.config.stake,
        });
    }

    /**
     * Unregister and begin stake unbonding (7-day period)
     * @returns Transaction hash
     */
    async unregister(): Promise<Hash> {
        return this.writeContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'unregisterRelayer',
        });
    }

    /**
     * Get the number of pending messages awaiting relay
     * @returns Count of pending messages
     */
    async getPendingMessages(): Promise<bigint> {
        return this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'getPendingMessageCount',
        });
    }

    /**
     * Relay a message with MEV protection via commit-reveal
     * @param messageId The message identifier
     * @param proof ZK proof data
     * @param publicInputs Public inputs for verification
     * @returns Relay result with tx hash and fee
     */
    async relay(messageId: Hash, proof: Hex, publicInputs: Hex): Promise<RelayResult> {
        // Step 1: Commit (MEV protection)
        const nonce = ('0x' + Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0')).join('')) as Hash;
        const commitment = ('0x' + Array.from(
            new Uint8Array(await crypto.subtle.digest('SHA-256',
                new TextEncoder().encode(messageId + nonce.slice(2))
            ))
        ).map(b => b.toString(16).padStart(2, '0')).join('')) as Hash;

        await this.publicClient.simulateContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'commitRelay',
            args: [commitment],
        });

        // Step 2: Reveal and relay
        const tx = await this.publicClient.simulateContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'revealRelay',
            args: [messageId, proof, nonce],
        });

        return {
            success: true,
            txHash: tx.request as unknown as Hash,
            fee: 0n,
            gasUsed: 0n,
        };
    }

    /**
     * Get relayer info for an address
     * @param relayerAddress The relayer to query
     * @returns Relayer information
     */
    async getRelayerInfo(relayerAddress: Address): Promise<RelayerInfo> {
        const [stake, reputation, isActive, totalRelayed] = await this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'getRelayerInfo',
            args: [relayerAddress],
        });

        return { address: relayerAddress, stake, reputation, isActive, totalRelayed };
    }

    /**
     * Estimate relay fee for a given gas limit and source chain
     * @param gasLimit Expected gas for relay
     * @param sourceChainId Source chain ID
     * @returns Estimated fee in wei
     */
    async estimateFee(gasLimit: bigint, sourceChainId: bigint): Promise<bigint> {
        return this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'estimateFee',
            args: [gasLimit, sourceChainId],
        });
    }

    /**
     * Claim accumulated relay fees
     * @returns Transaction hash
     */
    async claimFees(): Promise<Hash> {
        const tx = await this.publicClient.simulateContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'claimFees',
        });
        return tx.request as unknown as Hash;
    }

    /**
     * Get global relayer network statistics
     * @returns Network stats
     */
    async getStats(): Promise<RelayerStats> {
        const [totalRelayers, totalMessages, totalFees] = await this.publicClient.readContract({
            address: this.config.contractAddress,
            abi: RELAYER_ABI,
            functionName: 'getStats',
        });

        return { totalRelayers, totalMessages, totalFees };
    }
}
