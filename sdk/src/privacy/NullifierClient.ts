import { 
    PublicClient, 
    WalletClient, 
    getContract, 
    keccak256, 
    toHex, 
    toBytes, 
    concat, 
    getAddress, 
    Hex, 
    stringToBytes,
    decodeEventLog
} from 'viem';

// Chain domain configuration
export interface ChainDomain {
    chainId: number;
    domainTag: string;
    name: string;
}

// Nullifier types supported by different chains
export enum NullifierType {
    Soul_NATIVE = 0,
    MONERO_KEY_IMAGE = 1,
    ZCASH_NOTE = 2,
    SECRET_TEE = 3,
    OASIS_SGX = 4,
    RAILGUN_UTXO = 5,
    TORNADO_COMMITMENT = 6,
    AZTEC_NOTE = 7
}

// Registered nullifier record
export interface NullifierRecord {
    nullifier: Hex;
    domain: number;
    timestamp: number;
    soulBinding: Hex;
}

// Cross-domain nullifier derivation result
export interface CrossDomainNullifier {
    sourceNullifier: Hex;
    sourceDomain: number;
    targetDomain: number;
    crossDomainNullifier: Hex;
    soulBinding: Hex;
}

// Predefined chain domains
export const CHAIN_DOMAINS: Record<string, ChainDomain> = {
    Soul: { chainId: 1, domainTag: 'Soul_MAINNET', name: 'Soul Mainnet' },
    ETHEREUM: { chainId: 1, domainTag: 'ETHEREUM', name: 'Ethereum' },
    MONERO: { chainId: 0, domainTag: 'MONERO', name: 'Monero' },
    ZCASH: { chainId: 0, domainTag: 'ZCASH', name: 'Zcash' },
    SECRET: { chainId: 0, domainTag: 'SECRET_NETWORK', name: 'Secret Network' },
    OASIS: { chainId: 23294, domainTag: 'OASIS_SAPPHIRE', name: 'Oasis Sapphire' },
    RAILGUN: { chainId: 1, domainTag: 'RAILGUN', name: 'Railgun' },
    AZTEC: { chainId: 0, domainTag: 'AZTEC', name: 'Aztec' },
    ARBITRUM: { chainId: 42161, domainTag: 'ARBITRUM', name: 'Arbitrum One' },
    OPTIMISM: { chainId: 10, domainTag: 'OPTIMISM', name: 'Optimism' },
    POLYGON: { chainId: 137, domainTag: 'POLYGON', name: 'Polygon' },
    BASE: { chainId: 8453, domainTag: 'BASE', name: 'Base' }
};

// Domain separator constants
const NULLIFIER_DOMAIN = keccak256(stringToBytes('Soul_UNIFIED_NULLIFIER_V1'));
const CROSS_DOMAIN_TAG = keccak256(stringToBytes('CROSS_DOMAIN'));
const Soul_BINDING_TAG = keccak256(stringToBytes('Soul_BINDING'));

// ABI for UnifiedNullifierManager
const NULLIFIER_MANAGER_ABI = [
    { name: 'registerDomain', type: 'function', stateMutability: 'external', inputs: [{ name: 'chainId', type: 'uint256' }, { name: 'domainTag', type: 'bytes32' }] },
    { name: 'registerNullifier', type: 'function', stateMutability: 'external', inputs: [{ name: 'nullifier', type: 'bytes32' }, { name: 'domain', type: 'uint256' }] },
    { name: 'deriveCrossDomainNullifier', type: 'function', stateMutability: 'view', inputs: [{ name: 'sourceNullifier', type: 'bytes32' }, { name: 'sourceDomain', type: 'uint256' }, { name: 'targetDomain', type: 'uint256' }], outputs: [{ type: 'bytes32' }] },
    { name: 'deriveSoulBinding', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
    { name: 'isNullifierConsumed', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }, { name: 'domain', type: 'uint256' }], outputs: [{ type: 'bool' }] },
    { name: 'isDomainRegistered', type: 'function', stateMutability: 'view', inputs: [{ name: 'domain', type: 'uint256' }], outputs: [{ type: 'bool' }] },
    { name: 'getSoulBinding', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }], outputs: [{ type: 'bytes32' }] },
    { name: 'getNullifierRecord', type: 'function', stateMutability: 'view', inputs: [{ name: 'nullifier', type: 'bytes32' }, { name: 'domain', type: 'uint256' }], outputs: [{ name: 'timestamp', type: 'uint256' }, { name: 'soulBinding', type: 'bytes32' }] },
    { name: 'DomainRegistered', type: 'event', inputs: [{ name: 'chainId', type: 'uint256', indexed: true }, { name: 'domainTag', type: 'bytes32' }] },
    { name: 'NullifierRegistered', type: 'event', inputs: [{ name: 'nullifier', type: 'bytes32', indexed: true }, { name: 'domain', type: 'uint256', indexed: true }, { name: 'soulBinding', type: 'bytes32' }] },
    { name: 'CrossDomainNullifierDerived', type: 'event', inputs: [{ name: 'sourceNullifier', type: 'bytes32', indexed: true }, { name: 'crossNullifier', type: 'bytes32', indexed: true }, { name: 'sourceDomain', type: 'uint256' }, { name: 'targetDomain', type: 'uint256' }] }
] as const;

export class NullifierClient {
    private contract: any;
    private publicClient: PublicClient;
    private walletClient?: WalletClient;

    constructor(
        contractAddress: Hex,
        publicClient: PublicClient,
        walletClient?: WalletClient
    ) {
        this.publicClient = publicClient;
        this.walletClient = walletClient;
        this.contract = getContract({
            address: contractAddress,
            abi: NULLIFIER_MANAGER_ABI,
            client: { public: publicClient, wallet: walletClient }
        });
    }

    /**
     * Derive nullifier from secret and commitment
     */
    static deriveNullifier(secret: Hex, commitmentHash: Hex, chainId: number): Hex {
        return keccak256(concat([
            secret,
            commitmentHash,
            toHex(chainId, { size: 8 }),
            NULLIFIER_DOMAIN
        ]));
    }

    /**
     * Derive nullifier from Monero key image
     */
    static deriveFromMoneroKeyImage(keyImage: Hex): Hex {
        return keccak256(concat([
            keyImage,
            keccak256(stringToBytes('MONERO_KEY_IMAGE')),
            Soul_BINDING_TAG
        ]));
    }

    /**
     * Derive nullifier from Zcash note nullifier
     */
    static deriveFromZcashNullifier(noteNullifier: Hex, anchor: Hex): Hex {
        return keccak256(concat([
            noteNullifier,
            anchor,
            keccak256(stringToBytes('ZCASH_NOTE')),
            Soul_BINDING_TAG
        ]));
    }

    /**
     * Derive cross-domain nullifier locally
     */
    static deriveCrossDomainNullifierLocal(
        sourceNullifier: Hex,
        sourceDomain: ChainDomain,
        targetDomain: ChainDomain
    ): Hex {
        return keccak256(concat([
            sourceNullifier,
            toHex(sourceDomain.chainId, { size: 8 }),
            keccak256(stringToBytes(sourceDomain.domainTag)),
            toHex(targetDomain.chainId, { size: 8 }),
            keccak256(stringToBytes(targetDomain.domainTag)),
            CROSS_DOMAIN_TAG
        ]));
    }

    /**
     * Derive Soul binding locally
     */
    static deriveSoulBindingLocal(nullifier: Hex): Hex {
        return keccak256(concat([
            nullifier,
            Soul_BINDING_TAG
        ]));
    }

    /**
     * Register a new domain
     */
    async registerDomain(domain: ChainDomain): Promise<Hex> {
        if (!this.walletClient) throw new Error('Wallet client required');

        const domainTagHash = keccak256(stringToBytes(domain.domainTag));
        const hash = await this.contract.write.registerDomain([BigInt(domain.chainId), domainTagHash]);
        return hash;
    }

    /**
     * Register a nullifier in a domain
     */
    async registerNullifier(nullifier: Hex, domainChainId: number): Promise<Hex> {
        if (!this.walletClient) throw new Error('Wallet client required');

        const hash = await this.contract.write.registerNullifier([nullifier, BigInt(domainChainId)]);
        return hash;
    }

    /**
     * Derive cross-domain nullifier on-chain
     */
    async deriveCrossDomainNullifier(
        sourceNullifier: Hex,
        sourceDomainId: number,
        targetDomainId: number
    ): Promise<CrossDomainNullifier> {
        const crossDomainNullifier = await this.contract.read.deriveCrossDomainNullifier([
            sourceNullifier,
            BigInt(sourceDomainId),
            BigInt(targetDomainId)
        ]);

        const soulBinding = await this.contract.read.deriveSoulBinding([sourceNullifier]);

        return {
            sourceNullifier,
            sourceDomain: sourceDomainId,
            targetDomain: targetDomainId,
            crossDomainNullifier,
            soulBinding
        };
    }

    /**
     * Check if nullifier is consumed in a domain
     */
    async isNullifierConsumed(nullifier: Hex, domainChainId: number): Promise<boolean> {
        return await this.contract.read.isNullifierConsumed([nullifier, BigInt(domainChainId)]);
    }

    /**
     * Check if domain is registered
     */
    async isDomainRegistered(domainChainId: number): Promise<boolean> {
        return await this.contract.read.isDomainRegistered([BigInt(domainChainId)]);
    }

    /**
     * Get Soul binding for a nullifier
     */
    async getSoulBinding(nullifier: Hex): Promise<Hex> {
        return await this.contract.read.getSoulBinding([nullifier]);
    }

    /**
     * Get nullifier record
     */
    async getNullifierRecord(nullifier: Hex, domainChainId: number): Promise<NullifierRecord | null> {
        try {
            const [timestamp, soulBinding] = await this.contract.read.getNullifierRecord([nullifier, BigInt(domainChainId)]) as [bigint, Hex];
            
            if (timestamp === 0n) return null;

            return {
                nullifier,
                domain: domainChainId,
                timestamp: Number(timestamp),
                soulBinding
            };
        } catch {
            return null;
        }
    }

    /**
     * Check if two nullifiers are linked (same Soul binding)
     */
    async areNullifiersLinked(nullifier1: Hex, nullifier2: Hex): Promise<boolean> {
        const binding1 = await this.getSoulBinding(nullifier1);
        const binding2 = await this.getSoulBinding(nullifier2);
        return binding1 === binding2;
    }

    /**
     * Batch check multiple nullifiers
     */
    async batchCheckNullifiers(
        nullifiers: Hex[],
        domainChainId: number
    ): Promise<Map<string, boolean>> {
        const results = new Map<string, boolean>();

        await Promise.all(
            nullifiers.map(async (nf) => {
                const consumed = await this.isNullifierConsumed(nf, domainChainId);
                results.set(nf, consumed);
            })
        );

        return results;
    }

    /**
     * Listen for nullifier registration events
     */
    onNullifierRegistered(
        callback: (nullifier: Hex, domain: number, soulBinding: Hex) => void
    ): () => void {
        const unwatch = this.publicClient.watchContractEvent({
            address: this.contract.address,
            abi: NULLIFIER_MANAGER_ABI,
            eventName: 'NullifierRegistered',
            onLogs: logs => {
                for (const log of logs) {
                    const { args } = log as any;
                    callback(args.nullifier, Number(args.domain), args.soulBinding);
                }
            }
        });
        return unwatch;
    }

    /**
     * Listen for cross-domain derivation events
     */
    onCrossDomainDerived(
        callback: (sourceNf: Hex, crossNf: Hex, sourceDomain: number, targetDomain: number) => void
    ): () => void {
        const unwatch = this.publicClient.watchContractEvent({
            address: this.contract.address,
            abi: NULLIFIER_MANAGER_ABI,
            eventName: 'CrossDomainNullifierDerived',
            onLogs: logs => {
                for (const log of logs) {
                    const { args } = log as any;
                    callback(args.sourceNullifier, args.crossNullifier, Number(args.sourceDomain), Number(args.targetDomain));
                }
            }
        });
        return unwatch;
    }
}

export default NullifierClient;
