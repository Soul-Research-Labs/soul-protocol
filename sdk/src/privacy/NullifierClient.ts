/**
 * @title Unified Nullifier Client
 * @description TypeScript SDK for cross-domain nullifier operations
 */

import { ethers, Contract, Wallet, Provider, keccak256, toBeHex, getBytes, hexlify } from 'ethers';

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
    nullifier: string;
    domain: number;
    timestamp: number;
    pilBinding: string;
}

// Cross-domain nullifier derivation result
export interface CrossDomainNullifier {
    sourceNullifier: string;
    sourceDomain: number;
    targetDomain: number;
    crossDomainNullifier: string;
    pilBinding: string;
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
const NULLIFIER_DOMAIN = keccak256(ethers.toUtf8Bytes('Soul_UNIFIED_NULLIFIER_V1'));
const CROSS_DOMAIN_TAG = keccak256(ethers.toUtf8Bytes('CROSS_DOMAIN'));
const Soul_BINDING_TAG = keccak256(ethers.toUtf8Bytes('Soul_BINDING'));

// ABI for UnifiedNullifierManager
const NULLIFIER_MANAGER_ABI = [
    'function registerDomain(uint256 chainId, bytes32 domainTag) external',
    'function registerNullifier(bytes32 nullifier, uint256 domain) external',
    'function deriveCrossDomainNullifier(bytes32 sourceNullifier, uint256 sourceDomain, uint256 targetDomain) external view returns (bytes32)',
    'function deriveSoulBinding(bytes32 nullifier) external view returns (bytes32)',
    'function isNullifierConsumed(bytes32 nullifier, uint256 domain) external view returns (bool)',
    'function isDomainRegistered(uint256 domain) external view returns (bool)',
    'function getSoulBinding(bytes32 nullifier) external view returns (bytes32)',
    'function getNullifierRecord(bytes32 nullifier, uint256 domain) external view returns (uint256 timestamp, bytes32 pilBinding)',
    'event DomainRegistered(uint256 indexed chainId, bytes32 domainTag)',
    'event NullifierRegistered(bytes32 indexed nullifier, uint256 indexed domain, bytes32 pilBinding)',
    'event CrossDomainNullifierDerived(bytes32 indexed sourceNullifier, bytes32 indexed crossNullifier, uint256 sourceDomain, uint256 targetDomain)'
];

export class NullifierClient {
    private contract: Contract;
    private provider: Provider;
    private signer?: Wallet;

    constructor(
        contractAddress: string,
        provider: Provider,
        signer?: Wallet
    ) {
        this.provider = provider;
        this.signer = signer;
        this.contract = new Contract(
            contractAddress,
            NULLIFIER_MANAGER_ABI,
            signer || provider
        );
    }

    /**
     * Derive nullifier from secret and commitment
     */
    static deriveNullifier(secret: string, commitmentHash: string, chainId: number): string {
        return keccak256(ethers.concat([
            getBytes(secret),
            getBytes(commitmentHash),
            toBeHex(chainId, 8),
            getBytes(NULLIFIER_DOMAIN)
        ]));
    }

    /**
     * Derive nullifier from Monero key image
     */
    static deriveFromMoneroKeyImage(keyImage: string): string {
        return keccak256(ethers.concat([
            getBytes(keyImage),
            getBytes(keccak256(ethers.toUtf8Bytes('MONERO_KEY_IMAGE'))),
            getBytes(Soul_BINDING_TAG)
        ]));
    }

    /**
     * Derive nullifier from Zcash note nullifier
     */
    static deriveFromZcashNullifier(noteNullifier: string, anchor: string): string {
        return keccak256(ethers.concat([
            getBytes(noteNullifier),
            getBytes(anchor),
            getBytes(keccak256(ethers.toUtf8Bytes('ZCASH_NOTE'))),
            getBytes(Soul_BINDING_TAG)
        ]));
    }

    /**
     * Derive cross-domain nullifier locally
     */
    static deriveCrossDomainNullifierLocal(
        sourceNullifier: string,
        sourceDomain: ChainDomain,
        targetDomain: ChainDomain
    ): string {
        return keccak256(ethers.concat([
            getBytes(sourceNullifier),
            toBeHex(sourceDomain.chainId, 8),
            getBytes(keccak256(ethers.toUtf8Bytes(sourceDomain.domainTag))),
            toBeHex(targetDomain.chainId, 8),
            getBytes(keccak256(ethers.toUtf8Bytes(targetDomain.domainTag))),
            getBytes(CROSS_DOMAIN_TAG)
        ]));
    }

    /**
     * Derive Soul binding locally
     */
    static deriveSoulBindingLocal(nullifier: string): string {
        return keccak256(ethers.concat([
            getBytes(nullifier),
            getBytes(Soul_BINDING_TAG)
        ]));
    }

    /**
     * Register a new domain
     */
    async registerDomain(domain: ChainDomain): Promise<string> {
        if (!this.signer) throw new Error('Signer required');

        const domainTagHash = keccak256(ethers.toUtf8Bytes(domain.domainTag));
        const tx = await this.contract.registerDomain(domain.chainId, domainTagHash);
        const receipt = await tx.wait();
        return receipt.hash;
    }

    /**
     * Register a nullifier in a domain
     */
    async registerNullifier(nullifier: string, domainChainId: number): Promise<string> {
        if (!this.signer) throw new Error('Signer required');

        const tx = await this.contract.registerNullifier(nullifier, domainChainId);
        const receipt = await tx.wait();
        return receipt.hash;
    }

    /**
     * Derive cross-domain nullifier on-chain
     */
    async deriveCrossDomainNullifier(
        sourceNullifier: string,
        sourceDomainId: number,
        targetDomainId: number
    ): Promise<CrossDomainNullifier> {
        const crossDomainNullifier = await this.contract.deriveCrossDomainNullifier(
            sourceNullifier,
            sourceDomainId,
            targetDomainId
        );

        const pilBinding = await this.contract.deriveSoulBinding(sourceNullifier);

        return {
            sourceNullifier,
            sourceDomain: sourceDomainId,
            targetDomain: targetDomainId,
            crossDomainNullifier,
            pilBinding
        };
    }

    /**
     * Check if nullifier is consumed in a domain
     */
    async isNullifierConsumed(nullifier: string, domainChainId: number): Promise<boolean> {
        return await this.contract.isNullifierConsumed(nullifier, domainChainId);
    }

    /**
     * Check if domain is registered
     */
    async isDomainRegistered(domainChainId: number): Promise<boolean> {
        return await this.contract.isDomainRegistered(domainChainId);
    }

    /**
     * Get Soul binding for a nullifier
     */
    async getSoulBinding(nullifier: string): Promise<string> {
        return await this.contract.getSoulBinding(nullifier);
    }

    /**
     * Get nullifier record
     */
    async getNullifierRecord(nullifier: string, domainChainId: number): Promise<NullifierRecord | null> {
        try {
            const [timestamp, pilBinding] = await this.contract.getNullifierRecord(nullifier, domainChainId);
            
            if (timestamp === 0n) return null;

            return {
                nullifier,
                domain: domainChainId,
                timestamp: Number(timestamp),
                pilBinding
            };
        } catch {
            return null;
        }
    }

    /**
     * Check if two nullifiers are linked (same Soul binding)
     */
    async areNullifiersLinked(nullifier1: string, nullifier2: string): Promise<boolean> {
        const binding1 = await this.getSoulBinding(nullifier1);
        const binding2 = await this.getSoulBinding(nullifier2);
        return binding1 === binding2;
    }

    /**
     * Batch check multiple nullifiers
     */
    async batchCheckNullifiers(
        nullifiers: string[],
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
        callback: (nullifier: string, domain: number, pilBinding: string) => void
    ): () => void {
        const filter = this.contract.filters.NullifierRegistered();

        const handler = (nullifier: string, domain: bigint, pilBinding: string) => {
            callback(nullifier, Number(domain), pilBinding);
        };

        this.contract.on(filter, handler);

        return () => {
            this.contract.off(filter, handler);
        };
    }

    /**
     * Listen for cross-domain derivation events
     */
    onCrossDomainDerived(
        callback: (sourceNf: string, crossNf: string, sourceDomain: number, targetDomain: number) => void
    ): () => void {
        const filter = this.contract.filters.CrossDomainNullifierDerived();

        const handler = (sourceNf: string, crossNf: string, sourceDomain: bigint, targetDomain: bigint) => {
            callback(sourceNf, crossNf, Number(sourceDomain), Number(targetDomain));
        };

        this.contract.on(filter, handler);

        return () => {
            this.contract.off(filter, handler);
        };
    }
}

export default NullifierClient;
