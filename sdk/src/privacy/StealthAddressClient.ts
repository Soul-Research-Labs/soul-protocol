/**
 * @title Stealth Address Client
 * @description TypeScript SDK for ERC-5564 stealth address operations
 */

import { ethers, Contract, Wallet, Provider, keccak256, toBeHex, getBytes, hexlify, randomBytes } from 'ethers';

// Stealth Address Schemes
export enum StealthScheme {
    SECP256K1 = 0,
    ED25519 = 1,
    BLS12_381 = 2,
    BABYJUBJUB = 3
}

// Meta-address structure
export interface StealthMetaAddress {
    stealthId: string;
    spendingPubKey: string;
    viewingPubKey: string;
    scheme: StealthScheme;
}

// Computed stealth address result
export interface StealthAddressResult {
    stealthAddress: string;
    ephemeralPubKey: string;
    viewTag: string;
}

// Payment announcement
export interface PaymentAnnouncement {
    stealthAddress: string;
    ephemeralPubKey: string;
    metadata: string;
    blockNumber: number;
    transactionHash: string;
}

// ABI for StealthAddressRegistry
const STEALTH_REGISTRY_ABI = [
    'function registerMetaAddress(bytes32 stealthId, bytes spendingPubKey, bytes viewingPubKey, uint8 scheme) external',
    'function computeStealthAddress(bytes32 stealthId, bytes ephemeralPubKey) external view returns (address, bytes)',
    'function announcePayment(address stealthAddress, bytes ephemeralPubKey, bytes metadata) external',
    'function getMetaAddress(bytes32 stealthId) external view returns (bytes spendingPubKey, bytes viewingPubKey, uint8 scheme)',
    'function getAnnouncementCount() external view returns (uint256)',
    'event MetaAddressRegistered(bytes32 indexed stealthId, address indexed owner, uint8 scheme)',
    'event PaymentAnnounced(address indexed stealthAddress, bytes ephemeralPubKey, bytes metadata, uint256 indexed blockNumber)'
];

export class StealthAddressClient {
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
            STEALTH_REGISTRY_ABI,
            signer || provider
        );
    }

    /**
     * Generate a new stealth meta-address keypair
     */
    static generateMetaAddress(scheme: StealthScheme = StealthScheme.SECP256K1): {
        spendingPrivKey: string;
        spendingPubKey: string;
        viewingPrivKey: string;
        viewingPubKey: string;
    } {
        // Generate random private keys
        const spendingPrivKey = hexlify(randomBytes(32));
        const viewingPrivKey = hexlify(randomBytes(32));

        // Derive public keys (secp256k1)
        const spendingWallet = new Wallet(spendingPrivKey);
        const viewingWallet = new Wallet(viewingPrivKey);

        return {
            spendingPrivKey,
            spendingPubKey: spendingWallet.signingKey.publicKey,
            viewingPrivKey,
            viewingPubKey: viewingWallet.signingKey.publicKey
        };
    }

    /**
     * Compute stealth ID from meta-address components
     */
    static computeStealthId(spendingPubKey: string, viewingPubKey: string): string {
        return keccak256(ethers.concat([getBytes(spendingPubKey), getBytes(viewingPubKey)]));
    }

    /**
     * Register a new stealth meta-address
     */
    async registerMetaAddress(
        spendingPubKey: string,
        viewingPubKey: string,
        scheme: StealthScheme = StealthScheme.SECP256K1
    ): Promise<{ stealthId: string; txHash: string }> {
        if (!this.signer) throw new Error('Signer required for registration');

        const stealthId = StealthAddressClient.computeStealthId(spendingPubKey, viewingPubKey);

        const tx = await this.contract.registerMetaAddress(
            stealthId,
            spendingPubKey,
            viewingPubKey,
            scheme
        );
        const receipt = await tx.wait();

        return {
            stealthId,
            txHash: receipt.hash
        };
    }

    /**
     * Get registered meta-address by stealth ID
     */
    async getMetaAddress(stealthId: string): Promise<StealthMetaAddress | null> {
        try {
            const [spendingPubKey, viewingPubKey, scheme] = await this.contract.getMetaAddress(stealthId);
            
            if (spendingPubKey === '0x') return null;

            return {
                stealthId,
                spendingPubKey,
                viewingPubKey,
                scheme: scheme as StealthScheme
            };
        } catch {
            return null;
        }
    }

    /**
     * Generate ephemeral keypair and compute stealth address
     */
    async computeStealthAddress(stealthId: string): Promise<StealthAddressResult & { ephemeralPrivKey: string }> {
        // Generate ephemeral keypair
        const ephemeralPrivKey = hexlify(randomBytes(32));
        const ephemeralWallet = new Wallet(ephemeralPrivKey);
        const ephemeralPubKey = ephemeralWallet.signingKey.publicKey;

        // Compute stealth address on-chain
        const [stealthAddress, viewTag] = await this.contract.computeStealthAddress(
            stealthId,
            ephemeralPubKey
        );

        return {
            stealthAddress,
            ephemeralPubKey,
            viewTag,
            ephemeralPrivKey
        };
    }

    /**
     * Announce a payment to a stealth address
     */
    async announcePayment(
        stealthAddress: string,
        ephemeralPubKey: string,
        metadata: string = '0x'
    ): Promise<string> {
        if (!this.signer) throw new Error('Signer required for announcement');

        const tx = await this.contract.announcePayment(
            stealthAddress,
            ephemeralPubKey,
            metadata
        );
        const receipt = await tx.wait();
        return receipt.hash;
    }

    /**
     * Scan announcements for payments to our viewing key
     * @param viewingPrivKey - Private viewing key for scanning
     * @param fromBlock - Starting block number
     * @param toBlock - Ending block number (default: latest)
     */
    async scanAnnouncements(
        viewingPrivKey: string,
        spendingPubKey: string,
        fromBlock: number,
        toBlock?: number
    ): Promise<{ address: string; ephemeralPubKey: string; metadata: string; block: number }[]> {
        const filter = this.contract.filters.PaymentAnnounced();
        const events = await this.contract.queryFilter(filter, fromBlock, toBlock || 'latest');

        const matches: { address: string; ephemeralPubKey: string; metadata: string; block: number }[] = [];

        for (const event of events) {
            const args = (event as ethers.EventLog).args;
            const [stealthAddress, ephemeralPubKey, metadata, blockNumber] = args;

            // Try to derive the stealth address with our keys
            const derivedAddress = this.deriveStealthAddressLocally(
                viewingPrivKey,
                spendingPubKey,
                ephemeralPubKey
            );

            if (derivedAddress.toLowerCase() === stealthAddress.toLowerCase()) {
                matches.push({
                    address: stealthAddress,
                    ephemeralPubKey,
                    metadata,
                    block: Number(blockNumber)
                });
            }
        }

        return matches;
    }

    /**
     * Derive stealth address locally (for scanning)
     */
    private deriveStealthAddressLocally(
        viewingPrivKey: string,
        spendingPubKey: string,
        ephemeralPubKey: string
    ): string {
        // Compute shared secret: viewingPrivKey * ephemeralPubKey
        // In a real implementation, this would use elliptic curve multiplication
        const sharedSecret = keccak256(ethers.concat([
            getBytes(viewingPrivKey),
            getBytes(ephemeralPubKey)
        ]));

        // Derive stealth public key: spendingPubKey + hash(sharedSecret) * G
        // Simplified: just hash for now
        const stealthPubKey = keccak256(ethers.concat([
            getBytes(spendingPubKey),
            getBytes(sharedSecret)
        ]));

        // Convert to address
        return ethers.getAddress('0x' + stealthPubKey.slice(-40));
    }

    /**
     * Derive stealth private key for spending
     */
    static deriveStealthPrivateKey(
        spendingPrivKey: string,
        viewingPrivKey: string,
        ephemeralPubKey: string
    ): string {
        // Compute shared secret
        const sharedSecret = keccak256(ethers.concat([
            getBytes(viewingPrivKey),
            getBytes(ephemeralPubKey)
        ]));

        // Derive stealth private key: spendingPrivKey + hash(sharedSecret)
        const spendingBN = BigInt(spendingPrivKey);
        const sharedSecretBN = BigInt(sharedSecret);
        const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

        const stealthPrivKey = (spendingBN + sharedSecretBN) % curveOrder;
        return toBeHex(stealthPrivKey, 32);
    }

    /**
     * Get total announcement count
     */
    async getAnnouncementCount(): Promise<number> {
        const count = await this.contract.getAnnouncementCount();
        return Number(count);
    }
}

export default StealthAddressClient;
