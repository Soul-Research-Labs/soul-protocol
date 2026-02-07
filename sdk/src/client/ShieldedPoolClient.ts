/**
 * Shielded Pool Client
 *
 * SDK client for interacting with the UniversalShieldedPool contract.
 * Provides deposit, withdraw, cross-chain commitment, and Merkle tree querying.
 */

import {
    type PublicClient,
    type WalletClient,
    type Hex,
    type Address,
    zeroAddress,
    keccak256,
    encodePacked,
} from "viem";

/*//////////////////////////////////////////////////////////////
                          TYPES
//////////////////////////////////////////////////////////////*/

export interface ShieldedPoolConfig {
    publicClient: PublicClient;
    walletClient?: WalletClient;
    poolAddress: Address;
}

export interface DepositNote {
    commitment: Hex;
    secret: Hex;
    nullifier: Hex;
    amount: bigint;
    asset: Address;
    leafIndex: number;
}

export interface PoolStats {
    totalDeposits: bigint;
    totalWithdrawals: bigint;
    currentRoot: Hex;
    nextLeafIndex: number;
}

export interface AssetConfig {
    isRegistered: boolean;
    decimals: number;
    maxDeposit: bigint;
}

/*//////////////////////////////////////////////////////////////
                          ABI
//////////////////////////////////////////////////////////////*/

const SHIELDED_POOL_ABI = [
    {
        name: "deposit",
        type: "function",
        stateMutability: "payable",
        inputs: [
            { name: "commitment", type: "bytes32" },
            { name: "asset", type: "address" },
            { name: "amount", type: "uint256" },
        ],
        outputs: [{ name: "leafIndex", type: "uint256" }],
    },
    {
        name: "withdraw",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            { name: "nullifierHash", type: "bytes32" },
            { name: "recipient", type: "address" },
            { name: "relayer", type: "address" },
            { name: "fee", type: "uint256" },
            { name: "root", type: "bytes32" },
            { name: "proof", type: "bytes" },
        ],
        outputs: [],
    },
    {
        name: "getCurrentRoot",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bytes32" }],
    },
    {
        name: "isKnownRoot",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "root", type: "bytes32" }],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        name: "isSpent",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "nullifierHash", type: "bytes32" }],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        name: "nextLeafIndex",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        name: "totalDeposited",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        name: "totalWithdrawn",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        name: "testMode",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        name: "getRegisteredAssets",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "address[]" }],
    },
    {
        name: "getPoolStats",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [
            { name: "deposits", type: "uint256" },
            { name: "withdrawals", type: "uint256" },
            { name: "currentRoot", type: "bytes32" },
            { name: "leafCount", type: "uint256" },
        ],
    },
] as const;

/*//////////////////////////////////////////////////////////////
                    SHIELDED POOL CLIENT
//////////////////////////////////////////////////////////////*/

export class ShieldedPoolClient {
    public readonly publicClient: PublicClient;
    public readonly walletClient?: WalletClient;
    public readonly poolAddress: Address;

    constructor(config: ShieldedPoolConfig) {
        this.publicClient = config.publicClient;
        this.walletClient = config.walletClient;
        this.poolAddress = config.poolAddress;
    }

    /*//////////////////////////////////////////////////////////////
                        COMMITMENT GENERATION
    //////////////////////////////////////////////////////////////*/

    /**
     * Generate a random deposit note with commitment and nullifier.
     * The commitment is hash(secret, nullifier) and is stored on-chain.
     * The secret and nullifier must be saved privately by the user.
     */
    generateDepositNote(amount: bigint, asset: Address = zeroAddress): Omit<DepositNote, "leafIndex"> {
        const secret = this.randomBytes32();
        const nullifier = this.randomBytes32();
        const commitment = keccak256(
            encodePacked(["bytes32", "bytes32"], [secret, nullifier])
        );

        return {
            commitment,
            secret,
            nullifier,
            amount,
            asset,
        };
    }

    /**
     * Compute the nullifier hash from a nullifier.
     */
    computeNullifierHash(nullifier: Hex): Hex {
        return keccak256(nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                        WRITE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Deposit ETH into the shielded pool.
     * @param commitment - The Pedersen commitment for this deposit
     * @param amount - Amount of ETH to deposit (in wei)
     * @returns leafIndex and transaction hash
     */
    async depositETH(
        commitment: Hex,
        amount: bigint,
    ): Promise<{ leafIndex: number; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "deposit",
            args: [commitment, zeroAddress, amount],
            value: amount,
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });

        // Parse leafIndex from Deposit event logs
        const leafIndex = this.parseLeafIndex(receipt.logs);

        return { leafIndex, txHash };
    }

    /**
     * Deposit ERC20 tokens into the shielded pool.
     * Requires prior approval of tokens to the pool address.
     */
    async depositERC20(
        token: Address,
        amount: bigint,
        commitment: Hex,
    ): Promise<{ leafIndex: number; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "deposit",
            args: [commitment, token, amount],
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        const leafIndex = this.parseLeafIndex(receipt.logs);

        return { leafIndex, txHash };
    }

    /**
     * Withdraw from the shielded pool with a ZK proof.
     * @param nullifierHash - Hash of the nullifier (prevents double-spend)
     * @param recipient - Address to receive the withdrawn funds
     * @param root - Merkle root the proof is computed against
     * @param proof - ZK proof bytes
     * @param relayer - Optional relayer address (for gas abstraction)
     * @param fee - Optional relayer fee
     */
    async withdraw(
        nullifierHash: Hex,
        recipient: Address,
        root: Hex,
        proof: Hex,
        relayer: Address = zeroAddress,
        fee: bigint = 0n,
    ): Promise<Hex> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "withdraw",
            args: [nullifierHash, recipient, relayer, fee, root, proof],
        });

        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        return txHash;
    }

    /*//////////////////////////////////////////////////////////////
                        READ OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Get the current Merkle root of the shielded pool.
     */
    async getCurrentRoot(): Promise<Hex> {
        return await this.publicClient.readContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "getCurrentRoot",
        });
    }

    /**
     * Check if a Merkle root is known (valid for withdrawal).
     */
    async isKnownRoot(root: Hex): Promise<boolean> {
        return await this.publicClient.readContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "isKnownRoot",
            args: [root],
        });
    }

    /**
     * Check if a nullifier has been spent (prevents double-withdrawal).
     */
    async isSpent(nullifierHash: Hex): Promise<boolean> {
        return await this.publicClient.readContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "isSpent",
            args: [nullifierHash],
        });
    }

    /**
     * Get the next available leaf index in the Merkle tree.
     */
    async getNextLeafIndex(): Promise<number> {
        const result = await this.publicClient.readContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "nextLeafIndex",
        });
        return Number(result);
    }

    /**
     * Get aggregate pool statistics.
     */
    async getPoolStats(): Promise<PoolStats> {
        const [totalDeposits, totalWithdrawals, currentRoot, nextLeaf] = await Promise.all([
            this.publicClient.readContract({
                address: this.poolAddress,
                abi: SHIELDED_POOL_ABI,
                functionName: "totalDeposited",
            }),
            this.publicClient.readContract({
                address: this.poolAddress,
                abi: SHIELDED_POOL_ABI,
                functionName: "totalWithdrawn",
            }),
            this.getCurrentRoot(),
            this.getNextLeafIndex(),
        ]);

        return {
            totalDeposits,
            totalWithdrawals,
            currentRoot,
            nextLeafIndex: nextLeaf,
        };
    }

    /**
     * Get all registered asset addresses.
     */
    async getRegisteredAssets(): Promise<Address[]> {
        return await this.publicClient.readContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "getRegisteredAssets",
        }) as Address[];
    }

    /**
     * Check if the pool is in test mode (verifier bypass enabled).
     */
    async isTestMode(): Promise<boolean> {
        return await this.publicClient.readContract({
            address: this.poolAddress,
            abi: SHIELDED_POOL_ABI,
            functionName: "testMode",
        });
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    private requireWallet(): void {
        if (!this.walletClient) {
            throw new Error("Wallet client required for write operations");
        }
    }

    private randomBytes32(): Hex {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("")}` as Hex;
    }

    private parseLeafIndex(logs: readonly { data: Hex; topics: readonly Hex[] }[]): number {
        // Deposit(bytes32 indexed commitment, uint256 leafIndex, ...)
        for (const log of logs) {
            if (log.topics.length >= 2 && log.data.length >= 66) {
                return Number(BigInt(log.data.slice(0, 66)));
            }
        }
        return 0;
    }
}

/**
 * Create a ShieldedPoolClient instance.
 */
export function createShieldedPoolClient(config: ShieldedPoolConfig): ShieldedPoolClient {
    return new ShieldedPoolClient(config);
}
