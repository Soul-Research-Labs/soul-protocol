/**
 * Privacy Router Client
 *
 * High-level SDK client for the PrivacyRouter facade contract.
 * Provides unified access to deposit, withdraw, cross-chain transfer,
 * and stealth payment operations through a single interface.
 */

import {
    type PublicClient,
    type WalletClient,
    type Hex,
    type Address,
    parseEther,
    formatEther,
    zeroAddress,
} from "viem";

/*//////////////////////////////////////////////////////////////
                          TYPES
//////////////////////////////////////////////////////////////*/

export interface PrivacyRouterConfig {
    publicClient: PublicClient;
    walletClient?: WalletClient;
    routerAddress: Address;
}

export enum OperationType {
    DEPOSIT = 0,
    WITHDRAW = 1,
    CROSS_CHAIN_TRANSFER = 2,
    STEALTH_PAYMENT = 3,
}

export interface DepositParams {
    commitment: Hex;
    amount: bigint;
    asset?: Address; // defaults to ETH (zero address)
}

export interface WithdrawParams {
    nullifierHash: Hex;
    recipient: Address;
    relayer?: Address;
    fee?: bigint;
    root: Hex;
    proof: Hex;
}

export interface CrossChainTransferParams {
    commitment: Hex;
    nullifierHash: Hex;
    destinationChainId: number;
    proof: Hex;
    amount: bigint;
}

export interface OperationReceipt {
    operationId: Hex;
    operationType: OperationType;
    sender: Address;
    timestamp: bigint;
    chainId: number;
}

/*//////////////////////////////////////////////////////////////
                          ABI
//////////////////////////////////////////////////////////////*/

const PRIVACY_ROUTER_ABI = [
    {
        name: "depositETH",
        type: "function",
        stateMutability: "payable",
        inputs: [{ name: "commitment", type: "bytes32" }],
        outputs: [{ name: "operationId", type: "bytes32" }],
    },
    {
        name: "depositERC20",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            { name: "token", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "commitment", type: "bytes32" },
        ],
        outputs: [{ name: "operationId", type: "bytes32" }],
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
        outputs: [{ name: "operationId", type: "bytes32" }],
    },
    {
        name: "crossChainTransfer",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            { name: "commitment", type: "bytes32" },
            { name: "nullifierHash", type: "bytes32" },
            { name: "destinationChainId", type: "uint256" },
            { name: "proof", type: "bytes" },
        ],
        outputs: [{ name: "operationId", type: "bytes32" }],
    },
    {
        name: "getOperationCount",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        name: "getOperationReceipt",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "operationId", type: "bytes32" }],
        outputs: [
            {
                name: "",
                type: "tuple",
                components: [
                    { name: "operationId", type: "bytes32" },
                    { name: "operationType", type: "uint8" },
                    { name: "sender", type: "address" },
                    { name: "timestamp", type: "uint256" },
                    { name: "chainId", type: "uint256" },
                ],
            },
        ],
    },
    {
        name: "paused",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        name: "complianceEnabled",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bool" }],
    },
] as const;

/*//////////////////////////////////////////////////////////////
                    PRIVACY ROUTER CLIENT
//////////////////////////////////////////////////////////////*/

export class PrivacyRouterClient {
    public readonly publicClient: PublicClient;
    public readonly walletClient?: WalletClient;
    public readonly routerAddress: Address;

    constructor(config: PrivacyRouterConfig) {
        this.publicClient = config.publicClient;
        this.walletClient = config.walletClient;
        this.routerAddress = config.routerAddress;
    }

    /*//////////////////////////////////////////////////////////////
                        WRITE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Deposit ETH into the shielded pool via the privacy router.
     * @param commitment - The Pedersen commitment for the deposit note
     * @param amount - Amount of ETH to deposit (in wei)
     * @returns The operation ID and transaction hash
     */
    async depositETH(
        commitment: Hex,
        amount: bigint,
    ): Promise<{ operationId: Hex; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "depositETH",
            args: [commitment],
            value: amount,
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });

        // Parse operation ID from logs
        const operationId = this.parseOperationId(receipt.logs);

        return { operationId, txHash };
    }

    /**
     * Deposit ERC20 tokens into the shielded pool.
     * Requires prior token approval to the router address.
     * @param token - ERC20 token address
     * @param amount - Amount to deposit
     * @param commitment - The Pedersen commitment for the deposit note
     */
    async depositERC20(
        token: Address,
        amount: bigint,
        commitment: Hex,
    ): Promise<{ operationId: Hex; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "depositERC20",
            args: [token, amount, commitment],
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        const operationId = this.parseOperationId(receipt.logs);

        return { operationId, txHash };
    }

    /**
     * Withdraw from the shielded pool with a ZK proof.
     * @param params - Withdrawal parameters including nullifier, recipient, proof
     */
    async withdraw(params: WithdrawParams): Promise<{ operationId: Hex; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "withdraw",
            args: [
                params.nullifierHash,
                params.recipient,
                params.relayer ?? zeroAddress,
                params.fee ?? 0n,
                params.root,
                params.proof,
            ],
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        const operationId = this.parseOperationId(receipt.logs);

        return { operationId, txHash };
    }

    /**
     * Initiate a cross-chain transfer through the privacy router.
     * @param params - Cross-chain transfer parameters
     */
    async crossChainTransfer(
        params: CrossChainTransferParams,
    ): Promise<{ operationId: Hex; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "crossChainTransfer",
            args: [
                params.commitment,
                params.nullifierHash,
                params.destinationChainId,
                params.proof,
            ],
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        const operationId = this.parseOperationId(receipt.logs);

        return { operationId, txHash };
    }

    /*//////////////////////////////////////////////////////////////
                        READ OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Get the total number of operations processed by the router.
     */
    async getOperationCount(): Promise<bigint> {
        return await this.publicClient.readContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "getOperationCount",
        });
    }

    /**
     * Get the receipt for a specific operation by ID.
     */
    async getOperationReceipt(operationId: Hex): Promise<OperationReceipt> {
        const result = await this.publicClient.readContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "getOperationReceipt",
            args: [operationId],
        });

        return {
            operationId: result.operationId,
            operationType: result.operationType as OperationType,
            sender: result.sender,
            timestamp: result.timestamp,
            chainId: Number(result.chainId),
        };
    }

    /**
     * Check if the router is currently paused.
     */
    async isPaused(): Promise<boolean> {
        return await this.publicClient.readContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "paused",
        });
    }

    /**
     * Check if compliance screening is enabled.
     */
    async isComplianceEnabled(): Promise<boolean> {
        return await this.publicClient.readContract({
            address: this.routerAddress,
            abi: PRIVACY_ROUTER_ABI,
            functionName: "complianceEnabled",
        });
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    private requireWallet(): void {
        if (!this.walletClient) {
            throw new Error("Wallet client required for write operations. Provide a walletClient in config.");
        }
    }

    private parseOperationId(logs: readonly { data: Hex; topics: readonly Hex[] }[]): Hex {
        // OperationExecuted(bytes32 indexed operationId, ...)
        // Topic[0] = event signature, Topic[1] = operationId
        for (const log of logs) {
            if (log.topics.length >= 2) {
                return log.topics[1] as Hex;
            }
        }
        return "0x" as Hex;
    }
}

/**
 * Create a PrivacyRouterClient instance.
 */
export function createPrivacyRouterClient(config: PrivacyRouterConfig): PrivacyRouterClient {
    return new PrivacyRouterClient(config);
}
