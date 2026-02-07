/**
 * Relayer Fee Market Client
 *
 * SDK client for interacting with the RelayerFeeMarket contract.
 * Enables users to submit relay requests and relayers to claim/complete them.
 */

import {
    type PublicClient,
    type WalletClient,
    type Hex,
    type Address,
    zeroAddress,
} from "viem";

/*//////////////////////////////////////////////////////////////
                          TYPES
//////////////////////////////////////////////////////////////*/

export interface RelayerFeeMarketConfig {
    publicClient: PublicClient;
    walletClient?: WalletClient;
    feeMarketAddress: Address;
}

export enum RequestStatus {
    NONE = 0,
    PENDING = 1,
    CLAIMED = 2,
    COMPLETED = 3,
    CANCELLED = 4,
    EXPIRED = 5,
}

export interface RelayRequest {
    requestId: Hex;
    sender: Address;
    relayer: Address;
    sourceChain: number;
    destChain: number;
    fee: bigint;
    deadline: bigint;
    status: RequestStatus;
    proofData: Hex;
}

export interface FeeEstimate {
    baseFee: bigint;
    protocolFee: bigint;
    totalFee: bigint;
}

/*//////////////////////////////////////////////////////////////
                          ABI
//////////////////////////////////////////////////////////////*/

const RELAYER_FEE_MARKET_ABI = [
    {
        name: "submitRelayRequest",
        type: "function",
        stateMutability: "payable",
        inputs: [
            { name: "sourceChain", type: "uint256" },
            { name: "destChain", type: "uint256" },
            { name: "proofData", type: "bytes" },
            { name: "deadline", type: "uint256" },
        ],
        outputs: [{ name: "requestId", type: "bytes32" }],
    },
    {
        name: "claimRelayRequest",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "requestId", type: "bytes32" }],
        outputs: [],
    },
    {
        name: "completeRelay",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [
            { name: "requestId", type: "bytes32" },
            { name: "completionProof", type: "bytes" },
        ],
        outputs: [],
    },
    {
        name: "cancelRelayRequest",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "requestId", type: "bytes32" }],
        outputs: [],
    },
    {
        name: "expireRelayRequest",
        type: "function",
        stateMutability: "nonpayable",
        inputs: [{ name: "requestId", type: "bytes32" }],
        outputs: [],
    },
    {
        name: "estimateFee",
        type: "function",
        stateMutability: "view",
        inputs: [
            { name: "sourceChain", type: "uint256" },
            { name: "destChain", type: "uint256" },
        ],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        name: "getRelayRequest",
        type: "function",
        stateMutability: "view",
        inputs: [{ name: "requestId", type: "bytes32" }],
        outputs: [
            {
                name: "",
                type: "tuple",
                components: [
                    { name: "sender", type: "address" },
                    { name: "relayer", type: "address" },
                    { name: "sourceChain", type: "uint256" },
                    { name: "destChain", type: "uint256" },
                    { name: "fee", type: "uint256" },
                    { name: "deadline", type: "uint256" },
                    { name: "status", type: "uint8" },
                    { name: "proofData", type: "bytes" },
                ],
            },
        ],
    },
    {
        name: "protocolFeeBps",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        name: "accumulatedProtocolFees",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
] as const;

/*//////////////////////////////////////////////////////////////
                RELAYER FEE MARKET CLIENT
//////////////////////////////////////////////////////////////*/

export class RelayerFeeMarketClient {
    public readonly publicClient: PublicClient;
    public readonly walletClient?: WalletClient;
    public readonly feeMarketAddress: Address;

    constructor(config: RelayerFeeMarketConfig) {
        this.publicClient = config.publicClient;
        this.walletClient = config.walletClient;
        this.feeMarketAddress = config.feeMarketAddress;
    }

    /*//////////////////////////////////////////////////////////////
                        USER OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Submit a relay request with the required fee.
     * @param sourceChain - Source chain ID
     * @param destChain - Destination chain ID
     * @param proofData - Proof data to relay
     * @param deadline - Unix timestamp deadline
     * @param fee - Fee to attach (in wei). Use estimateFee() first.
     * @returns requestId and transaction hash
     */
    async submitRelayRequest(
        sourceChain: number,
        destChain: number,
        proofData: Hex,
        deadline: bigint,
        fee: bigint,
    ): Promise<{ requestId: Hex; txHash: Hex }> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "submitRelayRequest",
            args: [BigInt(sourceChain), BigInt(destChain), proofData, deadline],
            value: fee,
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });

        // Parse request ID from event logs
        const requestId = this.parseRequestId(receipt.logs);

        return { requestId, txHash };
    }

    /**
     * Cancel a pending (unclaimed) relay request and receive a refund.
     */
    async cancelRelayRequest(requestId: Hex): Promise<Hex> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "cancelRelayRequest",
            args: [requestId],
        });

        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        return txHash;
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Claim a pending relay request (relayer only).
     * After claiming, the relayer must complete the relay before the claim timeout.
     */
    async claimRelayRequest(requestId: Hex): Promise<Hex> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "claimRelayRequest",
            args: [requestId],
        });

        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        return txHash;
    }

    /**
     * Complete a claimed relay request with the completion proof.
     * The fee is transferred to the relayer upon successful completion.
     */
    async completeRelay(requestId: Hex, completionProof: Hex): Promise<Hex> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "completeRelay",
            args: [requestId, completionProof],
        });

        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        return txHash;
    }

    /**
     * Expire a relay request that has passed its deadline or claim timeout.
     * Anyone can call this to clean up expired requests.
     */
    async expireRelayRequest(requestId: Hex): Promise<Hex> {
        this.requireWallet();

        const txHash = await this.walletClient!.writeContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "expireRelayRequest",
            args: [requestId],
        });

        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        return txHash;
    }

    /*//////////////////////////////////////////////////////////////
                        READ OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * Estimate the required fee for a relay on a specific route.
     */
    async estimateFee(sourceChain: number, destChain: number): Promise<bigint> {
        return await this.publicClient.readContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "estimateFee",
            args: [BigInt(sourceChain), BigInt(destChain)],
        });
    }

    /**
     * Estimate fee with protocol fee breakdown.
     */
    async estimateFeeWithBreakdown(sourceChain: number, destChain: number): Promise<FeeEstimate> {
        const [baseFee, protocolFeeBps] = await Promise.all([
            this.estimateFee(sourceChain, destChain),
            this.getProtocolFeeBps(),
        ]);

        const protocolFee = (baseFee * protocolFeeBps) / 10000n;

        return {
            baseFee,
            protocolFee,
            totalFee: baseFee + protocolFee,
        };
    }

    /**
     * Get the details of a relay request.
     */
    async getRelayRequest(requestId: Hex): Promise<RelayRequest> {
        const result = await this.publicClient.readContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "getRelayRequest",
            args: [requestId],
        });

        return {
            requestId,
            sender: result.sender,
            relayer: result.relayer,
            sourceChain: Number(result.sourceChain),
            destChain: Number(result.destChain),
            fee: result.fee,
            deadline: result.deadline,
            status: result.status as RequestStatus,
            proofData: result.proofData,
        };
    }

    /**
     * Get the current protocol fee in basis points.
     */
    async getProtocolFeeBps(): Promise<bigint> {
        return await this.publicClient.readContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "protocolFeeBps",
        });
    }

    /**
     * Get the total accumulated protocol fees.
     */
    async getAccumulatedProtocolFees(): Promise<bigint> {
        return await this.publicClient.readContract({
            address: this.feeMarketAddress,
            abi: RELAYER_FEE_MARKET_ABI,
            functionName: "accumulatedProtocolFees",
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

    private parseRequestId(logs: readonly { data: Hex; topics: readonly Hex[] }[]): Hex {
        for (const log of logs) {
            if (log.topics.length >= 2) {
                return log.topics[1] as Hex;
            }
        }
        return "0x" as Hex;
    }
}

/**
 * Create a RelayerFeeMarketClient instance.
 */
export function createRelayerFeeMarketClient(config: RelayerFeeMarketConfig): RelayerFeeMarketClient {
    return new RelayerFeeMarketClient(config);
}
