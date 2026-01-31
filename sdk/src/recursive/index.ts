/**
 * Soul Recursive Proof SDK
 * 
 * Implements:
 * - Nova-style Incremental Verifiable Computation (IVC)
 * - Folding schemes (Sangria variant)
 * - Proof aggregation for gas optimization
 * - Cross-system recursion (Groth16 ↔ PLONK ↔ Noir)
 */

import { 
    keccak256, 
    encodeAbiParameters, 
    concat, 
    toBytes, 
    toHex,
    zeroHash,
    getContract,
    type PublicClient,
    type WalletClient,
    type Hex,
    type Abi
} from "viem";

// ============================================
// Types
// ============================================

export interface SoulState {
    merkleRoot: string;
    totalSupply: bigint;
    nonce: bigint;
    lastUpdateBlock: bigint;
}

export interface FoldedInstance {
    commitmentU: string;
    commitmentE: string;
    scalar: bigint;
    publicInputHash: string;
    round: number;
}

export interface IVCProof {
    currentState: SoulState;
    foldedInstance: FoldedInstance;
    stepProof: Uint8Array;
    previousStateHash: string;
    transitionProof: Uint8Array;
}

export interface AggregatedProof {
    proofHashes: string[];
    combinedProof: Uint8Array;
    merkleRoot: string;
    publicInputsCommitment: string;
    totalVerified: number;
}

export interface ProofInput {
    proof: Uint8Array;
    publicInputs: Uint8Array;
    proofSystem: string;
}

export interface RecursionConfig {
    maxBatchSize: number;
    targetGasSavings: number;
    verifierAddress?: string;
}

// ============================================
// IVC Manager
// ============================================

export class SoulIVCManager {
    private currentState: SoulState;
    private foldingHistory: FoldedInstance[] = [];
    private config: RecursionConfig;

    constructor(initialState: SoulState, config: RecursionConfig = { maxBatchSize: 32, targetGasSavings: 70 }) {
        this.currentState = initialState;
        this.config = config;
    }

    /**
     * Create genesis IVC state
     */
    static createGenesis(): SoulState {
        return {
            merkleRoot: zeroHash,
            totalSupply: 0n,
            nonce: 0n,
            lastUpdateBlock: 0n
        };
    }

    /**
     * Get current state
     */
    getState(): SoulState {
        return { ...this.currentState };
    }

    /**
     * Hash Soul state for commitments
     */
    hashState(state: SoulState): string {
        return keccak256(encodeAbiParameters(
            [{ type: "bytes32" }, { type: "uint256" }, { type: "uint256" }, { type: "uint256" }],
            [state.merkleRoot as Hex, state.totalSupply, state.nonce, state.lastUpdateBlock]
        ));
    }

    /**
     * Perform IVC step with state transition
     */
    async step(
        newMerkleRoot: string,
        supplyDelta: bigint,
        blockNumber: bigint,
        transitionWitness: Uint8Array
    ): Promise<IVCProof> {
        const previousStateHash = this.hashState(this.currentState);

        // Update state
        const newState: SoulState = {
            merkleRoot: newMerkleRoot,
            totalSupply: this.currentState.totalSupply + supplyDelta,
            nonce: this.currentState.nonce + 1n,
            lastUpdateBlock: blockNumber
        };

        // Create folded instance
        const foldedInstance = await this.fold(previousStateHash, this.hashState(newState));

        // Generate step proof
        const stepProof = await this.generateStepProof(
            this.currentState,
            newState,
            transitionWitness
        );

        // Generate transition proof
        const transitionProof = await this.generateTransitionProof(
            previousStateHash,
            newState,
            foldedInstance
        );

        // Update current state
        this.currentState = newState;
        this.foldingHistory.push(foldedInstance);

        return {
            currentState: newState,
            foldedInstance,
            stepProof,
            previousStateHash,
            transitionProof
        };
    }

    /**
     * Nova-style folding operation
     */
    private async fold(
        previousHash: string,
        currentHash: string
    ): Promise<FoldedInstance> {
        // Compute challenge for folding
        const challenge = keccak256(concat([
            toBytes(previousHash as Hex),
            toBytes(currentHash as Hex)
        ]));

        // Compute random scalar for folding
        const scalar = BigInt(challenge) % (2n ** 254n);

        // Compute commitments (simplified - real impl uses polynomial commitments)
        const commitmentU = keccak256(encodeAbiParameters(
            [{ type: "bytes32" }, { type: "uint256" }],
            [previousHash as Hex, scalar]
        ));

        const commitmentE = keccak256(encodeAbiParameters(
            [{ type: "bytes32" }, { type: "uint256" }],
            [currentHash as Hex, scalar]
        ));

        return {
            commitmentU,
            commitmentE,
            scalar,
            publicInputHash: currentHash,
            round: this.foldingHistory.length + 1
        };
    }

    /**
     * Generate step proof
     */
    private async generateStepProof(
        _oldState: SoulState,
        _newState: SoulState,
        _witness: Uint8Array
    ): Promise<Uint8Array> {
        // Mock proof generation
        // Real implementation uses Noir/SP1 prover
        const proof = new Uint8Array(256);
        crypto.getRandomValues(proof);
        return proof;
    }

    /**
     * Generate transition proof
     */
    private async generateTransitionProof(
        _previousHash: string,
        _newState: SoulState,
        _foldedInstance: FoldedInstance
    ): Promise<Uint8Array> {
        const proof = new Uint8Array(128);
        crypto.getRandomValues(proof);
        return proof;
    }

    /**
     * Verify IVC proof
     */
    async verifyIVCProof(proof: IVCProof): Promise<boolean> {
        // Verify state transition
        const expectedNonce = BigInt(proof.foldedInstance.round);
        if (proof.currentState.nonce !== expectedNonce) {
            return false;
        }

        // Verify folded instance matches public inputs
        const computedHash = this.hashState(proof.currentState);
        if (proof.foldedInstance.publicInputHash !== computedHash) {
            return false;
        }

        // Verify step proof (mock)
        // Real implementation verifies ZK proof

        return true;
    }

    /**
     * Get folding history
     */
    getFoldingHistory(): FoldedInstance[] {
        return [...this.foldingHistory];
    }

    /**
     * Export state for persistence
     */
    export(): {
        state: SoulState;
        history: FoldedInstance[];
    } {
        return {
            state: this.currentState,
            history: this.foldingHistory
        };
    }

    /**
     * Import state from persistence
     */
    import(data: { state: SoulState; history: FoldedInstance[] }): void {
        this.currentState = data.state;
        this.foldingHistory = data.history;
    }
}

// ============================================
// Proof Aggregator
// ============================================

export class SoulProofAggregator {
    private pendingProofs: ProofInput[] = [];
    private config: RecursionConfig;
    private aggregatedProofs: AggregatedProof[] = [];

    constructor(config: RecursionConfig = { maxBatchSize: 32, targetGasSavings: 70 }) {
        this.config = config;
    }

    /**
     * Add proof to aggregation batch
     */
    addProof(proof: ProofInput): void {
        this.pendingProofs.push(proof);
    }

    /**
     * Check if batch is ready for aggregation
     */
    isBatchReady(): boolean {
        return this.pendingProofs.length >= this.config.maxBatchSize;
    }

    /**
     * Get pending proof count
     */
    getPendingCount(): number {
        return this.pendingProofs.length;
    }

    /**
     * Aggregate pending proofs
     */
    async aggregate(): Promise<AggregatedProof | null> {
        if (this.pendingProofs.length === 0) {
            return null;
        }

        const batch = this.pendingProofs.splice(0, this.config.maxBatchSize);

        // Compute proof hashes
        const proofHashes = batch.map(p => 
            keccak256(p.proof)
        );

        // Build Merkle tree of proofs
        const merkleRoot = this.computeMerkleRoot(proofHashes);

        // Compute public inputs commitment
        const publicInputsCommitment = keccak256(
            concat(batch.map(p => p.publicInputs))
        );

        // Generate aggregated proof
        const combinedProof = await this.generateAggregatedProof(batch, merkleRoot);

        const aggregated: AggregatedProof = {
            proofHashes,
            combinedProof,
            merkleRoot,
            publicInputsCommitment,
            totalVerified: batch.length
        };

        this.aggregatedProofs.push(aggregated);

        return aggregated;
    }

    /**
     * Compute Merkle root of proof hashes
     */
    private computeMerkleRoot(hashes: string[]): string {
        if (hashes.length === 0) return zeroHash;
        if (hashes.length === 1) return hashes[0];

        // Pad to power of 2
        const paddedLength = Math.pow(2, Math.ceil(Math.log2(hashes.length)));
        const padded = [...hashes];
        while (padded.length < paddedLength) {
            padded.push(zeroHash);
        }

        // Build tree
        let level = padded;
        while (level.length > 1) {
            const nextLevel: string[] = [];
            for (let i = 0; i < level.length; i += 2) {
                nextLevel.push(keccak256(concat([
                    toBytes(level[i] as Hex),
                    toBytes(level[i + 1] as Hex)
                ])));
            }
            level = nextLevel;
        }

        return level[0];
    }

    /**
     * Generate aggregated proof
     */
    private async generateAggregatedProof(
        _batch: ProofInput[],
        _merkleRoot: string
    ): Promise<Uint8Array> {
        // Mock aggregated proof
        // Real implementation uses recursive SNARK
        const proof = new Uint8Array(512);
        crypto.getRandomValues(proof);
        return proof;
    }

    /**
     * Generate Merkle proof for inclusion
     */
    generateInclusionProof(
        aggregated: AggregatedProof,
        proofIndex: number
    ): string[] {
        const hashes = aggregated.proofHashes;
        const paddedLength = Math.pow(2, Math.ceil(Math.log2(hashes.length)));
        const padded = [...hashes];
        while (padded.length < paddedLength) {
            padded.push(zeroHash);
        }

        const path: string[] = [];
        let index = proofIndex;
        let level = padded;

        while (level.length > 1) {
            const sibling = index % 2 === 0 ? index + 1 : index - 1;
            path.push(level[sibling]);

            const nextLevel: string[] = [];
            for (let i = 0; i < level.length; i += 2) {
                nextLevel.push(keccak256(concat([
                    toBytes(level[i] as Hex),
                    toBytes(level[i + 1] as Hex)
                ])));
            }
            level = nextLevel;
            index = Math.floor(index / 2);
        }

        return path;
    }

    /**
     * Verify inclusion proof
     */
    verifyInclusionProof(
        proofHash: string,
        merkleRoot: string,
        path: string[],
        index: number
    ): boolean {
        let computed = proofHash;
        let currentIndex = index;

        for (const sibling of path) {
            if (currentIndex % 2 === 0) {
                computed = keccak256(concat([
                    toBytes(computed as Hex),
                    toBytes(sibling as Hex)
                ]));
            } else {
                computed = keccak256(concat([
                    toBytes(sibling as Hex),
                    toBytes(computed as Hex)
                ]));
            }
            currentIndex = Math.floor(currentIndex / 2);
        }

        return computed === merkleRoot;
    }

    /**
     * Estimate gas savings from aggregation
     */
    estimateGasSavings(individualGas: number, batchSize: number): {
        withoutAggregation: number;
        withAggregation: number;
        savings: number;
        savingsPercent: number;
    } {
        const withoutAggregation = individualGas * batchSize;
        
        // Aggregated verification is ~O(log n) instead of O(n)
        const aggregationOverhead = 50000; // Base overhead
        const perProofOverhead = 2000; // Per-proof Merkle verification
        const withAggregation = aggregationOverhead + (perProofOverhead * Math.log2(batchSize) * batchSize);

        const savings = withoutAggregation - withAggregation;
        const savingsPercent = (savings / withoutAggregation) * 100;

        return {
            withoutAggregation,
            withAggregation: Math.ceil(withAggregation),
            savings: Math.ceil(savings),
            savingsPercent: Math.round(savingsPercent)
        };
    }

    /**
     * Get aggregation history
     */
    getAggregationHistory(): AggregatedProof[] {
        return [...this.aggregatedProofs];
    }
}

// ============================================
// Cross-System Recursion
// ============================================

export type ProofSystemType = "groth16" | "plonk" | "noir" | "sp1" | "plonky3";

export interface CrossSystemProof {
    sourceSystem: ProofSystemType;
    targetSystem: ProofSystemType;
    originalProof: Uint8Array;
    wrappedProof: Uint8Array;
    intermediateHash: string;
}

export class SoulCrossSystemRecursor {
    private wrapperCircuits: Map<string, Uint8Array> = new Map();

    /**
     * Wrap proof from one system for verification in another
     */
    async wrapProof(
        proof: Uint8Array,
        publicInputs: Uint8Array,
        sourceSystem: ProofSystemType,
        targetSystem: ProofSystemType
    ): Promise<CrossSystemProof> {
        const key = `${sourceSystem}->${targetSystem}`;

        // Compute intermediate hash
        const intermediateHash = keccak256(concat([
            proof,
            publicInputs
        ]));

        // Generate wrapped proof
        const wrappedProof = await this.generateWrapper(
            proof,
            publicInputs,
            sourceSystem,
            targetSystem
        );

        return {
            sourceSystem,
            targetSystem,
            originalProof: proof,
            wrappedProof,
            intermediateHash
        };
    }

    /**
     * Generate wrapper proof
     */
    private async generateWrapper(
        _proof: Uint8Array,
        _publicInputs: Uint8Array,
        _source: ProofSystemType,
        _target: ProofSystemType
    ): Promise<Uint8Array> {
        // Mock wrapper proof
        // Real implementation generates recursive SNARK
        const wrapped = new Uint8Array(384);
        crypto.getRandomValues(wrapped);
        return wrapped;
    }

    /**
     * Verify cross-system proof
     */
    async verifyCrossSystemProof(crossProof: CrossSystemProof): Promise<boolean> {
        // Verify wrapped proof in target system
        // Mock verification
        return crossProof.wrappedProof.length > 0;
    }

    /**
     * Check if cross-system wrapping is supported
     */
    isSupported(source: ProofSystemType, target: ProofSystemType): boolean {
        const supportedPairs = [
            ["groth16", "plonk"],
            ["plonk", "groth16"],
            ["noir", "groth16"],
            ["sp1", "groth16"],
            ["plonky3", "groth16"]
        ];

        return supportedPairs.some(([s, t]) => s === source && t === target);
    }

    /**
     * Get optimal target system for on-chain verification
     */
    getOptimalTargetSystem(): ProofSystemType {
        // Groth16 is most gas-efficient for on-chain verification
        return "groth16";
    }
}

// ============================================
// On-Chain Verifier Client
// ============================================

export class SoulRecursiveVerifierClient {
    private publicClient: PublicClient;
    private walletClient?: WalletClient;
    private verifierContract: any;

    constructor(publicClient: PublicClient, verifierAddress: string, abi: Abi, walletClient?: WalletClient) {
        this.publicClient = publicClient;
        this.walletClient = walletClient;
        this.verifierContract = getContract({
            address: verifierAddress as Hex,
            abi,
            client: { public: publicClient, wallet: walletClient }
        });
    }

    /**
     * Submit aggregated proof for verification
     */
    async verifyAggregated(
        aggregated: AggregatedProof
    ): Promise<{ success: boolean; txHash: string; gasUsed: bigint }> {
        if (!this.walletClient) throw new Error("Wallet client required for write operations");

        const proofData = {
            merkleRoot: aggregated.merkleRoot,
            publicInputsCommitment: aggregated.publicInputsCommitment,
            proofCount: BigInt(aggregated.totalVerified),
            aggregatedProof: toHex(aggregated.combinedProof)
        };

        const hash = await this.verifierContract.write.verifyAggregatedProof([proofData]);
        const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

        return {
            success: true,
            txHash: receipt.transactionHash,
            gasUsed: receipt.gasUsed
        };
    }

    /**
     * Verify single proof for backward compatibility
     */
    async verifySingle(
        proof: Uint8Array,
        publicInputs: Uint8Array
    ): Promise<{ success: boolean; txHash: string; gasUsed: bigint }> {
        if (!this.walletClient) throw new Error("Wallet client required for write operations");

        const hash = await this.verifierContract.write.verifySingleProof([
            toHex(proof),
            toHex(publicInputs)
        ]);
        const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

        return {
            success: true,
            txHash: receipt.transactionHash,
            gasUsed: receipt.gasUsed
        };
    }

    /**
     * Estimate gas for aggregated verification
     */
    async estimateGas(aggregated: AggregatedProof): Promise<bigint> {
        const proofData = {
            merkleRoot: aggregated.merkleRoot,
            publicInputsCommitment: aggregated.publicInputsCommitment,
            proofCount: BigInt(aggregated.totalVerified),
            aggregatedProof: toHex(aggregated.combinedProof)
        };

        return await this.verifierContract.estimateGas.verifyAggregatedProof([proofData]);
    }

    /**
     * Check if proof was already verified
     */
    async isVerified(proofHash: string): Promise<boolean> {
        return await this.verifierContract.read.verifiedProofs([proofHash as Hex]);
    }
}

// ============================================
// Factory Functions
// ============================================

export function createIVCManager(
    initialState?: SoulState,
    config?: RecursionConfig
): SoulIVCManager {
    return new SoulIVCManager(
        initialState || SoulIVCManager.createGenesis(),
        config
    );
}

export function createProofAggregator(config?: RecursionConfig): SoulProofAggregator {
    return new SoulProofAggregator(config);
}

export function createCrossSystemRecursor(): SoulCrossSystemRecursor {
    return new SoulCrossSystemRecursor();
}

export function createVerifierClient(
    publicClient: PublicClient,
    verifierAddress: string,
    abi: Abi,
    walletClient?: WalletClient
): SoulRecursiveVerifierClient {
    return new SoulRecursiveVerifierClient(publicClient, verifierAddress, abi, walletClient);
}

// ============================================
// Export All
// ============================================

export default {
    SoulIVCManager,
    SoulProofAggregator,
    SoulCrossSystemRecursor,
    SoulRecursiveVerifierClient,
    createIVCManager,
    createProofAggregator,
    createCrossSystemRecursor,
    createVerifierClient
};
