// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IUniversalChainAdapter
 * @author ZASEON
 * @notice Universal interface for chain-agnostic adapters across all blockchain ecosystems
 * @dev Every chain adapter (EVM, Solana, StarkNet, Aptos, Midnight, Zcash, etc.)
 *      implements the EVM-side of this interface. Non-EVM chains also implement an
 *      equivalent adapter in their native language (Rust, Cairo, Move, etc.).
 *
 * ARCHITECTURE:
 *
 *   ┌──────────────────────────────────────────────────────────────────────────┐
 *   │                    ZASEON Universal Adapter Layer                 │
 *   ├──────────────────────────────────────────────────────────────────────────┤
 *   │                                                                          │
 *   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
 *   │  │   EVM    │  │  Solana  │  │ StarkNet │  │   Move   │  │ Privacy  │  │
 *   │  │ Adapter  │  │ Adapter  │  │ Adapter  │  │ Adapter  │  │ Adapter  │  │
 *   │  │(L1 + L2) │  │  (SVM)  │  │ (Cairo)  │  │(Aptos/   │  │(Aztec/   │  │
 *   │  │          │  │          │  │          │  │ Sui)     │  │ Midnight │  │
 *   │  │          │  │          │  │          │  │          │  │ /Zcash)  │  │
 *   │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
 *   │       │             │             │             │             │          │
 *   │       └─────────────┴──────┬──────┴─────────────┴─────────────┘          │
 *   │                            │                                             │
 *   │                    ┌───────▼───────┐                                     │
 *   │                    │  Proof Hub +  │                                     │
 *   │                    │  Nullifier    │                                     │
 *   │                    │  Registry     │                                     │
 *   │                    └───────────────┘                                     │
 *   └──────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED CHAIN TYPES:
 * - EVM L1: Ethereum mainnet
 * - EVM L2: Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM
 * - Solana: SVM (Rust programs)
 * - StarkNet: Cairo (STARK proofs)
 * - Move: Aptos, Sui
 * - Privacy-native: Aztec (Noir), Midnight (Compact), Zcash (shielded), Aleo (Leo)
 * - Cosmos: CosmWasm chains
 * - Other: TON, NEAR, Polkadot, Bitcoin (BitVM), XRPL, Cardano
 */
interface IUniversalChainAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Virtual machine / execution environment classification
    enum ChainVM {
        EVM, // Ethereum Virtual Machine (Solidity)
        SVM, // Solana Virtual Machine (Rust/BPF)
        CAIRO, // StarkNet (Cairo)
        MOVE_APTOS, // Aptos Move VM
        MOVE_SUI, // Sui Move VM
        COSMWASM, // Cosmos CosmWasm (Rust)
        NOIR_AZTEC, // Aztec (Noir circuits, privacy-native)
        MIDNIGHT, // Midnight (Compact/Haskell, ZK-native)
        ZCASH, // Zcash (shielded pool, Groth16)
        ALEO, // Aleo (Leo/snarkVM)
        TON, // TON (FunC/Fift)
        NEAR, // NEAR (Rust/WASM)
        SUBSTRATE, // Polkadot/Substrate (ink!/Rust)
        BITCOIN, // Bitcoin (Script/BitVM)
        XRPL, // XRP Ledger (Hooks)
        PLUTUS // Cardano (Plutus/Haskell)
    }

    /// @notice Proof system classification for cross-VM proof translation
    enum ProofSystem {
        GROTH16, // BN254/BLS12-381 Groth16 (Zcash, EVM default)
        PLONK, // PLONK (Aztec, Noir)
        STARK, // STARK (StarkNet, Polygon Miden)
        BULLETPROOFS, // Bulletproofs (Monero-style range proofs)
        HALO2, // Halo2 (Zcash Orchard, Scroll)
        NOVA, // Nova folding scheme (recursive)
        ULTRAPLONK, // UltraPlonk (Aztec Noir)
        HONK // Honk (Aztec successor to UltraPlonk)
    }

    /// @notice Chain network classification
    enum ChainLayer {
        L1_PUBLIC, // Public L1 (Ethereum, Solana, Aptos)
        L1_PRIVATE, // Privacy-native L1 (Midnight, Zcash, Aleo)
        L2_ROLLUP, // L2 rollup (Arbitrum, Optimism, zkSync, StarkNet)
        L2_VALIDIUM, // L2 validium (Polygon zkEVM)
        L3_APP_CHAIN, // L3 app-specific chain
        SIDECHAIN, // Sidechain (Polygon PoS)
        COSMOS_ZONE // Cosmos IBC zone
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Descriptor for a connected chain
    struct ChainDescriptor {
        bytes32 universalChainId; // Universal identifier across all ecosystems
        uint256 nativeChainId; // Native chain ID (e.g. EVM chainId, Solana cluster hash)
        ChainVM vm; // Execution environment
        ChainLayer layer; // Network layer classification
        ProofSystem proofSystem; // Native proof system
        string name; // Human-readable name
        bool active; // Whether adapter is operational
    }

    /// @notice Cross-chain proof envelope (chain-agnostic)
    struct UniversalProof {
        bytes32 proofId; // Unique proof identifier
        bytes32 sourceChainId; // Source chain universal ID
        bytes32 destChainId; // Destination chain universal ID
        ProofSystem proofSystem; // Proof system used
        bytes proof; // Serialized proof data
        bytes32[] publicInputs; // Public inputs
        bytes32 stateCommitment; // State commitment being proven
        bytes32 nullifier; // Nullifier for double-spend prevention
        uint256 timestamp; // Proof generation timestamp
    }

    /// @notice Cross-chain encrypted state transfer
    struct EncryptedStateTransfer {
        bytes32 transferId; // Unique transfer identifier
        bytes32 sourceChainId; // Origin chain
        bytes32 destChainId; // Destination chain
        bytes32 stateCommitment; // Commitment to encrypted state
        bytes encryptedPayload; // Encrypted state data
        bytes32 nullifier; // Nullifier for source chain
        bytes32 newCommitment; // New commitment on destination
        bytes proof; // ZK proof of valid transition
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a cross-chain proof is submitted
    event UniversalProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        ProofSystem proofSystem
    );

    /// @notice Emitted when a proof is verified on the destination
    event ProofVerifiedOnDestination(
        bytes32 indexed proofId,
        bytes32 indexed chainId,
        bool valid
    );

    /// @notice Emitted when encrypted state is bridged
    event EncryptedStateBridged(
        bytes32 indexed transferId,
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        bytes32 nullifier
    );

    /// @notice Emitted when a chain adapter is registered
    event ChainAdapterRegistered(
        bytes32 indexed universalChainId,
        ChainVM vm,
        ChainLayer layer
    );

    /*//////////////////////////////////////////////////////////////
                             CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ChainNotSupported(bytes32 chainId);
    error InvalidProofSystem(ProofSystem expected, ProofSystem actual);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error ProofVerificationFailed(bytes32 proofId);
    error TransferAlreadyProcessed(bytes32 transferId);
    error ChainAdapterNotActive(bytes32 chainId);
    error IncompatibleProofSystems(ProofSystem source, ProofSystem dest);
    error ZeroAddress();
    error InvalidStateCommitment();
    error ProofExpired(uint256 timestamp, uint256 maxAge);

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the chain descriptor for this adapter
    /// @return descriptor The chain configuration and metadata
    function getChainDescriptor()
        external
        view
        returns (ChainDescriptor memory descriptor);

    /// @notice Get the universal chain identifier
    /// @return The universal chain ID (deterministic across all ecosystems)
    function getUniversalChainId() external view returns (bytes32);

    /// @notice Get the native proof system for this chain
    /// @return The proof system used natively by this chain
    function getNativeProofSystem() external view returns (ProofSystem);

    /// @notice Verify a ZK proof on this chain
    /// @param proof The serialized ZK proof
    /// @param publicInputs The public inputs to the proof
    /// @param proofSystem The proof system used
    /// @return valid Whether the proof verified successfully
    function verifyProof(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        ProofSystem proofSystem
    ) external view returns (bool valid);

    /// @notice Submit encrypted state from another chain
    /// @param transfer The encrypted state transfer data
    /// @return success Whether the state was accepted
    function receiveEncryptedState(
        EncryptedStateTransfer calldata transfer
    ) external returns (bool success);

    /// @notice Send encrypted state to another chain
    /// @param destChainId The destination chain universal ID
    /// @param stateCommitment The commitment to the state
    /// @param encryptedPayload The encrypted state data
    /// @param proof The ZK proof of valid state transition
    /// @param nullifier The nullifier for this chain
    /// @return transferId The unique transfer identifier
    function sendEncryptedState(
        bytes32 destChainId,
        bytes32 stateCommitment,
        bytes calldata encryptedPayload,
        bytes calldata proof,
        bytes32 nullifier
    ) external returns (bytes32 transferId);

    /// @notice Submit a universal proof for cross-chain verification
    /// @param universalProof The chain-agnostic proof envelope
    /// @return proofId The proof identifier for tracking
    function submitUniversalProof(
        UniversalProof calldata universalProof
    ) external returns (bytes32 proofId);

    /// @notice Check if a nullifier has been used on this chain
    /// @param nullifier The nullifier to check
    /// @return used Whether the nullifier has been consumed
    function isNullifierUsed(
        bytes32 nullifier
    ) external view returns (bool used);

    /// @notice Check if a proof system is supported by this adapter
    /// @param proofSystem The proof system to check
    /// @return supported Whether the proof system can be verified
    function isProofSystemSupported(
        ProofSystem proofSystem
    ) external view returns (bool supported);

    /// @notice Translate a proof from one system to another (if supported)
    /// @dev Not all translations are possible; reverts with IncompatibleProofSystems if not
    /// @param proof The original proof
    /// @param publicInputs The public inputs
    /// @param fromSystem The source proof system
    /// @param toSystem The target proof system
    /// @return translatedProof The proof in the target system format
    function translateProof(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        ProofSystem fromSystem,
        ProofSystem toSystem
    ) external view returns (bytes memory translatedProof);
}
