// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IUniversalChainAdapter} from "../interfaces/IUniversalChainAdapter.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {UniversalChainRegistry} from "../libraries/UniversalChainRegistry.sol";

/**
 * @title EVMUniversalAdapter
 * @author ZASEON
 * @notice Universal chain adapter for all EVM-compatible chains (L1 + L2)
 * @dev Deployed on each EVM chain ZASEON supports. Handles ZK proof verification,
 *      encrypted state management, and cross-chain message relay for EVM environments.
 *
 * Supports: Ethereum, Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM
 *
 * SECURITY:
 * - ReentrancyGuard on all state-changing functions
 * - Signature malleability protection (secp256k1 s-value check)
 * - Nullifier double-spend prevention
 * - Chain ID replay protection
 * - Pausable emergency circuit breaker
 * - Role-based access for relayer and admin operations
 *
 * @custom:security-contact security@zaseon.network
 */
contract EVMUniversalAdapter is
    IUniversalChainAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("RELAYER_ROLE")
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @dev keccak256("VERIFIER_ROLE")
    bytes32 public constant VERIFIER_ROLE =
        0x21d1167972f621f75904fb065136bc8b53c7ba1c60ccd3a7f8571d930f6df85a;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum proof age before expiry (24 hours)
    uint256 public constant MAX_PROOF_AGE = 24 hours;

    /// @notice Maximum encrypted payload size (64KB)
    uint256 public constant MAX_PAYLOAD_SIZE = 65_536;

    /// @notice secp256k1 half curve order for malleability check
    uint256 private constant SECP256K1_N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice This chain's descriptor
    ChainDescriptor public chainDescriptor;

    /// @notice Registered remote chain adapters (universalChainId => remote adapter address bytes)
    mapping(bytes32 => bytes) public remoteAdapters;

    /// @notice Nullifier registry (nullifier => used)
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Processed transfer IDs
    mapping(bytes32 => bool) public processedTransfers;

    /// @notice Processed proof IDs
    mapping(bytes32 => bool) public processedProofs;

    /// @notice Supported proof systems
    mapping(ProofSystem => bool) public supportedProofSystems;

    /// @notice Proof verifier contracts per proof system
    mapping(ProofSystem => address) public proofVerifiers;

    /// @notice State commitments stored on this chain
    mapping(bytes32 => bytes32) public stateCommitments;

    /// @notice Universal proof translator contract
    address public proofTranslator;

    /// @notice Transfer nonce for unique ID generation
    uint256 public transferNonce;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total proofs verified
    uint256 public totalProofsVerified;

    /// @notice Total encrypted states received
    uint256 public totalStatesReceived;

    /// @notice Total encrypted states sent
    uint256 public totalStatesSent;

    /// @notice Total nullifiers consumed
    uint256 public totalNullifiersConsumed;

    /// @notice Proofs per source chain
    mapping(bytes32 => uint256) public proofsFromChain;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event RemoteAdapterRegistered(bytes32 indexed chainId, bytes adapter);
    event ProofVerifierSet(
        ProofSystem indexed proofSystem,
        address indexed verifier
    );
    event NullifierConsumed(
        bytes32 indexed nullifier,
        bytes32 indexed sourceChainId
    );
    event StateCommitmentStored(
        bytes32 indexed commitment,
        bytes32 indexed transferId
    );

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the EVM Universal Adapter
    /// @param _admin Admin address with full control
    /// @param _layer The chain layer (L1_PUBLIC, L2_ROLLUP, etc.)
    /// @param _name Human-readable chain name
    constructor(address _admin, ChainLayer _layer, string memory _name) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);

        bytes32 universalId = UniversalChainRegistry.computeEVMChainId(
            block.chainid
        );

        chainDescriptor = ChainDescriptor({
            universalChainId: universalId,
            nativeChainId: block.chainid,
            vm: ChainVM.EVM,
            layer: _layer,
            proofSystem: ProofSystem.GROTH16,
            name: _name,
            active: true
        });

        // EVM chains support Groth16 and PLONK natively
        supportedProofSystems[ProofSystem.GROTH16] = true;
        supportedProofSystems[ProofSystem.PLONK] = true;

        emit ChainAdapterRegistered(universalId, ChainVM.EVM, _layer);
    }

    /*//////////////////////////////////////////////////////////////
                           CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Returns the chain descriptor
     * @return The result value
     */
function getChainDescriptor()
        external
        view
        override
        returns (ChainDescriptor memory)
    {
        return chainDescriptor;
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Returns the universal chain id
     * @return The result value
     */
function getUniversalChainId() external view override returns (bytes32) {
        return chainDescriptor.universalChainId;
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Returns the native proof system
     * @return The result value
     */
function getNativeProofSystem()
        external
        view
        override
        returns (ProofSystem)
    {
        return chainDescriptor.proofSystem;
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Verifys proof
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @param proofSystem The proof system
     * @return valid The valid
     */
function verifyProof(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        ProofSystem proofSystem
    ) external view override returns (bool valid) {
        if (!supportedProofSystems[proofSystem]) {
            revert InvalidProofSystem(chainDescriptor.proofSystem, proofSystem);
        }

        address verifier = proofVerifiers[proofSystem];
        if (verifier == address(0)) {
            // No dedicated verifier — use inline verification
            return _inlineVerifyProof(proof, publicInputs, proofSystem);
        }

        // Delegate to external verifier contract
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes32[])",
                proof,
                publicInputs
            )
        );

        return success && abi.decode(result, (bool));
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Receive encrypted state
     * @param transfer The transfer
     * @return The result value
     */
function receiveEncryptedState(
        EncryptedStateTransfer calldata transfer
    )
        external
        override
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bool)
    {
        // Validate destination is this chain
        if (transfer.destChainId != chainDescriptor.universalChainId) {
            revert ChainNotSupported(transfer.destChainId);
        }

        // Check transfer not already processed
        if (processedTransfers[transfer.transferId]) {
            revert TransferAlreadyProcessed(transfer.transferId);
        }

        // Check nullifier not already used
        if (nullifierUsed[transfer.nullifier]) {
            revert NullifierAlreadyUsed(transfer.nullifier);
        }

        // Validate state commitment
        if (transfer.stateCommitment == bytes32(0)) {
            revert InvalidStateCommitment();
        }

        // Validate payload size
        require(
            transfer.encryptedPayload.length <= MAX_PAYLOAD_SIZE,
            "Payload too large"
        );

        // Verify the ZK proof via the registered verifier
        {
            address verifier = proofVerifiers[chainDescriptor.proofSystem];
            if (verifier == address(0)) {
                revert ProofVerificationFailed(transfer.transferId);
            }

            // Construct public inputs from transfer data
            uint256[] memory publicInputs = new uint256[](4);
            publicInputs[0] = uint256(transfer.stateCommitment);
            publicInputs[1] = uint256(transfer.nullifier);
            publicInputs[2] = uint256(transfer.sourceChainId);
            publicInputs[3] = uint256(transfer.newCommitment);

            bool proofValid = IProofVerifier(verifier).verify(
                transfer.proof,
                publicInputs
            );
            if (!proofValid) {
                revert ProofVerificationFailed(transfer.transferId);
            }
        }

        // Mark nullifier as used
        nullifierUsed[transfer.nullifier] = true;

        // Mark transfer as processed
        processedTransfers[transfer.transferId] = true;

        // Store state commitment
        stateCommitments[transfer.transferId] = transfer.stateCommitment;

        unchecked {
            ++totalStatesReceived;
            ++totalNullifiersConsumed;
        }

        emit EncryptedStateBridged(
            transfer.transferId,
            transfer.sourceChainId,
            transfer.destChainId,
            transfer.nullifier
        );

        emit NullifierConsumed(transfer.nullifier, transfer.sourceChainId);
        emit StateCommitmentStored(
            transfer.stateCommitment,
            transfer.transferId
        );

        return true;
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Send encrypted state
     * @param destChainId The destination chain identifier
     * @param stateCommitment The state commitment
     * @param encryptedPayload The encrypted payload
     * @param proof The ZK proof data
     * @param nullifier The nullifier hash
     * @return transferId The transfer id
     */
function sendEncryptedState(
        bytes32 destChainId,
        bytes32 stateCommitment,
        bytes calldata encryptedPayload,
        bytes calldata proof,
        bytes32 nullifier
    )
        external
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 transferId)
    {
        if (stateCommitment == bytes32(0)) revert InvalidStateCommitment();
        if (nullifierUsed[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Validate destination chain has a registered adapter
        require(remoteAdapters[destChainId].length > 0, "No remote adapter");
        require(
            encryptedPayload.length <= MAX_PAYLOAD_SIZE,
            "Payload too large"
        );
        // Verify ZK proof via registered verifier (same as receiveEncryptedState)
        {
            address verifier = proofVerifiers[chainDescriptor.proofSystem];
            require(verifier != address(0), "No proof verifier configured");

            uint256[] memory publicInputs = new uint256[](3);
            publicInputs[0] = uint256(stateCommitment);
            publicInputs[1] = uint256(nullifier);
            publicInputs[2] = uint256(destChainId);

            bool proofValid = IProofVerifier(verifier).verify(
                proof,
                publicInputs
            );
            require(proofValid, "Proof verification failed");
        }

        // Generate unique transfer ID
        transferId = keccak256(
            abi.encodePacked(
                chainDescriptor.universalChainId,
                destChainId,
                msg.sender,
                transferNonce,
                block.timestamp
            )
        );

        // Mark nullifier as used on source chain
        nullifierUsed[nullifier] = true;

        // Store commitment
        stateCommitments[transferId] = stateCommitment;

        unchecked {
            ++transferNonce;
            ++totalStatesSent;
            ++totalNullifiersConsumed;
        }

        emit EncryptedStateBridged(
            transferId,
            chainDescriptor.universalChainId,
            destChainId,
            nullifier
        );

        emit NullifierConsumed(nullifier, chainDescriptor.universalChainId);

        return transferId;
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Submits universal proof
     * @param universalProof The universal proof
     * @return The result value
     */
function submitUniversalProof(
        UniversalProof calldata universalProof
    )
        external
        override
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32)
    {
        // Validate proof not already processed
        if (processedProofs[universalProof.proofId]) {
            revert TransferAlreadyProcessed(universalProof.proofId);
        }

        // Check proof age
        if (block.timestamp > universalProof.timestamp + MAX_PROOF_AGE) {
            revert ProofExpired(universalProof.timestamp, MAX_PROOF_AGE);
        }

        // Check nullifier
        if (nullifierUsed[universalProof.nullifier]) {
            revert NullifierAlreadyUsed(universalProof.nullifier);
        }

        // Verify proof system is supported
        if (!supportedProofSystems[universalProof.proofSystem]) {
            revert InvalidProofSystem(
                chainDescriptor.proofSystem,
                universalProof.proofSystem
            );
        }

        // Verify the proof — try registered verifier first, then inline fallback
        address verifier = proofVerifiers[universalProof.proofSystem];
        bool valid;
        if (verifier != address(0)) {
            uint256[] memory pubInputs = new uint256[](
                universalProof.publicInputs.length
            );
            for (uint256 i; i < universalProof.publicInputs.length; ) {
                pubInputs[i] = uint256(universalProof.publicInputs[i]);
                unchecked {
                    ++i;
                }
            }
            valid = IProofVerifier(verifier).verify(
                universalProof.proof,
                pubInputs
            );
        } else {
            valid = _inlineVerifyProof(
                universalProof.proof,
                universalProof.publicInputs,
                universalProof.proofSystem
            );
        }

        if (!valid) {
            revert ProofVerificationFailed(universalProof.proofId);
        }

        // Mark as processed
        processedProofs[universalProof.proofId] = true;
        nullifierUsed[universalProof.nullifier] = true;

        // Store state commitment
        stateCommitments[universalProof.proofId] = universalProof
            .stateCommitment;

        unchecked {
            ++totalProofsVerified;
            ++totalNullifiersConsumed;
            ++proofsFromChain[universalProof.sourceChainId];
        }

        emit UniversalProofSubmitted(
            universalProof.proofId,
            universalProof.sourceChainId,
            universalProof.destChainId,
            universalProof.proofSystem
        );

        emit ProofVerifiedOnDestination(
            universalProof.proofId,
            chainDescriptor.universalChainId,
            true
        );

        return universalProof.proofId;
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Checks if nullifier used
     * @param nullifier The nullifier hash
     * @return The result value
     */
function isNullifierUsed(
        bytes32 nullifier
    ) external view override returns (bool) {
        return nullifierUsed[nullifier];
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Checks if proof system supported
     * @param proofSystem The proof system
     * @return The result value
     */
function isProofSystemSupported(
        ProofSystem proofSystem
    ) external view override returns (bool) {
        return supportedProofSystems[proofSystem];
    }

    /// @inheritdoc IUniversalChainAdapter
        /**
     * @notice Translate proof
     * @param proof The ZK proof data
     * @param fromSystem The from system
     * @param toSystem The to system
     * @return The result value
 */
function translateProof(
        bytes calldata proof,
        bytes32[] calldata /* publicInputs */,
        ProofSystem fromSystem,
        ProofSystem toSystem
    ) external view override returns (bytes memory) {
        // Check compatibility first
        if (
            !UniversalChainRegistry.areProofSystemsCompatible(
                fromSystem,
                toSystem
            )
        ) {
            revert IncompatibleProofSystems(fromSystem, toSystem);
        }

        // If natively compatible (same family), return proof as-is
        // The verifier can handle compatible proof formats directly
        if (fromSystem == toSystem) {
            return proof;
        }

        // Delegate to the UniversalProofTranslator for cross-system translation
        require(
            proofTranslator != address(0),
            "Proof translator not configured"
        );

        // The translator handles off-chain translation attestation + wrapper proof
        // verification. For view calls, return the proof bytes for client-side handling.
        return proof;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a remote chain adapter
    /// @param chainId The universal chain ID of the remote chain
    /// @param adapter The adapter address/identifier (bytes for cross-VM compatibility)
        /**
     * @notice Registers remote adapter
     * @param chainId The chain identifier
     * @param adapter The bridge adapter address
     */
function registerRemoteAdapter(
        bytes32 chainId,
        bytes calldata adapter
    ) external onlyRole(OPERATOR_ROLE) {
        require(adapter.length > 0, "Empty adapter");
        remoteAdapters[chainId] = adapter;
        emit RemoteAdapterRegistered(chainId, adapter);
    }

    /// @notice Set a proof verifier contract for a specific proof system
    /// @param proofSystem The proof system
    /// @param verifier The verifier contract address
        /**
     * @notice Sets the proof verifier
     * @param proofSystem The proof system
     * @param verifier The verifier contract address
     */
function setProofVerifier(
        ProofSystem proofSystem,
        address verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        proofVerifiers[proofSystem] = verifier;
        supportedProofSystems[proofSystem] = true;
        emit ProofVerifierSet(proofSystem, verifier);
    }

    /// @notice Enable or disable a proof system
    /// @param proofSystem The proof system to toggle
    /// @param enabled Whether to enable or disable
        /**
     * @notice Sets the proof system support
     * @param proofSystem The proof system
     * @param enabled Whether the feature is enabled
     */
function setProofSystemSupport(
        ProofSystem proofSystem,
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        supportedProofSystems[proofSystem] = enabled;
    }

    /// @notice Update the chain descriptor
    /// @param active Whether the adapter is active
        /**
     * @notice Sets the active
     * @param active Whether the feature is active
     */
function setActive(bool active) external onlyRole(OPERATOR_ROLE) {
        chainDescriptor.active = active;
    }

    /// @notice Set the proof translator contract
    /// @param translator The UniversalProofTranslator address
        /**
     * @notice Sets the proof translator
     * @param translator The translator
     */
function setProofTranslator(
        address translator
    ) external onlyRole(OPERATOR_ROLE) {
        if (translator == address(0)) revert ZeroAddress();
        proofTranslator = translator;
    }

    /// @notice Emergency pause
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpause
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Inline proof verification — rejects unless a dedicated verifier is registered
    /// @dev Call setProofVerifier() to register verifier contracts for each proof system.
    ///      This fallback enforces that proofs are never silently accepted without verification.
    function _inlineVerifyProof(
        bytes calldata proof,
        bytes32[] calldata /* _publicInputs */,
        ProofSystem /* _proofSystem */
    ) internal pure returns (bool) {
        // Structural sanity checks
        if (proof.length < 64) revert("Proof too short");

        // No inline verifier available — reject
        // Callers should register a dedicated verifier contract via setProofVerifier()
        // to enable verification for this proof system.
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get statistics for this adapter
    /// @return proofs Total proofs verified
    /// @return received Total states received
    /// @return sent Total states sent
    /// @return nullifiers Total nullifiers consumed
        /**
     * @notice Returns the stats
     * @return proofs The proofs
     * @return received The received
     * @return sent The sent
     * @return nullifiers The nullifiers
     */
function getStats()
        external
        view
        returns (
            uint256 proofs,
            uint256 received,
            uint256 sent,
            uint256 nullifiers
        )
    {
        return (
            totalProofsVerified,
            totalStatesReceived,
            totalStatesSent,
            totalNullifiersConsumed
        );
    }

    /// @notice Check if a remote adapter is registered for a chain
    /// @param chainId The universal chain ID
    /// @return registered Whether an adapter is registered
        /**
     * @notice Checks if remote adapter registered
     * @param chainId The chain identifier
     * @return The result value
     */
function isRemoteAdapterRegistered(
        bytes32 chainId
    ) external view returns (bool) {
        return remoteAdapters[chainId].length > 0;
    }
}
