// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";

/**
 * @title FalconZKVerifier
 * @author ZASEON
 * @notice On-chain bridge connecting Noir ZK proofs of Falcon-512 signature
 *         verification to the HybridPQCVerifier's approved results mapping.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                          ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * When the HybridPQCVerifier's verification backend is set to ZK_PROOF for
 * FN_DSA_512, it checks `approvedPQCResults[zkResultHash]`. This contract
 * bridges the gap:
 *
 *   1. Off-chain: Prover runs Falcon-512 verification and generates a Noir
 *      proof via the `falcon_signature` circuit.
 *   2. On-chain: This contract verifies the SNARK proof against public inputs
 *      and writes the result hash into HybridPQCVerifier's approvedPQCResults.
 *
 * PUBLIC INPUTS (from the Noir circuit):
 *   1. message_hash           — Hash of the signed message
 *   2. pk_commitment          — Poseidon commitment to Falcon-512 public key
 *   3. sig_commitment         — Poseidon commitment to Falcon-512 signature
 *   4. signer_address         — Ethereum address of the signer
 *   5. chain_id               — Chain ID for replay protection
 *   6. verification_commitment — Binding commitment to the verification result
 *
 * PROOF FORMAT: UltraHonk (Noir backend)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract FalconZKVerifier is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant VERIFIER_UPDATER_ROLE =
        keccak256("VERIFIER_UPDATER_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain separator matching HybridPQCVerifier.HYBRID_SIG_DOMAIN
    bytes32 public constant HYBRID_SIG_DOMAIN =
        keccak256("ZASEON_HYBRID_SIGNATURE_V1");

    /// @notice Domain separator for Falcon ZK verification results
    bytes32 public constant FALCON_ZK_DOMAIN =
        keccak256("ZASEON_FALCON_ZK_VERIFY_V1");

    /// @notice The PQC algorithm identifier for Falcon-512
    IPQCVerifier.PQCAlgorithm public constant FALCON_ALGORITHM =
        IPQCVerifier.PQCAlgorithm.FN_DSA_512;

    /// @notice Number of public inputs expected from the Noir circuit
    uint256 public constant NUM_PUBLIC_INPUTS = 6;

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Public inputs from the Falcon-512 Noir circuit
    struct FalconProofPublicInputs {
        bytes32 messageHash;
        bytes32 pkCommitment;
        bytes32 sigCommitment;
        address signerAddress;
        uint256 chainId;
        bytes32 verificationCommitment;
    }

    /// @notice Verification submission record
    struct VerificationRecord {
        bytes32 messageHash;
        address signer;
        bytes32 pkCommitment;
        bytes32 sigCommitment;
        uint256 timestamp;
        bool valid;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Address of the HybridPQCVerifier contract
    address public hybridPQCVerifier;

    /// @notice Address of the Noir UltraHonk verifier contract
    /// @dev This should be the generated verifier from `nargo codegen-verifier`
    address public noirVerifier;

    /// @notice Total proofs verified
    uint256 public totalProofsVerified;

    /// @notice Total proofs that passed verification
    uint256 public successfulProofs;

    /// @notice Total proofs that failed verification
    uint256 public failedProofs;

    /// @notice Verification records by hash
    mapping(bytes32 => VerificationRecord) public verificationRecords;

    /// @notice Nonce per signer to prevent replay
    mapping(address => uint256) public signerNonces;

    /// @notice Whether a specific proof hash has been used (prevents replay)
    mapping(bytes32 => bool) public usedProofHashes;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event FalconProofVerified(
        bytes32 indexed messageHash,
        address indexed signer,
        bytes32 pkCommitment,
        bytes32 sigCommitment,
        bytes32 resultHash,
        bool valid
    );

    event FalconProofRejected(
        bytes32 indexed messageHash,
        address indexed signer,
        string reason
    );

    event HybridPQCVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    event NoirVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidProof();
    error InvalidPublicInputs();
    error ChainIdMismatch(uint256 expected, uint256 provided);
    error ProofAlreadyUsed(bytes32 proofHash);
    error HybridVerifierNotSet();
    error NoirVerifierNotSet();
    error VerifierCallFailed();
    error SignerAddressMismatch();

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the FalconZKVerifier
     * @param admin The admin address (receives DEFAULT_ADMIN_ROLE)
     * @param _hybridPQCVerifier Address of the HybridPQCVerifier contract
     * @param _noirVerifier Address of the Noir UltraHonk verifier (can be address(0) initially)
     */
    constructor(
        address admin,
        address _hybridPQCVerifier,
        address _noirVerifier
    ) {
        if (admin == address(0)) revert ZeroAddress();
        if (_hybridPQCVerifier == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(VERIFIER_UPDATER_ROLE, admin);

        hybridPQCVerifier = _hybridPQCVerifier;
        noirVerifier = _noirVerifier;
    }

    /*//////////////////////////////////////////////////////////////
                      PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a Falcon-512 ZK proof and register the result
     * @dev The proof demonstrates that off-chain Falcon-512 signature
     *      verification was performed correctly. On success, the result
     *      is registered in HybridPQCVerifier's approvedPQCResults.
     *
     * @param proof The serialized Noir UltraHonk proof
     * @param publicInputs The FalconProofPublicInputs struct
     * @param pqcSigHash The keccak256 hash of the original PQC signature
     *                    (used to compute the result hash for HybridPQCVerifier)
     * @return valid Whether the proof verified successfully
     * @return resultHash The result hash written to HybridPQCVerifier
     */
    function verifyFalconProof(
        bytes calldata proof,
        FalconProofPublicInputs calldata publicInputs,
        bytes32 pqcSigHash
    )
        external
        nonReentrant
        whenNotPaused
        returns (bool valid, bytes32 resultHash)
    {
        // ─── Input validation ────────────────────────────────────
        if (publicInputs.signerAddress == address(0))
            revert InvalidPublicInputs();

        // Chain ID must match current chain
        if (publicInputs.chainId != block.chainid)
            revert ChainIdMismatch(block.chainid, publicInputs.chainId);

        // Compute proof hash for replay protection
        bytes32 proofHash = keccak256(
            abi.encodePacked(
                FALCON_ZK_DOMAIN,
                proof,
                publicInputs.messageHash,
                publicInputs.pkCommitment,
                publicInputs.sigCommitment,
                publicInputs.signerAddress,
                publicInputs.chainId,
                publicInputs.verificationCommitment
            )
        );

        if (usedProofHashes[proofHash]) revert ProofAlreadyUsed(proofHash);
        usedProofHashes[proofHash] = true;

        // ─── Verify the SNARK proof ──────────────────────────────
        totalProofsVerified++;

        bool proofValid = _verifyNoirProof(proof, publicInputs);

        if (!proofValid) {
            failedProofs++;

            emit FalconProofRejected(
                publicInputs.messageHash,
                publicInputs.signerAddress,
                "Noir proof verification failed"
            );

            // Store failed record
            verificationRecords[proofHash] = VerificationRecord({
                messageHash: publicInputs.messageHash,
                signer: publicInputs.signerAddress,
                pkCommitment: publicInputs.pkCommitment,
                sigCommitment: publicInputs.sigCommitment,
                timestamp: block.timestamp,
                valid: false
            });

            return (false, bytes32(0));
        }

        successfulProofs++;

        // ─── Compute HybridPQCVerifier-compatible result hash ────
        // This matches _verifyPQCViaZKProof() in HybridPQCVerifier
        resultHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                "ZK_VERIFIED",
                publicInputs.messageHash,
                pqcSigHash,
                publicInputs.signerAddress,
                FALCON_ALGORITHM
            )
        );

        // ─── Register result in HybridPQCVerifier ────────────────
        _submitToHybridVerifier(resultHash);

        // ─── Store verification record ───────────────────────────
        verificationRecords[proofHash] = VerificationRecord({
            messageHash: publicInputs.messageHash,
            signer: publicInputs.signerAddress,
            pkCommitment: publicInputs.pkCommitment,
            sigCommitment: publicInputs.sigCommitment,
            timestamp: block.timestamp,
            valid: true
        });

        emit FalconProofVerified(
            publicInputs.messageHash,
            publicInputs.signerAddress,
            publicInputs.pkCommitment,
            publicInputs.sigCommitment,
            resultHash,
            true
        );

        return (true, resultHash);
    }

    /**
     * @notice Batch verify multiple Falcon-512 ZK proofs
     * @param proofs Array of serialized proofs
     * @param publicInputsArray Array of public inputs
     * @param pqcSigHashes Array of PQC signature hashes
     * @return results Array of verification results
     */
    function batchVerifyFalconProofs(
        bytes[] calldata proofs,
        FalconProofPublicInputs[] calldata publicInputsArray,
        bytes32[] calldata pqcSigHashes
    ) external nonReentrant whenNotPaused returns (bool[] memory results) {
        uint256 len = proofs.length;
        require(
            len == publicInputsArray.length && len == pqcSigHashes.length,
            "Array length mismatch"
        );
        require(len > 0 && len <= 16, "Invalid batch size");

        results = new bool[](len);

        for (uint256 i = 0; i < len; ) {
            // Inline the core verification logic (skip reentrancy since outer has it)
            FalconProofPublicInputs calldata inputs = publicInputsArray[i];

            if (
                inputs.signerAddress == address(0) ||
                inputs.chainId != block.chainid
            ) {
                results[i] = false;
                unchecked {
                    ++i;
                }
                continue;
            }

            bytes32 proofHash = keccak256(
                abi.encodePacked(
                    FALCON_ZK_DOMAIN,
                    proofs[i],
                    inputs.messageHash,
                    inputs.pkCommitment,
                    inputs.sigCommitment,
                    inputs.signerAddress,
                    inputs.chainId,
                    inputs.verificationCommitment
                )
            );

            if (usedProofHashes[proofHash]) {
                results[i] = false;
                unchecked {
                    ++i;
                }
                continue;
            }

            usedProofHashes[proofHash] = true;
            totalProofsVerified++;

            bool proofValid = _verifyNoirProof(proofs[i], inputs);

            if (proofValid) {
                successfulProofs++;
                results[i] = true;

                bytes32 resultHash = keccak256(
                    abi.encodePacked(
                        HYBRID_SIG_DOMAIN,
                        "ZK_VERIFIED",
                        inputs.messageHash,
                        pqcSigHashes[i],
                        inputs.signerAddress,
                        FALCON_ALGORITHM
                    )
                );

                _submitToHybridVerifier(resultHash);

                emit FalconProofVerified(
                    inputs.messageHash,
                    inputs.signerAddress,
                    inputs.pkCommitment,
                    inputs.sigCommitment,
                    resultHash,
                    true
                );
            } else {
                failedProofs++;
                results[i] = false;

                emit FalconProofRejected(
                    inputs.messageHash,
                    inputs.signerAddress,
                    "Batch: Noir proof verification failed"
                );
            }

            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute the ZK result hash for a given set of parameters
     * @dev Used by off-chain provers to pre-compute the expected result hash
     */
    function computeResultHash(
        bytes32 messageHash,
        bytes32 pqcSigHash,
        address signer
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    keccak256("ZASEON_HYBRID_SIGNATURE_V1"),
                    "ZK_VERIFIED",
                    messageHash,
                    pqcSigHash,
                    signer,
                    IPQCVerifier.PQCAlgorithm.FN_DSA_512
                )
            );
    }

    /**
     * @notice Check if a proof hash has already been used
     */
    function isProofUsed(bytes32 proofHash) external view returns (bool) {
        return usedProofHashes[proofHash];
    }

    /**
     * @notice Get verification statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 total,
            uint256 successful,
            uint256 failed,
            uint256 successRate
        )
    {
        total = totalProofsVerified;
        successful = successfulProofs;
        failed = failedProofs;
        successRate = total > 0 ? (successful * 10000) / total : 0; // basis points
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the HybridPQCVerifier address
     */
    function setHybridPQCVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();
        address old = hybridPQCVerifier;
        hybridPQCVerifier = newVerifier;
        emit HybridPQCVerifierUpdated(old, newVerifier);
    }

    /**
     * @notice Update the Noir UltraHonk verifier contract
     * @dev Call this when a new circuit version is deployed
     */
    function setNoirVerifier(
        address newVerifier
    ) external onlyRole(VERIFIER_UPDATER_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();
        address old = noirVerifier;
        noirVerifier = newVerifier;
        emit NoirVerifierUpdated(old, newVerifier);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify the Noir UltraHonk proof against public inputs
     *      The verifier contract is the generated Solidity code from
     *      `nargo codegen-verifier` for the falcon_signature circuit.
     */
    function _verifyNoirProof(
        bytes calldata proof,
        FalconProofPublicInputs calldata publicInputs
    ) internal view returns (bool) {
        if (noirVerifier == address(0)) revert NoirVerifierNotSet();

        // Encode public inputs as bytes32 array matching Noir circuit order
        bytes32[] memory pubInputs = new bytes32[](NUM_PUBLIC_INPUTS);
        pubInputs[0] = publicInputs.messageHash;
        pubInputs[1] = publicInputs.pkCommitment;
        pubInputs[2] = publicInputs.sigCommitment;
        pubInputs[3] = bytes32(uint256(uint160(publicInputs.signerAddress)));
        pubInputs[4] = bytes32(publicInputs.chainId);
        pubInputs[5] = publicInputs.verificationCommitment;

        // Call the generated verifier: verify(bytes, bytes32[])
        (bool success, bytes memory result) = noirVerifier.staticcall(
            abi.encodeWithSignature("verify(bytes,bytes32[])", proof, pubInputs)
        );

        if (!success || result.length < 32) return false;

        return abi.decode(result, (bool));
    }

    /**
     * @dev Submit the verified result hash to HybridPQCVerifier
     *      Calls submitPQCResult() on the HybridPQCVerifier — this contract
     *      must be set as the PQC oracle for FN_DSA_512's ZK_PROOF backend.
     */
    function _submitToHybridVerifier(bytes32 resultHash) internal {
        if (hybridPQCVerifier == address(0)) revert HybridVerifierNotSet();

        (bool success, ) = hybridPQCVerifier.call(
            abi.encodeWithSignature("submitPQCResult(bytes32)", resultHash)
        );

        if (!success) revert VerifierCallFailed();
    }
}
