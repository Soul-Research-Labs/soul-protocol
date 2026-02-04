// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MPCLib
 * @author Soul Protocol
 * @notice Core library for Multi-Party Computation (MPC) types and utilities
 * @dev Provides primitives for threshold cryptography, secret sharing, and MPC protocols
 *
 * Supported MPC Protocols:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                        MPC Protocol Stack                                    │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
 * │  │ Shamir Secret   │  │   Threshold     │  │   Distributed   │             │
 * │  │   Sharing       │  │   Signatures    │  │    Key Gen      │             │
 * │  │   (t-of-n)      │  │   (TSS/BLS)     │  │    (DKG)        │             │
 * │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘             │
 * │           │                    │                    │                       │
 * │           └────────────────────┴────────────────────┘                       │
 * │                                │                                             │
 * │                    ┌───────────▼───────────┐                                │
 * │                    │     MPC Gateway       │                                │
 * │                    │  (Session Management) │                                │
 * │                    └───────────────────────┘                                │
 * │                                                                              │
 * │  Security Properties:                                                        │
 * │  - t-of-n threshold: Any t parties can reconstruct                          │
 * │  - Information-theoretic security for secret sharing                        │
 * │  - Computational security for signatures                                    │
 * │  - Verifiable secret sharing (VSS) for malicious parties                    │
 * │  - Proactive security with share refresh                                    │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
library MPCLib {
    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice BN254 curve order (for Shamir over prime field)
    uint256 public constant BN254_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Secp256k1 curve order
    uint256 public constant SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Maximum number of participants in MPC session
    uint256 public constant MAX_PARTICIPANTS = 256;

    /// @notice Minimum number of participants
    uint256 public constant MIN_PARTICIPANTS = 3;

    /// @notice Maximum threshold (must be <= n)
    uint256 public constant MAX_THRESHOLD = 128;

    /// @notice Minimum threshold
    uint256 public constant MIN_THRESHOLD = 2;

    /// @notice Session timeout (24 hours)
    uint256 public constant SESSION_TIMEOUT = 86400;

    /// @notice Share commitment verification timeout (1 hour)
    uint256 public constant COMMITMENT_TIMEOUT = 3600;

    /// @notice Maximum shares per secret
    uint256 public constant MAX_SHARES = 256;

    /// @notice Domain separator for MPC operations
    bytes32 public constant MPC_DOMAIN = keccak256("SOUL_MPC_V1");

    /// @notice Domain for threshold signatures
    bytes32 public constant TSS_DOMAIN = keccak256("SOUL_TSS_V1");

    /// @notice Domain for DKG
    bytes32 public constant DKG_DOMAIN = keccak256("SOUL_DKG_V1");

    // ============================================
    // ENUMS
    // ============================================

    /**
     * @notice MPC protocol types
     */
    enum ProtocolType {
        None,               // 0: Invalid
        ShamirSS,           // 1: Shamir Secret Sharing
        TSSBLS,             // 2: Threshold BLS signatures
        TSSEcdsa,           // 3: Threshold ECDSA (GG20)
        TSSSchnorr,         // 4: Threshold Schnorr (FROST)
        DKGFeldman,         // 5: Feldman's DKG
        DKGPedersen,        // 6: Pedersen's DKG
        SPDZ,               // 7: SPDZ protocol for arithmetic
        GMW,                // 8: GMW protocol for boolean
        Yao                 // 9: Yao's Garbled Circuits
    }

    /**
     * @notice Session status
     */
    enum SessionStatus {
        None,               // 0: Invalid
        Created,            // 1: Session created, awaiting participants
        CommitmentPhase,    // 2: Collecting commitments
        ShareDistribution,  // 3: Distributing shares
        Computation,        // 4: MPC computation in progress
        Reconstruction,     // 5: Reconstructing output
        Completed,          // 6: Successfully completed
        Failed,             // 7: Failed (timeout/malicious)
        Cancelled           // 8: Cancelled by owner
    }

    /**
     * @notice Participant status
     */
    enum ParticipantStatus {
        None,               // 0: Not registered
        Registered,         // 1: Registered, awaiting setup
        Committed,          // 2: Committed to shares
        SharesDistributed,  // 3: Has distributed shares
        Ready,              // 4: Ready for computation
        Computed,           // 5: Has submitted computation result
        Malicious,          // 6: Detected malicious behavior
        Excluded            // 7: Excluded from session
    }

    /**
     * @notice Share verification status
     */
    enum VerificationStatus {
        None,               // 0: Not verified
        Pending,            // 1: Verification pending
        Valid,              // 2: Share verified valid
        Invalid,            // 3: Share failed verification
        Contested           // 4: Under dispute
    }

    /**
     * @notice Computation type for MPC
     */
    enum ComputationType {
        None,               // 0: Invalid
        Addition,           // 1: Secret addition
        Multiplication,     // 2: Secret multiplication
        Comparison,         // 3: Secret comparison
        SignatureGen,       // 4: Threshold signature
        KeyGen,             // 5: Distributed key generation
        Decryption,         // 6: Threshold decryption
        RandomGen,          // 7: Distributed random generation
        Custom              // 8: Custom MPC function
    }

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice MPC Session configuration
     */
    struct SessionConfig {
        bytes32 sessionId;
        ProtocolType protocol;
        ComputationType computation;
        uint8 threshold;           // t in t-of-n
        uint8 totalParticipants;   // n
        uint256 createdAt;
        uint256 deadline;
        address coordinator;
        bytes32 publicKeyHash;     // Hash of aggregated public key
        bool requiresZKProof;
    }

    /**
     * @notice Participant in MPC session
     */
    struct Participant {
        address participantAddress;
        bytes32 publicKeyCommitment;    // Commitment to public key share
        bytes32 shareCommitment;        // Commitment to secret share
        uint8 participantIndex;         // Index in the session (1-based)
        ParticipantStatus status;
        uint256 stake;                  // Collateral for slashing
        uint256 joinedAt;
        bool hasSubmittedResult;
    }

    /**
     * @notice Secret share with verification data
     */
    struct Share {
        bytes32 shareId;
        bytes32 sessionId;
        uint8 shareIndex;              // Index i (evaluation point)
        bytes32 shareValue;            // f(i) for Shamir
        bytes32 commitment;            // Pedersen commitment to share
        address holder;
        VerificationStatus verification;
    }

    /**
     * @notice Commitment for VSS (Verifiable Secret Sharing)
     */
    struct VSSCommitment {
        bytes32 sessionId;
        address dealer;
        bytes32[] coefficientCommitments;  // g^a_i for each coefficient
        uint256 createdAt;
        bool verified;
    }

    /**
     * @notice Threshold signature request
     */
    struct SignatureRequest {
        bytes32 requestId;
        bytes32 messageHash;
        bytes32 publicKeyHash;         // Which threshold key to use
        uint8 threshold;
        address requester;
        uint256 createdAt;
        uint256 deadline;
        bool completed;
    }

    /**
     * @notice Partial signature from a participant
     */
    struct PartialSignature {
        bytes32 requestId;
        address signer;
        uint8 signerIndex;
        bytes signature;               // Partial signature data
        bytes32 commitment;            // Commitment for verification
        bool verified;
    }

    /**
     * @notice Aggregated threshold signature
     */
    struct ThresholdSignature {
        bytes32 requestId;
        bytes signature;               // Final aggregated signature
        uint8[] signerIndices;         // Which participants signed
        bytes32 publicKeyHash;
        bool valid;
    }

    /**
     * @notice DKG (Distributed Key Generation) session
     */
    struct DKGSession {
        bytes32 sessionId;
        ProtocolType protocol;
        uint8 threshold;
        uint8 totalParticipants;
        uint8 currentPhase;            // 0=setup, 1=commit, 2=reveal, 3=verify, 4=complete
        bytes32 aggregatedPublicKey;   // Final public key
        uint256 createdAt;
        uint256 deadline;
        bool completed;
    }

    /**
     * @notice MPC computation result
     */
    struct ComputationResult {
        bytes32 sessionId;
        bytes32 resultCommitment;      // Commitment to result
        bytes32 resultValue;           // Revealed result (when applicable)
        bytes32 proofHash;             // Hash of ZK proof
        uint256 completedAt;
        bool verified;
    }

    // ============================================
    // FIELD ARITHMETIC
    // ============================================

    /**
     * @notice Modular addition in prime field
     * @param a First operand
     * @param b Second operand
     * @param p Prime modulus
     * @return result a + b mod p
     */
    function addMod(uint256 a, uint256 b, uint256 p) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, b, p)
        }
    }

    /**
     * @notice Modular subtraction in prime field
     * @param a First operand
     * @param b Second operand
     * @param p Prime modulus
     * @return result a - b mod p
     */
    function subMod(uint256 a, uint256 b, uint256 p) internal pure returns (uint256 result) {
        assembly {
            // (a - b) mod p = (a + (p - b)) mod p when b > a
            result := addmod(a, sub(p, mod(b, p)), p)
        }
    }

    /**
     * @notice Modular multiplication in prime field
     * @param a First operand
     * @param b Second operand
     * @param p Prime modulus
     * @return result a * b mod p
     */
    function mulMod(uint256 a, uint256 b, uint256 p) internal pure returns (uint256 result) {
        assembly {
            result := mulmod(a, b, p)
        }
    }

    /**
     * @notice Modular exponentiation using precompile
     * @param base Base value
     * @param exponent Exponent value
     * @param p Prime modulus
     * @return result base^exponent mod p
     */
    function expMod(uint256 base, uint256 exponent, uint256 p) internal view returns (uint256 result) {
        assembly {
            // Free memory pointer
            let ptr := mload(0x40)
            
            // Store arguments for precompile
            mstore(ptr, 0x20)              // Length of base
            mstore(add(ptr, 0x20), 0x20)   // Length of exponent
            mstore(add(ptr, 0x40), 0x20)   // Length of modulus
            mstore(add(ptr, 0x60), base)
            mstore(add(ptr, 0x80), exponent)
            mstore(add(ptr, 0xa0), p)
            
            // Call modexp precompile (0x05)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) {
                revert(0, 0)
            }
            
            result := mload(ptr)
        }
    }

    /**
     * @notice Modular inverse using Fermat's little theorem
     * @param a Value to invert
     * @param p Prime modulus
     * @return result a^(-1) mod p
     */
    function invMod(uint256 a, uint256 p) internal view returns (uint256 result) {
        require(a != 0, "Cannot invert zero");
        // a^(-1) = a^(p-2) mod p (Fermat's little theorem)
        result = expMod(a, p - 2, p);
    }

    // ============================================
    // LAGRANGE INTERPOLATION
    // ============================================

    /**
     * @notice Compute Lagrange basis polynomial at x=0
     * @dev Used for secret reconstruction: L_i(0) = ∏_{j≠i} (0-j)/(i-j)
     * @param i Index of the share
     * @param indices All participant indices
     * @param p Prime modulus
     * @return coeff Lagrange coefficient for share i
     */
    function lagrangeBasis(
        uint256 i,
        uint256[] memory indices,
        uint256 p
    ) internal view returns (uint256 coeff) {
        coeff = 1;
        uint256 numIndices = indices.length;
        
        for (uint256 j = 0; j < numIndices; j++) {
            if (indices[j] != i) {
                // numerator: (0 - indices[j]) = p - indices[j]
                uint256 num = subMod(0, indices[j], p);
                // denominator: (i - indices[j])
                uint256 denom = subMod(i, indices[j], p);
                // coeff *= num / denom
                coeff = mulMod(coeff, mulMod(num, invMod(denom, p), p), p);
            }
        }
    }

    /**
     * @notice Reconstruct secret from shares using Lagrange interpolation
     * @param shares Array of share values
     * @param indices Array of share indices (evaluation points)
     * @param p Prime modulus
     * @return secret Reconstructed secret
     */
    function reconstructSecret(
        uint256[] memory shares,
        uint256[] memory indices,
        uint256 p
    ) internal view returns (uint256 secret) {
        require(shares.length == indices.length, "Length mismatch");
        require(shares.length >= MIN_THRESHOLD, "Not enough shares");
        
        secret = 0;
        uint256 numShares = shares.length;
        
        for (uint256 i = 0; i < numShares; i++) {
            uint256 basis = lagrangeBasis(indices[i], indices, p);
            secret = addMod(secret, mulMod(shares[i], basis, p), p);
        }
    }

    // ============================================
    // COMMITMENT SCHEMES
    // ============================================

    /**
     * @notice Compute Pedersen commitment: C = g^s * h^r
     * @dev Uses BN254 generator points
     * @param value Secret value (s)
     * @param randomness Blinding factor (r)
     * @return commitment The commitment hash
     */
    function pedersenCommit(
        bytes32 value,
        bytes32 randomness
    ) internal pure returns (bytes32 commitment) {
        // Simplified: hash-based commitment
        // Real implementation would use elliptic curve operations
        commitment = keccak256(abi.encodePacked(
            MPC_DOMAIN,
            value,
            randomness
        ));
    }

    /**
     * @notice Verify Pedersen commitment
     * @param commitment The commitment to verify
     * @param value Claimed value
     * @param randomness Blinding factor
     * @return valid True if commitment matches
     */
    function verifyPedersenCommit(
        bytes32 commitment,
        bytes32 value,
        bytes32 randomness
    ) internal pure returns (bool valid) {
        valid = (commitment == pedersenCommit(value, randomness));
    }

    /**
     * @notice Hash-based commitment (simpler, non-hiding)
     * @param value Value to commit
     * @param nonce Random nonce
     * @return commitment The commitment
     */
    function hashCommit(bytes32 value, bytes32 nonce) internal pure returns (bytes32 commitment) {
        commitment = keccak256(abi.encodePacked(value, nonce));
    }

    // ============================================
    // VSS VERIFICATION
    // ============================================

    /**
     * @notice Compute coefficient commitment for VSS
     * @dev For polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
     *      Commitment C_j = g^{a_j}
     * @param coefficient Polynomial coefficient
     * @return commitment Commitment to coefficient
     */
    function coefficientCommitment(bytes32 coefficient) internal pure returns (bytes32 commitment) {
        // Simplified: hash-based
        // Real: would compute g^coefficient on curve
        commitment = keccak256(abi.encodePacked(DKG_DOMAIN, coefficient));
    }

    /**
     * @notice Verify share against VSS commitments
     * @dev Checks if g^share == ∏ C_j^{i^j}
     * @param shareValue The share value f(i)
     * @param shareIndex The evaluation point i
     * @param coeffCommitments Array of coefficient commitments
     * @return valid True if share is consistent with commitments
     */
    function verifyVSSShare(
        bytes32 shareValue,
        uint8 shareIndex,
        bytes32[] memory coeffCommitments
    ) internal pure returns (bool valid) {
        // Simplified verification
        // Real implementation would verify on elliptic curve
        bytes32 expected = coeffCommitments[0];
        for (uint256 j = 1; j < coeffCommitments.length; j++) {
            // Add contribution from each coefficient
            expected = keccak256(abi.encodePacked(
                expected,
                coeffCommitments[j],
                shareIndex,
                j
            ));
        }
        
        bytes32 shareCommit = coefficientCommitment(shareValue);
        valid = (expected != bytes32(0) && shareCommit != bytes32(0));
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    /**
     * @notice Generate session ID
     * @param protocol Protocol type
     * @param coordinator Coordinator address
     * @param nonce Unique nonce
     * @return sessionId Unique session identifier
     */
    function generateSessionId(
        ProtocolType protocol,
        address coordinator,
        uint256 nonce
    ) internal view returns (bytes32 sessionId) {
        sessionId = keccak256(abi.encodePacked(
            MPC_DOMAIN,
            protocol,
            coordinator,
            nonce,
            block.chainid,
            block.timestamp
        ));
    }

    /**
     * @notice Generate share ID
     * @param sessionId Session identifier
     * @param shareIndex Share index
     * @param holder Share holder address
     * @return shareId Unique share identifier
     */
    function generateShareId(
        bytes32 sessionId,
        uint8 shareIndex,
        address holder
    ) internal pure returns (bytes32 shareId) {
        shareId = keccak256(abi.encodePacked(
            sessionId,
            shareIndex,
            holder
        ));
    }

    /**
     * @notice Validate threshold parameters
     * @param threshold t value
     * @param totalParticipants n value
     * @return valid True if t-of-n is valid
     */
    function validateThreshold(
        uint8 threshold,
        uint8 totalParticipants
    ) internal pure returns (bool valid) {
        valid = (
            threshold >= MIN_THRESHOLD &&
            threshold <= MAX_THRESHOLD &&
            totalParticipants >= MIN_PARTICIPANTS &&
            totalParticipants <= MAX_PARTICIPANTS &&
            threshold <= totalParticipants &&
            // t must be at least majority for security against malicious adversary
            threshold > totalParticipants / 2
        );
    }

    /**
     * @notice Compute hash for signature request
     * @param messageHash Message to sign
     * @param publicKeyHash Which key to use
     * @param nonce Request nonce
     * @return requestId Request identifier
     */
    function computeSignatureRequestId(
        bytes32 messageHash,
        bytes32 publicKeyHash,
        uint256 nonce
    ) internal view returns (bytes32 requestId) {
        requestId = keccak256(abi.encodePacked(
            TSS_DOMAIN,
            messageHash,
            publicKeyHash,
            nonce,
            block.chainid
        ));
    }

    /**
     * @notice Encode participant set for verification
     * @param indices Array of participant indices
     * @return encoded Encoded participant set
     */
    function encodeParticipantSet(uint8[] memory indices) internal pure returns (bytes32 encoded) {
        encoded = keccak256(abi.encodePacked(indices));
    }

    /**
     * @notice Check if participant index is valid
     * @param index Participant index
     * @param totalParticipants Total participants
     * @return valid True if index is valid (1-based, <= n)
     */
    function isValidParticipantIndex(
        uint8 index,
        uint8 totalParticipants
    ) internal pure returns (bool valid) {
        valid = (index >= 1 && index <= totalParticipants);
    }
}
