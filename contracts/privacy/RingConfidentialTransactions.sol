// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title RingConfidentialTransactions
 * @author Soul Protocol
 * @notice Implements Ring Confidential Transactions (RingCT) for amount hiding
 * @dev Based on Monero's RingCT with Pedersen commitments and CLSAG signatures
 *
 * RINGCT PROTOCOL:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Ring Confidential Transactions                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  AMOUNT HIDING (Pedersen Commitments):                                  │
 * │  C = amount * H + blinding_factor * G                                   │
 * │  where H = hash_to_curve(G) - "nothing up my sleeve" point              │
 * │                                                                          │
 * │  RING SIGNATURES (CLSAG):                                               │
 * │  - Hides which input is being spent among n decoys                      │
 * │  - Linkable: Key Image I = x * Hp(P) reveals double-spends              │
 * │  - Aggregatable: Multiple inputs in one signature                       │
 * │                                                                          │
 * │  BALANCE PROOF:                                                         │
 * │  Sum(input_commitments) = Sum(output_commitments) + fee * H             │
 * │  Proves: inputs = outputs + fee (without revealing amounts)             │
 * │                                                                          │
 * │  RANGE PROOFS (Bulletproofs+):                                          │
 * │  Proves: 0 ≤ amount < 2^64 (no overflow/negative amounts)               │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract RingConfidentialTransactions is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Generator point G (secp256k1)
    uint256 public constant G_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant G_Y =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /// @notice Generator point H = hash_to_curve(G) for Pedersen commitments
    /// @dev Computed as H = hash_to_point("Pedersen_H")
    uint256 public constant H_X =
        0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0;
    uint256 public constant H_Y =
        0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904;

    /// @notice Curve order (secp256k1)
    uint256 public constant CURVE_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Maximum ring size
    uint256 public constant MAX_RING_SIZE = 16;

    /// @notice Minimum ring size
    uint256 public constant MIN_RING_SIZE = 4;

    /// @notice Maximum outputs per transaction
    uint256 public constant MAX_OUTPUTS = 16;

    /// @notice Domain separator for RingCT
    bytes32 public constant RINGCT_DOMAIN = keccak256("Soul_RINGCT_V1");

    /// @notice Bulletproof range (64 bits)
    uint256 public constant BULLETPROOF_RANGE = 64;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum RingCTType {
        SIMPLE, // One ring signature per input
        FULL, // Borromean ring signatures (deprecated)
        BULLETPROOF, // Bulletproofs for range proofs
        BULLETPROOF_PLUS, // Bulletproofs+ (more efficient)
        CLSAG // Compact Linkable Spontaneous Anonymous Group
    }

    enum TransactionStatus {
        PENDING,
        VERIFIED,
        REJECTED,
        EXECUTED
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Pedersen commitment: C = amount*H + blinding*G
     */
    struct PedersenCommitment {
        uint256 commitmentX; // X coordinate of commitment point
        uint256 commitmentY; // Y coordinate of commitment point
        bytes32 blindingHash; // Hash of blinding factor (for verification)
    }

    /**
     * @notice Key Image for linkability (I = x * Hp(P))
     */
    struct KeyImage {
        uint256 imageX;
        uint256 imageY;
        bytes32 keyImageHash; // H(I) for efficient lookup
    }

    /**
     * @notice CLSAG Ring Signature
     */
    struct CLSAGSignature {
        uint256 c; // Initial challenge
        uint256[] s; // Response scalars (one per ring member)
        KeyImage keyImage; // Key image for linkability
        bytes32 messageHash; // Signed message
    }

    /**
     * @notice Ring member (decoy or real input)
     */
    struct RingMember {
        uint256 pubKeyX;
        uint256 pubKeyY;
        PedersenCommitment commitment;
        uint256 outputIndex;
    }

    /**
     * @notice Bulletproof range proof
     */
    struct BulletproofProof {
        uint256 A_x; // Commitment to bits
        uint256 A_y;
        uint256 S_x; // Commitment to blinding factors
        uint256 S_y;
        uint256 T1_x; // Polynomial commitment
        uint256 T1_y;
        uint256 T2_x;
        uint256 T2_y;
        uint256 taux; // Evaluation proof
        uint256 mu;
        uint256[] L; // Left vectors
        uint256[] R; // Right vectors
        uint256 a; // Final scalars
        uint256 b;
    }

    /**
     * @notice RingCT Transaction Input
     */
    struct RCTInput {
        RingMember[] ring; // Ring of potential inputs
        CLSAGSignature signature; // Ring signature
        uint256 realIndex; // Index of real input (only known to signer)
    }

    /**
     * @notice RingCT Transaction Output
     */
    struct RCTOutput {
        address recipient; // One-time address
        PedersenCommitment commitment;
        bytes32 encryptedAmount; // Amount encrypted to recipient's key
        BulletproofProof rangeProof;
    }

    /**
     * @notice Full RingCT Transaction
     */
    struct RCTTransaction {
        bytes32 txId;
        RCTInput[] inputs;
        RCTOutput[] outputs;
        uint256 fee;
        PedersenCommitment feeCommitment;
        RingCTType txType;
        TransactionStatus status;
        uint256 timestamp;
        uint256 chainId;
    }

    /**
     * @notice Cross-chain RingCT transfer
     */
    struct CrossChainRCT {
        bytes32 sourceTxId;
        bytes32 destTxId;
        uint256 sourceChainId;
        uint256 destChainId;
        KeyImage linkedKeyImage;
        bytes32 nullifier;
        uint256 timestamp;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice All RingCT transactions
    mapping(bytes32 => RCTTransaction) public transactions;

    /// @notice Spent key images (for double-spend prevention)
    mapping(bytes32 => bool) public spentKeyImages;

    /// @notice Cross-chain RCT transfers
    mapping(bytes32 => CrossChainRCT) public crossChainTransfers;

    /// @notice Commitment registry (for building rings)
    mapping(bytes32 => PedersenCommitment) public commitmentRegistry;

    /// @notice Output pool for decoy selection
    bytes32[] public outputPool;

    /// @notice Total transactions
    uint256 public totalTransactions;

    /// @notice Total cross-chain transfers
    uint256 public totalCrossChainTransfers;

    /// @notice Total volume (in commitment count, not amounts)
    uint256 public totalCommitments;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event RCTTransactionCreated(
        bytes32 indexed txId,
        uint256 inputCount,
        uint256 outputCount,
        RingCTType txType
    );

    event RCTTransactionVerified(
        bytes32 indexed txId,
        TransactionStatus status
    );

    event KeyImageSpent(bytes32 indexed keyImageHash, bytes32 indexed txId);

    event CommitmentRegistered(
        bytes32 indexed commitmentHash,
        uint256 indexed outputIndex
    );

    event CrossChainRCTInitiated(
        bytes32 indexed sourceTxId,
        bytes32 indexed destTxId,
        uint256 sourceChainId,
        uint256 destChainId
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidRingSize();
    error InvalidOutputCount();
    error KeyImageAlreadySpent();
    error InvalidSignature();
    error InvalidRangeProof();
    error InvalidCommitment();
    error BalanceNotConserved();
    error TransactionNotFound();
    error InvalidTransactionStatus();
    error ZeroValue();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    // =========================================================================
    // COMMITMENT FUNCTIONS
    // =========================================================================

    /**
     * @notice Create a Pedersen commitment: C = amount*H + blinding*G
     * @param amountHash Hash of the amount (actual amount kept private)
     * @param blindingHash Hash of the blinding factor
     * @return commitment The Pedersen commitment
     */
    function createCommitment(
        bytes32 amountHash,
        bytes32 blindingHash
    ) external returns (PedersenCommitment memory commitment) {
        // In practice, EC point multiplication is done off-chain
        // Here we create a simulated commitment
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(RINGCT_DOMAIN, amountHash, blindingHash)
        );

        // Derive "point" from hash (simulation)
        commitment = PedersenCommitment({
            commitmentX: uint256(commitmentHash),
            commitmentY: uint256(
                keccak256(abi.encodePacked(commitmentHash, "Y"))
            ),
            blindingHash: blindingHash
        });

        commitmentRegistry[commitmentHash] = commitment;
        outputPool.push(commitmentHash);
        totalCommitments++;

        emit CommitmentRegistered(commitmentHash, outputPool.length - 1);

        return commitment;
    }

    /**
     * @notice Verify commitment sum: sum(inputs) = sum(outputs) + fee
     * @dev Uses homomorphic property of Pedersen commitments
     */
    function verifyCommitmentBalance(
        PedersenCommitment[] calldata inputCommitments,
        PedersenCommitment[] calldata outputCommitments,
        PedersenCommitment calldata feeCommitment
    ) external pure returns (bool) {
        // Sum input commitments (homomorphic addition)
        uint256 inputSumX = 0;
        uint256 inputSumY = 0;
        for (uint256 i = 0; i < inputCommitments.length; i++) {
            inputSumX = addmod(
                inputSumX,
                inputCommitments[i].commitmentX,
                CURVE_ORDER
            );
            inputSumY = addmod(
                inputSumY,
                inputCommitments[i].commitmentY,
                CURVE_ORDER
            );
        }

        // Sum output commitments + fee
        uint256 outputSumX = feeCommitment.commitmentX;
        uint256 outputSumY = feeCommitment.commitmentY;
        for (uint256 i = 0; i < outputCommitments.length; i++) {
            outputSumX = addmod(
                outputSumX,
                outputCommitments[i].commitmentX,
                CURVE_ORDER
            );
            outputSumY = addmod(
                outputSumY,
                outputCommitments[i].commitmentY,
                CURVE_ORDER
            );
        }

        // Check equality (simplified - actual EC point comparison needed)
        return inputSumX == outputSumX && inputSumY == outputSumY;
    }

    // =========================================================================
    // KEY IMAGE FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute key image: I = x * Hp(P)
     * @dev Key image is used for linkability (detecting double-spends)
     */
    function computeKeyImage(
        bytes32 privKeyHash,
        uint256 pubKeyX,
        uint256 pubKeyY
    ) external pure returns (KeyImage memory keyImage) {
        // Hash public key to curve point Hp(P)
        bytes32 hpHash = keccak256(
            abi.encodePacked("HASH_TO_POINT", pubKeyX, pubKeyY)
        );

        // Key image I = privKey * Hp(P) (simulated)
        bytes32 imageHash = keccak256(abi.encodePacked(privKeyHash, hpHash));

        keyImage = KeyImage({
            imageX: uint256(imageHash),
            imageY: uint256(keccak256(abi.encodePacked(imageHash, "Y"))),
            keyImageHash: imageHash
        });

        return keyImage;
    }

    /**
     * @notice Check if key image has been spent
     */
    function isKeyImageSpent(
        bytes32 keyImageHash
    ) external view returns (bool) {
        return spentKeyImages[keyImageHash];
    }

    // =========================================================================
    // RING SIGNATURE FUNCTIONS
    // =========================================================================

    /**
     * @notice Create CLSAG ring signature
     * @param ring Array of ring members (decoys + real input)
     * @param messageHash Message being signed
     * @param signatureData Pre-computed signature data
     */
    function createCLSAGSignature(
        RingMember[] calldata ring,
        bytes32 messageHash,
        bytes calldata signatureData
    ) external returns (CLSAGSignature memory signature) {
        if (ring.length < MIN_RING_SIZE || ring.length > MAX_RING_SIZE) {
            revert InvalidRingSize();
        }

        // Decode signature data (computed off-chain)
        (uint256 c, uint256[] memory s, KeyImage memory keyImage) = abi.decode(
            signatureData,
            (uint256, uint256[], KeyImage)
        );

        signature = CLSAGSignature({
            c: c,
            s: s,
            keyImage: keyImage,
            messageHash: messageHash
        });

        return signature;
    }

    /**
     * @notice Verify CLSAG ring signature
     */
    function verifyCLSAGSignature(
        RingMember[] calldata ring,
        CLSAGSignature calldata signature
    ) external view returns (bool) {
        if (ring.length != signature.s.length) return false;
        if (spentKeyImages[signature.keyImage.keyImageHash]) return false;

        // CLSAG verification (simplified)
        // In practice, verify: c = H(m, L_n, R_n) where
        // L_i = s_i*G + c_i*P_i
        // R_i = s_i*Hp(P_i) + c_i*I

        bytes32 computedHash = keccak256(
            abi.encodePacked(
                RINGCT_DOMAIN,
                signature.messageHash,
                signature.c,
                signature.keyImage.keyImageHash
            )
        );

        // Verify ring structure
        for (uint256 i = 0; i < ring.length; i++) {
            computedHash = keccak256(
                abi.encodePacked(
                    computedHash,
                    ring[i].pubKeyX,
                    ring[i].pubKeyY,
                    signature.s[i]
                )
            );
        }

        // Final challenge should match initial
        return uint256(computedHash) % CURVE_ORDER == signature.c % CURVE_ORDER;
    }

    // =========================================================================
    // TRANSACTION FUNCTIONS
    // =========================================================================

    /**
     * @notice Create RingCT transaction
     */
    function createRCTTransaction(
        RCTInput[] calldata inputs,
        RCTOutput[] calldata outputs,
        uint256 fee,
        PedersenCommitment calldata feeCommitment,
        RingCTType txType
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 txId) {
        if (outputs.length == 0 || outputs.length > MAX_OUTPUTS) {
            revert InvalidOutputCount();
        }

        // Check key images not spent
        for (uint256 i = 0; i < inputs.length; i++) {
            if (spentKeyImages[inputs[i].signature.keyImage.keyImageHash]) {
                revert KeyImageAlreadySpent();
            }
        }

        txId = keccak256(
            abi.encodePacked(
                RINGCT_DOMAIN,
                block.timestamp,
                msg.sender,
                totalTransactions
            )
        );

        // Store transaction (simplified - full storage would be expensive)
        transactions[txId] = RCTTransaction({
            txId: txId,
            inputs: new RCTInput[](0), // Storage optimization
            outputs: new RCTOutput[](0),
            fee: fee,
            feeCommitment: feeCommitment,
            txType: txType,
            status: TransactionStatus.PENDING,
            timestamp: block.timestamp,
            chainId: block.chainid
        });

        totalTransactions++;

        emit RCTTransactionCreated(txId, inputs.length, outputs.length, txType);

        return txId;
    }

    /**
     * @notice Verify and execute RingCT transaction
     */
    function verifyAndExecuteRCT(
        bytes32 txId,
        RCTInput[] calldata inputs,
        RCTOutput[] calldata outputs,
        bytes calldata balanceProof,
        bytes[] calldata rangeProofs
    ) external onlyRole(VERIFIER_ROLE) returns (bool) {
        RCTTransaction storage txn = transactions[txId];
        if (txn.txId == bytes32(0)) revert TransactionNotFound();
        if (txn.status != TransactionStatus.PENDING)
            revert InvalidTransactionStatus();

        // 1. Verify all ring signatures
        for (uint256 i = 0; i < inputs.length; i++) {
            if (
                !this.verifyCLSAGSignature(inputs[i].ring, inputs[i].signature)
            ) {
                txn.status = TransactionStatus.REJECTED;
                emit RCTTransactionVerified(txId, TransactionStatus.REJECTED);
                return false;
            }
        }

        // 2. Verify range proofs (amounts are positive and in range)
        if (rangeProofs.length != outputs.length) {
            txn.status = TransactionStatus.REJECTED;
            emit RCTTransactionVerified(txId, TransactionStatus.REJECTED);
            return false;
        }

        for (uint256 i = 0; i < outputs.length; i++) {
            if (!_verifyBulletproof(outputs[i].rangeProof, rangeProofs[i])) {
                txn.status = TransactionStatus.REJECTED;
                emit RCTTransactionVerified(txId, TransactionStatus.REJECTED);
                return false;
            }
        }

        // 3. Verify balance (sum inputs = sum outputs + fee)
        if (
            !_verifyBalanceProof(
                inputs,
                outputs,
                txn.feeCommitment,
                balanceProof
            )
        ) {
            txn.status = TransactionStatus.REJECTED;
            emit RCTTransactionVerified(txId, TransactionStatus.REJECTED);
            return false;
        }

        // 4. Mark key images as spent
        for (uint256 i = 0; i < inputs.length; i++) {
            bytes32 keyImageHash = inputs[i].signature.keyImage.keyImageHash;
            spentKeyImages[keyImageHash] = true;
            emit KeyImageSpent(keyImageHash, txId);
        }

        // 5. Register new outputs in pool
        for (uint256 i = 0; i < outputs.length; i++) {
            bytes32 outHash = keccak256(
                abi.encodePacked(
                    outputs[i].commitment.commitmentX,
                    outputs[i].commitment.commitmentY
                )
            );
            commitmentRegistry[outHash] = outputs[i].commitment;
            outputPool.push(outHash);
        }

        txn.status = TransactionStatus.EXECUTED;
        emit RCTTransactionVerified(txId, TransactionStatus.EXECUTED);

        return true;
    }

    // =========================================================================
    // CROSS-CHAIN RINGCT
    // =========================================================================

    /**
     * @notice Initiate cross-chain RingCT transfer
     */
    function initiateCrossChainRCT(
        bytes32 sourceTxId,
        uint256 destChainId,
        KeyImage calldata keyImage,
        bytes calldata crossChainProof
    )
        external
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 destTxId, bytes32 nullifier)
    {
        RCTTransaction storage sourceTx = transactions[sourceTxId];
        if (sourceTx.txId == bytes32(0)) revert TransactionNotFound();
        if (sourceTx.status != TransactionStatus.EXECUTED)
            revert InvalidTransactionStatus();

        // Generate destination tx ID
        destTxId = keccak256(
            abi.encodePacked(
                sourceTxId,
                destChainId,
                block.timestamp,
                RINGCT_DOMAIN
            )
        );

        // Generate cross-chain nullifier
        nullifier = keccak256(
            abi.encodePacked(
                keyImage.keyImageHash,
                block.chainid,
                destChainId,
                "CROSS_CHAIN_NULLIFIER"
            )
        );

        crossChainTransfers[destTxId] = CrossChainRCT({
            sourceTxId: sourceTxId,
            destTxId: destTxId,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            linkedKeyImage: keyImage,
            nullifier: nullifier,
            timestamp: block.timestamp
        });

        totalCrossChainTransfers++;

        emit CrossChainRCTInitiated(
            sourceTxId,
            destTxId,
            block.chainid,
            destChainId
        );

        return (destTxId, nullifier);
    }

    // =========================================================================
    // DECOY SELECTION
    // =========================================================================

    /**
     * @notice Select decoys for ring signature (simplified)
     * @param realOutputIndex Index of real output in pool
     * @param ringSize Desired ring size
     */
    function selectDecoys(
        uint256 realOutputIndex,
        uint256 ringSize
    ) external view returns (bytes32[] memory decoyHashes) {
        if (ringSize < MIN_RING_SIZE || ringSize > MAX_RING_SIZE) {
            revert InvalidRingSize();
        }
        if (outputPool.length < ringSize) {
            revert InvalidRingSize();
        }

        decoyHashes = new bytes32[](ringSize);
        uint256 selected = 0;

        // Simple selection (in practice, use gamma distribution for realistic decoys)
        bytes32 seed = keccak256(
            abi.encodePacked(block.timestamp, realOutputIndex)
        );

        for (
            uint256 i = 0;
            selected < ringSize && i < outputPool.length * 2;
            i++
        ) {
            uint256 idx = uint256(keccak256(abi.encodePacked(seed, i))) %
                outputPool.length;

            // Check not already selected
            bool isDuplicate = false;
            for (uint256 j = 0; j < selected; j++) {
                if (decoyHashes[j] == outputPool[idx]) {
                    isDuplicate = true;
                    break;
                }
            }

            if (!isDuplicate) {
                decoyHashes[selected] = outputPool[idx];
                selected++;
            }
        }

        return decoyHashes;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _verifyBulletproof(
        BulletproofProof calldata proof,
        bytes calldata proofData
    ) internal pure returns (bool) {
        // Bulletproof verification (simplified)
        // In production, use proper Bulletproof verification
        return proof.A_x != 0 && proof.S_x != 0 && proofData.length >= 64;
    }

    function _verifyBalanceProof(
        RCTInput[] calldata inputs,
        RCTOutput[] calldata outputs,
        PedersenCommitment memory feeCommitment,
        bytes calldata proof
    ) internal pure returns (bool) {
        // Balance verification using Pedersen commitment homomorphism
        // sum(input_commitments) - sum(output_commitments) - fee_commitment = 0

        // Simplified verification
        return
            inputs.length > 0 &&
            outputs.length > 0 &&
            proof.length >= 32 &&
            feeCommitment.commitmentX != 0;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getTransaction(
        bytes32 txId
    ) external view returns (RCTTransaction memory) {
        return transactions[txId];
    }

    function getCrossChainTransfer(
        bytes32 destTxId
    ) external view returns (CrossChainRCT memory) {
        return crossChainTransfers[destTxId];
    }

    function getCommitment(
        bytes32 commitmentHash
    ) external view returns (PedersenCommitment memory) {
        return commitmentRegistry[commitmentHash];
    }

    function getOutputPoolSize() external view returns (uint256) {
        return outputPool.length;
    }

    function getStats()
        external
        view
        returns (
            uint256 _txCount,
            uint256 _crossChainCount,
            uint256 _commitmentCount,
            uint256 _outputPoolSize
        )
    {
        return (
            totalTransactions,
            totalCrossChainTransfers,
            totalCommitments,
            outputPool.length
        );
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
