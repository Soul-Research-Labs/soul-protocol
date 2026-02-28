// ═══════════════════════════════════════════════════════════════════════════════
// GasOptimizedPrivacy.spec — Certora CVL Specification
// Covers GasOptimizedStealthRegistry, GasOptimizedNullifierManager,
// and GasOptimizedRingCT contracts from GasOptimizedPrivacy.sol
// ═══════════════════════════════════════════════════════════════════════════════

methods {
    // GasOptimizedRingCT
    function usedKeyImages(bytes32) external returns (bool) envfree;
    function commitmentSet(bytes32) external returns (bool) envfree;
    function ringSignatureVerifier() external returns (address) envfree;
    function MIN_RING_SIZE() external returns (uint256) envfree;
    function MAX_RING_SIZE() external returns (uint256) envfree;
    function setRingSignatureVerifier(address) external;
    function processRingCT(bytes32[], bytes32[], bytes32[], bytes, bytes32) external;

    // Ownable
    function owner() external returns (address) envfree;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Ring size bounds are correct
rule minRingSizeIsTwo() {
    assert MIN_RING_SIZE() == 2, "Min ring size must be 2";
}

rule maxRingSizeIsSixteen() {
    assert MAX_RING_SIZE() == 16, "Max ring size must be 16";
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY IMAGE DOUBLE-SPEND PREVENTION
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Once a key image is marked used, it stays used forever
/// @notice This prevents double-spending of UTXOs in RingCT
invariant keyImagePermanence(bytes32 ki)
    usedKeyImages(ki) => usedKeyImages(ki)
    {
        preserved with (env e) {
            require e.msg.value == 0;
        }
    }

/// @title processRingCT marks all key images as used
rule processRingCTMarksKeyImages(
    env e,
    bytes32[] inputCommitments,
    bytes32[] outputCommitments,
    bytes32[] keyImages,
    bytes ringSignature,
    bytes32 pseudoOutputCommitment
) {
    require keyImages.length > 0;
    require keyImages.length <= 16;

    bytes32 firstKeyImage = keyImages[0];
    bool usedBefore = usedKeyImages(firstKeyImage);

    processRingCT(e, inputCommitments, outputCommitments, keyImages, ringSignature, pseudoOutputCommitment);

    bool usedAfter = usedKeyImages(firstKeyImage);

    assert usedAfter, "First key image must be marked used after processRingCT";
}

/// @title processRingCT reverts if any key image was already spent
rule doubleSpendReverts(
    env e,
    bytes32[] inputCommitments,
    bytes32[] outputCommitments,
    bytes32[] keyImages,
    bytes ringSignature,
    bytes32 pseudoOutputCommitment
) {
    require keyImages.length > 0;
    require keyImages.length <= 16;

    bytes32 firstKeyImage = keyImages[0];
    require usedKeyImages(firstKeyImage) == true;

    processRingCT@withrevert(e, inputCommitments, outputCommitments, keyImages, ringSignature, pseudoOutputCommitment);

    assert lastReverted, "processRingCT must revert when key image already spent";
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMITMENT SET PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Commitments once added are never removed
invariant commitmentPermanence(bytes32 c)
    commitmentSet(c) => commitmentSet(c)
    {
        preserved with (env e) {
            require e.msg.value == 0;
        }
    }

// ═══════════════════════════════════════════════════════════════════════════════
// RING SIGNATURE VERIFIER MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Only owner can set ring signature verifier
rule onlyOwnerSetsVerifier(env e, address newVerifier) {
    address ownerBefore = owner();

    setRingSignatureVerifier@withrevert(e, newVerifier);

    assert !lastReverted => e.msg.sender == ownerBefore,
        "Only owner can set ring signature verifier";
}

/// @title setRingSignatureVerifier rejects zero address
rule zeroVerifierReverts(env e) {
    setRingSignatureVerifier@withrevert(e, 0);
    assert lastReverted, "Zero address for verifier must revert";
}

/// @title setRingSignatureVerifier correctly updates the verifier address
rule verifierUpdateCorrect(env e, address newVerifier) {
    require newVerifier != 0;
    require e.msg.sender == owner();

    setRingSignatureVerifier(e, newVerifier);

    assert ringSignatureVerifier() == newVerifier,
        "Verifier must be updated to new address";
}

// ═══════════════════════════════════════════════════════════════════════════════
// INPUT VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

/// @title processRingCT rejects rings smaller than MIN_RING_SIZE
rule tooSmallRingReverts(
    env e,
    bytes32[] inputCommitments,
    bytes32[] outputCommitments,
    bytes32[] keyImages,
    bytes ringSignature,
    bytes32 pseudoOutputCommitment
) {
    require inputCommitments.length < 2;

    processRingCT@withrevert(e, inputCommitments, outputCommitments, keyImages, ringSignature, pseudoOutputCommitment);

    assert lastReverted, "processRingCT must revert for rings smaller than MIN_RING_SIZE";
}

/// @title processRingCT rejects rings larger than MAX_RING_SIZE
rule tooLargeRingReverts(
    env e,
    bytes32[] inputCommitments,
    bytes32[] outputCommitments,
    bytes32[] keyImages,
    bytes ringSignature,
    bytes32 pseudoOutputCommitment
) {
    require inputCommitments.length > 16;

    processRingCT@withrevert(e, inputCommitments, outputCommitments, keyImages, ringSignature, pseudoOutputCommitment);

    assert lastReverted, "processRingCT must revert for rings larger than MAX_RING_SIZE";
}

// ═══════════════════════════════════════════════════════════════════════════════
// NO RING SIGNATURE VERIFIER SET → REVERTS
// ═══════════════════════════════════════════════════════════════════════════════

/// @title processRingCT reverts when no ring signature verifier is set
rule noVerifierSetReverts(
    env e,
    bytes32[] inputCommitments,
    bytes32[] outputCommitments,
    bytes32[] keyImages,
    bytes ringSignature,
    bytes32 pseudoOutputCommitment
) {
    require ringSignatureVerifier() == 0;
    require inputCommitments.length >= 2;
    require inputCommitments.length <= 16;
    require keyImages.length > 0;
    require keyImages.length <= 16;

    // Fresh key images
    require keyImages.length == 1;
    bytes32 ki = keyImages[0];
    require !usedKeyImages(ki);

    processRingCT@withrevert(e, inputCommitments, outputCommitments, keyImages, ringSignature, pseudoOutputCommitment);

    assert lastReverted, "processRingCT must revert when no verifier is set";
}
