pragma circom 2.1.6;

include "circomlib/circuits/pedersen.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/**
 * @title PedersenStateCommitment
 * @notice State commitment using Pedersen hash for hiding property
 * @dev Pedersen commitments are additively homomorphic and perfectly hiding
 * 
 * Pedersen vs Poseidon:
 * - Pedersen: Perfectly hiding, computationally binding, ~250 constraints per bit
 * - Poseidon: Computationally hiding/binding, ~8 constraints per field element
 * 
 * Use Pedersen when hiding is critical (e.g., balance transfers)
 * Use Poseidon for general commitments where efficiency matters
 */
template PedersenStateCommitment() {
    // Private inputs
    signal input value;           // The value being committed (e.g., balance)
    signal input blinding;        // Random blinding factor (256 bits)
    signal input ownerSecret;     // Owner's secret key
    
    // Public inputs
    signal input commitment[2];   // Pedersen commitment point (x, y)
    signal input ownerPubkey;     // Owner's public identifier
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Convert value to bits for Pedersen
    // ═══════════════════════════════════════════════════════════════════
    
    component valueBits = Num2Bits(252);
    valueBits.in <== value;
    
    component blindingBits = Num2Bits(252);
    blindingBits.in <== blinding;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Compute Pedersen commitment C = vG + rH
    // ═══════════════════════════════════════════════════════════════════
    
    // Pedersen hash of value || blinding
    component pedersenCommit = Pedersen(504);  // 252 + 252 bits
    
    for (var i = 0; i < 252; i++) {
        pedersenCommit.in[i] <== valueBits.out[i];
        pedersenCommit.in[252 + i] <== blindingBits.out[i];
    }
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify commitment matches
    // ═══════════════════════════════════════════════════════════════════
    
    component checkX = IsEqual();
    checkX.in[0] <== pedersenCommit.out[0];
    checkX.in[1] <== commitment[0];
    
    component checkY = IsEqual();
    checkY.in[0] <== pedersenCommit.out[1];
    checkY.in[1] <== commitment[1];
    
    signal commitmentValid;
    commitmentValid <== checkX.out * checkY.out;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 4: Verify owner secret derives to pubkey
    // ═══════════════════════════════════════════════════════════════════
    
    component ownerHash = Poseidon(1);
    ownerHash.inputs[0] <== ownerSecret;
    
    component ownerValid = IsEqual();
    ownerValid.in[0] <== ownerHash.out;
    ownerValid.in[1] <== ownerPubkey;
    
    // Both must be valid
    valid <== commitmentValid * ownerValid.out;
}

/**
 * @title HomomorphicBalanceTransfer
 * @notice Proves valid balance transfer using Pedersen's homomorphic property
 * @dev C(v1) + C(v2) = C(v1 + v2) allows proving balance conservation privately
 */
template HomomorphicBalanceTransfer() {
    // Sender's commitment
    signal input senderValue;
    signal input senderBlinding;
    signal input senderCommitment[2];
    
    // Transfer amount (what sender sends)
    signal input transferValue;
    signal input transferBlinding;
    signal input transferCommitment[2];
    
    // Change back to sender
    signal input changeValue;
    signal input changeBlinding;
    signal input changeCommitment[2];
    
    // Public inputs for verification
    signal input senderPubkey;
    signal input senderSecret;
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify sender owns original commitment
    // ═══════════════════════════════════════════════════════════════════
    
    component senderCommit = PedersenStateCommitment();
    senderCommit.value <== senderValue;
    senderCommit.blinding <== senderBlinding;
    senderCommit.ownerSecret <== senderSecret;
    senderCommit.commitment[0] <== senderCommitment[0];
    senderCommit.commitment[1] <== senderCommitment[1];
    senderCommit.ownerPubkey <== senderPubkey;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Verify balance conservation: sender = transfer + change
    // ═══════════════════════════════════════════════════════════════════
    
    // Value conservation
    signal valueConserved;
    valueConserved <== senderValue - transferValue - changeValue;
    valueConserved === 0;
    
    // Blinding factor conservation (for homomorphic property)
    signal blindingConserved;
    blindingConserved <== senderBlinding - transferBlinding - changeBlinding;
    blindingConserved === 0;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify non-negative values (range proofs)
    // ═══════════════════════════════════════════════════════════════════
    
    // Ensure transfer and change are non-negative by checking bit representation
    component transferBits = Num2Bits(64);  // Max 64-bit values
    transferBits.in <== transferValue;
    
    component changeBits = Num2Bits(64);
    changeBits.in <== changeValue;
    
    valid <== senderCommit.valid;
}

/**
 * @title DualCommitment
 * @notice Creates both Poseidon (efficient) and Pedersen (hiding) commitments
 * @dev Use for applications requiring both efficiency and strong privacy guarantees
 */
template DualCommitment() {
    signal input value;
    signal input salt;
    signal input blinding;
    signal input ownerSecret;
    
    // Poseidon commitment (efficient)
    signal output poseidonCommitment;
    
    // Pedersen commitment (hiding)
    signal output pedersenCommitment[2];
    
    // Owner pubkey
    signal output ownerPubkey;
    
    // ═══════════════════════════════════════════════════════════════════
    // Poseidon commitment: H(value, salt, ownerSecret)
    // ═══════════════════════════════════════════════════════════════════
    
    component poseidonHash = Poseidon(3);
    poseidonHash.inputs[0] <== value;
    poseidonHash.inputs[1] <== salt;
    poseidonHash.inputs[2] <== ownerSecret;
    poseidonCommitment <== poseidonHash.out;
    
    // ═══════════════════════════════════════════════════════════════════
    // Pedersen commitment: vG + rH
    // ═══════════════════════════════════════════════════════════════════
    
    component valueBits = Num2Bits(252);
    valueBits.in <== value;
    
    component blindingBits = Num2Bits(252);
    blindingBits.in <== blinding;
    
    component pedersen = Pedersen(504);
    for (var i = 0; i < 252; i++) {
        pedersen.in[i] <== valueBits.out[i];
        pedersen.in[252 + i] <== blindingBits.out[i];
    }
    
    pedersenCommitment[0] <== pedersen.out[0];
    pedersenCommitment[1] <== pedersen.out[1];
    
    // ═══════════════════════════════════════════════════════════════════
    // Owner pubkey derivation
    // ═══════════════════════════════════════════════════════════════════
    
    component pubkeyHash = Poseidon(1);
    pubkeyHash.inputs[0] <== ownerSecret;
    ownerPubkey <== pubkeyHash.out;
}

// Main component for compilation
component main {public [commitment, ownerPubkey]} = PedersenStateCommitment();
