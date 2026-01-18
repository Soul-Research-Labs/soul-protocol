pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

/**
 * PC³ Container Validity Circuit
 * 
 * Proves that a container is valid without revealing its contents.
 * This circuit validates:
 * 1. The encrypted payload matches the commitment
 * 2. The state commitment is correctly formed
 * 3. The nullifier is derived correctly from secret values
 * 4. The container hasn't expired
 */

template ContainerValidity(PAYLOAD_CHUNKS) {
    // Public inputs
    signal input stateCommitment;       // Public state commitment
    signal input nullifierHash;          // Public nullifier hash
    signal input currentTimestamp;       // Current block timestamp
    signal input expiryTimestamp;        // Container expiry time
    
    // Private inputs  
    signal input payloadChunks[PAYLOAD_CHUNKS]; // Encrypted payload chunks
    signal input nullifierSecret;        // Secret for nullifier derivation
    signal input salt;                   // Random salt for commitments
    signal input secretKey;              // User's secret key
    
    // Output
    signal output valid;
    
    // Step 1: Verify payload commitment
    component payloadHasher = Poseidon(PAYLOAD_CHUNKS + 1);
    for (var i = 0; i < PAYLOAD_CHUNKS; i++) {
        payloadHasher.inputs[i] <== payloadChunks[i];
    }
    payloadHasher.inputs[PAYLOAD_CHUNKS] <== salt;
    signal payloadCommitment <== payloadHasher.out;
    
    // Step 2: Verify state commitment includes payload
    component stateHasher = Poseidon(3);
    stateHasher.inputs[0] <== payloadCommitment;
    stateHasher.inputs[1] <== secretKey;
    stateHasher.inputs[2] <== salt;
    signal computedState <== stateHasher.out;
    
    // State commitment must match
    signal stateMatch;
    stateMatch <== IsEqual()([computedState, stateCommitment]);
    
    // Step 3: Verify nullifier derivation
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== nullifierSecret;
    nullifierHasher.inputs[1] <== secretKey;
    signal computedNullifier <== nullifierHasher.out;
    
    // Nullifier must match
    signal nullifierMatch;
    nullifierMatch <== IsEqual()([computedNullifier, nullifierHash]);
    
    // Step 4: Check expiry (currentTimestamp < expiryTimestamp)
    component expiryCheck = LessThan(64);
    expiryCheck.in[0] <== currentTimestamp;
    expiryCheck.in[1] <== expiryTimestamp;
    signal notExpired <== expiryCheck.out;
    
    // All conditions must be met
    signal condition1 <== stateMatch * nullifierMatch;
    valid <== condition1 * notExpired;
}

/**
 * Container Transfer Circuit
 * 
 * Proves a valid transfer between two parties while keeping amounts private.
 */
template ContainerTransfer() {
    // Public inputs
    signal input senderNullifierHash;    // Sender's nullifier (to be consumed)
    signal input recipientCommitment;     // Recipient's new commitment
    signal input transferHash;            // Hash of transfer metadata
    
    // Private inputs
    signal input senderSecretKey;
    signal input senderBalance;
    signal input transferAmount;
    signal input recipientPublicKey;
    signal input senderNullifierSecret;
    signal input recipientSalt;
    
    // Output
    signal output valid;
    
    // Step 1: Verify sender has sufficient balance
    component balanceCheck = GreaterEqThan(252);
    balanceCheck.in[0] <== senderBalance;
    balanceCheck.in[1] <== transferAmount;
    signal hasSufficientBalance <== balanceCheck.out;
    
    // Step 2: Verify sender's nullifier
    component senderNullifierHasher = Poseidon(2);
    senderNullifierHasher.inputs[0] <== senderNullifierSecret;
    senderNullifierHasher.inputs[1] <== senderSecretKey;
    signal computedSenderNullifier <== senderNullifierHasher.out;
    
    signal nullifierValid;
    nullifierValid <== IsEqual()([computedSenderNullifier, senderNullifierHash]);
    
    // Step 3: Compute recipient's commitment
    component recipientCommitmentHasher = Poseidon(3);
    recipientCommitmentHasher.inputs[0] <== transferAmount;
    recipientCommitmentHasher.inputs[1] <== recipientPublicKey;
    recipientCommitmentHasher.inputs[2] <== recipientSalt;
    signal computedRecipientCommitment <== recipientCommitmentHasher.out;
    
    signal commitmentValid;
    commitmentValid <== IsEqual()([computedRecipientCommitment, recipientCommitment]);
    
    // Step 4: Verify transfer hash
    component transferHasher = Poseidon(3);
    transferHasher.inputs[0] <== senderNullifierHash;
    transferHasher.inputs[1] <== recipientCommitment;
    transferHasher.inputs[2] <== transferAmount;
    signal computedTransferHash <== transferHasher.out;
    
    signal transferHashValid;
    transferHashValid <== IsEqual()([computedTransferHash, transferHash]);
    
    // All conditions must be met
    signal cond1 <== hasSufficientBalance * nullifierValid;
    signal cond2 <== cond1 * commitmentValid;
    valid <== cond2 * transferHashValid;
}

// Default instantiation with 4 payload chunks
component main { public [stateCommitment, nullifierHash, currentTimestamp, expiryTimestamp] } = ContainerValidity(4);
