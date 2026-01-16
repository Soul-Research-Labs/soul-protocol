/**
 * @title State Transfer Circuit Tests
 * @description Test suite for state_transfer.circom using snarkjs
 */

const { buildPoseidon } = require("circomlibjs");
const path = require("path");
const assert = require("assert");
const snarkjs = require("snarkjs");
const fs = require("fs");

describe("StateTransfer Circuit", function () {
    this.timeout(120000);

    let poseidon;
    let F;
    let wasmPath;
    let zkeyPath;
    let vkey;

    // Circuit uses 8 state fields
    const STATE_FIELDS = 8;

    before(async () => {
        const buildDir = path.join(__dirname, "..", "build", "state_transfer");
        wasmPath = path.join(buildDir, "state_transfer_js", "state_transfer.wasm");
        zkeyPath = path.join(buildDir, "circuit_final.zkey");
        const vkeyPath = path.join(buildDir, "verification_key.json");

        if (!fs.existsSync(wasmPath)) {
            throw new Error(`WASM not found: ${wasmPath}. Run setup.sh first.`);
        }
        if (!fs.existsSync(zkeyPath)) {
            throw new Error(`ZKey not found: ${zkeyPath}. Run setup.sh first.`);
        }
        if (!fs.existsSync(vkeyPath)) {
            throw new Error(`Verification key not found: ${vkeyPath}. Run setup.sh first.`);
        }

        vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    async function generateProof(input) {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            wasmPath,
            zkeyPath
        );
        const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
        return { proof, publicSignals, isValid };
    }

    function computeCommitment(stateFields, salt, secret) {
        const stateHash = poseidon(stateFields);
        return poseidon([stateHash, salt, secret]);
    }

    function derivePubkey(secret) {
        return poseidon([secret]);
    }

    function computeNullifier(commitment, secret, nonce) {
        return poseidon([commitment, secret, nonce]);
    }

    describe("Valid Transfers", function () {
        it("should verify a valid state transfer", async () => {
            // Old state (1000 tokens)
            const oldStateFields = Array(8).fill(BigInt(0));
            oldStateFields[0] = BigInt(1000); // Balance field
            const oldSalt = BigInt("0xaaa");
            const senderSecret = BigInt("0xbbb");
            const oldCommitment = F.toObject(computeCommitment(oldStateFields, oldSalt, senderSecret));
            const senderPubkey = F.toObject(derivePubkey(senderSecret));
            
            // New state (same balance - circuit requires value conservation)
            const newStateFields = Array(8).fill(BigInt(0));
            newStateFields[0] = BigInt(1000);  // Must match old for value conservation
            const newSalt = BigInt("0xccc");
            const recipientSecret = BigInt("0xddd");
            // New commitment is bound to recipient
            const newCommitment = F.toObject(computeCommitment(newStateFields, newSalt, recipientSecret));
            const recipientPubkey = F.toObject(derivePubkey(recipientSecret));
            
            // Nullifier
            const transferNonce = BigInt(1);
            const oldNullifier = F.toObject(computeNullifier(oldCommitment, senderSecret, transferNonce));
            
            // Transfer value (for record keeping, not enforced by circuit)
            const transferValue = BigInt(1000);

            const input = {
                // Private inputs
                oldStateFields: oldStateFields.map(f => f.toString()),
                oldSalt: oldSalt.toString(),
                senderSecret: senderSecret.toString(),
                newStateFields: newStateFields.map(f => f.toString()),
                newSalt: newSalt.toString(),
                recipientSecret: recipientSecret.toString(),
                transferNonce: transferNonce.toString(),
                
                // Public inputs
                oldCommitment: oldCommitment.toString(),
                newCommitment: newCommitment.toString(),
                oldNullifier: oldNullifier.toString(),
                senderPubkey: senderPubkey.toString(),
                recipientPubkey: recipientPubkey.toString(),
                transferValue: transferValue.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof should be valid");
            assert.equal(publicSignals[0], "1", "Circuit output should be 1 (valid transfer)");
            console.log("✓ Valid state transfer proof verified");
        });

        it("should verify transfer of entire balance", async () => {
            const oldStateFields = Array(8).fill(BigInt(0));
            oldStateFields[0] = BigInt(1000);
            const oldSalt = BigInt("0x111");
            const senderSecret = BigInt("0x222");
            const oldCommitment = F.toObject(computeCommitment(oldStateFields, oldSalt, senderSecret));
            const senderPubkey = F.toObject(derivePubkey(senderSecret));
            
            // New state with same balance (value conservation)
            const newStateFields = Array(8).fill(BigInt(0));
            newStateFields[0] = BigInt(1000);  // Must match for value conservation
            const newSalt = BigInt("0x333");
            const recipientSecret = BigInt("0x444");
            const newCommitment = F.toObject(computeCommitment(newStateFields, newSalt, recipientSecret));
            const recipientPubkey = F.toObject(derivePubkey(recipientSecret));
            
            const transferNonce = BigInt(1);
            const oldNullifier = F.toObject(computeNullifier(oldCommitment, senderSecret, transferNonce));
            const transferValue = BigInt(1000);

            const input = {
                oldStateFields: oldStateFields.map(f => f.toString()),
                oldSalt: oldSalt.toString(),
                senderSecret: senderSecret.toString(),
                newStateFields: newStateFields.map(f => f.toString()),
                newSalt: newSalt.toString(),
                recipientSecret: recipientSecret.toString(),
                transferNonce: transferNonce.toString(),
                oldCommitment: oldCommitment.toString(),
                newCommitment: newCommitment.toString(),
                oldNullifier: oldNullifier.toString(),
                senderPubkey: senderPubkey.toString(),
                recipientPubkey: recipientPubkey.toString(),
                transferValue: transferValue.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof should be valid");
            assert.equal(publicSignals[0], "1", "Circuit output should be 1");
            console.log("✓ Full balance transfer proof verified");
        });
    });

    describe("Invalid Transfers", function () {
        it("should reject invalid nullifier", async () => {
            const oldStateFields = Array(8).fill(BigInt(0));
            oldStateFields[0] = BigInt(1000);
            const oldSalt = BigInt("0xaaa");
            const senderSecret = BigInt("0xbbb");
            const oldCommitment = F.toObject(computeCommitment(oldStateFields, oldSalt, senderSecret));
            const senderPubkey = F.toObject(derivePubkey(senderSecret));
            
            const newStateFields = Array(8).fill(BigInt(0));
            newStateFields[0] = BigInt(500);
            const newSalt = BigInt("0xccc");
            const newCommitment = F.toObject(computeCommitment(newStateFields, newSalt, senderSecret));
            
            const recipientSecret = BigInt("0xddd");
            const recipientPubkey = F.toObject(derivePubkey(recipientSecret));
            
            const transferNonce = BigInt(1);
            const wrongNullifier = BigInt("0x12345"); // Wrong nullifier
            const transferValue = BigInt(500);

            const input = {
                oldStateFields: oldStateFields.map(f => f.toString()),
                oldSalt: oldSalt.toString(),
                senderSecret: senderSecret.toString(),
                newStateFields: newStateFields.map(f => f.toString()),
                newSalt: newSalt.toString(),
                recipientSecret: recipientSecret.toString(),
                transferNonce: transferNonce.toString(),
                oldCommitment: oldCommitment.toString(),
                newCommitment: newCommitment.toString(),
                oldNullifier: wrongNullifier.toString(),
                senderPubkey: senderPubkey.toString(),
                recipientPubkey: recipientPubkey.toString(),
                transferValue: transferValue.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof generation should succeed");
            assert.equal(publicSignals[0], "0", "Circuit output should be 0 (invalid nullifier)");
            console.log("✓ Invalid nullifier correctly rejected");
        });

        it("should reject invalid sender commitment", async () => {
            const oldStateFields = Array(8).fill(BigInt(0));
            oldStateFields[0] = BigInt(1000);
            const oldSalt = BigInt("0xaaa");
            const senderSecret = BigInt("0xbbb");
            const wrongOldCommitment = BigInt("0x999"); // Wrong commitment
            const senderPubkey = F.toObject(derivePubkey(senderSecret));
            
            const newStateFields = Array(8).fill(BigInt(0));
            newStateFields[0] = BigInt(500);
            const newSalt = BigInt("0xccc");
            const newCommitment = F.toObject(computeCommitment(newStateFields, newSalt, senderSecret));
            
            const recipientSecret = BigInt("0xddd");
            const recipientPubkey = F.toObject(derivePubkey(recipientSecret));
            
            const transferNonce = BigInt(1);
            const oldNullifier = F.toObject(computeNullifier(wrongOldCommitment, senderSecret, transferNonce));
            const transferValue = BigInt(500);

            const input = {
                oldStateFields: oldStateFields.map(f => f.toString()),
                oldSalt: oldSalt.toString(),
                senderSecret: senderSecret.toString(),
                newStateFields: newStateFields.map(f => f.toString()),
                newSalt: newSalt.toString(),
                recipientSecret: recipientSecret.toString(),
                transferNonce: transferNonce.toString(),
                oldCommitment: wrongOldCommitment.toString(),
                newCommitment: newCommitment.toString(),
                oldNullifier: oldNullifier.toString(),
                senderPubkey: senderPubkey.toString(),
                recipientPubkey: recipientPubkey.toString(),
                transferValue: transferValue.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof generation should succeed");
            assert.equal(publicSignals[0], "0", "Circuit output should be 0 (invalid commitment)");
            console.log("✓ Invalid sender commitment correctly rejected");
        });
    });

    describe("Proof Structure", function () {
        it("should generate proof with correct Groth16 structure", async () => {
            const oldStateFields = Array(8).fill(BigInt(100));
            const oldSalt = BigInt("0x1");
            const senderSecret = BigInt("0x2");
            const oldCommitment = F.toObject(computeCommitment(oldStateFields, oldSalt, senderSecret));
            const senderPubkey = F.toObject(derivePubkey(senderSecret));
            
            const newStateFields = Array(8).fill(BigInt(50));
            const newSalt = BigInt("0x3");
            const newCommitment = F.toObject(computeCommitment(newStateFields, newSalt, senderSecret));
            
            const recipientSecret = BigInt("0x4");
            const recipientPubkey = F.toObject(derivePubkey(recipientSecret));
            
            const transferNonce = BigInt(1);
            const oldNullifier = F.toObject(computeNullifier(oldCommitment, senderSecret, transferNonce));
            const transferValue = BigInt(50);

            const input = {
                oldStateFields: oldStateFields.map(f => f.toString()),
                oldSalt: oldSalt.toString(),
                senderSecret: senderSecret.toString(),
                newStateFields: newStateFields.map(f => f.toString()),
                newSalt: newSalt.toString(),
                recipientSecret: recipientSecret.toString(),
                transferNonce: transferNonce.toString(),
                oldCommitment: oldCommitment.toString(),
                newCommitment: newCommitment.toString(),
                oldNullifier: oldNullifier.toString(),
                senderPubkey: senderPubkey.toString(),
                recipientPubkey: recipientPubkey.toString(),
                transferValue: transferValue.toString(),
            };

            const { proof, publicSignals, isValid } = await generateProof(input);

            assert(proof.pi_a, "Proof should have pi_a");
            assert(proof.pi_b, "Proof should have pi_b");
            assert(proof.pi_c, "Proof should have pi_c");
            assert.equal(proof.protocol, "groth16", "Protocol should be groth16");
            
            console.log(`✓ Transfer proof structure valid with ${publicSignals.length} public signals`);
            assert.equal(isValid, true, "Proof should verify");
        });
    });
});
