/**
 * @title State Commitment Circuit Tests
 * @description Test suite for state_commitment.circom using snarkjs
 */

const { buildPoseidon } = require("circomlibjs");
const path = require("path");
const assert = require("assert");
const snarkjs = require("snarkjs");
const fs = require("fs");

describe("StateCommitment Circuit", function () {
    this.timeout(100000);

    let poseidon;
    let F;
    let wasmPath;
    let zkeyPath;
    let vkey;

    // Circuit uses 8 state fields
    const STATE_FIELDS = 8;

    before(async () => {
        const buildDir = path.join(__dirname, "..", "build", "state_commitment");
        wasmPath = path.join(buildDir, "state_commitment_js", "state_commitment.wasm");
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

    function computeCommitment(stateFields, salt, ownerSecret) {
        // Circuit logic:
        // 1. Hash state fields in chunks of 16 (we have 8, so 1 chunk padded with zeros)
        const paddedFields = [...stateFields];
        while (paddedFields.length < 16) {
            paddedFields.push(BigInt(0));
        }
        // For 8 fields, Poseidon(8) is used (chunkSize = 8 since 8 % 16 = 8)
        const stateHash = poseidon(stateFields);  // Poseidon with actual 8 fields
        
        // 2. Combine hashes (single chunk, so Poseidon(1) just wraps it)
        const combinedHash = poseidon([stateHash]);
        
        // 3. Final commitment = Poseidon(combinedHash, salt, ownerSecret)
        return poseidon([combinedHash, salt, ownerSecret]);
    }

    function derivePubkey(secret) {
        return poseidon([secret]);
    }

    describe("Valid Proofs", function () {
        it("should verify a valid state commitment", async () => {
            const stateFields = [
                BigInt("123456789"),
                BigInt("987654321"),
                BigInt("111111111"),
                BigInt("222222222"),
                BigInt("333333333"),
                BigInt("444444444"),
                BigInt("555555555"),
                BigInt("666666666"),
            ];
            const salt = BigInt("0xdeadbeef");
            const ownerSecret = BigInt("0x1234567890abcdef");

            const commitment = F.toObject(computeCommitment(stateFields, salt, ownerSecret));
            const ownerPubkey = F.toObject(derivePubkey(ownerSecret));

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: salt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: commitment.toString(),
                ownerPubkey: ownerPubkey.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof should be valid");
            assert.equal(publicSignals[0], "1", "Circuit output should be 1 (valid)");
            console.log("✓ Valid state commitment proof verified");
        });

        it("should verify with zero state fields", async () => {
            const stateFields = Array(8).fill(BigInt(0));
            const salt = BigInt("0x11111111");
            const ownerSecret = BigInt("0x22222222");

            const commitment = F.toObject(computeCommitment(stateFields, salt, ownerSecret));
            const ownerPubkey = F.toObject(derivePubkey(ownerSecret));

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: salt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: commitment.toString(),
                ownerPubkey: ownerPubkey.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof should be valid");
            assert.equal(publicSignals[0], "1", "Circuit output should be 1 (valid)");
            console.log("✓ Zero state fields proof verified");
        });

        it("should verify with large field values", async () => {
            const stateFields = [
                BigInt("18446744073709551615"),  // 2^64 - 1
                BigInt("18446744073709551614"),
                BigInt("18446744073709551613"),
                BigInt("18446744073709551612"),
                BigInt("18446744073709551611"),
                BigInt("18446744073709551610"),
                BigInt("18446744073709551609"),
                BigInt("18446744073709551608"),
            ];
            const salt = BigInt("0xffffffffffffff");
            const ownerSecret = BigInt("0xffffffffffffff");

            const commitment = F.toObject(computeCommitment(stateFields, salt, ownerSecret));
            const ownerPubkey = F.toObject(derivePubkey(ownerSecret));

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: salt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: commitment.toString(),
                ownerPubkey: ownerPubkey.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof should be valid");
            assert.equal(publicSignals[0], "1", "Circuit output should be 1 (valid)");
            console.log("✓ Large field values proof verified");
        });
    });

    describe("Invalid Proofs", function () {
        it("should reject wrong commitment", async () => {
            const stateFields = Array(8).fill(BigInt(1));
            const salt = BigInt("0xaaa");
            const ownerSecret = BigInt("0xbbb");
            const ownerPubkey = F.toObject(derivePubkey(ownerSecret));
            const wrongCommitment = BigInt("0x999999999");

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: salt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: wrongCommitment.toString(),
                ownerPubkey: ownerPubkey.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof generation should succeed");
            assert.equal(publicSignals[0], "0", "Circuit output should be 0 (invalid commitment)");
            console.log("✓ Wrong commitment correctly rejected");
        });

        it("should reject wrong owner pubkey", async () => {
            const stateFields = Array(8).fill(BigInt(1));
            const salt = BigInt("0xaaa");
            const ownerSecret = BigInt("0xbbb");
            const commitment = F.toObject(computeCommitment(stateFields, salt, ownerSecret));
            const wrongPubkey = BigInt("0x123123123");

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: salt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: commitment.toString(),
                ownerPubkey: wrongPubkey.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof generation should succeed");
            assert.equal(publicSignals[0], "0", "Circuit output should be 0 (invalid pubkey)");
            console.log("✓ Wrong pubkey correctly rejected");
        });

        it("should reject wrong salt", async () => {
            const stateFields = Array(8).fill(BigInt(1));
            const salt = BigInt("0xaaa");
            const wrongSalt = BigInt("0xbbb");
            const ownerSecret = BigInt("0xccc");
            const commitment = F.toObject(computeCommitment(stateFields, salt, ownerSecret));
            const ownerPubkey = F.toObject(derivePubkey(ownerSecret));

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: wrongSalt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: commitment.toString(),
                ownerPubkey: ownerPubkey.toString(),
            };

            const { isValid, publicSignals } = await generateProof(input);
            
            assert.equal(isValid, true, "Proof generation should succeed");
            assert.equal(publicSignals[0], "0", "Circuit output should be 0 (wrong salt)");
            console.log("✓ Wrong salt correctly rejected");
        });
    });

    describe("Proof Structure", function () {
        it("should generate proof with correct Groth16 structure", async () => {
            const stateFields = Array(8).fill(BigInt(42));
            const salt = BigInt("0xabc");
            const ownerSecret = BigInt("0xdef");
            const commitment = F.toObject(computeCommitment(stateFields, salt, ownerSecret));
            const ownerPubkey = F.toObject(derivePubkey(ownerSecret));

            const input = {
                stateFields: stateFields.map(f => f.toString()),
                salt: salt.toString(),
                ownerSecret: ownerSecret.toString(),
                commitment: commitment.toString(),
                ownerPubkey: ownerPubkey.toString(),
            };

            const { proof, publicSignals } = await generateProof(input);
            
            assert(proof.pi_a, "Proof should have pi_a");
            assert(proof.pi_b, "Proof should have pi_b");
            assert(proof.pi_c, "Proof should have pi_c");
            assert(Array.isArray(proof.pi_a), "pi_a should be an array");
            assert.equal(proof.pi_a.length, 3, "pi_a should have 3 elements");
            assert.equal(proof.protocol, "groth16", "Protocol should be groth16");
            
            console.log(`✓ Proof structure valid with ${publicSignals.length} public signals`);
        });
    });
});
