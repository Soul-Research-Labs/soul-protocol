const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const path = require("path");
const fs = require("fs");

/**
 * @title ZK Proof Integration Tests
 * @description End-to-end tests for state commitment with real ZK proofs
 */
describe("ZK Proof Integration", function () {
    this.timeout(300000); // 5 minutes for proof generation

    let poseidon;
    let F;
    
    // Circuit artifacts paths
    const CIRCUIT_BUILD_DIR = path.join(__dirname, "..", "circuits", "build");
    const STATE_COMMITMENT_WASM = path.join(CIRCUIT_BUILD_DIR, "state_commitment", "state_commitment_js", "state_commitment.wasm");
    const STATE_COMMITMENT_ZKEY = path.join(CIRCUIT_BUILD_DIR, "state_commitment", "circuit_final.zkey");
    
    before(async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });

    // Check if circuits are compiled
    function circuitsCompiled() {
        return fs.existsSync(STATE_COMMITMENT_WASM) && fs.existsSync(STATE_COMMITMENT_ZKEY);
    }

    // Deploy fixture with real verifier
    async function deployWithVerifierFixture() {
        const [owner, user1, user2] = await ethers.getSigners();

        // Deploy VerifierHub
        const VerifierHub = await ethers.getContractFactory("VerifierHub");
        const verifierHub = await VerifierHub.deploy();

        // For now, use mock verifier until circuits are compiled
        const MockVerifier = await ethers.getContractFactory("MockProofVerifier");
        const mockVerifier = await MockVerifier.deploy();

        // Deploy StateContainer
        const ConfidentialStateContainerV3 = await ethers.getContractFactory("ConfidentialStateContainerV3");
        const stateContainer = await ConfidentialStateContainerV3.deploy(await mockVerifier.getAddress());

        return { stateContainer, verifierHub, mockVerifier, owner, user1, user2 };
    }

    /**
     * Helper: Compute state commitment using Poseidon
     */
    function computeStateCommitment(stateFields, salt, ownerSecret) {
        const stateHash = poseidon(stateFields);
        return F.toObject(poseidon([stateHash, salt, ownerSecret]));
    }

    /**
     * Helper: Derive public key from secret
     */
    function derivePubkey(secret) {
        return F.toObject(poseidon([secret]));
    }

    /**
     * Helper: Compute nullifier
     */
    function computeNullifier(commitment, secret, nonce) {
        return F.toObject(poseidon([commitment, secret, nonce]));
    }

    /**
     * Helper: Generate state commitment proof
     */
    async function generateStateCommitmentProof(stateFields, salt, ownerSecret) {
        const commitment = computeStateCommitment(stateFields, salt, ownerSecret);
        const ownerPubkey = derivePubkey(ownerSecret);

        const input = {
            stateFields: stateFields.map(f => f.toString()),
            salt: salt.toString(),
            ownerSecret: ownerSecret.toString(),
            commitment: commitment.toString(),
            ownerPubkey: ownerPubkey.toString(),
        };

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            STATE_COMMITMENT_WASM,
            STATE_COMMITMENT_ZKEY
        );

        return { proof, publicSignals, commitment, ownerPubkey };
    }

    /**
     * Helper: Format proof for Solidity
     */
    function formatProofForSolidity(proof) {
        return [
            proof.pi_a[0], proof.pi_a[1],
            proof.pi_b[0][1], proof.pi_b[0][0],
            proof.pi_b[1][1], proof.pi_b[1][0],
            proof.pi_c[0], proof.pi_c[1]
        ];
    }

    describe("Commitment Computation", function () {
        it("should compute deterministic commitments", async function () {
            const stateFields = [BigInt(100), BigInt(200), BigInt(300), BigInt(400)];
            const salt = BigInt("0xdeadbeef");
            const ownerSecret = BigInt("0x123456789");

            const commitment1 = computeStateCommitment(stateFields, salt, ownerSecret);
            const commitment2 = computeStateCommitment(stateFields, salt, ownerSecret);

            expect(commitment1).to.equal(commitment2);
        });

        it("should produce different commitments for different salts", async function () {
            const stateFields = [BigInt(100), BigInt(200), BigInt(300), BigInt(400)];
            const salt1 = BigInt("0xaaa");
            const salt2 = BigInt("0xbbb");
            const ownerSecret = BigInt("0x123");

            const commitment1 = computeStateCommitment(stateFields, salt1, ownerSecret);
            const commitment2 = computeStateCommitment(stateFields, salt2, ownerSecret);

            expect(commitment1).to.not.equal(commitment2);
        });

        it("should produce different commitments for different owners", async function () {
            const stateFields = [BigInt(100), BigInt(200), BigInt(300), BigInt(400)];
            const salt = BigInt("0xaaa");
            const owner1 = BigInt("0x111");
            const owner2 = BigInt("0x222");

            const commitment1 = computeStateCommitment(stateFields, salt, owner1);
            const commitment2 = computeStateCommitment(stateFields, salt, owner2);

            expect(commitment1).to.not.equal(commitment2);
        });
    });

    describe("Nullifier Computation", function () {
        it("should compute deterministic nullifiers", async function () {
            const commitment = BigInt("0x123456");
            const secret = BigInt("0xabcdef");
            const nonce = BigInt("0x999");

            const nullifier1 = computeNullifier(commitment, secret, nonce);
            const nullifier2 = computeNullifier(commitment, secret, nonce);

            expect(nullifier1).to.equal(nullifier2);
        });

        it("should produce unique nullifiers per nonce", async function () {
            const commitment = BigInt("0x123456");
            const secret = BigInt("0xabcdef");

            const nullifier1 = computeNullifier(commitment, secret, BigInt(1));
            const nullifier2 = computeNullifier(commitment, secret, BigInt(2));

            expect(nullifier1).to.not.equal(nullifier2);
        });

        it("should bind nullifier to commitment", async function () {
            const secret = BigInt("0xabcdef");
            const nonce = BigInt("0x999");

            const nullifier1 = computeNullifier(BigInt("0x111"), secret, nonce);
            const nullifier2 = computeNullifier(BigInt("0x222"), secret, nonce);

            expect(nullifier1).to.not.equal(nullifier2);
        });
    });

    describe("Contract Integration", function () {
        it("should register state with computed commitment", async function () {
            const { stateContainer, user1 } = await loadFixture(deployWithVerifierFixture);

            const stateFields = [BigInt(1000), BigInt(0), BigInt(0), BigInt(0)];
            const salt = BigInt("0xdeadbeef");
            const ownerSecret = BigInt("0x12345");
            const nonce = BigInt("0x1");

            const commitment = computeStateCommitment(stateFields, salt, ownerSecret);
            const nullifier = computeNullifier(BigInt(commitment), ownerSecret, nonce);

            const encryptedState = ethers.toUtf8Bytes("encrypted_balance_1000");
            const proof = ethers.toUtf8Bytes("mock_proof");
            const publicInputs = ethers.toUtf8Bytes("mock_inputs");

            // Convert to bytes32
            const commitmentBytes32 = ethers.zeroPadValue(ethers.toBeHex(commitment), 32);
            const nullifierBytes32 = ethers.zeroPadValue(ethers.toBeHex(nullifier), 32);

            await expect(stateContainer.connect(user1).registerState(
                encryptedState,
                commitmentBytes32,
                nullifierBytes32,
                proof,
                publicInputs,
                ethers.ZeroHash
            )).to.emit(stateContainer, "StateRegistered");

            const state = await stateContainer.getState(commitmentBytes32);
            expect(state.owner).to.equal(user1.address);
            expect(state.nullifier).to.equal(nullifierBytes32);
        });

        it("should prevent double-spend with same nullifier", async function () {
            const { stateContainer, user1, user2 } = await loadFixture(deployWithVerifierFixture);

            const stateFields = [BigInt(1000), BigInt(0), BigInt(0), BigInt(0)];
            const salt = BigInt("0xaaa");
            const ownerSecret = BigInt("0x111");
            const nonce = BigInt("0x1");

            const commitment1 = computeStateCommitment(stateFields, salt, ownerSecret);
            const commitment2 = computeStateCommitment(stateFields, BigInt("0xbbb"), ownerSecret);
            const nullifier = computeNullifier(BigInt(commitment1), ownerSecret, nonce);

            const encryptedState = ethers.toUtf8Bytes("encrypted");
            const proof = ethers.toUtf8Bytes("proof");
            const publicInputs = ethers.toUtf8Bytes("inputs");

            const commitmentBytes32_1 = ethers.zeroPadValue(ethers.toBeHex(commitment1), 32);
            const commitmentBytes32_2 = ethers.zeroPadValue(ethers.toBeHex(commitment2), 32);
            const nullifierBytes32 = ethers.zeroPadValue(ethers.toBeHex(nullifier), 32);

            // First registration
            await stateContainer.connect(user1).registerState(
                encryptedState, commitmentBytes32_1, nullifierBytes32, proof, publicInputs, ethers.ZeroHash
            );

            // Second registration with same nullifier should fail
            await expect(stateContainer.connect(user2).registerState(
                encryptedState, commitmentBytes32_2, nullifierBytes32, proof, publicInputs, ethers.ZeroHash
            )).to.be.revertedWithCustomError(stateContainer, "NullifierAlreadyUsed");
        });

        it("should track state transfers correctly", async function () {
            const { stateContainer, user1, user2 } = await loadFixture(deployWithVerifierFixture);

            // Initial state
            const stateFields = [BigInt(500), BigInt(0), BigInt(0), BigInt(0)];
            const salt1 = BigInt("0xaaa");
            const owner1Secret = BigInt("0x111");
            const nonce1 = BigInt("0x1");

            const commitment1 = computeStateCommitment(stateFields, salt1, owner1Secret);
            const nullifier1 = computeNullifier(BigInt(commitment1), owner1Secret, nonce1);

            // Transfer to new owner
            const salt2 = BigInt("0xbbb");
            const owner2Secret = BigInt("0x222");
            const nonce2 = BigInt("0x2");

            const commitment2 = computeStateCommitment(stateFields, salt2, owner2Secret);
            const nullifier2 = computeNullifier(BigInt(commitment2), owner2Secret, nonce2);

            const encryptedState = ethers.toUtf8Bytes("encrypted");
            const proof = ethers.toUtf8Bytes("proof");
            const publicInputs = ethers.toUtf8Bytes("inputs");

            const commitmentBytes32_1 = ethers.zeroPadValue(ethers.toBeHex(commitment1), 32);
            const nullifierBytes32_1 = ethers.zeroPadValue(ethers.toBeHex(nullifier1), 32);
            const commitmentBytes32_2 = ethers.zeroPadValue(ethers.toBeHex(commitment2), 32);
            const nullifierBytes32_2 = ethers.zeroPadValue(ethers.toBeHex(nullifier2), 32);

            // Register initial state
            await stateContainer.connect(user1).registerState(
                encryptedState, commitmentBytes32_1, nullifierBytes32_1, proof, publicInputs, ethers.ZeroHash
            );

            // Transfer state
            await stateContainer.connect(user1).transferState(
                commitmentBytes32_1,
                encryptedState,
                commitmentBytes32_2,
                nullifierBytes32_2,
                proof,
                publicInputs,
                user2.address
            );

            // Verify old state is retired
            const oldState = await stateContainer.getState(commitmentBytes32_1);
            expect(oldState.status).to.equal(3); // Retired

            // Verify new state is active and owned by user2
            const newState = await stateContainer.getState(commitmentBytes32_2);
            expect(newState.status).to.equal(0); // Active
            expect(newState.owner).to.equal(user2.address);
        });
    });

    describe("Real ZK Proof Generation", function () {
        before(function () {
            if (!circuitsCompiled()) {
                console.log("⚠️  Circuits not compiled. Run: cd circuits && ./setup.sh");
                this.skip();
            }
        });

        it("should generate and verify state commitment proof", async function () {
            // Circuit expects 8 state fields (STATE_FIELDS = 8)
            const stateFields = [
                BigInt(100), BigInt(200), BigInt(300), BigInt(400),
                BigInt(500), BigInt(600), BigInt(700), BigInt(800)
            ];
            const salt = BigInt("0xdeadbeef");
            const ownerSecret = BigInt("0x123456789");

            const { proof, publicSignals, commitment, ownerPubkey } = 
                await generateStateCommitmentProof(stateFields, salt, ownerSecret);

            // Verify proof locally
            const vkeyPath = path.join(CIRCUIT_BUILD_DIR, "state_commitment", "verification_key.json");
            const vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
            
            const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
            expect(valid).to.be.true;

            console.log("✓ Proof generated and verified");
            console.log(`  Commitment: ${commitment}`);
            console.log(`  Owner Pubkey: ${ownerPubkey}`);
        });
    });
});
