import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex } from "viem";

/**
 * Midnight Bridge Adapter Tests
 * 
 * Tests Midnight privacy chain integration including:
 * - Shielded asset management
 * - ZK proof verification
 * - Compact contract management
 * - Private message passing
 * - Selective disclosure
 */
describe("MidnightBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const ZK_VERIFIER_ROLE = keccak256(toBytes("ZK_VERIFIER_ROLE"));
    const CONCLAVE_ROLE = keccak256(toBytes("CONCLAVE_ROLE"));

    // Test data
    const testAssetId = keccak256(toBytes("DUST-TOKEN"));
    const testAssetCommitment = keccak256(toBytes("asset-commitment"));
    const testContractHash = keccak256(toBytes("compact-contract"));
    const testProofHash = keccak256(toBytes("zk-proof-1"));
    const testMidnightAddress = keccak256(toBytes("midnight-address-1"));
    const testTreasuryAddress = keccak256(toBytes("midnight-treasury"));

    // Network enum
    const MAINNET = 0;
    const TESTNET = 1;
    const DEVNET = 2;

    // ZK proof types
    const GROTH16 = 0;
    const PLONK = 1;
    const BULLETPROOFS = 2;
    const STARK = 3;

    // Transaction types
    const TRANSPARENT = 0;
    const SHIELDED = 1;
    const MIXED = 2;

    async function getViem() {
        const connection = await hre.network.connect();
        return connection.viem;
    }

    async function deployBridge() {
        const viem = await getViem();
        const [admin] = await viem.getWalletClients();
        
        const bridge = await viem.deployContract("MidnightBridgeAdapter", [
            admin.account.address,
            MAINNET,
            testTreasuryAddress,
            2n // guardian threshold
        ]);

        return { viem, bridge, admin };
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    describe("Deployment", function () {
        it("Should deploy with correct initial state", async function () {
            const { bridge } = await deployBridge();

            const network = await bridge.read.network();
            expect(network).to.equal(MAINNET);

            const bridgeFee = await bridge.read.bridgeFee();
            expect(bridgeFee).to.equal(25n); // 0.25%

            const minTransfer = await bridge.read.minTransferAmount();
            expect(minTransfer).to.equal(10000n);
        });

        it("Should grant admin role to deployer", async function () {
            const { bridge, admin } = await deployBridge();

            const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });
            const hasRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should set treasury address", async function () {
            const { bridge } = await deployBridge();

            const treasury = await bridge.read.midnightTreasuryAddress();
            expect(treasury).to.equal(testTreasuryAddress);
        });

        it("Should start with zero counters", async function () {
            const { bridge } = await deployBridge();

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(0n); // messagesSent
            expect(stats[1]).to.equal(0n); // messagesReceived
            expect(stats[2]).to.equal(0n); // shieldedTransfers
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set network", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setNetwork([TESTNET]);

            const network = await bridge.read.network();
            expect(network).to.equal(TESTNET);
        });

        it("Should set bridge fee", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setBridgeFee([30n]); // 0.3%

            const fee = await bridge.read.bridgeFee();
            expect(fee).to.equal(30n);
        });

        it("Should reject fee above 0.5%", async function () {
            const { bridge } = await deployBridge();

            let reverted = false;
            try {
                await bridge.write.setBridgeFee([51n]); // 0.51%
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should register verification key", async function () {
            const { bridge } = await deployBridge();

            const vkHash = keccak256(toBytes("verification-key"));
            await bridge.write.registerVerificationKey([vkHash]);

            const isRegistered = await bridge.read.verificationKeys([vkHash]);
            expect(isRegistered).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      SHIELDED ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Shielded Asset Management", function () {
        it("Should register shielded asset", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.registerShieldedAsset([
                testAssetId,
                testAssetCommitment,
                8, // decimals
                admin.account.address
            ]);

            const asset = await bridge.read.getShieldedAsset([testAssetId]);
            expect(asset[0]).to.equal(testAssetId); // assetId
            expect(asset[1]).to.equal(testAssetCommitment); // assetCommitment
            expect(asset[2]).to.equal(8); // decimals
            expect(asset[4]).to.be.false; // verified
        });

        it("Should verify shielded asset", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.registerShieldedAsset([
                testAssetId,
                testAssetCommitment,
                8,
                admin.account.address
            ]);

            await bridge.write.verifyShieldedAsset([testAssetId]);

            const asset = await bridge.read.getShieldedAsset([testAssetId]);
            expect(asset[4]).to.be.true; // verified
        });

        it("Should reject zero asset ID", async function () {
            const { bridge, admin } = await deployBridge();

            const zeroId = padHex("0x00", { size: 32 });

            let reverted = false;
            try {
                await bridge.write.registerShieldedAsset([
                    zeroId,
                    testAssetCommitment,
                    8,
                    admin.account.address
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should map EVM token to Midnight asset", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.registerShieldedAsset([
                testAssetId,
                testAssetCommitment,
                8,
                admin.account.address
            ]);

            const mappedAsset = await bridge.read.evmToMidnightAsset([admin.account.address]);
            expect(mappedAsset).to.equal(testAssetId);
        });
    });

    /*//////////////////////////////////////////////////////////////
                      COMPACT CONTRACT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Compact Contract Management", function () {
        it("Should register Compact contract", async function () {
            const { bridge } = await deployBridge();

            const codeHash = keccak256(toBytes("compact-code"));
            const stateRoot = keccak256(toBytes("initial-state"));

            await bridge.write.registerCompactContract([
                testContractHash,
                codeHash,
                stateRoot
            ]);

            const contract = await bridge.read.getCompactContract([testContractHash]);
            expect(contract[0]).to.equal(testContractHash); // contractHash
            expect(contract[1]).to.equal(codeHash); // codeHash
            expect(contract[2]).to.equal(stateRoot); // stateRoot
            expect(contract[3]).to.equal(1); // status = PENDING
        });

        it("Should verify Compact contract", async function () {
            const { bridge } = await deployBridge();

            const codeHash = keccak256(toBytes("compact-code"));
            const stateRoot = keccak256(toBytes("initial-state"));

            await bridge.write.registerCompactContract([
                testContractHash,
                codeHash,
                stateRoot
            ]);
            await bridge.write.verifyCompactContract([testContractHash]);

            const contract = await bridge.read.getCompactContract([testContractHash]);
            expect(contract[3]).to.equal(2); // status = VERIFIED
        });
    });

    /*//////////////////////////////////////////////////////////////
                         ZK PROOF MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("ZK Proof Management", function () {
        it("Should submit ZK proof", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([ZK_VERIFIER_ROLE, admin.account.address]);

            const proofData = toHex("zk-proof-data");
            const publicInputs = [keccak256(toBytes("input1"))];

            await bridge.write.submitZKProof([
                testProofHash,
                GROTH16,
                proofData,
                publicInputs
            ]);

            const proof = await bridge.read.getZKProof([testProofHash]);
            expect(proof[0]).to.equal(testProofHash); // proofHash
            expect(proof[1]).to.equal(GROTH16); // proofType
            expect(proof[5]).to.be.false; // isValid (not yet verified)
        });

        it("Should verify ZK proof", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([ZK_VERIFIER_ROLE, admin.account.address]);

            // Register verification key first
            const vkHash = keccak256(toBytes("vk-groth16"));
            await bridge.write.registerVerificationKey([vkHash]);

            // Submit proof
            const proofData = toHex("zk-proof-data-valid");
            const publicInputs = [keccak256(toBytes("input1"))];
            await bridge.write.submitZKProof([
                testProofHash,
                GROTH16,
                proofData,
                publicInputs
            ]);

            // Verify
            await bridge.write.verifyZKProof([testProofHash, vkHash]);

            const proof = await bridge.read.getZKProof([testProofHash]);
            expect(proof[5]).to.be.true; // isValid
        });

        it("Should reject unregistered verification key", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([ZK_VERIFIER_ROLE, admin.account.address]);

            const proofData = toHex("zk-proof-data");
            const publicInputs = [keccak256(toBytes("input1"))];
            await bridge.write.submitZKProof([
                testProofHash,
                GROTH16,
                proofData,
                publicInputs
            ]);

            const unregisteredVk = keccak256(toBytes("unregistered"));

            let reverted = false;
            try {
                await bridge.write.verifyZKProof([testProofHash, unregisteredVk]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should check ZK proof validity", async function () {
            const { bridge } = await deployBridge();

            // Unsubmitted proof should be invalid
            const randomHash = keccak256(toBytes("random"));
            const isValid = await bridge.read.isZKProofValid([randomHash]);
            expect(isValid).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      SHIELDED TRANSFER OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Shielded Transfer Operations", function () {
        it("Should initiate shielded transfer", async function () {
            const { bridge, admin } = await deployBridge();

            // Register and verify asset
            await bridge.write.registerShieldedAsset([
                testAssetId,
                testAssetCommitment,
                8,
                admin.account.address
            ]);
            await bridge.write.verifyShieldedAsset([testAssetId]);

            const amountCommitment = keccak256(toBytes("amount-100"));
            const recipientCommitment = keccak256(toBytes("recipient"));
            const rangeProof = toHex("range-proof-data");

            await bridge.write.initiateShieldedTransfer(
                [testAssetId, amountCommitment, recipientCommitment, rangeProof],
                { value: parseEther("0.1") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[2]).to.equal(1n); // shieldedTransfers
        });

        it("Should reject transfer with unverified asset", async function () {
            const { bridge, admin } = await deployBridge();

            // Register but don't verify
            await bridge.write.registerShieldedAsset([
                testAssetId,
                testAssetCommitment,
                8,
                admin.account.address
            ]);

            const amountCommitment = keccak256(toBytes("amount"));
            const recipientCommitment = keccak256(toBytes("recipient"));
            const rangeProof = toHex("range-proof");

            let reverted = false;
            try {
                await bridge.write.initiateShieldedTransfer(
                    [testAssetId, amountCommitment, recipientCommitment, rangeProof],
                    { value: parseEther("0.1") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      PRIVATE MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Private Message Operations", function () {
        it("Should send private message", async function () {
            const { bridge } = await deployBridge();

            const encryptedPayload = toHex("encrypted-message-content");
            const payloadCommitment = keccak256(toBytes("payload"));

            await bridge.write.sendPrivateMessage(
                [testMidnightAddress, encryptedPayload, payloadCommitment, SHIELDED],
                { value: parseEther("0.01") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // messagesSent
        });

        it("Should reject invalid Midnight address", async function () {
            const { bridge } = await deployBridge();

            const zeroAddress = padHex("0x00", { size: 32 });
            const payload = toHex("test");
            const commitment = keccak256(toBytes("test"));

            let reverted = false;
            try {
                await bridge.write.sendPrivateMessage(
                    [zeroAddress, payload, commitment, SHIELDED],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject oversized payload", async function () {
            const { bridge } = await deployBridge();

            // Create a 40KB payload (over 32KB limit)
            const largePayload = "0x" + "ab".repeat(40000) as `0x${string}`;
            const commitment = keccak256(toBytes("large"));

            let reverted = false;
            try {
                await bridge.write.sendPrivateMessage(
                    [testMidnightAddress, largePayload, commitment, SHIELDED],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                    SELECTIVE DISCLOSURE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Selective Disclosure", function () {
        it("Should create disclosure proof", async function () {
            const { bridge } = await deployBridge();

            const dataCommitment = keccak256(toBytes("private-data"));
            const revealedFields = [keccak256(toBytes("field1"))];
            const zkProof = toHex("disclosure-zk-proof");

            await bridge.write.createDisclosureProof([
                dataCommitment,
                revealedFields,
                zkProof,
                86400n // 1 day validity
            ]);

            // Should have created the proof (can't easily get the ID in this test)
        });

        it("Should reject empty commitment", async function () {
            const { bridge } = await deployBridge();

            const zeroCommitment = padHex("0x00", { size: 32 });
            const revealedFields = [keccak256(toBytes("field1"))];
            const zkProof = toHex("disclosure-proof");

            let reverted = false;
            try {
                await bridge.write.createDisclosureProof([
                    zeroCommitment,
                    revealedFields,
                    zkProof,
                    86400n
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("Utility Functions", function () {
        it("Should compute commitment", async function () {
            const { bridge } = await deployBridge();

            const value = keccak256(toBytes("value"));
            const blinding = keccak256(toBytes("blinding"));

            const commitment = await bridge.read.computeCommitment([value, blinding]);
            expect(commitment).to.not.equal(padHex("0x00", { size: 32 }));

            // Same inputs should produce same commitment
            const commitment2 = await bridge.read.computeCommitment([value, blinding]);
            expect(commitment).to.equal(commitment2);
        });

        it("Should verify commitment opening", async function () {
            const { bridge } = await deployBridge();

            const value = keccak256(toBytes("value"));
            const blinding = keccak256(toBytes("blinding"));

            const commitment = await bridge.read.computeCommitment([value, blinding]);
            const isValid = await bridge.read.verifyCommitmentOpening([
                commitment,
                value,
                blinding
            ]);
            expect(isValid).to.be.true;
        });

        it("Should reject invalid commitment opening", async function () {
            const { bridge } = await deployBridge();

            const value = keccak256(toBytes("value"));
            const blinding = keccak256(toBytes("blinding"));
            const wrongValue = keccak256(toBytes("wrong"));

            const commitment = await bridge.read.computeCommitment([value, blinding]);
            const isValid = await bridge.read.verifyCommitmentOpening([
                commitment,
                wrongValue,
                blinding
            ]);
            expect(isValid).to.be.false;
        });

        it("Should generate nullifier", async function () {
            const { bridge } = await deployBridge();

            const transferId = keccak256(toBytes("transfer-1"));
            const secret = keccak256(toBytes("secret"));

            const nullifier = await bridge.read.generateNullifier([transferId, secret]);
            expect(nullifier).to.not.equal(padHex("0x00", { size: 32 }));

            // Same inputs should produce same nullifier
            const nullifier2 = await bridge.read.generateNullifier([transferId, secret]);
            expect(nullifier).to.equal(nullifier2);
        });

        it("Should check nullifier status", async function () {
            const { bridge } = await deployBridge();

            const randomNullifier = keccak256(toBytes("random-nullifier"));
            const isSpent = await bridge.read.isNullifierSpent([randomNullifier]);
            expect(isSpent).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PAUSABLE TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Pausable", function () {
        it("Should pause the bridge", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.pause();

            const isPaused = await bridge.read.paused();
            expect(isPaused).to.be.true;
        });

        it("Should unpause the bridge", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.pause();
            await bridge.write.unpause();

            const isPaused = await bridge.read.paused();
            expect(isPaused).to.be.false;
        });

        it("Should reject transfers when paused", async function () {
            const { bridge, admin } = await deployBridge();

            // Setup asset
            await bridge.write.registerShieldedAsset([
                testAssetId,
                testAssetCommitment,
                8,
                admin.account.address
            ]);
            await bridge.write.verifyShieldedAsset([testAssetId]);

            // Pause
            await bridge.write.pause();

            const amountCommitment = keccak256(toBytes("amount"));
            const recipientCommitment = keccak256(toBytes("recipient"));
            const rangeProof = toHex("range-proof");

            let reverted = false;
            try {
                await bridge.write.initiateShieldedTransfer(
                    [testAssetId, amountCommitment, recipientCommitment, rangeProof],
                    { value: parseEther("0.1") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         BRIDGE STATISTICS
    //////////////////////////////////////////////////////////////*/

    describe("Bridge Statistics", function () {
        it("Should return correct statistics", async function () {
            const { bridge } = await deployBridge();

            const stats = await bridge.read.getBridgeStats();

            expect(stats[0]).to.equal(0n); // messagesSent
            expect(stats[1]).to.equal(0n); // messagesReceived
            expect(stats[2]).to.equal(0n); // shieldedTransfers
            expect(stats[3]).to.equal(0n); // fees
            expect(stats[4]).to.equal(0n); // valueBridgedCount
        });
    });
});
