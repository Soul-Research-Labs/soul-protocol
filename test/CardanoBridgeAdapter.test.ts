import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex } from "viem";

/**
 * Cardano Bridge Adapter Tests
 * 
 * Tests Cardano/Mithril integration including:
 * - Plutus script registration
 * - Native asset management
 * - Mithril certificate verification
 * - UTXO proofs
 * - Hydra head operations
 * - Cross-chain transfers
 */
describe("CardanoBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const MITHRIL_SIGNER_ROLE = keccak256(toBytes("MITHRIL_SIGNER_ROLE"));
    const HYDRA_OPERATOR_ROLE = keccak256(toBytes("HYDRA_OPERATOR_ROLE"));

    // Test data
    const testPolicyId = "0x" + "ab".repeat(28) as `0x${string}`;
    const testAssetName = keccak256(toBytes("HOSKY"));
    const testScriptHash = keccak256(toBytes("test-plutus-script"));
    const testCardanoAddress = "0x" + "cd".repeat(57) as `0x${string}`;
    const testMithrilCertHash = keccak256(toBytes("mithril-cert"));
    const testHeadId = keccak256(toBytes("hydra-head-1"));

    // Cardano network enum
    const MAINNET = 0;
    const PREPROD = 1;
    const PREVIEW = 2;

    // Plutus script types
    const PLUTUS_V1 = 0;
    const PLUTUS_V2 = 1;
    const PLUTUS_V3 = 2;

    async function getViem() {
        const connection = await hre.network.connect();
        return connection.viem;
    }

    async function deployBridge() {
        const viem = await getViem();
        const [admin] = await viem.getWalletClients();
        
        const bridge = await viem.deployContract("CardanoBridgeAdapter", [
            admin.account.address,
            MAINNET,
            testCardanoAddress,
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
            expect(bridgeFee).to.equal(30n); // 0.3%

            const minTransfer = await bridge.read.minTransferAmount();
            expect(minTransfer).to.equal(2_000_000n); // 2 ADA
        });

        it("Should grant admin role to deployer", async function () {
            const { bridge, admin } = await deployBridge();

            const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });
            const hasRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should set treasury address", async function () {
            const { bridge } = await deployBridge();

            const treasury = await bridge.read.cardanoTreasuryAddress();
            expect(treasury).to.equal(testCardanoAddress);
        });

        it("Should set guardian threshold", async function () {
            const { bridge } = await deployBridge();

            const threshold = await bridge.read.guardianThreshold();
            expect(threshold).to.equal(2n);
        });

        it("Should start with zero counters", async function () {
            const { bridge } = await deployBridge();

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(0n); // messagesSent
            expect(stats[1]).to.equal(0n); // messagesReceived
            expect(stats[2]).to.equal(0n); // adaBridged
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set network", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setNetwork([PREPROD]);

            const network = await bridge.read.network();
            expect(network).to.equal(PREPROD);
        });

        it("Should set bridge fee", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setBridgeFee([50n]); // 0.5%

            const fee = await bridge.read.bridgeFee();
            expect(fee).to.equal(50n);
        });

        it("Should reject fee above 1%", async function () {
            const { bridge } = await deployBridge();

            let reverted = false;
            try {
                await bridge.write.setBridgeFee([101n]); // 1.01%
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should set minimum transfer amount", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setMinTransferAmount([5_000_000n]); // 5 ADA

            const minAmount = await bridge.read.minTransferAmount();
            expect(minAmount).to.equal(5_000_000n);
        });

        it("Should reject transfer amount below min UTXO", async function () {
            const { bridge } = await deployBridge();

            let reverted = false;
            try {
                await bridge.write.setMinTransferAmount([500_000n]); // 0.5 ADA
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should whitelist policy ID", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.whitelistPolicy([testPolicyId, true]);

            const isWhitelisted = await bridge.read.isPolicyWhitelisted([testPolicyId]);
            expect(isWhitelisted).to.be.true;
        });

        it("Should un-whitelist policy ID", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.whitelistPolicy([testPolicyId, true]);
            await bridge.write.whitelistPolicy([testPolicyId, false]);

            const isWhitelisted = await bridge.read.isPolicyWhitelisted([testPolicyId]);
            expect(isWhitelisted).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      PLUTUS SCRIPT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Plutus Script Management", function () {
        it("Should register Plutus V2 script", async function () {
            const { bridge } = await deployBridge();

            const scriptBytes = toHex("test script bytes");
            await bridge.write.registerPlutusScript([testScriptHash, PLUTUS_V2, scriptBytes]);

            const script = await bridge.read.plutusScripts([testScriptHash]);
            expect(script[0]).to.equal(testScriptHash); // scriptHash
            expect(script[1]).to.equal(PLUTUS_V2); // scriptType
            expect(script[3]).to.be.false; // verified
        });

        it("Should register Plutus V3 script", async function () {
            const { bridge } = await deployBridge();

            const scriptBytes = toHex("plutus v3 script");
            await bridge.write.registerPlutusScript([testScriptHash, PLUTUS_V3, scriptBytes]);

            const script = await bridge.read.plutusScripts([testScriptHash]);
            expect(script[1]).to.equal(PLUTUS_V3);
        });

        it("Should reject zero hash script registration", async function () {
            const { bridge } = await deployBridge();

            const zeroHash = padHex("0x00", { size: 32 });
            const scriptBytes = toHex("test script");

            let reverted = false;
            try {
                await bridge.write.registerPlutusScript([zeroHash, PLUTUS_V2, scriptBytes]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      NATIVE ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Native Asset Management", function () {
        it("Should register native asset", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.registerNativeAsset([
                testPolicyId,
                testAssetName,
                admin.account.address
            ]);

            const asset = await bridge.read.getNativeAsset([testPolicyId, testAssetName]);
            expect(asset[0]).to.equal(testPolicyId); // policyId
            expect(asset[1]).to.equal(testAssetName); // assetName
            expect(asset[3].toLowerCase()).to.equal(admin.account.address.toLowerCase()); // evmToken
            expect(asset[4]).to.be.false; // verified
        });

        it("Should reject zero policy ID", async function () {
            const { bridge, admin } = await deployBridge();

            const zeroPolicyId = "0x" + "00".repeat(28) as `0x${string}`;

            let reverted = false;
            try {
                await bridge.write.registerNativeAsset([
                    zeroPolicyId,
                    testAssetName,
                    admin.account.address
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should map EVM token to Cardano asset", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.registerNativeAsset([
                testPolicyId,
                testAssetName,
                admin.account.address
            ]);

            const assetId = await bridge.read.evmToCardanoAsset([admin.account.address]);
            expect(assetId).to.not.equal(padHex("0x00", { size: 32 }));
        });
    });

    /*//////////////////////////////////////////////////////////////
                    MITHRIL CERTIFICATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Mithril Certificate Management", function () {
        it("Should submit Mithril certificate", async function () {
            const { bridge, viem, admin } = await deployBridge();

            // Grant MITHRIL_SIGNER_ROLE
            await bridge.write.grantRole([MITHRIL_SIGNER_ROLE, admin.account.address]);

            const merkleRoot = keccak256(toBytes("merkle-root"));
            const stakesRoot = keccak256(toBytes("stakes-root"));
            const signature = toHex("aggregate-signature");

            await bridge.write.submitMithrilCertificate([
                testMithrilCertHash,
                100n, // epoch
                1000n, // immutableFileNumber
                merkleRoot,
                stakesRoot,
                10n, // signersCount
                signature
            ]);

            const cert = await bridge.read.getMithrilCertificate([testMithrilCertHash]);
            expect(cert[0]).to.equal(testMithrilCertHash); // certHash
            expect(cert[1]).to.equal(100n); // epoch
            expect(cert[3]).to.equal(merkleRoot); // merkleRoot
        });

        it("Should check certificate validity", async function () {
            const { bridge } = await deployBridge();

            // Unsubmitted certificate should be invalid
            const randomHash = keccak256(toBytes("random"));
            const isValid = await bridge.read.isMithrilCertificateValid([randomHash]);
            expect(isValid).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                        HYDRA HEAD OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Hydra Head Operations", function () {
        it("Should create Hydra head", async function () {
            const { bridge, viem, admin } = await deployBridge();

            // Grant HYDRA_OPERATOR_ROLE
            await bridge.write.grantRole([HYDRA_OPERATOR_ROLE, admin.account.address]);

            const participants = [
                keccak256(toBytes("participant-1")),
                keccak256(toBytes("participant-2"))
            ];
            const evmParticipants = [
                admin.account.address,
                admin.account.address
            ];

            await bridge.write.createHydraHead([
                testHeadId,
                participants,
                evmParticipants,
                300n // 5 minute contestation
            ]);

            const head = await bridge.read.getHydraHead([testHeadId]);
            expect(head[0]).to.equal(testHeadId); // headId
            expect(head[3]).to.equal(300n); // contestationPeriod
            expect(head[4]).to.equal(1); // state = INITIALIZING
        });

        it("Should reject mismatched participant arrays", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([HYDRA_OPERATOR_ROLE, admin.account.address]);

            const participants = [keccak256(toBytes("participant-1"))];
            const evmParticipants = [
                admin.account.address,
                admin.account.address // One extra
            ];

            let reverted = false;
            try {
                await bridge.write.createHydraHead([
                    testHeadId,
                    participants,
                    evmParticipants,
                    300n
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should open Hydra head", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([HYDRA_OPERATOR_ROLE, admin.account.address]);

            const participants = [keccak256(toBytes("participant-1"))];
            const evmParticipants = [admin.account.address];

            await bridge.write.createHydraHead([
                testHeadId,
                participants,
                evmParticipants,
                60n
            ]);

            const utxoHash = keccak256(toBytes("committed-utxos"));
            await bridge.write.openHydraHead([testHeadId, utxoHash]);

            const head = await bridge.read.getHydraHead([testHeadId]);
            expect(head[4]).to.equal(2); // state = OPEN
            expect(head[5]).to.equal(utxoHash); // utxoHash
        });

        it("Should close Hydra head", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([HYDRA_OPERATOR_ROLE, admin.account.address]);

            const participants = [keccak256(toBytes("participant-1"))];
            await bridge.write.createHydraHead([
                testHeadId,
                participants,
                [admin.account.address],
                60n
            ]);
            await bridge.write.openHydraHead([testHeadId, keccak256(toBytes("utxos"))]);
            await bridge.write.closeHydraHead([testHeadId]);

            const head = await bridge.read.getHydraHead([testHeadId]);
            expect(head[4]).to.equal(3); // state = CLOSED
        });

        it("Should reject opening non-initializing head", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([HYDRA_OPERATOR_ROLE, admin.account.address]);

            const participants = [keccak256(toBytes("participant-1"))];
            await bridge.write.createHydraHead([
                testHeadId,
                participants,
                [admin.account.address],
                60n
            ]);
            await bridge.write.openHydraHead([testHeadId, keccak256(toBytes("utxos"))]);

            // Try to open again
            let reverted = false;
            try {
                await bridge.write.openHydraHead([testHeadId, keccak256(toBytes("utxos2"))]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         TRANSFER OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Transfer Operations", function () {
        it("Should initiate transfer to Cardano", async function () {
            const { bridge, admin } = await deployBridge();

            // Whitelist policy for native asset, or use ADA (zero policy)
            const adaPolicyId = "0x" + "00".repeat(28) as `0x${string}`;
            const adaAssetName = padHex("0x00", { size: 32 });

            const fee = parseEther("0.001");
            const tx = await bridge.write.initiateTransferToCardano(
                [adaPolicyId, adaAssetName, 5_000_000n, testCardanoAddress],
                { value: fee }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // messagesSent
        });

        it("Should reject transfer below minimum", async function () {
            const { bridge } = await deployBridge();

            const adaPolicyId = "0x" + "00".repeat(28) as `0x${string}`;
            const adaAssetName = padHex("0x00", { size: 32 });

            let reverted = false;
            try {
                await bridge.write.initiateTransferToCardano(
                    [adaPolicyId, adaAssetName, 500_000n, testCardanoAddress], // 0.5 ADA
                    { value: parseEther("0.001") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject non-whitelisted native asset", async function () {
            const { bridge } = await deployBridge();

            let reverted = false;
            try {
                await bridge.write.initiateTransferToCardano(
                    [testPolicyId, testAssetName, 1_000_000n, testCardanoAddress],
                    { value: parseEther("0.001") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should accept whitelisted native asset transfer", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.whitelistPolicy([testPolicyId, true]);

            const tx = await bridge.write.initiateTransferToCardano(
                [testPolicyId, testAssetName, 5_000_000n, testCardanoAddress],
                { value: parseEther("0.001") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // messagesSent
        });
    });

    /*//////////////////////////////////////////////////////////////
                         MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Message Operations", function () {
        it("Should send message to Cardano", async function () {
            const { bridge } = await deployBridge();

            const payload = toHex("Hello Cardano!");

            await bridge.write.sendMessageToCardano(
                [testCardanoAddress, payload],
                { value: parseEther("0.001") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // messagesSent
        });

        it("Should reject invalid Cardano address", async function () {
            const { bridge } = await deployBridge();

            const shortAddress = "0x" + "ab".repeat(10) as `0x${string}`; // Too short
            const payload = toHex("test");

            let reverted = false;
            try {
                await bridge.write.sendMessageToCardano(
                    [shortAddress, payload],
                    { value: parseEther("0.001") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject oversized payload", async function () {
            const { bridge } = await deployBridge();

            // Create a 70KB payload (over 65KB limit)
            const largePayload = "0x" + "ab".repeat(70000) as `0x${string}`;

            let reverted = false;
            try {
                await bridge.write.sendMessageToCardano(
                    [testCardanoAddress, largePayload],
                    { value: parseEther("0.001") }
                );
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
        it("Should convert lovelace to ADA", async function () {
            const { bridge } = await deployBridge();

            const ada = await bridge.read.lovelaceToAda([1_000_000n]);
            expect(ada).to.equal(1_000_000n); // 1 ADA = 1,000,000 lovelace
        });

        it("Should convert ADA to lovelace", async function () {
            const { bridge } = await deployBridge();

            const lovelace = await bridge.read.adaToLovelace([1_000_000n]);
            expect(lovelace).to.equal(1_000_000n);
        });

        it("Should validate Cardano mainnet address", async function () {
            const { bridge } = await deployBridge();

            // Valid mainnet address (header byte 0x01 = base address, mainnet)
            const validAddress = "0x01" + "ab".repeat(56) as `0x${string}`;
            const isValid = await bridge.read.isValidCardanoAddress([validAddress]);
            expect(isValid).to.be.true;
        });

        it("Should validate Cardano testnet address", async function () {
            const { bridge } = await deployBridge();

            // Valid testnet address (header byte 0x00 = base address, testnet)
            const validAddress = "0x00" + "ab".repeat(56) as `0x${string}`;
            const isValid = await bridge.read.isValidCardanoAddress([validAddress]);
            expect(isValid).to.be.true;
        });

        it("Should reject invalid address type", async function () {
            const { bridge } = await deployBridge();

            // Invalid address type (0xF0 = type 15, invalid)
            const invalidAddress = "0xF0" + "ab".repeat(56) as `0x${string}`;
            const isValid = await bridge.read.isValidCardanoAddress([invalidAddress]);
            expect(isValid).to.be.false;
        });

        it("Should reject too short address", async function () {
            const { bridge } = await deployBridge();

            const shortAddress = "0x01" + "ab".repeat(20) as `0x${string}`;
            const isValid = await bridge.read.isValidCardanoAddress([shortAddress]);
            expect(isValid).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PAUSABLE TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Pausable", function () {
        it("Should pause the bridge", async function () {
            const { bridge, admin } = await deployBridge();

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
            const { bridge } = await deployBridge();

            await bridge.write.pause();

            const adaPolicyId = "0x" + "00".repeat(28) as `0x${string}`;
            const adaAssetName = padHex("0x00", { size: 32 });

            let reverted = false;
            try {
                await bridge.write.initiateTransferToCardano(
                    [adaPolicyId, adaAssetName, 5_000_000n, testCardanoAddress],
                    { value: parseEther("0.001") }
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
            expect(stats[2]).to.equal(0n); // adaBridged
            expect(stats[3]).to.equal(0n); // fees
            expect(stats[4]).to.equal(0n); // latestSlot
            expect(stats[5]).to.equal(0n); // latestEpoch
        });

        it("Should track accumulated fees", async function () {
            const { bridge } = await deployBridge();

            const adaPolicyId = "0x" + "00".repeat(28) as `0x${string}`;
            const adaAssetName = padHex("0x00", { size: 32 });

            await bridge.write.initiateTransferToCardano(
                [adaPolicyId, adaAssetName, 10_000_000n, testCardanoAddress], // 10 ADA
                { value: parseEther("0.01") }
            );

            const fees = await bridge.read.accumulatedFees();
            expect(fees).to.be.greaterThan(0n);
        });
    });
});
