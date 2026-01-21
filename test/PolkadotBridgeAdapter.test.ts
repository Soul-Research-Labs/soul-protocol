import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex } from "viem";

/**
 * Polkadot Bridge Adapter Tests
 * 
 * Tests Polkadot ecosystem integration including:
 * - Parachain management
 * - Asset registration and transfers
 * - XCM messaging
 * - GRANDPA finality proofs
 * - BEEFY commitments
 * - State proofs
 */
describe("PolkadotBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const VALIDATOR_ROLE = keccak256(toBytes("VALIDATOR_ROLE"));
    const BEEFY_ROLE = keccak256(toBytes("BEEFY_ROLE"));

    // Test data
    const testAssetId = keccak256(toBytes("DOT-ASSET"));
    const testGenesisHash = keccak256(toBytes("polkadot-genesis"));
    const testBlockHash = keccak256(toBytes("block-hash-1"));
    const testRecipient = keccak256(toBytes("polkadot-recipient"));
    const testSovereignAccount = keccak256(toBytes("sovereign-account"));

    // Network types
    const POLKADOT = 0;
    const KUSAMA = 1;
    const ROCOCO = 2;
    const WESTEND = 3;

    // Transfer types
    const TELEPORT = 0;
    const RESERVE_WITHDRAW = 1;
    const RESERVE_DEPOSIT = 2;
    const LOCAL_RESERVE = 3;

    // Parachain statuses
    const INACTIVE = 0;
    const ONBOARDING = 1;
    const ACTIVE = 2;
    const OFFBOARDING = 3;
    const RETIRED = 4;

    // Common parachain IDs
    const MOONBEAM_PARA_ID = 2004;
    const ACALA_PARA_ID = 2000;
    const ASTAR_PARA_ID = 2006;

    async function getViem() {
        const connection = await hre.network.connect();
        return connection.viem;
    }

    async function deployBridge() {
        const viem = await getViem();
        const [admin] = await viem.getWalletClients();
        
        const bridge = await viem.deployContract("PolkadotBridgeAdapter", [
            admin.account.address,
            POLKADOT,
            testGenesisHash,
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
            expect(network).to.equal(POLKADOT);

            const bridgeFee = await bridge.read.bridgeFee();
            expect(bridgeFee).to.equal(25n); // 0.25%

            const minTransfer = await bridge.read.minTransferAmount();
            expect(minTransfer).to.equal(BigInt(1e15));
        });

        it("Should grant admin role to deployer", async function () {
            const { bridge, admin } = await deployBridge();

            const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });
            const hasRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should set relay genesis hash", async function () {
            const { bridge } = await deployBridge();

            const genesis = await bridge.read.relayGenesisHash();
            expect(genesis).to.equal(testGenesisHash);
        });

        it("Should start with zero counters", async function () {
            const { bridge } = await deployBridge();

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(0n); // transfersOut
            expect(stats[1]).to.equal(0n); // transfersIn
            expect(stats[2]).to.equal(0n); // valueBridged
        });
    });

    /*//////////////////////////////////////////////////////////////
                       PARACHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Parachain Management", function () {
        it("Should register a parachain", async function () {
            const { bridge } = await deployBridge();

            const moonbeamGenesis = keccak256(toBytes("moonbeam-genesis"));
            
            await bridge.write.registerParachain([
                MOONBEAM_PARA_ID,
                moonbeamGenesis,
                true, // evmCompatible
                testSovereignAccount
            ]);

            const para = await bridge.read.getParachain([MOONBEAM_PARA_ID]);
            expect(para[0]).to.equal(MOONBEAM_PARA_ID); // paraId
            expect(para[1]).to.equal(moonbeamGenesis); // genesisHash
            expect(para[4]).to.equal(ONBOARDING); // status
            expect(para[5]).to.be.true; // evmCompatible
        });

        it("Should activate a parachain", async function () {
            const { bridge } = await deployBridge();

            const acalaGenesis = keccak256(toBytes("acala-genesis"));
            
            await bridge.write.registerParachain([
                ACALA_PARA_ID,
                acalaGenesis,
                false,
                testSovereignAccount
            ]);

            await bridge.write.activateParachain([ACALA_PARA_ID]);

            const para = await bridge.read.getParachain([ACALA_PARA_ID]);
            expect(para[4]).to.equal(ACTIVE);
        });

        it("Should reject duplicate parachain registration", async function () {
            const { bridge } = await deployBridge();

            const genesis = keccak256(toBytes("genesis"));
            
            await bridge.write.registerParachain([
                ASTAR_PARA_ID,
                genesis,
                true,
                testSovereignAccount
            ]);

            let reverted = false;
            try {
                await bridge.write.registerParachain([
                    ASTAR_PARA_ID,
                    genesis,
                    true,
                    testSovereignAccount
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should update parachain state", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([RELAYER_ROLE, admin.account.address]);

            const genesis = keccak256(toBytes("genesis"));
            const newStateRoot = keccak256(toBytes("new-state-root"));
            
            await bridge.write.registerParachain([
                MOONBEAM_PARA_ID,
                genesis,
                true,
                testSovereignAccount
            ]);
            await bridge.write.activateParachain([MOONBEAM_PARA_ID]);

            await bridge.write.updateParachainState([
                MOONBEAM_PARA_ID,
                newStateRoot,
                100
            ]);

            const para = await bridge.read.getParachain([MOONBEAM_PARA_ID]);
            expect(para[2]).to.equal(newStateRoot); // stateRoot
            expect(para[3]).to.equal(100); // lastRelayBlock
        });

        it("Should get all parachain IDs", async function () {
            const { bridge } = await deployBridge();

            const genesis1 = keccak256(toBytes("genesis1"));
            const genesis2 = keccak256(toBytes("genesis2"));
            
            await bridge.write.registerParachain([MOONBEAM_PARA_ID, genesis1, true, testSovereignAccount]);
            await bridge.write.registerParachain([ACALA_PARA_ID, genesis2, false, testSovereignAccount]);

            const ids = await bridge.read.getParachainIds();
            expect(ids.length).to.equal(2);
        });
    });

    /*//////////////////////////////////////////////////////////////
                       ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Asset Management", function () {
        it("Should register an asset", async function () {
            const { bridge, admin } = await deployBridge();

            const interior = toHex("PalletInstance(10)/GeneralIndex(0)");
            
            await bridge.write.registerAsset([
                testAssetId,
                1, // parents
                interior,
                admin.account.address, // evmAddress
                10, // decimals
                true, // teleportable
                true  // reserveTransferable
            ]);

            const asset = await bridge.read.getAsset([testAssetId]);
            expect(asset[0]).to.equal(testAssetId); // assetId
            expect(asset[3]).to.equal(10); // decimals
            expect(asset[6]).to.be.true; // teleportable
        });

        it("Should update asset limits", async function () {
            const { bridge, admin } = await deployBridge();

            const interior = toHex("Here");
            
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                12,
                true,
                true
            ]);

            await bridge.write.updateAssetLimits([
                testAssetId,
                BigInt(1e18),
                BigInt(1e26)
            ]);

            const asset = await bridge.read.getAsset([testAssetId]);
            expect(asset[4]).to.equal(BigInt(1e18)); // minTransfer
            expect(asset[5]).to.equal(BigInt(1e26)); // maxTransfer
        });

        it("Should map EVM token to Polkadot asset", async function () {
            const { bridge, admin } = await deployBridge();

            const interior = toHex("Here");
            
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                18,
                true,
                true
            ]);

            const mappedAsset = await bridge.read.evmToPolkadotAsset([admin.account.address]);
            expect(mappedAsset).to.equal(testAssetId);
        });

        it("Should reject zero asset ID", async function () {
            const { bridge, admin } = await deployBridge();

            const zeroAssetId = padHex("0x00", { size: 32 });
            const interior = toHex("Here");

            let reverted = false;
            try {
                await bridge.write.registerAsset([
                    zeroAssetId,
                    0,
                    interior,
                    admin.account.address,
                    18,
                    true,
                    true
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN TRANSFERS
    //////////////////////////////////////////////////////////////*/

    describe("Cross-Chain Transfers", function () {
        it("Should initiate a teleport transfer", async function () {
            const { bridge, admin } = await deployBridge();

            // Register asset
            const interior = toHex("Here");
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                18,
                true,
                true
            ]);

            // Register and activate parachain
            const genesis = keccak256(toBytes("moonbeam-genesis"));
            await bridge.write.registerParachain([
                MOONBEAM_PARA_ID,
                genesis,
                true,
                testSovereignAccount
            ]);
            await bridge.write.activateParachain([MOONBEAM_PARA_ID]);

            const amount = BigInt(1e18);
            const fee = (amount * 25n) / 10000n; // 0.25% fee

            await bridge.write.initiateTransfer(
                [testAssetId, amount, testRecipient, MOONBEAM_PARA_ID, TELEPORT],
                { value: fee }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // transfersOut
            expect(stats[2]).to.equal(amount); // valueBridged
        });

        it("Should reject transfer below minimum", async function () {
            const { bridge, admin } = await deployBridge();

            const interior = toHex("Here");
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                18,
                true,
                true
            ]);

            const tooSmall = BigInt(1e10); // Below min

            let reverted = false;
            try {
                await bridge.write.initiateTransfer(
                    [testAssetId, tooSmall, testRecipient, 0, TELEPORT],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject transfer with insufficient fee", async function () {
            const { bridge, admin } = await deployBridge();

            const interior = toHex("Here");
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                18,
                true,
                true
            ]);

            const amount = BigInt(1e18);

            let reverted = false;
            try {
                await bridge.write.initiateTransfer(
                    [testAssetId, amount, testRecipient, 0, TELEPORT],
                    { value: 0n }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should get user transfers", async function () {
            const { bridge, admin } = await deployBridge();

            const interior = toHex("Here");
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                18,
                true,
                true
            ]);

            const amount = BigInt(1e18);
            const fee = (amount * 25n) / 10000n;

            await bridge.write.initiateTransfer(
                [testAssetId, amount, testRecipient, 0, TELEPORT],
                { value: fee }
            );

            const transfers = await bridge.read.getUserTransfers([admin.account.address]);
            expect(transfers.length).to.equal(1);
        });
    });

    /*//////////////////////////////////////////////////////////////
                          XCM MESSAGING
    //////////////////////////////////////////////////////////////*/

    describe("XCM Messaging", function () {
        it("Should send XCM message", async function () {
            const { bridge } = await deployBridge();

            const dest = toHex("Parachain(2004)");
            const instructions = toHex("WithdrawAsset,BuyExecution,DepositAsset");
            const weight = BigInt(1e9);

            await bridge.write.sendXCMMessage(
                [MOONBEAM_PARA_ID, dest, instructions, weight],
                { value: parseEther("0.01") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[4]).to.equal(1n); // xcmMessageCount
        });

        it("Should reject empty XCM instructions", async function () {
            const { bridge } = await deployBridge();

            const dest = toHex("Parachain(2004)");
            const emptyInstructions = "0x" as `0x${string}`;

            let reverted = false;
            try {
                await bridge.write.sendXCMMessage(
                    [MOONBEAM_PARA_ID, dest, emptyInstructions, BigInt(1e9)],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should estimate XCM weight", async function () {
            const { bridge } = await deployBridge();

            const weight = await bridge.read.estimateXCMWeight([5n, 1000n]);
            expect(weight).to.equal(5n * BigInt(1e9) + 1000n * 10000n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                      GRANDPA VERIFICATION
    //////////////////////////////////////////////////////////////*/

    describe("GRANDPA Verification", function () {
        it("Should submit GRANDPA proof", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([RELAYER_ROLE, admin.account.address]);

            const setId = keccak256(toBytes("set-1"));
            const precommits = toHex("precommit-data");
            const authorityProof = toHex("authority-proof");

            await bridge.write.submitGrandpaProof([
                testBlockHash,
                100,
                setId,
                precommits,
                authorityProof
            ]);

            const proof = await bridge.read.getGrandpaProof([testBlockHash]);
            expect(proof[0]).to.equal(testBlockHash);
            expect(proof[1]).to.equal(100);
            expect(proof[5]).to.be.false; // not verified yet
        });

        it("Should verify GRANDPA proof", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([RELAYER_ROLE, admin.account.address]);
            await bridge.write.grantRole([VALIDATOR_ROLE, admin.account.address]);

            const setId = keccak256(toBytes("set-1"));
            const precommits = toHex("precommit-data");
            const authorityProof = toHex("authority-proof");

            await bridge.write.submitGrandpaProof([
                testBlockHash,
                100,
                setId,
                precommits,
                authorityProof
            ]);

            await bridge.write.verifyGrandpaProof([testBlockHash]);

            const proof = await bridge.read.getGrandpaProof([testBlockHash]);
            expect(proof[5]).to.be.true; // verified

            const finalized = await bridge.read.isBlockFinalized([100]);
            expect(finalized).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                      BEEFY VERIFICATION
    //////////////////////////////////////////////////////////////*/

    describe("BEEFY Verification", function () {
        it("Should submit BEEFY commitment", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([BEEFY_ROLE, admin.account.address]);

            const payloadHash = keccak256(toBytes("mmr-root"));
            const nextAuthorityRoot = keccak256(toBytes("next-authority"));
            const signatures = toHex("aggregated-bls-signatures");

            await bridge.write.submitBeefyCommitment([
                payloadHash,
                200,
                1,
                nextAuthorityRoot,
                signatures
            ]);

            const commitment = await bridge.read.getBeefyCommitment([200]);
            expect(commitment[0]).to.equal(payloadHash);
            expect(commitment[1]).to.equal(200);
            expect(commitment[5]).to.be.false; // not finalized
        });

        it("Should finalize BEEFY commitment", async function () {
            const { bridge, admin } = await deployBridge();

            await bridge.write.grantRole([BEEFY_ROLE, admin.account.address]);
            await bridge.write.grantRole([VALIDATOR_ROLE, admin.account.address]);

            const payloadHash = keccak256(toBytes("mmr-root"));
            const nextAuthorityRoot = keccak256(toBytes("next-authority"));
            const signatures = toHex("aggregated-bls-signatures");

            await bridge.write.submitBeefyCommitment([
                payloadHash,
                200,
                2,
                nextAuthorityRoot,
                signatures
            ]);

            await bridge.write.finalizeBeefyCommitment([200]);

            const commitment = await bridge.read.getBeefyCommitment([200]);
            expect(commitment[5]).to.be.true; // finalized

            const setId = await bridge.read.beefyValidatorSetId();
            expect(setId).to.equal(2);
        });
    });

    /*//////////////////////////////////////////////////////////////
                      VALIDATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Validator Management", function () {
        it("Should update validator set", async function () {
            const { bridge } = await deployBridge();

            const validatorIds = [
                keccak256(toBytes("validator-1")),
                keccak256(toBytes("validator-2"))
            ];
            const beefyKeys = [
                keccak256(toBytes("beefy-1")),
                keccak256(toBytes("beefy-2"))
            ];
            const stakes = [BigInt(1e24), BigInt(2e24)];

            await bridge.write.updateValidatorSet([
                validatorIds,
                beefyKeys,
                stakes,
                5
            ]);

            const validators = await bridge.read.getActiveValidators();
            expect(validators.length).to.equal(2);

            const setId = await bridge.read.beefyValidatorSetId();
            expect(setId).to.equal(5);
        });

        it("Should get validator info", async function () {
            const { bridge } = await deployBridge();

            const validatorId = keccak256(toBytes("validator-1"));
            const beefyKey = keccak256(toBytes("beefy-1"));

            await bridge.write.updateValidatorSet([
                [validatorId],
                [beefyKey],
                [BigInt(1e24)],
                1
            ]);

            const validator = await bridge.read.getValidator([validatorId]);
            expect(validator[0]).to.equal(validatorId);
            expect(validator[1]).to.equal(beefyKey);
            expect(validator[3]).to.be.true; // active
        });
    });

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set network type", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setNetwork([KUSAMA]);

            const network = await bridge.read.network();
            expect(network).to.equal(KUSAMA);
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

        it("Should set transfer limits", async function () {
            const { bridge } = await deployBridge();

            await bridge.write.setTransferLimits([
                BigInt(1e16),
                BigInt(1e25)
            ]);

            const minTransfer = await bridge.read.minTransferAmount();
            const maxTransfer = await bridge.read.maxTransferAmount();
            expect(minTransfer).to.equal(BigInt(1e16));
            expect(maxTransfer).to.equal(BigInt(1e25));
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

            const interior = toHex("Here");
            await bridge.write.registerAsset([
                testAssetId,
                0,
                interior,
                admin.account.address,
                18,
                true,
                true
            ]);

            await bridge.write.pause();

            const amount = BigInt(1e18);
            const fee = (amount * 25n) / 10000n;

            let reverted = false;
            try {
                await bridge.write.initiateTransfer(
                    [testAssetId, amount, testRecipient, 0, TELEPORT],
                    { value: fee }
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
        it("Should compute MultiLocation hash", async function () {
            const { bridge } = await deployBridge();

            const interior = toHex("Parachain(2004)");
            const hash = await bridge.read.computeMultiLocationHash([1, interior]);

            expect(hash).to.not.equal(padHex("0x00", { size: 32 }));
        });

        it("Should encode MultiLocation", async function () {
            const { bridge } = await deployBridge();

            const interior = toHex("Here");
            const encoded = await bridge.read.encodeMultiLocation([0, interior]);

            expect(encoded.length).to.be.greaterThan(2);
        });

        it("Should convert SS58 to bytes32", async function () {
            const { bridge } = await deployBridge();

            const ss58 = toHex("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
            const hash = await bridge.read.ss58ToBytes32([ss58]);

            expect(hash).to.not.equal(padHex("0x00", { size: 32 }));
        });

        it("Should check message processed status", async function () {
            const { bridge } = await deployBridge();

            const randomId = keccak256(toBytes("random-message"));
            const isProcessed = await bridge.read.isMessageProcessed([randomId]);
            expect(isProcessed).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         BRIDGE STATISTICS
    //////////////////////////////////////////////////////////////*/

    describe("Bridge Statistics", function () {
        it("Should return correct statistics", async function () {
            const { bridge } = await deployBridge();

            const stats = await bridge.read.getBridgeStats();

            expect(stats[0]).to.equal(0n); // transfersOut
            expect(stats[1]).to.equal(0n); // transfersIn
            expect(stats[2]).to.equal(0n); // valueBridged
            expect(stats[3]).to.equal(0n); // fees
            expect(stats[4]).to.equal(0n); // messages
            expect(stats[5]).to.equal(0); // finalizedBlock
        });
    });
});
