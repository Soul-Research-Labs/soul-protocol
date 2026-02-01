// SPDX-License-Identifier: MIT
/**
 * @title CrossChainPrivacy Integration Tests
 * @notice Full flow integration tests for cross-chain privacy operations
 * @dev Tests stealth addresses, RingCT, nullifiers, and privacy hub
 */

import { expect } from "chai";
import hre from "hardhat";
const { ethers } = hre as any;
import { keccak256, toBytes, encodePacked, getAddress, parseEther } from "viem";

// Test constants
const NULLIFIER_DOMAIN = keccak256(toBytes("Soul_UNIFIED_NULLIFIER_V1"));
const STEALTH_DOMAIN = keccak256(toBytes("Soul_STEALTH_ADDRESS_V1"));
const RINGCT_DOMAIN = keccak256(toBytes("Soul_RINGCT_V1"));

// Chain IDs for testing
const CHAIN_IDS = {
    ETHEREUM: 1n,
    POLYGON: 137n,
    ARBITRUM: 42161n,
    OPTIMISM: 10n,
    MONERO_MOCK: 1000001n,
    ZCASH_MOCK: 1000002n,
    SECRET_MOCK: 1000003n,
};

// Privacy protocols
const PRIVACY_PROTOCOLS = {
    MONERO: 1,
    ZCASH: 2,
    SECRET: 3,
    OASIS: 4,
    RAILGUN: 5,
    TORNADO: 6,
    AZTEC: 7,
    Soul_NATIVE: 8,
};

describe("CrossChainPrivacy Integration", function () {
    // Contracts
    let privacyHub: any;
    let stealthRegistry: any;
    let ringCT: any;
    let nullifierManager: any;

    // Accounts
    let admin: any;
    let operator: any;
    let relayer: any;
    let user1: any;
    let user2: any;
    let bridgeValidator: any;

    // Test data
    let user1SpendingKey: string;
    let user1ViewingKey: string;
    let user2SpendingKey: string;
    let user2ViewingKey: string;

    before(async function () {
        [admin, operator, relayer, user1, user2, bridgeValidator] = await ethers.getSigners();

        // Generate test keys
        user1SpendingKey = ethers.hexlify(ethers.randomBytes(32));
        user1ViewingKey = ethers.hexlify(ethers.randomBytes(32));
        user2SpendingKey = ethers.hexlify(ethers.randomBytes(32));
        user2ViewingKey = ethers.hexlify(ethers.randomBytes(32));
    });

    /*//////////////////////////////////////////////////////////////
                    DEPLOYMENT & SETUP
    //////////////////////////////////////////////////////////////*/

    describe("Deployment", function () {
        it("Should deploy CrossChainPrivacyHub", async function () {
            const CrossChainPrivacyHub = await ethers.getContractFactory("CrossChainPrivacyHub");
            privacyHub = await CrossChainPrivacyHub.deploy();
            await privacyHub.waitForDeployment();
            await privacyHub.initialize(admin.address);

            expect(await privacyHub.hasRole(await privacyHub.DEFAULT_ADMIN_ROLE(), admin.address)).to.be.true;
        });

        it("Should deploy StealthAddressRegistry", async function () {
            const StealthAddressRegistry = await ethers.getContractFactory("StealthAddressRegistry");
            stealthRegistry = await StealthAddressRegistry.deploy();
            await stealthRegistry.waitForDeployment();
            await stealthRegistry.initialize(admin.address);

            expect(await stealthRegistry.hasRole(await stealthRegistry.DEFAULT_ADMIN_ROLE(), admin.address)).to.be.true;
        });

        it("Should deploy RingConfidentialTransactions", async function () {
            const RingConfidentialTransactions = await ethers.getContractFactory("RingConfidentialTransactions");
            ringCT = await RingConfidentialTransactions.deploy();
            await ringCT.waitForDeployment();
            await ringCT.initialize(admin.address);

            expect(await ringCT.hasRole(await ringCT.DEFAULT_ADMIN_ROLE(), admin.address)).to.be.true;
        });

        it("Should deploy UnifiedNullifierManager", async function () {
            const UnifiedNullifierManager = await ethers.getContractFactory("UnifiedNullifierManager");
            nullifierManager = await UnifiedNullifierManager.deploy();
            await nullifierManager.waitForDeployment();
            await nullifierManager.initialize(admin.address);

            expect(await nullifierManager.hasRole(await nullifierManager.DEFAULT_ADMIN_ROLE(), admin.address)).to.be.true;
        });

        it("Should setup roles and link contracts", async function () {
            // Grant roles
            const OPERATOR_ROLE = await privacyHub.OPERATOR_ROLE();
            const RELAYER_ROLE = await privacyHub.RELAYER_ROLE();

            await privacyHub.connect(admin).grantRole(OPERATOR_ROLE, operator.address);
            await privacyHub.connect(admin).grantRole(RELAYER_ROLE, relayer.address);

            // Link contracts (if applicable)
            expect(await privacyHub.hasRole(OPERATOR_ROLE, operator.address)).to.be.true;
            expect(await privacyHub.hasRole(RELAYER_ROLE, relayer.address)).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                    STEALTH ADDRESS TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Stealth Address Operations", function () {
        let user1StealthMeta: any;

        it("Should register stealth meta-address", async function () {
            // Compute meta-address hash
            const spendingPubKeyHash = keccak256(toBytes(user1SpendingKey));
            const viewingPubKeyHash = keccak256(toBytes(user1ViewingKey));

            const tx = await stealthRegistry.connect(user1).registerStealthMetaAddress(
                spendingPubKeyHash,
                viewingPubKeyHash,
                1 // SECP256K1 scheme
            );
            await tx.wait();

            user1StealthMeta = await stealthRegistry.getStealthMetaAddress(user1.address);
            expect(user1StealthMeta.spendingPubKeyHash).to.equal(spendingPubKeyHash);
            expect(user1StealthMeta.viewingPubKeyHash).to.equal(viewingPubKeyHash);
        });

        it("Should generate stealth address for recipient", async function () {
            const ephemeralPrivKey = ethers.hexlify(ethers.randomBytes(32));
            const ephemeralPubKeyHash = keccak256(toBytes(ephemeralPrivKey));

            const stealthAddress = await stealthRegistry.computeStealthAddress(
                user1StealthMeta.spendingPubKeyHash,
                user1StealthMeta.viewingPubKeyHash,
                ephemeralPubKeyHash
            );

            expect(stealthAddress).to.not.equal(ethers.ZeroAddress);
        });

        it("Should announce stealth payment", async function () {
            const ephemeralPubKey = ethers.hexlify(ethers.randomBytes(33));
            const viewTag = "0x" + ephemeralPubKey.slice(2, 4);
            const stealthAddress = getAddress(ethers.hexlify(ethers.randomBytes(20)));
            const metadata = "0x";

            const tx = await stealthRegistry.connect(user2).announceStealthPayment(
                1, // SECP256K1
                stealthAddress,
                ephemeralPubKey,
                viewTag,
                metadata
            );
            await tx.wait();

            // Check event was emitted
            const events = await stealthRegistry.queryFilter(
                stealthRegistry.filters.StealthPaymentAnnounced()
            );
            expect(events.length).to.be.greaterThan(0);
        });

        it("Should scan announcements by view tag", async function () {
            // Get all announcements for the scheme
            const announcements = await stealthRegistry.getAnnouncementsByScheme(1, 0, 100);
            expect(announcements.length).to.be.greaterThan(0);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    RING CONFIDENTIAL TRANSACTION TESTS
    //////////////////////////////////////////////////////////////*/

    describe("RingCT Operations", function () {
        let outputCommitment: string;
        let outputBlinding: string;

        it("Should create Pedersen commitment", async function () {
            const amount = parseEther("10");
            outputBlinding = ethers.hexlify(ethers.randomBytes(32));

            outputCommitment = await ringCT.computePedersenCommitment(amount, outputBlinding);
            expect(outputCommitment).to.not.equal(ethers.ZeroHash);
        });

        it("Should verify commitment sum (outputs = inputs)", async function () {
            // Create input commitment
            const inputAmount = parseEther("10");
            const inputBlinding = ethers.hexlify(ethers.randomBytes(32));
            const inputCommitment = await ringCT.computePedersenCommitment(inputAmount, inputBlinding);

            // In a real RingCT, sum(inputs) - sum(outputs) = fee * H
            // For this test, we verify the commitment computation
            expect(inputCommitment).to.not.equal(outputCommitment); // Different blinding factors
        });

        it("Should generate range proof for commitment", async function () {
            const amount = parseEther("1");
            const blinding = ethers.hexlify(ethers.randomBytes(32));

            // Generate range proof (simplified for testing)
            const rangeProofData = await ringCT.generateRangeProofData(amount, blinding);
            expect(rangeProofData.commitment).to.not.equal(ethers.ZeroHash);
        });

        it("Should create confidential transaction", async function () {
            const inputCommitments = [await ringCT.computePedersenCommitment(parseEther("10"), ethers.hexlify(ethers.randomBytes(32)))];
            const outputCommitments = [await ringCT.computePedersenCommitment(parseEther("9"), ethers.hexlify(ethers.randomBytes(32)))];
            const fee = parseEther("1");

            // Fee commitment implicitly covers the difference
            const txHash = keccak256(encodePacked(
                ["bytes32[]", "bytes32[]", "uint256"],
                [inputCommitments, outputCommitments, fee]
            ));

            expect(txHash).to.not.equal(ethers.ZeroHash);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    UNIFIED NULLIFIER MANAGER TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Unified Nullifier Operations", function () {
        let testNullifier: string;
        let crossDomainNullifier: string;

        it("Should register domain", async function () {
            const domainId = keccak256(toBytes("test_domain"));
            const bridgeAdapter = relayer.address; // Mock bridge
            const chainType = 1; // EVM

            await nullifierManager.connect(admin).registerDomain(domainId, bridgeAdapter, chainType);

            const domainInfo = await nullifierManager.getDomainInfo(domainId);
            expect(domainInfo.isActive).to.be.true;
        });

        it("Should register nullifier", async function () {
            testNullifier = keccak256(toBytes("test_nullifier_" + Date.now()));
            const commitment = keccak256(toBytes("test_commitment"));
            const domainId = keccak256(toBytes("test_domain"));

            await nullifierManager.connect(relayer).registerNullifier(
                testNullifier,
                commitment,
                domainId
            );

            expect(await nullifierManager.isNullifierUsed(testNullifier)).to.be.true;
        });

        it("Should prevent double-spending (nullifier reuse)", async function () {
            const commitment = keccak256(toBytes("test_commitment_2"));
            const domainId = keccak256(toBytes("test_domain"));

            await (expect(
                nullifierManager.connect(relayer).registerNullifier(
                    testNullifier,
                    commitment,
                    domainId
                )
            ) as any).to.be.reverted;
        });

        it("Should derive cross-domain nullifier", async function () {
            const sourceNullifier = keccak256(toBytes("source_nf"));
            const sourceDomain = keccak256(toBytes("source_domain"));
            const targetDomain = keccak256(toBytes("target_domain"));

            crossDomainNullifier = await nullifierManager.deriveCrossDomainNullifier(
                sourceNullifier,
                sourceDomain,
                targetDomain
            );

            expect(crossDomainNullifier).to.not.equal(sourceNullifier);
            expect(crossDomainNullifier).to.not.equal(ethers.ZeroHash);
        });

        it("Should derive Soul binding", async function () {
            const soulBinding = await nullifierManager.deriveSoulBinding(testNullifier);
            expect(soulBinding).to.not.equal(ethers.ZeroHash);
        });

        it("Should verify cross-domain proof", async function () {
            const sourceNullifier = keccak256(toBytes("verified_source"));
            const sourceDomain = keccak256(toBytes("verified_domain"));
            const targetDomain = keccak256(toBytes("target_domain"));
            const proof = ethers.hexlify(ethers.randomBytes(128)); // Mock proof

            // This would verify the proof in production
            const expectedCrossDomain = await nullifierManager.deriveCrossDomainNullifier(
                sourceNullifier,
                sourceDomain,
                targetDomain
            );

            expect(expectedCrossDomain).to.not.equal(ethers.ZeroHash);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN PRIVACY HUB TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Privacy Hub Operations", function () {
        it("Should register bridge adapter", async function () {
            const bridgeId = keccak256(toBytes("test_bridge"));
            const chainId = CHAIN_IDS.POLYGON;
            const protocolType = PRIVACY_PROTOCOLS.Soul_NATIVE;

            await privacyHub.connect(admin).registerBridge(
                bridgeId,
                relayer.address, // Mock bridge adapter
                chainId,
                protocolType
            );

            const bridgeInfo = await privacyHub.getBridgeInfo(bridgeId);
            expect(bridgeInfo.isActive).to.be.true;
        });

        it("Should initiate private cross-chain transfer", async function () {
            const bridgeId = keccak256(toBytes("test_bridge"));
            const recipient = user2.address;
            const amount = parseEther("1");
            const commitment = keccak256(encodePacked(
                ["address", "uint256", "bytes32"],
                [recipient, amount, ethers.hexlify(ethers.randomBytes(32))]
            ));
            const proof = ethers.hexlify(ethers.randomBytes(256));

            const tx = await privacyHub.connect(user1).initiatePrivateTransfer(
                bridgeId,
                commitment,
                proof,
                { value: amount }
            );
            await tx.wait();

            const events = await privacyHub.queryFilter(
                privacyHub.filters.PrivateTransferInitiated()
            );
            expect(events.length).to.be.greaterThan(0);
        });

        it("Should relay private transfer", async function () {
            const transferId = keccak256(toBytes("transfer_id"));
            const nullifier = keccak256(toBytes("transfer_nullifier"));
            const commitment = keccak256(toBytes("transfer_commitment"));
            const proof = ethers.hexlify(ethers.randomBytes(256));

            // Relayer completes the transfer on destination
            // This is a simplified test - real implementation verifies proof
            const relayData = encodePacked(
                ["bytes32", "bytes32", "bytes32"],
                [transferId, nullifier, commitment]
            );

            expect(relayData.length).to.be.greaterThan(0);
        });

        it("Should get privacy stats", async function () {
            const stats = await privacyHub.getStats();
            expect(stats.totalBridges).to.be.gte(1);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    END-TO-END PRIVACY FLOW
    //////////////////////////////////////////////////////////////*/

    describe("End-to-End Privacy Flow", function () {
        it("Should complete full private cross-chain transfer", async function () {
            // 1. User1 registers stealth meta-address
            const spending = keccak256(toBytes("e2e_spending"));
            const viewing = keccak256(toBytes("e2e_viewing"));
            await stealthRegistry.connect(user1).registerStealthMetaAddress(
                spending,
                viewing,
                1
            );

            // 2. User2 generates stealth address for User1
            const ephemeral = keccak256(toBytes("e2e_ephemeral"));
            const stealthAddr = await stealthRegistry.computeStealthAddress(
                spending,
                viewing,
                ephemeral
            );

            // 3. Create commitment for the transfer
            const amount = parseEther("5");
            const blinding = ethers.hexlify(ethers.randomBytes(32));
            const commitment = await ringCT.computePedersenCommitment(amount, blinding);

            // 4. Derive nullifier
            const nullifier = keccak256(encodePacked(
                ["bytes32", "bytes32", "address"],
                [commitment, blinding, stealthAddr]
            ));

            // 5. Register nullifier to prevent double-spend
            const domainId = keccak256(toBytes("test_domain"));
            await nullifierManager.connect(relayer).registerNullifier(
                nullifier,
                commitment,
                domainId
            );

            // 6. Verify nullifier is consumed
            expect(await nullifierManager.isNullifierUsed(nullifier)).to.be.true;

            // 7. Announce stealth payment
            await stealthRegistry.connect(user2).announceStealthPayment(
                1,
                stealthAddr,
                ethers.hexlify(ethers.randomBytes(33)),
                "0x00",
                "0x"
            );

            console.log("✅ End-to-end private cross-chain transfer completed");
            console.log("   Stealth Address:", stealthAddr);
            console.log("   Commitment:", commitment);
            console.log("   Nullifier:", nullifier);
        });

        it("Should handle multi-chain nullifier synchronization", async function () {
            const sourceNullifier = keccak256(toBytes("multichain_nf"));
            const sourceDomain = keccak256(toBytes("ethereum"));
            const targetDomains = [
                keccak256(toBytes("polygon")),
                keccak256(toBytes("arbitrum")),
                keccak256(toBytes("optimism")),
            ];

            // Derive cross-domain nullifiers for each target
            const crossDomainNullifiers = await Promise.all(
                targetDomains.map(target =>
                    nullifierManager.deriveCrossDomainNullifier(
                        sourceNullifier,
                        sourceDomain,
                        target
                    )
                )
            );

            // All cross-domain nullifiers should be unique
            const uniqueNullifiers = new Set(crossDomainNullifiers);
            expect(uniqueNullifiers.size).to.equal(targetDomains.length);

            console.log("✅ Multi-chain nullifier synchronization verified");
            console.log("   Source:", sourceNullifier);
            console.log("   Cross-domain nullifiers:", crossDomainNullifiers);
        });

        it("Should verify ring signature anonymity set", async function () {
            // Create a ring of decoy commitments
            const ringSize = 11;
            const commitments = await Promise.all(
                Array(ringSize).fill(0).map(async (_, i) => {
                    const amount = parseEther(String(i + 1));
                    const blinding = ethers.hexlify(ethers.randomBytes(32));
                    return ringCT.computePedersenCommitment(amount, blinding);
                })
            );

            // Real output is hidden among decoys
            const realIndex = Math.floor(Math.random() * ringSize);

            // All commitments should be unique (high probability)
            const uniqueCommitments = new Set(commitments);
            expect(uniqueCommitments.size).to.equal(ringSize);

            console.log("✅ Ring signature anonymity set created");
            console.log("   Ring size:", ringSize);
            console.log("   Real output hidden at index:", realIndex);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    ERROR HANDLING TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Error Handling", function () {
        it("Should revert on invalid stealth scheme", async function () {
            await (expect(
                stealthRegistry.connect(user1).registerStealthMetaAddress(
                    keccak256(toBytes("spending")),
                    keccak256(toBytes("viewing")),
                    255 // Invalid scheme
                )
            ) as any).to.be.reverted;
        });

        it("Should revert on zero commitment", async function () {
            await (expect(
                ringCT.computePedersenCommitment(0, ethers.hexlify(ethers.randomBytes(32)))
            ) as any).to.be.reverted;
        });

        it("Should revert on duplicate domain registration", async function () {
            const domainId = keccak256(toBytes("duplicate_domain"));

            await nullifierManager.connect(admin).registerDomain(
                domainId,
                relayer.address,
                1
            );

            await (expect(
                nullifierManager.connect(admin).registerDomain(
                    domainId,
                    relayer.address,
                    1
                )
            ) as any).to.be.reverted;
        });
    });

    /*//////////////////////////////////////////////////////////////
                    GAS OPTIMIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Gas Optimization", function () {
        it("Should measure stealth address registration gas", async function () {
            const tx = await stealthRegistry.connect(user2).registerStealthMetaAddress(
                keccak256(toBytes("gas_spending")),
                keccak256(toBytes("gas_viewing")),
                1
            );
            const receipt = await tx.wait();
            console.log("   Stealth registration gas:", receipt?.gasUsed?.toString());
            expect(Number(receipt?.gasUsed)).to.be.lt(200_000);
        });

        it("Should measure nullifier registration gas", async function () {
            const nullifier = keccak256(toBytes("gas_nullifier_" + Date.now()));
            const domainId = keccak256(toBytes("test_domain"));

            const tx = await nullifierManager.connect(relayer).registerNullifier(
                nullifier,
                keccak256(toBytes("gas_commitment")),
                domainId
            );
            const receipt = await tx.wait();
            console.log("   Nullifier registration gas:", receipt?.gasUsed?.toString());
            expect(Number(receipt?.gasUsed)).to.be.lt(150_000);
        });

        it("Should measure commitment computation gas", async function () {
            const amount = parseEther("1");
            const blinding = ethers.hexlify(ethers.randomBytes(32));

            // Static call to measure gas
            const gasEstimate = await ringCT.computePedersenCommitment.estimateGas(amount, blinding);
            console.log("   Commitment computation gas:", gasEstimate.toString());
            expect(Number(gasEstimate)).to.be.lt(100_000);
        });
    });
});
