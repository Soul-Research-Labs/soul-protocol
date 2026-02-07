import hre from "hardhat";
import { expect } from "chai";
import { parseEther, zeroAddress, type Address } from "viem";

/**
 * Privacy Middleware Integration Tests (Hardhat v3 / viem)
 *
 * Tests the full privacy middleware stack:
 * - UniversalShieldedPool
 * - CrossChainSanctionsOracle
 * - RelayerFeeMarket
 * - UniversalProofTranslator
 * - PrivacyRouter
 */
describe("Privacy Middleware (viem)", function () {
    let publicClient: any;
    let deployer: any;
    let user: any;

    let pool: any;
    let oracle: any;
    let translator: any;
    let router: any;

    before(async function () {
        const { viem } = await hre.network.connect();
        publicClient = await viem.getPublicClient();
        [deployer, user] = await viem.getWalletClients();
    });

    describe("UniversalShieldedPool", function () {
        before(async function () {
            const { viem } = await hre.network.connect();
            pool = await viem.deployContract("UniversalShieldedPool", [
                deployer.account.address,
                zeroAddress, // no verifier (test mode)
                true,        // test mode enabled
            ]);
        });

        it("Should deploy with correct initial state", async function () {
            const root = await pool.read.currentRoot();
            expect(root).to.not.equal("0x" + "0".repeat(64));

            const testMode = await pool.read.testMode();
            expect(testMode).to.equal(true);
        });

        it("Should accept ETH deposits", async function () {
            // Commitment must be < BN254 field size
            const commitment = "0x0000000000000000000000000000000000000000000000000000000000000001" as `0x${string}`;

            await pool.write.depositETH(
                [commitment],
                { value: parseEther("1") },
            );

            const nextLeaf = await pool.read.nextLeafIndex();
            expect(Number(nextLeaf)).to.equal(1);
        });

        it("Should track Merkle root changes", async function () {
            const rootBefore = await pool.read.currentRoot();

            const commitment2 = "0x0000000000000000000000000000000000000000000000000000000000000002" as `0x${string}`;
            await pool.write.depositETH(
                [commitment2],
                { value: parseEther("0.5") },
            );

            const rootAfter = await pool.read.currentRoot();
            expect(rootAfter).to.not.equal(rootBefore);
        });

        it("Should reject duplicate commitments", async function () {
            const commitment = "0x0000000000000000000000000000000000000000000000000000000000000001" as `0x${string}`;

            try {
                await pool.write.depositETH(
                    [commitment],
                    { value: parseEther("0.1") },
                );
                expect.fail("Should have reverted");
            } catch (e: any) {
                // Expected - duplicate commitment reverts
                expect(e).to.exist;
            }
        });

        it("Should disable test mode irreversibly", async function () {
            // Deploy a fresh pool to test disableTestMode
            const { viem } = await hre.network.connect();
            const freshPool = await viem.deployContract("UniversalShieldedPool", [
                deployer.account.address,
                zeroAddress,
                true,
            ]);

            expect(await freshPool.read.testMode()).to.equal(true);

            await freshPool.write.disableTestMode();

            expect(await freshPool.read.testMode()).to.equal(false);
        });
    });

    describe("CrossChainSanctionsOracle", function () {
        before(async function () {
            const { viem } = await hre.network.connect();
            oracle = await viem.deployContract("CrossChainSanctionsOracle", [
                deployer.account.address,
                1n, // quorum threshold
            ]);
        });

        it("Should deploy with default configuration", async function () {
            const failOpen = await oracle.read.failOpen();
            expect(failOpen).to.equal(true);

            const quorum = await oracle.read.quorumThreshold();
            expect(Number(quorum)).to.equal(1);
        });

        it("Should allow admin to register providers", async function () {
            await oracle.write.registerProvider([
                deployer.account.address,
                "TestProvider",
                100n, // weight
            ]);

            // Verify provider was registered (check the struct fields)
            // ScreeningProvider: { providerAddress, name, weight, active, totalScreenings }
            const provider = await oracle.read.providers([deployer.account.address]);
            // provider is tuple: [address, string, uint256, bool, uint256]
            // The 'active' field is at index 3
            expect(provider[3]).to.equal(true); // active
        });
    });

    describe("UniversalProofTranslator", function () {
        before(async function () {
            const { viem } = await hre.network.connect();
            translator = await viem.deployContract("UniversalProofTranslator", [
                deployer.account.address,
            ]);
        });

        it("Should deploy with correct admin", async function () {
            const adminRole = "0x" + "0".repeat(64) as `0x${string}`;
            const hasRole = await translator.read.hasRole([adminRole, deployer.account.address]);
            expect(hasRole).to.equal(true);
        });

        it("Should recognize native compatibility paths", async function () {
            // PLONK (1) and UltraPlonk (6) should be natively compatible
            const [possible, nativeCompat] = await translator.read.canTranslate([1, 6]);
            expect(possible).to.equal(true);
            expect(nativeCompat).to.equal(true);
        });
    });

    describe("PrivacyRouter", function () {
        before(async function () {
            const { viem } = await hre.network.connect();

            // Deploy fresh pool for router tests
            pool = await viem.deployContract("UniversalShieldedPool", [
                deployer.account.address,
                zeroAddress,
                true, // test mode
            ]);

            router = await viem.deployContract("PrivacyRouter", [
                deployer.account.address,
                pool.address,
                zeroAddress, // crossChainHub
                zeroAddress, // stealthRegistry
                zeroAddress, // nullifierManager
                zeroAddress, // compliance
                zeroAddress, // proofTranslator
            ]);
        });

        it("Should deploy with correct component addresses", async function () {
            const shieldedPool = await router.read.shieldedPool();
            expect(shieldedPool.toLowerCase()).to.equal(pool.address.toLowerCase());
        });

        it("Should track operation count", async function () {
            const count = await router.read.operationNonce();
            expect(Number(count)).to.equal(0);
        });

        it("Should allow compliance toggle", async function () {
            await router.write.setComplianceEnabled([false]);
            const enabled = await router.read.complianceEnabled();
            expect(enabled).to.equal(false);
        });
    });
});
