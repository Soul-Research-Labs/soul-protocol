import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes } from "viem";

describe("EthereumL1Bridge Gas Audit", function () {
    const CHAIN_ID = 10n; // Optimism
    const TEST_STATE_ROOT = keccak256(toBytes("state"));
    const TEST_PROOF_ROOT = keccak256(toBytes("proof"));
    const MOCK_BLOB_HASH = keccak256(toBytes("blob"));
    
    async function getViem() {
        // @ts-expect-error - Hardhat 3 viem integration
        const { viem } = await hre.network.connect();
        return viem;
    }

    async function deployBridge() {
        const viem = await getViem();
        const [owner, relayer] = await viem.getWalletClients();
        const publicClient = await viem.getPublicClient();

        const bridge = await viem.deployContract("MockEthereumL1Bridge");
        
        const RELAYER_ROLE = await bridge.read.RELAYER_ROLE();
        await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
        
        await bridge.write.setMockBlobHash([MOCK_BLOB_HASH]);
        
        return { bridge, owner, relayer, publicClient };
    }

    it("Gas: Submit State Commitment (Legacy)", async function () {
        const { bridge, relayer, publicClient } = await deployBridge();

        const hash = await bridge.write.submitStateCommitment([
            CHAIN_ID,
            TEST_STATE_ROOT,
            TEST_PROOF_ROOT,
            100n // blockNumber
        ], { 
            account: relayer.account,
            value: parseEther("0.1") 
        });
        
        const receipt = await publicClient.waitForTransactionReceipt({ hash });
        console.log("Legacy Submission Gas Used:", receipt.gasUsed.toString());
    });

    it("Gas: Submit State Commitment (Blob)", async function () {
        const { bridge, relayer, publicClient } = await deployBridge();

        const hash = await bridge.write.submitStateCommitmentWithBlob([
            CHAIN_ID,
            TEST_STATE_ROOT,
            TEST_PROOF_ROOT,
            101n, // blockNumber
            0n    // blobIndex
        ], {
            account: relayer.account,
            value: parseEther("0.1")
        });
        
        const receipt = await publicClient.waitForTransactionReceipt({ hash });
        console.log("Blob Submission Gas Used:  ", receipt.gasUsed.toString());
    });
});
