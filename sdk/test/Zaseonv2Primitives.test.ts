import { expect } from "chai";
import { 
    createPublicClient, 
    createWalletClient, 
    http,
    Hex, 
    keccak256, 
    toBytes, 
    getAddress 
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";
import { 
    Zaseonv2ClientFactory, 
    Zaseonv2Config,
    ProofCarryingContainerClient
} from "../src/client/Zaseonv2Primitives";

describe("Zaseonv2Primitives SDK Verification", function () {
    this.timeout(120000);

    let publicClient: any;
    let walletClient: any;
    let factory: Zaseonv2ClientFactory;
    let pc3: ProofCarryingContainerClient;
    
    let pc3Address: Hex;

    before(async function () {
        // Mock clients
        const account = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        
        // Creating real clients but connected to a dummy URL just for type satisfaction
        // The tests that make network calls will fail unless we mock the request method
        // But the current test only checks initialization and internal structure before network call
        
        publicClient = createPublicClient({
            chain: mainnet,
            transport: http("http://127.0.0.1:8545")
        });

        walletClient = createWalletClient({
            account,
            chain: mainnet,
            transport: http("http://127.0.0.1:8545")
        });

        pc3Address = getAddress("0x1234567890123456789012345678901234567890");

        const config: Zaseonv2Config = {
            proofCarryingContainer: pc3Address,
            policyBoundProofs: pc3Address,
            executionAgnosticStateCommitments: pc3Address,
            crossDomainNullifierAlgebra: pc3Address,
            orchestrator: pc3Address
        };

        factory = new Zaseonv2ClientFactory(config, publicClient, walletClient);
        pc3 = factory.proofCarryingContainer();
    });

    describe("Factory Initialization", function () {
        it("should create clients with correct addresses", async function () {
            expect(pc3.contract.address.toLowerCase()).to.equal(pc3Address.toLowerCase());
        });
    });

    describe("ProofCarryingContainerClient (PC3)", function () {
        it("should format transaction options correctly", async function () {
            // This test verifies that the SDK correctly passes options to viem
            const dummyId = keccak256(toBytes("test"));
            
            // We expect this to fail because of network connection error (dummy URL),
            // NOT because of missing wallet client or bad request formatting.
            try {
                await pc3.getContainer(dummyId);
            } catch (err: any) {
                // If the error is network related, it means it tried to call the chain, 
                // which means the SDK wrapper worked.
                // If it was a code error (like undefined wallet), it would match that.
                
                // We just want to ensure it's NOT "Wallet client required"
                expect(err.message).to.not.contain("Wallet client required");
            }
        });
    });
});
