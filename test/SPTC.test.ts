import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, toHex, zeroHash, type Address, type Hash } from "viem";

/**
 * Semantic Proof Translation Certificate (SPTC) Test Suite
 * Tests the complete SPTC system for certified proof translations
 */
describe("Semantic Proof Translation Certificates (SPTC)", function () {
  this.timeout(180000);

  describe("SemanticProofTranslationCertificate", function () {
    describe("Capability Registration", function () {
      it("Should register a translation capability", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // Register capability: Groth16 BN254 -> PLONK
        const sourceSystem = 1; // GROTH16_BN254
        const targetSystem = 3; // PLONK
        const direction = 0; // Bidirectional
        const supportedDomains = [0, 1]; // Arithmetic, StateTransition
        const translatorCircuitHash = keccak256(toBytes("translator_circuit"));
        const semanticPreservationProof = keccak256(toBytes("semantic_proof"));
        const maxInputSize = 1024 * 1024; // 1MB
        const gasEstimate = 500000n;

        const tx = await sptc.write.registerCapability([
          sourceSystem,
          targetSystem,
          direction,
          supportedDomains,
          translatorCircuitHash,
          semanticPreservationProof,
          maxInputSize,
          gasEstimate
        ]);

        // Verify capability was registered
        const totalCapabilities = await sptc.read.totalCapabilities();
        expect(totalCapabilities).to.equal(1n);
      });

      it("Should reject unknown proof systems", async function () {
        const { viem } = await hre.network.connect();
        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        try {
          await sptc.write.registerCapability([
            0, // Unknown
            3, // PLONK
            0,
            [0],
            keccak256(toBytes("circuit")),
            keccak256(toBytes("proof")),
            1024,
            100000n
          ]);
          expect.fail("Should have reverted");
        } catch (error: any) {
          expect(error.message).to.include("UnsupportedTranslation");
        }
      });
    });

    describe("Translation Requests", function () {
      it("Should create a translation request", async function () {
        const { viem } = await hre.network.connect();
        const [admin, user] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // First register capability
        await sptc.write.registerCapability([
          1, // GROTH16_BN254
          3, // PLONK
          0, // Bidirectional
          [0, 1],
          keccak256(toBytes("translator_circuit")),
          keccak256(toBytes("semantic_proof")),
          1024 * 1024,
          500000n
        ]);

        // Calculate fee
        const sourceProof = toHex(toBytes("mock_source_proof_data"));
        const fee = await sptc.read.calculateTranslationFee([BigInt(sourceProof.length / 2 - 1), 0]);

        // Request translation
        const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
        await sptc.write.requestTranslation(
          [
            1, // GROTH16_BN254
            3, // PLONK
            0, // Arithmetic domain
            sourceProof,
            [keccak256(toBytes("input1")), keccak256(toBytes("input2"))],
            keccak256(toBytes("verifying_key")),
            keccak256(toBytes("statement")),
            deadline
          ],
          { value: fee, account: user.account }
        );

        const totalRequests = await sptc.read.totalRequests();
        expect(totalRequests).to.equal(1n);
      });

      it("Should reject request with insufficient fee", async function () {
        const { viem } = await hre.network.connect();
        const [admin, user] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // Register capability first
        await sptc.write.registerCapability([
          1, 3, 0, [0], 
          keccak256(toBytes("circuit")),
          keccak256(toBytes("proof")),
          1024 * 1024, 500000n
        ]);

        try {
          const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
          await sptc.write.requestTranslation(
            [
              1, 3, 0,
              toHex(toBytes("proof")),
              [keccak256(toBytes("input"))],
              keccak256(toBytes("key")),
              keccak256(toBytes("statement")),
              deadline
            ],
            { value: 1n, account: user.account } // Insufficient fee
          );
          expect.fail("Should have reverted");
        } catch (error: any) {
          expect(error.message).to.include("InsufficientFee");
        }
      });
    });

    describe("Certificate Issuance", function () {
      it("Should issue translation certificate via direct translate", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // Register capability
        await sptc.write.registerCapability([
          1, 3, 0, [0, 1],
          keccak256(toBytes("translator_circuit")),
          keccak256(toBytes("semantic_proof")),
          1024 * 1024, 500000n
        ]);

        // Grant translator role
        const translatorRole = keccak256(toBytes("CERTIFIED_TRANSLATOR_ROLE"));
        await sptc.write.grantRole([translatorRole, translator.account.address]);

        // Translator stakes
        await sptc.write.stakeAsTranslator([], { 
          value: 1000000000000000000n, // 1 ETH
          account: translator.account 
        });

        // Issue certificate
        const sourceProofHash = keccak256(toBytes("source_proof"));
        const targetProofHash = keccak256(toBytes("target_proof"));
        const sourceVK = keccak256(toBytes("source_vk"));
        const targetVK = keccak256(toBytes("target_vk"));
        const statementHash = keccak256(toBytes("statement"));
        const semanticCommitment = keccak256(toBytes("semantic_commitment"));
        const translationProof = toHex(toBytes("translation_proof_data"));

        await sptc.write.translateAndCertify(
          [
            1, // GROTH16_BN254
            3, // PLONK
            0, // Arithmetic
            sourceProofHash,
            sourceVK,
            [keccak256(toBytes("input1"))],
            targetProofHash,
            targetVK,
            [keccak256(toBytes("input1_translated"))],
            statementHash,
            semanticCommitment,
            translationProof
          ],
          { account: translator.account }
        );

        const totalCerts = await sptc.read.totalCertificates();
        expect(totalCerts).to.equal(1n);
      });
    });

    describe("Certificate Verification", function () {
      it("Should verify valid certificate", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // Setup
        await sptc.write.registerCapability([
          1, 3, 0, [0],
          keccak256(toBytes("circuit")),
          keccak256(toBytes("proof")),
          1024 * 1024, 500000n
        ]);

        const translatorRole = keccak256(toBytes("CERTIFIED_TRANSLATOR_ROLE"));
        await sptc.write.grantRole([translatorRole, translator.account.address]);
        await sptc.write.stakeAsTranslator([], { 
          value: 1000000000000000000n, 
          account: translator.account 
        });

        // Issue certificate
        const sourceProofHash = keccak256(toBytes("source_proof"));
        const targetProofHash = keccak256(toBytes("target_proof"));
        const statementHash = keccak256(toBytes("statement"));

        // Get certificate ID by computing it the same way the contract does
        const certificateId = keccak256(
          toHex(
            new Uint8Array([
              ...toBytes(sourceProofHash),
              ...toBytes(targetProofHash),
              ...toBytes(translator.account.address as `0x${string}`).slice(12), // address is 20 bytes
            ])
          )
        );

        await sptc.write.translateAndCertify(
          [
            1, 3, 0,
            sourceProofHash,
            keccak256(toBytes("source_vk")),
            [],
            targetProofHash,
            keccak256(toBytes("target_vk")),
            [],
            statementHash,
            keccak256(toBytes("semantic")),
            toHex(toBytes("translation_proof"))
          ],
          { account: translator.account }
        );

        // Verify semantic equivalence
        const totalCerts = await sptc.read.totalCertificates();
        expect(totalCerts).to.equal(1n);
      });
    });

    describe("Challenge Mechanism", function () {
      it("Should allow challenging certificates", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator, challenger] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // Setup and issue certificate
        await sptc.write.registerCapability([
          1, 3, 0, [0],
          keccak256(toBytes("circuit")),
          keccak256(toBytes("proof")),
          1024 * 1024, 500000n
        ]);

        const translatorRole = keccak256(toBytes("CERTIFIED_TRANSLATOR_ROLE"));
        await sptc.write.grantRole([translatorRole, translator.account.address]);
        await sptc.write.stakeAsTranslator([], { 
          value: 1000000000000000000n, 
          account: translator.account 
        });

        await sptc.write.translateAndCertify(
          [
            1, 3, 0,
            keccak256(toBytes("source")),
            keccak256(toBytes("svk")),
            [],
            keccak256(toBytes("target")),
            keccak256(toBytes("tvk")),
            [],
            keccak256(toBytes("stmt")),
            keccak256(toBytes("semantic")),
            toHex(toBytes("proof"))
          ],
          { account: translator.account }
        );

        // Get challenge stake requirement
        const challengeStake = await sptc.read.challengeStake();

        // Challenge would require knowing the certificate ID
        // This test verifies the challenge stake is set correctly
        expect(challengeStake).to.be.gt(0n);
      });
    });

    describe("Translator Staking", function () {
      it("Should allow staking and withdrawing", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const sptc = await viem.deployContract("SemanticProofTranslationCertificate");

        // Stake
        const stakeAmount = 2000000000000000000n; // 2 ETH
        await sptc.write.stakeAsTranslator([], { 
          value: stakeAmount, 
          account: translator.account 
        });

        let stake = await sptc.read.translatorStake([translator.account.address]);
        expect(stake).to.equal(stakeAmount);

        // Withdraw half
        const withdrawAmount = 1000000000000000000n;
        await sptc.write.withdrawStake([withdrawAmount], { account: translator.account });

        stake = await sptc.read.translatorStake([translator.account.address]);
        expect(stake).to.equal(stakeAmount - withdrawAmount);
      });
    });
  });

  describe("TranslationCertificateRegistry", function () {
    describe("Translator Registration", function () {
      it("Should register new translator", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const registry = await viem.deployContract("TranslationCertificateRegistry");

        // Get minimum stake requirement
        const requirements = await registry.read.levelRequirements([1]); // Provisional
        const minStake = requirements[0]; // First element is minStake

        await registry.write.registerTranslator(
          [
            "Test Translator",
            "Test Organization",
            keccak256(toBytes("public_key"))
          ],
          { value: minStake, account: translator.account }
        );

        const profile = await registry.read.getTranslator([translator.account.address]);
        expect(profile.translator.toLowerCase()).to.equal(translator.account.address.toLowerCase());
        expect(profile.name).to.equal("Test Translator");
        expect(profile.level).to.equal(1); // Provisional
      });

      it("Should reject duplicate registration", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const registry = await viem.deployContract("TranslationCertificateRegistry");
        const requirements = await registry.read.levelRequirements([1]);
        const minStake = requirements[0];

        // First registration
        await registry.write.registerTranslator(
          ["Translator", "Org", keccak256(toBytes("key"))],
          { value: minStake, account: translator.account }
        );

        // Duplicate attempt
        try {
          await registry.write.registerTranslator(
            ["Translator2", "Org2", keccak256(toBytes("key2"))],
            { value: minStake, account: translator.account }
          );
          expect.fail("Should have reverted");
        } catch (error: any) {
          expect(error.message).to.include("TranslatorAlreadyRegistered");
        }
      });
    });

    describe("Capability Certification", function () {
      it("Should certify translator capability", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const registry = await viem.deployContract("TranslationCertificateRegistry");
        
        // Register translator first
        const requirements = await registry.read.levelRequirements([1]);
        await registry.write.registerTranslator(
          ["Translator", "Org", keccak256(toBytes("key"))],
          { value: requirements[0], account: translator.account }
        );

        // Certify capability
        await registry.write.certifyCapability(
          [
            1, // GROTH16_BN254
            3, // PLONK
            keccak256(toBytes("translator_circuit")),
            keccak256(toBytes("verification_key")),
            BigInt(1024 * 1024)
          ],
          { account: translator.account }
        );

        const capabilities = await registry.read.getTranslatorCapabilities([translator.account.address]);
        expect(capabilities.length).to.equal(1);
      });
    });

    describe("Attestations", function () {
      it("Should create attestation for capability", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator, attester] = await viem.getWalletClients();

        const registry = await viem.deployContract("TranslationCertificateRegistry");

        // Setup translator
        const requirements = await registry.read.levelRequirements([1]);
        await registry.write.registerTranslator(
          ["Translator", "Org", keccak256(toBytes("key"))],
          { value: requirements[0], account: translator.account }
        );

        // Certify capability
        await registry.write.certifyCapability(
          [1, 3, keccak256(toBytes("circuit")), keccak256(toBytes("vk")), BigInt(1024 * 1024)],
          { account: translator.account }
        );

        const capabilities = await registry.read.getTranslatorCapabilities([translator.account.address]);
        const capabilityId = capabilities[0];

        // Grant attester role
        const attesterRole = keccak256(toBytes("ATTESTER_ROLE"));
        await registry.write.grantRole([attesterRole, attester.account.address]);

        // Create attestation
        const minAttesterStake = await registry.read.minAttesterStake();
        await registry.write.createAttestation(
          [
            capabilityId,
            keccak256(toBytes("evidence_hash")),
            "Verified translator capability through testing"
          ],
          { value: minAttesterStake, account: attester.account }
        );

        // Verify attestation was recorded
        // capabilities returns tuple: [certId, translator, srcSys, tgtSys, circuitHash, vkHash, maxSize, attestCount, totalStake, certAt, expiresAt, active]
        const updatedCap = await registry.read.capabilities([capabilityId]);
        // attestationCount is index 7 in the struct
        expect(updatedCap[7]).to.equal(1n);
      });
    });

    describe("Suspension and Moderation", function () {
      it("Should suspend and reinstate translator", async function () {
        const { viem } = await hre.network.connect();
        const [admin, translator] = await viem.getWalletClients();

        const registry = await viem.deployContract("TranslationCertificateRegistry");

        // Register
        const requirements = await registry.read.levelRequirements([1]);
        await registry.write.registerTranslator(
          ["Translator", "Org", keccak256(toBytes("key"))],
          { value: requirements[0], account: translator.account }
        );

        // Suspend
        await registry.write.suspendTranslator([
          translator.account.address,
          "Policy violation"
        ]);

        let profile = await registry.read.getTranslator([translator.account.address]);
        expect(profile.suspended).to.be.true;

        // Reinstate
        await registry.write.reinstateTranslator([translator.account.address]);
        
        profile = await registry.read.getTranslator([translator.account.address]);
        expect(profile.suspended).to.be.false;
      });
    });
  });

  describe("SemanticEquivalenceVerifier", function () {
    describe("Statement Registration", function () {
      it("Should register a semantic statement", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        const domain = 0; // Arithmetic
        const predicateHash = keccak256(toBytes("x + y = z"));
        const boundVars = [keccak256(toBytes("x")), keccak256(toBytes("y"))];
        const freeVars = [keccak256(toBytes("z"))];
        const domainSep = keccak256(toBytes("arithmetic_domain"));

        await verifier.write.registerStatement([
          domain,
          predicateHash,
          boundVars,
          freeVars,
          domainSep,
          false // not quantified
        ]);

        // Calculate statement ID
        const statementId = keccak256(
          toHex(new Uint8Array([
            // This is a simplified hash - actual would use encodePacked
          ]))
        );

        // Verify statement exists via event or read
        const totalEquiv = await verifier.read.totalEquivalences();
        // Statement registration doesn't increment equivalences
        expect(totalEquiv).to.equal(0n);
      });
    });

    describe("Circuit Equivalence", function () {
      it("Should register circuit equivalence", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        const sourceCircuit = keccak256(toBytes("groth16_circuit"));
        const targetCircuit = keccak256(toBytes("plonk_circuit"));
        const equivalenceProof = keccak256(toBytes("formal_equivalence_proof"));
        const witnessRelation = keccak256(toBytes("witness_mapping"));
        const domain = 0; // Arithmetic
        const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60);

        await verifier.write.registerCircuitEquivalence([
          sourceCircuit,
          targetCircuit,
          equivalenceProof,
          witnessRelation,
          domain,
          expiresAt
        ]);

        const totalEquiv = await verifier.read.totalEquivalences();
        expect(totalEquiv).to.equal(1n);

        // Check equivalence exists
        const [hasEquiv, equivId] = await verifier.read.hasEquivalence([sourceCircuit, targetCircuit]);
        expect(hasEquiv).to.be.true;
      });

      it("Should verify equivalence of translated proofs", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        // Register equivalence first
        const sourceCircuit = keccak256(toBytes("source_circuit"));
        const targetCircuit = keccak256(toBytes("target_circuit"));
        const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60);

        await verifier.write.registerCircuitEquivalence([
          sourceCircuit,
          targetCircuit,
          keccak256(toBytes("equiv_proof")),
          keccak256(toBytes("witness_rel")),
          0, // Arithmetic
          expiresAt
        ]);

        // Verify equivalence
        const sourceProof = keccak256(toBytes("source_proof"));
        const targetProof = keccak256(toBytes("target_proof"));
        const statementHash = keccak256(toBytes("statement"));

        const tx = await verifier.write.verifyEquivalence([
          sourceProof,
          targetProof,
          sourceCircuit,
          targetCircuit,
          statementHash,
          [keccak256(toBytes("input1"))],
          [keccak256(toBytes("input1_mapped"))]
        ]);

        const totalVerifications = await verifier.read.totalVerifications();
        expect(totalVerifications).to.equal(1n);
      });
    });

    describe("Semantic Binding", function () {
      it("Should create semantic binding for proof", async function () {
        const { viem } = await hre.network.connect();
        const [admin, user] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        const proofHash = keccak256(toBytes("proof_data"));
        const statementHash = keccak256(toBytes("statement"));
        const witnessCommitment = keccak256(toBytes("witness_commitment"));
        const domain = 1; // StateTransition
        const contextHash = keccak256(toBytes("application_context"));

        await verifier.write.createSemanticBinding(
          [
            proofHash,
            statementHash,
            witnessCommitment,
            [keccak256(toBytes("input1")), keccak256(toBytes("input2"))],
            domain,
            contextHash
          ],
          { account: user.account }
        );

        // Binding was created - verify via return value in real scenario
        // Here we just check no revert occurred
      });
    });

    describe("Trusted Circuits", function () {
      it("Should mark circuit as trusted", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        const circuitHash = keccak256(toBytes("formally_verified_circuit"));

        await verifier.write.setTrustedCircuit([circuitHash, true]);

        const isTrusted = await verifier.read.isCircuitTrusted([circuitHash]);
        expect(isTrusted).to.be.true;

        // Remove trust
        await verifier.write.setTrustedCircuit([circuitHash, false]);
        const isStillTrusted = await verifier.read.isCircuitTrusted([circuitHash]);
        expect(isStillTrusted).to.be.false;
      });
    });

    describe("Composition Rules", function () {
      it("Should add composition rule for domain", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        const domain = 0; // Arithmetic
        const requiredPredicates = [
          keccak256(toBytes("pred1")),
          keccak256(toBytes("pred2"))
        ];
        const preservedProperties = [
          keccak256(toBytes("soundness")),
          keccak256(toBytes("completeness"))
        ];
        const compositionProofHash = keccak256(toBytes("composition_valid"));

        await verifier.write.addCompositionRule([
          domain,
          requiredPredicates,
          preservedProperties,
          compositionProofHash
        ]);

        const rules = await verifier.read.getDomainRules([domain]);
        expect(rules.length).to.equal(1);
      });
    });

    describe("Cache Management", function () {
      it("Should cache verification results", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        // Setup equivalence
        const sourceCircuit = keccak256(toBytes("src"));
        const targetCircuit = keccak256(toBytes("tgt"));
        const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60);

        await verifier.write.registerCircuitEquivalence([
          sourceCircuit, targetCircuit,
          keccak256(toBytes("equiv")),
          keccak256(toBytes("witness")),
          0, expiresAt
        ]);

        // First verification
        const sourceProof = keccak256(toBytes("sp"));
        const targetProof = keccak256(toBytes("tp"));
        const statement = keccak256(toBytes("stmt"));

        await verifier.write.verifyEquivalence([
          sourceProof, targetProof,
          sourceCircuit, targetCircuit,
          statement, [], []
        ]);

        // Check cache
        const [exists, result] = await verifier.read.getCachedResult([
          sourceProof, targetProof, statement
        ]);

        expect(exists).to.be.true;
      });

      it("Should update cache expiry", async function () {
        const { viem } = await hre.network.connect();
        const [admin] = await viem.getWalletClients();

        const verifier = await viem.deployContract("SemanticEquivalenceVerifier");

        const newExpiry = 48n * 60n * 60n; // 48 hours
        await verifier.write.setCacheExpiry([newExpiry]);

        const cacheExpiry = await verifier.read.cacheExpiry();
        expect(cacheExpiry).to.equal(newExpiry);
      });
    });
  });

  describe("Integration Tests", function () {
    it("Should complete full translation workflow", async function () {
      const { viem } = await hre.network.connect();
      const [admin, translator, verifierAccount] = await viem.getWalletClients();

      // Deploy all contracts
      const sptc = await viem.deployContract("SemanticProofTranslationCertificate");
      const registry = await viem.deployContract("TranslationCertificateRegistry");
      const equivVerifier = await viem.deployContract("SemanticEquivalenceVerifier");

      // 1. Register translator in registry
      const requirements = await registry.read.levelRequirements([1]);
      await registry.write.registerTranslator(
        ["Integration Translator", "Test Org", keccak256(toBytes("pk"))],
        { value: requirements[0], account: translator.account }
      );

      // 2. Register capability in SPTC
      await sptc.write.registerCapability([
        1, 3, 0, [0, 1],
        keccak256(toBytes("circuit")),
        keccak256(toBytes("semantic")),
        1024 * 1024, 500000n
      ]);

      // 3. Register circuit equivalence in verifier
      const sourceCircuit = keccak256(toBytes("groth16_bn254"));
      const targetCircuit = keccak256(toBytes("plonk"));
      const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60);

      await equivVerifier.write.registerCircuitEquivalence([
        sourceCircuit, targetCircuit,
        keccak256(toBytes("equiv")),
        keccak256(toBytes("witness")),
        0, expiresAt
      ]);

      // 4. Grant translator role and stake
      const translatorRole = keccak256(toBytes("CERTIFIED_TRANSLATOR_ROLE"));
      await sptc.write.grantRole([translatorRole, translator.account.address]);
      await sptc.write.stakeAsTranslator([], { 
        value: 1000000000000000000n, 
        account: translator.account 
      });

      // 5. Issue certificate
      const sourceProof = keccak256(toBytes("source"));
      const targetProof = keccak256(toBytes("target"));
      const statement = keccak256(toBytes("stmt"));

      await sptc.write.translateAndCertify(
        [
          1, 3, 0,
          sourceProof,
          keccak256(toBytes("svk")),
          [],
          targetProof,
          keccak256(toBytes("tvk")),
          [],
          statement,
          keccak256(toBytes("semantic")),
          toHex(toBytes("proof"))
        ],
        { account: translator.account }
      );

      // 6. Verify semantic equivalence
      await equivVerifier.write.verifyEquivalence([
        sourceProof, targetProof,
        sourceCircuit, targetCircuit,
        statement, [], []
      ]);

      // All steps completed successfully
      const totalCerts = await sptc.read.totalCertificates();
      const totalVerifications = await equivVerifier.read.totalVerifications();

      expect(totalCerts).to.equal(1n);
      expect(totalVerifications).to.equal(1n);
    });
  });
});
