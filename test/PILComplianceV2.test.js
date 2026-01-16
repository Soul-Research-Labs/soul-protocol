const { expect } = require("chai");
const { ethers } = require("hardhat");
const {
  loadFixture,
  time,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * @title PILComplianceV2 Tests
 * @description Comprehensive test coverage for compliance and KYC contract
 */
describe("PILComplianceV2", function () {
  // Test fixtures
  async function deployComplianceFixture() {
    const [owner, provider, auditor, user1, user2, attacker] =
      await ethers.getSigners();

    // Deploy compliance contract
    const PILComplianceV2 = await ethers.getContractFactory("PILComplianceV2");
    const compliance = await PILComplianceV2.deploy();

    // Authorize provider and auditor
    await compliance.connect(owner).authorizeProvider(provider.address);
    await compliance.connect(owner).authorizeAuditor(auditor.address);

    return { compliance, owner, provider, auditor, user1, user2, attacker };
  }

  describe("Deployment", function () {
    it("Should deploy with correct owner", async function () {
      const { compliance, owner } = await loadFixture(deployComplianceFixture);
      expect(await compliance.owner()).to.equal(owner.address);
    });

    it("Should have default KYC validity of 365 days", async function () {
      const { compliance } = await loadFixture(deployComplianceFixture);
      expect(await compliance.kycValidityDuration()).to.equal(
        365 * 24 * 60 * 60
      );
    });

    it("Should have default minimum tier as Basic", async function () {
      const { compliance } = await loadFixture(deployComplianceFixture);
      expect(await compliance.minRequiredTier()).to.equal(1); // KYCTier.Basic
    });
  });

  describe("Provider Management", function () {
    it("Should authorize provider", async function () {
      const { compliance, owner, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(owner).authorizeProvider(attacker.address)
      )
        .to.emit(compliance, "KYCProviderAuthorized")
        .withArgs(attacker.address);

      expect(await compliance.authorizedProviders(attacker.address)).to.be.true;
    });

    it("Should revoke provider", async function () {
      const { compliance, owner, provider } = await loadFixture(
        deployComplianceFixture
      );

      await expect(compliance.connect(owner).revokeProvider(provider.address))
        .to.emit(compliance, "KYCProviderRevoked")
        .withArgs(provider.address);

      expect(await compliance.authorizedProviders(provider.address)).to.be
        .false;
    });

    it("Should only allow owner to manage providers", async function () {
      const { compliance, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).authorizeProvider(attacker.address)
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("Auditor Management", function () {
    it("Should authorize auditor", async function () {
      const { compliance, owner, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(compliance.connect(owner).authorizeAuditor(attacker.address))
        .to.emit(compliance, "AuditorAuthorized")
        .withArgs(attacker.address);

      expect(await compliance.authorizedAuditors(attacker.address)).to.be.true;
    });

    it("Should revoke auditor", async function () {
      const { compliance, owner, auditor } = await loadFixture(
        deployComplianceFixture
      );

      await expect(compliance.connect(owner).revokeAuditor(auditor.address))
        .to.emit(compliance, "AuditorRevoked")
        .withArgs(auditor.address);

      expect(await compliance.authorizedAuditors(auditor.address)).to.be.false;
    });

    it("Should only allow owner to manage auditors", async function () {
      const { compliance, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).authorizeAuditor(attacker.address)
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("KYC Verification", function () {
    it("Should verify user KYC successfully", async function () {
      const { compliance, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      const credentialHash = ethers.keccak256(
        ethers.toUtf8Bytes("user1_credentials")
      );
      const jurisdiction = ethers.encodeBytes32String("US").slice(0, 6); // bytes2

      await expect(
        compliance.connect(provider).verifyKYC(
          user1.address,
          2, // KYCTier.Standard
          credentialHash,
          jurisdiction
        )
      )
        .to.emit(compliance, "KYCVerified")
        .withArgs(user1.address, 2, provider.address);

      const record = await compliance.kycRecords(user1.address);
      expect(record.status).to.equal(2); // KYCStatus.Approved
      expect(record.tier).to.equal(2); // KYCTier.Standard
      expect(record.provider).to.equal(provider.address);
      expect(record.credentialHash).to.equal(credentialHash);
    });

    it("Should set correct expiry on KYC", async function () {
      const { compliance, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      const credentialHash = ethers.keccak256(
        ethers.toUtf8Bytes("user1_credentials")
      );
      const jurisdiction = ethers.encodeBytes32String("US").slice(0, 6);

      const blockTime = await time.latest();
      await compliance
        .connect(provider)
        .verifyKYC(user1.address, 2, credentialHash, jurisdiction);

      const record = await compliance.kycRecords(user1.address);
      expect(record.expiresAt).to.be.closeTo(
        blockTime + 365 * 24 * 60 * 60,
        10
      );
    });

    it("Should reject verification from unauthorized provider", async function () {
      const { compliance, attacker, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).verifyKYC(
          user1.address,
          2,
          ethers.ZeroHash,
          "0x5553" // "US"
        )
      ).to.be.revertedWithCustomError(compliance, "NotAuthorizedProvider");
    });

    it("Should reject verification for restricted jurisdiction", async function () {
      const { compliance, owner, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      const jurisdiction = "0x4b50"; // "KP" (North Korea)
      await compliance.connect(owner).restrictJurisdiction(jurisdiction);

      await expect(
        compliance
          .connect(provider)
          .verifyKYC(user1.address, 2, ethers.ZeroHash, jurisdiction)
      ).to.be.revertedWithCustomError(compliance, "RestrictedJurisdiction");
    });

    it("Should reject verification for sanctioned address", async function () {
      const { compliance, owner, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await compliance.connect(owner).sanctionAddress(user1.address);

      await expect(
        compliance
          .connect(provider)
          .verifyKYC(user1.address, 2, ethers.ZeroHash, "0x5553")
      ).to.be.revertedWithCustomError(compliance, "AddressIsSanctioned");
    });

    it("Should revoke user KYC", async function () {
      const { compliance, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      // First verify
      await compliance
        .connect(provider)
        .verifyKYC(user1.address, 2, ethers.ZeroHash, "0x5553");

      // Then revoke
      await expect(
        compliance
          .connect(provider)
          .revokeKYC(user1.address, "Suspicious activity")
      )
        .to.emit(compliance, "KYCRevoked")
        .withArgs(user1.address, "Suspicious activity");

      const record = await compliance.kycRecords(user1.address);
      expect(record.status).to.equal(3); // KYCStatus.Rejected
    });
  });

  describe("KYC Validation", function () {
    it("Should return true for valid KYC", async function () {
      const { compliance, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await compliance.connect(provider).verifyKYC(
        user1.address,
        2, // Standard tier (meets Basic minimum)
        ethers.ZeroHash,
        "0x5553"
      );

      expect(await compliance.isKYCValid(user1.address)).to.be.true;
    });

    it("Should return false for unverified user", async function () {
      const { compliance, user1 } = await loadFixture(deployComplianceFixture);
      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should return false for expired KYC", async function () {
      const { compliance, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await compliance
        .connect(provider)
        .verifyKYC(user1.address, 2, ethers.ZeroHash, "0x5553");

      // Fast forward past expiry
      await time.increase(366 * 24 * 60 * 60);

      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should return false if tier below minimum", async function () {
      const { compliance, owner, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      // Set minimum tier to Standard
      await compliance.connect(owner).setMinRequiredTier(2); // Standard

      // Verify with Basic tier
      await compliance.connect(provider).verifyKYC(
        user1.address,
        1, // Basic tier
        ethers.ZeroHash,
        "0x5553"
      );

      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should check if user meets specific tier", async function () {
      const { compliance, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await compliance.connect(provider).verifyKYC(
        user1.address,
        2, // Standard tier
        ethers.ZeroHash,
        "0x5553"
      );

      expect(await compliance.meetsKYCTier(user1.address, 1)).to.be.true; // Basic
      expect(await compliance.meetsKYCTier(user1.address, 2)).to.be.true; // Standard
      expect(await compliance.meetsKYCTier(user1.address, 3)).to.be.false; // Enhanced
    });
  });

  describe("Audit Trail", function () {
    it("Should record audit successfully", async function () {
      const { compliance, auditor, user1 } = await loadFixture(
        deployComplianceFixture
      );

      const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state_root"));
      const proof = ethers.toUtf8Bytes("compliance_proof");

      await expect(
        compliance
          .connect(auditor)
          .recordAudit(user1.address, stateRoot, proof, true)
      ).to.emit(compliance, "AuditCompleted");
    });

    it("Should store audit data correctly", async function () {
      const { compliance, auditor, user1 } = await loadFixture(
        deployComplianceFixture
      );

      const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state_root"));
      const proof = ethers.toUtf8Bytes("compliance_proof");

      const tx = await compliance
        .connect(auditor)
        .recordAudit(user1.address, stateRoot, proof, true);
      const receipt = await tx.wait();
      const event = receipt.logs.find((log) => {
        try {
          return compliance.interface.parseLog(log)?.name === "AuditCompleted";
        } catch {
          return false;
        }
      });
      const auditId = compliance.interface.parseLog(event).args.auditId;

      const audit = await compliance.auditTrails(auditId);
      expect(audit.auditor).to.equal(auditor.address);
      expect(audit.user).to.equal(user1.address);
      expect(audit.stateRoot).to.equal(stateRoot);
      expect(audit.result).to.be.true;
    });

    it("Should track user audit history", async function () {
      const { compliance, auditor, user1 } = await loadFixture(
        deployComplianceFixture
      );

      // Record multiple audits
      await compliance
        .connect(auditor)
        .recordAudit(
          user1.address,
          ethers.keccak256(ethers.toUtf8Bytes("root1")),
          "0x",
          true
        );
      await compliance
        .connect(auditor)
        .recordAudit(
          user1.address,
          ethers.keccak256(ethers.toUtf8Bytes("root2")),
          "0x",
          false
        );

      const history = await compliance.getUserAuditHistory(user1.address);
      expect(history.length).to.equal(2);
    });

    it("Should reject audit from unauthorized auditor", async function () {
      const { compliance, attacker, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance
          .connect(attacker)
          .recordAudit(user1.address, ethers.ZeroHash, "0x", true)
      ).to.be.revertedWithCustomError(compliance, "NotAuthorizedAuditor");
    });
  });

  describe("Sanctions Management", function () {
    it("Should sanction address", async function () {
      const { compliance, owner, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await expect(compliance.connect(owner).sanctionAddress(user1.address))
        .to.emit(compliance, "AddressSanctioned")
        .withArgs(user1.address);

      expect(await compliance.sanctionedAddresses(user1.address)).to.be.true;
    });

    it("Should revoke KYC when sanctioned", async function () {
      const { compliance, owner, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      // Verify user first
      await compliance
        .connect(provider)
        .verifyKYC(user1.address, 2, ethers.ZeroHash, "0x5553");

      // Then sanction
      await compliance.connect(owner).sanctionAddress(user1.address);

      const record = await compliance.kycRecords(user1.address);
      expect(record.status).to.equal(3); // KYCStatus.Rejected
    });

    it("Should unsanction address", async function () {
      const { compliance, owner, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await compliance.connect(owner).sanctionAddress(user1.address);

      await expect(compliance.connect(owner).unsanctionAddress(user1.address))
        .to.emit(compliance, "AddressUnsanctioned")
        .withArgs(user1.address);

      expect(await compliance.sanctionedAddresses(user1.address)).to.be.false;
    });

    it("Should only allow owner to manage sanctions", async function () {
      const { compliance, attacker, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).sanctionAddress(user1.address)
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("Jurisdiction Management", function () {
    it("Should restrict jurisdiction", async function () {
      const { compliance, owner } = await loadFixture(deployComplianceFixture);

      const jurisdiction = "0x4b50"; // "KP"

      await expect(compliance.connect(owner).restrictJurisdiction(jurisdiction))
        .to.emit(compliance, "JurisdictionRestricted")
        .withArgs(jurisdiction);

      expect(await compliance.restrictedJurisdictions(jurisdiction)).to.be.true;
    });

    it("Should unrestrict jurisdiction", async function () {
      const { compliance, owner } = await loadFixture(deployComplianceFixture);

      const jurisdiction = "0x4b50";
      await compliance.connect(owner).restrictJurisdiction(jurisdiction);

      await expect(
        compliance.connect(owner).unrestrictJurisdiction(jurisdiction)
      )
        .to.emit(compliance, "JurisdictionUnrestricted")
        .withArgs(jurisdiction);

      expect(await compliance.restrictedJurisdictions(jurisdiction)).to.be
        .false;
    });

    it("Should only allow owner to manage jurisdictions", async function () {
      const { compliance, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).restrictJurisdiction("0x4b50")
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("Configuration", function () {
    it("Should update minimum required tier", async function () {
      const { compliance, owner } = await loadFixture(deployComplianceFixture);

      await compliance.connect(owner).setMinRequiredTier(3); // Enhanced
      expect(await compliance.minRequiredTier()).to.equal(3);
    });

    it("Should update KYC validity duration", async function () {
      const { compliance, owner } = await loadFixture(deployComplianceFixture);

      const newDuration = 180 * 24 * 60 * 60; // 180 days
      await compliance.connect(owner).setKYCValidityDuration(newDuration);
      expect(await compliance.kycValidityDuration()).to.equal(newDuration);
    });

    it("Should only allow owner to update config", async function () {
      const { compliance, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).setMinRequiredTier(3)
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");

      await expect(
        compliance.connect(attacker).setKYCValidityDuration(100)
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("Pausable", function () {
    it("Should pause and unpause verification", async function () {
      const { compliance, owner, provider, user1 } = await loadFixture(
        deployComplianceFixture
      );

      await compliance.connect(owner).pause();

      await expect(
        compliance
          .connect(provider)
          .verifyKYC(user1.address, 2, ethers.ZeroHash, "0x5553")
      ).to.be.revertedWithCustomError(compliance, "EnforcedPause");

      await compliance.connect(owner).unpause();

      await expect(
        compliance
          .connect(provider)
          .verifyKYC(user1.address, 2, ethers.ZeroHash, "0x5553")
      ).to.emit(compliance, "KYCVerified");
    });

    it("Should only allow owner to pause", async function () {
      const { compliance, attacker } = await loadFixture(
        deployComplianceFixture
      );

      await expect(
        compliance.connect(attacker).pause()
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("Multiple Tiers", function () {
    it("Should handle all KYC tiers correctly", async function () {
      const { compliance, provider, user1, user2 } = await loadFixture(
        deployComplianceFixture
      );

      const tiers = [
        { tier: 0, name: "Unverified" },
        { tier: 1, name: "Basic" },
        { tier: 2, name: "Standard" },
        { tier: 3, name: "Enhanced" },
        { tier: 4, name: "Institutional" },
      ];

      for (let i = 1; i <= 4; i++) {
        const wallet = ethers.Wallet.createRandom().connect(ethers.provider);

        await compliance
          .connect(provider)
          .verifyKYC(wallet.address, i, ethers.ZeroHash, "0x5553");

        const record = await compliance.kycRecords(wallet.address);
        expect(record.tier).to.equal(i);
      }
    });
  });
});
