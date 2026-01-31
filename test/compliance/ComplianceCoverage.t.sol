// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/compliance/SoulComplianceV2.sol";
import "../../contracts/security/ThresholdSignature.sol";

contract ComplianceCoverageTest is Test {
    SoulComplianceV2 public compliance;
    ThresholdSignature public thresholdSig;

    address public admin = address(this);
    address public provider = makeAddr("provider");

    function setUp() public {
        // Deploy contracts
        compliance = new SoulComplianceV2();
        thresholdSig = new ThresholdSignature();
    }

    function test_SoulComplianceV2_Lifecycle() public {
        // Test provider authorization
        compliance.authorizeProvider(provider);
        assertTrue(compliance.authorizedProviders(provider));
        
        vm.startPrank(provider);
        // Basic check to ensure we can call it (reverts due to logic checks are fine for coverage)
        // verifyKYC requires credentialHash and jurisdiction
        bytes32 credHash = keccak256("cred");
        bytes2 jurisdiction = bytes2("US");
        
        // compliance.verifyKYC should succeed for valid inputs
        compliance.verifyKYC(makeAddr("user"), SoulComplianceV2.KYCTier.Basic, credHash, jurisdiction);
        vm.stopPrank();
    }

    function test_ThresholdSignature_Lifecycle() public {
        // Verify roles
        assertTrue(thresholdSig.hasRole(thresholdSig.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(thresholdSig.hasRole(thresholdSig.COORDINATOR_ROLE(), admin));
    }
}
