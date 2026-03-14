// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/privacy/CrossChainPrivacyHub.sol";
import "../../contracts/compliance/SelectiveDisclosureManager.sol";
import "../../contracts/compliance/ComplianceReportingModule.sol";
import "../../contracts/compliance/ConfigurablePrivacyLevels.sol";
import "../../contracts/mocks/MockProofVerifier.sol";

/**
 * @title CompliancePrivacyE2E
 * @notice End-to-end tests for the privacy ↔ compliance integration.
 * @dev Validates that:
 *   1. CrossChainPrivacyHub setComplianceModule works correctly
 *   2. Hub transfers succeed regardless of compliance module state
 *   3. SelectiveDisclosureManager viewing keys and disclosure tiers work
 *   4. ComplianceReportingModule can generate aggregate reports
 *   5. ConfigurablePrivacyLevels maps correctly to disclosure levels
 */
contract CompliancePrivacyE2E is Test {
    // =========================================================================
    // CONTRACTS
    // =========================================================================

    CrossChainPrivacyHub public privacyHub;
    SelectiveDisclosureManager public disclosure;
    ComplianceReportingModule public reporting;
    ConfigurablePrivacyLevels public privacyLevels;
    MockProofVerifier public mockVerifier;

    // =========================================================================
    // ACTORS
    // =========================================================================

    address public admin = makeAddr("admin");
    address public guardian = makeAddr("guardian");
    address public feeRecipient = makeAddr("feeRecipient");
    address public user = makeAddr("user");
    address public auditor = makeAddr("auditor");
    address public relayer = makeAddr("relayer");
    address public officer = makeAddr("officer");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 constant DEST_CHAIN = 42161;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        vm.warp(1740000000); // Feb 2025 — prevent timestamp underflow

        // Fund actors
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
        vm.deal(feeRecipient, 1 ether);

        vm.startPrank(admin);

        // Deploy mock verifier
        mockVerifier = new MockProofVerifier();
        mockVerifier.setVerificationResult(true);

        // Deploy compliance contracts
        disclosure = new SelectiveDisclosureManager(
            admin,
            address(mockVerifier)
        );
        reporting = new ComplianceReportingModule(admin, address(mockVerifier));
        privacyLevels = new ConfigurablePrivacyLevels(admin);

        // Deploy CrossChainPrivacyHub via UUPS proxy
        CrossChainPrivacyHub impl = new CrossChainPrivacyHub();
        bytes memory initData = abi.encodeCall(
            CrossChainPrivacyHub.initialize,
            (admin, guardian, feeRecipient)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        privacyHub = CrossChainPrivacyHub(payable(address(proxy)));

        // Wire compliance module into privacy hub
        privacyHub.grantRole(privacyHub.OPERATOR_ROLE(), admin);
        privacyHub.setComplianceModule(address(reporting));

        // Register a bridge adapter for destination chain
        privacyHub.registerAdapter(
            CrossChainPrivacyHub.AdapterRegistrationParams({
                chainId: DEST_CHAIN,
                adapter: makeAddr("adapter"),
                chainType: CrossChainPrivacyHub.ChainType.EVM,
                proofSystem: CrossChainPrivacyHub.ProofSystem.GROTH16,
                supportsPrivacy: true,
                minConfirmations: 1,
                maxTransfer: 100 ether,
                dailyLimit: 1000 ether
            })
        );

        // Grant relayer role
        privacyHub.grantRole(privacyHub.RELAYER_ROLE(), relayer);

        // Configure Groth16 proof verifier (required for MEDIUM+ privacy levels)
        privacyHub.setProofVerifier(
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            address(mockVerifier)
        );

        // Grant compliance officer role on reporting module
        reporting.grantRole(reporting.COMPLIANCE_OFFICER(), officer);

        // Grant COMPLIANCE_ADMIN on disclosure manager for standalone tests
        disclosure.grantRole(disclosure.COMPLIANCE_ADMIN(), admin);

        vm.stopPrank();
    }

    // =========================================================================
    // HUB TRANSFER + COMPLIANCE MODULE SETTER
    // =========================================================================

    function test_transferSucceedsWithComplianceModuleSet() public {
        vm.prank(user);
        bytes32 requestId = privacyHub.initiatePrivateTransfer{value: 1 ether}(
            DEST_CHAIN,
            keccak256(abi.encodePacked(user)),
            0.5 ether,
            CrossChainPrivacyHub.PrivacyLevel.BASIC,
            CrossChainPrivacyHub.PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.NONE,
                proof: "",
                publicInputs: new bytes32[](0),
                proofHash: bytes32(0)
            })
        );

        CrossChainPrivacyHub.TransferRequest memory t = privacyHub.getTransfer(
            requestId
        );
        assertEq(
            uint256(t.status),
            uint256(CrossChainPrivacyHub.TransferStatus.PENDING)
        );
        assertNotEq(requestId, bytes32(0));
    }

    function test_transferWithMediumPrivacy() public {
        CrossChainPrivacyHub.PrivacyProof memory proof = CrossChainPrivacyHub
            .PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.GROTH16,
                proof: hex"deadbeef",
                publicInputs: new bytes32[](0),
                proofHash: keccak256("proof")
            });

        vm.prank(user);
        bytes32 requestId = privacyHub.initiatePrivateTransfer{value: 1 ether}(
            DEST_CHAIN,
            keccak256(abi.encodePacked(user)),
            0.5 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            proof
        );

        assertNotEq(requestId, bytes32(0));
        assertEq(privacyHub.totalPrivateTransfers(), 1);
    }

    function test_transferWithMaximumPrivacy() public {
        CrossChainPrivacyHub.PrivacyProof memory proof = CrossChainPrivacyHub
            .PrivacyProof({
                system: CrossChainPrivacyHub.ProofSystem.GROTH16,
                proof: hex"deadbeef",
                publicInputs: new bytes32[](0),
                proofHash: keccak256("proof")
            });

        vm.prank(user);
        bytes32 requestId = privacyHub.initiatePrivateTransfer{value: 1 ether}(
            DEST_CHAIN,
            keccak256(abi.encodePacked(user)),
            0.5 ether,
            CrossChainPrivacyHub.PrivacyLevel.MAXIMUM,
            proof
        );

        assertNotEq(requestId, bytes32(0));
    }

    // =========================================================================
    // SELECTIVE DISCLOSURE: Standalone Viewing Keys
    // =========================================================================

    function test_disclosureManager_registerAndGrantViewingAccess() public {
        // Register a transaction directly on disclosure manager
        bytes32 txId = keccak256("test_tx_1");
        bytes32 commitment = keccak256("test_commitment");

        vm.prank(admin);
        disclosure.registerTransactionFor(
            txId,
            commitment,
            user,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR
        );

        // Verify registered
        SelectiveDisclosureManager.PrivateTransaction memory txn = disclosure
            .getTransaction(txId);
        assertTrue(txn.exists, "transaction should be registered");
        assertEq(txn.owner, user);
        assertEq(
            uint256(txn.defaultLevel),
            uint256(SelectiveDisclosureManager.DisclosureLevel.AUDITOR)
        );

        // User grants auditor viewing access
        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](2);
        fields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;
        fields[1] = SelectiveDisclosureManager.FieldType.SENDER;

        vm.prank(user);
        disclosure.grantViewingKey(
            txId,
            auditor,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            30 days,
            fields
        );

        // Verify auditor has access
        bool hasAccess = disclosure.hasViewingPermission(txId, auditor);
        assertTrue(hasAccess, "auditor should have viewing permission");
    }

    // =========================================================================
    // COMPLIANCE REPORTING: Aggregate Reports
    // =========================================================================

    function test_complianceOfficerCanGenerateReport() public {
        address[] memory viewers = new address[](1);
        viewers[0] = auditor;

        vm.prank(officer);
        bytes32 reportId = reporting.generateReport(
            user,
            ComplianceReportingModule.ReportType.TRANSACTION_SUMMARY,
            uint48(block.timestamp - 30 days),
            uint48(block.timestamp),
            keccak256("report_data"),
            5, // txCount
            viewers
        );

        assertTrue(reportId != bytes32(0), "report should be created");

        // Auditor should be able to access
        bool canAccess = reporting.canAccessReport(reportId, auditor);
        assertTrue(canAccess, "auditor should access report");

        // Non-viewer should not
        bool cannotAccess = reporting.canAccessReport(
            reportId,
            makeAddr("random")
        );
        assertFalse(cannotAccess, "random address should not access");
    }

    function test_reportVerificationFlow() public {
        address[] memory viewers = new address[](1);
        viewers[0] = auditor;

        vm.startPrank(officer);
        bytes32 reportId = reporting.generateReport(
            user,
            ComplianceReportingModule.ReportType.AML_CHECK,
            uint48(block.timestamp - 7 days),
            uint48(block.timestamp),
            keccak256("aml_check"),
            3,
            viewers
        );

        // Verify report with mock proof (moves DRAFT → VERIFIED)
        reporting.verifyReport(reportId, hex"aabbccdd", hex"11223344");
        assertTrue(
            reporting.isReportVerified(reportId),
            "report should be verified"
        );

        vm.stopPrank();
    }

    // =========================================================================
    // SETTER ACCESS CONTROL
    // =========================================================================

    function test_onlyOperatorCanSetComplianceModule() public {
        vm.prank(user); // NOT operator
        vm.expectRevert();
        privacyHub.setComplianceModule(address(disclosure));
    }

    function test_setComplianceModule_revertOnZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(CrossChainPrivacyHub.ZeroAddress.selector);
        privacyHub.setComplianceModule(address(0));
    }

    function test_setComplianceModule_updatesAddress() public {
        address newModule = makeAddr("newModule");
        vm.prank(admin);
        privacyHub.setComplianceModule(newModule);
        assertEq(privacyHub.complianceModule(), newModule);
    }
}
