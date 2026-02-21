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
 *   1. CrossChainPrivacyHub correctly registers transfers with SelectiveDisclosureManager
 *   2. Compliance hooks use non-reverting try/catch (never block transfers)
 *   3. Viewing keys and disclosure tiers work across privacy levels
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

        // Grant COMPLIANCE_ADMIN on disclosure manager to the privacy hub
        // so registerTransactionFor() calls succeed
        disclosure.grantRole(
            disclosure.COMPLIANCE_ADMIN(),
            address(privacyHub)
        );

        // Wire compliance into privacy hub
        privacyHub.setDisclosureManager(address(disclosure));
        privacyHub.setComplianceReporting(address(reporting));

        // Register a bridge adapter for destination chain
        privacyHub.grantRole(privacyHub.OPERATOR_ROLE(), admin);
        privacyHub.registerAdapter(
            DEST_CHAIN,
            makeAddr("adapter"),
            CrossChainPrivacyHub.ChainType.EVM,
            CrossChainPrivacyHub.ProofSystem.GROTH16,
            true, // supportsPrivacy
            1, // minConfirmations
            100 ether, // maxTransfer
            1000 ether // dailyLimit
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

        vm.stopPrank();
    }

    // =========================================================================
    // DISCLOSURE INTEGRATION: Transfer Registration
    // =========================================================================

    function test_transferRegistersWithDisclosureManager() public {
        // User initiates a MEDIUM privacy transfer (→ AUDITOR disclosure level)
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
            keccak256(abi.encodePacked(user)), // recipient as bytes32
            0.5 ether,
            CrossChainPrivacyHub.PrivacyLevel.MEDIUM,
            proof
        );

        // The transfer should have been registered with the disclosure manager
        SelectiveDisclosureManager.PrivateTransaction memory txn = disclosure
            .getTransaction(requestId);
        assertTrue(txn.exists, "transaction should be registered");
        assertEq(txn.owner, user, "owner should be the user");
        // MEDIUM privacy → AUDITOR disclosure level per our mapping
        assertEq(
            uint256(txn.defaultLevel),
            uint256(SelectiveDisclosureManager.DisclosureLevel.AUDITOR)
        );
    }

    function test_maximumPrivacyMapsToCounterpartyLevel() public {
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

        SelectiveDisclosureManager.PrivateTransaction memory txn = disclosure
            .getTransaction(requestId);
        assertTrue(txn.exists, "transaction should be registered");
        assertEq(
            uint256(txn.defaultLevel),
            uint256(SelectiveDisclosureManager.DisclosureLevel.COUNTERPARTY)
        );
    }

    function test_highPrivacyMapsToRegulatorLevel() public {
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
            CrossChainPrivacyHub.PrivacyLevel.HIGH,
            proof
        );

        SelectiveDisclosureManager.PrivateTransaction memory txn = disclosure
            .getTransaction(requestId);
        assertTrue(txn.exists, "transaction should be registered");
        assertEq(
            uint256(txn.defaultLevel),
            uint256(SelectiveDisclosureManager.DisclosureLevel.REGULATOR)
        );
    }

    function test_basicPrivacyMapsToPublicLevel() public {
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

        SelectiveDisclosureManager.PrivateTransaction memory txn = disclosure
            .getTransaction(requestId);
        assertTrue(txn.exists, "transaction should be registered");
        assertEq(
            uint256(txn.defaultLevel),
            uint256(SelectiveDisclosureManager.DisclosureLevel.PUBLIC)
        );
    }

    // =========================================================================
    // NON-REVERTING: Compliance Never Blocks Transfers
    // =========================================================================

    function test_transferSucceedsWhenDisclosureManagerReverts() public {
        // Deploy a broken disclosure manager that always reverts
        // Note: deploy separately to avoid vm.prank being consumed by CREATE
        RevertingDisclosureManager broken = new RevertingDisclosureManager();
        vm.prank(admin);
        privacyHub.setDisclosureManager(address(broken));

        // Transfer should still succeed despite compliance hook failure
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

        // Transfer should be in PENDING status (not reverted)
        CrossChainPrivacyHub.TransferRequest memory transfer = _getTransfer(
            requestId
        );
        assertEq(
            uint256(transfer.status),
            uint256(CrossChainPrivacyHub.TransferStatus.PENDING)
        );
    }

    function test_transferSucceedsWhenDisclosureManagerNotSet() public {
        // Remove disclosure manager
        vm.prank(admin);
        privacyHub.setDisclosureManager(address(0));

        // Transfer should succeed
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

        CrossChainPrivacyHub.TransferRequest memory transfer = _getTransfer(
            requestId
        );
        assertEq(
            uint256(transfer.status),
            uint256(CrossChainPrivacyHub.TransferStatus.PENDING)
        );
    }

    // =========================================================================
    // VIEWING KEYS: Auditor Access After Transfer
    // =========================================================================

    function test_auditorCanBeGrantedViewingAccess() public {
        // Initiate transfer
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

        // User grants auditor viewing access
        SelectiveDisclosureManager.FieldType[]
            memory fields = new SelectiveDisclosureManager.FieldType[](2);
        fields[0] = SelectiveDisclosureManager.FieldType.AMOUNT;
        fields[1] = SelectiveDisclosureManager.FieldType.SENDER;

        vm.prank(user);
        disclosure.grantViewingKey(
            requestId,
            auditor,
            SelectiveDisclosureManager.DisclosureLevel.AUDITOR,
            30 days,
            fields
        );

        // Verify auditor has access
        bool hasAccess = disclosure.hasViewingPermission(requestId, auditor);
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

        // Note: submitReport requires DRAFT status, so it cannot be called
        // after verifyReport (which sets VERIFIED). Verification is sufficient.
        vm.stopPrank();
    }

    // =========================================================================
    // SETTER ACCESS CONTROL
    // =========================================================================

    function test_onlyAdminCanSetDisclosureManager() public {
        vm.prank(user); // NOT admin
        vm.expectRevert();
        privacyHub.setDisclosureManager(address(disclosure));
    }

    function test_onlyAdminCanSetComplianceReporting() public {
        vm.prank(user); // NOT admin
        vm.expectRevert();
        privacyHub.setComplianceReporting(address(reporting));
    }

    function test_settersEmitEvents() public {
        address newDisc = makeAddr("newDisclosure");
        address newReport = makeAddr("newReporting");

        vm.startPrank(admin);

        vm.expectEmit(true, true, false, false);
        emit CrossChainPrivacyHub.DisclosureManagerUpdated(
            address(disclosure),
            newDisc
        );
        privacyHub.setDisclosureManager(newDisc);

        vm.expectEmit(true, true, false, false);
        emit CrossChainPrivacyHub.ComplianceReportingUpdated(
            address(reporting),
            newReport
        );
        privacyHub.setComplianceReporting(newReport);

        vm.stopPrank();
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _getTransfer(
        bytes32 requestId
    ) internal view returns (CrossChainPrivacyHub.TransferRequest memory) {
        (
            bytes32 id,
            address sender,
            bytes32 recipient,
            uint256 srcChain,
            uint256 destChain,
            address token,
            uint256 amount,
            uint256 fee,
            CrossChainPrivacyHub.PrivacyLevel pvLevel,
            bytes32 commitment,
            bytes32 nullifier,
            uint64 timestamp,
            uint64 expiry,
            CrossChainPrivacyHub.TransferStatus status
        ) = privacyHub.transfers(requestId);

        return
            CrossChainPrivacyHub.TransferRequest({
                requestId: id,
                sender: sender,
                recipient: recipient,
                sourceChainId: srcChain,
                destChainId: destChain,
                token: token,
                amount: amount,
                fee: fee,
                privacyLevel: pvLevel,
                commitment: commitment,
                nullifier: nullifier,
                timestamp: timestamp,
                expiry: expiry,
                status: status
            });
    }
}

/**
 * @notice Mock that always reverts — used to test non-reverting compliance hooks
 */
contract RevertingDisclosureManager {
    fallback() external {
        revert("ALWAYS_REVERTS");
    }
}
