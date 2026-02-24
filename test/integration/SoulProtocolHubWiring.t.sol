// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SoulProtocolHub} from "../../contracts/core/SoulProtocolHub.sol";
import "../../contracts/interfaces/ISoulProtocolHub.sol";

/// @title SoulProtocolHubWiringTest
/// @notice Tests SoulProtocolHub wireAll, isFullyConfigured, getComponentStatus
contract SoulProtocolHubWiringTest is Test {
    SoulProtocolHub public hub;
    address admin = address(this);

    // Dummy addresses for wiring
    address constant VERIFIER_REG = address(0x1001);
    address constant UNIVERSAL_VER = address(0x1002);
    address constant MSG_RELAY = address(0x1003);
    address constant PRIVACY_HUB = address(0x1004);
    address constant STEALTH_REG = address(0x1005);
    address constant RELAYER_NET = address(0x1006);
    address constant VIEW_KEY_REG = address(0x1007);
    address constant SHIELDED = address(0x1008);
    address constant NULLIFIER_MGR = address(0x1009);
    address constant COMPLIANCE = address(0x100A);
    address constant PROOF_TRANSLATOR = address(0x100B);
    address constant PRIVACY_ROUTER = address(0x100C);
    address constant BRIDGE_VALIDATOR = address(0x100D);
    address constant ZK_SLOCKS = address(0x100E);
    address constant PC3 = address(0x100F);
    address constant CDNA = address(0x1010);
    address constant PBP = address(0x1011);
    address constant MULTI_PROVER = address(0x1012);
    address constant BRIDGE_WATCH = address(0x1013);

    function setUp() public {
        hub = new SoulProtocolHub();
    }

    /// @notice Hub starts not fully configured
    function test_NotFullyConfiguredInitially() public view {
        assertFalse(hub.isFullyConfigured());
    }

    /// @notice wireAll sets all components in a single tx
    function test_WireAll() public {
        hub.wireAll(
            ISoulProtocolHub.WireAllParams({
                _verifierRegistry: VERIFIER_REG,
                _universalVerifier: UNIVERSAL_VER,
                _crossChainMessageRelay: MSG_RELAY,
                _crossChainPrivacyHub: PRIVACY_HUB,
                _stealthAddressRegistry: STEALTH_REG,
                _privateRelayerNetwork: RELAYER_NET,
                _viewKeyRegistry: VIEW_KEY_REG,
                _shieldedPool: SHIELDED,
                _nullifierManager: NULLIFIER_MGR,
                _complianceOracle: COMPLIANCE,
                _proofTranslator: PROOF_TRANSLATOR,
                _privacyRouter: PRIVACY_ROUTER,
                _bridgeProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: PBP,
                _multiProver: address(0),
                _bridgeWatchtower: address(0),
                _intentSettlementLayer: address(0),
                _instantSettlementGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0)
            })
        );

        // Verify all components are set
        assertEq(hub.verifierRegistry(), VERIFIER_REG);
        assertEq(hub.universalVerifier(), UNIVERSAL_VER);
        assertEq(hub.crossChainMessageRelay(), MSG_RELAY);
        assertEq(hub.crossChainPrivacyHub(), PRIVACY_HUB);
        assertEq(hub.stealthAddressRegistry(), STEALTH_REG);
        assertEq(hub.privateRelayerNetwork(), RELAYER_NET);
        assertEq(hub.viewKeyRegistry(), VIEW_KEY_REG);
        assertEq(hub.shieldedPool(), SHIELDED);
        assertEq(hub.nullifierManager(), NULLIFIER_MGR);
        assertEq(hub.complianceOracle(), COMPLIANCE);
        assertEq(hub.proofTranslator(), PROOF_TRANSLATOR);
        assertEq(hub.privacyRouter(), PRIVACY_ROUTER);
        assertEq(hub.bridgeProofValidator(), BRIDGE_VALIDATOR);
        assertEq(hub.zkBoundStateLocks(), ZK_SLOCKS);
        assertEq(hub.proofCarryingContainer(), PC3);
        assertEq(hub.crossDomainNullifierAlgebra(), CDNA);
        assertEq(hub.policyBoundProofs(), PBP);
    }

    /// @notice isFullyConfigured returns true after wireAll with all 16 critical components
    function test_IsFullyConfiguredAfterWire() public {
        hub.wireAll(
            ISoulProtocolHub.WireAllParams({
                _verifierRegistry: VERIFIER_REG,
                _universalVerifier: UNIVERSAL_VER,
                _crossChainMessageRelay: MSG_RELAY,
                _crossChainPrivacyHub: PRIVACY_HUB,
                _stealthAddressRegistry: STEALTH_REG,
                _privateRelayerNetwork: RELAYER_NET,
                _viewKeyRegistry: address(0),
                _shieldedPool: SHIELDED,
                _nullifierManager: NULLIFIER_MGR,
                _complianceOracle: COMPLIANCE,
                _proofTranslator: address(0),
                _privacyRouter: PRIVACY_ROUTER,
                _bridgeProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: address(0),
                _multiProver: MULTI_PROVER,
                _bridgeWatchtower: BRIDGE_WATCH,
                _intentSettlementLayer: address(0),
                _instantSettlementGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0)
            })
        );

        assertTrue(hub.isFullyConfigured());
    }

    /// @notice wireAll skips zero addresses (partial wiring)
    function test_PartialWireAll() public {
        // First wire some components
        hub.setVerifierRegistry(VERIFIER_REG);

        // Then wireAll with partial addresses (zeros are skipped)
        hub.wireAll(
            ISoulProtocolHub.WireAllParams({
                _verifierRegistry: address(0), // skip — keep existing
                _universalVerifier: UNIVERSAL_VER,
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0),
                _nullifierManager: address(0),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0),
                _bridgeProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _bridgeWatchtower: address(0),
                _intentSettlementLayer: address(0),
                _instantSettlementGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0)
            })
        );

        // verifierRegistry from individual setter is preserved
        assertEq(hub.verifierRegistry(), VERIFIER_REG);
        // universalVerifier from wireAll is set
        assertEq(hub.universalVerifier(), UNIVERSAL_VER);
    }

    /// @notice getComponentStatus returns all 17 components
    function test_GetComponentStatus() public {
        hub.wireAll(
            ISoulProtocolHub.WireAllParams({
                _verifierRegistry: VERIFIER_REG,
                _universalVerifier: UNIVERSAL_VER,
                _crossChainMessageRelay: MSG_RELAY,
                _crossChainPrivacyHub: PRIVACY_HUB,
                _stealthAddressRegistry: STEALTH_REG,
                _privateRelayerNetwork: RELAYER_NET,
                _viewKeyRegistry: VIEW_KEY_REG,
                _shieldedPool: SHIELDED,
                _nullifierManager: NULLIFIER_MGR,
                _complianceOracle: COMPLIANCE,
                _proofTranslator: PROOF_TRANSLATOR,
                _privacyRouter: PRIVACY_ROUTER,
                _bridgeProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: PBP,
                _multiProver: address(0),
                _bridgeWatchtower: address(0),
                _intentSettlementLayer: address(0),
                _instantSettlementGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0)
            })
        );

        (string[] memory names, address[] memory addrs) = hub
            .getComponentStatus();
        assertEq(names.length, 25);
        assertEq(addrs.length, 25);

        // Spot check a few
        assertEq(addrs[0], VERIFIER_REG); // verifierRegistry
        assertEq(addrs[11], PRIVACY_ROUTER); // privacyRouter
        assertEq(addrs[16], PBP); // policyBoundProofs
    }

    /// @notice wireAll requires OPERATOR_ROLE
    function test_WireAllRevertWithoutRole() public {
        address attacker = address(0xDEAD);
        vm.prank(attacker);
        vm.expectRevert();
        hub.wireAll(
            ISoulProtocolHub.WireAllParams({
                _verifierRegistry: attacker,
                _universalVerifier: address(0),
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0),
                _nullifierManager: address(0),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0),
                _bridgeProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _bridgeWatchtower: address(0),
                _intentSettlementLayer: address(0),
                _instantSettlementGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0)
            })
        );
    }

    /// @notice setPrivacyRouter setter works
    function test_SetPrivacyRouter() public {
        hub.setPrivacyRouter(PRIVACY_ROUTER);
        assertEq(hub.privacyRouter(), PRIVACY_ROUTER);
    }

    /// @notice setPrivacyRouter reverts on zero address
    function test_SetPrivacyRouterRevertsZero() public {
        vm.expectRevert(ISoulProtocolHub.ZeroAddress.selector);
        hub.setPrivacyRouter(address(0));
    }
}
