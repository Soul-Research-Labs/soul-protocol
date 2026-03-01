// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZaseonProtocolHub} from "../../contracts/core/ZaseonProtocolHub.sol";
import "../../contracts/interfaces/IZaseonProtocolHub.sol";

/// @title ZaseonProtocolHubWiringTest
/// @notice Tests ZaseonProtocolHub wireAll, isFullyConfigured, getComponentStatus
contract ZaseonProtocolHubWiringTest is Test {
    ZaseonProtocolHub public hub;
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
    address constant LIQ_VAULT = address(0x1014);

    function setUp() public {
        hub = new ZaseonProtocolHub();
    }

    /// @notice Hub starts not fully configured
    function test_NotFullyConfiguredInitially() public view {
        assertFalse(hub.isFullyConfigured());
    }

    /// @notice wireAll sets all components in a single tx
    function test_WireAll() public {
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
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
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: PBP,
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
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
        assertEq(hub.relayProofValidator(), BRIDGE_VALIDATOR);
        assertEq(hub.zkBoundStateLocks(), ZK_SLOCKS);
        assertEq(hub.proofCarryingContainer(), PC3);
        assertEq(hub.crossDomainNullifierAlgebra(), CDNA);
        assertEq(hub.policyBoundProofs(), PBP);
    }

    /// @notice isFullyConfigured returns true after wireAll with all 16 critical components
    function test_IsFullyConfiguredAfterWire() public {
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
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
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: address(0),
                _multiProver: MULTI_PROVER,
                _relayWatchtower: BRIDGE_WATCH,
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: LIQ_VAULT
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
            IZaseonProtocolHub.WireAllParams({
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
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
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
            IZaseonProtocolHub.WireAllParams({
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
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: PBP,
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );

        (string[] memory names, address[] memory addrs) = hub
            .getComponentStatus();
        assertEq(names.length, 26);
        assertEq(addrs.length, 26);

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
            IZaseonProtocolHub.WireAllParams({
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
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
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
        vm.expectRevert(IZaseonProtocolHub.ZeroAddress.selector);
        hub.setPrivacyRouter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                    EXTENDED WIRING TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice wireAll with all 22 fields set wires every component
    function test_WireAllFull22Components() public {
        address ICL = address(0x1014);
        address ICG = address(0x1015);
        address DRO = address(0x1016);

        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
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
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: PBP,
                _multiProver: MULTI_PROVER,
                _relayWatchtower: BRIDGE_WATCH,
                _intentCompletionLayer: ICL,
                _instantCompletionGuarantee: ICG,
                _dynamicRoutingOrchestrator: DRO,
                _crossChainLiquidityVault: address(0)
            })
        );

        // All 22 fields should be set
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
        assertEq(hub.relayProofValidator(), BRIDGE_VALIDATOR);
        assertEq(hub.zkBoundStateLocks(), ZK_SLOCKS);
        assertEq(hub.proofCarryingContainer(), PC3);
        assertEq(hub.crossDomainNullifierAlgebra(), CDNA);
        assertEq(hub.policyBoundProofs(), PBP);
        assertEq(hub.multiProver(), MULTI_PROVER);
        assertEq(hub.relayWatchtower(), BRIDGE_WATCH);
        assertEq(hub.intentCompletionLayer(), ICL);
        assertEq(hub.instantCompletionGuarantee(), ICG);
        assertEq(hub.dynamicRoutingOrchestrator(), DRO);
    }

    /// @notice isFullyConfigured returns false when missing any single required component
    function test_IsFullyConfigured_MissingOneRequired() public {
        // Wire all 16 required components
        _wireAllRequired();
        assertTrue(hub.isFullyConfigured(), "Should be fully configured");

        // Deploy a fresh hub and wire all except verifierRegistry
        ZaseonProtocolHub hub2 = new ZaseonProtocolHub();
        hub2.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0), // Missing!
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
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: address(0),
                _multiProver: MULTI_PROVER,
                _relayWatchtower: BRIDGE_WATCH,
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );
        assertFalse(
            hub2.isFullyConfigured(),
            "Missing verifierRegistry should not be fully configured"
        );
    }

    /// @notice wireAll is idempotent — calling twice with same params yields same state
    function test_WireAllIdempotent() public {
        IZaseonProtocolHub.WireAllParams
            memory params = _buildFullRequiredParams();

        hub.wireAll(params);
        assertEq(hub.verifierRegistry(), VERIFIER_REG);

        // Second call with identical params — state should remain the same
        hub.wireAll(params);
        assertEq(hub.verifierRegistry(), VERIFIER_REG);
        assertEq(hub.universalVerifier(), UNIVERSAL_VER);
        assertTrue(hub.isFullyConfigured());
    }

    /// @notice wireAll can overwrite previously set components
    function test_WireAllOverwritesExisting() public {
        _wireAllRequired();
        assertEq(hub.verifierRegistry(), VERIFIER_REG);

        // Now overwrite verifierRegistry with a new address
        address newVerifier = address(0x2001);
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: newVerifier,
                _universalVerifier: address(0), // skip all others
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
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );

        assertEq(
            hub.verifierRegistry(),
            newVerifier,
            "Should overwrite verifierRegistry"
        );
        // Other components should remain from previous wireAll
        assertEq(
            hub.universalVerifier(),
            UNIVERSAL_VER,
            "universalVerifier should be preserved"
        );
        assertTrue(hub.isFullyConfigured(), "Should still be fully configured");
    }

    /// @notice wireAll with all zeros updates no components
    function test_WireAllAllZeros() public {
        _wireAllRequired();
        assertTrue(hub.isFullyConfigured());

        // Wire with all zeros — nothing should change
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0),
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
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );

        // All components should remain from previous wireAll
        assertTrue(hub.isFullyConfigured(), "Should remain fully configured");
        assertEq(hub.verifierRegistry(), VERIFIER_REG);
    }

    /// @notice ProtocolWired event emitted with correct count
    function test_WireAllEmitsProtocolWired() public {
        IZaseonProtocolHub.WireAllParams
            memory params = _buildFullRequiredParams();

        vm.expectEmit(true, false, false, true);
        // WireAll with 17 non-zero addresses should emit ProtocolWired(admin, 17)
        emit IZaseonProtocolHub.ProtocolWired(admin, 17);
        hub.wireAll(params);
    }

    /// @notice getComponentStatus consistency check after full wireAll
    function test_GetComponentStatusConsistency() public {
        _wireAllRequired();

        (string[] memory names, address[] memory addrs) = hub
            .getComponentStatus();

        // Find verifierRegistry and check it matches the getter
        bool found = false;
        for (uint256 i = 0; i < names.length; i++) {
            if (
                keccak256(bytes(names[i])) ==
                keccak256(bytes("verifierRegistry"))
            ) {
                assertEq(
                    addrs[i],
                    hub.verifierRegistry(),
                    "getComponentStatus must match getter"
                );
                found = true;
                break;
            }
        }
        assertTrue(found, "verifierRegistry must appear in getComponentStatus");
    }

    /// @notice Individual setter + wireAll composability
    function test_IndividualSetterThenWireAll() public {
        // Set one component individually
        hub.setVerifierRegistry(VERIFIER_REG);
        assertEq(hub.verifierRegistry(), VERIFIER_REG);

        // Then wireAll with 0 for verifierRegistry (skip) but set others
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0), // keep existing
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
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: address(0),
                _multiProver: MULTI_PROVER,
                _relayWatchtower: BRIDGE_WATCH,
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: LIQ_VAULT
            })
        );

        // verifierRegistry from individual setter preserved
        assertEq(hub.verifierRegistry(), VERIFIER_REG);
        // Other components from wireAll
        assertEq(hub.universalVerifier(), UNIVERSAL_VER);
        assertTrue(hub.isFullyConfigured());
    }

    /// @notice Optional components don't affect isFullyConfigured
    function test_OptionalComponentsDontAffectFullConfig() public {
        // Wire ONLY required 16 — no optional components
        _wireAllRequired();
        assertTrue(
            hub.isFullyConfigured(),
            "Should be configured with only required components"
        );

        // viewKeyRegistry, policyBoundProofs, proofTranslator,
        // intentCompletionLayer, instantCompletionGuarantee,
        // dynamicRoutingOrchestrator should all be zero
        assertEq(hub.viewKeyRegistry(), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         HELPERS
    //////////////////////////////////////////////////////////////*/

    function _wireAllRequired() internal {
        hub.wireAll(_buildFullRequiredParams());
    }

    function _buildFullRequiredParams()
        internal
        pure
        returns (IZaseonProtocolHub.WireAllParams memory)
    {
        return
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: VERIFIER_REG,
                _universalVerifier: UNIVERSAL_VER,
                _crossChainMessageRelay: MSG_RELAY,
                _crossChainPrivacyHub: PRIVACY_HUB,
                _stealthAddressRegistry: STEALTH_REG,
                _privateRelayerNetwork: RELAYER_NET,
                _viewKeyRegistry: address(0), // optional
                _shieldedPool: SHIELDED,
                _nullifierManager: NULLIFIER_MGR,
                _complianceOracle: COMPLIANCE,
                _proofTranslator: address(0), // optional
                _privacyRouter: PRIVACY_ROUTER,
                _relayProofValidator: BRIDGE_VALIDATOR,
                _zkBoundStateLocks: ZK_SLOCKS,
                _proofCarryingContainer: PC3,
                _crossDomainNullifierAlgebra: CDNA,
                _policyBoundProofs: address(0), // optional
                _multiProver: MULTI_PROVER,
                _relayWatchtower: BRIDGE_WATCH,
                _intentCompletionLayer: address(0), // optional
                _instantCompletionGuarantee: address(0), // optional
                _dynamicRoutingOrchestrator: address(0), // optional
                _crossChainLiquidityVault: LIQ_VAULT
            });
    }
}
