// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SoulProtocolHub} from "../../contracts/core/SoulProtocolHub.sol";

/**
 * @title SoulProtocolHubTest
 * @notice Comprehensive tests for the central registry hub
 */
contract SoulProtocolHubTest is Test {
    SoulProtocolHub public hub;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public nonAdmin = makeAddr("nonAdmin");

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;

    function setUp() public {
        vm.startPrank(admin);
        hub = new SoulProtocolHub();
        hub.grantRole(OPERATOR_ROLE, operator);
        hub.grantRole(GUARDIAN_ROLE, guardian);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_AdminHasAllRoles() public view {
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hub.hasRole(OPERATOR_ROLE, admin));
        assertTrue(hub.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_OperatorHasRole() public view {
        assertTrue(hub.hasRole(OPERATOR_ROLE, operator));
    }

    function test_NonAdminHasNoRoles() public view {
        assertFalse(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), nonAdmin));
        assertFalse(hub.hasRole(OPERATOR_ROLE, nonAdmin));
        assertFalse(hub.hasRole(GUARDIAN_ROLE, nonAdmin));
    }

    function test_Constants() public view {
        assertEq(hub.MAX_BATCH_SIZE(), 50);
        assertEq(hub.ZKSYNC_CHAIN_ID(), 324);
        assertEq(hub.SCROLL_CHAIN_ID(), 534352);
        assertEq(hub.LINEA_CHAIN_ID(), 59144);
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_SetVerifierRegistry() public {
        address registry = makeAddr("verifierRegistry");
        vm.prank(operator);
        hub.setVerifierRegistry(registry);
        assertEq(hub.verifierRegistry(), registry);
    }

    function test_SetUniversalVerifier() public {
        address verifier = makeAddr("universalVerifier");
        vm.prank(operator);
        hub.setUniversalVerifier(verifier);
        assertEq(hub.universalVerifier(), verifier);
    }

    function test_SetMultiProver() public {
        address prover = makeAddr("multiProver");
        vm.prank(operator);
        hub.setMultiProver(prover);
        assertEq(hub.multiProver(), prover);
    }

    function test_RegisterVerifier() public {
        bytes32 verifierType = hub.GROTH16_VERIFIER();
        address verifier = makeAddr("groth16");

        vm.prank(operator);
        hub.registerVerifier(verifierType, verifier, 300_000);

        assertEq(hub.getVerifier(verifierType), verifier);

        SoulProtocolHub.VerifierInfo memory info = hub.getVerifierInfo(verifierType);
        assertEq(info.verifier, verifier);
        assertEq(info.proofType, verifierType);
        assertEq(info.gasLimit, 300_000);
        assertTrue(info.isActive);
    }

    function test_RegisterVerifierDefaultGas() public {
        bytes32 verifierType = hub.PLONK_VERIFIER();
        address verifier = makeAddr("plonk");

        vm.prank(operator);
        hub.registerVerifier(verifierType, verifier, 0);

        SoulProtocolHub.VerifierInfo memory info = hub.getVerifierInfo(verifierType);
        assertEq(info.gasLimit, 500_000, "Should default to 500k");
    }

    function test_BatchRegisterVerifiers() public {
        bytes32 g16 = hub.GROTH16_VERIFIER();
        bytes32 plonk = hub.PLONK_VERIFIER();
        bytes32 fri = hub.FRI_VERIFIER();

        bytes32[] memory types = new bytes32[](3);
        types[0] = g16;
        types[1] = plonk;
        types[2] = fri;

        address[] memory addrs = new address[](3);
        addrs[0] = makeAddr("groth16");
        addrs[1] = makeAddr("plonk");
        addrs[2] = makeAddr("fri");

        uint256[] memory limits = new uint256[](3);
        limits[0] = 300_000;
        limits[1] = 400_000;
        limits[2] = 500_000;

        vm.prank(operator);
        hub.batchRegisterVerifiers(types, addrs, limits);

        assertEq(hub.getVerifier(types[0]), addrs[0]);
        assertEq(hub.getVerifier(types[1]), addrs[1]);
        assertEq(hub.getVerifier(types[2]), addrs[2]);
    }

    function test_RevertBatchTooLarge() public {
        uint256 size = 51;
        bytes32[] memory types = new bytes32[](size);
        address[] memory addrs = new address[](size);
        uint256[] memory limits = new uint256[](size);
        for (uint256 i = 0; i < size; i++) {
            types[i] = keccak256(abi.encodePacked("V", i));
            addrs[i] = address(uint160(i + 1));
            limits[i] = 300_000;
        }

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(SoulProtocolHub.BatchTooLarge.selector, size, 50)
        );
        hub.batchRegisterVerifiers(types, addrs, limits);
    }

    function test_RevertVerifierZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(SoulProtocolHub.ZeroAddress.selector));
        hub.setVerifierRegistry(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       BRIDGE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterBridgeAdapter() public {
        address adapter = makeAddr("arbAdapter");
        uint256 chainId = 42161; // Arbitrum

        vm.prank(operator);
        hub.registerBridgeAdapter(chainId, adapter, true, 12);

        assertEq(hub.getBridgeAdapter(chainId), adapter);
        assertTrue(hub.isChainSupported(chainId));

        SoulProtocolHub.BridgeInfo memory info = hub.getBridgeInfo(chainId);
        assertEq(info.adapter, adapter);
        assertEq(info.chainId, chainId);
        assertTrue(info.supportsPrivacy);
        assertTrue(info.isActive);
        assertEq(info.minConfirmations, 12);
    }

    function test_RegisterMultipleBridges() public {
        vm.startPrank(operator);
        hub.registerBridgeAdapter(42161, makeAddr("arb"), true, 12);
        hub.registerBridgeAdapter(10, makeAddr("op"), true, 1);
        hub.registerBridgeAdapter(8453, makeAddr("base"), false, 1);
        vm.stopPrank();

        uint256[] memory chains = hub.getSupportedChainIds();
        assertEq(chains.length, 3);
    }

    function test_BatchRegisterBridgeAdapters() public {
        uint256[] memory chainIds = new uint256[](2);
        chainIds[0] = 42161;
        chainIds[1] = 10;

        address[] memory adapters = new address[](2);
        adapters[0] = makeAddr("arb");
        adapters[1] = makeAddr("op");

        bool[] memory privacy = new bool[](2);
        privacy[0] = true;
        privacy[1] = true;

        uint256[] memory confirmations = new uint256[](2);
        confirmations[0] = 12;
        confirmations[1] = 1;

        vm.prank(operator);
        hub.batchRegisterBridgeAdapters(chainIds, adapters, privacy, confirmations);

        assertTrue(hub.isChainSupported(42161));
        assertTrue(hub.isChainSupported(10));
    }

    function test_UpdateExistingBridgeAdapter() public {
        address adapter1 = makeAddr("arb_v1");
        address adapter2 = makeAddr("arb_v2");

        vm.startPrank(operator);
        hub.registerBridgeAdapter(42161, adapter1, false, 12);
        hub.registerBridgeAdapter(42161, adapter2, true, 6);
        vm.stopPrank();

        assertEq(hub.getBridgeAdapter(42161), adapter2);
        // Should not duplicate chain ID
        uint256[] memory chains = hub.getSupportedChainIds();
        assertEq(chains.length, 1);
    }

    function test_RevertBridgeZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(SoulProtocolHub.ZeroAddress.selector));
        hub.registerBridgeAdapter(42161, address(0), true, 12);
    }

    /*//////////////////////////////////////////////////////////////
                      PRIVACY MODULE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_SetPrivacyModules() public {
        address mlsag = makeAddr("mlsag");
        address ringCT = makeAddr("ringCT");
        address mixnet = makeAddr("mixnet");
        address stealth = makeAddr("stealth");

        vm.startPrank(operator);
        hub.setMLSAGSignatures(mlsag);
        hub.setRingConfidentialTransactions(ringCT);
        hub.setMixnetNodeRegistry(mixnet);
        hub.setStealthAddressRegistry(stealth);
        vm.stopPrank();

        assertEq(hub.mlsagSignatures(), mlsag);
        assertEq(hub.ringConfidentialTransactions(), ringCT);
        assertEq(hub.mixnetNodeRegistry(), mixnet);
        assertEq(hub.stealthAddressRegistry(), stealth);
    }

    function test_RevertPrivacyModuleZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(SoulProtocolHub.ZeroAddress.selector));
        hub.setMLSAGSignatures(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                    SECURITY MODULE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_SetSecurityModules() public {
        address validator = makeAddr("validator");
        address watchtower = makeAddr("watchtower");
        address breaker = makeAddr("breaker");

        vm.startPrank(operator);
        hub.setBridgeProofValidator(validator);
        hub.setBridgeWatchtower(watchtower);
        hub.setBridgeCircuitBreaker(breaker);
        vm.stopPrank();

        assertEq(hub.bridgeProofValidator(), validator);
        assertEq(hub.bridgeWatchtower(), watchtower);
        assertEq(hub.bridgeCircuitBreaker(), breaker);
    }

    /*//////////////////////////////////////////////////////////////
                   THRESHOLD SIG REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_SetThresholdSigModules() public {
        address gateway = makeAddr("tsgGateway");
        address sig = makeAddr("tsgSig");
        address shamir = makeAddr("shamir");

        vm.startPrank(operator);
        hub.setThresholdSigGateway(gateway);
        hub.setThresholdSignature(sig);
        hub.setShamirSecretSharing(shamir);
        vm.stopPrank();

        assertEq(hub.thresholdSigGateway(), gateway);
        assertEq(hub.thresholdSignature(), sig);
        assertEq(hub.shamirSecretSharing(), shamir);
    }

    /*//////////////////////////////////////////////////////////////
                     PRIMITIVE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_SetPrimitives() public {
        address zkLocks = makeAddr("zkLocks");
        address pc3 = makeAddr("pc3");
        address cdna = makeAddr("cdna");
        address pbp = makeAddr("pbp");

        vm.startPrank(operator);
        hub.setZKBoundStateLocks(zkLocks);
        hub.setProofCarryingContainer(pc3);
        hub.setCrossDomainNullifierAlgebra(cdna);
        hub.setPolicyBoundProofs(pbp);
        vm.stopPrank();

        assertEq(hub.zkBoundStateLocks(), zkLocks);
        assertEq(hub.proofCarryingContainer(), pc3);
        assertEq(hub.crossDomainNullifierAlgebra(), cdna);
        assertEq(hub.policyBoundProofs(), pbp);
    }

    /*//////////////////////////////////////////////////////////////
                    GOVERNANCE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_SetGovernanceModules() public {
        address tl = makeAddr("timelock");
        address utl = makeAddr("upgradeTimelock");

        vm.startPrank(admin);
        hub.setTimelock(tl);
        hub.setUpgradeTimelock(utl);
        vm.stopPrank();

        assertEq(hub.timelock(), tl);
        assertEq(hub.upgradeTimelock(), utl);
    }

    function test_RevertGovernanceSetByNonAdmin() public {
        vm.prank(operator);
        vm.expectRevert();
        hub.setTimelock(makeAddr("tl"));
    }

    /*//////////////////////////////////////////////////////////////
                      EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_PauseByGuardian() public {
        vm.prank(guardian);
        hub.pause();
        assertTrue(hub.paused());
    }

    function test_UnpauseByOperator() public {
        vm.prank(guardian);
        hub.pause();

        vm.prank(operator);
        hub.unpause();
        assertFalse(hub.paused());
    }

    function test_RevertPauseByNonGuardian() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        hub.pause();
    }

    function test_DeactivateVerifier() public {
        bytes32 verifierType = hub.GROTH16_VERIFIER();
        address verifier = makeAddr("groth16");

        vm.prank(operator);
        hub.registerVerifier(verifierType, verifier, 300_000);

        vm.prank(guardian);
        hub.deactivateVerifier(verifierType);

        SoulProtocolHub.VerifierInfo memory info = hub.getVerifierInfo(verifierType);
        assertFalse(info.isActive);
    }

    function test_DeactivateBridge() public {
        vm.prank(operator);
        hub.registerBridgeAdapter(42161, makeAddr("arb"), true, 12);

        vm.prank(guardian);
        hub.deactivateBridge(42161);

        assertFalse(hub.isChainSupported(42161));
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_RevertNonOperatorSetVerifier() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        hub.setVerifierRegistry(makeAddr("x"));
    }

    function test_RevertNonOperatorRegisterBridge() public {
        vm.prank(nonAdmin);
        vm.expectRevert();
        hub.registerBridgeAdapter(42161, makeAddr("x"), true, 12);
    }

    function test_RevertNonGuardianDeactivateVerifier() public {
        // Register first
        bytes32 verifierType = hub.GROTH16_VERIFIER();

        vm.prank(operator);
        hub.registerVerifier(verifierType, makeAddr("v"), 300_000);

        vm.prank(nonAdmin);
        vm.expectRevert();
        hub.deactivateVerifier(verifierType);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterVerifier(
        bytes32 verifierType,
        uint256 gasLimit
    ) public {
        gasLimit = bound(gasLimit, 1, 10_000_000);
        address verifier = makeAddr("fuzzVerifier");

        vm.prank(operator);
        hub.registerVerifier(verifierType, verifier, gasLimit);

        assertEq(hub.getVerifier(verifierType), verifier);
        assertEq(hub.getVerifierInfo(verifierType).gasLimit, gasLimit);
    }

    function testFuzz_RegisterBridgeAdapter(
        uint256 chainId,
        bool supportsPrivacy,
        uint256 minConfs
    ) public {
        minConfs = bound(minConfs, 1, 100);
        address adapter = makeAddr("fuzzAdapter");

        vm.prank(operator);
        hub.registerBridgeAdapter(chainId, adapter, supportsPrivacy, minConfs);

        assertEq(hub.getBridgeAdapter(chainId), adapter);
        assertTrue(hub.isChainSupported(chainId));
    }
}
