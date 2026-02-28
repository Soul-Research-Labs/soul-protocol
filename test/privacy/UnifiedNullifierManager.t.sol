// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/UnifiedNullifierManager.sol";
import "../../contracts/interfaces/IProofVerifier.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Mock proof verifier that always returns true
contract MockProofVerifier is IProofVerifier {
    bool public shouldVerify = true;

    function setResult(bool _result) external {
        shouldVerify = _result;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldVerify;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 3;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

contract UnifiedNullifierManagerTest is Test {
    UnifiedNullifierManager public manager;
    UnifiedNullifierManager public impl;
    MockProofVerifier public verifier;

    address public admin = address(this);

    bytes32 public constant RELAY_ROLE = keccak256("RELAY_ROLE");
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;

    function setUp() public {
        impl = new UnifiedNullifierManager();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(UnifiedNullifierManager.initialize, (admin))
        );
        manager = UnifiedNullifierManager(address(proxy));

        verifier = new MockProofVerifier();
        manager.setCrossChainVerifier(address(verifier));
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    function test_initialize() public view {
        assertTrue(manager.hasRole(manager.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(manager.hasRole(OPERATOR_ROLE, admin));
        assertTrue(manager.hasRole(RELAY_ROLE, admin));
        assertTrue(manager.hasRole(UPGRADER_ROLE, admin));
    }

    function test_initialize_revertOnZeroAddress() public {
        UnifiedNullifierManager newImpl = new UnifiedNullifierManager();
        vm.expectRevert(UnifiedNullifierManager.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(UnifiedNullifierManager.initialize, (address(0)))
        );
    }

    function test_initialize_defaultChains() public view {
        // Should have 13 default chains registered
        assertEq(manager.getRegisteredChainCount(), 13);

        // Spot check some chains
        UnifiedNullifierManager.ChainDomain memory arb = manager.getChainDomain(
            42_161
        );
        assertTrue(arb.isActive);
        assertEq(
            uint256(arb.chainType),
            uint256(UnifiedNullifierManager.ChainType.EVM)
        );

        UnifiedNullifierManager.ChainDomain memory monero = manager
            .getChainDomain(900_001);
        assertTrue(monero.isActive);
        assertEq(
            uint256(monero.chainType),
            uint256(UnifiedNullifierManager.ChainType.PRIVACY)
        );
    }

    function test_initialize_revertOnDoubleInit() public {
        vm.expectRevert();
        manager.initialize(admin);
    }

    // =========================================================================
    // CHAIN DOMAIN REGISTRATION
    // =========================================================================

    function test_registerChainDomain() public {
        uint256 newChainId = 12_345;
        bytes32 tag = keccak256("CUSTOM");
        manager.registerChainDomain(
            newChainId,
            UnifiedNullifierManager.ChainType.EVM,
            tag,
            address(0xADA)
        );

        UnifiedNullifierManager.ChainDomain memory domain = manager
            .getChainDomain(newChainId);
        assertEq(domain.chainId, newChainId);
        assertTrue(domain.isActive);
        assertEq(domain.relayAdapter, address(0xADA));
        assertEq(domain.domainTag, tag);
    }

    function test_registerChainDomain_accessControl() public {
        vm.prank(address(0xBAD));
        vm.expectRevert();
        manager.registerChainDomain(
            99,
            UnifiedNullifierManager.ChainType.EVM,
            keccak256("X"),
            address(0)
        );
    }

    // =========================================================================
    // SET CROSS CHAIN VERIFIER
    // =========================================================================

    function test_setCrossChainVerifier() public {
        address newVerifier = address(0xFF);
        manager.setCrossChainVerifier(newVerifier);
        assertEq(manager.crossChainVerifier(), newVerifier);
    }

    function test_setCrossChainVerifier_revertOnZero() public {
        vm.expectRevert(UnifiedNullifierManager.ZeroAddress.selector);
        manager.setCrossChainVerifier(address(0));
    }

    // =========================================================================
    // REGISTER NULLIFIER
    // =========================================================================

    function test_registerNullifier() public {
        bytes32 nullifier = keccak256("n1");
        bytes32 commitment = keccak256("c1");
        uint256 chainId = 42_161; // Arbitrum

        bytes32 zaseon = manager.registerNullifier(
            nullifier,
            commitment,
            chainId,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        assertNotEq(zaseon, bytes32(0));

        UnifiedNullifierManager.NullifierRecord memory record = manager
            .getNullifierRecord(nullifier);
        assertEq(record.nullifier, nullifier);
        assertEq(record.commitment, commitment);
        assertEq(record.chainId, chainId);
        assertEq(
            uint256(record.status),
            uint256(UnifiedNullifierManager.NullifierStatus.REGISTERED)
        );

        // Verify zaseon binding
        assertEq(manager.getZaseonBinding(nullifier), zaseon);
        assertEq(manager.totalNullifiers(), 1);
    }

    function test_registerNullifier_revertOnDuplicate() public {
        bytes32 nullifier = keccak256("dup");
        manager.registerNullifier(
            nullifier,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        vm.expectRevert(
            UnifiedNullifierManager.NullifierAlreadyExists.selector
        );
        manager.registerNullifier(
            nullifier,
            keccak256("c2"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );
    }

    function test_registerNullifier_revertOnInactiveChain() public {
        vm.expectRevert(
            UnifiedNullifierManager.ChainDomainNotRegistered.selector
        );
        manager.registerNullifier(
            keccak256("x"),
            keccak256("c"),
            99_999,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );
    }

    function test_registerNullifier_zaseonBindingDerived() public {
        bytes32 nullifier = keccak256("sb");
        bytes32 zaseon = manager.registerNullifier(
            nullifier,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        UnifiedNullifierManager.ChainDomain memory domain = manager
            .getChainDomain(42_161);
        bytes32 expected = manager.deriveZaseonBinding(
            nullifier,
            domain.domainTag
        );
        assertEq(zaseon, expected);

        // Verify reverse lookup
        bytes32[] memory sources = manager.getSourceNullifiers(zaseon);
        assertEq(sources.length, 1);
        assertEq(sources[0], nullifier);
    }

    // =========================================================================
    // SPEND NULLIFIER
    // =========================================================================

    function test_spendNullifier() public {
        bytes32 nullifier = keccak256("spend1");
        manager.registerNullifier(
            nullifier,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        manager.spendNullifier(nullifier);
        assertTrue(manager.isNullifierSpent(nullifier));
    }

    function test_spendNullifier_revertOnUnknown() public {
        vm.expectRevert(UnifiedNullifierManager.NullifierNotFound.selector);
        manager.spendNullifier(keccak256("doesnt_exist"));
    }

    function test_spendNullifier_revertOnAlreadySpent() public {
        bytes32 nullifier = keccak256("doubleSpend");
        manager.registerNullifier(
            nullifier,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );
        manager.spendNullifier(nullifier);

        vm.expectRevert(UnifiedNullifierManager.NullifierAlreadySpent.selector);
        manager.spendNullifier(nullifier);
    }

    function test_spendNullifier_revertOnExpired() public {
        bytes32 nullifier = keccak256("expired");
        uint256 expiry = block.timestamp + 1 hours;
        manager.registerNullifier(
            nullifier,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.TIME_BOUND,
            expiry
        );

        vm.warp(expiry + 1);
        vm.expectRevert(UnifiedNullifierManager.NullifierExpired.selector);
        manager.spendNullifier(nullifier);
    }

    function test_spendNullifier_accessControl() public {
        bytes32 nullifier = keccak256("ac");
        manager.registerNullifier(
            nullifier,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        vm.prank(address(0xBAD));
        vm.expectRevert();
        manager.spendNullifier(nullifier);
    }

    // =========================================================================
    // CROSS-DOMAIN BINDING
    // =========================================================================

    function test_createCrossDomainBinding() public {
        bytes32 sourceNull = keccak256("crossSrc");
        manager.registerNullifier(
            sourceNull,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        (bytes32 destNull, bytes32 zaseon) = manager.createCrossDomainBinding(
            sourceNull,
            42_161, // Arbitrum
            10, // Optimism
            abi.encode("valid_proof")
        );

        assertNotEq(destNull, bytes32(0));
        assertNotEq(zaseon, bytes32(0));
        assertEq(manager.totalBindings(), 1);

        // Verify binding
        (bool valid, bytes32 zaseonBinding) = manager.verifyCrossDomainBinding(
            sourceNull,
            destNull
        );
        assertTrue(valid);
        assertEq(zaseonBinding, zaseon);
    }

    function test_createCrossDomainBinding_revertOnUnknownSource() public {
        vm.expectRevert(UnifiedNullifierManager.NullifierNotFound.selector);
        manager.createCrossDomainBinding(keccak256("fake"), 42_161, 10, "");
    }

    function test_createCrossDomainBinding_revertOnInactiveChain() public {
        bytes32 sourceNull = keccak256("inactiveChain");
        manager.registerNullifier(
            sourceNull,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        vm.expectRevert(
            UnifiedNullifierManager.ChainDomainNotRegistered.selector
        );
        manager.createCrossDomainBinding(sourceNull, 42_161, 99_999, "");
    }

    function test_createCrossDomainBinding_revertOnInvalidProof() public {
        bytes32 sourceNull = keccak256("badProof");
        manager.registerNullifier(
            sourceNull,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        verifier.setResult(false);
        vm.expectRevert(UnifiedNullifierManager.InvalidProof.selector);
        manager.createCrossDomainBinding(sourceNull, 42_161, 10, "proof");
    }

    function test_createCrossDomainBinding_destNullifierDerivation() public {
        bytes32 sourceNull = keccak256("derive");
        manager.registerNullifier(
            sourceNull,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        (bytes32 destNull, ) = manager.createCrossDomainBinding(
            sourceNull,
            42_161,
            10,
            "proof"
        );

        // Should match the pure derivation function
        bytes32 expected = manager.deriveCrossDomainNullifier(
            sourceNull,
            42_161,
            10
        );
        assertEq(destNull, expected);
    }

    // =========================================================================
    // BATCH OPERATIONS
    // =========================================================================

    function test_processBatch() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = keccak256(abi.encode("batch", i));
            commitments[i] = keccak256(abi.encode("commit", i));
        }

        bytes32 batchId = manager.processBatch(
            nullifiers,
            commitments,
            42_161,
            keccak256("merkle")
        );

        assertNotEq(batchId, bytes32(0));
        assertEq(manager.totalBatches(), 1);
        assertEq(manager.totalNullifiers(), 3);
        assertTrue(manager.validMerkleRoots(keccak256("merkle")));
    }

    function test_processBatch_revertOnEmpty() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(UnifiedNullifierManager.InvalidBatchSize.selector);
        manager.processBatch(empty, empty, 42_161, bytes32(0));
    }

    function test_processBatch_revertOnTooLarge() public {
        bytes32[] memory big = new bytes32[](101);
        bytes32[] memory bigC = new bytes32[](101);
        vm.expectRevert(UnifiedNullifierManager.InvalidBatchSize.selector);
        manager.processBatch(big, bigC, 42_161, bytes32(0));
    }

    function test_processBatch_revertOnMismatchedLengths() public {
        bytes32[] memory n = new bytes32[](3);
        bytes32[] memory c = new bytes32[](2);
        vm.expectRevert(UnifiedNullifierManager.InvalidBatchSize.selector);
        manager.processBatch(n, c, 42_161, bytes32(0));
    }

    function test_processBatch_skipsExisting() public {
        // Register one nullifier first
        bytes32 existing = keccak256(abi.encode("batch", uint256(0)));
        manager.registerNullifier(
            existing,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );
        assertEq(manager.totalNullifiers(), 1);

        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = keccak256(abi.encode("batch", i));
            commitments[i] = keccak256(abi.encode("commit", i));
        }

        manager.processBatch(nullifiers, commitments, 42_161, keccak256("m"));
        // Only 2 new should be registered (1 already existed)
        assertEq(manager.totalNullifiers(), 3);
    }

    function test_processBatch_revertOnInactiveChain() public {
        bytes32[] memory n = new bytes32[](1);
        bytes32[] memory c = new bytes32[](1);
        n[0] = keccak256("x");
        c[0] = keccak256("y");
        vm.expectRevert(
            UnifiedNullifierManager.ChainDomainNotRegistered.selector
        );
        manager.processBatch(n, c, 99_999, bytes32(0));
    }

    // =========================================================================
    // DERIVATION FUNCTIONS
    // =========================================================================

    function test_deriveZaseonBinding_deterministic() public view {
        bytes32 n = keccak256("test");
        bytes32 d = keccak256("domain");
        bytes32 s1 = manager.deriveZaseonBinding(n, d);
        bytes32 s2 = manager.deriveZaseonBinding(n, d);
        assertEq(s1, s2);
    }

    function test_deriveZaseonBinding_domainSeparation() public view {
        bytes32 n = keccak256("test");
        bytes32 d1 = keccak256("ARBITRUM");
        bytes32 d2 = keccak256("OPTIMISM");

        bytes32 s1 = manager.deriveZaseonBinding(n, d1);
        bytes32 s2 = manager.deriveZaseonBinding(n, d2);
        assertNotEq(s1, s2);
    }

    function test_deriveChainNullifier() public view {
        bytes32 commitment = keccak256("c");
        bytes32 secret = keccak256("s");
        bytes32 nullifier = manager.deriveChainNullifier(
            commitment,
            secret,
            42_161
        );
        assertNotEq(nullifier, bytes32(0));
    }

    function test_deriveChainNullifier_revertOnInactiveChain() public {
        vm.expectRevert(
            UnifiedNullifierManager.ChainDomainNotRegistered.selector
        );
        manager.deriveChainNullifier(keccak256("c"), keccak256("s"), 99_999);
    }

    function test_deriveCrossDomainNullifier_deterministic() public view {
        bytes32 source = keccak256("src");
        bytes32 n1 = manager.deriveCrossDomainNullifier(source, 42_161, 10);
        bytes32 n2 = manager.deriveCrossDomainNullifier(source, 42_161, 10);
        assertEq(n1, n2);
    }

    // =========================================================================
    // PAGINATION
    // =========================================================================

    function test_getSourceNullifiersPaginated() public {
        // Register multiple nullifiers that map to the same zaseon binding
        bytes32 n1 = keccak256("p1");
        bytes32 n2 = keccak256("p2");

        manager.registerNullifier(
            n1,
            keccak256("c1"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        bytes32 zaseon = manager.getZaseonBinding(n1);

        // Use createCrossDomainBinding to add more entries to the same zaseon binding
        // The second nullifier would need same domain tag to get same zaseon binding
        // Let's just test the pagination function directly
        (bytes32[] memory nullifiers, uint256 total) = manager
            .getSourceNullifiersPaginated(zaseon, 0, 10);
        assertEq(total, 1);
        assertEq(nullifiers.length, 1);
        assertEq(nullifiers[0], n1);
    }

    function test_getSourceNullifiersPaginated_offsetExceedsTotal() public {
        bytes32 n = keccak256("offset");
        manager.registerNullifier(
            n,
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );
        bytes32 zaseon = manager.getZaseonBinding(n);

        (bytes32[] memory nullifiers, uint256 total) = manager
            .getSourceNullifiersPaginated(zaseon, 100, 10);
        assertEq(total, 1);
        assertEq(nullifiers.length, 0);
    }

    // =========================================================================
    // STATS
    // =========================================================================

    function test_getStats() public {
        manager.registerNullifier(
            keccak256("s1"),
            keccak256("c"),
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        (
            uint256 totalN,
            uint256 totalB,
            uint256 totalBatch,
            uint256 chains
        ) = manager.getStats();
        assertEq(totalN, 1);
        assertEq(totalB, 0);
        assertEq(totalBatch, 0);
        assertEq(chains, 13); // Default chains
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function test_upgrade_onlyUpgrader() public {
        address newImpl = address(new UnifiedNullifierManager());

        // Admin has UPGRADER_ROLE, so this should work
        manager.upgradeToAndCall(newImpl, "");
    }

    function test_upgrade_revertOnUnauthorized() public {
        address newImpl = address(new UnifiedNullifierManager());

        vm.prank(address(0xBAD));
        vm.expectRevert();
        manager.upgradeToAndCall(newImpl, "");
    }

    // =========================================================================
    // FUZZ
    // =========================================================================

    function testFuzz_registerAndSpend(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));
        vm.assume(commitment != bytes32(0));

        manager.registerNullifier(
            nullifier,
            commitment,
            42_161,
            UnifiedNullifierManager.NullifierType.STANDARD,
            0
        );
        assertFalse(manager.isNullifierSpent(nullifier));

        manager.spendNullifier(nullifier);
        assertTrue(manager.isNullifierSpent(nullifier));
    }
}
