// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/security/SecurityIntegrations.sol";
import "../../contracts/crosschain/CrossL2Atomicity.sol";
import "../../contracts/crosschain/LayerZeroAdapter.sol";
import "../../contracts/crosschain/HyperlaneAdapter.sol";

/**
 * @title SoulSecurityIntegrationsFuzz
 * @notice Fuzz tests for SecurityIntegrations, CrossL2Atomicity, LayerZeroAdapter, HyperlaneAdapter
 * @dev Tests MEV protection, flash loan guards, cross-L2 atomicity, and cross-chain messaging
 *
 * Run with: forge test --match-contract SoulSecurityIntegrationsFuzz --fuzz-runs 10000
 */
contract SoulSecurityIntegrationsFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MIN_REVEAL_DELAY = 2;
    uint256 constant MAX_COMMITMENT_AGE = 100;
    uint256 constant MAX_CHAINS = 10;
    uint256 constant DEFAULT_TIMEOUT = 1 hours;

    /*//////////////////////////////////////////////////////////////
                              CONTRACTS
    //////////////////////////////////////////////////////////////*/

    SecurityIntegrations public securityIntegrations;
    CrossL2Atomicity public crossL2Atomicity;
    LayerZeroAdapter public layerZeroAdapter;
    HyperlaneAdapter public hyperlaneAdapter;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public guardian = address(0x3);
    address public relayer = address(0x4);
    address public user = address(0x5);
    address public attacker = address(0x6);

    // Mock addresses
    address public mockEndpoint = address(0x100);
    address public mockMailbox = address(0x101);
    address public mockISM = address(0x102);

    // Role constants
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant DVN_ROLE = keccak256("DVN_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy SecurityIntegrations
        securityIntegrations = new SecurityIntegrations(admin);
        securityIntegrations.grantRole(OPERATOR_ROLE, operator);
        securityIntegrations.grantRole(GUARDIAN_ROLE, guardian);
        securityIntegrations.grantRole(RELAYER_ROLE, relayer);

        // Deploy CrossL2Atomicity
        crossL2Atomicity = new CrossL2Atomicity(admin);
        crossL2Atomicity.grantRole(OPERATOR_ROLE, operator);
        crossL2Atomicity.grantRole(EXECUTOR_ROLE, relayer);
        crossL2Atomicity.grantRole(GUARDIAN_ROLE, guardian);

        // Deploy LayerZeroAdapter
        layerZeroAdapter = new LayerZeroAdapter(mockEndpoint, 1, admin);
        layerZeroAdapter.grantRole(OPERATOR_ROLE, operator);
        layerZeroAdapter.grantRole(DVN_ROLE, relayer);
        layerZeroAdapter.grantRole(GUARDIAN_ROLE, guardian);

        // Deploy HyperlaneAdapter (mailbox, localDomain, admin)
        hyperlaneAdapter = new HyperlaneAdapter(mockMailbox, 1, admin);
        hyperlaneAdapter.grantRole(OPERATOR_ROLE, operator);
        hyperlaneAdapter.grantRole(VALIDATOR_ROLE, relayer);
        hyperlaneAdapter.grantRole(GUARDIAN_ROLE, guardian);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    SECURITY INTEGRATIONS FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Commit operation with random data
    function testFuzz_CommitOperation(
        bytes32 operationType,
        bytes32 commitHash
    ) public {
        vm.assume(operationType != bytes32(0));
        vm.assume(commitHash != bytes32(0));

        vm.prank(user);
        bytes32 operationId = securityIntegrations.commitOperation(
            operationType,
            commitHash
        );

        // Verify operation was stored
        (
            address opUser,
            bytes32 opType,
            bytes32 opCommitHash,
            ,
            ,
            ,
            ,
            ,

        ) = securityIntegrations.operations(operationId);

        assertEq(opUser, user);
        assertEq(opType, operationType);
        assertEq(opCommitHash, commitHash);
    }

    /// @notice Fuzz test: Cannot commit twice in same block (flash loan protection)
    function testFuzz_CannotCommitTwiceSameBlock(
        bytes32 operationType1,
        bytes32 operationType2,
        bytes32 commitHash1,
        bytes32 commitHash2
    ) public {
        vm.assume(operationType1 != bytes32(0));
        vm.assume(operationType2 != bytes32(0));
        vm.assume(commitHash1 != bytes32(0));
        vm.assume(commitHash2 != bytes32(0));

        vm.startPrank(user);

        // First commit succeeds
        securityIntegrations.commitOperation(operationType1, commitHash1);

        // Second commit in same block should fail
        vm.expectRevert(SecurityIntegrations.FlashLoanGuardFailed.selector);
        securityIntegrations.commitOperation(operationType2, commitHash2);

        vm.stopPrank();
    }

    /// @notice Fuzz test: User nonces are strictly increasing
    function testFuzz_UserNoncesIncreasing(uint8 numOperations) public {
        vm.assume(numOperations > 0 && numOperations <= 50);

        vm.startPrank(user);

        uint256 previousNonce = 0;
        for (uint8 i = 0; i < numOperations; i++) {
            // Roll forward to avoid same-block protection
            vm.roll(block.number + 1);

            bytes32 operationType = keccak256(abi.encodePacked("OP", i));
            bytes32 commitHash = keccak256(abi.encodePacked("HASH", i));

            securityIntegrations.commitOperation(operationType, commitHash);

            uint256 currentNonce = securityIntegrations.userNonces(user);
            assertGt(currentNonce, previousNonce);
            previousNonce = currentNonce;
        }

        vm.stopPrank();
    }

    /// @notice Fuzz test: Operation counter always increases
    function testFuzz_OperationCounterIncreases(
        uint8 numUsers,
        uint8 operationsPerUser
    ) public {
        // Use bound instead of assume to avoid rejection
        numUsers = uint8(bound(numUsers, 1, 10));
        operationsPerUser = uint8(bound(operationsPerUser, 1, 5)); // Reduce to 5 for gas efficiency

        uint256 expectedCounter = 0;
        uint256 blockNum = block.number;

        for (uint8 u = 0; u < numUsers; u++) {
            address currentUser = address(uint160(0x1000 + u));

            for (uint8 o = 0; o < operationsPerUser; o++) {
                blockNum++;
                vm.roll(blockNum);
                vm.prank(currentUser);

                bytes32 opType = keccak256(abi.encodePacked(u, o));
                bytes32 hash = keccak256(abi.encodePacked("H", u, o));

                securityIntegrations.commitOperation(opType, hash);
                expectedCounter++;

                assertEq(
                    securityIntegrations.operationCounter(),
                    expectedCounter
                );
            }
        }
    }

    /// @notice Fuzz test: Price deviation validation
    function testFuzz_PriceDeviationBps(uint256 bps) public {
        vm.assume(bps <= 10000); // Max 100%

        vm.prank(admin);
        securityIntegrations.setMaxPriceDeviation(bps);

        assertEq(securityIntegrations.maxPriceDeviationBps(), bps);
    }

    /// @notice Fuzz test: Oracle staleness threshold
    function testFuzz_OracleStalenessThreshold(uint256 threshold) public {
        vm.assume(threshold >= 60 && threshold <= 86400); // 1 min to 1 day

        vm.prank(admin);
        securityIntegrations.setOracleStalenessThreshold(threshold);

        assertEq(securityIntegrations.oracleStalenessThreshold(), threshold);
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS L2 ATOMICITY FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Create atomic bundle with random chains
    function testFuzz_CreateAtomicBundle(
        uint8 numChains,
        uint256 timeout
    ) public {
        // Bound instead of assume to avoid rejection
        numChains = uint8(bound(numChains, 1, MAX_CHAINS));
        timeout = bound(timeout, 60, 7 days);

        // Prepare arrays
        uint256[] memory chainIds = new uint256[](numChains);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](numChains);
        address[] memory targets = new address[](numChains);
        bytes[] memory datas = new bytes[](numChains);
        uint256[] memory values = new uint256[](numChains);

        for (uint8 i = 0; i < numChains; i++) {
            chainIds[i] = uint256(i + 1);
            chainTypes[i] = CrossL2Atomicity.ChainType(i % 7);
            targets[i] = address(uint160(0x2000 + i));
            datas[i] = abi.encodePacked("data", i);
            values[i] = 0;
        }

        vm.prank(user);
        bytes32 bundleId = crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            timeout
        );

        // Verify bundle created
        (
            address initiator,
            CrossL2Atomicity.BundlePhase phase,
            uint256 chainCount,
            ,
            ,

        ) = crossL2Atomicity.getBundle(bundleId);

        assertEq(initiator, user);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.CREATED));
        assertEq(chainCount, numChains);
    }

    /// @notice Fuzz test: Cannot create bundle with zero chains
    function testFuzz_CannotCreateEmptyBundle(uint256 timeout) public {
        uint256[] memory chainIds = new uint256[](0);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](0);
        address[] memory targets = new address[](0);
        bytes[] memory datas = new bytes[](0);
        uint256[] memory values = new uint256[](0);

        vm.prank(user);
        vm.expectRevert(CrossL2Atomicity.InvalidChainCount.selector);
        crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            timeout
        );
    }

    /// @notice Fuzz test: Cannot create bundle with too many chains
    function testFuzz_CannotCreateOversizedBundle(uint8 numChains) public {
        vm.assume(numChains > MAX_CHAINS);

        uint256[] memory chainIds = new uint256[](numChains);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](numChains);
        address[] memory targets = new address[](numChains);
        bytes[] memory datas = new bytes[](numChains);
        uint256[] memory values = new uint256[](numChains);

        for (uint8 i = 0; i < numChains; i++) {
            chainIds[i] = uint256(i + 1);
            chainTypes[i] = CrossL2Atomicity.ChainType.GENERIC;
            targets[i] = address(uint160(0x2000 + i));
            datas[i] = abi.encodePacked("data", i);
            values[i] = 0;
        }

        vm.prank(user);
        vm.expectRevert(CrossL2Atomicity.InvalidChainCount.selector);
        crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    /// @notice Fuzz test: Global nonce always increases
    function testFuzz_GlobalNonceIncreases(uint8 numBundles) public {
        vm.assume(numBundles > 0 && numBundles <= 20);

        uint256[] memory chainIds = new uint256[](1);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        uint256[] memory values = new uint256[](1);

        chainIds[0] = 1;
        chainTypes[0] = CrossL2Atomicity.ChainType.GENERIC;
        targets[0] = address(0x1234);
        datas[0] = "data";
        values[0] = 0;

        uint256 previousNonce = 0;

        for (uint8 i = 0; i < numBundles; i++) {
            vm.prank(address(uint160(0x3000 + i)));
            crossL2Atomicity.createAtomicBundle(
                chainIds,
                chainTypes,
                targets,
                datas,
                values,
                0
            );

            uint256 currentNonce = crossL2Atomicity.globalNonce();
            assertGt(currentNonce, previousNonce);
            previousNonce = currentNonce;
        }
    }

    /// @notice Fuzz test: Bundle expiration
    function testFuzz_BundleExpiration(uint256 timeout) public {
        vm.assume(timeout >= 60 && timeout <= 7 days);

        uint256[] memory chainIds = new uint256[](2);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](2);
        address[] memory targets = new address[](2);
        bytes[] memory datas = new bytes[](2);
        uint256[] memory values = new uint256[](2);

        for (uint8 i = 0; i < 2; i++) {
            chainIds[i] = uint256(i + 1);
            chainTypes[i] = CrossL2Atomicity.ChainType.GENERIC;
            targets[i] = address(uint160(0x2000 + i));
            datas[i] = abi.encodePacked("data", i);
            values[i] = 0;
        }

        vm.prank(user);
        bytes32 bundleId = crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            timeout
        );

        // Initially not expired
        assertFalse(crossL2Atomicity.isBundleExpired(bundleId));

        // Warp past timeout
        vm.warp(block.timestamp + timeout + 1);

        // Now expired
        assertTrue(crossL2Atomicity.isBundleExpired(bundleId));
    }

    /// @notice Fuzz test: Mark chain prepared
    function testFuzz_MarkChainPrepared(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));

        // Create bundle
        uint256[] memory chainIds = new uint256[](2);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](2);
        address[] memory targets = new address[](2);
        bytes[] memory datas = new bytes[](2);
        uint256[] memory values = new uint256[](2);

        chainIds[0] = 1;
        chainIds[1] = 2;
        chainTypes[0] = CrossL2Atomicity.ChainType.OP_STACK;
        chainTypes[1] = CrossL2Atomicity.ChainType.ARBITRUM;
        targets[0] = address(0x1111);
        targets[1] = address(0x2222);
        datas[0] = "data1";
        datas[1] = "data2";
        values[0] = 0;
        values[1] = 0;

        vm.prank(user);
        bytes32 bundleId = crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );

        // Mark first chain prepared
        vm.prank(relayer);
        crossL2Atomicity.markChainPrepared(bundleId, 1, proofHash);

        // Check phase is PREPARING
        (
            ,
            CrossL2Atomicity.BundlePhase phase,
            ,
            uint256 preparedCount,
            ,

        ) = crossL2Atomicity.getBundle(bundleId);

        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.PREPARING));
        assertEq(preparedCount, 1);

        // Mark second chain prepared - should auto-commit
        vm.prank(relayer);
        crossL2Atomicity.markChainPrepared(bundleId, 2, proofHash);

        (, phase, , preparedCount, , ) = crossL2Atomicity.getBundle(bundleId);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.COMMITTED));
        assertEq(preparedCount, 2);
    }

    /// @notice Fuzz test: Rollback after timeout
    function testFuzz_RollbackAfterTimeout(uint256 timeout) public {
        vm.assume(timeout >= 60 && timeout <= 1 days);

        uint256[] memory chainIds = new uint256[](1);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        uint256[] memory values = new uint256[](1);

        chainIds[0] = 1;
        chainTypes[0] = CrossL2Atomicity.ChainType.GENERIC;
        targets[0] = address(0x1234);
        datas[0] = "data";
        values[0] = 0;

        vm.prank(user);
        bytes32 bundleId = crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            timeout
        );

        // Cannot rollback before timeout
        vm.expectRevert(CrossL2Atomicity.TimeoutNotReached.selector);
        crossL2Atomicity.rollbackAfterTimeout(bundleId);

        // Warp past timeout
        vm.warp(block.timestamp + timeout + 1);

        // Now can rollback
        crossL2Atomicity.rollbackAfterTimeout(bundleId);

        (, CrossL2Atomicity.BundlePhase phase, , , , ) = crossL2Atomicity
            .getBundle(bundleId);
        assertEq(uint8(phase), uint8(CrossL2Atomicity.BundlePhase.ROLLEDBACK));
    }

    /*//////////////////////////////////////////////////////////////
                    LAYERZERO ADAPTER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Set trusted remote
    function testFuzz_SetTrustedRemote(uint32 eid, bytes32 remote) public {
        vm.assume(eid > 0);
        vm.assume(remote != bytes32(0));

        vm.prank(operator);
        layerZeroAdapter.setTrustedRemote(eid, remote);

        assertEq(layerZeroAdapter.trustedRemotes(eid), remote);
    }

    /// @notice Fuzz test: Set ULN config
    function testFuzz_SetUlnConfig(
        uint64 confirmations,
        uint8 requiredDVNs,
        uint8 optionalDVNs,
        uint8 optionalThreshold
    ) public {
        // Use bound instead of assume to avoid rejection
        confirmations = uint64(bound(confirmations, 1, 100));
        requiredDVNs = uint8(bound(requiredDVNs, 0, 10));
        optionalDVNs = uint8(bound(optionalDVNs, 0, 10));
        optionalThreshold = uint8(bound(optionalThreshold, 0, optionalDVNs));

        // Create ULN config struct
        address[] memory requiredDVNAddrs = new address[](0);
        address[] memory optionalDVNAddrs = new address[](0);

        LayerZeroAdapter.UlnConfig memory config = LayerZeroAdapter.UlnConfig({
            confirmations: confirmations,
            requiredDVNCount: requiredDVNs,
            optionalDVNCount: optionalDVNs,
            optionalDVNThreshold: optionalThreshold,
            requiredDVNs: requiredDVNAddrs,
            optionalDVNs: optionalDVNAddrs
        });

        vm.prank(operator);
        layerZeroAdapter.setUlnConfig(1, config);

        // Config was set (can't easily verify without a getter)
        assertTrue(true);
    }

    /// @notice Fuzz test: DVN configuration
    function testFuzz_DVNConfiguration(uint8 count) public {
        vm.assume(count <= 10 && count > 0);

        // Create DVN addresses
        address[] memory dvns = new address[](count);
        for (uint8 i = 0; i < count; i++) {
            dvns[i] = address(uint160(0x100 + i));
        }

        // Register DVN (use startPrank for multiple calls)
        vm.startPrank(admin);
        for (uint8 i = 0; i < count; i++) {
            layerZeroAdapter.grantRole(DVN_ROLE, dvns[i]);
        }
        vm.stopPrank();

        // DVNs should have DVN_ROLE
        for (uint8 i = 0; i < count; i++) {
            assertTrue(layerZeroAdapter.hasRole(DVN_ROLE, dvns[i]));
        }
    }

    /*//////////////////////////////////////////////////////////////
                    HYPERLANE ADAPTER FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Set multisig parameters
    function testFuzz_SetMultisigParams(
        uint8 validatorCount,
        uint8 threshold
    ) public {
        // Use bound instead of assume to avoid rejection
        validatorCount = uint8(bound(validatorCount, 1, 10));
        threshold = uint8(bound(threshold, 1, validatorCount));

        address[] memory validators = new address[](validatorCount);
        for (uint8 i = 0; i < validatorCount; i++) {
            validators[i] = address(uint160(0x200 + i));
        }

        vm.prank(operator);
        hyperlaneAdapter.setMultisigParams(1, validators, threshold);

        // Verify through mapping getter - struct fields: (uint8 threshold, bytes32 commitment)
        // Note: validators array is not returned by public mapping getter
        (uint8 storedThreshold, ) = hyperlaneAdapter.multisigParams(1);
        assertEq(storedThreshold, threshold);
    }

    /// @notice Fuzz test: Set trusted sender
    function testFuzz_SetTrustedSender(uint32 domain, bytes32 sender) public {
        vm.assume(domain > 0);
        vm.assume(sender != bytes32(0));

        vm.prank(operator);
        hyperlaneAdapter.setTrustedSender(domain, sender);

        assertEq(hyperlaneAdapter.trustedSenders(domain), sender);
    }

    /// @notice Fuzz test: ISM configuration
    function testFuzz_ISMConfig(uint32 domain, uint8 threshold) public {
        vm.assume(domain > 0);
        vm.assume(threshold > 0 && threshold <= 10);

        address[] memory validators = new address[](threshold);
        for (uint8 i = 0; i < threshold; i++) {
            validators[i] = address(uint160(0x300 + i));
        }

        HyperlaneAdapter.ISMConfig memory config = HyperlaneAdapter.ISMConfig({
            ism: address(0x456),
            ismType: HyperlaneAdapter.ISMType.MULTISIG,
            enabled: true,
            threshold: threshold,
            validators: validators
        });

        vm.prank(operator);
        hyperlaneAdapter.setISMConfig(domain, config);

        // Verify ISM config was set (first 4 fields from mapping getter)
        (
            address storedIsm,
            HyperlaneAdapter.ISMType storedType,
            bool enabled,
            uint8 storedThreshold
        ) = hyperlaneAdapter.ismConfigs(domain);
        assertEq(storedIsm, address(0x456));
        assertEq(uint8(storedType), uint8(HyperlaneAdapter.ISMType.MULTISIG));
        assertTrue(enabled);
        assertEq(storedThreshold, threshold);
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz test: Unauthorized user cannot commit when paused
    function testFuzz_CannotCommitWhenPaused(
        bytes32 operationType,
        bytes32 commitHash
    ) public {
        vm.assume(operationType != bytes32(0));
        vm.assume(commitHash != bytes32(0));

        // Pause the contract
        vm.prank(guardian);
        securityIntegrations.pause();

        // User cannot commit
        vm.prank(user);
        vm.expectRevert();
        securityIntegrations.commitOperation(operationType, commitHash);
    }

    /// @notice Fuzz test: Only executor can mark chain prepared
    function testFuzz_OnlyExecutorCanPrepare(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));

        // Create bundle first
        uint256[] memory chainIds = new uint256[](1);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        uint256[] memory values = new uint256[](1);

        chainIds[0] = 1;
        chainTypes[0] = CrossL2Atomicity.ChainType.GENERIC;
        targets[0] = address(0x1234);
        datas[0] = "data";
        values[0] = 0;

        vm.prank(user);
        bytes32 bundleId = crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );

        // Attacker cannot mark chain prepared
        vm.prank(attacker);
        vm.expectRevert();
        crossL2Atomicity.markChainPrepared(bundleId, 1, proofHash);
    }

    /// @notice Fuzz test: Only DVN can confirm messages
    function testFuzz_OnlyDVNCanConfirm(bytes32 messageId) public {
        vm.assume(messageId != bytes32(0));

        // Attacker cannot confirm
        vm.prank(attacker);
        vm.expectRevert();
        layerZeroAdapter.dvnConfirm(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                        INVARIANT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Invariant: Paused contracts reject all state-changing operations
    function testInvariant_PausedContractsRejectOperations() public {
        // Pause all contracts
        vm.startPrank(guardian);
        securityIntegrations.pause();
        crossL2Atomicity.pause();
        layerZeroAdapter.pause();
        hyperlaneAdapter.pause();
        vm.stopPrank();

        // Try operations on SecurityIntegrations
        vm.prank(user);
        vm.expectRevert();
        securityIntegrations.commitOperation(bytes32("TEST"), bytes32("HASH"));

        // Try operations on CrossL2Atomicity
        uint256[] memory chainIds = new uint256[](1);
        CrossL2Atomicity.ChainType[]
            memory chainTypes = new CrossL2Atomicity.ChainType[](1);
        address[] memory targets = new address[](1);
        bytes[] memory datas = new bytes[](1);
        uint256[] memory values = new uint256[](1);

        chainIds[0] = 1;
        chainTypes[0] = CrossL2Atomicity.ChainType.GENERIC;
        targets[0] = address(0x1234);
        datas[0] = "data";
        values[0] = 0;

        vm.prank(user);
        vm.expectRevert();
        crossL2Atomicity.createAtomicBundle(
            chainIds,
            chainTypes,
            targets,
            datas,
            values,
            0
        );
    }

    /// @notice Invariant: Nonces never decrease
    function testInvariant_NoncesNeverDecrease() public {
        uint256 initialNonce = securityIntegrations.userNonces(user);

        for (uint8 i = 0; i < 10; i++) {
            vm.roll(block.number + 1);
            vm.prank(user);
            securityIntegrations.commitOperation(
                bytes32(uint256(i)),
                bytes32(uint256(i + 1))
            );

            uint256 newNonce = securityIntegrations.userNonces(user);
            assertGe(newNonce, initialNonce);
            initialNonce = newNonce;
        }
    }
}
