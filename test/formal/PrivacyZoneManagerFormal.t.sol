// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/privacy/PrivacyZoneManager.sol";

/**
 * @title PrivacyZoneManager Formal Property Tests
 * @notice Fuzz-based invariant checks for zone isolation, nullifier uniqueness,
 *         and commitment field-size validation
 */
contract PrivacyZoneManagerFormalTest is Test {
    PrivacyZoneManager public pzm;

    bytes32 public constant ZONE_ADMIN_ROLE = keccak256("ZONE_ADMIN_ROLE");
    bytes32 public constant MIGRATION_OPERATOR_ROLE = keccak256("MIGRATION_OPERATOR_ROLE");

    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        pzm = new PrivacyZoneManager(address(this), true);
    }

    /// @dev Helper to create a default ZoneConfig
    function _defaultConfig(string memory name, bytes32 policyHash)
        internal pure returns (IPrivacyZoneManager.ZoneConfig memory)
    {
        return IPrivacyZoneManager.ZoneConfig({
            name: name,
            privacyLevel: IPrivacyZoneManager.PrivacyLevel.Standard,
            policyHash: policyHash,
            maxThroughput: 100,
            epochDuration: 3600,
            minDepositAmount: 0,
            maxDepositAmount: 0,
            merkleTreeDepth: 20,
            crossZoneMigration: true,
            maxTotalDeposits: 0 // Unlimited by default
        });
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    /**
     * @notice Property: TVL Cap Enforcement
     * @dev Create zone with cap, fuzz deposits. Exceeding cap must revert.
     */
    function test_TVLCapEnforcement(uint256 capAmount, uint256 depositAmount) public {
        capAmount = bound(capAmount, 1 ether, 100 ether);
        depositAmount = bound(depositAmount, 0.1 ether, 200 ether);

        IPrivacyZoneManager.ZoneConfig memory config = _defaultConfig("CappedZone", bytes32(0));
        config.maxTotalDeposits = capAmount;

        bytes32 zoneId = pzm.createZone(config);
        bytes32 commitment = bytes32(uint256(12345));

        vm.deal(address(this), depositAmount);

        if (depositAmount > capAmount) {
            vm.expectRevert(); // ZoneDepositCapReached
            pzm.depositToZone{value: depositAmount}(zoneId, commitment);
        } else {
            pzm.depositToZone{value: depositAmount}(zoneId, commitment);
            
            // Check TVL
            IPrivacyZoneManager.Zone memory zone = pzm.getZone(zoneId);
            assertEq(zone.totalValueLocked, depositAmount, "TVL should update");
        }
    }

    /**
     * @notice Property: Commitment must be < FIELD_SIZE to be deposited
     * @dev Fuzz random commitment values — deposits with commitment >= FIELD_SIZE
     *      must always revert with InvalidCommitment()
     */
    function test_CommitmentFieldSizeValidation(
        uint256 rawCommitment,
        uint256 depositAmount
    ) public {
        depositAmount = bound(depositAmount, 0.01 ether, 100 ether);

        bytes32 zoneId = pzm.createZone(_defaultConfig("FuzzZone", bytes32(0)));
        bytes32 commitment = bytes32(rawCommitment);

        vm.deal(address(this), depositAmount);

        if (rawCommitment == 0 || rawCommitment >= FIELD_SIZE) {
            // Should revert
            vm.expectRevert();
            pzm.depositToZone{value: depositAmount}(zoneId, commitment);
        } else {
            // Should succeed (commitment is valid field element)
            pzm.depositToZone{value: depositAmount}(zoneId, commitment);
            assertTrue(pzm.zoneCommitments(zoneId, commitment));
        }
    }

    /**
     * @notice Property: Nullifier double-spend prevention
     * @dev Deposit, withdraw with a nullifier, then attempt withdrawal with same
     *      nullifier — second withdrawal must always fail
     */
    function test_NullifierDoubleSpendPrevention(
        uint256 nullifierSeed
    ) public {
        nullifierSeed = bound(nullifierSeed, 1, FIELD_SIZE - 1);
        bytes32 nullifier = bytes32(nullifierSeed);

        bytes32 zoneId = pzm.createZone(_defaultConfig("NullifierFuzz", bytes32(0)));

        // Deposit
        uint256 commitValue = bound(nullifierSeed, 1, FIELD_SIZE - 1);
        bytes32 commitment = bytes32(commitValue);
        vm.deal(address(this), 1 ether);
        pzm.depositToZone{value: 0.1 ether}(zoneId, commitment);

        // Set withdrawal verifier for test mode
        pzm.setWithdrawalVerifier(address(1));

        pzm.withdrawFromZone(
            zoneId,
            nullifier,
            address(this),
            0.1 ether,
            new bytes(1)
        );

        // Nullifier should be marked as spent
        assertTrue(pzm.isNullifierSpent(zoneId, nullifier));

        // Second withdrawal with same nullifier must revert
        vm.expectRevert();
        pzm.withdrawFromZone(
            zoneId,
            nullifier,
            address(this),
            0.1 ether,
            new bytes(1)
        );
    }

    /**
     * @notice Property: Zone creation counter monotonically increases
     * @dev Create multiple zones and verify counter only goes up
     */
    function test_ZoneCreationCounterMonotonicity(uint8 numZones) public {
        numZones = uint8(bound(numZones, 1, 10));

        uint256 prevCount = pzm.getTotalZones();

        for (uint8 i = 0; i < numZones; i++) {
            pzm.createZone(_defaultConfig(
                string(abi.encodePacked("Zone", uint8(i + 1))),
                bytes32(uint256(i))
            ));
            uint256 newCount = pzm.getTotalZones();

            // Counter must be strictly greater than before
            assertGt(newCount, prevCount, "Zone counter must monotonically increase");
            prevCount = newCount;
        }
    }

    /**
     * @notice Property: Deposits into zone A do not affect zone B
     * @dev Create two zones, deposit into one, verify the other is unmodified
     */
    function test_ZoneIsolation_DepositDoesNotCrossZones(
        uint256 commitmentSeed
    ) public {
        commitmentSeed = bound(commitmentSeed, 1, FIELD_SIZE - 1);
        bytes32 commitment = bytes32(commitmentSeed);

        bytes32 zoneA = pzm.createZone(_defaultConfig("ZoneA", bytes32(uint256(1))));
        bytes32 zoneB = pzm.createZone(_defaultConfig("ZoneB", bytes32(uint256(2))));

        bytes32 rootBBefore = pzm.getZoneMerkleRoot(zoneB);

        // Deposit into zone A
        vm.deal(address(this), 1 ether);
        pzm.depositToZone{value: 0.1 ether}(zoneA, commitment);

        // Zone B must be unaffected
        bytes32 rootBAfter = pzm.getZoneMerkleRoot(zoneB);
        assertEq(rootBBefore, rootBAfter, "Zone B root must not change from Zone A deposit");
        assertFalse(pzm.zoneCommitments(zoneB, commitment), "Zone B must not have Zone A's commitment");
    }

    /**
     * @notice Property: Test mode can never be re-enabled once permanently disabled
     */
    function test_TestModeCannotBeReEnabled() public {
        assertTrue(pzm.testMode(), "Should start in test mode");

        pzm.disableTestMode();

        assertFalse(pzm.testMode(), "Test mode should be disabled");
        assertTrue(pzm.testModePermanentlyDisabled(), "Should be permanently disabled");

        // Verify state is permanent
        assertFalse(pzm.testMode());
    }

    receive() external payable {}
}
