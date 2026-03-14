// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/UnifiedRelayerFacade.sol";
import "../../contracts/interfaces/IUnifiedRelayerRegistry.sol";

/// @dev Mock DecentralizedRelayerRegistry for testing
contract MockDecentralizedRegistry {
    struct RelayerInfo {
        uint256 stake;
        uint256 registeredAt;
        uint256 unlockTime;
        bool isRegistered;
    }

    mapping(address => RelayerInfo) public relayers;
    uint256 public activeCount;

    function setRelayer(
        address relayer,
        uint256 stake,
        bool registered,
        uint256 unlockTime
    ) external {
        relayers[relayer] = RelayerInfo(
            stake,
            block.timestamp,
            unlockTime,
            registered
        );
        if (registered && unlockTime == 0) activeCount++;
    }

    function getActiveRelayerCount() external view returns (uint256) {
        return activeCount;
    }

    bool public slashCalled;
    address public slashedRelayer;
    uint256 public slashedAmount;

    function slash(address relayer, uint256 amount, address) external {
        slashCalled = true;
        slashedRelayer = relayer;
        slashedAmount = amount;
    }
}

/// @dev Mock RelayerStaking (token-based) for testing
contract MockTokenStaking {
    mapping(address => bool) public activeRelayers;
    uint256 public count;

    function setActive(address relayer, bool active) external {
        activeRelayers[relayer] = active;
        if (active) count++;
    }

    function isActiveRelayer(address relayer) external view returns (bool) {
        return activeRelayers[relayer];
    }

    function getActiveRelayerCount() external view returns (uint256) {
        return count;
    }

    // Return a mock relayer struct with 224 bytes (8 x 32-byte slots)
    function relayers(
        address
    )
        external
        pure
        returns (
            uint256 stakedAmount,
            uint256 registeredAt,
            uint256 unlockTime,
            uint256 slashCount,
            uint256 successfulRelays,
            uint256 failedRelays,
            bool isActive,
            string memory name
        )
    {
        return (500 ether, 1000, 0, 0, 10, 1, true, "mock");
    }

    bool public slashCalled;

    function slash(address, string calldata) external {
        slashCalled = true;
    }
}

contract UnifiedRelayerFacadeTest is Test {
    UnifiedRelayerFacade public facade;
    MockDecentralizedRegistry public decentralized;
    MockTokenStaking public tokenStaking;

    address public admin = address(this);
    address public relayerA = address(0xA);
    address public relayerB = address(0xB);
    address public relayerC = address(0xC);
    address public nonRelayer = address(0xDEAD);

    function setUp() public {
        decentralized = new MockDecentralizedRegistry();
        tokenStaking = new MockTokenStaking();

        facade = new UnifiedRelayerFacade(
            admin,
            address(decentralized),
            address(0), // no heterogeneous registry for this test
            address(tokenStaking)
        );

        // Register relayerA in decentralized registry
        decentralized.setRelayer(relayerA, 1 ether, true, 0);

        // Register relayerB in token staking
        tokenStaking.setActive(relayerB, true);
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    function test_constructor_setsAdmin() public view {
        assertTrue(facade.hasRole(facade.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(facade.hasRole(facade.SLASHER_ROLE(), admin));
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(UnifiedRelayerFacade.ZeroAdmin.selector);
        new UnifiedRelayerFacade(
            address(0),
            address(decentralized),
            address(0),
            address(tokenStaking)
        );
    }

    function test_constructor_setsRegistryAddresses() public view {
        assertEq(facade.decentralizedRegistry(), address(decentralized));
        assertEq(facade.heterogeneousRegistry(), address(0));
        assertEq(facade.tokenStakingRegistry(), address(tokenStaking));
    }

    // =========================================================================
    // isActiveRelayer
    // =========================================================================

    function test_isActiveRelayer_decentralizedRelayer() public view {
        assertTrue(facade.isActiveRelayer(relayerA));
    }

    function test_isActiveRelayer_tokenStakingRelayer() public view {
        assertTrue(facade.isActiveRelayer(relayerB));
    }

    function test_isActiveRelayer_nonRelayerReturnsFalse() public view {
        assertFalse(facade.isActiveRelayer(nonRelayer));
    }

    function test_isActiveRelayer_unbondingRelayerReturnsFalse() public {
        // Relayer with unlockTime > 0 is unbonding, not active
        decentralized.setRelayer(
            relayerC,
            1 ether,
            true,
            block.timestamp + 1 days
        );
        assertFalse(facade.isActiveRelayer(relayerC));
    }

    function test_isActiveRelayer_zeroStakeReturnsFalse() public {
        decentralized.setRelayer(relayerC, 0, true, 0);
        assertFalse(facade.isActiveRelayer(relayerC));
    }

    // =========================================================================
    // getRelayer
    // =========================================================================

    function test_getRelayer_decentralizedSource() public view {
        IUnifiedRelayerRegistry.RelayerView memory v = facade.getRelayer(
            relayerA
        );
        assertEq(v.relayerAddress, relayerA);
        assertEq(
            uint256(v.source),
            uint256(IUnifiedRelayerRegistry.RegistrySource.DECENTRALIZED)
        );
        assertEq(v.stakedAmount, 1 ether);
        assertTrue(v.isActive);
    }

    function test_getRelayer_nonRelayerReturnsNoneSource() public view {
        IUnifiedRelayerRegistry.RelayerView memory v = facade.getRelayer(
            nonRelayer
        );
        assertEq(v.relayerAddress, nonRelayer);
        assertEq(
            uint256(v.source),
            uint256(IUnifiedRelayerRegistry.RegistrySource.NONE)
        );
    }

    // =========================================================================
    // totalActiveRelayers
    // =========================================================================

    function test_totalActiveRelayers_sumsAcrossRegistries() public view {
        uint256 total = facade.totalActiveRelayers();
        // 1 from decentralized + 1 from token staking
        assertEq(total, 2);
    }

    // =========================================================================
    // slash
    // =========================================================================

    function test_slash_decentralizedRelayer() public {
        facade.slash(relayerA, 0.5 ether, "test slash");
        assertTrue(decentralized.slashCalled());
        assertEq(decentralized.slashedRelayer(), relayerA);
        assertEq(decentralized.slashedAmount(), 0.5 ether);
    }

    function test_slash_tokenStakingRelayer() public {
        facade.slash(relayerB, 0.5 ether, "test slash");
        assertTrue(tokenStaking.slashCalled());
    }

    function test_slash_revertsForNonRelayer() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnifiedRelayerRegistry.RelayerNotFound.selector,
                nonRelayer
            )
        );
        facade.slash(nonRelayer, 0.5 ether, "should fail");
    }

    function test_slash_revertsForNonSlasherRole() public {
        vm.prank(relayerA);
        vm.expectRevert();
        facade.slash(relayerB, 0.5 ether, "unauthorized");
    }

    // =========================================================================
    // setRegistries
    // =========================================================================

    function test_setRegistries_updatesAddresses() public {
        address newDec = address(0x111);
        address newHet = address(0x222);
        address newTok = address(0x333);

        facade.setRegistries(newDec, newHet, newTok);
        assertEq(facade.decentralizedRegistry(), newDec);
        assertEq(facade.heterogeneousRegistry(), newHet);
        assertEq(facade.tokenStakingRegistry(), newTok);
    }

    function test_setRegistries_revertsForNonAdmin() public {
        vm.prank(relayerA);
        vm.expectRevert();
        facade.setRegistries(address(0), address(0), address(0));
    }

    // =========================================================================
    // RECEIVE ETH
    // =========================================================================

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        (bool sent, ) = address(facade).call{value: 0.5 ether}("");
        assertTrue(sent);
        assertEq(address(facade).balance, 0.5 ether);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_isActiveRelayer_neverRevertsOnRandomAddress(
        address random
    ) public view {
        // Should never revert, just return true or false
        facade.isActiveRelayer(random);
    }

    function testFuzz_getRelayer_neverReverts(address random) public view {
        IUnifiedRelayerRegistry.RelayerView memory v = facade.getRelayer(
            random
        );
        // Non-relayer should always return NONE source
        if (random != relayerA && random != relayerB) {
            assertEq(
                uint256(v.source),
                uint256(IUnifiedRelayerRegistry.RegistrySource.NONE)
            );
        }
    }
}
