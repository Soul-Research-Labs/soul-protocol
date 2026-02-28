// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/governance/ZaseonToken.sol";

contract ZaseonTokenTest is Test {
    ZaseonToken public token;

    address public admin = makeAddr("admin");
    address public minter = makeAddr("minter");
    address public treasury = makeAddr("treasury");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public charlie = makeAddr("charlie");

    uint256 constant INITIAL_MINT = 100_000_000e18; // 100M

    event TokensBurned(address indexed burner, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 value);

    function setUp() public {
        token = new ZaseonToken(admin, treasury, INITIAL_MINT);

        // Grant minter role to minter address
        bytes32 minterRole = token.MINTER_ROLE();
        vm.prank(admin);
        token.grantRole(minterRole, minter);
    }

    /*//////////////////////////////////////////////////////////////
                        DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Name() public view {
        assertEq(token.name(), "ZASEON");
    }

    function test_Symbol() public view {
        assertEq(token.symbol(), "ZASEON");
    }

    function test_Decimals() public view {
        assertEq(token.decimals(), 18);
    }

    function test_MaxSupply() public view {
        assertEq(token.cap(), 1_000_000_000e18);
    }

    function test_InitialMint() public view {
        assertEq(token.balanceOf(treasury), INITIAL_MINT);
        assertEq(token.totalSupply(), INITIAL_MINT);
    }

    function test_AdminHasRoles() public view {
        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(token.hasRole(token.MINTER_ROLE(), admin));
    }

    function test_Constructor_ZeroAdmin_Reverts() public {
        vm.expectRevert(ZaseonToken.ZeroAddress.selector);
        new ZaseonToken(address(0), treasury, INITIAL_MINT);
    }

    function test_Constructor_ZeroRecipient_Reverts() public {
        vm.expectRevert(ZaseonToken.ZeroAddress.selector);
        new ZaseonToken(admin, address(0), INITIAL_MINT);
    }

    function test_Constructor_ZeroInitialMint() public {
        ZaseonToken t = new ZaseonToken(admin, treasury, 0);
        assertEq(t.totalSupply(), 0);
        assertEq(t.balanceOf(treasury), 0);
    }

    /*//////////////////////////////////////////////////////////////
                          MINTING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Mint_ByMinter() public {
        vm.prank(minter);
        token.mint(alice, 1000e18);
        assertEq(token.balanceOf(alice), 1000e18);
    }

    function test_Mint_ByAdmin() public {
        vm.prank(admin);
        token.mint(alice, 500e18);
        assertEq(token.balanceOf(alice), 500e18);
    }

    function test_Mint_Unauthorized_Reverts() public {
        vm.prank(alice);
        vm.expectRevert();
        token.mint(alice, 100e18);
    }

    function test_Mint_ZeroAmount_Reverts() public {
        vm.prank(minter);
        vm.expectRevert(ZaseonToken.MintAmountZero.selector);
        token.mint(alice, 0);
    }

    function test_Mint_ZeroAddress_Reverts() public {
        vm.prank(minter);
        vm.expectRevert(ZaseonToken.ZeroAddress.selector);
        token.mint(address(0), 100e18);
    }

    function test_Mint_ExceedsCap_Reverts() public {
        // Already have 100M minted. Try to mint 901M more (exceeds 1B cap)
        vm.prank(minter);
        vm.expectRevert();
        token.mint(alice, 901_000_000e18);
    }

    function test_Mint_UpToCap() public {
        uint256 remaining = token.cap() - token.totalSupply();
        vm.prank(minter);
        token.mint(alice, remaining);
        assertEq(token.totalSupply(), token.cap());
    }

    /*//////////////////////////////////////////////////////////////
                          BURNING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Burn() public {
        vm.prank(admin);
        token.mint(alice, 1000e18);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit TokensBurned(alice, 300e18);
        token.burn(300e18);

        assertEq(token.balanceOf(alice), 700e18);
    }

    function test_Burn_ZeroAmount_Reverts() public {
        vm.prank(alice);
        vm.expectRevert(ZaseonToken.BurnAmountZero.selector);
        token.burn(0);
    }

    function test_Burn_ExceedsBalance_Reverts() public {
        vm.prank(alice);
        vm.expectRevert();
        token.burn(1);
    }

    function test_Burn_ReducesSupply() public {
        uint256 supplyBefore = token.totalSupply();

        vm.prank(treasury);
        token.burn(1000e18);

        assertEq(token.totalSupply(), supplyBefore - 1000e18);
    }

    /*//////////////////////////////////////////////////////////////
                      DELEGATION & VOTING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SelfDelegate_ActivatesVotingPower() public {
        vm.prank(admin);
        token.mint(alice, 1_000_000e18);

        // Before delegation: no voting power
        assertEq(token.getVotes(alice), 0);

        // Self-delegate
        vm.prank(alice);
        token.delegate(alice);

        // After delegation: full voting power
        assertEq(token.getVotes(alice), 1_000_000e18);
    }

    function test_DelegateToOther() public {
        vm.prank(admin);
        token.mint(alice, 1_000_000e18);

        vm.prank(alice);
        token.delegate(bob);

        assertEq(token.getVotes(alice), 0);
        assertEq(token.getVotes(bob), 1_000_000e18);
        assertEq(token.delegates(alice), bob);
    }

    function test_VotingPower_Snapshot() public {
        vm.warp(100); // Start at known timestamp

        vm.prank(admin);
        token.mint(alice, 1_000_000e18);

        vm.prank(alice);
        token.delegate(alice);

        vm.warp(200); // Advance time

        // Mint more
        vm.prank(admin);
        token.mint(alice, 500_000e18);

        vm.warp(300); // Advance past the second checkpoint

        // Past checkpoint should still show old balance
        assertEq(token.getPastVotes(alice, 100), 1_000_000e18);

        // Second checkpoint should show new balance
        assertEq(token.getPastVotes(alice, 200), 1_500_000e18);

        // Current should show new balance
        assertEq(token.getVotes(alice), 1_500_000e18);
    }

    function test_TransferUpdatesVotingPower() public {
        vm.prank(admin);
        token.mint(alice, 1_000_000e18);

        vm.prank(alice);
        token.delegate(alice);
        vm.prank(bob);
        token.delegate(bob);

        // Transfer half to bob
        vm.prank(alice);
        token.transfer(bob, 500_000e18);

        assertEq(token.getVotes(alice), 500_000e18);
        assertEq(token.getVotes(bob), 500_000e18);
    }

    /*//////////////////////////////////////////////////////////////
                        CLOCK MODE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ClockMode() public view {
        assertEq(token.CLOCK_MODE(), "mode=timestamp&from=default");
    }

    function test_Clock() public view {
        assertEq(token.clock(), uint48(block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                        PERMIT TESTS (EIP-2612)
    //////////////////////////////////////////////////////////////*/

    function test_PermitTypehash() public view {
        // Just verify permit nonces work
        assertEq(token.nonces(alice), 0);
    }

    /*//////////////////////////////////////////////////////////////
                      ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GrantMinterRole() public {
        bytes32 minterRole = token.MINTER_ROLE();
        vm.prank(admin);
        token.grantRole(minterRole, charlie);

        vm.prank(charlie);
        token.mint(alice, 100e18);
        assertEq(token.balanceOf(alice), 100e18);
    }

    function test_RevokeMinterRole() public {
        bytes32 minterRole = token.MINTER_ROLE();
        vm.prank(admin);
        token.revokeRole(minterRole, minter);

        vm.prank(minter);
        vm.expectRevert();
        token.mint(alice, 100e18);
    }

    function test_SupportsInterface() public view {
        // ERC165 interface for AccessControl
        assertTrue(token.supportsInterface(type(IAccessControl).interfaceId));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_Mint(uint256 amount) public {
        uint256 remaining = token.cap() - token.totalSupply();
        amount = bound(amount, 1, remaining);

        vm.prank(minter);
        token.mint(alice, amount);
        assertEq(token.balanceOf(alice), amount);
    }

    function testFuzz_Transfer(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_MINT);

        vm.prank(treasury);
        token.transfer(alice, amount);

        assertEq(token.balanceOf(alice), amount);
        assertEq(token.balanceOf(treasury), INITIAL_MINT - amount);
    }

    function testFuzz_BurnReducesSupply(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_MINT);
        uint256 supplyBefore = token.totalSupply();

        vm.prank(treasury);
        token.burn(amount);

        assertEq(token.totalSupply(), supplyBefore - amount);
    }

    /*//////////////////////////////////////////////////////////////
                    GOVERNANCE INTEGRATION TEST
    //////////////////////////////////////////////////////////////*/

    function test_MultipleVoters_TotalVotingPower() public {
        vm.startPrank(admin);
        token.mint(alice, 5_000_000e18);
        token.mint(bob, 3_000_000e18);
        token.mint(charlie, 2_000_000e18);
        vm.stopPrank();

        vm.prank(alice);
        token.delegate(alice);
        vm.prank(bob);
        token.delegate(bob);
        vm.prank(charlie);
        token.delegate(charlie);

        uint256 totalVotes = token.getVotes(alice) +
            token.getVotes(bob) +
            token.getVotes(charlie);
        assertEq(totalVotes, 10_000_000e18);

        // Treasury hasn't delegated
        assertEq(token.getVotes(treasury), 0);
    }

    function test_ReDelegate() public {
        vm.prank(admin);
        token.mint(alice, 1_000_000e18);

        // Delegate to bob
        vm.prank(alice);
        token.delegate(bob);
        assertEq(token.getVotes(bob), 1_000_000e18);

        // Re-delegate to charlie
        vm.prank(alice);
        token.delegate(charlie);
        assertEq(token.getVotes(bob), 0);
        assertEq(token.getVotes(charlie), 1_000_000e18);
    }
}
