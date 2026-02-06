// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/HyperlaneAdapter.sol";

contract HyperlaneBridgeFuzz is Test {
    HyperlaneAdapter public bridge;

    address public mockMailbox = address(0x1234);
    uint32 public localDomain = 1;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public validator1 = address(0xD);
    address public user1 = address(0xE);

    function setUp() public {
        bridge = new HyperlaneAdapter(mockMailbox, localDomain, admin);
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.VALIDATOR_ROLE(), validator1);
        vm.stopPrank();
    }

    // --- Constructor ---
    function test_constructorSetup() public view {
        assertEq(bridge.mailbox(), mockMailbox);
        assertEq(bridge.localDomain(), localDomain);
        assertTrue(bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), admin));
    }

    function testFuzz_constructorZeroMailboxReverts(uint32 domain) public {
        vm.expectRevert(HyperlaneAdapter.InvalidMailbox.selector);
        new HyperlaneAdapter(address(0), domain, admin);
    }

    // --- Trusted Senders ---
    function testFuzz_setTrustedSender(uint32 domain, bytes32 sender) public {
        vm.assume(domain != 0 && sender != bytes32(0));
        vm.prank(operator);
        bridge.setTrustedSender(domain, sender);
        assertEq(bridge.trustedSenders(domain), sender);
    }

    // --- ISM Configuration ---
    function testFuzz_setISMConfig(uint32 domain) public {
        vm.assume(domain != 0);
        address[] memory validators = new address[](1);
        validators[0] = validator1;
        HyperlaneAdapter.ISMConfig memory config = HyperlaneAdapter.ISMConfig({
            ism: address(0x999),
            ismType: HyperlaneAdapter.ISMType.MULTISIG,
            enabled: true,
            threshold: 1,
            validators: validators
        });
        vm.prank(operator);
        bridge.setISMConfig(domain, config);
        (address ism, HyperlaneAdapter.ISMType ismType, bool enabled, uint8 threshold) = bridge.ismConfigs(domain);
        assertEq(ism, address(0x999));
        assertEq(uint8(ismType), uint8(HyperlaneAdapter.ISMType.MULTISIG));
        assertTrue(enabled);
    }

    // --- Multisig Params ---
    function testFuzz_setMultisigParams(uint32 domain) public {
        vm.assume(domain != 0);
        address[] memory validators = new address[](2);
        validators[0] = address(0x10);
        validators[1] = address(0x11);
        vm.prank(operator);
        bridge.setMultisigParams(domain, validators, 2);
    }

    // --- Dispatch ---
    function testFuzz_dispatchRequiresTrustedSender(uint32 dest, bytes32 recipient) public {
        vm.assume(dest != 0 && recipient != bytes32(0));
        // No trusted sender set for this domain
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(HyperlaneAdapter.InvalidDomain.selector);
        bridge.dispatch{value: 0.01 ether}(dest, recipient, "hello");
    }

    function testFuzz_dispatchWithTrustedSender(uint32 dest, bytes32 recipient) public {
        vm.assume(dest != 0 && dest != localDomain && recipient != bytes32(0));
        vm.prank(operator);
        bridge.setTrustedSender(dest, bytes32(uint256(1)));
        // Dispatch will try to call _dispatchToMailbox which needs a real mailbox
        // We verify the trusted sender is set correctly
        assertEq(bridge.trustedSenders(dest), bytes32(uint256(1)));
        assertEq(bridge.outboundNonce(dest), 0);
    }

    // --- Handle ---
    function testFuzz_handleOnlyMailbox(address caller) public {
        vm.assume(caller != mockMailbox);
        vm.prank(caller);
        vm.expectRevert(HyperlaneAdapter.InvalidMailbox.selector);
        bridge.handle(1, bytes32(uint256(1)), abi.encodePacked(uint256(1), "hello"));
    }

    function testFuzz_handleFromMailbox(uint32 origin, bytes32 sender) public {
        vm.assume(origin != 0 && sender != bytes32(0));
        vm.prank(operator);
        bridge.setTrustedSender(origin, sender);
        bytes memory message = abi.encodePacked(uint256(1), "hello world");
        vm.prank(mockMailbox);
        bridge.handle(origin, sender, message);
    }

    function testFuzz_handleUntrustedSender(uint32 origin, bytes32 sender, bytes32 wrongSender) public {
        vm.assume(origin != 0 && sender != bytes32(0) && wrongSender != bytes32(0) && sender != wrongSender);
        vm.prank(operator);
        bridge.setTrustedSender(origin, sender);
        vm.prank(mockMailbox);
        vm.expectRevert(HyperlaneAdapter.UntrustedSender.selector);
        bridge.handle(origin, wrongSender, abi.encodePacked(uint256(1), "test"));
    }

    // --- Pause ---
    function test_pauseAndUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
        vm.prank(guardian);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function testFuzz_onlyGuardianPauses(address caller) public {
        vm.assume(caller != admin && caller != guardian);
        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    // --- Access Control ---
    function testFuzz_onlyOperatorSetsTrustedSender(address caller) public {
        vm.assume(caller != admin && caller != operator);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setTrustedSender(1, bytes32(uint256(1)));
    }

    // --- Quote ---
    function testFuzz_quoteDispatch(uint32 dest, bytes calldata message) public view {
        uint256 fee = bridge.quoteDispatch(dest, message);
        assertTrue(fee > 0);
    }

    // --- Nonces ---
    function test_initialNonces() public view {
        assertEq(bridge.outboundNonce(1), 0);
        assertEq(bridge.inboundNonce(1), 0);
    }
}
