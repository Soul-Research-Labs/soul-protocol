// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/HyperlaneAdapter.sol";
import {BridgeAdapterBase} from "../../contracts/crosschain/base/BridgeAdapterBase.sol";

contract HyperlaneAdapterTest is Test {
    HyperlaneAdapter adapter;
    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address guardian = address(0x6A1);
    address mailbox = address(0xA11);
    address igp = address(0x169);
    address user = address(0xBEEF);
    address treasury = address(0x7EA5);
    uint32 localDomain = 1; // Ethereum

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    function setUp() public {
        adapter = new HyperlaneAdapter(admin, mailbox, igp, localDomain);
        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(GUARDIAN_ROLE, guardian);
        adapter.grantRole(RELAYER_ROLE, operator);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_InitialState() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, operator));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, guardian));
        assertEq(adapter.mailbox(), mailbox);
        assertEq(adapter.igp(), igp);
        assertEq(adapter.localDomain(), localDomain);
        assertEq(adapter.bridgeFeeBps(), 10);
    }

    function test_Constructor_RevertZeroAdmin() public {
        vm.expectRevert(BridgeAdapterBase.ZeroAddress.selector);
        new HyperlaneAdapter(address(0), mailbox, igp, localDomain);
    }

    function test_Constructor_RevertZeroMailbox() public {
        vm.expectRevert(BridgeAdapterBase.ZeroAddress.selector);
        new HyperlaneAdapter(admin, address(0), igp, localDomain);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureDomain() public {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.configureDomain(42161, router, address(0), 200_000);

        (
            uint32 domain,
            ,
            bytes32 storedRouter,
            address ism,
            uint256 gasOverhead,
            bool active
        ) = adapter.domains(42161);
        assertEq(domain, 42161);
        assertEq(storedRouter, router);
        assertEq(ism, address(0));
        assertEq(gasOverhead, 200_000);
        assertTrue(active);
    }

    function test_ConfigureDomain_RevertZeroRouter() public {
        vm.prank(operator);
        vm.expectRevert(HyperlaneAdapter.InvalidRouter.selector);
        adapter.configureDomain(42161, bytes32(0), address(0), 200_000);
    }

    function test_ConfigureDomain_RevertNonOperator() public {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(user);
        vm.expectRevert();
        adapter.configureDomain(42161, router, address(0), 200_000);
    }

    function test_ConfigureISM() public {
        address[] memory validators = new address[](3);
        validators[0] = address(0x1);
        validators[1] = address(0x2);
        validators[2] = address(0x3);

        vm.prank(operator);
        adapter.configureISM(
            42161,
            HyperlaneAdapter.ISMType.MULTISIG,
            address(0xAAA),
            2,
            validators
        );

        (
            HyperlaneAdapter.ISMType ismType,
            address ismAddr,
            uint8 threshold
        ) = adapter.ismConfigs(42161);
        assertEq(uint8(ismType), uint8(HyperlaneAdapter.ISMType.MULTISIG));
        assertEq(ismAddr, address(0xAAA));
        assertEq(threshold, 2);
    }

    /*//////////////////////////////////////////////////////////////
                         DISPATCH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Dispatch_RevertDomainNotConfigured() public {
        bytes32 recipient = bytes32(uint256(uint160(address(0xDEAD))));
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                HyperlaneAdapter.DomainNotConfigured.selector,
                uint32(42161)
            )
        );
        adapter.dispatch{value: 0.1 ether}(42161, recipient, "hello");
    }

    function test_Dispatch_RevertZeroRecipient() public {
        _configureDomain(42161);

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(HyperlaneAdapter.ZeroRecipient.selector);
        adapter.dispatch{value: 0.1 ether}(42161, bytes32(0), "hello");
    }

    function test_Dispatch_RevertMessageBodyTooLarge() public {
        _configureDomain(42161);
        bytes memory oversized = new bytes(65537);
        bytes32 recipient = bytes32(uint256(uint160(address(0xDEAD))));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                HyperlaneAdapter.MessageBodyTooLarge.selector,
                uint256(65537),
                uint256(65536)
            )
        );
        adapter.dispatch{value: 0.1 ether}(42161, recipient, oversized);
    }

    function test_Dispatch_RevertWhenPaused() public {
        _configureDomain(42161);
        bytes32 recipient = bytes32(uint256(uint160(address(0xDEAD))));

        vm.prank(guardian);
        adapter.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.dispatch{value: 0.1 ether}(42161, recipient, "hello");
    }

    /*//////////////////////////////////////////////////////////////
                        HANDLE (RECEIVE) TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Handle_RevertUnauthorizedMailbox() public {
        bytes32 sender = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(user); // Not the mailbox
        vm.expectRevert(HyperlaneAdapter.UnauthorizedMailbox.selector);
        adapter.handle(42161, sender, "hello");
    }

    function test_Handle_RevertDomainNotConfigured() public {
        bytes32 sender = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(mailbox);
        vm.expectRevert(
            abi.encodeWithSelector(
                HyperlaneAdapter.DomainNotConfigured.selector,
                uint32(42161)
            )
        );
        adapter.handle(42161, sender, "hello");
    }

    function test_Handle_RevertUnauthorizedSender() public {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.configureDomain(42161, router, address(0), 200_000);

        bytes32 wrongSender = bytes32(uint256(uint160(address(0xBAD))));
        vm.prank(mailbox);
        vm.expectRevert(
            abi.encodeWithSelector(
                HyperlaneAdapter.UnauthorizedSender.selector,
                uint32(42161),
                wrongSender
            )
        );
        adapter.handle(42161, wrongSender, "hello");
    }

    function test_Handle_Success() public {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.configureDomain(42161, router, address(0), 200_000);

        vm.prank(mailbox);
        adapter.handle(42161, router, "hello");

        assertEq(adapter.totalDelivered(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                       FEE ESTIMATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_QuoteDispatch() public {
        _configureDomain(42161);

        uint256 fee = adapter.quoteDispatch(42161, "hello");
        assertGt(fee, 0);
    }

    function test_QuoteDispatch_RevertUnconfigured() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                HyperlaneAdapter.DomainNotConfigured.selector,
                uint32(99999)
            )
        );
        adapter.quoteDispatch(99999, "hello");
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetFee() public {
        vm.prank(operator);
        adapter.setFee(50);
        assertEq(adapter.bridgeFeeBps(), 50);
    }

    function test_SetFee_RevertTooHigh() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                HyperlaneAdapter.FeeTooHigh.selector,
                uint256(101)
            )
        );
        adapter.setFee(101);
    }

    function test_SetTreasury() public {
        vm.prank(operator);
        adapter.setTreasury(treasury);
        assertEq(adapter.treasury(), treasury);
    }

    function test_SetTreasury_RevertZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(BridgeAdapterBase.ZeroAddress.selector);
        adapter.setTreasury(address(0));
    }

    function test_SetDefaultISM() public {
        vm.prank(operator);
        adapter.setDefaultISM(address(0xBBB));
        assertEq(adapter.defaultISM(), address(0xBBB));
    }

    function test_DisableDomain() public {
        _configureDomain(42161);

        vm.prank(guardian);
        adapter.disableDomain(42161);

        (, , , , , bool active) = adapter.domains(42161);
        assertFalse(active);
    }

    function test_InterchainSecurityModule_Default() public {
        vm.prank(operator);
        adapter.setDefaultISM(address(0xBBB));

        // No specific ISM for domain 42161 => returns default
        assertEq(adapter.interchainSecurityModule(42161), address(0xBBB));
    }

    function test_InterchainSecurityModule_Custom() public {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.configureDomain(42161, router, address(0xCCC), 200_000);

        assertEq(adapter.interchainSecurityModule(42161), address(0xCCC));
    }

    /*//////////////////////////////////////////////////////////////
                       PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(guardian);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_Unpause() public {
        vm.prank(guardian);
        adapter.pause();
        vm.prank(guardian);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_Pause_RevertNonGuardian() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    /*//////////////////////////////////////////////////////////////
                   IBridgeAdapter COMPATIBILITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_BridgeMessage_RevertsUnmappedChain() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        // Payload encodes chainId=999 (unmapped) + actual message
        bytes memory payload = abi.encodePacked(uint256(999), bytes("hello"));
        vm.expectRevert();
        adapter.bridgeMessage{value: 0.1 ether}(
            address(0x1),
            payload,
            address(0)
        );
    }

    function test_EstimateFee_IBridgeAdapter_Reverts() public {
        vm.expectRevert();
        adapter.estimateFee(address(0x1), "");
    }

    function test_IsMessageVerified_DefaultFalse() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(1))));
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetUserMessages_Empty() public view {
        bytes32[] memory msgs = adapter.getUserMessages(user);
        assertEq(msgs.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetFee(uint256 feeBps) public {
        vm.prank(operator);
        if (feeBps > 100) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    HyperlaneAdapter.FeeTooHigh.selector,
                    feeBps
                )
            );
        }
        adapter.setFee(feeBps);
    }

    function testFuzz_ConfigureDomain(
        uint32 domain,
        uint256 gasOverhead
    ) public {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.configureDomain(domain, router, address(0), gasOverhead);
        (uint32 storedDomain, , , , , bool active) = adapter.domains(domain);
        assertEq(storedDomain, domain);
        assertTrue(active);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPERS
    //////////////////////////////////////////////////////////////*/

    function _configureDomain(uint32 domain) internal {
        bytes32 router = bytes32(uint256(uint160(address(0xDEAD))));
        vm.prank(operator);
        adapter.configureDomain(domain, router, address(0), 200_000);
    }
}
