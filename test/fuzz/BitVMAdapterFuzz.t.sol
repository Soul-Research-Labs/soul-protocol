// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BitVMAdapter.sol";

contract BitVMAdapterFuzzTest is Test {
    BitVMAdapter internal adapter;

    address internal admin = address(0xA11CE);
    address internal user = address(0xCAFE);
    address internal target = address(0xD00D);
    address internal treasury = address(0x7EA5);

    function setUp() public {
        adapter = new BitVMAdapter(admin, treasury);
        vm.deal(user, 100 ether);
    }

    function testFuzz_EstimateFee_Monotonic(
        uint16 payloadSizeA,
        uint16 payloadSizeB
    ) public view {
        payloadSizeA = uint16(bound(payloadSizeA, 0, 32_768));
        payloadSizeB = uint16(bound(payloadSizeB, 0, 32_768));

        bytes memory payloadA = _payloadOfSize(payloadSizeA);
        bytes memory payloadB = _payloadOfSize(payloadSizeB);

        uint256 feeA = adapter.estimateFee(target, payloadA);
        uint256 feeB = adapter.estimateFee(target, payloadB);

        if (payloadSizeA >= payloadSizeB) {
            assertGe(feeA, feeB);
        } else {
            assertGe(feeB, feeA);
        }
    }

    function testFuzz_BridgeMessage_UniqueIdsByNonce(
        uint16 payloadSize,
        uint96 extra
    ) public {
        payloadSize = uint16(bound(payloadSize, 1, 32_768));
        bytes memory payload = _payloadOfSize(payloadSize);
        uint256 fee = adapter.estimateFee(target, payload);

        vm.prank(user);
        bytes32 id1 = adapter.bridgeMessage{value: fee + extra}(
            target,
            payload,
            user
        );

        vm.prank(user);
        bytes32 id2 = adapter.bridgeMessage{value: fee + extra}(
            target,
            payload,
            user
        );

        assertTrue(id1 != id2);
    }

    function testFuzz_BridgeMessage_RevertWhenPayloadTooLarge(
        uint16 oversize
    ) public {
        oversize = uint16(bound(oversize, 1, 4096));
        uint256 size = 32_768 + oversize;
        bytes memory payload = _payloadOfSize(size);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.PayloadTooLarge.selector,
                uint256(size),
                uint256(32_768)
            )
        );
        adapter.bridgeMessage{value: 1 ether}(target, payload, user);
    }

    function testFuzz_SetFeeParams_WithinBounds(
        uint64 baseFee,
        uint64 perByteFee,
        uint16 bps
    ) public {
        uint256 boundedBaseFee = bound(baseFee, 0, 0.1 ether);
        uint256 boundedPerByteFee = bound(perByteFee, 0, 100 gwei);
        uint256 boundedBps = bound(bps, 0, 100);

        vm.prank(admin);
        adapter.setFeeParams(boundedBaseFee, boundedPerByteFee, boundedBps);

        assertEq(adapter.baseFee(), boundedBaseFee);
        assertEq(adapter.perByteFee(), boundedPerByteFee);
        assertEq(adapter.bridgeFeeBps(), boundedBps);
    }

    function _payloadOfSize(uint256 size) internal pure returns (bytes memory p) {
        p = new bytes(size);
        if (size > 0) {
            p[size - 1] = bytes1(uint8(size));
        }
    }
}
