// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/ValidationLib.sol";

/// @dev Wrapper to expose ValidationLib internal functions for testing
contract ValidationLibHarness {
    function requireNonZeroAddress(address addr) external pure {
        ValidationLib.requireNonZeroAddress(addr);
    }

    function requireNonZeroAddresses(address[] memory addrs) external pure {
        ValidationLib.requireNonZeroAddresses(addrs);
    }

    function requireNonZeroAddresses2(address a, address b) external pure {
        ValidationLib.requireNonZeroAddresses(a, b);
    }

    function requireNonZeroValue(uint256 value) external pure {
        ValidationLib.requireNonZeroValue(value);
    }

    function requireInBounds(
        uint256 value,
        uint256 min,
        uint256 max
    ) external pure {
        ValidationLib.requireInBounds(value, min, max);
    }

    function requireBelowThreshold(
        uint256 value,
        uint256 threshold
    ) external pure {
        ValidationLib.requireBelowThreshold(value, threshold);
    }

    function requireNonEmptyArray(uint256 length) external pure {
        ValidationLib.requireNonEmptyArray(length);
    }

    function requireMatchingLengths(uint256 len1, uint256 len2) external pure {
        ValidationLib.requireMatchingLengths(len1, len2);
    }

    function requireValidBatchSize(
        uint256 size,
        uint256 maxSize
    ) external pure {
        ValidationLib.requireValidBatchSize(size, maxSize);
    }

    function requireNotExpired(uint256 deadline) external view {
        ValidationLib.requireNotExpired(deadline);
    }

    function requireExpired(uint256 deadline) external view {
        ValidationLib.requireExpired(deadline);
    }

    function requireValidDestinationChain(uint256 chainId) external view {
        ValidationLib.requireValidDestinationChain(chainId);
    }

    function requireNonEmptyBytes(bytes calldata data) external pure {
        ValidationLib.requireNonEmptyBytes(data);
    }

    function requireNonZeroBytes32(bytes32 value) external pure {
        ValidationLib.requireNonZeroBytes32(value);
    }

    function validateTransfer(address recipient, uint256 amount) external pure {
        ValidationLib.validateTransfer(recipient, amount);
    }
}

contract ValidationLibTest is Test {
    ValidationLibHarness public lib;

    function setUp() public {
        lib = new ValidationLibHarness();
    }

    /* ── Address Validation ─────────────────────────── */

    function test_requireNonZeroAddress_passes() public view {
        lib.requireNonZeroAddress(address(0x1));
    }

    function test_requireNonZeroAddress_reverts() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        lib.requireNonZeroAddress(address(0));
    }

    function testFuzz_requireNonZeroAddress(address addr) public view {
        vm.assume(addr != address(0));
        lib.requireNonZeroAddress(addr);
    }

    function test_requireNonZeroAddresses_array() public view {
        address[] memory addrs = new address[](3);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        lib.requireNonZeroAddresses(addrs);
    }

    function test_requireNonZeroAddresses_arrayReverts() public {
        address[] memory addrs = new address[](2);
        addrs[0] = address(0x1);
        addrs[1] = address(0);
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        lib.requireNonZeroAddresses(addrs);
    }

    function test_requireNonZeroAddresses2_passes() public view {
        lib.requireNonZeroAddresses2(address(0x1), address(0x2));
    }

    function test_requireNonZeroAddresses2_revertsFirst() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        lib.requireNonZeroAddresses2(address(0), address(0x2));
    }

    function test_requireNonZeroAddresses2_revertsSecond() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        lib.requireNonZeroAddresses2(address(0x1), address(0));
    }

    /* ── Value Validation ───────────────────────────── */

    function test_requireNonZeroValue_passes() public view {
        lib.requireNonZeroValue(1);
    }

    function test_requireNonZeroValue_reverts() public {
        vm.expectRevert(ValidationLib.ZeroValue.selector);
        lib.requireNonZeroValue(0);
    }

    function test_requireInBounds_passes() public view {
        lib.requireInBounds(50, 10, 100);
    }

    function test_requireInBounds_revertsBelow() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.OutOfBounds.selector,
                5,
                10,
                100
            )
        );
        lib.requireInBounds(5, 10, 100);
    }

    function test_requireInBounds_revertsAbove() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.OutOfBounds.selector,
                101,
                10,
                100
            )
        );
        lib.requireInBounds(101, 10, 100);
    }

    function test_requireInBounds_boundary() public view {
        lib.requireInBounds(10, 10, 100); // min
        lib.requireInBounds(100, 10, 100); // max
    }

    function test_requireBelowThreshold_passes() public view {
        lib.requireBelowThreshold(50, 100);
    }

    function test_requireBelowThreshold_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.AmountExceedsThreshold.selector,
                101,
                100
            )
        );
        lib.requireBelowThreshold(101, 100);
    }

    /* ── Array Validation ───────────────────────────── */

    function test_requireNonEmptyArray_passes() public view {
        lib.requireNonEmptyArray(1);
    }

    function test_requireNonEmptyArray_reverts() public {
        // Assembly uses hardcoded selector 0x0a72b8ce for gas efficiency
        vm.expectRevert(bytes4(0x0a72b8ce));
        lib.requireNonEmptyArray(0);
    }

    function test_requireMatchingLengths_passes() public view {
        lib.requireMatchingLengths(5, 5);
    }

    function test_requireMatchingLengths_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.ArrayLengthMismatch.selector,
                5,
                3
            )
        );
        lib.requireMatchingLengths(5, 3);
    }

    function test_requireValidBatchSize_passes() public view {
        lib.requireValidBatchSize(10, 100);
    }

    function test_requireValidBatchSize_revertsEmpty() public {
        // Assembly uses hardcoded selector 0x0a72b8ce for gas efficiency
        vm.expectRevert(bytes4(0x0a72b8ce));
        lib.requireValidBatchSize(0, 100);
    }

    function test_requireValidBatchSize_revertsTooLarge() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.BatchTooLarge.selector,
                101,
                100
            )
        );
        lib.requireValidBatchSize(101, 100);
    }

    /* ── Time Validation ────────────────────────────── */

    function test_requireNotExpired_passes() public view {
        lib.requireNotExpired(block.timestamp + 1 hours);
    }

    function test_requireNotExpired_reverts() public {
        uint256 pastDeadline = block.timestamp - 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.Expired.selector,
                pastDeadline,
                block.timestamp
            )
        );
        lib.requireNotExpired(pastDeadline);
    }

    function test_requireExpired_passes() public {
        uint256 pastDeadline = block.timestamp - 1;
        vm.warp(block.timestamp + 10);
        lib.requireExpired(pastDeadline);
    }

    function test_requireExpired_reverts() public {
        uint256 futureDeadline = block.timestamp + 1 hours;
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.Expired.selector,
                futureDeadline,
                block.timestamp
            )
        );
        lib.requireExpired(futureDeadline);
    }

    /* ── Chain ID Validation ────────────────────────── */

    function test_requireValidDestinationChain_passes() public view {
        // Foundry default chain ID is 31337
        lib.requireValidDestinationChain(1); // Ethereum mainnet
    }

    function test_requireValidDestinationChain_revertsZero() public {
        vm.expectRevert(
            abi.encodeWithSelector(ValidationLib.InvalidChainId.selector, 0)
        );
        lib.requireValidDestinationChain(0);
    }

    function test_requireValidDestinationChain_revertsSameChain() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationLib.InvalidChainId.selector,
                block.chainid
            )
        );
        lib.requireValidDestinationChain(block.chainid);
    }

    /* ── Bytes Validation ───────────────────────────── */

    function test_requireNonEmptyBytes_passes() public view {
        lib.requireNonEmptyBytes(hex"AA");
    }

    function test_requireNonEmptyBytes_reverts() public {
        vm.expectRevert(ValidationLib.EmptyArray.selector);
        lib.requireNonEmptyBytes(hex"");
    }

    function test_requireNonZeroBytes32_passes() public view {
        lib.requireNonZeroBytes32(bytes32(uint256(1)));
    }

    function test_requireNonZeroBytes32_reverts() public {
        vm.expectRevert(ValidationLib.ZeroValue.selector);
        lib.requireNonZeroBytes32(bytes32(0));
    }

    /* ── Compound Validations ───────────────────────── */

    function test_validateTransfer_passes() public view {
        lib.validateTransfer(address(0x1), 100);
    }

    function test_validateTransfer_revertsZeroAddr() public {
        vm.expectRevert(ValidationLib.ZeroAddress.selector);
        lib.validateTransfer(address(0), 100);
    }

    function test_validateTransfer_revertsZeroAmount() public {
        vm.expectRevert(ValidationLib.ZeroValue.selector);
        lib.validateTransfer(address(0x1), 0);
    }
}
