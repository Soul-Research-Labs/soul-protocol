// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GasNormalizer} from "../../contracts/privacy/GasNormalizer.sol";

/// @notice Sanity check that core privacy contracts deploy and respond correctly
contract SanityCheckTest is Test {
    function test_GasNormalizerDeploys() public {
        GasNormalizer gn = new GasNormalizer(address(this));
        assertTrue(gn.hasRole(gn.DEFAULT_ADMIN_ROLE(), address(this)));
        assertTrue(gn.enabled());
    }
}
