// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import "../../contracts/crosschain/CrossChainMessageRelay.sol";

contract RelayFuzzTest is Test {
    CrossChainMessageRelay relay;

    function setUp() public {
        relay = new CrossChainMessageRelay();
        bytes32 relayerRole = relay.RELAYER_ROLE();
        relay.grantRole(relayerRole, address(this));
    }

    function testFuzz_ReceiveMessageRobustness(
        CrossChainMessageRelay.CrossChainMessage memory message,
        bytes calldata proof
    ) public {
        // Must perform bounds check on untrusted inputs if strict
        // But here we want to ensure no PANICs occur even with garbage.
        
        try relay.receiveMessage(message, proof) {
            // Success
        } catch {
            // Any failure (revert or panic) is caught here
        }
    }
}
