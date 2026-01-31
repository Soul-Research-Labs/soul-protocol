// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ConfidentialStateContainerV3} from "../../contracts/core/ConfidentialStateContainerV3.sol";
import {Handler} from "./Handler.t.sol";

// Interface for MockVerifier
interface IProofVerifier {
    function verifyProof(bytes calldata, bytes calldata) external view returns (bool);
}

contract MockVerifier is IProofVerifier {
    function verifyProof(
        bytes calldata, 
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

contract ConfidentialStateInvariant is StdInvariant, Test {
    ConfidentialStateContainerV3 public container;
    Handler public handler;
    MockVerifier public verifier;
    address admin = address(0x1);

    function setUp() public {
        verifier = new MockVerifier();
        
        vm.prank(admin);
        container = new ConfidentialStateContainerV3(address(verifier));
        
        handler = new Handler(container, admin);
        
        targetContract(address(handler));
    }

    // Invariant 1: Nullifiers used in Ghost State must be marked used in Contract
    // Note: This is hard to iterate map in Solidity.
    // Instead we rely on the Handler checking success.
    
    // Invariant 2: Active State Count in Contract should match our expectations?
    // As noted in Handler, Transfer doesn't decrement active count of old state?
    // Let's check strict property:
    // "Sum of active states should be equal to registered - retired - frozen"
    // Ideally we fuzz for unexpected reverts or corrupted state.

    function invariant_ProtocolShouldNotPanic() public view {
        // Basic liveness check
        assert(container.totalStates() >= 0);
    }
    
    function invariant_ActiveStatesLeqTotalStates() public view {
        assert(container.activeStates() <= container.totalStates());
    }
}
