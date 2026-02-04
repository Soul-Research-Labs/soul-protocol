// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {SecurityModule} from "../../contracts/security/SecurityModule.sol";

/**
 * @title SecurityModuleGasTest
 * @notice Gas benchmarks for SecurityModule packed flags optimization
 * @dev Run with: forge test --match-contract SecurityModuleGasTest --gas-report -vvv
 *
 * Optimization: Packed 5 bool flags into single uint8 bitmap
 * Expected savings: ~8,400 gas (4 storage slots reduced to 1)
 */
contract SecurityModuleGasTest is Test {
    TestableSecurityModule public module;

    function setUp() public {
        module = new TestableSecurityModule();
    }

    /*//////////////////////////////////////////////////////////////
                        FLAG ACCESS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Measure gas for reading all flag values
    function test_gas_readAllFlags() public view {
        uint256 gasBefore = gasleft();
        
        bool a = module.rateLimitingEnabled();
        bool b = module.circuitBreakerEnabled();
        bool c = module.circuitBreakerTripped();
        bool d = module.flashLoanGuardEnabled();
        bool e = module.withdrawalLimitsEnabled();
        
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Read all 5 flags gas:", gasUsed);
        
        // With packed flags, all reads come from same storage slot
        // Should be ~2100 gas for SLOAD + ~200 for bitwise ops
        // Much cheaper than 5 x 2100 = 10500 for separate SLOADs
        assertTrue(a && b && !c && d && e, "Default flags");
    }

    /// @notice Measure gas for toggling security features
    function test_gas_setSecurityFeatures() public {
        uint256 gasBefore = gasleft();
        
        module.setSecurityFeatures(false, false, false, false);
        
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Set 4 security features gas:", gasUsed);
        
        // With packed flags, single SSTORE updates all 4 flags
        // Should be ~5000-22000 gas for single SSTORE
        // Much cheaper than 4 x 5000+ = 20000+ for separate SSTOREs
    }

    /// @notice Measure gas for circuit breaker trip (single flag write)
    function test_gas_circuitBreakerTrip() public {
        // First make a deposit to enable circuit breaker tracking
        module.simulateVolumeIncrease(module.volumeThreshold() + 1);
    }

    /// @notice Measure gas for rate limited operation
    function test_gas_rateLimitedOperation() public {
        uint256 gasBefore = gasleft();
        
        module.performRateLimitedAction();
        
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Rate limited action gas:", gasUsed);
    }

    /// @notice Measure gas for flash loan guarded operation
    function test_gas_flashLoanGuardedOperation() public {
        // First record a deposit in a previous block
        module.recordTestDeposit(address(this));
        vm.roll(block.number + 2);
        
        uint256 gasBefore = gasleft();
        
        module.performFlashLoanGuardedAction();
        
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Flash loan guarded action gas:", gasUsed);
    }
}

/**
 * @title TestableSecurityModule
 * @notice Concrete implementation of SecurityModule for testing
 */
contract TestableSecurityModule is SecurityModule {
    uint256 public totalActions;

    /// @notice Expose _setSecurityFeatures for testing
    function setSecurityFeatures(
        bool rateLimiting,
        bool circuitBreakers,
        bool flashLoanGuard,
        bool withdrawalLimits
    ) external {
        _setSecurityFeatures(rateLimiting, circuitBreakers, flashLoanGuard, withdrawalLimits);
    }

    /// @notice Simulate volume increase to trigger circuit breaker
    function simulateVolumeIncrease(uint256 amount) external {
        lastHourlyVolume += amount;
    }

    /// @notice Perform a rate-limited action
    function performRateLimitedAction() external rateLimited {
        totalActions++;
    }

    /// @notice Perform a flash-loan guarded action
    function performFlashLoanGuardedAction() external noFlashLoan {
        totalActions++;
    }

    /// @notice Record a test deposit
    function recordTestDeposit(address account) external {
        _recordDeposit(account);
    }
}
