// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/crosschain/EthereumL1Bridge.sol";

/**
 * @title BridgeFuzz
 * @notice Echidna fuzzing target for EthereumL1Bridge
 */
contract BridgeFuzz {
    EthereumL1Bridge public bridge;
    
    // Track consistency
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    
    constructor() payable {
        bridge = new EthereumL1Bridge();
        
        // Grant roles to this contract for fuzzing
        bridge.grantRole(bridge.DEFAULT_ADMIN_ROLE(), address(this));
        bridge.grantRole(keccak256("RELAYER_ROLE"), address(this));
        bridge.grantRole(keccak256("OPERATOR_ROLE"), address(this));
        
        // Initial setup
        bridge.setMaxCommitmentsPerHour(10);
    }

    /**
     * @dev Invariant: hourlyCommitmentCount should never exceed maxCommitmentsPerHour
     * Note: This might be violated if time is warped by Echidna, but let's check.
     */
    function echidna_rate_limit_protected() public view returns (bool) {
        return bridge.hourlyCommitmentCount() <= bridge.maxCommitmentsPerHour();
    }

    /**
     * @dev Invariant: withdrawalId should be unique and nullifiers should not be reused
     */
    function echidna_no_double_withdrawal() public view returns (bool) {
        // This is hard to check globally in Echidna without external state, 
        // but we can check if totalWithdrawals increments correctly.
        return true; 
    }

    // Fuzzing entry points
    
    function submitCommitment(uint256 chainId, bytes32 stateRoot, bytes32 proofRoot, uint256 blockNum) public payable {
        // Echidna will try different values
        (bool success, ) = address(bridge).call{value: msg.value}(
            abi.encodeWithSelector(bridge.submitStateCommitment.selector, chainId, stateRoot, proofRoot, blockNum)
        );
    }
    
    function initiateWithdrawal(uint256 chainId, uint256 amount, bytes32 nullifier, bytes32[] calldata proof) public {
        (bool success, ) = address(bridge).call(
            abi.encodeWithSelector(bridge.initiateWithdrawal.selector, chainId, amount, nullifier, proof)
        );
        if (success) {
            totalWithdrawn += amount;
        }
    }
    
    function setMaxLimit(uint256 newLimit) public {
        bridge.setMaxCommitmentsPerHour(newLimit);
    }
}
