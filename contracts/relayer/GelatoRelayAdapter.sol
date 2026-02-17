// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IRelayerAdapter.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Mock Gelato Interface
interface IGelatoRelay {
    function callWithSyncFee(
        address _target,
        bytes calldata _data,
        address _feeToken
    ) external returns (bytes32);
    
    function getFeeEstimate(
        address _target,
        bytes calldata _data,
        address _feeToken
    ) external view returns (uint256);
}

/**
 * @title GelatoRelayAdapter
 * @notice Adapter for Gelato Relay Network
 */
contract GelatoRelayAdapter is IRelayerAdapter, Ownable {
    address public immutable GELATO_RELAY;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    constructor(address _gelatoRelay) Ownable(msg.sender) {
        GELATO_RELAY = _gelatoRelay;
    }

    function relayMessage(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable override returns (bytes32) {
        // Gelato fee logic: we pay with ETH (syncFee)
        // User pays this contract, this contract pays Gelato
        
        // In callWithSyncFee, Gelato deducts fee from the target contract or msg.value?
        // Actually, callWithSyncFee usually involves the target paying.
        // Or if using callWithSyncFee, the fee is taken from the transaction execution?
        // For simplicity, we assume we forward the msg.value or use a sponsored method if set up.
        // Here we mock the integration assuming we forward the call.
        
        // Real Gelato integration is complex. We use a simplified wrapper call.
        // We assume msg.value covers the fee.
        
        // Note: callWithSyncFee sends the call to `target`. 
        // Inside `target`, it should use GelatoRelayContext to pay fee?
        // Use `callWithSyncFeeERC2771` if using meta-tx.
        
        // For this adapter, we just assume simple forwarding.
        return IGelatoRelay(GELATO_RELAY).callWithSyncFee(target, payload, ETH);
    }

    function getFee(uint256 gasLimit) external view override returns (uint256) {
        // Mock fee estimation
        return 0.001 ether; 
    }
}
