// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../contracts/privacy/UnifiedNullifierManager.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title PrivacyFuzz
 * @notice Echidna fuzzing target for UnifiedNullifierManager
 */
contract PrivacyFuzz is UnifiedNullifierManager {
    constructor() {
        // Manually setup state instead of calling initialize() which is disabled in constructor
        _grantRole(DEFAULT_ADMIN_ROLE, address(this));
        _grantRole(OPERATOR_ROLE, address(this));
        _grantRole(BRIDGE_ROLE, address(this));
        
        _registerDefaultChains();
    }
    
    bytes32 public lastNullifier;
    
    /**
     * @dev Invariant: The last registered nullifier must have a valid record.
     */
    function echidna_nullifier_status_valid() public view returns (bool) {
        if (lastNullifier == bytes32(0)) return true;
        UnifiedNullifierManager.NullifierRecord memory record = nullifierRecords[lastNullifier];
        return record.chainId != 0 || record.status == UnifiedNullifierManager.NullifierStatus.UNKNOWN;
    }
    
    function fuzz_registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 chainId,
        UnifiedNullifierManager.NullifierType nType,
        uint256 expiresAt
    ) public {
        lastNullifier = nullifier;
        (bool success, ) = address(this).call(
            abi.encodeWithSelector(
                this.registerNullifier.selector,
                nullifier,
                commitment,
                chainId,
                nType,
                expiresAt
            )
        );
    }
    
    function fuzz_spendNullifier(bytes32 nullifier) public {
        (bool success, ) = address(this).call(
             abi.encodeWithSelector(this.spendNullifier.selector, nullifier)
        );
    }
    
    function fuzz_processBatch(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        uint256 chainId,
        bytes32 merkleRoot
    ) public {
        (bool success, ) = address(this).call(
            abi.encodeWithSelector(
                this.processBatch.selector,
                nullifiers,
                commitments,
                chainId,
                merkleRoot
            )
        );
    }
}
