// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoseidonT3} from "./PoseidonT3.sol";

/**
 * @title PoseidonYul
 * @author ZASEON
 * @notice Thin wrapper around PoseidonT3 for backward compatibility.
 * @dev DEPRECATED — Use PoseidonT3.hash2() directly in new code.
 *      This library now delegates to the full 65-round Poseidon (PoseidonT3)
 *      which provides complete security against algebraic attacks.
 *
 *      Previous versions used a simplified 8-round implementation that was
 *      NOT cryptographically secure for adversarial inputs.
 *
 * @custom:deprecated Use PoseidonT3 directly.
 */
library PoseidonYul {
    /// @notice BN254 scalar field prime (kept for backward compatibility)
    uint256 internal constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice Hash two BN254 field elements using Poseidon (T=3)
     * @dev Delegates to PoseidonT3.hash2() — full 65-round implementation
     * @param input1 First input element
     * @param input2 Second input element
     * @return result The Poseidon hash
     */
    function hash2(
        uint256 input1,
        uint256 input2
    ) internal pure returns (uint256 result) {
        return PoseidonT3.hash2(input1, input2);
    }
}
