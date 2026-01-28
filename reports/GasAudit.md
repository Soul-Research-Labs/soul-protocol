# Gas Audit: EIP-4844 Blob Integration

## Summary
This audit compares the gas costs of the legacy state commitment submission against the new EIP-4844 blob-enabled submission in `EthereumL1Bridge`.

## Results

| Method | Execution Gas | Notes |
|--------|---------------|-------|
| `submitStateCommitment` (Legacy) | **273,666** | Standard execution. |
| `submitStateCommitmentWithBlob` | **296,661** | Includes blob versioned hash storage. |

## Analysis
The "Blob" path requires approximately **23,000 additional gas** during execution. 
*   **Reason**: This increase corresponds almost entirely to writing the non-zero `blobVersionedHash` to the `StateCommitment` struct in storage (SSTORE cost for non-zero value is 22,100 gas).
*   **Net Benefit**: While the execution cost is slightly higher, this method allows up to **128KB** of data to be attached as a blob for a negligible blob base fee, avoiding the prohibitive cost of Calldata (approx. 2 million gas for 128KB).
*   **Conclusion**: The ~8.4% increase in bridge execution gas unlocks >90% savings in total transaction cost for data-heavy updates.

## Methodology
*   **Network**: Hardhat Local (Cancun EVM).
*   **Mocking**: Used `MockEthereumL1Bridge` to simulate `blobhash` opcode return values.
*   **Test File**: `test/EthereumL1BridgeGas.test.ts`.
