// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// STUB for coverage only
library ConstantTimeOperations {
    function constantTimeEquals(bytes32, bytes32) internal pure returns (bool) { return true; }
    function constantTimeEqualsUint(uint256, uint256) internal pure returns (bool) { return true; }
    function constantTimeEqualsBytes(bytes memory, bytes memory) internal pure returns (bool) { return true; }
    function constantTimeSelect(bool, bytes32, bytes32) internal pure returns (bytes32) { return bytes32(0); }
    function constantTimeSelectUint(bool, uint256, uint256) internal pure returns (uint256) { return 0; }
    function constantTimeSelectAddress(bool, address, address) internal pure returns (address) { return address(0); }
    function constantTimeLessThan(uint256, uint256) internal pure returns (uint256) { return 0; }
    function constantTimeGreaterThan(uint256, uint256) internal pure returns (uint256) { return 0; }
    function constantTimeMin(uint256, uint256) internal pure returns (uint256) { return 0; }
    function constantTimeMax(uint256, uint256) internal pure returns (uint256) { return 0; }
    function constantTimeAbsDiff(uint256, uint256) internal pure returns (uint256) { return 0; }
    function constantTimeCopy(bytes memory, bytes memory, uint256) internal pure {}
    function constantTimeZero(bytes memory) internal pure {}
    function constantTimeGetBit(uint256, uint8) internal pure returns (uint256) { return 0; }
    function constantTimeSetBit(uint256, uint8, bool) internal pure returns (uint256) { return 0; }
    function constantTimePopCount(uint256) internal pure returns (uint256) { return 0; }
    function constantTimeInRange(uint256, uint256, uint256) internal pure returns (bool) { return true; }
    function constantTimeIsNonZero(uint256) internal pure returns (bool) { return true; }
    function constantTimeIsPowerOf2(uint256) internal pure returns (bool) { return true; }
    function constantTimeSwap(bool, uint256, uint256) internal pure returns (uint256, uint256) { return (0, 0); }
    function constantTimeModHint(uint256, uint256) internal pure returns (uint256) { return 0; }
}

library ConstantTimePrivacy {
    function constantTimeNullifierLookup(bytes32, bytes32[] memory) internal pure returns (bool, uint256) { return (true, 0); }
    function constantTimeKeyImageLookup(bytes32, bytes32[] memory) internal pure returns (bool) { return true; }
    function constantTimeDecoySelect(uint256, uint256, uint256) internal pure returns (uint256[] memory) { return new uint256[](0); }
    function constantTimeCommitmentVerify(bytes32, uint256, bytes32, bytes32) internal pure returns (bool) { return true; }
}
