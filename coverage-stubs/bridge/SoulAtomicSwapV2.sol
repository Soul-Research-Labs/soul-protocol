// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract SoulAtomicSwapV2 is Ownable, ReentrancyGuard, Pausable {
    enum SwapStatus { Invalid, Created, Claimed, Refunded, Expired }

    struct Swap {
        bytes32 id;
        address initiator;
        address recipient;
        address token;
        uint256 amount;
        bytes32 hashLock;
        uint256 timeLock;
        SwapStatus status;
        bytes32 commitment;
    }

    mapping(bytes32 => Swap) public swaps;
    mapping(bytes32 => bytes32) public hashLockToSwap;
    mapping(address => uint256) public collectedFees;
    
    uint256 public constant MIN_TIMELOCK = 1 hours;
    uint256 public constant MAX_TIMELOCK = 7 days;
    address public feeRecipient;
    uint256 public protocolFeeBps;

    error InvalidRecipient();
    error InvalidAmount();
    error InvalidTimeLock();
    error InvalidHashLock();
    error SwapAlreadyExists();
    error SwapNotFound();
    error SwapNotPending();
    error InvalidSecret();
    error SwapNotExpired();
    error SwapExpired();
    error NotInitiator();
    error TransferFailed();
    error ZeroAddress();
    error CommitTooRecent();
    error InvalidCommitHash();
    error WithdrawalNotReady();
    error WithdrawalNotFound();
    error UseCommitReveal();
    error NoFeesToWithdraw();
    error FeeTransferFailed();

    event SwapCreated(bytes32 indexed swapId, address indexed initiator, address indexed recipient, address token, uint256 amount, bytes32 hashLock, uint256 timeLock);
    event SwapClaimed(bytes32 indexed swapId, address indexed claimer, bytes32 secret);
    event SwapRefunded(bytes32 indexed swapId, address indexed initiator);
    event ClaimCommitted(bytes32 indexed swapId, address indexed committer, bytes32 commitHash);
    
    constructor(address _feeRecipient) Ownable(msg.sender) {
        feeRecipient = _feeRecipient;
    }

    function createSwapETH(address r, bytes32 h, uint256 t, bytes32 c) external payable returns (bytes32) {
        return keccak256(abi.encode(r, h, t, c));
    }

    function createSwapToken(address r, address tk, uint256 a, bytes32 h, uint256 t, bytes32 c) external returns (bytes32) {
        return keccak256(abi.encode(r, tk, a, h, t, c));
    }

    function commitClaim(bytes32, bytes32) external {}
    function revealClaim(bytes32, bytes32, bytes32) external {}
    function claim(bytes32, bytes32) external {}
    function refund(bytes32) external {}
    function getSwapByHashLock(bytes32 h) external view returns (Swap memory) { return swaps[hashLockToSwap[h]]; }
    function isClaimable(bytes32) external view returns (bool) { return true; }
    function isRefundable(bytes32) external view returns (bool) { return true; }
    function setProtocolFee(uint256) external {}
    function setFeeRecipient(address) external {}
    function requestFeeWithdrawal(address) external returns (bytes32) { return bytes32(0); }
    function executeFeeWithdrawal(address, bytes32) external {}
    function withdrawFees(address) external {}
    function pause() external { _pause(); }
    function unpause() external { _unpause(); }
    
    function setRateLimitConfig(uint256, uint256) external {}
    function setCircuitBreakerConfig(uint256, uint256) external {}
    function setSecurityFeatures(bool, bool, bool, bool) external {}
    function resetCircuitBreaker() external {}
    
    receive() external payable {}
}
