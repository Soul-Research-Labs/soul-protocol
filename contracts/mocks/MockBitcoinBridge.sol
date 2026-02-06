// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockBTCSPVVerifier
 * @notice Mock Bitcoin SPV proof verifier for testing BitcoinBridgeAdapter
 * @dev Simulates Bitcoin transaction verification via SPV proofs
 */
contract MockBTCSPVVerifier {
    mapping(bytes32 => bool) public verifiedTxs;
    mapping(bytes32 => uint256) public blockConfirmations;
    uint256 public requiredConfirmations = 6;

    event TxVerified(bytes32 indexed txHash, uint256 blockHeight);

    function setRequiredConfirmations(uint256 confs) external {
        requiredConfirmations = confs;
    }

    function submitSPVProof(
        bytes32 txHash,
        bytes calldata, // merkleProof
        bytes calldata, // blockHeader
        uint256 blockHeight
    ) external returns (bool) {
        verifiedTxs[txHash] = true;
        blockConfirmations[txHash] = blockHeight;
        emit TxVerified(txHash, blockHeight);
        return true;
    }

    function isTxVerified(bytes32 txHash) external view returns (bool) {
        return verifiedTxs[txHash];
    }

    function getConfirmations(bytes32 txHash) external view returns (uint256) {
        return blockConfirmations[txHash];
    }

    function verifyMerkleProof(
        bytes32,      // txHash
        bytes32,      // merkleRoot
        bytes32[] calldata, // proof
        uint256       // index
    ) external pure returns (bool) {
        return true;
    }
}

/**
 * @title MockWrappedBTC
 * @notice Mock wBTC token for testing Bitcoin bridge
 */
contract MockWrappedBTC {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    string public name = "Wrapped Bitcoin";
    string public symbol = "WBTC";
    uint8 public decimals = 8;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
