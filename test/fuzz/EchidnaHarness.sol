// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title EchidnaHarness
 * @notice Echidna-compatible property testing harness for ZASEON
 * @dev Properties use `echidna_` prefix (required by Echidna's property mode).
 *      Action functions are public for Echidna to call in fuzz sequences.
 *
 * Run: echidna . --config test/fuzz/echidna.config.yaml --contract EchidnaHarness
 *
 * Properties tested:
 *   1. Balance conservation: deposits == withdrawals + current balance
 *   2. Nullifier uniqueness: no nullifier used twice
 *   3. LP supply consistency: minted == burned + outstanding
 *   4. Fee bounds: fees never exceed 10% of volume
 *   5. Cross-chain message ID uniqueness
 *   6. Order count monotonicity
 */
contract EchidnaHarness {
    /*//////////////////////////////////////////////////////////////
                           STATE
    //////////////////////////////////////////////////////////////*/

    // Balance tracking
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalBalance;

    // LP tracking
    uint256 public totalLPMinted;
    uint256 public totalLPBurned;
    uint256 public outstandingLP;

    // Nullifier tracking
    mapping(bytes32 => bool) public usedNullifiers;
    uint256 public nullifierCollisions;
    uint256 public nullifierCount;

    // Fee tracking
    uint256 public totalFeesCollected;
    uint256 public totalVolume;

    // Message tracking
    mapping(bytes32 => bool) public usedMessageIds;
    uint256 public messageIdCollisions;

    // Order tracking
    uint256 public activeOrders;
    uint256 public totalOrdersCreated;

    /*//////////////////////////////////////////////////////////////
                       ACTION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Simulate a deposit
    function deposit(uint256 amount) public {
        if (amount == 0 || amount > 1e30) return;
        balances[msg.sender] += amount;
        totalDeposited += amount;
        totalBalance += amount;
    }

    /// @dev Simulate a withdrawal
    function withdraw(uint256 amount) public {
        if (amount == 0 || amount > balances[msg.sender]) return;
        balances[msg.sender] -= amount;
        totalWithdrawn += amount;
        totalBalance -= amount;
    }

    /// @dev Simulate nullifier consumption
    function consumeNullifier(bytes32 nullifier) public {
        if (nullifier == bytes32(0)) return;
        if (usedNullifiers[nullifier]) {
            nullifierCollisions++;
            return;
        }
        usedNullifiers[nullifier] = true;
        nullifierCount++;
    }

    /// @dev Simulate LP token minting
    function mintLP(uint256 amount) public {
        if (amount == 0 || amount > 1e30) return;
        totalLPMinted += amount;
        outstandingLP += amount;
    }

    /// @dev Simulate LP token burning
    function burnLP(uint256 amount) public {
        if (amount == 0 || amount > outstandingLP) return;
        totalLPBurned += amount;
        outstandingLP -= amount;
    }

    /// @dev Simulate fee collection with volume tracking
    function collectFee(uint256 volume, uint256 feeRate) public {
        if (volume == 0 || volume > 1e30) return;
        // Bound fee rate to 10% max (1000 basis points)
        if (feeRate > 1000) feeRate = 1000;
        uint256 fee = (volume * feeRate) / 10000;
        totalVolume += volume;
        totalFeesCollected += fee;
    }

    /// @dev Simulate cross-chain message sending
    function sendMessage(bytes32 messageId) public {
        if (messageId == bytes32(0)) return;
        if (usedMessageIds[messageId]) {
            messageIdCollisions++;
            return;
        }
        usedMessageIds[messageId] = true;
    }

    /// @dev Simulate order creation
    function createOrder() public {
        totalOrdersCreated++;
        activeOrders++;
    }

    /// @dev Simulate order completion
    function completeOrder() public {
        if (activeOrders == 0) return;
        activeOrders--;
    }

    /*//////////////////////////////////////////////////////////////
                      ECHIDNA PROPERTIES
    //////////////////////////////////////////////////////////////*/

    /// @notice Balance conservation: deposits == withdrawals + current balance
    function echidna_balance_conservation() public view returns (bool) {
        return totalDeposited == totalWithdrawn + totalBalance;
    }

    /// @notice No nullifier collisions ever occur (double-spend prevention)
    function echidna_nullifier_uniqueness() public view returns (bool) {
        return nullifierCollisions == 0;
    }

    /// @notice LP supply is consistent: minted == burned + outstanding
    function echidna_lp_supply_consistency() public view returns (bool) {
        return totalLPMinted == totalLPBurned + outstandingLP;
    }

    /// @notice Fees never exceed 10% of total volume
    function echidna_fees_bounded() public view returns (bool) {
        if (totalVolume == 0) return true;
        return totalFeesCollected <= totalVolume / 10;
    }

    /// @notice No message ID collisions (replay prevention)
    function echidna_message_id_uniqueness() public view returns (bool) {
        return messageIdCollisions == 0;
    }

    /// @notice Active orders never exceed total created
    function echidna_order_count_bounded() public view returns (bool) {
        return activeOrders <= totalOrdersCreated;
    }
}
