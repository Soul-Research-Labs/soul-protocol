// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/privacy/StealthContractFactory.sol";

contract StealthContractFactoryTest is Test {
    StealthContractFactory public factory;
    StealthContractFactory public impl;

    address public admin = makeAddr("admin");
    address public user = makeAddr("user");

    function setUp() public {
        impl = new StealthContractFactory();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(StealthContractFactory.initialize.selector, admin)
        );
        factory = StealthContractFactory(address(proxy));

        vm.deal(user, 10 ether);
        vm.deal(address(this), 10 ether);
    }

    // ─── Initialization ─────────────────────────────────────

    function test_initialize() public view {
        assertTrue(factory.hasRole(factory.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(factory.stealthWalletImplementation() != address(0));
        assertEq(factory.totalDeployments(), 0);
    }

    function test_initialize_revert_doubleInit() public {
        vm.expectRevert();
        factory.initialize(admin);
    }

    // ─── Recipient Registration ─────────────────────────────

    function test_registerRecipient() public {
        // Public keys must be exactly 33 bytes (compressed)
        bytes memory spendingKey = _pubKey(1);
        bytes memory viewingKey = _pubKey(2);

        bytes32 recipientId = factory.registerRecipient(spendingKey, viewingKey);
        assertTrue(recipientId != bytes32(0));

        StealthContractFactory.StealthKeys memory keys = factory.getRecipientKeys(recipientId);
        assertTrue(keys.isActive);
        assertEq(keys.spendingPubKey, spendingKey);
        assertEq(keys.viewingPubKey, viewingKey);
    }

    function test_registerRecipient_emitsEvent() public {
        bytes memory spendKey = _pubKey(1);
        bytes memory viewKey = _pubKey(2);

        // Just check that event is emitted (don't match indexed params)
        vm.expectEmit(false, false, false, false);
        emit StealthContractFactory.RecipientRegistered(bytes32(0), spendKey, viewKey);
        factory.registerRecipient(spendKey, viewKey);
    }

    function test_registerRecipient_revert_invalidPubKeyLength() public {
        bytes memory badKey = abi.encodePacked(uint256(1)); // 32 bytes, not 33
        bytes memory goodKey = _pubKey(1);

        vm.expectRevert(StealthContractFactory.InvalidPubKey.selector);
        factory.registerRecipient(badKey, goodKey);
    }

    function test_deactivateRecipient() public {
        bytes32 recipientId = factory.registerRecipient(_pubKey(1), _pubKey(2));

        factory.deactivateRecipient(recipientId);

        StealthContractFactory.StealthKeys memory keys = factory.getRecipientKeys(recipientId);
        assertFalse(keys.isActive);
    }

    function test_deactivateRecipient_emitsEvent() public {
        bytes32 recipientId = factory.registerRecipient(_pubKey(1), _pubKey(2));

        vm.expectEmit(true, false, false, false);
        emit StealthContractFactory.RecipientDeactivated(recipientId);
        factory.deactivateRecipient(recipientId);
    }

    // ─── Deploy Stealth Contract ────────────────────────────

    function test_deployStealthContract() public {
        bytes memory ephKey = _pubKey(10);
        bytes memory metadata = abi.encodePacked(keccak256("metadata"));

        address stealth = factory.deployStealthContract{value: 0.01 ether}(ephKey, metadata);
        assertTrue(stealth != address(0));
        assertEq(factory.totalDeployments(), 1);
        assertEq(factory.deploymentNonce(), 1);

        StealthContractFactory.StealthDeployment memory d = factory.getDeployment(stealth);
        assertEq(d.contractAddress, stealth);
        assertEq(d.value, 0.01 ether);
        assertFalse(d.isWithdrawn);
    }

    function test_deployStealthContract_emitsEvent() public {
        bytes memory ephKey = _pubKey(10);
        bytes memory metadata = abi.encodePacked(keccak256("meta"));

        // Just check that StealthContractDeployed event is emitted (don't match params)
        vm.expectEmit(false, false, false, false);
        emit StealthContractFactory.StealthContractDeployed(address(0), bytes32(0), ephKey, 0, 0);
        factory.deployStealthContract{value: 0.01 ether}(ephKey, metadata);
    }

    function test_deployStealthContract_revert_insufficientValue() public {
        vm.expectRevert(StealthContractFactory.InsufficientValue.selector);
        factory.deployStealthContract{value: 0.0001 ether}(
            _pubKey(10),
            abi.encodePacked(keccak256("meta"))
        );
    }

    function test_deployStealthContract_multiple() public {
        bytes memory ephKey1 = _pubKey(10);
        bytes memory ephKey2 = _pubKey(11);
        bytes memory metadata = abi.encodePacked(keccak256("meta"));

        address s1 = factory.deployStealthContract{value: 0.01 ether}(ephKey1, metadata);
        address s2 = factory.deployStealthContract{value: 0.01 ether}(ephKey2, metadata);

        assertTrue(s1 != s2);
        assertEq(factory.totalDeployments(), 2);
    }

    // ─── Compute Stealth Address ────────────────────────────

    function test_computeStealthAddress() public view {
        bytes memory ephKey = abi.encodePacked(keccak256("eph"));
        bytes memory metadata = abi.encodePacked(keccak256("meta"));

        address predicted = factory.computeStealthAddress(ephKey, metadata, 0);
        assertTrue(predicted != address(0));
    }

    function test_computeStealthAddress_deterministicDeploy() public {
        bytes memory ephKey = _pubKey(10);
        bytes memory metadata = abi.encodePacked(keccak256("meta"));

        address predicted = factory.computeStealthAddress(ephKey, metadata, 0);
        address deployed = factory.deployStealthContract{value: 0.01 ether}(ephKey, metadata);
        assertEq(predicted, deployed);
    }

    // ─── Withdraw ───────────────────────────────────────────

    function test_withdrawFromStealth() public {
        bytes memory ephKey = _pubKey(10);
        bytes memory metadata = abi.encodePacked(keccak256("meta"));

        address stealth = factory.deployStealthContract{value: 1 ether}(ephKey, metadata);

        address recipient = makeAddr("recipient");
        // Build signature (65 bytes needed for validation)
        bytes memory sig = new bytes(65);
        sig[0] = 0x01;
        sig[64] = 0x1b;
        bytes memory zkProof = "proof_data";

        uint256 balBefore = recipient.balance;
        factory.withdrawFromStealth(stealth, recipient, sig, zkProof);

        StealthContractFactory.StealthDeployment memory d = factory.getDeployment(stealth);
        assertTrue(d.isWithdrawn);
    }

    function test_withdrawFromStealth_revert_alreadyWithdrawn() public {
        bytes memory ephKey = _pubKey(10);
        address stealth = factory.deployStealthContract{value: 1 ether}(
            ephKey, abi.encodePacked(keccak256("meta"))
        );

        bytes memory sig = new bytes(65);
        sig[0] = 0x01;
        sig[64] = 0x1b;
        factory.withdrawFromStealth(stealth, makeAddr("r"), sig, "proof");

        vm.expectRevert(StealthContractFactory.AlreadyWithdrawn.selector);
        factory.withdrawFromStealth(stealth, makeAddr("r"), sig, "proof");
    }

    // ─── Batch Withdraw ─────────────────────────────────────

    function test_batchWithdraw() public {
        address[] memory contracts = new address[](2);
        bytes[] memory sigs = new bytes[](2);
        bytes[] memory proofs = new bytes[](2);

        for (uint256 i = 0; i < 2; i++) {
            contracts[i] = factory.deployStealthContract{value: 0.01 ether}(
                _pubKey(20 + i),
                abi.encodePacked(keccak256(abi.encodePacked("meta", i)))
            );
            sigs[i] = new bytes(65);
            sigs[i][0] = 0x01;
            sigs[i][64] = 0x1b;
            proofs[i] = "proof";
        }

        address recipient = makeAddr("batchRecipient");
        factory.batchWithdraw(contracts, recipient, sigs, proofs);

        // Verify both are withdrawn
        for (uint256 i = 0; i < 2; i++) {
            StealthContractFactory.StealthDeployment memory d = factory.getDeployment(contracts[i]);
            assertTrue(d.isWithdrawn);
        }
    }

    // ─── View Functions ─────────────────────────────────────

    function test_getDeployedContracts() public {
        for (uint256 i = 0; i < 3; i++) {
            factory.deployStealthContract{value: 0.01 ether}(
                _pubKey(30 + i),
                abi.encodePacked(keccak256(abi.encodePacked("meta", i)))
            );
        }

        (address[] memory addrs, bytes32[] memory hashes, uint256[] memory timestamps) =
            factory.getDeployedContracts(0, 10);
        assertEq(addrs.length, 3);
        assertEq(hashes.length, 3);
        assertEq(timestamps.length, 3);
    }

    function test_getDeployedContracts_pagination() public {
        for (uint256 i = 0; i < 5; i++) {
            factory.deployStealthContract{value: 0.01 ether}(
                _pubKey(40 + i),
                abi.encodePacked(keccak256(abi.encodePacked("m", i)))
            );
        }

        (address[] memory page1,,) = factory.getDeployedContracts(0, 2);
        (address[] memory page2,,) = factory.getDeployedContracts(2, 2);

        assertEq(page1.length, 2);
        assertEq(page2.length, 2);
        assertTrue(page1[0] != page2[0]);
    }

    function test_getDeploymentsSince() public {
        uint256 ts1 = block.timestamp;
        factory.deployStealthContract{value: 0.01 ether}(
            _pubKey(50),
            abi.encodePacked(keccak256("m1"))
        );

        vm.warp(block.timestamp + 1 hours);
        uint256 ts2 = block.timestamp;

        factory.deployStealthContract{value: 0.01 ether}(
            _pubKey(51),
            abi.encodePacked(keccak256("m2"))
        );

        (address[] memory addrs,) = factory.getDeploymentsSince(ts2);
        assertEq(addrs.length, 1);
    }

    function test_getTotalDeployments() public {
        assertEq(factory.getTotalDeployments(), 0);
        factory.deployStealthContract{value: 0.01 ether}(
            _pubKey(60),
            abi.encodePacked(keccak256("m"))
        );
        assertEq(factory.getTotalDeployments(), 1);
    }

    function test_getUnwithdrawnCount() public {
        factory.deployStealthContract{value: 0.01 ether}(
            _pubKey(70),
            abi.encodePacked(keccak256("m1"))
        );
        address s2 = factory.deployStealthContract{value: 0.01 ether}(
            _pubKey(71),
            abi.encodePacked(keccak256("m2"))
        );

        assertEq(factory.getUnwithdrawnCount(), 2);

        bytes memory sig = new bytes(65);
        sig[0] = 0x01;
        sig[64] = 0x1b;
        factory.withdrawFromStealth(s2, makeAddr("r"), sig, "proof");

        assertEq(factory.getUnwithdrawnCount(), 1);
    }

    // ─── Fuzz ───────────────────────────────────────────────

    function testFuzz_deployStealthContract(uint256 value) public {
        value = bound(value, 0.001 ether, 5 ether);
        vm.deal(address(this), value);

        address stealth = factory.deployStealthContract{value: value}(
            _pubKey(80),
            abi.encodePacked(keccak256("meta"))
        );
        assertTrue(stealth != address(0));

        StealthContractFactory.StealthDeployment memory d = factory.getDeployment(stealth);
        assertEq(d.value, value);
    }

    // ─── Helpers ────────────────────────────────────────────

    /// @dev Create a 33-byte compressed public key
    function _pubKey(uint256 seed) internal pure returns (bytes memory) {
        bytes32 x = keccak256(abi.encodePacked(seed));
        // Compressed key: 0x02 prefix + 32 bytes x-coord
        return abi.encodePacked(uint8(0x02), x);
    }
}
