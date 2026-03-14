// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/UnifiedNullifierManager.sol";
import "../../contracts/interfaces/IUnifiedNullifierManager.sol";
import "../../contracts/privacy/CrossChainPrivacyHub.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract PrivacyCoverageTest is Test {
    UnifiedNullifierManager public nullifierManager;
    UnifiedNullifierManager public managerImpl;
    CrossChainPrivacyHub public privacyHub;
    CrossChainPrivacyHub public hubImpl;

    bytes32 public constant BRIDGE_ROLE =
        0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        // Deploy UnifiedNullifierManager
        managerImpl = new UnifiedNullifierManager();
        ERC1967Proxy managerProxy = new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                UnifiedNullifierManager.initialize,
                (address(this)) // admin
            )
        );
        nullifierManager = UnifiedNullifierManager(address(managerProxy));

        // Deploy CrossChainPrivacyHub
        hubImpl = new CrossChainPrivacyHub();
        // admin, guardian, feeRecipient
        ERC1967Proxy hubProxy = new ERC1967Proxy(
            address(hubImpl),
            abi.encodeCall(
                CrossChainPrivacyHub.initialize,
                (
                    address(this), // admin
                    address(this), // guardian
                    address(this) // fee recipient
                )
            )
        );
        privacyHub = CrossChainPrivacyHub(payable(address(hubProxy)));
        // Grant OPERATOR_ROLE to this contract so it can register adapters
        privacyHub.grantRole(OPERATOR_ROLE, address(this));
    }

    function test_UnifiedNullifierManager_Lifecycle() public {
        bytes32 nullifier = keccak256("test_nullifier");
        bytes32 commitment = keccak256("test_commitment");
        uint256 chainId = 1;

        // BRIDGE_ROLE is required for nullifier registration/spending.
        // Admin has all roles granted in initialize, let's verify
        assertTrue(
            nullifierManager.hasRole(BRIDGE_ROLE, address(this)),
            "Should have BRIDGE_ROLE"
        );

        // Register Nullifier
        vm.expectEmit(true, true, false, true);
        emit IUnifiedNullifierManager.NullifierRegistered(
            nullifier,
            commitment,
            chainId,
            IUnifiedNullifierManager.NullifierType.STANDARD
        );

        bytes32 zaseonNullifier = nullifierManager.registerNullifier(
            nullifier,
            commitment,
            chainId,
            IUnifiedNullifierManager.NullifierType.STANDARD,
            0 // no expiry
        );

        // precise checking of return value
        assertNotEq(zaseonNullifier, bytes32(0));

        // Check state
        IUnifiedNullifierManager.NullifierRecord
            memory record = nullifierManager.getNullifierRecord(nullifier);
        // assertEq(record.status == IUnifiedNullifierManager.NullifierStatus.REGISTERED, true);
        // Enum comparison fix handled by assertEq casting or just bool check
        assertEq(
            uint(record.status),
            uint(IUnifiedNullifierManager.NullifierStatus.REGISTERED)
        );
        assertEq(record.commitment, commitment);

        // Spend Nullifier
        nullifierManager.spendNullifier(nullifier);
        assertTrue(nullifierManager.isNullifierSpent(nullifier));

        // Re-spend should fail
        vm.expectRevert(
            IUnifiedNullifierManager.NullifierAlreadySpent.selector
        );
        nullifierManager.spendNullifier(nullifier);
    }

    /*
        bytes32 commitment = keccak256("test_commitment");
        ...
        nullifierManager.spendNullifier(nullifier);
    }
    */

    function test_CrossChainPrivacyHub_AdapterRegistry() public {
        // Register an adapter
        address mockAdapter = address(0x123);
        uint256 chainId = 10; // Optimism

        privacyHub.registerAdapter(
            CrossChainPrivacyHub.AdapterRegistrationParams({
                chainId: chainId,
                adapter: mockAdapter,
                chainType: CrossChainPrivacyHub.ChainType.EVM,
                proofSystem: CrossChainPrivacyHub.ProofSystem.NONE,
                supportsPrivacy: true,
                minConfirmations: 1,
                maxTransfer: 1000 ether,
                dailyLimit: 10000 ether
            })
        );

        (address adapterAddr, , , , , , , , , , ) = privacyHub.adapters(
            chainId
        );
        assertEq(adapterAddr, mockAdapter);

        // Update adapter
        privacyHub.updateAdapter(chainId, false, 500 ether, 5000 ether);
        (, , , , bool isActive, , , , , , ) = privacyHub.adapters(chainId);
        assertFalse(isActive);
    }

    function test_CrossDomainBinding() public {
        bytes32 sourceNf = keccak256("source");
        uint256 srcChain = 1;
        uint256 dstChain = 10;

        // Mock register source nullifier first
        nullifierManager.registerNullifier(
            sourceNf,
            keccak256("commit"),
            srcChain,
            IUnifiedNullifierManager.NullifierType.STANDARD,
            0
        );

        // Set up a mock cross-chain verifier that always returns true
        TestProofVerifier mockVerifier = new TestProofVerifier();
        nullifierManager.setCrossChainVerifier(address(mockVerifier));

        // Create binding
        // We need a proof, but for local tests we can assume the internal verification passes
        // if we are not on mainnet (block.chainid != 1). Simple check.
        bytes memory proof = new bytes(32); // Valid length

        (bytes32 destNf, bytes32 zaseonNf) = nullifierManager
            .createCrossDomainBinding(sourceNf, srcChain, dstChain, proof);

        assertNotEq(destNf, bytes32(0));
        assertNotEq(zaseonNf, bytes32(0));

        (bool valid, bytes32 queriedPil) = nullifierManager
            .verifyCrossDomainBinding(sourceNf, destNf);
        assertTrue(valid);
        assertEq(queriedPil, zaseonNf);
    }
}

/// @notice Mock proof verifier that always returns true for testing
contract TestProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 3;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}
