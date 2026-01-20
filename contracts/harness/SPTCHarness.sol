// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SPTCHarness
 * @notice Simplified harness for Certora verification of SPTC properties
 * @dev Contains core invariants without deep stack complexity
 */
contract SPTCHarness is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant CERTIFIED_TRANSLATOR_ROLE =
        keccak256("CERTIFIED_TRANSLATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    enum ProofSystem {
        GROTH16,
        PLONK,
        STARK,
        BULLETPROOFS,
        NOVA,
        HALO2,
        SPARTAN
    }

    enum CertificateStatus {
        Valid,
        Revoked,
        Expired,
        Challenged
    }

    /// @notice Simplified certificate for verification
    struct SimpleCertificate {
        bytes32 certificateId;
        bytes32 sourceProofHash;
        bytes32 targetProofHash;
        ProofSystem sourceSystem;
        ProofSystem targetSystem;
        address translator;
        uint64 issuedAt;
        uint64 expiresAt;
        CertificateStatus status;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Translator stake requirements
    uint256 public minTranslatorStake;
    mapping(address => uint256) public translatorStake;

    /// @notice Certificate storage
    mapping(bytes32 => SimpleCertificate) public certificates;
    mapping(bytes32 => bool) public validCertificates;

    /// @notice Counters
    uint256 public totalCertificates;
    mapping(address => uint256) public translatorSuccessCount;

    /// @notice Certificate validity period
    uint256 public certificateValidityPeriod = 30 days;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(uint256 _minStake) {
        minTranslatorStake = _minStake;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          TRANSLATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function stake() external payable {
        translatorStake[msg.sender] += msg.value;
    }

    function registerAsTranslator() external {
        require(
            translatorStake[msg.sender] >= minTranslatorStake,
            "Insufficient stake"
        );
        _grantRole(CERTIFIED_TRANSLATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         CERTIFICATE ISSUANCE
    //////////////////////////////////////////////////////////////*/

    function issueCertificate(
        bytes32 sourceProofHash,
        bytes32 targetProofHash,
        ProofSystem sourceSystem,
        ProofSystem targetSystem
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(CERTIFIED_TRANSLATOR_ROLE)
        returns (bytes32 certificateId)
    {
        require(
            translatorStake[msg.sender] >= minTranslatorStake,
            "Insufficient stake"
        );

        certificateId = keccak256(
            abi.encodePacked(
                sourceProofHash,
                targetProofHash,
                msg.sender,
                block.timestamp
            )
        );

        certificates[certificateId] = SimpleCertificate({
            certificateId: certificateId,
            sourceProofHash: sourceProofHash,
            targetProofHash: targetProofHash,
            sourceSystem: sourceSystem,
            targetSystem: targetSystem,
            translator: msg.sender,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + certificateValidityPeriod),
            status: CertificateStatus.Valid
        });

        validCertificates[certificateId] = true;
        totalCertificates++;
        translatorSuccessCount[msg.sender]++;

        return certificateId;
    }

    /*//////////////////////////////////////////////////////////////
                         CERTIFICATE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function verifyCertificate(
        bytes32 certificateId
    ) external view returns (bool valid, SimpleCertificate memory certificate) {
        certificate = certificates[certificateId];

        if (certificate.certificateId == bytes32(0)) {
            return (false, certificate);
        }

        if (certificate.status != CertificateStatus.Valid) {
            return (false, certificate);
        }

        if (block.timestamp > certificate.expiresAt) {
            return (false, certificate);
        }

        return (true, certificate);
    }

    function isValidCertificate(
        bytes32 certificateId
    ) external view returns (bool) {
        return
            validCertificates[certificateId] &&
            certificates[certificateId].status == CertificateStatus.Valid &&
            block.timestamp <= certificates[certificateId].expiresAt;
    }

    /*//////////////////////////////////////////////////////////////
                          CERTIFICATE REVOCATION
    //////////////////////////////////////////////////////////////*/

    function revokeCertificate(
        bytes32 certificateId
    ) external onlyRole(ADMIN_ROLE) {
        require(
            certificates[certificateId].certificateId != bytes32(0),
            "Certificate not found"
        );
        certificates[certificateId].status = CertificateStatus.Revoked;
        validCertificates[certificateId] = false;
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    function getCertificateStatus(
        bytes32 certificateId
    ) external view returns (CertificateStatus) {
        return certificates[certificateId].status;
    }

    function getCertificateTranslator(
        bytes32 certificateId
    ) external view returns (address) {
        return certificates[certificateId].translator;
    }
}
