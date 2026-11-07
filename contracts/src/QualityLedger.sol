// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IDataRegistry} from "./interfaces/IDataRegistry.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title QualityLedger
/// @notice Independent data-quality attestations per dataset version. An auditor runs the checks off-chain,
///         publishes the report and signs its hash here. Auditors cannot attest datasets they manage.
contract QualityLedger is AccessControl {
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    uint16 public constant MAX_SCORE_BPS = 10_000;

    struct Attestation {
        address auditor;
        uint16 scoreBps;
        bool passed;
        uint64 attestedAt;
        bytes32 reportHash;
        string reportURI;
    }

    IDataRegistry public immutable registry;

    mapping(uint256 datasetId => mapping(uint32 version => Attestation[])) private _attestations;
    mapping(uint256 datasetId => mapping(uint32 version => mapping(address auditor => bool))) public hasAttested;

    event QualityAttested(
        uint256 indexed datasetId,
        uint32 indexed version,
        address indexed auditor,
        uint16 scoreBps,
        bool passed,
        bytes32 reportHash,
        string reportURI
    );

    error InvalidAccount();
    error InvalidScore(uint16 scoreBps);
    error InvalidHash();
    error VersionNotAttestable(uint256 datasetId, uint32 version);
    error AlreadyAttested(uint256 datasetId, uint32 version, address auditor);
    error ConflictOfInterest(uint256 datasetId, address auditor);
    error UnknownAttestation(uint256 datasetId, uint32 version, uint256 index);

    constructor(IDataRegistry registry_, address admin) {
        if (address(registry_) == address(0) || admin == address(0)) revert InvalidAccount();
        registry = registry_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function attest(
        uint256 datasetId,
        uint32 version,
        uint16 scoreBps,
        bool passed,
        bytes32 reportHash,
        string calldata reportURI
    ) external onlyRole(AUDITOR_ROLE) {
        IDataRegistry.VersionStatus status = registry.versionStatus(datasetId, version);
        if (status != IDataRegistry.VersionStatus.Active && status != IDataRegistry.VersionStatus.Deprecated) {
            revert VersionNotAttestable(datasetId, version);
        }
        if (scoreBps > MAX_SCORE_BPS) revert InvalidScore(scoreBps);
        if (reportHash == bytes32(0)) revert InvalidHash();
        if (registry.canManage(datasetId, msg.sender)) revert ConflictOfInterest(datasetId, msg.sender);
        if (hasAttested[datasetId][version][msg.sender]) revert AlreadyAttested(datasetId, version, msg.sender);

        hasAttested[datasetId][version][msg.sender] = true;
        _attestations[datasetId][version].push(
            Attestation({
                auditor: msg.sender,
                scoreBps: scoreBps,
                passed: passed,
                attestedAt: uint64(block.timestamp),
                reportHash: reportHash,
                reportURI: reportURI
            })
        );
        emit QualityAttested(datasetId, version, msg.sender, scoreBps, passed, reportHash, reportURI);
    }

    function attestationCount(uint256 datasetId, uint32 version) external view returns (uint256) {
        return _attestations[datasetId][version].length;
    }

    function getAttestation(uint256 datasetId, uint32 version, uint256 index)
        external
        view
        returns (Attestation memory)
    {
        Attestation[] storage list = _attestations[datasetId][version];
        if (index >= list.length) revert UnknownAttestation(datasetId, version, index);
        return list[index];
    }

    /// @notice Roll-up for consumers: how many auditors looked, how many passed it, and the lowest score given.
    function qualitySummary(uint256 datasetId, uint32 version)
        external
        view
        returns (uint256 count, uint256 passedCount, uint16 minScoreBps)
    {
        Attestation[] storage list = _attestations[datasetId][version];
        count = list.length;
        minScoreBps = count == 0 ? 0 : MAX_SCORE_BPS;
        for (uint256 i = 0; i < count; ++i) {
            if (list[i].passed) ++passedCount;
            if (list[i].scoreBps < minScoreBps) minScoreBps = list[i].scoreBps;
        }
    }
}
