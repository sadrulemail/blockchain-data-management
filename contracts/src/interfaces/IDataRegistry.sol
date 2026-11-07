// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IDataRegistry
/// @notice Shared types and read functions of the dataset registry, used by the access and quality ledgers.
interface IDataRegistry {
    /// @notice Sensitivity label of a dataset. Public datasets are readable by everyone; the rest need a grant.
    enum Classification {
        Public,
        Internal,
        Confidential,
        Restricted
    }

    /// @notice Lifecycle of a committed version. `None` means the version does not exist.
    enum VersionStatus {
        None,
        Active,
        Deprecated,
        Withdrawn
    }

    struct Dataset {
        address owner;
        Classification classification;
        bool archived;
        uint32 versionCount;
        uint64 createdAt;
        bytes32 schemaHash;
        string name;
        string metadataURI;
    }

    struct Version {
        bytes32 merkleRoot;
        bytes32 contentHash;
        bytes32 schemaHash;
        uint64 recordCount;
        uint64 committedAt;
        address committer;
        VersionStatus status;
        string storageURI;
    }

    struct VersionInput {
        bytes32 merkleRoot;
        bytes32 contentHash;
        bytes32 schemaHash;
        uint64 recordCount;
        string storageURI;
    }

    struct VersionRef {
        uint256 datasetId;
        uint32 version;
    }

    function exists(uint256 datasetId) external view returns (bool);

    function datasetOwner(uint256 datasetId) external view returns (address);

    function canManage(uint256 datasetId, address account) external view returns (bool);

    function classificationOf(uint256 datasetId) external view returns (Classification);

    function versionStatus(uint256 datasetId, uint32 version) external view returns (VersionStatus);
}
