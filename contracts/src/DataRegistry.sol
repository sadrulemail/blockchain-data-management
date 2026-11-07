// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IDataRegistry} from "./interfaces/IDataRegistry.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title DataRegistry
/// @notice On-chain catalogue of datasets and their immutable versions. Data never lives here: each version anchors
///         a Merkle root over canonical records, a SHA-256 fingerprint of the file and a pointer to encrypted storage.
///         Versions can name parent versions, which builds a verifiable lineage graph across datasets.
contract DataRegistry is IDataRegistry, AccessControl, Pausable {
    bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 public constant MAX_PARENTS = 16;
    uint256 public constant MAX_NAME_LENGTH = 64;

    uint256 public datasetCount;

    mapping(uint256 datasetId => Dataset) private _datasets;
    mapping(uint256 datasetId => mapping(uint32 version => Version)) private _versions;
    mapping(uint256 datasetId => mapping(uint32 version => VersionRef[])) private _parents;
    mapping(uint256 datasetId => mapping(address account => bool)) private _stewards;
    mapping(uint256 datasetId => address) private _pendingOwners;
    mapping(bytes32 contentHash => VersionRef) private _contentIndex;

    event DatasetRegistered(
        uint256 indexed datasetId,
        address indexed owner,
        string name,
        Classification classification,
        bytes32 schemaHash,
        string metadataURI
    );
    event VersionCommitted(
        uint256 indexed datasetId,
        uint32 indexed version,
        address indexed committer,
        bytes32 merkleRoot,
        bytes32 contentHash,
        uint64 recordCount,
        string storageURI
    );
    event LineageLinked(
        uint256 indexed datasetId, uint32 indexed version, uint256 indexed parentDatasetId, uint32 parentVersion
    );
    event SchemaChanged(uint256 indexed datasetId, uint32 indexed version, bytes32 previousSchema, bytes32 newSchema);
    event VersionStatusChanged(
        uint256 indexed datasetId, uint32 indexed version, VersionStatus previous, VersionStatus current, string reason
    );
    event StewardUpdated(uint256 indexed datasetId, address indexed account, bool enabled);
    event MetadataUpdated(uint256 indexed datasetId, string metadataURI);
    event ClassificationChanged(uint256 indexed datasetId, Classification previous, Classification current);
    event DatasetArchived(uint256 indexed datasetId);
    event OwnershipTransferStarted(uint256 indexed datasetId, address indexed currentOwner, address indexed newOwner);
    event OwnershipTransferred(uint256 indexed datasetId, address indexed previousOwner, address indexed newOwner);

    error UnknownDataset(uint256 datasetId);
    error UnknownVersion(uint256 datasetId, uint32 version);
    error NotDatasetOwner(uint256 datasetId, address account);
    error NotDatasetManager(uint256 datasetId, address account);
    error DatasetIsArchived(uint256 datasetId);
    error InvalidName();
    error InvalidHash();
    error EmptyDataset();
    error EmptyStorageURI();
    error TooManyParents(uint256 count);
    error DuplicateParent(uint256 datasetId, uint32 version);
    error ParentNotUsable(uint256 datasetId, uint32 version);
    error InvalidStatusTransition(VersionStatus current, VersionStatus requested);
    error InvalidAccount();
    error NotPendingOwner(uint256 datasetId, address account);

    constructor(address admin) {
        if (admin == address(0)) revert InvalidAccount();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Dataset lifecycle
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Registers a dataset owned by the caller. The schema hash fixes the record structure for version 1.
    function registerDataset(
        string calldata name,
        Classification classification,
        bytes32 schemaHash,
        string calldata metadataURI
    ) external onlyRole(PUBLISHER_ROLE) whenNotPaused returns (uint256 datasetId) {
        uint256 nameLength = bytes(name).length;
        if (nameLength == 0 || nameLength > MAX_NAME_LENGTH) revert InvalidName();
        if (schemaHash == bytes32(0)) revert InvalidHash();

        datasetId = ++datasetCount;
        Dataset storage ds = _datasets[datasetId];
        ds.owner = msg.sender;
        ds.classification = classification;
        ds.createdAt = uint64(block.timestamp);
        ds.schemaHash = schemaHash;
        ds.name = name;
        ds.metadataURI = metadataURI;

        emit DatasetRegistered(datasetId, msg.sender, name, classification, schemaHash, metadataURI);
    }

    /// @notice Anchors a new immutable version. Parents record which upstream versions the data was derived from.
    function commitVersion(uint256 datasetId, VersionInput calldata input, VersionRef[] calldata parents)
        external
        whenNotPaused
        returns (uint32 version)
    {
        Dataset storage ds = _managedDataset(datasetId);
        if (ds.archived) revert DatasetIsArchived(datasetId);
        if (input.merkleRoot == bytes32(0) || input.contentHash == bytes32(0) || input.schemaHash == bytes32(0)) {
            revert InvalidHash();
        }
        if (input.recordCount == 0) revert EmptyDataset();
        if (bytes(input.storageURI).length == 0) revert EmptyStorageURI();
        if (parents.length > MAX_PARENTS) revert TooManyParents(parents.length);

        version = ++ds.versionCount;

        for (uint256 i = 0; i < parents.length; ++i) {
            VersionRef calldata parent = parents[i];
            VersionStatus parentStatus = _versions[parent.datasetId][parent.version].status;
            if (parentStatus != VersionStatus.Active && parentStatus != VersionStatus.Deprecated) {
                revert ParentNotUsable(parent.datasetId, parent.version);
            }
            for (uint256 j = 0; j < i; ++j) {
                if (parents[j].datasetId == parent.datasetId && parents[j].version == parent.version) {
                    revert DuplicateParent(parent.datasetId, parent.version);
                }
            }
            _parents[datasetId][version].push(parent);
            emit LineageLinked(datasetId, version, parent.datasetId, parent.version);
        }

        Version storage v = _versions[datasetId][version];
        v.merkleRoot = input.merkleRoot;
        v.contentHash = input.contentHash;
        v.schemaHash = input.schemaHash;
        v.recordCount = input.recordCount;
        v.committedAt = uint64(block.timestamp);
        v.committer = msg.sender;
        v.status = VersionStatus.Active;
        v.storageURI = input.storageURI;

        if (_contentIndex[input.contentHash].datasetId == 0) {
            _contentIndex[input.contentHash] = VersionRef({datasetId: datasetId, version: version});
        }

        if (input.schemaHash != ds.schemaHash) {
            emit SchemaChanged(datasetId, version, ds.schemaHash, input.schemaHash);
            ds.schemaHash = input.schemaHash;
        }

        emit VersionCommitted(
            datasetId, version, msg.sender, input.merkleRoot, input.contentHash, input.recordCount, input.storageURI
        );
    }

    /// @notice Moves a version forward in its lifecycle: Active -> Deprecated -> Withdrawn. Withdrawn is final.
    function setVersionStatus(uint256 datasetId, uint32 version, VersionStatus status, string calldata reason)
        external
    {
        _managedDataset(datasetId);
        Version storage v = _versions[datasetId][version];
        VersionStatus current = v.status;
        if (current == VersionStatus.None) revert UnknownVersion(datasetId, version);
        bool allowed =
            (current == VersionStatus.Active
                    && (status == VersionStatus.Deprecated || status == VersionStatus.Withdrawn))
                || (current == VersionStatus.Deprecated && status == VersionStatus.Withdrawn);
        if (!allowed) revert InvalidStatusTransition(current, status);

        v.status = status;
        emit VersionStatusChanged(datasetId, version, current, status, reason);
    }

    function setSteward(uint256 datasetId, address account, bool enabled) external {
        _ownedDataset(datasetId);
        if (account == address(0)) revert InvalidAccount();
        _stewards[datasetId][account] = enabled;
        emit StewardUpdated(datasetId, account, enabled);
    }

    function updateMetadata(uint256 datasetId, string calldata metadataURI) external {
        _managedDataset(datasetId).metadataURI = metadataURI;
        emit MetadataUpdated(datasetId, metadataURI);
    }

    function setClassification(uint256 datasetId, Classification classification) external {
        Dataset storage ds = _ownedDataset(datasetId);
        Classification previous = ds.classification;
        ds.classification = classification;
        emit ClassificationChanged(datasetId, previous, classification);
    }

    /// @notice Closes a dataset for new versions. Existing versions stay verifiable.
    function archiveDataset(uint256 datasetId) external {
        Dataset storage ds = _ownedDataset(datasetId);
        if (ds.archived) revert DatasetIsArchived(datasetId);
        ds.archived = true;
        emit DatasetArchived(datasetId);
    }

    /// @notice First step of a two-step ownership hand-over; the new owner must accept.
    function transferDatasetOwnership(uint256 datasetId, address newOwner) external {
        _ownedDataset(datasetId);
        if (newOwner == address(0)) revert InvalidAccount();
        _pendingOwners[datasetId] = newOwner;
        emit OwnershipTransferStarted(datasetId, msg.sender, newOwner);
    }

    function acceptDatasetOwnership(uint256 datasetId) external {
        Dataset storage ds = _existingDataset(datasetId);
        if (_pendingOwners[datasetId] != msg.sender) revert NotPendingOwner(datasetId, msg.sender);
        address previous = ds.owner;
        ds.owner = msg.sender;
        delete _pendingOwners[datasetId];
        emit OwnershipTransferred(datasetId, previous, msg.sender);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Verification
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Leaf of one record: double keccak over (position, canonical bytes), so a leaf can never pass as a node.
    function recordLeaf(uint256 index, bytes calldata record) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(index, record))));
    }

    /// @notice True when `record` at `index` is part of the version's Merkle root. Status is reported separately.
    function verifyRecord(
        uint256 datasetId,
        uint32 version,
        uint256 index,
        bytes calldata record,
        bytes32[] calldata proof
    ) external view returns (bool) {
        Version storage v = _versions[datasetId][version];
        if (v.status == VersionStatus.None) revert UnknownVersion(datasetId, version);
        if (index >= v.recordCount) return false;
        return MerkleProof.verifyCalldata(proof, v.merkleRoot, recordLeaf(index, record));
    }

    /// @notice First version that anchored a given file fingerprint, or (0, 0) when the file is unknown.
    function locateContent(bytes32 contentHash) external view returns (uint256 datasetId, uint32 version) {
        VersionRef memory ref = _contentIndex[contentHash];
        return (ref.datasetId, ref.version);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------------------------

    function getDataset(uint256 datasetId) external view returns (Dataset memory) {
        return _existingDataset(datasetId);
    }

    function getVersion(uint256 datasetId, uint32 version) external view returns (Version memory) {
        Version storage v = _versions[datasetId][version];
        if (v.status == VersionStatus.None) revert UnknownVersion(datasetId, version);
        return v;
    }

    function getParents(uint256 datasetId, uint32 version) external view returns (VersionRef[] memory) {
        return _parents[datasetId][version];
    }

    function pendingOwner(uint256 datasetId) external view returns (address) {
        return _pendingOwners[datasetId];
    }

    function isSteward(uint256 datasetId, address account) external view returns (bool) {
        return _stewards[datasetId][account];
    }

    function exists(uint256 datasetId) public view returns (bool) {
        return datasetId != 0 && datasetId <= datasetCount;
    }

    function datasetOwner(uint256 datasetId) external view returns (address) {
        return _existingDataset(datasetId).owner;
    }

    function canManage(uint256 datasetId, address account) public view returns (bool) {
        return _existingDataset(datasetId).owner == account || _stewards[datasetId][account];
    }

    function classificationOf(uint256 datasetId) external view returns (Classification) {
        return _existingDataset(datasetId).classification;
    }

    function versionStatus(uint256 datasetId, uint32 version) external view returns (VersionStatus) {
        return _versions[datasetId][version].status;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Internal guards
    // ---------------------------------------------------------------------------------------------------------------

    function _existingDataset(uint256 datasetId) private view returns (Dataset storage) {
        if (!exists(datasetId)) revert UnknownDataset(datasetId);
        return _datasets[datasetId];
    }

    function _ownedDataset(uint256 datasetId) private view returns (Dataset storage ds) {
        ds = _existingDataset(datasetId);
        if (ds.owner != msg.sender) revert NotDatasetOwner(datasetId, msg.sender);
    }

    function _managedDataset(uint256 datasetId) private view returns (Dataset storage ds) {
        ds = _existingDataset(datasetId);
        if (ds.owner != msg.sender && !_stewards[datasetId][msg.sender]) {
            revert NotDatasetManager(datasetId, msg.sender);
        }
    }
}
