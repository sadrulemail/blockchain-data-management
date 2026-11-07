// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IDataRegistry} from "./interfaces/IDataRegistry.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title AccessLedger
/// @notice Consent and access control for registered datasets. Consumers request access with a stated purpose,
///         dataset managers approve time-boxed grants, and the data gateway records every read on-chain.
contract AccessLedger is AccessControl {
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    uint64 public constant MAX_GRANT_DURATION = 365 days;

    enum RequestStatus {
        None,
        Pending,
        Approved,
        Rejected,
        Cancelled
    }

    struct Grant {
        bytes32 purposeHash;
        address grantedBy;
        uint64 grantedAt;
        uint64 expiresAt;
        bool revoked;
    }

    struct AccessRequest {
        uint256 datasetId;
        address requester;
        uint64 requestedAt;
        RequestStatus status;
        bytes32 purposeHash;
    }

    IDataRegistry public immutable registry;

    uint256 public requestCount;
    mapping(uint256 datasetId => mapping(address account => Grant)) private _grants;
    mapping(uint256 requestId => AccessRequest) private _requests;
    mapping(uint256 datasetId => mapping(address account => uint256 requestId)) public openRequestOf;
    mapping(uint256 datasetId => uint256) public accessCount;

    event AccessRequested(
        uint256 indexed requestId,
        uint256 indexed datasetId,
        address indexed requester,
        bytes32 purposeHash,
        string purpose
    );
    event AccessRequestApproved(uint256 indexed requestId, address indexed approver, uint64 expiresAt);
    event AccessRequestRejected(uint256 indexed requestId, address indexed approver, string reason);
    event AccessRequestCancelled(uint256 indexed requestId);
    event AccessGranted(
        uint256 indexed datasetId,
        address indexed grantee,
        address indexed grantedBy,
        bytes32 purposeHash,
        uint64 expiresAt
    );
    event AccessRevoked(uint256 indexed datasetId, address indexed grantee, address indexed revokedBy);
    event DataAccessed(
        uint256 indexed datasetId, uint32 indexed version, address indexed accessor, bytes32 receiptHash
    );

    error UnknownDataset(uint256 datasetId);
    error UnknownRequest(uint256 requestId);
    error NotDatasetManager(uint256 datasetId, address account);
    error NotRequester(uint256 requestId, address account);
    error RequestNotPending(uint256 requestId);
    error RequestAlreadyOpen(uint256 datasetId, address requester, uint256 requestId);
    error AccessNotRequired(uint256 datasetId, address account);
    error InvalidDuration(uint64 duration);
    error InvalidAccount();
    error EmptyPurpose();
    error NoActiveGrant(uint256 datasetId, address account);
    error AccessDenied(uint256 datasetId, address account);
    error VersionNotServable(uint256 datasetId, uint32 version);

    constructor(IDataRegistry registry_, address admin) {
        if (address(registry_) == address(0) || admin == address(0)) revert InvalidAccount();
        registry = registry_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Request / approve flow
    // ---------------------------------------------------------------------------------------------------------------

    function requestAccess(uint256 datasetId, string calldata purpose) external returns (uint256 requestId) {
        _requireDataset(datasetId);
        if (bytes(purpose).length == 0) revert EmptyPurpose();
        if (hasAccess(datasetId, msg.sender)) revert AccessNotRequired(datasetId, msg.sender);
        uint256 open = openRequestOf[datasetId][msg.sender];
        if (open != 0) revert RequestAlreadyOpen(datasetId, msg.sender, open);

        requestId = ++requestCount;
        bytes32 purposeHash = keccak256(bytes(purpose));
        _requests[requestId] = AccessRequest({
            datasetId: datasetId,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            status: RequestStatus.Pending,
            purposeHash: purposeHash
        });
        openRequestOf[datasetId][msg.sender] = requestId;

        emit AccessRequested(requestId, datasetId, msg.sender, purposeHash, purpose);
    }

    function approveRequest(uint256 requestId, uint64 duration) external {
        AccessRequest storage req = _pendingRequest(requestId);
        _requireManager(req.datasetId);
        req.status = RequestStatus.Approved;
        delete openRequestOf[req.datasetId][req.requester];

        uint64 expiresAt = _writeGrant(req.datasetId, req.requester, req.purposeHash, duration);
        emit AccessRequestApproved(requestId, msg.sender, expiresAt);
    }

    function rejectRequest(uint256 requestId, string calldata reason) external {
        AccessRequest storage req = _pendingRequest(requestId);
        _requireManager(req.datasetId);
        req.status = RequestStatus.Rejected;
        delete openRequestOf[req.datasetId][req.requester];
        emit AccessRequestRejected(requestId, msg.sender, reason);
    }

    function cancelRequest(uint256 requestId) external {
        AccessRequest storage req = _pendingRequest(requestId);
        if (req.requester != msg.sender) revert NotRequester(requestId, msg.sender);
        req.status = RequestStatus.Cancelled;
        delete openRequestOf[req.datasetId][req.requester];
        emit AccessRequestCancelled(requestId);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Direct grants
    // ---------------------------------------------------------------------------------------------------------------

    function grantAccess(uint256 datasetId, address grantee, uint64 duration, string calldata purpose) external {
        _requireDataset(datasetId);
        _requireManager(datasetId);
        if (grantee == address(0)) revert InvalidAccount();
        if (bytes(purpose).length == 0) revert EmptyPurpose();
        _writeGrant(datasetId, grantee, keccak256(bytes(purpose)), duration);
    }

    function revokeAccess(uint256 datasetId, address grantee) external {
        _requireDataset(datasetId);
        _requireManager(datasetId);
        _revoke(datasetId, grantee);
    }

    /// @notice Lets a grantee give up access before it expires.
    function renounceAccess(uint256 datasetId) external {
        _revoke(datasetId, msg.sender);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Gateway
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Called by the data gateway before it serves a version. Rechecks access so a buggy gateway cannot
    ///         leak data without leaving evidence, and refuses withdrawn versions.
    function logAccess(uint256 datasetId, uint32 version, address accessor, bytes32 receiptHash)
        external
        onlyRole(GATEWAY_ROLE)
    {
        IDataRegistry.VersionStatus status = registry.versionStatus(datasetId, version);
        if (status != IDataRegistry.VersionStatus.Active && status != IDataRegistry.VersionStatus.Deprecated) {
            revert VersionNotServable(datasetId, version);
        }
        if (!hasAccess(datasetId, accessor)) revert AccessDenied(datasetId, accessor);
        ++accessCount[datasetId];
        emit DataAccessed(datasetId, version, accessor, receiptHash);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Public datasets are open; otherwise the owner, stewards and holders of a live grant may read.
    function hasAccess(uint256 datasetId, address account) public view returns (bool) {
        if (!registry.exists(datasetId)) return false;
        if (registry.classificationOf(datasetId) == IDataRegistry.Classification.Public) return true;
        if (registry.canManage(datasetId, account)) return true;
        Grant storage g = _grants[datasetId][account];
        return !g.revoked && g.expiresAt > block.timestamp;
    }

    function getGrant(uint256 datasetId, address account) external view returns (Grant memory) {
        return _grants[datasetId][account];
    }

    function getRequest(uint256 requestId) external view returns (AccessRequest memory) {
        AccessRequest storage req = _requests[requestId];
        if (req.status == RequestStatus.None) revert UnknownRequest(requestId);
        return req;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------------------------

    function _writeGrant(uint256 datasetId, address grantee, bytes32 purposeHash, uint64 duration)
        private
        returns (uint64 expiresAt)
    {
        if (duration == 0 || duration > MAX_GRANT_DURATION) revert InvalidDuration(duration);
        expiresAt = uint64(block.timestamp) + duration;
        _grants[datasetId][grantee] = Grant({
            purposeHash: purposeHash,
            grantedBy: msg.sender,
            grantedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revoked: false
        });
        emit AccessGranted(datasetId, grantee, msg.sender, purposeHash, expiresAt);
    }

    function _revoke(uint256 datasetId, address grantee) private {
        Grant storage g = _grants[datasetId][grantee];
        if (g.revoked || g.expiresAt <= block.timestamp) revert NoActiveGrant(datasetId, grantee);
        g.revoked = true;
        emit AccessRevoked(datasetId, grantee, msg.sender);
    }

    function _pendingRequest(uint256 requestId) private view returns (AccessRequest storage req) {
        req = _requests[requestId];
        if (req.status == RequestStatus.None) revert UnknownRequest(requestId);
        if (req.status != RequestStatus.Pending) revert RequestNotPending(requestId);
    }

    function _requireDataset(uint256 datasetId) private view {
        if (!registry.exists(datasetId)) revert UnknownDataset(datasetId);
    }

    function _requireManager(uint256 datasetId) private view {
        if (!registry.canManage(datasetId, msg.sender)) revert NotDatasetManager(datasetId, msg.sender);
    }
}
