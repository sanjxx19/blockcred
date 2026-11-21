// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title IssuerRegistry
/// @notice Trust anchor for BlockCred: which issuer DIDs are accredited, which Ethereum
///         account controls each issuer's on-chain operations, and which credential
///         schemas (SD-JWT VC `vct` values) are recognised.
/// @dev    Issuers are keyed by keccak256(utf8(did)). No personal data is ever stored.
///         In production DEFAULT_ADMIN_ROLE and GOVERNOR_ROLE should be held by a
///         multi-sig (e.g. Safe) and/or a TimelockController.
contract IssuerRegistry is AccessControl, Pausable {
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    enum Status {
        None,
        Active,
        Suspended,
        Revoked
    }

    struct Issuer {
        address controller;
        Status status;
        uint64 registeredAt;
        uint64 updatedAt;
        string did;
        string metadataURI;
    }

    struct Schema {
        bool registered;
        bool deprecated;
        uint64 registeredAt;
        string uri;
    }

    mapping(bytes32 => Issuer) private _issuers;
    mapping(bytes32 => Schema) private _schemas;
    uint256 public issuerCount;

    event IssuerRegistered(bytes32 indexed didHash, string did, address indexed controller, string metadataURI);
    event IssuerStatusChanged(bytes32 indexed didHash, Status previous, Status current);
    event ControllerRotated(bytes32 indexed didHash, address indexed previous, address indexed current);
    event IssuerMetadataUpdated(bytes32 indexed didHash, string metadataURI);
    event SchemaRegistered(bytes32 indexed schemaHash, string uri);
    event SchemaDeprecated(bytes32 indexed schemaHash);

    error ZeroAddress();
    error EmptyDid();
    error IssuerAlreadyRegistered(bytes32 didHash);
    error IssuerNotFound(bytes32 didHash);
    error InvalidStatusTransition(Status current, Status requested);
    error NotAuthorized();
    error SchemaAlreadyRegistered(bytes32 schemaHash);
    error SchemaNotFound(bytes32 schemaHash);

    constructor(address admin, address[] memory governors) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        for (uint256 i = 0; i < governors.length; i++) {
            if (governors[i] == address(0)) revert ZeroAddress();
            _grantRole(GOVERNOR_ROLE, governors[i]);
        }
    }

    // ------------------------------------------------------------------ issuers

    function registerIssuer(string calldata did, address controller, string calldata metadataURI)
        external
        onlyRole(GOVERNOR_ROLE)
        whenNotPaused
        returns (bytes32 didHash)
    {
        if (bytes(did).length == 0) revert EmptyDid();
        if (controller == address(0)) revert ZeroAddress();
        didHash = keccak256(bytes(did));
        if (_issuers[didHash].status != Status.None) revert IssuerAlreadyRegistered(didHash);

        uint64 nowTs = uint64(block.timestamp);
        _issuers[didHash] = Issuer({
            controller: controller,
            status: Status.Active,
            registeredAt: nowTs,
            updatedAt: nowTs,
            did: did,
            metadataURI: metadataURI
        });
        unchecked {
            issuerCount++;
        }
        emit IssuerRegistered(didHash, did, controller, metadataURI);
        emit IssuerStatusChanged(didHash, Status.None, Status.Active);
    }

    /// @notice Temporarily stop trusting an issuer (e.g. under investigation).
    ///         A suspended issuer can still revoke credentials but cannot anchor new batches.
    function suspendIssuer(bytes32 didHash) external onlyRole(GOVERNOR_ROLE) {
        _transition(didHash, Status.Active, Status.Suspended);
    }

    function reinstateIssuer(bytes32 didHash) external onlyRole(GOVERNOR_ROLE) whenNotPaused {
        _transition(didHash, Status.Suspended, Status.Active);
    }

    /// @notice Permanently de-accredit an issuer. Irreversible.
    function revokeIssuer(bytes32 didHash) external onlyRole(GOVERNOR_ROLE) {
        Issuer storage issuer = _getExisting(didHash);
        Status previous = issuer.status;
        if (previous == Status.Revoked) revert InvalidStatusTransition(previous, Status.Revoked);
        issuer.status = Status.Revoked;
        issuer.updatedAt = uint64(block.timestamp);
        emit IssuerStatusChanged(didHash, previous, Status.Revoked);
    }

    /// @notice Rotate the Ethereum account that operates an issuer (e.g. after a hot-wallet
    ///         compromise). Governor-only so a stolen controller key cannot lock the issuer out.
    function rotateController(bytes32 didHash, address newController) external onlyRole(GOVERNOR_ROLE) {
        Issuer storage issuer = _getExisting(didHash);
        if (issuer.status == Status.Revoked) revert InvalidStatusTransition(Status.Revoked, Status.Revoked);
        if (newController == address(0)) revert ZeroAddress();
        address previous = issuer.controller;
        issuer.controller = newController;
        issuer.updatedAt = uint64(block.timestamp);
        emit ControllerRotated(didHash, previous, newController);
    }

    function updateMetadata(bytes32 didHash, string calldata metadataURI) external {
        Issuer storage issuer = _getExisting(didHash);
        if (msg.sender != issuer.controller && !hasRole(GOVERNOR_ROLE, msg.sender)) revert NotAuthorized();
        issuer.metadataURI = metadataURI;
        issuer.updatedAt = uint64(block.timestamp);
        emit IssuerMetadataUpdated(didHash, metadataURI);
    }

    // ------------------------------------------------------------------ schemas

    function registerSchema(bytes32 schemaHash, string calldata uri) external onlyRole(GOVERNOR_ROLE) {
        if (_schemas[schemaHash].registered) revert SchemaAlreadyRegistered(schemaHash);
        _schemas[schemaHash] = Schema({registered: true, deprecated: false, registeredAt: uint64(block.timestamp), uri: uri});
        emit SchemaRegistered(schemaHash, uri);
    }

    function deprecateSchema(bytes32 schemaHash) external onlyRole(GOVERNOR_ROLE) {
        if (!_schemas[schemaHash].registered) revert SchemaNotFound(schemaHash);
        _schemas[schemaHash].deprecated = true;
        emit SchemaDeprecated(schemaHash);
    }

    // ------------------------------------------------------------------ emergency

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ------------------------------------------------------------------ views

    function getIssuer(bytes32 didHash) external view returns (Issuer memory) {
        return _issuers[didHash];
    }

    function getSchema(bytes32 schemaHash) external view returns (Schema memory) {
        return _schemas[schemaHash];
    }

    function isAccredited(bytes32 didHash) public view returns (bool) {
        return _issuers[didHash].status == Status.Active;
    }

    function isAccreditedDid(string calldata did) external view returns (bool) {
        return isAccredited(keccak256(bytes(did)));
    }

    /// @notice True if `account` may perform issuance-side operations (anchoring).
    function isActiveController(bytes32 didHash, address account) external view returns (bool) {
        Issuer storage issuer = _issuers[didHash];
        return issuer.status == Status.Active && issuer.controller == account;
    }

    /// @notice True if `account` may revoke credentials. Allowed while Active or Suspended,
    ///         so an issuer under investigation can still revoke bad credentials.
    function canRevoke(bytes32 didHash, address account) external view returns (bool) {
        Issuer storage issuer = _issuers[didHash];
        return (issuer.status == Status.Active || issuer.status == Status.Suspended) && issuer.controller == account;
    }

    function isSchemaRegistered(bytes32 schemaHash) external view returns (bool) {
        Schema storage schema = _schemas[schemaHash];
        return schema.registered && !schema.deprecated;
    }

    function didHashOf(string calldata did) external pure returns (bytes32) {
        return keccak256(bytes(did));
    }

    // ------------------------------------------------------------------ internal

    function _getExisting(bytes32 didHash) private view returns (Issuer storage issuer) {
        issuer = _issuers[didHash];
        if (issuer.status == Status.None) revert IssuerNotFound(didHash);
    }

    function _transition(bytes32 didHash, Status expected, Status next) private {
        Issuer storage issuer = _getExisting(didHash);
        if (issuer.status != expected) revert InvalidStatusTransition(issuer.status, next);
        issuer.status = next;
        issuer.updatedAt = uint64(block.timestamp);
        emit IssuerStatusChanged(didHash, expected, next);
    }
}
