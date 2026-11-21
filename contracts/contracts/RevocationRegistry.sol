// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IssuerRegistry} from "./IssuerRegistry.sol";

/// @title RevocationRegistry
/// @notice Per-issuer revocation bitstring packed into uint256 words (256 credentials per
///         storage slot). Credentials carry only an opaque random index; nothing on-chain
///         links an index to a person.
/// @dev    Revocation is permanent and idempotent. It is intentionally NOT pausable:
///         an emergency pause must never stop issuers from revoking compromised credentials.
contract RevocationRegistry {
    uint256 public constant MAX_BATCH_SIZE = 512;

    IssuerRegistry public immutable issuerRegistry;

    mapping(bytes32 => mapping(uint256 => uint256)) private _words;
    mapping(bytes32 => uint256) public revokedCount;

    event CredentialRevoked(bytes32 indexed didHash, uint256 indexed index, address indexed revokedBy);

    error ZeroAddress();
    error NotIssuerController(bytes32 didHash, address caller);
    error EmptyBatch();
    error BatchTooLarge(uint256 size, uint256 max);

    constructor(IssuerRegistry registry) {
        if (address(registry) == address(0)) revert ZeroAddress();
        issuerRegistry = registry;
    }

    modifier onlyController(bytes32 didHash) {
        if (!issuerRegistry.canRevoke(didHash, msg.sender)) revert NotIssuerController(didHash, msg.sender);
        _;
    }

    function revoke(bytes32 didHash, uint256 index) external onlyController(didHash) {
        _revoke(didHash, index);
    }

    function revokeBatch(bytes32 didHash, uint256[] calldata indices) external onlyController(didHash) {
        uint256 n = indices.length;
        if (n == 0) revert EmptyBatch();
        if (n > MAX_BATCH_SIZE) revert BatchTooLarge(n, MAX_BATCH_SIZE);
        for (uint256 i = 0; i < n; ) {
            _revoke(didHash, indices[i]);
            unchecked {
                ++i;
            }
        }
    }

    function isRevoked(bytes32 didHash, uint256 index) public view returns (bool) {
        return ((_words[didHash][index >> 8] >> (index & 0xff)) & 1) == 1;
    }

    function isRevokedBatch(bytes32 didHash, uint256[] calldata indices) external view returns (bool[] memory result) {
        result = new bool[](indices.length);
        for (uint256 i = 0; i < indices.length; i++) {
            result[i] = isRevoked(didHash, indices[i]);
        }
    }

    /// @notice Returns a whole 256-bit word. Verifiers should prefer this over isRevoked():
    ///         the RPC provider then only learns which group of 256 credentials was checked.
    function getWord(bytes32 didHash, uint256 wordIndex) external view returns (uint256) {
        return _words[didHash][wordIndex];
    }

    function getWords(bytes32 didHash, uint256 startWord, uint256 count) external view returns (uint256[] memory words) {
        words = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            words[i] = _words[didHash][startWord + i];
        }
    }

    function _revoke(bytes32 didHash, uint256 index) private {
        uint256 wordIndex = index >> 8;
        uint256 mask = uint256(1) << (index & 0xff);
        uint256 current = _words[didHash][wordIndex];
        if ((current & mask) != 0) return; // idempotent
        _words[didHash][wordIndex] = current | mask;
        unchecked {
            revokedCount[didHash]++;
        }
        emit CredentialRevoked(didHash, index, msg.sender);
    }
}
