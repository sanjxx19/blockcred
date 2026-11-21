// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IssuerRegistry} from "./IssuerRegistry.sol";

/// @title MerkleAnchor
/// @notice Issuers commit the Merkle root of a batch of issued credentials in one
///         transaction. This gives tamper-evidence and a trusted issuance timestamp
///         without paying gas per credential and without publishing any credential data.
/// @dev    Leaves follow the OpenZeppelin StandardMerkleTree encoding for ["bytes32"]:
///         leaf = keccak256(bytes.concat(keccak256(abi.encode(keccak256(issuerSignedJwt))))).
contract MerkleAnchor {
    struct Batch {
        uint64 anchoredAt;
        uint64 blockNumber;
        uint32 leafCount;
    }

    IssuerRegistry public immutable issuerRegistry;

    mapping(bytes32 => mapping(bytes32 => Batch)) private _batches;
    mapping(bytes32 => uint256) public batchCount;

    event BatchAnchored(bytes32 indexed didHash, bytes32 indexed merkleRoot, uint256 leafCount, uint256 timestamp);

    error ZeroAddress();
    error RegistryPaused();
    error NotIssuerController(bytes32 didHash, address caller);
    error ZeroRoot();
    error InvalidLeafCount();
    error AlreadyAnchored(bytes32 merkleRoot);

    constructor(IssuerRegistry registry) {
        if (address(registry) == address(0)) revert ZeroAddress();
        issuerRegistry = registry;
    }

    function anchorBatch(bytes32 didHash, bytes32 merkleRoot, uint32 leafCount) external {
        if (issuerRegistry.paused()) revert RegistryPaused();
        if (!issuerRegistry.isActiveController(didHash, msg.sender)) revert NotIssuerController(didHash, msg.sender);
        if (merkleRoot == bytes32(0)) revert ZeroRoot();
        if (leafCount == 0) revert InvalidLeafCount();
        if (_batches[didHash][merkleRoot].anchoredAt != 0) revert AlreadyAnchored(merkleRoot);

        _batches[didHash][merkleRoot] = Batch({
            anchoredAt: uint64(block.timestamp),
            blockNumber: uint64(block.number),
            leafCount: leafCount
        });
        unchecked {
            batchCount[didHash]++;
        }
        emit BatchAnchored(didHash, merkleRoot, leafCount, block.timestamp);
    }

    function getBatch(bytes32 didHash, bytes32 merkleRoot) external view returns (Batch memory) {
        return _batches[didHash][merkleRoot];
    }

    function anchoredAt(bytes32 didHash, bytes32 merkleRoot) external view returns (uint64) {
        return _batches[didHash][merkleRoot].anchoredAt;
    }

    /// @notice On-chain inclusion check (verifiers can also do this off-chain with the SDK).
    function verifyInclusion(bytes32 didHash, bytes32 merkleRoot, bytes32 leaf, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        if (_batches[didHash][merkleRoot].anchoredAt == 0) return false;
        return MerkleProof.verifyCalldata(proof, merkleRoot, leaf);
    }
}
