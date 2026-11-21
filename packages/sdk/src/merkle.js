// Merkle helpers compatible with @openzeppelin/merkle-tree StandardMerkleTree
// (leaf encoding ["bytes32"]) and OpenZeppelin MerkleProof.sol.

import { AbiCoder, concat, keccak256, toUtf8Bytes } from 'ethers';

/** The value committed for a credential: keccak256 of the issuer-signed JWT. */
export const credentialLeafValue = (issuerJwt) => keccak256(toUtf8Bytes(issuerJwt));

/** StandardMerkleTree leaf hash: keccak256(bytes.concat(keccak256(abi.encode(value)))). */
export const standardLeafHash = (value) =>
  keccak256(keccak256(AbiCoder.defaultAbiCoder().encode(['bytes32'], [value])));

/** Same algorithm as MerkleProof.processProof (sorted pair hashing). */
export function verifyMerkleProof(root, leafHash, proof) {
  let computed = leafHash.toLowerCase();
  for (const node of proof) {
    const sibling = node.toLowerCase();
    computed = computed < sibling ? keccak256(concat([computed, sibling])) : keccak256(concat([sibling, computed]));
  }
  return computed === root.toLowerCase();
}
