// Requires `npm install` (uses ethers + @openzeppelin/merkle-tree for cross-checking).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import merkle from '@openzeppelin/merkle-tree';
import { credentialLeafValue, standardLeafHash, verifyMerkleProof } from '../src/merkle.js';

const { StandardMerkleTree } = merkle;

describe('merkle', () => {
  it('matches OpenZeppelin StandardMerkleTree', () => {
    const values = ['a.b.c', 'd.e.f', 'g.h.i', 'j.k.l', 'm.n.o'].map(credentialLeafValue);
    const tree = StandardMerkleTree.of(values.map((v) => [v]), ['bytes32']);
    values.forEach((v, i) => {
      assert.equal(standardLeafHash(v), tree.leafHash([v]));
      assert.ok(verifyMerkleProof(tree.root, standardLeafHash(v), tree.getProof(i)));
    });
    assert.ok(!verifyMerkleProof(tree.root, standardLeafHash(credentialLeafValue('x')), tree.getProof(0)));
  });
});
