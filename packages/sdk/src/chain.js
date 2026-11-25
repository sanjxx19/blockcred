// Read-only access to the BlockCred contracts (any EVM chain).

import { Contract, FallbackProvider, JsonRpcProvider, Network, getAddress, keccak256, toUtf8Bytes } from 'ethers';

export const ABIS = {
  IssuerRegistry: [
    'function isAccredited(bytes32 didHash) view returns (bool)',
    'function isSchemaRegistered(bytes32 schemaHash) view returns (bool)',
    'function isActiveController(bytes32 didHash, address account) view returns (bool)',
    'function canRevoke(bytes32 didHash, address account) view returns (bool)',
    'function paused() view returns (bool)',
    'function getIssuer(bytes32 didHash) view returns ((address controller, uint8 status, uint64 registeredAt, uint64 updatedAt, string did, string metadataURI))',
  ],
  RevocationRegistry: [
    'function isRevoked(bytes32 didHash, uint256 index) view returns (bool)',
    'function getWord(bytes32 didHash, uint256 wordIndex) view returns (uint256)',
    'function revokedCount(bytes32 didHash) view returns (uint256)',
    'function revoke(bytes32 didHash, uint256 index)',
    'function revokeBatch(bytes32 didHash, uint256[] indices)',
    'event CredentialRevoked(bytes32 indexed didHash, uint256 indexed index, address indexed revokedBy)',
  ],
  MerkleAnchor: [
    'function anchoredAt(bytes32 didHash, bytes32 merkleRoot) view returns (uint64)',
    'function anchorBatch(bytes32 didHash, bytes32 merkleRoot, uint32 leafCount)',
    'function verifyInclusion(bytes32 didHash, bytes32 merkleRoot, bytes32 leaf, bytes32[] proof) view returns (bool)',
    'event BatchAnchored(bytes32 indexed didHash, bytes32 indexed merkleRoot, uint256 leafCount, uint256 timestamp)',
  ],
};

export const didHash = (did) => keccak256(toUtf8Bytes(did));
export const schemaHash = (vct) => keccak256(toUtf8Bytes(vct));

/** One or many RPC URLs (comma-separated). Multiple URLs => FallbackProvider for resilience. */
export function createProvider(rpcUrls, chainId) {
  const urls = (Array.isArray(rpcUrls) ? rpcUrls : String(rpcUrls).split(','))
    .map((u) => u.trim())
    .filter(Boolean);
  if (!urls.length) throw new Error('At least one RPC URL is required');
  const network = Network.from(Number(chainId));
  // cacheTimeout -1: ethers caches identical RPC calls for 250 ms by default, so the second of two
  // back-to-back sends (approve = registerIssuer + fund) read a stale eth_getTransactionCount and
  // failed with "nonce has already been used" on fast chains.
  const providers = urls.map((u) => new JsonRpcProvider(u, network, { staticNetwork: network, cacheTimeout: -1 }));
  if (providers.length === 1) return providers[0];
  return new FallbackProvider(
    providers.map((provider, i) => ({ provider, priority: i + 1, weight: 1, stallTimeout: 1500 })),
    network,
    { quorum: 1, cacheTimeout: -1 },
  );
}

export class BlockCredChain {
  /**
   * @param {object} o
   * @param {import('ethers').Provider|import('ethers').Signer} o.runner provider (reads) or signer (writes)
   * @param {number} o.chainId
   * @param {{IssuerRegistry:string, RevocationRegistry:string, MerkleAnchor:string}} o.contracts
   */
  constructor({ runner, chainId, contracts }) {
    this.chainId = Number(chainId);
    this.addresses = {
      IssuerRegistry: getAddress(contracts.IssuerRegistry),
      RevocationRegistry: getAddress(contracts.RevocationRegistry),
      MerkleAnchor: getAddress(contracts.MerkleAnchor),
    };
    this.issuerRegistry = new Contract(this.addresses.IssuerRegistry, ABIS.IssuerRegistry, runner);
    this.revocationRegistry = new Contract(this.addresses.RevocationRegistry, ABIS.RevocationRegistry, runner);
    this.merkleAnchor = new Contract(this.addresses.MerkleAnchor, ABIS.MerkleAnchor, runner);
  }

  static fromConfig({ rpcUrl, chainId, contracts }) {
    return new BlockCredChain({ runner: createProvider(rpcUrl, chainId), chainId, contracts });
  }

  isAccredited(did) {
    return this.issuerRegistry.isAccredited(didHash(did));
  }

  isSchemaRegistered(vct) {
    return this.issuerRegistry.isSchemaRegistered(schemaHash(vct));
  }

  /**
   * Reads the whole 256-bit word rather than the single bit, so the RPC
   * provider only learns "one of 256 credentials" (herd privacy).
   */
  async isRevoked(did, index) {
    const idx = BigInt(index);
    const word = await this.revocationRegistry.getWord(didHash(did), idx >> 8n);
    return ((word >> (idx & 255n)) & 1n) === 1n;
  }

  async anchoredAt(did, root) {
    return Number(await this.merkleAnchor.anchoredAt(didHash(did), root));
  }
}
