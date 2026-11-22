import { BlockCredChain, createProvider, didHash } from '@blockcred/sdk/chain';
import { Contract, NonceManager, Wallet, formatEther, parseEther } from 'ethers';

const GOVERNANCE_ABI = [
  'function registerIssuer(string did, address controller, string metadataURI) returns (bytes32)',
  'function suspendIssuer(bytes32 didHash)',
  'function reinstateIssuer(bytes32 didHash)',
  'function getIssuer(bytes32 didHash) view returns ((address controller, uint8 status, uint64 registeredAt, uint64 updatedAt, string did, string metadataURI))',
  'function hasRole(bytes32 role, address account) view returns (bool)',
  'function GOVERNOR_ROLE() view returns (bytes32)',
];

/**
 * Platform chain client.
 *  - governor: the platform's governance account (registers / suspends issuers, funds controllers)
 *  - controllers: one Ethereum account per university (anchors batches, revokes credentials)
 * Every write takes a Postgres advisory lock keyed by the sending account, so any number of
 * API replicas can run without nonce collisions.
 */
export function createPlatformChain(config, pool, logger) {
  const provider = createProvider(config.rpcUrl, config.chainId);
  const reader = new BlockCredChain({ runner: provider, chainId: config.chainId, contracts: config.contracts });
  const governorWallet = new Wallet(config.governorPrivateKey, provider);

  async function send(account, label, buildTx) {
    const client = await pool.connect();
    try {
      await client.query('SELECT pg_advisory_lock(hashtext($1))', [`tx:${account.address.toLowerCase()}`]);
      const signer = new NonceManager(account);
      const tx = await buildTx(signer);
      logger.info({ tx: tx.hash, label, from: account.address }, 'transaction sent');
      const receipt = await tx.wait(config.txConfirmations);
      if (!receipt || receipt.status !== 1) throw new Error(`${label} transaction failed`);
      return receipt;
    } finally {
      await client.query('SELECT pg_advisory_unlock(hashtext($1))', [`tx:${account.address.toLowerCase()}`]).catch(() => {});
      client.release();
    }
  }

  const registryAs = (signer) => new Contract(config.contracts.IssuerRegistry, GOVERNANCE_ABI, signer);

  function controller(privateKey) {
    const account = new Wallet(privateKey, provider);
    return {
      address: account.address,
      anchorBatch: (did, root, count) =>
        send(account, 'anchorBatch', (s) => new BlockCredChain({ runner: s, chainId: config.chainId, contracts: config.contracts }).merkleAnchor.anchorBatch(didHash(did), root, count)),
      revokeBatch: (did, indices) =>
        send(account, 'revokeBatch', (s) => new BlockCredChain({ runner: s, chainId: config.chainId, contracts: config.contracts }).revocationRegistry.revokeBatch(didHash(did), indices)),
      balance: async () => formatEther(await provider.getBalance(account.address)),
    };
  }

  return {
    provider,
    reader,
    governorAddress: governorWallet.address,
    controller,

    async issuerOnChain(did) {
      const issuer = await registryAs(provider).getIssuer(didHash(did));
      return { status: ['none', 'active', 'suspended', 'revoked'][Number(issuer.status)], controller: issuer.controller };
    },
    registerIssuer: (did, controllerAddress, metadataURI = '') =>
      send(governorWallet, 'registerIssuer', (s) => registryAs(s).registerIssuer(did, controllerAddress, metadataURI)),
    suspendIssuer: (did) => send(governorWallet, 'suspendIssuer', (s) => registryAs(s).suspendIssuer(didHash(did))),
    reinstateIssuer: (did) => send(governorWallet, 'reinstateIssuer', (s) => registryAs(s).reinstateIssuer(didHash(did))),
    fund: (to, eth) => send(governorWallet, 'fund', (s) => s.sendTransaction({ to, value: parseEther(eth) })),

    async status() {
      const registry = registryAs(provider);
      const [blockNumber, balance, isGovernor] = await Promise.all([
        provider.getBlockNumber(),
        provider.getBalance(governorWallet.address),
        registry.GOVERNOR_ROLE().then((role) => registry.hasRole(role, governorWallet.address)),
      ]);
      return {
        chainId: config.chainId,
        blockNumber,
        contracts: reader.addresses,
        governor: governorWallet.address,
        governorBalance: formatEther(balance),
        governorAuthorized: isGovernor,
      };
    },
  };
}
