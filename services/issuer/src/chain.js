import { BlockCredChain, createProvider, didHash } from '@blockcred/sdk/chain';
import { NonceManager, Wallet, formatEther } from 'ethers';

const TX_LOCK = 724_002; // advisory-lock key serialising on-chain writes across replicas

/**
 * Issuer-side chain client. All writes go through `withTxLock`, which takes a
 * Postgres advisory lock so that horizontally-scaled replicas never race on the
 * controller account's nonce.
 */
export function createIssuerChain(config, pool, logger) {
  const provider = createProvider(config.rpcUrl, config.chainId);
  const wallet = new Wallet(config.controllerPrivateKey, provider);
  const signer = new NonceManager(wallet);
  const chain = new BlockCredChain({ runner: signer, chainId: config.chainId, contracts: config.contracts });
  const reader = new BlockCredChain({ runner: provider, chainId: config.chainId, contracts: config.contracts });
  const issuerHash = didHash(config.did);

  async function withTxLock(fn) {
    const client = await pool.connect();
    try {
      await client.query('SELECT pg_advisory_lock($1)', [TX_LOCK]);
      signer.reset(); // another replica may have used the account since our last tx
      return await fn();
    } finally {
      await client.query('SELECT pg_advisory_unlock($1)', [TX_LOCK]).catch(() => {});
      client.release();
    }
  }

  async function send(label, txPromiseFactory) {
    return withTxLock(async () => {
      const tx = await txPromiseFactory();
      logger.info({ tx: tx.hash, label }, 'transaction sent');
      const receipt = await tx.wait(config.txConfirmations);
      if (!receipt || receipt.status !== 1) throw new Error(`${label} transaction failed`);
      return receipt;
    });
  }

  return {
    reader,
    provider,
    issuerHash,
    controllerAddress: wallet.address,

    anchorBatch: (root, leafCount) =>
      send('anchorBatch', () => chain.merkleAnchor.anchorBatch(issuerHash, root, leafCount)),

    revokeBatch: (indices) => send('revokeBatch', () => chain.revocationRegistry.revokeBatch(issuerHash, indices)),

    async status() {
      const [accredited, isController, canRevoke, balance, blockNumber] = await Promise.all([
        reader.isAccredited(config.did),
        reader.issuerRegistry.isActiveController(issuerHash, wallet.address),
        reader.issuerRegistry.canRevoke(issuerHash, wallet.address),
        provider.getBalance(wallet.address),
        provider.getBlockNumber(),
      ]);
      return {
        chainId: config.chainId,
        blockNumber,
        contracts: reader.addresses,
        did: config.did,
        didHash: issuerHash,
        accredited,
        controller: wallet.address,
        controllerAuthorized: isController,
        canRevoke,
        controllerBalance: formatEther(balance),
      };
    },
  };
}
