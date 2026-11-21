// Governance operations on an existing issuer, run from a governor account.
//
//   ACTION=suspend|reinstate|revoke|rotate ISSUER_DID=did:web:... [NEW_CONTROLLER=0x...] \
//     npx hardhat run scripts/issuer-admin.js --network localhost

const hre = require('hardhat');
const { readDeployment } = require('./lib');

const STATUS = ['None', 'Active', 'Suspended', 'Revoked'];

async function main() {
  const { ethers, network } = hre;
  const { ACTION: action, ISSUER_DID: did, NEW_CONTROLLER: newController } = process.env;
  if (!did) throw new Error('Set ISSUER_DID');

  const { contracts } = readDeployment(network.name);
  const registry = await ethers.getContractAt('IssuerRegistry', contracts.IssuerRegistry);
  const didHash = ethers.id(did);

  let tx;
  switch (action) {
    case 'suspend':
      tx = await registry.suspendIssuer(didHash);
      break;
    case 'reinstate':
      tx = await registry.reinstateIssuer(didHash);
      break;
    case 'revoke':
      tx = await registry.revokeIssuer(didHash);
      break;
    case 'rotate':
      if (!newController) throw new Error('Set NEW_CONTROLLER');
      tx = await registry.rotateController(didHash, newController);
      break;
    case undefined:
    case 'status':
      break;
    default:
      throw new Error(`Unknown ACTION ${action}`);
  }
  if (tx) {
    console.log(`tx ${tx.hash}`);
    await tx.wait();
  }
  const issuer = await registry.getIssuer(didHash);
  console.log({ did, status: STATUS[Number(issuer.status)], controller: issuer.controller });
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
