// Registers an additional issuer from a governor account.
//
//   ISSUER_DID=did:web:college-b.github.io ISSUER_CONTROLLER_ADDRESS=0x... \
//     npx hardhat run scripts/register-issuer.js --network amoy

const hre = require('hardhat');
const { readDeployment } = require('./lib');

async function main() {
  const { ethers, network } = hre;
  const did = process.env.ISSUER_DID;
  const controller = process.env.ISSUER_CONTROLLER_ADDRESS;
  if (!did || !controller) throw new Error('Set ISSUER_DID and ISSUER_CONTROLLER_ADDRESS');

  const { contracts } = readDeployment(network.name);
  const registry = await ethers.getContractAt('IssuerRegistry', contracts.IssuerRegistry);
  const didHash = ethers.id(did);
  const existing = await registry.getIssuer(didHash);
  if (existing.status !== 0n) {
    console.log(`Issuer ${did} already registered (status ${existing.status}).`);
    return;
  }
  const tx = await registry.registerIssuer(did, controller, process.env.ISSUER_METADATA_URI || '');
  console.log(`tx ${tx.hash}`);
  await tx.wait();
  console.log(`Registered ${did} -> controller ${controller} (didHash ${didHash})`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
