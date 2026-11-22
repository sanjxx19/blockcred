// Deploys IssuerRegistry, RevocationRegistry and MerkleAnchor, writes
// deployments/<network>.json and (optionally) bootstraps the first issuer + schema.
//
//   npx hardhat run scripts/deploy.js --network localhost|amoy|sepolia
//
// Env (all optional on local networks):
//   ADMIN_ADDRESS               DEFAULT_ADMIN_ROLE + PAUSER_ROLE holder (default: deployer)
//   GOVERNOR_ADDRESSES          comma-separated GOVERNOR_ROLE holders (default: deployer)
//   ISSUER_DID + ISSUER_CONTROLLER_ADDRESS  optional: pre-register one issuer
//   CREDENTIAL_VCTS             comma-separated vct values to register (default: degree vct)

const hre = require('hardhat');
const { DEFAULT_VCT, writeDeployment } = require('./lib');

async function main() {
  const { ethers, network } = hre;
  const signers = await ethers.getSigners();
  if (!signers.length) throw new Error('No deployer account. Set DEPLOYER_PRIVATE_KEY in .env');
  const deployer = signers[0];
  const chainId = Number((await ethers.provider.getNetwork()).chainId);

  const admin = process.env.ADMIN_ADDRESS || deployer.address;
  const governors = (process.env.GOVERNOR_ADDRESSES || deployer.address)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  console.log(`Network: ${network.name} (chainId ${chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Balance: ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))}`);

  const IssuerRegistry = await ethers.getContractFactory('IssuerRegistry');
  const issuerRegistry = await IssuerRegistry.deploy(admin, governors);
  await issuerRegistry.waitForDeployment();
  const issuerRegistryAddress = await issuerRegistry.getAddress();
  console.log(`IssuerRegistry:     ${issuerRegistryAddress}`);

  const RevocationRegistry = await ethers.getContractFactory('RevocationRegistry');
  const revocationRegistry = await RevocationRegistry.deploy(issuerRegistryAddress);
  await revocationRegistry.waitForDeployment();
  console.log(`RevocationRegistry: ${await revocationRegistry.getAddress()}`);

  const MerkleAnchor = await ethers.getContractFactory('MerkleAnchor');
  const merkleAnchor = await MerkleAnchor.deploy(issuerRegistryAddress);
  await merkleAnchor.waitForDeployment();
  console.log(`MerkleAnchor:       ${await merkleAnchor.getAddress()}`);

  const deploymentTx = issuerRegistry.deploymentTransaction();
  const receipt = deploymentTx ? await deploymentTx.wait() : null;

  const deployment = {
    network: network.name,
    chainId,
    deployer: deployer.address,
    admin,
    governors,
    startBlock: receipt ? receipt.blockNumber : null,
    deployedAt: new Date().toISOString(),
    contracts: {
      IssuerRegistry: issuerRegistryAddress,
      RevocationRegistry: await revocationRegistry.getAddress(),
      MerkleAnchor: await merkleAnchor.getAddress(),
    },
  };
  const file = writeDeployment(network.name, deployment);
  console.log(`Deployment written to ${file}`);

  // ---- Bootstrap (only possible if the deployer is a governor) ----
  const deployerIsGovernor = governors.some((g) => g.toLowerCase() === deployer.address.toLowerCase());
  if (!deployerIsGovernor) {
    console.log('Deployer is not a governor; skipping bootstrap. Use scripts/register-issuer.js from a governor account.');
    return;
  }

  const vcts = (process.env.CREDENTIAL_VCTS || DEFAULT_VCT).split(',').map((s) => s.trim()).filter(Boolean);
  for (const vct of vcts) {
    const tx = await issuerRegistry.registerSchema(ethers.id(vct), vct);
    await tx.wait();
    console.log(`Registered schema ${vct}`);
  }

  // Universities are normally registered by the accreditation admin from the web app.
  // Optionally pre-register one here (e.g. an issuer hosted elsewhere):
  const issuerDid = process.env.ISSUER_DID || '';
  const controller = process.env.ISSUER_CONTROLLER_ADDRESS || '';
  if (issuerDid && controller) {
    const tx = await issuerRegistry.registerIssuer(issuerDid, controller, process.env.ISSUER_METADATA_URI || '');
    await tx.wait();
    console.log(`Registered issuer ${issuerDid} (controller ${controller})`);
  } else {
    console.log('Universities will be accredited from the admin dashboard.');
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
