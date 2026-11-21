const fs = require('node:fs');
const path = require('node:path');

const LOCAL_NETWORKS = new Set(['hardhat', 'localhost', 'docker']);
const DEFAULT_VCT = 'urn:blockcred:vct:degree:v1';
const deploymentsDir = path.resolve(__dirname, '..', 'deployments');

/** http://localhost:4000 -> did:web:localhost%3A4000 (mirrors packages/sdk didWebFromUrl) */
function didWebFromUrl(url) {
  const u = new URL(url);
  const host = u.port ? `${u.hostname}%3A${u.port}` : u.hostname;
  const segments = u.pathname.split('/').filter(Boolean).map(encodeURIComponent);
  return ['did:web', host, ...segments].join(':');
}

function deploymentPath(networkName) {
  return path.join(deploymentsDir, `${networkName}.json`);
}

function readDeployment(networkName) {
  const file = deploymentPath(networkName);
  if (!fs.existsSync(file)) throw new Error(`No deployment found at ${file}. Run the deploy script first.`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeDeployment(networkName, data) {
  fs.mkdirSync(deploymentsDir, { recursive: true });
  fs.writeFileSync(deploymentPath(networkName), `${JSON.stringify(data, null, 2)}\n`);
  return deploymentPath(networkName);
}

module.exports = { LOCAL_NETWORKS, DEFAULT_VCT, didWebFromUrl, readDeployment, writeDeployment };
