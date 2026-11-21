const path = require('node:path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });
require('@nomicfoundation/hardhat-toolbox');

const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
const remoteAccounts = deployerKey ? [deployerKey] : [];

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: '0.8.28',
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
    },
  },
  networks: {
    hardhat: { chainId: 31337 },
    localhost: { url: 'http://127.0.0.1:8545', chainId: 31337 },
    // Used by docker-compose (the Hardhat node runs in the "chain" container)
    docker: { url: process.env.DOCKER_CHAIN_RPC_URL || 'http://chain:8545', chainId: 31337 },
    amoy: {
      url: process.env.AMOY_RPC_URL || 'https://rpc-amoy.polygon.technology',
      chainId: 80002,
      accounts: remoteAccounts,
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com',
      chainId: 11155111,
      accounts: remoteAccounts,
    },
  },
  etherscan: {
    // Etherscan API v2: one key works for Sepolia and Polygon Amoy
    apiKey: process.env.ETHERSCAN_API_KEY || '',
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === 'true',
    currency: 'USD',
  },
};
