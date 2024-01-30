import { HardhatUserConfig } from "hardhat/types";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";
import "solidity-coverage";

import * as dotenv from "dotenv";
dotenv.config();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1_000_000,
      },
      metadata: {
        bytecodeHash: "none",
      },
      viaIR: false,
    },
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: false,
    },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
  },
}

export default config;
