import { usePlugin } from "@nomiclabs/buidler/config";

// use env vars from .env file
import { config } from "dotenv"
config({ path: ".env" })

usePlugin("@nomiclabs/buidler-waffle");

const URL = process.env.ENDPOINT || "";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "";

export default {
    defaultNetwork: "buidlerevm",
    networks: {
        mainnet: {
            url: URL,
            accounts: [PRIVATE_KEY],
        },
    },
    solc: {
        version: "0.6.6",
        optimizer: {
            enabled: true,
            runs: 200,
        }
    },
    paths: {
        artifacts: "./build"
    }
};
