import { ethers } from "@nomiclabs/buidler";

async function main() {
  const factory = await ethers.getContract("DKG")

  let contract = await factory.deploy(process.env.PHASE_DURATION)

  // The address the Contract WILL have once mined
  console.log("DKG deployed at:", contract.address);

  // The transaction that was sent to the network to deploy the Contract
  console.log("Transaction hash:", contract.deployTransaction.hash);

  // The contract is NOT deployed yet; we must wait until it is mined
  await contract.deployed()
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
