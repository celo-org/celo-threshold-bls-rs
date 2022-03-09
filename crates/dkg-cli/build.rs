use ethers::{contract::Abigen, solc::{Solc, CompilerInput}};
use std::{fs::File, io::Write};
use ethers_solc::{Project, ProjectPathsConfig};
use serde::{Deserialize, Serialize};
use serde_json::Result;

const PATH: &str = "../../solidity/";
const CONTRACT_NAME: &str = "DKG.sol";
// Generates the bindings under `src/`
fn main() {
    // Only re-run the builder script if the contract changes
    println!("cargo:rerun-if-changed={}", PATH);

    // compile the DKG contract (requires solc on the builder's system)
    //let contracts = Solc::new(PATH).build_raw().expect("could not compile");
    //let contract = contracts.get("DKG").expect("contract not found");
    let project = Project::builder()
        .paths(ProjectPathsConfig::hardhat(PATH).unwrap())
        .build()
        .unwrap();
    println!("project: {:?}", project);
    let contract = project.compile().unwrap();
    
    println!("test: {}", contract.has_compiled_contracts());
    let mut artifacts = contract.into_artifacts();
    let artifact = artifacts.next().unwrap().1;
    let abi = artifact.abi.clone().unwrap();
    let bytecode = artifact.bytecode.clone().unwrap();
    //println!("artifact: {:?}", artifact);
    println!("abi: {:?}", abi);
    //println!("abi.abi: {:?}", abi.abi);
    //println!("bytecode: {:?}", bytecode);

    //let abi = contract.abi.clone();
    let abi_string = serde_json::to_string(&abi).unwrap();

    let mut f = File::create("dkg.bin").expect("could not create DKG bytecode file");
    /*f.write_all(contract.bin.as_bytes())
        .expect("could not write DKG bytecode to the file");*/
    //f.write_all(bytecode.as_bytes())
      //  .expect("could not write DKG bytecode to the file");

    // generate type-safe bindings to it
    let bindings = Abigen::new("DKG", abi_string)
        .expect("could not instantiate Abigen")
        .generate()
        .expect("could not generate bindings");
    bindings
        .write_to_file("./src/dkg_contract.rs")
        .expect("could not write bindings to file");
}
