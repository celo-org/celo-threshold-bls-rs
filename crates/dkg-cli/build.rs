use ethers::{contract::Abigen};
use std::{fs::File, io::Write};
use ethers_solc::{Project, ProjectPathsConfig};
//use rustc_hex::{FromHex, ToHex};

const PATH: &str = "../../solidity/";
const CONTRACT_NAME: &str = "DKG";
// Generates the bindings under `src/`
fn main() {
    // Only re-run the builder script if the contract changes
    println!("cargo:rerun-if-changed={}", PATH);

    // compile the DKG contract (requires solc on the builder's system)
    let project = Project::builder()
        .paths(ProjectPathsConfig::hardhat(PATH).unwrap())
        .build()
        .unwrap();
    let compiler_output = project.compile().unwrap();
    let contract = compiler_output.find(CONTRACT_NAME).unwrap();
    
    let mut f = File::create("dkg.bin").expect("could not create DKG bytecode file");
    let bytes = contract.bytecode.clone().unwrap().object.into_bytes().unwrap();
    //let bytes_str = hex::encode(bytes);
    //let bytes_vec = bytes.to_vec();
    //let sbytes = std::str::from_utf8(&bytes_vec).unwrap();
    //f.write_all(&sbytes.as_bytes())
    //    .expect("could not write DKG bytecode to the file");

    // generate type-safe bindings to it
    let abi = contract.abi.as_ref().unwrap();
    let abi_string = serde_json::to_string(&abi.clone()).unwrap();

    let bindings = Abigen::new("DKG", abi_string)
        .expect("could not instantiate Abigen")
        .generate()
        .expect("could not generate bindings");
    bindings
        .write_to_file("./src/dkg_contract.rs")
        .expect("could not write bindings to file");
}