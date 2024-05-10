use ethers::contract::Abigen;
use ethers::utils::hex::ToHex;
use ethers_solc::{Project, ProjectPathsConfig};
use std::fs::File;
use std::io::Write;
use std::path::Path;

const PATH: &str = "../../solidity/";
const CONTRACT_PATH: &str = "../../solidity/contracts/DKG.sol";
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

    let full_path = Path::new(CONTRACT_PATH).canonicalize().unwrap();
    let full_path = full_path.to_str().unwrap();

    let compiler_output = project.compile().unwrap();
    let contract = compiler_output.find(full_path, CONTRACT_NAME).unwrap();

    let mut f = File::create("dkg.bin").expect("could not create DKG bytecode file");
    let bytecode: String = contract.bytecode.clone().unwrap().object.encode_hex();

    f.write_all(bytecode.as_bytes())
        .expect("could not write DKG bytecode to the file");

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

    let verification_input = project
        .standard_json_input(project.sources_path().join("DKG.sol"))
        .unwrap();
    let mut j = File::create("dkg.json").expect("could not create DKG standard sol input file");

    j.write_all(
        serde_json::to_string(&verification_input)
            .unwrap()
            .as_bytes(),
    )
    .expect("could not write DKG standard json input to the file");
}
