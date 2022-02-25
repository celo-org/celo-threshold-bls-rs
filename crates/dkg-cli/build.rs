use ethers::{contract::Abigen, solc::{Solc, CompilerInput}};
use std::{fs::File, io::Write};

const PATH: &str = "../../solidity/contracts/DKG.sol";
// Generates the bindings under `src/`
fn main() {
    // Only re-run the builder script if the contract changes
    println!("cargo:rerun-if-changed={}", PATH);

    // compile the DKG contract (requires solc on the builder's system)
    let contracts = Solc::new(PATH).build_raw().expect("could not compile");
    let contract = contracts.get("DKG").expect("contract not found");

    let abi = contract.abi.clone();

    let mut f = File::create("dkg.bin").expect("could not create DKG bytecode file");
    f.write_all(contract.bin.as_bytes())
        .expect("could not write DKG bytecode to the file");

    // generate type-safe bindings to it
    let bindings = Abigen::new("DKG", abi)
        .expect("could not instantiate Abigen")
        .generate()
        .expect("could not generate bindings");
    bindings
        .write_to_file("./src/dkg_contract.rs")
        .expect("could not write bindings to file");
}
