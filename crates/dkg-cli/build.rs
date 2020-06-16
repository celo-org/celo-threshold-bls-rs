use ethers::{contract::Abigen, utils::Solc};

const PATH: &str = "../../solidity/contracts/DKG.sol";
// Generates the bindings under `src/`
fn main() {
    // Only re-run the builder script if the contract changes
    println!("cargo:rerun-if-changed={}", PATH);

    // compile the DKG contract (requires solc on the builder's system)
    let contracts = Solc::new(PATH).build_raw().expect("could not compile");
    let abi = contracts
        .get("DKG")
        .expect("contract not found")
        .abi
        .clone();

    // generate type-safe bindings to it
    let bindings = Abigen::new("DKG", abi)
        .expect("could not instantiate Abigen")
        .generate()
        .expect("could not generate bindings");
    bindings
        .write_to_file("./src/dkg_contract.rs")
        .expect("could not write bindings to file");
}
