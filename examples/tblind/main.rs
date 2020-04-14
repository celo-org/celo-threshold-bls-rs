mod board;
mod curve;
mod node;
mod orchestrator;

fn main() {
    let mut god = orchestrator::Orchestrator::new(6, 4);
    god.run_dkg(true).unwrap();
    god.threshold_blind_sign(&vec![1, 9, 6, 9]).unwrap();
}
