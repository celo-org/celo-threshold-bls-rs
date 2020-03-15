extern crate threshold;

mod board;
mod curve;
mod node;
mod orchestrator;

fn main() {
    let mut god = orchestrator::Orchestrator::new(6, 4);
    god.run_dkg();
}
