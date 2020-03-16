use crate::board::Board;
use crate::curve::{KeyCurve, PrivateKey, PublicKey, Scheme};
use crate::node::Node;
use rand::prelude::*;
use std::error::Error;
use threshold::dkg;
use threshold::sig::*;
use threshold::*;

pub struct Orchestrator {
    n: usize,
    thr: usize,
    nodes: Vec<Node>,
    group: dkg::Group<KeyCurve>,
    board: Board,
}

impl Orchestrator {
    pub fn new(n: usize, thr: usize) -> Orchestrator {
        let keypairs: Vec<_> = (0..n).map(|_| new_keypair()).collect();
        let dkgnodes: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, (private, public))| dkg::Node::new(i as Index, public.clone()))
            .collect();
        let group = match dkg::Group::new(dkgnodes, thr) {
            Ok(group) => group,
            Err(e) => panic!(e),
        };
        let board = Board::init(group.clone());
        let nodes: Vec<_> = keypairs
            .into_iter()
            .enumerate()
            .map(|(i, (private, public))| Node::new(i, private, public, group.clone()))
            .collect();

        Self {
            n,
            thr,
            nodes: nodes,
            group: group,
            board: board,
        }
    }

    // run the dkg phase by phase
    pub fn run_dkg(&mut self) -> Result<(), String> {
        self.board.dkg_start();
        // phase1: publishing shares
        for node in self.nodes.iter_mut() {
            node.dkg_phase1(&mut self.board);
        }

        // phase2: read all shares and producing responses
        self.board.dkg_phase2();
        let all_shares = self.board.get_shares();
        for node in self.nodes.iter_mut() {
            node.dkg_phase2(&mut self.board, &all_shares);
        }

        // end of phase 2: read all responses and see if dkg can finish
        let all_responses = self.board.get_responses();
        for node in self.nodes.iter_mut() {
            node.dkg_endphase2(&mut self.board, &all_responses)
        }

        if self.board.dkg_need_phase3() {
            // XXX do justification phase
        }
        Ok(())
    }

    pub fn threshold_blind_sign(&mut self, msg: &[u8]) -> Result<(), Box<dyn Error>> {
        // 1. blind the message for each destination
        let blindeds: Vec<_> = self.nodes.iter().map(|_| Scheme::blind(msg)).collect();
        // 2. request partial signatures from t nodes
        let partials: Vec<_> = self
            .nodes
            .iter_mut()
            .enumerate()
            .map(|(i, n)| n.partial(&blindeds[i].1))
            .filter_map(Result::ok)
            .collect();

        // 3. unblind each partial signatures
        let unblindeds: Vec<_> = blindeds
            .into_iter()
            .enumerate()
            .map(|(i, b)| Scheme::unblind(b.0, &partials[i]))
            .filter_map(Result::ok)
            .collect();
        // 3. reconstruct final signature
        let dist_public = self.nodes[0].publickey();
        let reconstructed = Scheme::aggregate(&dist_public, msg, &unblindeds)?;
        // 5. verify
        Scheme::verify(&dist_public.free_coeff(), msg, &reconstructed)
    }
}
fn new_keypair() -> (PrivateKey, PublicKey) {
    let mut private = KeyCurve::scalar();
    private.pick(&mut thread_rng());
    let mut public = KeyCurve::point();
    public.mul(&private);
    (private, public)
}
