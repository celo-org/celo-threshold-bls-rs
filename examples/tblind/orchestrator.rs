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
        let (token, blind) = Scheme::blind(msg);
        // 2. request partial signatures from t nodes
        let partials: Vec<_> = self
            .nodes
            .iter_mut()
            .enumerate()
            .map(|(i, n)| n.partial(&blind))
            .filter_map(Result::ok)
            .collect();

        // 3. aggregate all blinded signatures together
        // It can be done by any third party
        let dist_public = self.nodes[0].publickey();
        let blinded_sig = Scheme::aggregate(self.thr, &partials)?;
        // 4. unblind the signature
        let final_sig = Scheme::unblind(&token, &blinded_sig)?;
        // 5. verify
        Scheme::verify(&dist_public.public_key(), msg, &final_sig)
    }
}
fn new_keypair() -> (PrivateKey, PublicKey) {
    let mut private = KeyCurve::scalar();
    private.pick(&mut thread_rng());
    let mut public = KeyCurve::point();
    public.mul(&private);
    (private, public)
}
