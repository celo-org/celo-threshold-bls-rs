use crate::board::Board;
use crate::curve::{KeyCurve, PrivateKey, PublicKey};
use crate::node::Node;
use rand::prelude::*;
use threshold::dkg;
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
}
fn new_keypair() -> (PrivateKey, PublicKey) {
    let mut private = KeyCurve::scalar();
    private.pick(&mut thread_rng());
    let mut public = KeyCurve::point();
    public.mul(&private);
    (private, public)
}
