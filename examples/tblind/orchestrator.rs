use crate::board::Board;
use crate::curve::{KeyCurve, PrivateKey, PublicKey, Scheme};
use crate::node::Node;
use rand::prelude::*;
use std::error::Error;
use threshold::dkg;
use threshold::sig::*;
use threshold::*;

pub struct Orchestrator {
    thr: usize,
    nodes: Vec<Node>,
    board: Board,
    // qualified group of nodes after the dkg protocol
    qual: Option<dkg::Group<KeyCurve>>,
    dist_public: Option<DistPublic<KeyCurve>>,
}

impl Orchestrator {
    pub fn new(n: usize, thr: usize) -> Orchestrator {
        println!("- New example with {} nodes and a threshold of {}", n, thr);
        let keypairs: Vec<_> = (0..n).map(|_| new_keypair()).collect();
        let dkgnodes: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, (_, public))| dkg::Node::new(i as Index, public.clone()))
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
            thr,
            nodes: nodes,
            board: board,
            qual: None::<dkg::Group<KeyCurve>>,
            dist_public: None::<DistPublic<KeyCurve>>,
        }
    }

    /// run the dkg phase by phase
    /// if phase3 is set to true, the orchestrator simulates an invalid
    /// deal/share such that it requires a justification phase.
    pub fn run_dkg(&mut self, phase3: bool) -> Result<(), String> {
        println!("- DKG starting (justification? {:?})", phase3);
        self.board.dkg_start();
        // phase1: publishing shares
        println!("- Phase 1: publishing shares");
        for (i, node) in self.nodes.iter_mut().enumerate() {
            let mut badnode = false;
            if i == 0 && phase3 {
                badnode = true;
                println!("\t -> node {} publish shares (bad node)", i);
            } else {
                println!("\t -> node {} publish shares", i);
            }
            node.dkg_phase1(&mut self.board, badnode);
        }

        // phase2: read all shares and producing responses
        self.board.dkg_phase2();
        println!("- Phase 2: processing shares and publishing potential responses");
        let all_shares = self.board.get_shares();
        for (i, node) in self.nodes.iter_mut().enumerate() {
            println!("\t -> node {} process shares", i);
            node.dkg_phase2(&mut self.board, &all_shares);
        }
        if self.board.dkg_need_phase3() {
            println!("- Phase 3 required since responses have been issued");
            self.board.dkg_phase3();
        } else {
            println!("- Final phase of dkg - computing shares");
            self.board.finish_dkg();
        }

        // end of phase 2: read all responses and see if dkg can finish
        // if there is need for justifications, nodes will publish
        let all_responses = self.board.get_responses();
        for node in self.nodes.iter_mut() {
            node.dkg_endphase2(&mut self.board, &all_responses);
        }

        if self.board.dkg_need_phase3() {
            let all_justifs = self.board.get_justifications();
            println!(
                "- Number of dealers that are pushing justifications: {}",
                all_justifs.len()
            );
            for (i, node) in self.nodes.iter_mut().enumerate() {
                match node.dkg_phase3(&all_justifs) {
                    Err(e) => {
                        // we only exclude node 0 in this toy example
                        if i != 0 {
                            panic!("that should not happen: idx {} -> {:?}", i, e);
                        }
                    }
                    _ => {
                        if i == 0 {
                            // we dont take qualified from node 0 since he's a
                            // bad node
                            continue;
                        }
                        self.qual = Some(node.qual());
                        self.dist_public = Some(node.dist_public());
                        println!("\t -> dealer {} has qualified set {:?}", i, node.qual());
                    }
                }
            }
        }
        let d = self.dist_public.take().unwrap();
        println!("- Distributed public key: {:?}", d.public_key());
        self.dist_public = Some(d);
        println!("- DKG ended");
        Ok(())
    }

    pub fn threshold_blind_sign(&mut self, msg: &[u8]) -> Result<(), Box<dyn Error>> {
        println!("\nThreshold blind signature example");
        let qual = self.qual.take().unwrap();
        println!("\t -> using qualified set {:?}\n", qual);
        // 1. blind the message for each destination
        println!("- Phase 1: client blinds the message");
        let (token, blind) = Scheme::blind(msg);
        // 2. request partial signatures from t nodes
        println!(
            "- Phase 2: request (blinded) partial signatures over the blinded message to qualified nodes"
        );
        let partials: Vec<_> = qual
            .nodes
            .iter()
            .map(|n| {
                println!("\t -> {} is signing partial", n.id());
                self.nodes[n.id() as usize].partial(&blind)
            })
            .filter_map(Result::ok)
            .collect();

        // 3. aggregate all blinded signatures together
        // It can be done by any third party
        println!(
            "- Phase 3: aggregating all blinded partial signatures into final blinded signature"
        );
        let blinded_sig = Scheme::aggregate(self.thr, &partials)?;
        // 4. unblind the signature - this is done by the "client"
        println!("- Phase 4: client unblinds the final signature");
        let final_sig = Scheme::unblind(&token, &blinded_sig)?;
        // 5. verify
        Scheme::verify(
            &self.dist_public.take().unwrap().public_key(),
            msg,
            &final_sig,
        )?;
        println!("- Signature verifed against the distributed public key");
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
