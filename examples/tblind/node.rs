use crate::board::Board;
use crate::curve::{KeyCurve, PrivateKey, PublicKey, Scheme};
use blind_threshold_bls::dkg;
use blind_threshold_bls::sig::ThresholdScheme;
use blind_threshold_bls::*;
use std::error::Error;
/// Node holds the logic of a participants, for the different phases of the
/// example.
pub struct Node {
    public: PublicKey,
    // Index is a type alias to represent the index of a participant. It can be
    // changed depending on the size of the network - u16 is likely to work for
    // most cases though.
    index: Index,
    bad: bool,
    dkg0: Option<dkg::DKG<KeyCurve>>,
    dkg1: Option<dkg::DKGWaitingShare<KeyCurve>>,
    dkg2: Option<dkg::DKGWaitingResponse<KeyCurve>>,
    dkg3: Option<dkg::DKGWaitingJustification<KeyCurve>>,
    output: Option<dkg::DKGOutput<KeyCurve>>,
}

impl Node {
    pub fn new(
        index: usize,
        private: PrivateKey,
        public: PublicKey,
        group: dkg::Group<KeyCurve>,
    ) -> Self {
        // XXX use lifetimes to remove cloning requirement
        let d = match dkg::DKG::new(private, group.clone()) {
            Ok(dkg) => dkg,
            Err(e) => {
                println!("{}", e);
                panic!(e)
            }
        };
        Self {
            public,
            index: index as Index,
            bad: false,
            dkg0: Some(d),
            dkg1: None::<dkg::DKGWaitingShare<KeyCurve>>,
            dkg2: None,
            dkg3: None,
            output: None,
        }
    }

    pub fn dkg_phase1(&mut self, board: &mut Board, be_bad: bool) {
        let to_phase1 = self.dkg0.take().unwrap();
        let (ndkg, shares) = to_phase1.shares();
        if !be_bad {
            self.bad = true;
            board.publish_shares(&self.public, shares);
        }
        self.dkg1 = Some(ndkg);
    }

    pub fn dkg_phase2(&mut self, board: &mut Board, shares: &Vec<dkg::BundledShares<KeyCurve>>) {
        let to_phase2 = self.dkg1.take().unwrap();
        match to_phase2.process_shares(shares) {
            Ok((ndkg, bundle_o)) => {
                if let Some(bundle) = bundle_o {
                    println!("\t\t -> node publish {} responses", self.index);
                    board.publish_responses(&self.public, bundle);
                }
                self.dkg2 = Some(ndkg);
            }
            Err(e) => panic!("index {}: {:?}", self.index, e),
        }
    }

    pub fn dkg_endphase2(&mut self, board: &mut Board, bundle: &Vec<dkg::BundledResponses>) {
        let end_phase2 = self.dkg2.take().unwrap();
        match end_phase2.process_responses(bundle) {
            Ok(output) => self.output = Some(output),
            Err((ndkg, justifs)) => {
                self.dkg3 = Some(ndkg);
                // publish justifications if you have some
                // Nodes may just see that justifications are needed but they
                // don't have to create any, since no  complaint have been filed
                // against their deal.
                if let Some(j) = justifs {
                    board.publish_justifications(&self.public, j);
                }
            }
        }
    }

    pub fn dkg_phase3(
        &mut self,
        justifications: &Vec<dkg::BundledJustification<KeyCurve>>,
    ) -> Result<(), Box<dyn Error>> {
        let phase3 = self.dkg3.take().unwrap();
        match phase3.process_justifications(justifications) {
            Ok(output) => {
                self.output = Some(output);
                Ok(())
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn partial(&mut self, partial: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let out = self.output.take().unwrap();
        let res = Scheme::partial_sign(&out.share, partial);
        self.output = Some(out);
        res
    }

    pub fn qual(&mut self) -> dkg::Group<KeyCurve> {
        let output = self.output.take().unwrap();
        let qual = output.qual.clone();
        self.output = Some(output);
        qual
    }

    pub fn dist_public(&mut self) -> DistPublic<KeyCurve> {
        let output = self.output.take().unwrap();
        let dpub = output.public.clone();
        self.output = Some(output);
        dpub
    }
}
