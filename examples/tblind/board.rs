use crate::curve::{KeyCurve, PublicKey};
use blind_threshold_bls::dkg;
use blind_threshold_bls::*;

pub struct Board {
    group: dkg::Group<KeyCurve>,
    phase1: bool,
    phase2: bool,
    phase3: bool,
    dkg_finished: bool,
    bundles: Vec<dkg::BundledShares<KeyCurve>>,
    responses: Vec<dkg::BundledResponses>,
    justifs: Vec<dkg::BundledJustification<KeyCurve>>,
}

impl Board {
    pub fn init(group: dkg::Group<KeyCurve>) -> Self {
        let len = Vec::with_capacity(group.len());
        Self {
            group: group,
            phase1: false,
            phase2: false,
            phase3: false,
            dkg_finished: false,
            bundles: len,
            responses: vec![],
            justifs: vec![],
        }
    }

    pub fn dkg_start(&mut self) {
        self.phase1 = true;
    }

    pub fn dkg_phase2(&mut self) -> Vec<dkg::BundledShares<KeyCurve>> {
        if !self.phase1 {
            panic!("can't pass to phase2 if dkg not started");
        }
        self.phase1 = false;
        self.phase2 = true;
        return self.bundles.clone();
    }

    pub fn dkg_need_phase3(&self) -> bool {
        // if there is no complaint we dont need any justifications
        return self.responses.len() != 0;
    }

    pub fn dkg_phase3(&mut self) {
        if !self.phase2 {
            panic!("can't pass to phase3 if not phase2");
        }
        self.phase2 = false;
        self.phase3 = true;
    }

    pub fn finish_dkg(&mut self) {
        if !self.phase3 || !self.dkg_need_phase3() {
            panic!("can't finish dkg if not in right phase");
        }
        self.phase3 = false;
        self.dkg_finished = true;
    }

    /// publish_shares is called by each participant of the dkg protocol during
    /// the phase 1.
    /// NOTE: this call should verify the authenticity of the sender! This
    /// function only checks the public key at the moment - Needs further
    /// clarification from actual use case
    pub fn publish_shares(&mut self, sender_pk: &PublicKey, bundle: dkg::BundledShares<KeyCurve>) {
        if !self.phase1 {
            panic!("dkg is not in phase1 - can't publish shares");
        }
        match self.check_authenticity(sender_pk, bundle.dealer_idx) {
            Ok(_) => self.bundles.push(bundle),
            Err(s) => panic!(s),
        }
    }

    /// publish_responses is called during phase 2 by participant that claim
    /// having received an invalid share.
    /// NOTE: this call should verify the authenticity of the sender! This
    /// function only checks the public key at the moment - Needs further
    /// clarification from actual use case
    pub fn publish_responses(&mut self, sender_pk: &PublicKey, bundle: dkg::BundledResponses) {
        if !self.phase2 {
            panic!("dkg is not in phase2 - can't publish responses");
        }
        match self.check_authenticity(sender_pk, bundle.share_idx) {
            Ok(_) => self.responses.push(bundle),
            Err(e) => panic!(e),
        }
    }

    pub fn publish_justifications(
        &mut self,
        sender_pk: &PublicKey,
        bundle: dkg::BundledJustification<KeyCurve>,
    ) {
        if !self.phase3 {
            panic!("dkg is not in phase3 - can't publish justifications");
        }
        match self.check_authenticity(sender_pk, bundle.dealer_idx) {
            Ok(_) => self.justifs.push(bundle),
            Err(e) => panic!(e),
        }
    }

    pub fn get_shares(&self) -> Vec<dkg::BundledShares<KeyCurve>> {
        return self.bundles.clone();
    }

    pub fn get_responses(&self) -> Vec<dkg::BundledResponses> {
        return self.responses.clone();
    }

    pub fn get_justifications(&self) -> Vec<dkg::BundledJustification<KeyCurve>> {
        return self.justifs.clone();
    }

    fn check_authenticity(
        &self,
        sender: &PublicKey,
        claimed_index: Index,
    ) -> Result<Index, String> {
        match self.group.index(sender) {
            Some(i) => {
                // Actual verification
                if i != claimed_index {
                    Err(String::from(
                        "publish shares called with different index than bundle",
                    ))
                } else {
                    Ok(i)
                }
            }
            None => Err(String::from(
                "publish shares called with a public that does not belong to group",
            )),
        }
    }
}
