use super::{
    group::Group,
    status::{Status, StatusMatrix},
};

use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use threshold_bls::{
    ecies::{self, EciesCipher},
    group::{Curve, Element},
    poly::{Idx, Poly, PrivatePoly, PublicPoly},
    DistPublic, Share,
};

use super::{DKGError, DKGResult, ShareError, ShareErrorType};

// TODO
// - check VSS-forgery article
// - zeroise

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
struct DKGInfo<C: Curve> {
    private_key: C::Scalar,
    index: Idx,
    group: Group<C>,
    secret: Poly<C::Scalar>,
    public: Poly<C::Point>,
}

impl<C> DKGInfo<C>
where
    C: Curve,
{
    /// Returns the number of nodes participating in the group for this DKG
    fn n(&self) -> usize {
        self.group.len()
    }

    /// Returns the threshold of the group for this DKG
    fn thr(&self) -> usize {
        self.group.threshold
    }
}

/// DKG is the struct containing the logic to run the Distributed Key Generation
/// protocol from [Pedersen](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf).
///
/// The protocol runs at minimum in two phases and at most in three phases as
/// described in the module documentation.
///
/// Each transition to a new phase is consuming the DKG state (struct) to produce
/// a new state that only accepts to transition to the next phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKG<C: Curve> {
    /// Metadata about the DKG
    info: DKGInfo<C>,
}

/// EncryptedShare holds the ECIES encryption of a share destined to the
/// `share_idx`-th participant. When receiving the share, if the participant has
/// the same specified index, the corresponding dkg state decrypts the share using
/// the participant's private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct EncryptedShare<C: Curve> {
    /// The index of the participant this share belongs to
    share_idx: Idx,
    /// The ECIES encrypted share
    secret: EciesCipher<C>,
}

/// BundledShares holds all encrypted shares a dealer creates during the first
/// phase of the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct BundledShares<C: Curve> {
    pub dealer_idx: Idx,
    pub shares: Vec<EncryptedShare<C>>,
    /// public is the commitment of the secret polynomial
    /// created by the dealer. In the context of using a blockchain as a
    /// broadcast channel, it can be posted only once.
    pub public: PublicPoly<C>,
}

impl<C> DKG<C>
where
    C: Curve,
{
    /// Creates a new DKG instance from the provided private key and group.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub fn new(private_key: C::Scalar, group: Group<C>) -> Result<DKG<C>, DKGError> {
        use rand::prelude::*;
        Self::new_rand(private_key, group, &mut thread_rng())
    }

    pub fn new_rand<R: RngCore>(
        private_key: C::Scalar,
        group: Group<C>,
        rng: &mut R,
    ) -> Result<DKG<C>, DKGError> {
        // check if public key is included
        let mut public_key = C::Point::one();
        public_key.mul(&private_key);
        let idx = group
            .index(&public_key)
            .ok_or_else(|| DKGError::PublicKeyNotFound)?;
        let secret = PrivatePoly::<C>::new_from(group.threshold - 1, rng);
        let public = secret.commit::<C::Point>();
        let info = DKGInfo {
            private_key,
            index: idx,
            group,
            secret,
            public,
        };
        Ok(DKG { info })
    }

    pub fn encrypt_shares<R: RngCore>(self, rng: &mut R) -> (DKGWaitingShare<C>, BundledShares<C>) {
        let shares = self
            .info
            .group
            .nodes
            .iter()
            .map(|n| {
                let sec = self.info.secret.eval(n.id() as Idx);
                let buff = bincode::serialize(&sec.value).expect("serialization should not fail");
                let cipher = ecies::encrypt::<C, _>(n.key(), &buff, rng);
                EncryptedShare::<C> {
                    share_idx: n.id(),
                    secret: cipher,
                }
            })
            .collect();

        let bundle = BundledShares {
            dealer_idx: self.info.index,
            shares,
            public: self.info.public.clone(),
        };
        let dw = DKGWaitingShare { info: self.info };
        (dw, bundle)
    }
}

/// DKGOutput is the final output of the DKG protocol in case it runs
/// successfully. It contains the QUALified group (the list of nodes that
/// sucessfully ran the protocol until the end), the distributed public key and
/// the private share corresponding to the participant's index.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKGOutput<C: Curve> {
    pub qual: Group<C>,
    pub public: DistPublic<C>,
    pub share: Share<C::Scalar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub dealer_idx: Idx,
    pub status: Status,
}

/// A `BundledResponse` is sent during the second phase of the protocol by all
/// participants that have received invalid or inconsistent shares (all statuses
/// are `Complaint`). The bundles contains the index of the recipient of the
/// shares, the one that created the response.  Each `Response` contains the
/// index of the participant that created the share (a *dealer*),
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundledResponses {
    /// share_idx is the index of the node that received the shares
    pub share_idx: Idx,
    pub responses: Vec<Response>,
}

/// A `Justification` contains the share of the share holder that issued a
/// complaint, in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct Justification<C: Curve> {
    share_idx: Idx,
    share: C::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct BundledJustification<C: Curve> {
    pub dealer_idx: Idx,
    pub justifications: Vec<Justification<C>>,
    pub public: PublicPoly<C>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKGWaitingShare<C: Curve> {
    info: DKGInfo<C>,
}

impl<C> DKGWaitingShare<C>
where
    C: Curve,
{
    /// (a) Report complaint on invalid dealer index
    /// (b) Report complaint on absentee shares for us
    /// (c) Report complaint on invalid encryption
    /// (d) Report complaint on invalid length of public polynomial
    /// (e) Report complaint on invalid share w.r.t. public polynomial
    pub fn process_shares(
        self,
        bundles: &[BundledShares<C>],
    ) -> DKGResult<(DKGWaitingResponse<C>, Option<BundledResponses>)> {
        self.process_shares_get_complaint(bundles)
    }

    fn process_shares_get_complaint(
        self,
        bundles: &[BundledShares<C>],
    ) -> DKGResult<(DKGWaitingResponse<C>, Option<BundledResponses>)> {
        // true means we suppose every missing responses is a success at the end of
        // the period. Hence we only need to get & broadcast the complaints.
        // See DKGWaitingResponse::new for more information.
        let myidx = self.info.index;

        let (newdkg, bundle) = self.process_shares_get_all(bundles)?;

        let complaints: Vec<_> = bundle
            .responses
            .into_iter()
            .filter(|r| !r.status.is_success())
            .collect();

        let bundle = if !complaints.is_empty() {
            Some(BundledResponses {
                responses: complaints,
                share_idx: myidx,
            })
        } else {
            None
        };

        Ok((newdkg, bundle))
    }

    // get_all exists to make the dkg impl. handle the case where we don't want
    // to wait until the end of the period to progress: if all inputs are
    // are valid, we can already broadcast "Success" responses. If all peers
    // receive all "Sucess" responses from everybody then the protocol can
    // short-circuit and directly finish.
    fn process_shares_get_all(
        self,
        bundles: &[BundledShares<C>],
    ) -> DKGResult<(DKGWaitingResponse<C>, BundledResponses)> {
        use Status::{Complaint, Success};
        let n = self.info.n();
        let thr = self.info.thr();
        let my_idx = self.info.index;
        // the default defines the capability of the protocol to finish
        // before an epoch or not if all responses are correct.  A `true`
        // value indicates that participants should only broadcast their
        // complaint (negative response) in the event they have complaints
        // and "do nothing" in case there is no complaints to broadcast. At
        // the end of the period, each participant will call this method
        // with all responses seen so far. At the end of the period, all
        // absent responses are assumed to have the success status meaning
        // their issuer have not found any problem with their received
        // shares. Hence, it forces the protocol to wait until the end of
        // the period, to make sure there is no complaint unseen. This case
        // follows the paper specification of the protocol and is especially
        // relevant in the context of having a blockchain as a bulletin
        // board, where periods are clearly delimited,for example with block
        // heights.  **Note**: this is the default behavior of this
        // implementation.
        //
        // On the other hand, a `false` value indicates miners MUST
        // broadcast all of their responses, regardless of their status for
        // them to be considered. Otherwise, a participant risk to be
        // considered absent. This specific case is useful in the context of
        // streamlining the protocol, so it can move to the next period
        // before the end, in case all responses are success. Note this mode
        // is currently *not* used.
        //
        // Currently: all responses are set to true except for my own indexes so
        // by default this node requires to have all shares and will issue a
        // response if any share is missing or wrong
        let mut statuses = StatusMatrix::new(n, n, Success);
        for dealer_idx in 0..n {
            if dealer_idx == my_idx as usize {
                continue;
            }
            statuses.set(dealer_idx as Idx, my_idx, Complaint);
        }
        let public_polynomials = Self::extract_poly(&bundles);

        let not_from_me = bundles.iter().filter(|b| b.dealer_idx != my_idx);
        let mut ok = vec![];
        // iterate, extract and decode all shares for us
        for bundle in not_from_me {
            if bundle.dealer_idx >= n as Idx {
                // (a) reporting
                continue;
            }
            // NOTE: this implementation stops at the first one.
            // TODO: should it return an error if multiple shares are for my idx?
            //       -> probably yes
            if let Some(my_share) = bundle.shares.iter().find(|s| s.share_idx == my_idx) {
                match self.try_share(bundle.dealer_idx, &bundle.public, my_share) {
                    Ok(share) => ok.push((bundle.dealer_idx, &bundle.public, share)),
                    Err(err) => {
                        eprintln!("Could not share: {}", err);
                    }
                }
            } else {
                // (b) reporting
                continue;
            }
        }

        // thr - 1 because I have my own shares
        if ok.len() < thr - 1 {
            return Err(DKGError::NotEnoughValidShares(ok.len(), thr));
        }

        // add shares and public polynomial together for all ok deal
        let mut fshare = self.info.secret.eval(self.info.index).value;
        let mut fpub = self.info.public.clone();
        for bundle in ok {
            statuses.set(bundle.0, my_idx, Success);
            fpub.add(&bundle.1);
            fshare.add(&bundle.2);
        }

        let responses: Vec<Response> = statuses
            .get_for_share(my_idx)
            .iter()
            .enumerate()
            .map(|(i, b)| Response {
                dealer_idx: i as Idx,
                status: Status::from(*b),
            })
            .collect();
        let bundle = BundledResponses {
            share_idx: my_idx,
            responses,
        };
        let new_dkg =
            DKGWaitingResponse::new(self.info, fshare, fpub, statuses, public_polynomials);
        Ok((new_dkg, bundle))
    }

    // extract_poly maps the bundles into a map: Idx -> public poly for ease of
    // use later on
    fn extract_poly(bundles: &[BundledShares<C>]) -> HashMap<Idx, PublicPoly<C>> {
        // TODO avoid cloning by using lifetime or better gestin in
        // process_shares
        bundles.iter().fold(HashMap::new(), |mut acc, b| {
            acc.insert(b.dealer_idx, b.public.clone());
            acc
        })
    }

    fn try_share(
        &self,
        dealer: Idx,
        public: &PublicPoly<C>,
        share: &EncryptedShare<C>,
    ) -> Result<C::Scalar, ShareError> {
        let thr = self.info.thr();
        if public.degree() + 1 != thr {
            // report (d) error
            return Err(ShareError::from(
                dealer,
                ShareErrorType::InvalidPublicPolynomial(public.degree(), thr),
            ));
        }
        let buff = ecies::decrypt::<C>(&self.info.private_key, &share.secret)
            .map_err(|err| ShareError::from(dealer, ShareErrorType::InvalidCiphertext(err)))?;

        let share: C::Scalar =
            bincode::deserialize(&buff).expect("scalar should not fail when unmarshaling");
        if !share_correct::<C>(self.info.index, &share, public) {
            return Err(ShareError::from(dealer, ShareErrorType::InvalidShare));
        }
        Ok(share)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKGWaitingResponse<C: Curve> {
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    statuses: StatusMatrix,
    publics: HashMap<Idx, PublicPoly<C>>,
}

impl<C> DKGWaitingResponse<C>
where
    C: Curve,
{
    fn new(
        info: DKGInfo<C>,
        dist_share: C::Scalar,
        dist_pub: PublicPoly<C>,
        statuses: StatusMatrix,
        publics: HashMap<Idx, PublicPoly<C>>,
    ) -> Self {
        Self {
            info,
            dist_share,
            dist_pub,
            statuses,
            publics,
        }
    }

    /// Check:
    /// - no more than
    #[allow(clippy::type_complexity)]
    pub fn process_responses(
        self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, (DKGWaitingJustification<C>, Option<BundledJustification<C>>)> {
        let n = self.info.n();
        let statuses = self.set_statuses(responses);
        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let required = (0..n).any(|dealer| !statuses.all_true(dealer as Idx));

        if !required {
            // bingo ! Returns the final share now and stop the protocol
            let share = Share {
                index: self.info.index,
                private: self.dist_share,
            };
            return Ok(DKGOutput {
                // everybody is qualified in this case since there is no
                // complaint at all
                qual: self.info.group.clone(),
                public: self.dist_pub,
                share,
            });
        }

        // find out if some responses correspond to our deal
        let mut ret_justif: Option<BundledJustification<C>> = None;
        let my_idx = self.info.index;
        if !statuses.all_true(my_idx) {
            let my_row = statuses.get_for_dealer(my_idx);
            let mut justifs = Vec::with_capacity(my_row.len());
            for (i, success) in my_row.iter().enumerate() {
                if *success {
                    continue;
                }
                let id = i as Idx;
                // reveal the share
                let ijust = Justification {
                    share_idx: id,
                    share: self.info.secret.eval(id).value,
                };
                justifs.push(ijust);
            }
            let bundle = BundledJustification {
                dealer_idx: self.info.index,
                justifications: justifs,
                public: self.info.public.clone(),
            };
            ret_justif = Some(bundle);
        }
        let dkg = DKGWaitingJustification {
            info: self.info,
            dist_share: self.dist_share,
            dist_pub: self.dist_pub,
            statuses,
            publics: self.publics,
        };
        Err((dkg, ret_justif))
    }

    /// set_statuses set the status of the given responses on the status matrix.
    fn set_statuses(&self, responses: &[BundledResponses]) -> StatusMatrix {
        let mut statuses = self.statuses.clone();
        let my_idx = self.info.index;
        let n = self.info.n();

        // makes sure the API doesn't take into account our own responses!
        let not_from_me = responses.iter().filter(|r| r.share_idx != my_idx);
        let valid_idx = not_from_me.filter(|r| {
            let good_holder = r.share_idx < n as Idx;
            let good_dealers = !r.responses.iter().any(|resp| resp.dealer_idx >= n as Idx);
            good_dealers && good_holder
        });
        for bundle in valid_idx {
            let holder_index = bundle.share_idx;
            for response in bundle.responses.iter() {
                let dealer_index = response.dealer_idx;
                statuses.set(dealer_index, holder_index, response.status);
            }
        }
        statuses
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKGWaitingJustification<C: Curve> {
    // TODO: transform that into one info variable that gets default value for
    // missing parts depending in the round of the protocol.
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    // guaranteed to be of the right size (n)
    statuses: StatusMatrix,
    publics: HashMap<Idx, PublicPoly<C>>,
}

impl<C> DKGWaitingJustification<C>
where
    C: Curve,
{
    /// Accept a justification if the following conditions are true:
    /// - bundle's dealer index is in range
    /// - a justification was required for the given share (no-op)
    /// - share corresponds to public polynomial received in the bundled shares during
    /// first period.
    /// Return an output if `len(qual) > thr`
    pub fn process_justifications(
        self,
        justifs: &[BundledJustification<C>],
    ) -> Result<DKGOutput<C>, DKGError> {
        use Status::Success;
        // avoid a mutable ref needed, ok for small miner size..
        let mut statuses = self.statuses.clone();
        let mut add_share = C::Scalar::zero();
        let mut add_public = PublicPoly::<C>::zero();
        for bundle in justifs
            .iter()
            .filter(|b| b.dealer_idx < self.info.n() as Idx)
            .filter(|b| b.dealer_idx != self.info.index)
            .filter(|b| self.publics.contains_key(&b.dealer_idx))
        {
            // guaranteed unwrap from previous filter
            let public = self.publics.get(&bundle.dealer_idx).unwrap();
            for j in bundle.justifications.iter() {
                if !share_correct::<C>(j.share_idx, &j.share, public) {
                    continue;
                }
                // justification is valid, we mark it off from our matrix
                statuses.set(bundle.dealer_idx, j.share_idx, Success);
                // if it is for us, then add it to our final share and public poly
                if j.share_idx == self.info.index {
                    add_share.add(&j.share);
                    add_public.add(&bundle.public);
                }
            }
        }

        let n = self.info.n();
        // QUAL is the set of all entries in the matrix where all bits are set
        let qual_indices = (0..n).fold(Vec::new(), |mut acc, dealer| {
            if statuses.all_true(dealer as Idx) {
                acc.push(dealer);
            }
            acc
        });
        let thr = self.info.group.threshold;
        if qual_indices.len() < thr {
            // too many unanswered justifications, DKG abort !
            return Err(DKGError::NotEnoughJustifications(qual_indices.len(), thr));
        }

        let qual_nodes = self
            .info
            .group
            .nodes
            .into_iter()
            .filter(|n| qual_indices.contains(&(n.id() as usize)))
            .collect();
        let group = Group::<C>::new(qual_nodes, thr)?;

        // add all good shares and public poly together
        add_share.add(&self.dist_share);
        add_public.add(&self.dist_pub);
        let ds = Share {
            index: self.info.index,
            private: add_share,
        };
        Ok(DKGOutput {
            qual: group,
            public: add_public,
            share: ds,
        })
    }
}

/// Checks if the commitment to the share corresponds to the public polynomial's
/// evaluated at the given point.
fn share_correct<C: Curve>(idx: Idx, share: &C::Scalar, public: &PublicPoly<C>) -> bool {
    let mut commit = C::Point::one();
    commit.mul(&share);
    let pub_eval = public.eval(idx);
    pub_eval.value == commit
}

#[cfg(feature = "bls12_381")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::curve::bls12381::{Curve as BCurve, Scalar, G1};
    use crate::poly::{Eval, InvalidRecovery};

    use rand::prelude::*;

    use serde::{de::DeserializeOwned, Serialize};
    use static_assertions::assert_impl_all;

    assert_impl_all!(Node<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(Group<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(DKGInfo<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(DKG<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(EncryptedShare<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(BundledShares<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(DKGOutput<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);
    assert_impl_all!(BundledJustification<BCurve>: Serialize, DeserializeOwned, Clone, std::fmt::Debug);

    fn setup_group(n: usize) -> (Vec<Scalar>, Group<BCurve>) {
        let privs: Vec<Scalar> = (0..n)
            .map(|_| {
                let mut private = Scalar::new();
                private.pick(&mut thread_rng());
                private
            })
            .collect();
        let pubs: Vec<G1> = privs
            .iter()
            .map(|private| {
                let mut public = G1::one();
                public.mul(private);
                public
            })
            .collect();
        return (privs, pubs.into());
    }

    fn reconstruct<C: Curve>(
        thr: usize,
        shares: &Vec<DKGOutput<C>>,
    ) -> Result<PrivatePoly<C>, InvalidRecovery> {
        let evals: Vec<_> = shares
            .iter()
            .map(|o| Eval {
                value: o.share.private.clone(),
                index: o.share.index,
            })
            .collect();
        Poly::<C::Scalar, C::Scalar>::full_recover(thr, evals)
    }

    #[test]
    fn group_index() {
        let n = 6;
        //let thr = default_threshold(n);
        let (privs, group) = setup_group(n);
        let cloned = group.clone();
        for private in privs {
            let mut public = G1::one();
            public.mul(&private);
            cloned.index(&public).expect("should find public key");
        }
    }

    #[test]
    fn full_dkg() {
        let n = 5;
        let thr = default_threshold(n);
        let (privs, group) = setup_group(n);
        let dkgs: Vec<_> = privs
            .into_iter()
            .map(|p| DKG::new(p, group.clone()).unwrap())
            .collect();
        let mut all_shares = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, shares) = dkg.shares();
                all_shares.push(shares);
                ndkg
            })
            .collect();
        let response_bundles = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                // TODO clone inneficient for test but likely use case for API
                // Make that take a reference
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares).unwrap();
                if let Some(_) = bundle_o {
                    panic!("full dkg should not return any complaint")
                    //response_bundles.push(bundle);
                }
                ndkg
            })
            .collect();
        let outputs: Vec<_> = dkgs
            .into_iter()
            // TODO implement debug for err return so we can use unwrap
            .map(|dkg| match dkg.process_responses(&response_bundles) {
                Ok(out) => out,
                // Err((ndkg,justifs)) =>
                Err((_, _)) => panic!("should not happen"),
            })
            .collect();
        let recovered_private = reconstruct(thr, &outputs).unwrap();
        let recovered_public = recovered_private.commit::<G1>();
        let recovered_key = recovered_public.free_coeff();
        for out in outputs.iter() {
            let public = &out.public;
            assert_eq!(public.free_coeff(), recovered_key);
        }
    }

    #[test]
    fn invalid_shares() {
        let n = 5;
        let thr = default_threshold(n);
        let (privs, group) = setup_group(n);
        let dkgs: Vec<_> = privs
            .into_iter()
            .map(|p| DKG::new(p, group.clone()).unwrap())
            .collect();

        let mut all_shares = Vec::with_capacity(n);

        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, shares) = dkg.shares();
                all_shares.push(shares);
                ndkg
            })
            .collect();

        // modify a share
        all_shares[0].shares[1].secret = ecies::encrypt(&BCurve::point(), &vec![1]);
        all_shares[3].shares[4].secret = ecies::encrypt(&BCurve::point(), &vec![1]);

        let mut response_bundles = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                // TODO clone inneficient for test but likely use case for API
                // Make that take a reference
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares).unwrap();
                if let Some(bundle) = bundle_o {
                    response_bundles.push(bundle);
                }
                ndkg
            })
            .collect();

        let mut justifications = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            // TODO implement debug for err return so we can use unwrap
            .map(|dkg| match dkg.process_responses(&response_bundles) {
                // it shouldn't be ok if there are some justifications
                // since some shares are invalid there should be
                Ok(_out) => panic!("that should not happen"),
                Err((ndkg, justifs)) => {
                    if let Some(j) = justifs {
                        justifications.push(j);
                    }
                    ndkg
                }
            })
            .collect();

        let outputs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| match dkg.process_justifications(&justifications) {
                Ok(out) => out,
                Err(e) => panic!("{}", e),
            })
            .collect();

        let recovered_private = reconstruct(thr, &outputs).unwrap();
        let recovered_public = recovered_private.commit::<G1>();
        let recovered_key = recovered_public.public_key();
        for out in outputs.iter() {
            let public = &out.public;
            assert_eq!(public.free_coeff(), recovered_key);
        }
    }
}
