use super::{
    group::Group,
    status::{Status, StatusMatrix},
    DKGError, DKGResult, ShareError,
};

use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use threshold_bls::{
    ecies::{self, EciesCipher},
    group::{Curve, Element},
    poly::{Idx, Poly, PrivatePoly, PublicPoly},
    sig::Share,
};

use std::cell::RefCell;

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

impl<C: Curve> DKGInfo<C> {
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
    /// The dealer's index
    pub dealer_idx: Idx,
    /// The encrypted shared created by the dealer
    pub shares: Vec<EncryptedShare<C>>,
    /// The commitment of the secret polynomial created by the dealer.
    /// In the context of using a blockchain as a broadcast channel,
    /// it can be posted only once.
    pub public: PublicPoly<C>,
}

impl<C: Curve> DKG<C> {
    /// Creates a new DKG instance from the provided private key and group.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub fn new(private_key: C::Scalar, group: Group<C>) -> Result<DKG<C>, DKGError> {
        use rand::prelude::*;
        Self::new_rand(private_key, group, &mut thread_rng())
    }

    /// Creates a new DKG instance from the provided private key, group and RNG.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub fn new_rand<R: RngCore>(
        private_key: C::Scalar,
        group: Group<C>,
        rng: &mut R,
    ) -> Result<DKG<C>, DKGError> {
        // get the public key
        let mut public_key = C::Point::one();
        public_key.mul(&private_key);

        // check if the public key is part of the group
        let index = group
            .index(&public_key)
            .ok_or_else(|| DKGError::PublicKeyNotFound)?;

        // Generate a secret polynomial and commit to it
        let secret = PrivatePoly::<C>::new_from(group.threshold - 1, rng);
        let public = secret.commit::<C::Point>();

        let info = DKGInfo {
            private_key,
            index,
            group,
            secret,
            public,
        };

        Ok(DKG { info })
    }

    /// Evaluates the secret polynomial at the index of each DKG participant and encrypts
    /// the result with the corresponding public key. Returns the bundled encrypted shares
    /// as well as the next phase of the DKG.
    pub fn encrypt_shares<R: RngCore>(
        self,
        rng: &mut R,
    ) -> DKGResult<(DKGWaitingShare<C>, BundledShares<C>)> {
        let shares = self
            .info
            .group
            .nodes
            .iter()
            .map(|n| {
                // evaluate the secret polynomial at the node's id
                let sec = self.info.secret.eval(n.id() as Idx);

                // serialize the evaluation
                let buff = bincode::serialize(&sec.value)?;

                // encrypt it
                let cipher = ecies::encrypt::<C, _>(n.key(), &buff, rng);

                // save the share
                Ok(EncryptedShare {
                    share_idx: n.id(),
                    secret: cipher,
                })
            })
            .collect::<Result<Vec<_>, DKGError>>()?;

        // Return the encrypted shares along with a commitment
        // to their secret polynomial.
        let bundle = BundledShares {
            dealer_idx: self.info.index,
            shares,
            public: self.info.public.clone(),
        };
        let dw = DKGWaitingShare { info: self.info };

        Ok((dw, bundle))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A response which gets generated when processing the shares from Phase 1
pub struct Response {
    /// The index of the dealer (the person that created the share)
    pub dealer_idx: Idx,
    /// The status of the response (whether it suceeded or if there were complaints)
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
    /// A vector of responses from each share creator
    pub responses: Vec<Response>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// DKG Stage which waits to receive the shares from the previous phase's participants
/// as input. After processing the shares, if there were any complaints it will generate
/// a bundle of responses for the next phase.
pub struct DKGWaitingShare<C: Curve> {
    /// Metadata about the DKG
    info: DKGInfo<C>,
}

impl<C: Curve> DKGWaitingShare<C> {
    /// Tries to decrypt the provided shares and calculate the secret key and the
    /// threshold public key.
    ///
    /// Will return a complaint in the responses on the following cases:
    /// (a) invalid dealer index
    /// (b) absentee shares for us
    /// (c) invalid encryption
    /// (d) invalid length of public polynomial
    /// (e) invalid share w.r.t. public polynomial
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

        // complaints are unsuccessful responses
        let complaints = bundle
            .responses
            .into_iter()
            .filter(|r| !r.status.is_success())
            .collect::<Vec<_>>();

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
        let mut statuses = StatusMatrix::new(n, n, Status::Success);
        for dealer_idx in 0..n {
            if dealer_idx == my_idx as usize {
                continue;
            }
            statuses.set(dealer_idx as Idx, my_idx, Status::Complaint);
        }

        let valid_shares = bundles
            .iter()
            // check the ones we did not deal out
            .filter(|b| b.dealer_idx != my_idx)
            // check the ones with a valid dealer index
            .filter(|b| b.dealer_idx <= n as Idx)
            // get the share which corresponds to us
            .filter_map(|b| {
                // TODO: Return an error if there are multiple cases where the share
                // index matches ours.
                // `.find` stops at the first occurence only.
                b.shares
                    .iter()
                    .find(|s| s.share_idx == my_idx)
                    .map(|share| (b, share))
            })
            // try to decrypt it (ignore invalid decryptions)
            .filter_map(|(bundle, encrypted_share)| {
                self.decrypt_and_check_share(bundle.dealer_idx, &bundle.public, encrypted_share)
                    .map(|share| (bundle, share))
                    .ok()
            })
            // TODO: Can we avoid this allocation and combine it with the `for_each`
            // below while also being able to check the length?
            .collect::<Vec<_>>();

        // we check with `thr - 1` because we already have our shares
        if valid_shares.len() < thr - 1 {
            return Err(DKGError::NotEnoughValidShares(valid_shares.len(), thr));
        }

        // The user's secret share is the sum of all received shares (remember: each share is
        // an evaluation of a participant's private polynomial at our index)
        let mut fshare = self.info.secret.eval(self.info.index).value;
        // The public key polynomial is the sum of all shared polynomials
        let mut fpub = self.info.public.clone();
        valid_shares.iter().for_each(|(bundle, share)| {
            statuses.set(bundle.dealer_idx, my_idx, Status::Success);
            fpub.add(&bundle.public);
            fshare.add(&share);
        });

        // Convert the values in the status matrix for all other participants at
        // our share to responses
        let responses = statuses
            .get_for_share(my_idx)
            .into_iter()
            .enumerate()
            .map(|(i, b)| Response {
                dealer_idx: i as Idx,
                status: Status::from(b),
            })
            .collect::<Vec<_>>();

        let bundle = BundledResponses {
            share_idx: my_idx,
            responses,
        };

        let public_polynomials = Self::extract_poly(&bundles);
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

    fn decrypt_and_check_share(
        &self,
        dealer: Idx,
        public: &PublicPoly<C>,
        share: &EncryptedShare<C>,
    ) -> Result<C::Scalar, DKGError> {
        // report (d) error
        let thr = self.info.thr();
        if public.degree() + 1 != thr {
            return Err(ShareError::InvalidPublicPolynomial(dealer, public.degree(), thr).into());
        }

        let buff = ecies::decrypt::<C>(&self.info.private_key, &share.secret)
            .map_err(|err| ShareError::InvalidCiphertext(dealer, err))?;

        let share: C::Scalar = bincode::deserialize(&buff)?;

        if !share_correct::<C>(self.info.index, &share, public) {
            return Err(ShareError::InvalidShare(dealer).into());
        }

        Ok(share)
    }
}

/// A `Justification` contains the share of the share holder that issued a
/// complaint, in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct Justification<C: Curve> {
    /// The share holder's index
    share_idx: Idx,
    /// The plaintext share
    share: C::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// A BundledJustification is broadcast by a dealer and contains the justifications
/// they have received along with their corresponding Public polynomial
pub struct BundledJustification<C: Curve> {
    /// The dealer's index
    pub dealer_idx: Idx,
    /// The justifications
    pub justifications: Vec<Justification<C>>,
    /// The public polynomial
    pub public: PublicPoly<C>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// DKG Stage which waits to receive the responses from the previous phase's participants
/// as input. The responses will be processed and justifications may be generated as a byproduct
/// if there are complaints.
pub struct DKGWaitingResponse<C: Curve> {
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    statuses: StatusMatrix,
    publics: HashMap<Idx, PublicPoly<C>>,
}

/// DKGOutput is the final output of the DKG protocol in case it runs
/// successfully.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct DKGOutput<C: Curve> {
    /// The list of nodes that successfully ran the protocol until the end
    pub qual: Group<C>,
    /// The distributed public key
    pub public: PublicPoly<C>,
    /// The private share which corresponds to the participant's index
    pub share: Share<C::Scalar>,
}

impl<C: Curve> DKGWaitingResponse<C> {
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

    #[allow(clippy::type_complexity)]
    /// Checks if the responses when applied to the status matrix result in a matrix with only
    /// `Success` elements. If so, the protocol terminates.
    ///
    /// If there are complaints in the Status matrix, then it will return an error with the
    /// justifications required for Phase 3 of the DKG.
    pub fn process_responses(
        mut self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, (DKGWaitingJustification<C>, Option<BundledJustification<C>>)> {
        let n = self.info.n();
        self.set_statuses(responses);
        let statuses = &self.statuses;

        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let justifications_required = (0..n).any(|dealer| !statuses.all_true(dealer as Idx));

        if justifications_required {
            // If there were any complaints against our deal, then we should re-evaluate
            // our secret polynomial at the indexes where the complaints were, and publish
            // these as justifications (i.e. indicating that we are still behaving correctly).
            let my_idx = self.info.index;
            let bundled_justifications = if !statuses.all_true(my_idx) {
                let justifications = statuses
                    .get_for_dealer(my_idx)
                    .iter()
                    .enumerate()
                    .filter_map(|(i, success)| {
                        if !success {
                            // reveal the share
                            let id = i as Idx;
                            Some(Justification {
                                share_idx: id,
                                share: self.info.secret.eval(id).value,
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                Some(BundledJustification {
                    dealer_idx: self.info.index,
                    justifications,
                    public: self.info.public.clone(),
                })
            } else {
                None
            };

            let dkg = DKGWaitingJustification {
                info: self.info,
                dist_share: self.dist_share,
                dist_pub: self.dist_pub,
                statuses: RefCell::new(self.statuses),
                publics: self.publics,
            };

            return Err((dkg, bundled_justifications));
        }

        // bingo ! Returns the final share now and stop the protocol
        let share = Share {
            index: self.info.index,
            private: self.dist_share,
        };

        Ok(DKGOutput {
            // everybody is qualified in this case since there is no
            // complaint at all
            qual: self.info.group.clone(),
            public: self.dist_pub,
            share,
        })
    }

    /// set_statuses set the status of the given responses on the status matrix.
    fn set_statuses(&mut self, responses: &[BundledResponses]) {
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
                self.statuses
                    .set(dealer_index, holder_index, response.status);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// DKG Stage which waits to receive the justifications from the previous phase's participants
/// as input to produce either the final DKG Output, or an error.
pub struct DKGWaitingJustification<C: Curve> {
    // TODO: transform that into one info variable that gets default value for
    // missing parts depending in the round of the protocol.
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    // guaranteed to be of the right size (n)
    statuses: RefCell<StatusMatrix>,
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
        let n = self.info.n();

        // Calculate the share and public polynomial from the provided justifications
        // (they will later be added to our existing share and public polynomial)
        let mut add_share = C::Scalar::zero();
        let mut add_public = PublicPoly::<C>::zero();
        justifs
            .iter()
            .filter(|b| b.dealer_idx < n as Idx)
            .filter(|b| b.dealer_idx != self.info.index)
            // get only the bundles for which we have a public polynomial for
            .filter_map(|b| self.publics.get(&b.dealer_idx).map(|public| (b, public)))
            .for_each(|(bundle, public)| {
                bundle
                    .justifications
                    .iter()
                    // ignore incorrect shares
                    .filter(|justification| {
                        share_correct::<C>(justification.share_idx, &justification.share, public)
                    })
                    .for_each(|justification| {
                        // justification is valid, we mark it off from our matrix
                        self.statuses.borrow_mut().set(
                            bundle.dealer_idx,
                            justification.share_idx,
                            Status::Success,
                        );

                        // if it is for us, then add it to our final share and public poly
                        if justification.share_idx == self.info.index {
                            add_share.add(&justification.share);
                            add_public.add(&bundle.public);
                        }
                    })
            });

        // QUAL is the set of all entries in the matrix where all bits are set
        let statuses = self.statuses.borrow();
        let qual_indices = (0..n)
            .filter(|&dealer| statuses.all_true(dealer as Idx))
            .collect::<Vec<_>>();

        let thr = self.info.group.threshold;
        if qual_indices.len() < thr {
            // too many unanswered justifications, DKG abort !
            return Err(DKGError::NotEnoughJustifications(qual_indices.len(), thr));
        }

        // create a group out of the qualifying nodes
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::primitives::default_threshold;
    use threshold_bls::{
        curve::bls12381::{Curve as BCurve, Scalar, G1},
        poly::{Eval, PolyError},
    };

    use rand::prelude::*;
    use std::fmt::Debug;

    use serde::{de::DeserializeOwned, Serialize};
    use static_assertions::assert_impl_all;

    assert_impl_all!(Group<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(DKGInfo<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(DKG<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(EncryptedShare<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(BundledShares<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(DKGOutput<BCurve>: Serialize, DeserializeOwned, Clone, Debug);
    assert_impl_all!(BundledJustification<BCurve>: Serialize, DeserializeOwned, Clone, Debug);

    fn setup_group(n: usize) -> (Vec<Scalar>, Group<BCurve>) {
        let privs = (0..n)
            .map(|_| Scalar::rand(&mut thread_rng()))
            .collect::<Vec<_>>();

        let pubs: Vec<G1> = privs
            .iter()
            .map(|private| {
                let mut public = G1::one();
                public.mul(private);
                public
            })
            .collect();

        (privs, pubs.into())
    }

    fn reconstruct<C: Curve>(
        thr: usize,
        shares: &[DKGOutput<C>],
    ) -> Result<PrivatePoly<C>, PolyError> {
        let evals: Vec<_> = shares
            .iter()
            .map(|o| Eval {
                value: o.share.private.clone(),
                index: o.share.index,
            })
            .collect();
        Poly::<C::Scalar>::full_recover(thr, evals)
    }

    #[test]
    fn group_index() {
        let n = 6;
        let (privs, group) = setup_group(n);
        for (i, private) in privs.iter().enumerate() {
            let mut public = G1::one();
            public.mul(&private);
            let idx = group.index(&public).expect("should find public key");
            assert_eq!(idx, i as Idx);
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

        // Step 1. evaluate polynomial, encrypt shares and broadcast
        let mut all_shares = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, shares) = dkg.encrypt_shares(&mut thread_rng()).unwrap();
                all_shares.push(shares);
                ndkg
            })
            .collect();

        // Step 2. verify the received shares (there should be no complaints)
        let response_bundles = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares).unwrap();
                assert!(
                    bundle_o.is_none(),
                    "full dkg should not have any complaints"
                );
                ndkg
            })
            .collect();

        // Step 3. get the responses
        let outputs = dkgs
            .into_iter()
            .map(|dkg| dkg.process_responses(&response_bundles).unwrap())
            .collect::<Vec<_>>();

        // Reconstruct the threshold private polynomial from all the outputs
        let recovered_private = reconstruct(thr, &outputs).unwrap();
        // Get the threshold public key from the private polynomial
        let recovered_public = recovered_private.commit::<G1>();
        let recovered_key = recovered_public.public_key();

        // it matches with the outputs of each DKG participant, even though they
        // do not have access to the threshold private key
        for out in outputs {
            assert_eq!(out.public.public_key(), recovered_key);
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
                let (ndkg, shares) = dkg.encrypt_shares(&mut thread_rng()).unwrap();
                all_shares.push(shares);
                ndkg
            })
            .collect();

        // modify a share
        all_shares[0].shares[1].secret = ecies::encrypt(&BCurve::point(), &[1], &mut thread_rng());
        all_shares[3].shares[4].secret = ecies::encrypt(&BCurve::point(), &[1], &mut thread_rng());

        let mut response_bundles = Vec::with_capacity(2);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares).unwrap();
                if let Some(bundle) = bundle_o {
                    response_bundles.push(bundle);
                }
                ndkg
            })
            .collect();

        // there should be exactly 2 complaints, one for each bad share where decryption failed
        assert_eq!(response_bundles.len(), 2);

        let mut justifications = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                let (ndkg, justifs) = dkg.process_responses(&response_bundles).unwrap_err();
                if let Some(j) = justifs {
                    justifications.push(j);
                }
                ndkg
            })
            .collect();

        // both participants whose encryptiosn were tampered with revealed their shares,
        // so there should be exactly 2 justifications
        assert_eq!(justifications.len(), 2);

        // ...and the DKG finishes correctly as expected
        let outputs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| dkg.process_justifications(&justifications).unwrap())
            .collect();

        let recovered_private = reconstruct(thr, &outputs).unwrap();
        let recovered_public = recovered_private.commit::<G1>();
        let recovered_key = recovered_public.public_key();
        for out in outputs.iter() {
            let public = &out.public;
            assert_eq!(public.public_key(), recovered_key);
        }
    }
}
