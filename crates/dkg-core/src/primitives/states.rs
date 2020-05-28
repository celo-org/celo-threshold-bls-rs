use super::{
    group::Group,
    status::{Status, StatusMatrix},
    DKGError, DKGResult, ShareError,
};

use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use threshold_bls::{
    ecies::{self, EciesCipher},
    group::{Curve, Element},
    poly::{Eval, Idx, Poly, PrivatePoly, PublicPoly},
    sig::Share,
};

use std::cell::RefCell;

pub trait Phase0<C: Curve>: Clone + Debug + Serialize + for<'a> Deserialize<'a> {
    type Next: Phase1<C>;

    fn encrypt_shares<R: RngCore>(self, rng: &mut R) -> DKGResult<(Self::Next, BundledShares<C>)>;
}

pub trait Phase1<C: Curve>: Clone + Debug + Serialize + for<'a> Deserialize<'a> {
    type Next: Phase2<C>;
    fn process_shares(
        self,
        bundles: &[BundledShares<C>],
        publish_all: bool,
    ) -> DKGResult<(Self::Next, Option<BundledResponses>)>;
}

pub trait Phase2<C: Curve>: Clone + Debug + Serialize + for<'a> Deserialize<'a> {
    type Next: Phase3<C>;
    fn process_responses(
        self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, DKGResult<(Self::Next, Option<BundledJustification<C>>)>>;
}

pub trait Phase3<C: Curve>: Debug {
    fn process_justifications(
        self,
        justifs: &[BundledJustification<C>],
    ) -> Result<DKGOutput<C>, DKGError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
struct DKGInfo<C: Curve> {
    private_key: C::Scalar,
    public_key: C::Point,
    index: Idx,
    group: Group<C>,
    secret: Poly<C::Scalar>,
    public: Poly<C::Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
struct ReshareInfo<C: Curve> {
    private_key: C::Scalar,
    public_key: C::Point,
    // our previous index in the group - it can be none if we are a new member
    prev_index: Option<Idx>,
    // previous group on which to reshare
    prev_group: Group<C>,
    // previous group distributed public polynomial
    prev_public: Poly<C::Point>,
    // secret and public polynomial of a dealer
    secret: Option<Poly<C::Scalar>>,
    public: Option<Poly<C::Point>>,

    // our new index in the group - it can be none if we are a leaving member
    new_index: Option<Idx>,
    // new group that is receiving the refreshed shares
    new_group: Group<C>,
}

impl<C: Curve> ReshareInfo<C> {
    fn is_dealer(&self) -> bool {
        self.prev_index.is_some()
    }
    fn is_share_holder(&self) -> bool {
        self.new_index.is_some()
    }

    fn new_n(&self) -> usize {
        self.new_group.len()
    }

    fn old_n(&self) -> usize {
        self.prev_group.len()
    }

    fn new_thr(&self) -> usize {
        self.new_group.threshold
    }

    fn old_thr(&self) -> usize {
        self.prev_group.threshold
    }
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

/// RDKG is the struct containing the logic to run the resharing scheme from
/// Desmedt et al.
/// ([paper](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.55.2968&rep=rep1&type=pdf)).
/// The protoocol has the same phases of the DKG but requires additional checks
/// to verify the resharing is performed correctly. The resharing scheme runs
/// between two potentially distinct groups: the dealers (nodes that already
/// have a share, that ran a DKG previously) and the share holders (nodes that
/// receives a refreshed share of the same secret).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct RDKG<C: Curve> {
    info: ReshareInfo<C>,
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

impl<C: Curve> RDKG<C> {
    pub(crate) fn new_from_share<R: RngCore>(
        private_key: C::Scalar,
        curr_share: DKGOutput<C>,
        new_group: Group<C>,
        rng: &mut R,
    ) -> Result<RDKG<C>, DKGError> {
        let oldi = Some(curr_share.share.index);
        let prev_group = curr_share.qual;
        let prev_public = curr_share.public;
        // generate a secret polynomial with the share being the free
        // coefficient
        let mut secret = PrivatePoly::<C>::new_from(new_group.threshold - 1, rng);
        secret.set(0, curr_share.share.private);
        let public = secret.commit::<C::Point>();
        let mut pubkey = C::point();
        pubkey.mul(&private_key);
        let new_idx = new_group.index(&pubkey);
        let info = ReshareInfo {
            private_key: private_key,
            public_key: pubkey,
            prev_index: oldi,
            prev_group: prev_group,
            prev_public: prev_public,
            secret: Some(secret),
            public: Some(public),
            new_index: new_idx,
            new_group: new_group,
        };
        Ok(RDKG { info: info })
    }

    pub(crate) fn new_member(
        private_key: C::Scalar,
        curr_group: Group<C>,
        curr_public: PublicPoly<C>,
        new_group: Group<C>,
    ) -> Result<RDKG<C>, DKGError> {
        let mut pubkey = C::point();
        pubkey.mul(&private_key);
        let new_idx = new_group.index(&pubkey);
        let info = ReshareInfo {
            private_key: private_key,
            public_key: pubkey,
            prev_index: None,
            prev_group: curr_group,
            prev_public: curr_public,
            secret: None,
            public: None,
            new_index: new_idx,
            new_group: new_group,
        };
        Ok(RDKG { info: info })
    }
}

impl<C: Curve> Phase0<C> for RDKG<C> {
    type Next = RDKGWaitingShare<C>;
    fn encrypt_shares<R: RngCore>(
        self,
        rng: &mut R,
    ) -> DKGResult<(RDKGWaitingShare<C>, BundledShares<C>)> {
        if !self.info.is_dealer() {
            return Err(DKGError::NotDealer);
        }
        let info = self.info;
        let public = info.public.unwrap();
        let secret = info.secret.unwrap();
        let bundle = create_share_bundle(
            info.prev_index.unwrap(),
            &secret,
            &public,
            &info.prev_group,
            rng,
        )?;
        let dw = RDKGWaitingShare {
            info: ReshareInfo {
                public: Some(public),
                secret: Some(secret),
                ..info
            },
        };
        Ok((dw, bundle))
    }
}

impl<C: Curve> DKG<C> {
    /// Creates a new DKG instance from the provided private key and group.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub(crate) fn new(private_key: C::Scalar, group: Group<C>) -> Result<DKG<C>, DKGError> {
        use rand::prelude::*;
        Self::new_rand(private_key, group, &mut thread_rng())
    }

    /// Creates a new DKG instance from the provided private key, group and RNG.
    ///
    /// The private key must be part of the group, otherwise this will return an error.
    pub(crate) fn new_rand<R: RngCore>(
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
            public_key,
            index,
            group,
            secret,
            public,
        };

        Ok(DKG { info })
    }
}

impl<C: Curve> Phase0<C> for DKG<C> {
    type Next = DKGWaitingShare<C>;
    /// Evaluates the secret polynomial at the index of each DKG participant and encrypts
    /// the result with the corresponding public key. Returns the bundled encrypted shares
    /// as well as the next phase of the DKG.
    fn encrypt_shares<R: RngCore>(
        self,
        rng: &mut R,
    ) -> DKGResult<(DKGWaitingShare<C>, BundledShares<C>)> {
        let bundle = create_share_bundle(
            self.info.index,
            &self.info.secret,
            &self.info.public,
            &self.info.group,
            rng,
        )?;
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

/// A `BundledResponses` is sent during the second phase of the protocol by all
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
/// Resharing stage which waits to receive the shares from the previous phase's
/// participants as input. After processing the share, if there were any
/// complaints, it will generate a bundle of responses for the next phase.
pub struct RDKGWaitingShare<C: Curve> {
    info: ReshareInfo<C>,
}

impl<C: Curve> Phase1<C> for RDKGWaitingShare<C> {
    type Next = RDKGWaitingResponse<C>;
    fn process_shares(
        self,
        bundles: &[BundledShares<C>],
        publish_all: bool,
    ) -> DKGResult<(RDKGWaitingResponse<C>, Option<BundledResponses>)> {
        if !self.info.is_share_holder() {
            return Ok((
                RDKGWaitingResponse {
                    statuses: StatusMatrix::new(
                        self.info.prev_group.len(),
                        self.info.new_group.len(),
                        Status::Success,
                    ),
                    info: self.info,
                    shares: ShareInfo::<C>::new(),
                    publics: PublicInfo::<C>::new(),
                },
                None,
            ));
        }

        let my_idx = self.info.new_index.unwrap();
        let (mut shares, mut publics, mut statuses) = process_shares_get_all(
            &self.info.prev_group,
            &self.info.new_group,
            my_idx,
            &self.info.private_key,
            bundles,
        )?;

        bundles
            .iter()
            // this bundle was invalid for some reason
            .filter(|b| publics.contains_key(&b.dealer_idx))
            // only keep the ones that don't respect the rules to remove them
            // from the list of valid shares and put their status to complaint
            .filter(|b| {
                !check_public_resharing::<C>(b.dealer_idx, &b.public, &self.info.prev_public)
            })
            .for_each(|b| {
                shares.remove(&b.dealer_idx);
                for n in &self.info.new_group.nodes {
                    statuses.set(b.dealer_idx, n.id(), Status::Complaint);
                }
            });

        let mut info = self.info;
        {
            let public = info.public.take().unwrap();
            let secret = info.secret.take().unwrap();
            if info.is_dealer() {
                // we register our own share and publics into the mix
                let didx = info.prev_index.unwrap();
                shares.insert(didx, secret.eval(didx).value);
                publics.insert(didx, public.clone());
                // we treat our own share as valid!
                statuses.set(didx, my_idx, Status::Success);
            }
            info.public = Some(public);
            info.secret = Some(secret);
        }

        // we need at least a threshold of dealers to share their share to be
        // able to reconstruct a share of the same distributed private key.
        if shares.len() < info.prev_group.threshold {
            return Err(DKGError::NotEnoughValidShares(
                shares.len(),
                info.prev_group.threshold,
            ));
        }

        let bundle = compute_bundle_response(my_idx, &statuses, publish_all);
        let new_dkg = RDKGWaitingResponse {
            info: info,
            shares: shares,
            publics: publics,
            statuses: statuses,
        };
        Ok((new_dkg, bundle))
    }
}

impl<C: Curve> Phase1<C> for DKGWaitingShare<C> {
    type Next = DKGWaitingResponse<C>;
    /// Tries to decrypt the provided shares and calculate the secret key and the
    /// threshold public key. If `publish_all` is set to true then the returned
    /// responses will include both complaints and successful statuses. Consider setting
    /// it to false when communication complexity is high.
    ///
    /// A complaint is returned in the following cases:
    /// - invalid dealer index
    /// - absentee shares for us
    /// - invalid encryption
    /// - invalid length of public polynomial
    /// - invalid share w.r.t. public polynomial
    fn process_shares(
        self,
        bundles: &[BundledShares<C>],
        publish_all: bool,
    ) -> DKGResult<(DKGWaitingResponse<C>, Option<BundledResponses>)> {
        let thr = self.info.thr();
        let my_idx = self.info.index;
        let (shares, publics, mut statuses) = process_shares_get_all(
            &self.info.group,
            &self.info.group,
            my_idx,
            &self.info.private_key,
            bundles,
        )?;

        // we check with `thr - 1` because we already have our shares
        if shares.len() < thr - 1 {
            // that means the threat model is not respected since there should
            // be at least a threshold of honest shares
            return Err(DKGError::NotEnoughValidShares(shares.len(), thr));
        }

        // The user's secret share is the sum of all received shares (remember:
        // each share is an evaluation of a participant's private polynomial at
        // our index)
        let mut fshare = self.info.secret.eval(self.info.index).value;
        // The public key polynomial is the sum of all shared polynomials
        let mut fpub = self.info.public.clone();
        shares.iter().for_each(|(&dealer_idx, share)| {
            fpub.add(&publics.get(&dealer_idx).unwrap());
            fshare.add(&share);
        });
        let bundle = compute_bundle_response(my_idx, &statuses, publish_all);
        let new_dkg = DKGWaitingResponse::new(self.info, fshare, fpub, statuses, publics);

        Ok((new_dkg, bundle))
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
    publics: PublicInfo<C>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct RDKGWaitingResponse<C: Curve> {
    info: ReshareInfo<C>,
    shares: ShareInfo<C>,
    publics: PublicInfo<C>,
    statuses: StatusMatrix,
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
        publics: PublicInfo<C>,
    ) -> Self {
        Self {
            info,
            dist_share,
            dist_pub,
            statuses,
            publics,
        }
    }
}

impl<C: Curve> Phase2<C> for RDKGWaitingResponse<C> {
    type Next = RDKGWaitingJustification<C>;
    #[allow(clippy::type_complexity)]
    /// Checks if the responses when applied to the status matrix result in a
    /// matrix with only `Success` elements. If so, the protocol terminates.
    ///
    /// If there are complaints in the Status matrix, then it will return an
    /// error with the justifications required for Phase 3 of the DKG.
    fn process_responses(
        self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, DKGResult<(Self::Next, Option<BundledJustification<C>>)>> {
        if !self.info.is_share_holder() {
            // we just silently pass
            let dkg = RDKGWaitingJustification {
                info: self.info,
                shares: self.shares,
                statuses: RefCell::new(self.statuses),
                publics: self.publics,
            };
            return Err(Ok((dkg, None)));
        }

        let info = self.info;
        let mut statuses = self.statuses;
        set_statuses(
            info.new_index.unwrap(),
            &info.prev_group,
            &info.new_group,
            &mut statuses,
            responses,
        );

        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let justifications_required = info
            .prev_group
            .nodes
            .iter()
            .any(|n| !statuses.all_true(n.id()));

        if justifications_required {
            let public = info.public.unwrap();
            let secret = info.secret.unwrap();
            let bundled_justifications =
                get_justification(info.prev_index.unwrap(), &secret, &public, &statuses);
            let dkg = RDKGWaitingJustification {
                info: ReshareInfo {
                    public: Some(public),
                    secret: Some(secret),
                    ..info
                },
                shares: self.shares,
                statuses: RefCell::new(statuses),
                publics: self.publics,
            };
            return Err(Ok((dkg, bundled_justifications)));
        }
        // in case of error here, the protocol must be aborted
        compute_resharing_output(info, self.shares, self.publics, RefCell::new(statuses))
            .map_err(|e| Err(e))
    }
}

impl<C: Curve> Phase2<C> for DKGWaitingResponse<C> {
    type Next = DKGWaitingJustification<C>;
    #[allow(clippy::type_complexity)]
    /// Checks if the responses when applied to the status matrix result in a
    /// matrix with only `Success` elements. If so, the protocol terminates.
    ///
    /// If there are complaints in the Status matrix, then it will return an
    /// error with the justifications required for Phase 3 of the DKG.
    fn process_responses(
        self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, DKGResult<(Self::Next, Option<BundledJustification<C>>)>> {
        let info = self.info;
        let mut statuses = self.statuses;
        set_statuses(
            info.index,
            &info.group,
            &info.group,
            &mut statuses,
            responses,
        );

        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let justifications_required = info.group.nodes.iter().any(|n| !statuses.all_true(n.id()));

        if justifications_required {
            let bundled_justifications =
                get_justification(info.index, &info.secret, &info.public, &statuses);
            let dkg = DKGWaitingJustification {
                info: info,
                dist_share: self.dist_share,
                dist_pub: self.dist_pub,
                statuses: RefCell::new(statuses),
                publics: self.publics,
            };

            return Err(Ok((dkg, bundled_justifications)));
        }

        // bingo ! Returns the final share now and stop the protocol
        let share = Share {
            index: info.index,
            private: self.dist_share,
        };

        Ok(DKGOutput {
            // everybody is qualified in this case since there is no
            // complaint at all
            qual: info.group.clone(),
            public: self.dist_pub,
            share,
        })
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct RDKGWaitingJustification<C: Curve> {
    info: ReshareInfo<C>,
    shares: ShareInfo<C>,
    publics: PublicInfo<C>,
    // guaranteed to be of the right size (n)
    statuses: RefCell<StatusMatrix>,
}

impl<C> Phase3<C> for DKGWaitingJustification<C>
where
    C: Curve,
{
    /// Accept a justification if the following conditions are true:
    /// - bundle's dealer index is in range
    /// - a justification was required for the given share (no-op)
    /// - share corresponds to public polynomial received in the bundled shares during
    /// first period.
    /// Return an output if `len(qual) > thr`
    fn process_justifications(
        self,
        justifs: &[BundledJustification<C>],
    ) -> Result<DKGOutput<C>, DKGError> {
        // Calculate the share and public polynomial from the provided justifications
        // (they will later be added to our existing share and public polynomial)
        let mut add_share = C::Scalar::zero();
        let mut add_public = PublicPoly::<C>::zero();
        let valid_shares = internal_process_justifications(
            self.info.index,
            &self.info.group,
            &mut self.statuses.borrow_mut(),
            &self.publics,
            justifs,
        );

        for (idx, share) in &valid_shares {
            add_share.add(&share);
            // unwrap since internal_process_justi. gauarantees each share comes
            // from a public polynomial we've seen in the first round.
            add_public.add(&self.publics.get(idx).unwrap());
        }
        // QUAL is the set of all entries in the matrix where all bits are set
        let statuses = self.statuses.borrow();
        let qual_indices = (0..self.info.n())
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

impl<C> Phase3<C> for RDKGWaitingJustification<C>
where
    C: Curve,
{
    /// Accept a justification if the following conditions are true:
    /// - bundle's dealer index is in range
    /// - a justification was required for the given share (no-op)
    /// - share corresponds to public polynomial received in the bundled shares during
    /// first period.
    /// Return an output if `len(qual) > thr`
    fn process_justifications(
        self,
        justifs: &[BundledJustification<C>],
    ) -> DKGResult<DKGOutput<C>> {
        if !self.info.is_share_holder() {
            return Err(DKGError::NotShareHolder);
        }
        let mut valid_shares = internal_process_justifications(
            self.info.new_index.unwrap(),
            &self.info.prev_group,
            &mut self.statuses.borrow_mut(),
            &self.publics,
            justifs,
        );

        let info = self.info;
        let publics = self.publics;
        let shares = self.shares;
        let mut statuses = self.statuses;
        justifs
            .iter()
            // this bundle was already invalid for some reason
            .filter(|b| publics.contains_key(&b.dealer_idx))
            // only keep the ones that don't respect the rules to remove them
            // from the list of valid shares and put their status to complaint
            .filter(|b| !check_public_resharing::<C>(b.dealer_idx, &b.public, &info.prev_public))
            .for_each(|b| {
                // we remove the shares coming from invalid justification
                valid_shares.remove(&b.dealer_idx);
                for n in &info.new_group.nodes {
                    statuses
                        .borrow_mut()
                        .set(b.dealer_idx, n.id(), Status::Complaint);
                }
            });

        compute_resharing_output(
            info,
            valid_shares.into_iter().chain(shares).collect(),
            publics,
            statuses,
        )
    }
}

fn decrypt_and_check_share<C: Curve>(
    private_key: &C::Scalar,
    own_idx: Idx,
    dealer_idx: Idx,
    public: &PublicPoly<C>,
    share: &EncryptedShare<C>,
) -> Result<C::Scalar, DKGError> {
    let buff = ecies::decrypt::<C>(private_key, &share.secret)
        .map_err(|err| ShareError::InvalidCiphertext(dealer_idx, err))?;

    let clear_share: C::Scalar = bincode::deserialize(&buff)?;

    if !share_correct::<C>(own_idx, &clear_share, public) {
        return Err(ShareError::InvalidShare(dealer_idx).into());
    }

    Ok(clear_share)
}

/// set_statuses set the status of the given responses on the status matrix.
fn set_statuses<C: Curve>(
    holder_idx: Idx,
    dealers: &Group<C>,
    holders: &Group<C>,
    statuses: &mut StatusMatrix,
    responses: &[BundledResponses],
) {
    // makes sure the API doesn't take into account our own responses!
    let not_from_me = responses.iter().filter(|r| r.share_idx != holder_idx);
    let valid_idx = not_from_me.filter(|r| {
        let good_holder = holders.contains_index(r.share_idx);
        let good_dealers = !r
            .responses
            .iter()
            .any(|resp| !dealers.contains_index(resp.dealer_idx));
        good_dealers && good_holder
    });

    for bundle in valid_idx {
        let holder_index = bundle.share_idx;
        for response in bundle.responses.iter() {
            let dealer_index = response.dealer_idx;
            statuses.set(dealer_index, holder_index, response.status);
        }
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

/// Creates the encrypted shares with the given secret polynomial to the given
/// group.
fn create_share_bundle<C: Curve, R: RngCore>(
    dealer_idx: Idx,
    secret: &PrivatePoly<C>,
    public: &PublicPoly<C>,
    group: &Group<C>,
    rng: &mut R,
) -> DKGResult<BundledShares<C>> {
    let shares = group
        .nodes
        .iter()
        .map(|n| {
            // evaluate the secret polynomial at the node's id
            let sec = secret.eval(n.id() as Idx);

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
    Ok(BundledShares {
        dealer_idx: dealer_idx,
        shares,
        public: public.clone(),
    })
}

// extract_poly maps the bundles into a map: Idx -> public poly for ease of
// use later on
fn extract_poly<C: Curve>(degree: usize, bundles: &[BundledShares<C>]) -> PublicInfo<C> {
    // TODO avoid cloning by using lifetime or better gestin in
    // process_shares
    bundles
        .iter()
        .filter(|b| b.public.degree() == degree)
        .fold(HashMap::new(), |mut acc, b| {
            acc.insert(b.dealer_idx, b.public.clone());
            acc
        })
}

fn compute_bundle_response(
    my_idx: Idx,
    statuses: &StatusMatrix,
    publish_all: bool,
) -> Option<BundledResponses> {
    let responses = statuses
        .get_for_share(my_idx)
        .into_iter()
        .enumerate()
        .map(|(i, b)| Response {
            dealer_idx: i as Idx,
            status: Status::from(b),
        });

    let responses = if !publish_all {
        // only get the complaints
        responses
            .filter(|r| !r.status.is_success())
            .collect::<Vec<_>>()
    } else {
        responses.collect::<Vec<_>>()
    };

    if !responses.is_empty() {
        Some(BundledResponses {
            responses,
            share_idx: my_idx,
        })
    } else {
        None
    }
}

type ShareInfo<C: Curve> = HashMap<Idx, C::Scalar>;
type PublicInfo<C: Curve> = HashMap<Idx, PublicPoly<C>>;

/// Processes the shares and returns the private share of the user and a public
/// polynomial, as well as the status matrix of the protocol.
///
/// Depending on which variant of the DKG protocol is used, the status
/// matrix responses which correspond to our index may be used in the
/// following way:
///
/// - All responses get broadcast: You assume that shares of other nodes are
/// not good unless you hear otherwise.  - Broadcast only responses which
/// are complaints: You assume that shares of other nodes are good unless
/// you hear otherwise.
fn process_shares_get_all<C: Curve>(
    dealers: &Group<C>,
    share_holders: &Group<C>,
    my_idx: Idx,
    my_private: &C::Scalar,
    bundles: &[BundledShares<C>],
) -> DKGResult<(ShareInfo<C>, PublicInfo<C>, StatusMatrix)> {
    // there are "old_n" dealers and for each dealer, "new_n" share holders
    let mut statuses = StatusMatrix::new(dealers.len(), share_holders.len(), Status::Success);

    // set by default all the shares we could receive as complaint - that puts
    // us on the conservative side of only explicitely allowing correct shares.
    (0..dealers.len())
        .filter(|&dealer_idx| dealer_idx != my_idx as usize)
        .for_each(|dealer_idx| {
            statuses.set(dealer_idx as Idx, my_idx, Status::Complaint);
        });

    let mut publics = PublicInfo::<C>::new();
    let valid_shares = bundles
        .iter()
        // check the ones that are not from us
        .filter(|b| b.dealer_idx != my_idx)
        // check the ones with a valid dealer index
        .filter(|b| dealers.contains_index(b.dealer_idx))
        // only consider public polynomial of the right form
        .filter(|b| b.public.degree() == share_holders.threshold - 1)
        // save them for later
        .inspect(|b| {
            publics.insert(b.dealer_idx, b.public.clone());
        })
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
            decrypt_and_check_share(
                my_private,
                my_idx,
                bundle.dealer_idx,
                &bundle.public,
                encrypted_share,
            )
            .map(|share| (bundle.dealer_idx, share))
            .ok()
        })
        .fold(ShareInfo::<C>::new(), |mut acc, (didx, share)| {
            statuses.set(didx, my_idx, Status::Success);
            acc.insert(didx, share);
            acc
        });

    Ok((valid_shares, publics, statuses))
}

fn get_justification<C: Curve>(
    dealer_idx: Idx,
    secret: &PrivatePoly<C>,
    public: &PublicPoly<C>,
    statuses: &StatusMatrix,
) -> Option<BundledJustification<C>> {
    // If there were any complaints against our deal, then we should re-evaluate our
    // secret polynomial at the indexes where the complaints were, and publish these
    // as justifications (i.e. indicating that we are still behaving correctly).
    if !statuses.all_true(dealer_idx) {
        let justifications = statuses
            .get_for_dealer(dealer_idx)
            .iter()
            .enumerate()
            .filter_map(|(i, success)| {
                if !success {
                    // reveal the share
                    let id = i as Idx;
                    Some(Justification {
                        share_idx: id,
                        share: secret.eval(id).value,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Some(BundledJustification {
            dealer_idx: dealer_idx,
            justifications,
            public: public.clone(),
        })
    } else {
        None
    }
}

// returns the correct shares destined to the given holder index
fn internal_process_justifications<C: Curve>(
    holder_idx: Idx,
    dealers: &Group<C>,
    statuses: &mut StatusMatrix,
    publics: &PublicInfo<C>,
    justifs: &[BundledJustification<C>],
) -> ShareInfo<C> {
    let mut valid_shares = ShareInfo::<C>::new();
    justifs
        .iter()
        .filter(|b| dealers.contains_index(b.dealer_idx))
        // get only the bundles for which we have a public polynomial for
        // i.e. only justif for polynomials that have been broadcasted in the
        // first phase
        .filter_map(|b| publics.get(&b.dealer_idx).map(|public| (b, public)))
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
                    statuses.set(bundle.dealer_idx, justification.share_idx, Status::Success);
                    if holder_idx == justification.share_idx {
                        valid_shares.insert(bundle.dealer_idx, justification.share.clone());
                    }
                })
        });
    valid_shares
}

fn compute_resharing_output<C: Curve>(
    info: ReshareInfo<C>,
    shares: ShareInfo<C>,
    publics: PublicInfo<C>,
    statuses: RefCell<StatusMatrix>,
) -> DKGResult<DKGOutput<C>> {
    // to compute the final share, we interpolate all the valid shares received
    let mut shares_eval: Vec<Eval<C::Scalar>> = shares
        .into_iter()
        .map(|(idx, sh)| Eval {
            value: sh,
            index: idx,
        })
        .collect();

    // only take the first t shares sorted
    shares_eval.sort_by(|a, b| a.index.cmp(&b.index));
    let shares_indexes = shares_eval.iter().map(|e| e.index).collect::<Vec<Idx>>();
    let shortened_evals = shares_eval
        .into_iter()
        .take(info.prev_group.threshold)
        .collect::<Vec<Eval<C::Scalar>>>();

    let recovered_share = Poly::recover(info.prev_group.threshold, shortened_evals)
        .map_err(DKGError::InvalidRecovery)?;
    // recover public polynomial by interpolating coefficient-wise all
    // polynomials. the new public polynomial have "newT"
    // coefficients
    let recovered_public: PublicPoly<C> = (0..info.new_group.threshold)
        .map(|cidx| {
            // interpolate the cidx coefficient of the final public polynomial
            let mut to_recover = shares_indexes
                .iter()
                .map(|sh_idx| {
                    match publics.get(sh_idx) {
                        Some(poly) => Eval {
                            // value is the cidx coefficient of that dealer's public
                            // poly
                            value: poly.get(cidx as Idx),
                            // the index is the index from the dealer
                            index: *sh_idx,
                        },
                        None => panic!("BUG: public polynomial evaluating failed"),
                    }
                })
                .collect::<Vec<_>>();

            // recover the cidx coefficient of the final public polynomial
            Poly::recover(info.prev_group.threshold, to_recover).map_err(DKGError::InvalidRecovery)
        })
        .collect::<Result<Vec<C::Point>, DKGError>>()?
        .into();
    // To compute the QUAL in the resharing case, we take each new nodes whose
    // column in the status matrix contains true for all valid dealers.
    let qual = info
        .new_group
        .nodes
        .into_iter()
        .filter(|node| {
            shares_indexes
                .iter()
                .all(|&sidx| statuses.borrow().get(sidx, node.id()).is_success())
        })
        .collect::<Vec<_>>();

    let qual_group = Group::<C>::new(qual, info.new_group.threshold)?;
    Ok(DKGOutput {
        qual: qual_group,
        public: recovered_public,
        share: Share {
            index: info.new_index.unwrap(),
            private: recovered_share,
        },
    })
}

struct PublicDeal<C: Curve> {
    dealer_idx: Idx,
    public: PublicPoly<C>,
}
// we verify that the public polynomial is created with the public
// share of the dealer,i.e. it's actually a resharing
// if it returns false, we must set the dealer's shares as being complaint, all
// of them since he is not respecting the protocol
fn check_public_resharing<C: Curve>(
    dealer_idx: Idx,
    deal_poly: &PublicPoly<C>,
    group_poly: &PublicPoly<C>,
) -> bool {
    // evaluation of the public key the dealer gives us which should be
    // the commitment of its current share
    let givenPoint = deal_poly.public_key();
    // computing the current share commitment of the dealer
    let expPoint = &group_poly.eval(dealer_idx).value;
    expPoint == givenPoint
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
    fn test_full_dkg() {
        let n = 5;
        let thr = default_threshold(n);
        let (privs, group) = setup_group(n);
        let dkgs = privs
            .into_iter()
            .map(|p| DKG::new(p, group.clone()).unwrap())
            .collect::<Vec<_>>();
        full_dkg(thr, dkgs);
    }

    #[test]
    fn test_full_resharing() {
        let n = 5;
        let thr = default_threshold(n);
        let (privs, group) = setup_group(n);
        // simulate shares
        let private_poly = Poly::<Scalar>::new_from(group.threshold - 1, &mut thread_rng());
        let shares = group
            .nodes
            .iter()
            .map(|n| private_poly.eval(n.id()))
            .collect::<Vec<_>>();
        let public_poly = private_poly.commit::<G1>();
        let dkgs = privs
            .into_iter()
            .zip(shares.into_iter())
            .map(|(p, sh)| {
                let out = DKGOutput {
                    share: Share {
                        index: sh.index,
                        private: sh.value,
                    },
                    public: public_poly.clone(),
                    qual: group.clone(),
                };
                RDKG::new_from_share(p, out, group.clone(), &mut thread_rng()).unwrap()
            })
            .collect::<Vec<_>>();
        let reshared = full_dkg(thr, dkgs);
        // test that it gives the same public key
        assert_eq!(public_poly.public_key(), reshared.public_key());
    }

    fn full_dkg<C, P>(nthr: usize, dkgs: Vec<P>) -> PublicPoly<C>
    where
        C: Curve,
        P: Phase0<C>,
    {
        let n = dkgs.len();

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
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares, false).unwrap();
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
            .map(|dkg| dkg.process_responses(&response_bundles).expect("wholo"))
            .collect::<Vec<_>>();

        // Reconstruct the threshold private polynomial from all the outputs
        let recovered_private = reconstruct(nthr, &outputs).unwrap();
        // Get the threshold public key from the private polynomial
        let recovered_public = recovered_private.commit::<C::Point>();
        // let mut recovered_public = G1::one();
        // recovered_public.mul(&recovered_private);
        let recovered_key = recovered_public.public_key();

        // it matches with the outputs of each DKG participant, even though they
        // do not have access to the threshold private key
        for out in outputs {
            //println!("out.publickey(): {:?}", out.public.public_key());
            assert_eq!(out.public.public_key(), recovered_key);
        }
        recovered_public
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
                let (ndkg, bundle_o) = dkg.process_shares(&all_shares, false).unwrap();
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
            .map(|dkg| match dkg.process_responses(&response_bundles) {
                Ok(output) => panic!("dkg shouldn't have finished"),
                Err(next) => match next {
                    Ok((ndkg, justifs)) => {
                        if let Some(j) = justifs {
                            justifications.push(j);
                        }
                        ndkg
                    }
                    Err(e) => panic!(e),
                },
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
