use crate::ecies::{self, EciesCipher};
use crate::group::{Curve, Element, Encodable};
use crate::poly::{Idx, InvalidRecovery, Poly, PrivatePoly, PublicPoly};
use crate::{Public, Share};
use rand_core::RngCore;
use smallbitvec::SmallBitVec;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Node is a participant in the DKG protocol. In a DKG protocol, each
/// participant must be identified both by an index and a public key. At the end
/// of the protocol, if sucessful, the index is used to verify the validity of
/// the share this node holds.
pub struct Node<C: Curve>(ID, C::Point);

impl<C> Node<C>
where
    C: Curve,
{
    pub fn new(index: ID, public: C::Point) -> Self {
        Self(index, public)
    }
}

/// A Group is a collection of Nodes with an associated threshold. A DKG scheme
/// takes in a group at the beginning of the protocol and outputs a potentially
/// new group that contains members that succesfully ran the protocol. When
/// creating a new group using the `from()` or `from_list()`method, the module
/// sets the threshold to the output of `default_threshold()`.
#[derive(Debug)]
pub struct Group<C: Curve> {
    pub nodes: Vec<Node<C>>,
    pub threshold: usize,
}

type ID = Idx;
// type alias for readability.
type Bitset = SmallBitVec;

// TODO
// - check VSS-forgery article
// - zeroise

impl<C> fmt::Debug for Node<C>
where
    C: Curve,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node{{{} -> {:?} }}", self.0, self.1)
    }
}

impl<C> Clone for Node<C>
where
    C: Curve,
{
    fn clone(&self) -> Self {
        Node(self.0, self.1.clone())
    }
}

impl<C> Node<C>
where
    C: Curve,
{
    pub fn id(&self) -> ID {
        self.0
    }
    pub fn key(&self) -> &C::Point {
        &self.1
    }
}

impl<C> Clone for Group<C>
where
    C: Curve,
{
    // because of https://stackoverflow.com/questions/37765586/why-does-cloning-my-custom-type-result-in-t-instead-of-t
    fn clone(&self) -> Self {
        Group {
            nodes: self.nodes.clone(),
            threshold: self.threshold,
        }
    }
}

impl<C> Group<C>
where
    C: Curve,
{
    pub fn from_list(nodes: Vec<Node<C>>) -> Group<C> {
        let l = nodes.len();
        Self {
            nodes: nodes,
            threshold: default_threshold(l),
        }
    }
    pub fn new(nodes: Vec<Node<C>>, threshold: usize) -> DKGResult<Group<C>> {
        let minimum = minimum_threshold(nodes.len());
        let maximum = nodes.len();
        if threshold < minimum || threshold > maximum {
            return Err(DKGError::InvalidThreshold(threshold, minimum, maximum));
        }
        Ok(Self { nodes, threshold })
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn index(&self, public: &C::Point) -> Option<ID> {
        match self.nodes.iter().find(|n| &n.1 == public) {
            Some(n) => Some(n.0),
            _ => None,
        }
    }
}

impl<C> From<Vec<C::Point>> for Group<C>
where
    C: Curve,
{
    fn from(list: Vec<C::Point>) -> Self {
        let thr = default_threshold(list.len());
        // TODO check if we can do stg like .map(Node::new)
        let nodes = list
            .into_iter()
            .enumerate()
            .map(|(i, public)| Node(i as ID, public))
            .collect();
        Self::new(nodes, thr).expect("threshold should be good here")
    }
}

struct DKGInfo<C: Curve> {
    private_key: C::Scalar,
    index: ID,
    group: Group<C>,
    secret: Poly<C::Scalar, C::Scalar>,
    public: Poly<C::Scalar, C::Point>,
}

impl<C> DKGInfo<C>
where
    C: Curve,
{
    fn n(&self) -> usize {
        self.group.len()
    }
    fn thr(&self) -> usize {
        self.group.threshold
    }
}

/// DKG is the struct containing the logic to run the Distributed Key Generation
/// protocol from
/// [Pedersen](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_21.pdf).
/// The protocol runs at minimum in two phases and at most in three phases as
/// described in the module documentation. Each transition to a new phase is
/// consuming the DKG state (struct) to produce a new state that only accepts to
/// transition to the next phase.
pub struct DKG<C: Curve> {
    info: DKGInfo<C>,
}

/// EncryptedShare holds the ECIES encryption of a share destined to the
/// `share_idx`-th participant. When receiving the share, if the participant has
/// the same specified index, the corresponding dkg state decrypts the share using
/// the participant's private key.
pub struct EncryptedShare<C: Curve> {
    share_idx: ID,
    secret: EciesCipher<C>,
}

impl<C> Clone for EncryptedShare<C>
where
    C: Curve,
{
    fn clone(&self) -> Self {
        EncryptedShare {
            share_idx: self.share_idx,
            secret: self.secret.clone(),
        }
    }
}

/// BundledShares holds all encrypted shares a dealer creates during the first
/// phase of the protocol.
pub struct BundledShares<C: Curve> {
    pub dealer_idx: ID,
    pub shares: Vec<EncryptedShare<C>>,
    /// public is the commitment of the secret polynomial
    /// created by the dealer. In the context of using a blockchain as a
    /// broadcast channel, it can be posted only once.
    pub public: PublicPoly<C>,
}

impl<C> Clone for BundledShares<C>
where
    C: Curve,
{
    fn clone(&self) -> Self {
        BundledShares {
            dealer_idx: self.dealer_idx,
            shares: self.shares.clone(),
            public: self.public.clone(),
        }
    }
}

/// DKGOutput is the final output of the DKG protocol in case it runs
/// successfully. It contains the QUALified group (the list of nodes that
/// sucessfully ran the protocol until the end), the distributed public key and
/// the private share corresponding to the participant's index.
pub struct DKGOutput<C: Curve> {
    pub qual: Group<C>,
    pub public: Public<C>,
    pub share: Share<C::Scalar>,
}

/// A `Status` holds the claim of a validity or not of a share from the point of
/// a view of the share holder. A status is sent inside a `Response` during the
/// second phase of the protocol.
/// Currently, this protocol only outputs `Complaint` since that is how the protocol
/// is specified using a synchronous network with a broadcast channel. In
/// practice, that means any `Response` seen during the second phase is a
/// `Complaint` from a participant about one of its received share.
#[derive(Debug, Clone)]
pub enum Status {
    Success,
    Complaint,
}

impl From<bool> for Status {
    fn from(b: bool) -> Self {
        if b {
            Status::Success
        } else {
            Status::Complaint
        }
    }
}

impl Status {
    fn to_bool(&self) -> bool {
        self.is_success()
    }

    fn is_success(&self) -> bool {
        match self {
            Status::Success => true,
            Status::Complaint => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub dealer_idx: ID,
    pub status: Status,
}

/// A `BundledResponse` is sent during the second phase of the protocol by all
/// participants that have received invalid or inconsistent shares (all statuses
/// are `Complaint`). The bundles contains the index of the recipient of the
/// shares, the one that created the response.  Each `Response` contains the
/// index of the participant that created the share (a *dealer*),
#[derive(Debug, Clone)]
pub struct BundledResponses {
    /// share_idx is the index of the node that received the shares
    pub share_idx: ID,
    pub responses: Vec<Response>,
}

/// A `Justification` is
pub struct Justification<C: Curve> {
    share_idx: ID,
    share: C::Scalar,
}

pub struct BundledJustification<C: Curve> {
    pub dealer_idx: ID,
    pub justifications: Vec<Justification<C>>,
    pub public: PublicPoly<C>,
}

impl<C> DKG<C>
where
    C: Curve,
    C::Point: Encodable,
    C::Scalar: Encodable,
{
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
        match group.index(&public_key) {
            Some(idx) => {
                let secret = PrivatePoly::<C>::new_from(group.threshold - 1, rng);
                let public = secret.commit::<C::Point>();
                let info = DKGInfo {
                    private_key: private_key,
                    index: idx,
                    group: group,
                    secret: secret,
                    public: public,
                };
                Ok(DKG { info: info })
            }
            None => Err(DKGError::PublicKeyNotFound),
        }
    }

    pub fn shares(self) -> (DKGWaitingShare<C>, BundledShares<C>) {
        let shares = self
            .info
            .group
            .nodes
            .iter()
            .map(|n| {
                let sec = self.info.secret.eval(n.id() as Idx);
                let buff = sec.value.marshal();
                let cipher = ecies::encrypt::<C>(n.key(), &buff);
                EncryptedShare::<C> {
                    share_idx: n.id(),
                    secret: cipher,
                }
            })
            .collect();
        let bundle = BundledShares {
            dealer_idx: self.info.index,
            shares: shares,
            public: self.info.public.clone(),
        };
        let dw = DKGWaitingShare { info: self.info };
        (dw, bundle)
    }
}

pub struct DKGWaitingShare<C: Curve> {
    info: DKGInfo<C>,
}

impl<C> DKGWaitingShare<C>
where
    C: Curve,
    C::Scalar: Encodable,
    C::Point: Encodable,
{
    /// (a) Report complaint on invalid dealer index
    /// (b) Report complaint on absentee shares for us
    /// (c) Report complaint on invalid encryption
    /// (d) Report complaint on invalid length of public polynomial
    /// (e) Report complaint on invalid share w.r.t. public polynomial
    pub fn process_shares(
        self,
        bundles: &Vec<BundledShares<C>>,
    ) -> DKGResult<(DKGWaitingResponse<C>, BundledResponses)> {
        self.process_shares_get_complaint(bundles)
    }

    fn process_shares_get_complaint(
        self,
        bundles: &Vec<BundledShares<C>>,
    ) -> DKGResult<(DKGWaitingResponse<C>, BundledResponses)> {
        // true means we suppose every missing responses is a success at the end of
        // the period. Hence we only need to get & broadcast the complaints.
        // See DKGWaitingResponse::new for more information.
        let myidx = self.info.index.clone();
        let (newdkg, bundle) = self.process_shares_get_all(bundles)?;
        let complaints = bundle
            .responses
            .into_iter()
            .filter(|r| !r.status.is_success())
            .collect();
        Ok((
            newdkg,
            BundledResponses {
                responses: complaints,
                share_idx: myidx,
            },
        ))
    }

    // get_all exists to make the dkg impl. handle the case where we don't want
    // to wait until the end of the period to progress: if all inputs are
    // are valid, we can already broadcast "Success" responses. If all peers
    // receive all "Sucess" responses from everybody then the protocol can
    // short-circuit and directly finish.
    fn process_shares_get_all(
        self,
        bundles: &Vec<BundledShares<C>>,
    ) -> DKGResult<(DKGWaitingResponse<C>, BundledResponses)> {
        use Status::{Complaint, Success};
        let n = self.info.n();
        let thr = self.info.thr();
        let my_idx = self.info.index;
        // all responses are set to complaint by default
        let mut responses_bitset = Bitset::from_elem(n, Complaint.to_bool());
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
            let s = bundle.shares.iter().find(|s| s.share_idx == my_idx);
            if let None = s {
                // (b) reporting
                continue;
            }
            match self.try_share(bundle.dealer_idx, &bundle.public, s.unwrap()) {
                Ok(share) => ok.push((bundle.dealer_idx, &bundle.public, share)),
                Err(_) => {
                    // println! ...
                    // TODO find a way to report error, even though the function
                    // might return OK
                    // logger ?
                }
            }
        }
        // thr - 1 because I have my own shares
        if ok.len() < thr - 1 {
            return Err(DKGError::NotEnoughValidShares(ok.len(), thr));
        }

        // add shares and public polynomial together for all ok deal
        // and set our responses to success
        // we always include our own share and our own public poly
        let mut fshare = self.info.secret.eval(self.info.index).value;
        let mut fpub = self.info.public.clone();
        for bundle in ok {
            responses_bitset.set(bundle.0 as usize, Success.to_bool());
            fpub.add(&bundle.1);
            fshare.add(&bundle.2);
        }

        let responses: Vec<Response> = responses_bitset
            .iter()
            .enumerate()
            .map(|(i, b)| Response {
                dealer_idx: i as ID,
                status: Status::from(b),
            })
            .collect();
        let bundle = BundledResponses {
            share_idx: my_idx,
            responses: responses,
        };
        let new_dkg = DKGWaitingResponse::new(
            self.info,
            fshare,
            fpub,
            responses_bitset,
            public_polynomials,
        );
        Ok((new_dkg, bundle))
    }

    // extract_poly maps the bundles into a map: ID -> public poly for ease of
    // use later on
    fn extract_poly(bundles: &Vec<BundledShares<C>>) -> HashMap<ID, PublicPoly<C>> {
        // TODO avoid cloning by using lifetime or better gestin in
        // process_shares
        bundles.iter().fold(HashMap::new(), |mut acc, b| {
            acc.insert(b.dealer_idx, b.public.clone());
            acc
        })
    }
    fn try_share(
        &self,
        dealer: ID,
        public: &PublicPoly<C>,
        share: &EncryptedShare<C>,
    ) -> Result<C::Scalar, ShareError> {
        use ShareErrorType::*;
        let thr = self.info.thr();
        if public.degree() + 1 != thr {
            // report (d) error
            return Err(ShareError::from(
                dealer,
                InvalidPublicPolynomial(public.degree(), thr),
            ));
        }
        // TODO By implementing From<> should be able to use `?` notation
        let res = ecies::decrypt::<C>(&self.info.private_key, &share.secret);
        if res.is_err() {
            // report (c) error
            return Err(ShareError::from(
                dealer,
                InvalidCiphertext(res.unwrap_err()),
            ));
        }
        let buff = res.unwrap();
        let mut share = C::Scalar::new();
        share
            .unmarshal(&buff)
            // TODO verify that !!!
            .expect("scalar should not fail when unmarshaling");
        if !share_correct::<C>(self.info.index, &share, public) {
            return Err(ShareError::from(dealer, InvalidShare));
        }
        Ok(share)
    }
}

pub struct DKGWaitingResponse<C: Curve> {
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    own_responses: Bitset,
    default_resp: Status,
    publics: HashMap<ID, PublicPoly<C>>,
}

impl<C> DKGWaitingResponse<C>
where
    C: Curve,
{
    fn new(
        info: DKGInfo<C>,
        dist_share: C::Scalar,
        dist_pub: PublicPoly<C>,
        own: Bitset,
        publics: HashMap<ID, PublicPoly<C>>,
    ) -> Self {
        assert_eq!(own.len(), info.n());
        Self {
            info,
            dist_share,
            dist_pub,
            own_responses: own,
            // default_resp defines the capability of the protocol to finish
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
            default_resp: Status::Success,
            publics,
        }
    }

    /// Check:
    /// - no more than
    pub fn process_responses(
        self,
        responses: &Vec<BundledResponses>,
    ) -> Result<DKGOutput<C>, (DKGWaitingJustification<C>, Option<BundledJustification<C>>)> {
        let matrix = self.compute_statuses(responses);
        /*println!("Responses matrix for party {}", self.info.index);*/
        //for (i, row) in matrix.iter().enumerate() {
        //let row_str: String = row.iter().map(|b| if b { '1' } else { '0' }).collect();
        //println!("\t-party {} -> {}", i, row_str);
        /*}*/
        // find out if justifications are required
        // if there is a least one participant that issued one complaint
        let required = matrix.iter().any(|row| !row.all_true());

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
                share: share,
            });
        }

        // find out if some responses correspond to our deal
        let mut ret_justif: Option<BundledJustification<C>> = None;
        let for_us = &matrix[self.info.index as usize];
        let how_many = for_us.iter().filter(|b| !b).count();
        if how_many > 0 {
            let mut justifs = Vec::with_capacity(how_many);
            for (i, _) in for_us.iter().enumerate().filter(|(_, b)| !b) {
                let id = i as ID;
                // reveal the share
                let ijust = Justification {
                    share_idx: id,
                    share: self.info.secret.eval(id).value,
                };
                justifs.push(ijust);
            }
            ret_justif = Some(BundledJustification {
                dealer_idx: self.info.index,
                justifications: justifs,
                public: self.info.public.clone(),
            });
        }
        let dkg = DKGWaitingJustification {
            info: self.info,
            dist_share: self.dist_share,
            dist_pub: self.dist_pub,
            responses: matrix,
            publics: self.publics,
        };
        Err((dkg, ret_justif))
    }

    /// compute_statuses computes the final matrix of status according to the
    /// following rules:
    /// (a) initializes matrix to the default_resp field (by default is false)
    /// (b) set the status from the given responses
    /// (c) set to Success all position where dealer = share holder: in practice,
    /// it means we assume a dealer makes a valid share for himself and will not
    /// broadcast its response to its own share.
    /// (d) set the positions of our own responses computed during previous step,
    /// at `process_shares`.
    fn compute_statuses(&self, responses: &Vec<BundledResponses>) -> Vec<Bitset> {
        let my_idx = self.info.index;
        let n = self.info.n();
        // (a)
        let mut statuses = vec![Bitset::from_elem(n, (&self.default_resp).to_bool()); n];
        // makes sure the API doesn't take into account our own responses!
        let not_from_me = responses.iter().filter(|r| r.share_idx != my_idx);
        let valid_idx = not_from_me.filter(|r| {
            let good_holder = r.share_idx < n as ID;
            let good_dealers = !r.responses.iter().any(|resp| resp.dealer_idx >= n as ID);
            good_dealers && good_holder
        });
        for bundle in valid_idx {
            let holder_index = bundle.share_idx as usize;
            for response in bundle.responses.iter() {
                let dealer_index = response.dealer_idx as usize;
                // (b)
                // bit set = Success, bit unset = Complaint
                statuses[dealer_index].set(holder_index, response.status.to_bool());
            }
        }
        // (d) add our "own" previous responses
        statuses[self.info.index as usize] = self.own_responses.clone();
        // (c)
        for (i, row) in statuses.iter_mut().enumerate() {
            row.set(i, Status::Success.to_bool())
        }
        statuses
    }
}

pub struct DKGWaitingJustification<C: Curve> {
    // TODO: transform that into one info variable that gets default value for
    // missing parts depending in the round of the protocol.
    info: DKGInfo<C>,
    dist_share: C::Scalar,
    dist_pub: PublicPoly<C>,
    // guaranteed to be of the right size (n)
    responses: Vec<Bitset>,
    publics: HashMap<ID, PublicPoly<C>>,
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
        justifs: Vec<BundledJustification<C>>,
    ) -> Result<DKGOutput<C>, DKGError> {
        use Status::Success;
        // avoid an additional "mut" when using DKG; bitset is small
        let mut responses = self.responses.clone();
        let mut add_share = C::Scalar::zero();
        let mut add_public = PublicPoly::<C>::zero();
        for bundle in justifs
            .iter()
            .filter(|b| b.dealer_idx < self.info.n() as ID)
            .filter(|b| self.publics.contains_key(&b.dealer_idx))
        {
            // safe because we filter it from before
            let public = self.publics.get(&bundle.dealer_idx).unwrap();
            for j in bundle.justifications.iter() {
                if !share_correct::<C>(j.share_idx, &j.share, public) {
                    continue;
                }
                // justification is valid, we mark it off from our matrix
                responses[bundle.dealer_idx as usize].set(j.share_idx as usize, Success.to_bool());
                // if it is for us, then add it to our final share and public poly
                if j.share_idx == self.info.index {
                    add_share.add(&j.share);
                    add_public.add(&bundle.public);
                }
            }
        }
        // QUAL is the set of all entries in the matrix where all bits are set
        let qual_indices =
            responses
                .iter()
                .enumerate()
                .fold(Vec::new(), |mut acc, (idx, entry)| {
                    if entry.all_true() {
                        acc.push(idx as ID);
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
            .iter()
            .filter(|n| qual_indices.contains(&n.0))
            .map(|n| n.clone())
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

pub type DKGResult<A> = Result<A, DKGError>;

#[derive(Debug)]
pub enum DKGError {
    /// PublicKeyNotFound is raised when the private key given to the DKG init
    /// function does not yield a public key that is included in the group.
    PublicKeyNotFound,
    /// InvalidThreshold is raised when creating a group and specifying an
    /// invalid threshold. Either the threshold is too low, inferior to
    /// what `minimum_threshold()` returns or is too large (i.e. larger than the
    /// number of nodes).
    InvalidThreshold(usize, usize, usize),

    /// NotEnoughValidShares is raised when the DKG has not successfully
    /// processed enough shares because they were invalid. In that case, the DKG
    /// can not continue, the protocol MUST be aborted.
    NotEnoughValidShares(usize, usize),
    NotEnoughJustifications(usize, usize),
}

// TODO: potentially add to the API the ability to streamline the decryption of
// bundles, and in that case, it would make sense to report those errors.
#[derive(Debug)]
struct ShareError {
    // XXX better structure to put dealer_idx in an outmost struct but leads to
    // more verbose code. To review?
    dealer_idx: ID,
    error: ShareErrorType,
}

impl ShareError {
    fn from(dealer_idx: ID, error: ShareErrorType) -> Self {
        Self {
            dealer_idx,
            error: error,
        }
    }
}

#[derive(Debug)]
enum ShareErrorType {
    /// InvalidCipherText returns the error raised when decrypted the encrypted
    /// share.
    InvalidCiphertext(ecies::EciesError),
    /// InvalidShare is raised when the share does not corresponds to the public
    /// polynomial associated.
    InvalidShare,
    /// InvalidPublicPolynomial is raised when the public polynomial does not
    /// have the correct degree. Each public polynomial in the scheme must have
    /// a degree equals to `threshold - 1` set for the DKG protocol.
    /// The two fields are (1) the degree of the polynomial and (2) the
    /// second is the degree it should be,i.e. `threshold - 1`.
    InvalidPublicPolynomial(usize, usize),
}

impl fmt::Display for DKGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DKGError::*;
        match self {
            PublicKeyNotFound => write!(f, "public key not found in list of participants"),
            NotEnoughValidShares(have, must) => {
                write!(f, "only has {}/{} valid shares", have, must)
            }
            NotEnoughJustifications(have, must) => {
                write!(f, "only has {}/{} required justifications", have, must)
            }
            InvalidThreshold(have, min, max) => {
                write!(f, "threshold {} is not in range [{},{}]", have, min, max)
            }
        }
    }
}

impl Error for DKGError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        // TODO
        None
    }
}

/// Checks if the commitment to the share corresponds to the public polynomial's
/// evaluated at the given point.
fn share_correct<C: Curve>(idx: ID, share: &C::Scalar, public: &PublicPoly<C>) -> bool {
    let mut commit = C::Point::one();
    commit.mul(&share);
    let pub_eval = public.eval(idx);
    pub_eval.value == commit
}

pub fn minimum_threshold(n: usize) -> usize {
    (((n as f64) / 2.0) + 1.0) as usize
}
pub fn default_threshold(n: usize) -> usize {
    (((n as f64) * 2.0 / 3.0) + 1.0) as usize
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::curve::bls12381::{Curve as BCurve, Scalar, G1};
    use crate::poly::Eval;
    use rand::prelude::*;

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
        Poly::<C::Scalar, C::Scalar>::recover(thr, evals)
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
        let mut response_bundles = Vec::with_capacity(n);
        let dkgs: Vec<_> = dkgs
            .into_iter()
            .map(|dkg| {
                // TODO clone inneficient for test but likely use case for API
                // Make that take a reference
                let (ndkg, bundle) = dkg.process_shares(&all_shares).unwrap();
                response_bundles.push(bundle);
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
}
