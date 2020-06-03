use crate::primitives::{group::Group, status::Status};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use threshold_bls::{
    ecies::EciesCipher,
    group::Curve,
    poly::{Idx, PublicPoly},
    sig::Share,
};

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

/// EncryptedShare holds the ECIES encryption of a share destined to the
/// `share_idx`-th participant. When receiving the share, if the participant has
/// the same specified index, the corresponding dkg state decrypts the share using
/// the participant's private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct EncryptedShare<C: Curve> {
    /// The index of the participant this share belongs to
    pub share_idx: Idx,
    /// The ECIES encrypted share
    pub secret: EciesCipher<C>,
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

/// A `Justification` contains the share of the share holder that issued a
/// complaint, in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct Justification<C: Curve> {
    /// The share holder's index
    pub share_idx: Idx,
    /// The plaintext share
    pub share: C::Scalar,
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
/// A response which gets generated when processing the shares from Phase 1
pub struct Response {
    /// The index of the dealer (the person that created the share)
    pub dealer_idx: Idx,
    /// The status of the response (whether it suceeded or if there were complaints)
    pub status: Status,
}
