use crate::primitives::{
    types::{BundledJustification, BundledResponses, BundledShares, DKGOutput},
    DKGError, DKGResult,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use threshold_bls::group::Curve;

use std::fmt::Debug;

/// Phase0 is the trait abstracting the first step of a distributed key
/// generation computation. At this stage, the "dealer" nodes create their
/// shares and encrypt them to the "share holders".
pub trait Phase0<C: Curve>: Clone + Debug + Serialize + for<'a> Deserialize<'a> {
    type Next: Phase1<C>;

    fn encrypt_shares<R: RngCore>(
        self,
        rng: &mut R,
    ) -> DKGResult<(Self::Next, Option<BundledShares<C>>)>;
}

/// Phase1 is the trait abstracting the second step of a distributed key
/// generation computation. At this stage, the "share holders" nodes decrypt the
/// shares and create responses to broadcast to both dealers and share holders.
pub trait Phase1<C: Curve>: Clone + Debug + Serialize + for<'a> Deserialize<'a> {
    type Next: Phase2<C>;

    fn process_shares(
        self,
        bundles: &[BundledShares<C>],
        publish_all: bool,
    ) -> DKGResult<(Self::Next, Option<BundledResponses>)>;
}

/// Phase2 is the trait abstracting the third stage of a distributed key
/// generation computation. At this stage, every participant process the
/// responses, look if they can finish the protocol. If not, dealers look if
/// they have to produce some justifications.
///
/// The return method of this trait is first the `DKGOutput` if the protocol can
/// be finished already. If not, the call returns an error which either contains
/// the next phase and potential justifications or a fatal error that makes this
/// node unable to continue participating in the protocol.
pub trait Phase2<C: Curve>: Clone + Debug + Serialize + for<'a> Deserialize<'a> {
    type Next: Phase3<C>;

    #[allow(clippy::type_complexity)]
    fn process_responses(
        self,
        responses: &[BundledResponses],
    ) -> Result<DKGOutput<C>, DKGResult<(Self::Next, Option<BundledJustification<C>>)>>;
}

/// Phase3 is the trait abstracting the final stage of a distributed key
/// generation protocol. At this stage, the share holders process the potential
/// justifications, and look if they can finish the protocol.
pub trait Phase3<C: Curve>: Debug {
    fn process_justifications(
        self,
        justifs: &[BundledJustification<C>],
    ) -> Result<DKGOutput<C>, DKGError>;
}
