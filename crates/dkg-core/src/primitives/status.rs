use bitvec::{prelude::*, vec::BitVec};
use serde::{Deserialize, Serialize};
use std::fmt;
use threshold_bls::poly::Idx;

/// A `Status` holds the claim of a validity or not of a share from the point of
/// a view of the share holder. A status is sent inside a `Response` during the
/// second phase of the protocol.
/// Currently, this protocol only outputs `Complaint` since that is how the protocol
/// is specified using a synchronous network with a broadcast channel. In
/// practice, that means any `Response` seen during the second phase is a
/// `Complaint` from a participant about one of its received share.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    fn to_bool(self) -> bool {
        self.is_success()
    }

    pub(super) fn is_success(self) -> bool {
        match self {
            Status::Success => true,
            Status::Complaint => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusMatrix(Vec<BitVec>);

impl StatusMatrix {
    /// Returns a NxM Status Matrix (N = dealers, M = share_holders) where all elements
    /// are initialized to `default`. The elements on the diagonal (i==j) are by initialized
    /// to `Success`, since the dealer is assumed to succeed
    pub fn new(dealers: usize, share_holders: usize, default: Status) -> StatusMatrix {
        let m = (0..dealers)
            .map(|i| {
                let mut bs = bitvec![default.to_bool() as u8; share_holders];
                bs.set(i, Status::Success.to_bool());
                bs
            })
            .collect();
        Self(m)
    }

    pub fn set(&mut self, dealer: Idx, share: Idx, status: Status) {
        self.0[dealer as usize].set(share as usize, status.to_bool());
    }

    /// Return a bitvec whose indices are the dealer indexes
    pub fn get_for_share(&self, share: Idx) -> BitVec {
        let mut bs = bitvec![0; self.0.len()];
        for (dealer_idx, shares) in self.0.iter().enumerate() {
            bs.set(dealer_idx, *shares.get(share as usize).unwrap());
        }
        bs
    }

    /// Returns `true` if the row corresponding to `dealer` is all 1s.
    pub fn all_true(&self, dealer: Idx) -> bool {
        self.0[dealer as usize].all()
    }

    pub fn get_for_dealer(&self, dealer: Idx) -> &BitVec {
        &self.0[dealer as usize]
    }
}

impl fmt::Display for StatusMatrix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (dealer, shares) in self.0.iter().enumerate() {
            match writeln!(f, "-> dealer {}: {:?}", dealer, shares) {
                Ok(()) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
