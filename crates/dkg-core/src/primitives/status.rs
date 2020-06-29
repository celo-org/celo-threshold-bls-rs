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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
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

    pub(crate) fn is_success(self) -> bool {
        match self {
            Status::Success => true,
            Status::Complaint => false,
        }
    }
}

/// A `StatusMatrix` is a 2D binary array containing `Status::Success` or `Status::Complaint`
/// values. Under the hood, it utilizes [`bitvec`]
///
/// # Examples
///
/// ```rust,ignore
/// use dkg_core::primitives::status::{Status, StatusMatrix};
///
/// // initializes the matrix (diagonal elements are always set to Status::Success)
/// let mut matrix = StatusMatrix::new(3, 5, Status::Complaint);
///
/// // get the matrix's first row
/// let row = matrix.get_for_dealer(1);
///
/// // get the matrix's first column
/// let column = matrix.get_for_dealer(1);
///
/// // set a value in the matrix
/// matrix.set(1, 2, Status::Complaint);
///
/// // get a value in the matrix
/// let val = matrix.get(1, 2);
/// assert_eq!(val, Status::Complaint);
///
/// // check if all values in a row are OK
/// let all_ones: bool = matrix.all_true(2);
/// ```
///
/// [`bitvec`]: http://docs.rs/bitvec/0.17.4/
#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct StatusMatrix(Vec<BitVec>);

impl AsRef<[BitVec]> for StatusMatrix {
    fn as_ref(&self) -> &[BitVec] {
        &self.0
    }
}

impl IntoIterator for StatusMatrix {
    type Item = BitVec;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl fmt::Display for StatusMatrix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (dealer, shares) in self.0.iter().enumerate() {
            writeln!(f, "-> dealer {}: {}", dealer, shares)?;
        }
        Ok(())
    }
}

impl StatusMatrix {
    /// Returns a MxN Status Matrix (M = dealers, N = share_holders) where all elements
    /// are initialized to `default`.
    ///
    /// # Panics
    ///
    /// If `dealers > share_holders`
    pub fn new(dealers: usize, share_holders: usize, default: Status) -> StatusMatrix {
        let m = (0..dealers)
            .map(|_| bitvec![default.to_bool() as u8; share_holders])
            .collect();

        Self(m)
    }

    /// Sets an element at the cell corresponding to (dealer, share) to `status`.
    ///
    /// # Panics
    ///
    /// - If the `share` index is greater than the number of shareholders
    /// - If the `dealer` index is greater than the number of dealers
    pub fn set(&mut self, dealer: Idx, share: Idx, status: Status) {
        self.0[dealer as usize].set(share as usize, status.to_bool());
    }

    /// Gets the element at the cell corresponding to (dealer, share)
    ///
    /// # Panics
    ///
    /// - If the `share` index is greater than the number of shareholders
    /// - If the `dealer` index is greater than the number of dealers
    #[allow(unused)]
    pub fn get(&self, dealer: Idx, share: Idx) -> Status {
        Status::from(
            *self.0[dealer as usize]
                .get(share as usize)
                .expect("share index out of bounds"),
        )
    }

    /// Returns the column corresponding to the shareholder at `share`.
    ///
    /// This will allocate a new vector, and as such changing the underlying
    /// status matrix will _not_ affect the returned value.
    ///
    /// # Panics
    ///
    /// If the `share` index is greater than the number of shareholders
    pub fn get_for_share(&self, share: Idx) -> BitVec {
        let mut col = bitvec![0; self.0.len()];

        for (dealer_idx, shares) in self.0.iter().enumerate() {
            let share_bit = shares
                .get(share as usize)
                .expect("share index out of bounds");
            col.set(dealer_idx, *share_bit);
        }

        col
    }

    /// Returns the row corresponding to the dealer at `dealer`
    ///
    /// # Panics
    ///
    /// If the `dealer` index is greater than the number of dealers
    pub fn get_for_dealer(&self, dealer: Idx) -> &BitVec {
        self.0
            .get(dealer as usize)
            .expect("dealer index out of bounds")
    }

    /// Returns `true` if the row corresponding to `dealer` is all 1s.
    ///
    /// # Panics
    ///
    /// If the `dealer` index is greater than the number of dealers
    pub fn all_true(&self, dealer: Idx) -> bool {
        self.get_for_dealer(dealer).all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set() {
        let mut matrix = StatusMatrix::new(3, 3, Status::Complaint);
        matrix.set(1, 1, Status::Complaint);
        let status = matrix.get(1, 1);
        assert_eq!(status, Status::Complaint);
    }

    #[test]
    fn get_for_dealer() {
        let mut matrix = StatusMatrix::new(3, 3, Status::Complaint);
        matrix.set(1, 1, Status::Success);
        let get_for_dealer = matrix.get_for_dealer(1);
        assert_eq!(get_for_dealer, &bitvec![0, 1, 0]);
    }

    #[test]
    #[should_panic(expected = "dealer index out of bounds")]
    fn dealer_out_of_bounds() {
        let matrix = StatusMatrix::new(3, 5, Status::Complaint);
        matrix.get_for_dealer(3);
    }

    #[test]
    fn get_for_share() {
        let matrix = StatusMatrix::new(2, 3, Status::Complaint);
        let col = matrix.get_for_share(2);
        assert_eq!(col, bitvec![0, 0]);
    }

    #[test]
    #[should_panic(expected = "share index out of bounds")]
    fn share_out_of_bounds() {
        let matrix = StatusMatrix::new(3, 5, Status::Complaint);
        matrix.get_for_share(5);
    }

    #[test]
    fn display() {
        let matrix = StatusMatrix::new(3, 3, Status::Complaint);
        let s = matrix.to_string();
        assert_eq!(
            s,
            "-> dealer 0: [000]\n-> dealer 1: [000]\n-> dealer 2: [000]\n"
        );
    }
}
