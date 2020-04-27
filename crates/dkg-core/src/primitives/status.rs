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

    pub(super) fn is_success(self) -> bool {
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
/// ```rust
/// use dkg_core::primitives::status::{Status, StatusMatrix};
///
/// // iniitializes the matrix (diagonal elements are always set to Status::Success)
/// let mut matrix = StatusMatrix::new(3, 5, Status::Complaint);
///
/// // get the matrix's first row
/// let row = matrix.row(1);
///
/// // get the matrix's first column
/// let column = matrix.row(1);
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
    /// are initialized to `default`. The elements on the diagonal (i==j) are by initialized
    /// to `Success`, since the dealer is assumed to succeed
    ///
    /// # Panics
    ///
    /// If `dealers > share_holders`
    pub fn new(dealers: usize, share_holders: usize, default: Status) -> StatusMatrix {
        debug_assert!(
            dealers <= share_holders,
            "dealers cannot be more than share holders"
        );

        let m = (0..dealers)
            .map(|i| {
                let mut bs = bitvec![default.to_bool() as u8; share_holders];
                bs.set(i, Status::Success.to_bool());
                bs
            })
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
    pub fn column(&self, share: Idx) -> BitVec {
        // each column has `rows.length` elements
        let mut col = bitvec![0; self.0.len()];

        for (dealer_idx, shares) in self.0.iter().enumerate() {
            let share_bit = shares
                .get(share as usize)
                .expect("share index out of bounds");
            col.set(dealer_idx, *share_bit);
        }

        col
    }

    /// Returns `true` if the row corresponding to `dealer` is all 1s.
    ///
    /// # Panics
    ///
    /// If the `dealer` index is greater than the number of rows
    pub fn all_true(&self, dealer: Idx) -> bool {
        self.row(dealer).all()
    }

    /// Returns the row corresponding to `dealer`
    ///
    /// # Panics
    ///
    /// If the `dealer` index is greater than the number of rows
    pub fn row(&self, dealer: Idx) -> &BitVec {
        self.0
            .get(dealer as usize)
            .expect("dealer index out of bounds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagonal_success() {
        let matrix = StatusMatrix::new(10, 10, Status::Complaint);
        for (i, row) in matrix.into_iter().enumerate() {
            assert_eq!(row.get(i).unwrap(), &true);
        }
    }

    #[test]
    fn set() {
        let mut matrix = StatusMatrix::new(3, 3, Status::Complaint);
        let status = matrix.get(1, 1);
        assert_eq!(status, Status::Success);
        matrix.set(1, 1, Status::Complaint);
        let status = matrix.get(1, 1);
        assert_eq!(status, Status::Complaint);
    }

    #[test]
    fn get_row() {
        let matrix = StatusMatrix::new(3, 3, Status::Complaint);
        let row = matrix.row(1);
        assert_eq!(row, &bitvec![0, 1, 0]);
    }

    #[test]
    #[should_panic(expected = "dealer index out of bounds")]
    fn dealer_out_of_bounds() {
        let matrix = StatusMatrix::new(3, 5, Status::Complaint);
        matrix.row(3);
    }

    #[test]
    fn get_column() {
        let matrix = StatusMatrix::new(2, 3, Status::Complaint);
        let col = matrix.column(2);
        assert_eq!(col, bitvec![0, 0]);
    }

    #[test]
    #[should_panic(expected = "share index out of bounds")]
    fn share_out_of_bounds() {
        let matrix = StatusMatrix::new(3, 5, Status::Complaint);
        matrix.column(5);
    }

    #[test]
    fn display() {
        let matrix = StatusMatrix::new(3, 3, Status::Complaint);
        let s = matrix.to_string();
        assert_eq!(
            s,
            "-> dealer 0: [100]\n-> dealer 1: [010]\n-> dealer 2: [001]\n"
        );
    }

    #[test]
    #[should_panic(expected = "dealers cannot be more than share holders")]
    fn dealers_more_than_shareholders_panics() {
        StatusMatrix::new(6, 5, Status::Complaint);
    }
}
