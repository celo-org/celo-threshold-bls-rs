use super::{default_threshold, minimum_threshold, DKGError, DKGResult};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use threshold_bls::{group::Curve, poly::Idx};

/// Node is a participant in the DKG protocol. In a DKG protocol, each
/// participant must be identified both by an index and a public key. At the end
/// of the protocol, if sucessful, the index is used to verify the validity of
/// the share this node holds.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Node<C: Curve>(Idx, C::Point);

impl<C: Curve> Node<C> {
    pub fn new(index: Idx, public: C::Point) -> Self {
        Self(index, public)
    }
}

impl<C: Curve> Node<C> {
    /// Returns the node's index
    pub fn id(&self) -> Idx {
        self.0
    }

    /// Returns the node's public key
    pub fn key(&self) -> &C::Point {
        &self.1
    }
}

/// A Group is a collection of Nodes with an associated threshold. A DKG scheme
/// takes in a group at the beginning of the protocol and outputs a potentially
/// new group that contains members that succesfully ran the protocol. When
/// creating a new group using the `from()` or `from_list()`method, the module
/// sets the threshold to the output of `default_threshold()`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(bound = "C::Scalar: DeserializeOwned")]
pub struct Group<C: Curve> {
    /// The vector of nodes in the group
    pub nodes: Vec<Node<C>>,
    /// The minimum number of nodes required to participate in the DKG for this group
    pub threshold: usize,
}

impl<C> Group<C>
where
    C: Curve,
{
    /// Converts a vector of nodes to a group with the default threshold (51%)
    pub fn from_list(nodes: Vec<Node<C>>) -> Group<C> {
        let l = nodes.len();
        Self {
            nodes,
            threshold: default_threshold(l),
        }
    }

    /// Creates a new group from the provided vector of nodes and threshold.
    ///
    /// Valid thresholds are `>= 51% * nodes.len()` and `<= 100% * nodes.len()`
    pub fn new(nodes: Vec<Node<C>>, threshold: usize) -> DKGResult<Group<C>> {
        let minimum = minimum_threshold(nodes.len());
        let maximum = nodes.len();

        // reject invalid thresholds
        if threshold < minimum || threshold > maximum {
            return Err(DKGError::InvalidThreshold(threshold, minimum, maximum));
        }

        Ok(Self { nodes, threshold })
    }

    /// Returns the number of nodes in the group
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Checks if the group is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Gets the index of the node corresponding to the provided public key
    pub fn index(&self, public: &C::Point) -> Option<Idx> {
        self.nodes.iter().find(|n| &n.1 == public).map(|n| n.0)
    }

    pub fn contains_index(&self, idx: Idx) -> bool {
        self.nodes.iter().any(|n| n.0 == idx)
    }
}

impl<C> From<Vec<C::Point>> for Group<C>
where
    C: Curve,
{
    fn from(list: Vec<C::Point>) -> Self {
        let thr = default_threshold(list.len());

        let nodes = list
            .into_iter()
            .enumerate()
            .map(|(i, public)| Node::new(i as Idx, public))
            .collect();

        Self::new(nodes, thr).expect("threshold should be good here")
    }
}
