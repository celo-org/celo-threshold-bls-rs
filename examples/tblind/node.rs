use crate::curve::{KeyCurve, Pairing};
use rand::prelude::*;
use threshold::dkg;
use threshold::*;
/// Node holds the logic of a participants, for the different phases of the
/// example.
pub struct Node {
    // One can simply use the Scalar and Point type directly instead of using
    // the rather verbose trait bounds phrase. This example shows how to have a
    // generic implementation.
    private: <KeyCurve as Curve>::Scalar,
    public: <KeyCurve as Curve>::Point,
    // Index is a type alias to represent the index of a participant. It can be
    // changed depending on the size of the network - u16 is likely to work for
    // most cases though.
    index: Index,
}

impl Node {
    fn new(index: usize) -> Self {
        let mut private = KeyCurve::scalar();
        private.pick(&mut thread_rng());
        let mut public = KeyCurve::point();
        public.pick(&mut thread_rng());
        Self {
            private,
            public,
            index: index as Index,
        }
    }

    // this method returns the struct to be used by the DKG
    fn as_dkg_node(&self) -> dkg::Node<KeyCurve> {
        dkg::Node::new(self.index, self.public.clone())
    }
}
