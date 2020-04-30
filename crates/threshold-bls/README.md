# BLS Threshold CryptoSignatures

This library provides primitives for (blind) threshold cryptography. Currently supported
curves are BLS12-377 and BLS12-381.

**Work In Progress: DO NOT EXPECT ANY STABLE API NOW**

## Group functionality

[`src/group.rs`](src/group.rs) contains the definitions of generic trait to work
with scalars of prime fields and points on elliptic curves. The following
`Element` trait allows to get a generic implementation of a polynomial with lagrange interpolation for both scalars and points.
```rust
pub trait Element<RHS = Self>: Clone + fmt::Display + fmt::Debug + Eq {
    /// new MUST return the zero element of the group.
    fn new() -> Self;
    fn one() -> Self;
    fn add(&mut self, s2: &Self);
    fn mul(&mut self, mul: &RHS);
    fn pick<R: RngCore>(&mut self, rng: &mut R);
    fn zero() -> Self {
        Self::new()
    }
}
```

There is an implementation of these traits using the curve BLS12-381 in
[`src/bls12381.rs`](src/bls12381.rs).

## Polynomial functionality

[`src/poly.rs`](src/poly.rs) contains the implementation of a polynomial
suitable to be used for secret sharing schemes and the dkg protocol. It can
evaluates shares and interpolate private and public shares to their
corresponding polynomial.

The following (from the [tests](src/poly.rs#L264)) shows how to interploate
a set of private shares:

```rust
use crate::bls12381::Scalar as Sc;
fn interpolation() {
    let degree = 4;
    let threshold = degree + 1;
    let poly = Poly::<Sc, Sc>::new(degree);
    let shares = (0..threshold)
        .map(|i| poly.eval(i as u64))
        .collect::<Vec<Share<Sc>>>();
    let recovered = Poly::<Sc, Sc>::recover(threshold as usize, shares);
    let expected = poly.c[0];
    let computed = recovered.c[0];
    assert_eq!(expected, computed);
}
```

## Curve Implementations

Curently there are two curves available, `BLS12 381` and `BLS 377`. By default they are enabled both, but you can select which one you want to use using
the features `bls12_381` and `bls_377`.

You can use them like this when adding the dependency to your `Cargo.toml` file.

```toml
# Only bls12_381
threshold = { version = "0.1", default-features = false, features = ["bls12_381"] }
# Only bls12_377
threshold = { version = "0.1", default-features = false, features = ["bls12_377"] }
# Both
threshold = { version = "0.1" }
```
