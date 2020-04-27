use crate::group::{Curve, Element, Point, Scalar};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};
use thiserror::Error;

pub type PrivatePoly<C> = Poly<<C as Curve>::Scalar>;
pub type PublicPoly<C> = Poly<<C as Curve>::Point>;

pub type Idx = u32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eval<A> {
    pub value: A,
    pub index: Idx,
}

impl<A: fmt::Display> fmt::Display for Eval<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ idx: {}, value: {} }}", self.index, self.value)
    }
}

/// A polynomial that is using a scalar for the variable x and a generic
/// element for the coefficients. The coefficients must be able to multiply
/// the type of the variable, which is always a scalar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Poly<C> {
    c: Vec<C>,
}

impl<C> Poly<C> {
    pub fn degree(&self) -> usize {
        self.c.len() - 1
    }
}

impl<C: Element> Poly<C> {
    /// Returns a new polynomial of the given degree where each coefficients is
    /// sampled at random from the given RNG.
    /// In the context of secret sharing, the threshold is the degree + 1.
    pub fn new_from<R: RngCore>(degree: usize, rng: &mut R) -> Self {
        let coeffs: Vec<C> = (0..=degree).map(|_| C::rand(rng)).collect();
        Self::from(coeffs)
    }

    pub fn new(degree: usize) -> Self {
        use rand::prelude::*;
        Self::new_from(degree, &mut thread_rng())
    }

    /// Returns a polynomial from the given list of coefficients
    // TODO: implement the From<> trait
    // TODO fix semantics of zero:
    // it should be G1::zero() as only element
    pub fn zero() -> Self {
        Self::from(vec![C::zero()])
    }
}

#[derive(Debug, Error)]
pub enum PolyError {
    #[error("Invalid recovery: only has {0}/{1} shares")]
    InvalidRecovery(usize, usize),
}

impl<C> Poly<C>
where
    C: Element,
    C::RHS: Scalar<RHS = C::RHS>,
{
    pub fn eval(&self, i: Idx) -> Eval<C> {
        let mut xi = C::RHS::new();
        // +1 because we must never evaluate the polynomial at its first point
        // otherwise it reveals the "secret" value !
        // TODO: maybe move that a layer above, to not mix ss scheme with poly.
        xi.set_int((i + 1).into());
        let mut res = C::new();
        (0..=self.degree()).rev().for_each(|i| {
            res.mul(&xi);
            res.add(&self.c[i]);
        });
        Eval {
            value: res,
            index: i,
        }
    }

    /// Adds the two polynomial togethers.
    pub fn add(&mut self, other: &Self) {
        if self.degree() < other.degree() {
            // self has lesser degree so we extend it
            let diff = other.degree() - self.degree();
            self.c.extend(vec![C::new(); diff]);
            let zipped = self.c.iter_mut().zip(other.c.iter());
            zipped.for_each(|(a, b)| a.add(&b));
            return;
        }
        // if self.degree() >= other.degree() the coefficients
        // outside the zip dont need to change
        let zipped = self.c.iter_mut().zip(other.c.iter());
        zipped.for_each(|(a, b)| a.add(&b));
    }

    pub fn recover(t: usize, mut shares: Vec<Eval<C>>) -> Result<C, PolyError> {
        if shares.len() < t {
            return Err(PolyError::InvalidRecovery(shares.len(), t));
        }

        // first sort the shares as it can happens recovery happens for
        // non-correlated shares so the subset chosen becomes important
        shares.sort_by(|a, b| a.index.cmp(&b.index));

        // convert the indexes of the shares into scalars
        let xs = shares.iter().take(t).fold(HashMap::new(), |mut m, sh| {
            let mut xi = C::RHS::new();
            xi.set_int((sh.index + 1).into());
            m.insert(sh.index, (xi, &sh.value));
            m
        });

        assert!(xs.len() == t);
        let mut acc = C::zero();

        // iterate over all indices and for each multiply the lagrange basis
        // with the value of the share
        for (i, xi) in &xs {
            let mut yi = xi.1.clone();
            let mut num = C::RHS::one();
            let mut den = C::RHS::one();

            for (j, xj) in &xs {
                if i == j {
                    continue;
                }

                // xj - 0
                num.mul(&xj.0);

                // 1 / (xj - xi)
                let mut tmp = xj.0.clone();
                tmp.sub(&xi.0);
                den.mul(&tmp);
            }

            let inv = den.inverse().unwrap();
            num.mul(&inv);
            yi.mul(&num);
            acc.add(&yi);
        }
        Ok(acc)
    }

    pub fn full_recover(t: usize, mut shares: Vec<Eval<C>>) -> Result<Self, PolyError> {
        if shares.len() < t {
            return Err(PolyError::InvalidRecovery(shares.len(), t));
        }
        // first sort the shares as it can happens recovery happens for
        // non-correlated shares so the subset chosen becomes important
        shares.sort_by(|a, b| a.index.cmp(&b.index));

        // convert the indexes of the shares into scalars
        let xs = shares.iter().take(t).fold(HashMap::new(), |mut m, sh| {
            let mut xi = C::RHS::new();
            xi.set_int((sh.index + 1).into());
            m.insert(sh.index, (xi, &sh.value));
            m
        });
        assert!(xs.len() == t);
        let mut acc: Self = vec![C::new()].into();
        // iterate over all indices and for each multiply the lagrange basis
        // with the value of the share
        for (i, sh) in &xs {
            let basis = Self::lagrange_basis(*i, &xs);
            // one element of the linear combination
            // y_j * L_y
            let lin = basis
                .c
                .iter()
                .map(|c| {
                    // TODO avoid re-allocation for <X,X> case by just mul()
                    let mut s = sh.1.clone();
                    s.mul(c);
                    s
                })
                .collect::<Vec<C>>();
            let linear_poly: Poly<C> = Self::from(lin);
            acc.add(&linear_poly);
        }
        Ok(acc)
    }

    /// Computes the lagrange basis polynomial of index i
    // TODO: move that to poly<X,X>
    fn lagrange_basis(i: Idx, xs: &HashMap<Idx, (C::RHS, &C)>) -> Poly<C::RHS> {
        let mut basis = Poly::<C::RHS>::from(vec![C::RHS::one()]);
        // accumulator of the denominator values
        let mut acc = C::RHS::one();
        // TODO remove that cloning due to borrowing issue with the map
        let xi = xs.get(&i).unwrap().clone().0;
        for (idx, sc) in xs.iter() {
            if *idx == i {
                continue;
            }

            // basis * (x - sc)
            let minus_sc = Self::new_neg_constant(&sc.0);
            basis.mul(&minus_sc);
            // den = xi - sc
            let mut den = C::RHS::zero();
            den.add(&xi);
            den.sub(&sc.0);
            // den = 1 / den
            den = den.inverse().unwrap();
            // acc = acc * den
            acc.mul(&den);
        }
        // multiply all coefficients by the denominator
        basis.mul(&Poly::from(vec![acc]));
        basis
    }

    /// Returns a scalar polynomial f(x) = x - c
    fn new_neg_constant(x: &C::RHS) -> Poly<C::RHS> {
        let mut neg = x.clone();
        neg.negate();
        Poly::from(vec![neg, C::RHS::one()])
    }

    pub fn free_coeff(&self) -> C {
        self.c[0].clone()
    }

    pub fn public_key(&self) -> C {
        self.free_coeff()
    }
}

impl<C: Element> From<Vec<C>> for Poly<C> {
    fn from(c: Vec<C>) -> Self {
        Self { c }
    }
}

impl<C: Element> From<Poly<C>> for Vec<C> {
    fn from(poly: Poly<C>) -> Self {
        poly.c
    }
}

/// Adds the multiplication operation for polynomial scalars. Note this is a
/// simple implementation that is suitable for secret sharing schemes, but may
/// be inneficient for other purposes: the degree of the returned polynomial
/// is always the greatest possible, regardless of the actual coefficients
/// given.
impl<X: Scalar<RHS = X>> Poly<X> {
    fn mul(&mut self, other: &Self) {
        let d1 = self.degree();
        let d2 = other.degree();
        let d3 = d1 + d2;

        // need to initializes every coeff to zero first
        let mut coeffs = (0..=d3).map(|_| X::zero()).collect::<Vec<X>>();

        for (i, c1) in self.c.iter().enumerate() {
            for (j, c2) in other.c.iter().enumerate() {
                let mut tmp = X::one();
                tmp.mul(c1);
                tmp.mul(c2);
                coeffs[i + j].add(&tmp);
            }
        }

        self.c = coeffs;
    }

    pub fn commit<P: Point<RHS = X>>(&self) -> Poly<P> {
        let commits = self
            .c
            .iter()
            .map(|c| {
                let mut commitment = P::one();
                commitment.mul(c);
                commitment
            })
            .collect::<Vec<P>>();
        Poly::<P>::from(commits)
    }
}

impl<C: fmt::Display> fmt::Display for Poly<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self
            .c
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{}: {}", i, c))
            .collect::<Vec<String>>()
            .join(", ");
        write!(f, "[deg: {}, coeffs: [{}]]", self.degree(), s)
    }
}

#[cfg(feature = "bls12_381")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::curve::bls12381::Scalar as Sc;
    use crate::curve::bls12381::G1;
    use rand::prelude::*;

    #[test]
    fn new_poly() {
        let s = 5;
        let p = Poly::<Sc>::new(s);
        assert_eq!(p.c.len(), s + 1);
    }

    #[test]
    fn serialization() {
        let p = Poly::<Sc>::new(10);

        let ser = bincode::serialize(&p).unwrap();

        let de: Poly<Sc> = bincode::deserialize(&ser).unwrap();

        assert_eq!(p, de);
    }

    #[test]
    fn full_interpolation() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = Poly::<Sc>::new(degree);
        let shares = (0..threshold)
            .map(|i| poly.eval(i as Idx))
            .collect::<Vec<Eval<Sc>>>();
        let smaller_shares: Vec<_> = shares.iter().take(threshold - 1).cloned().collect();
        let recovered = Poly::<Sc>::full_recover(threshold as usize, shares).unwrap();
        let expected = poly.c[0];
        let computed = recovered.c[0];
        assert_eq!(expected, computed);
        Poly::<Sc>::recover(threshold as usize, smaller_shares).unwrap_err();
    }

    #[test]
    fn interpolation() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = Poly::<Sc>::new(degree);
        let shares = (0..threshold)
            .map(|i| poly.eval(i as Idx))
            .collect::<Vec<Eval<Sc>>>();
        let smaller_shares: Vec<_> = shares.iter().take(threshold - 1).cloned().collect();
        let recovered = Poly::<Sc>::recover(threshold as usize, shares).unwrap();
        let expected = poly.c[0];
        assert_eq!(expected, recovered);
        Poly::<Sc>::recover(threshold as usize, smaller_shares).unwrap_err();
    }

    #[test]
    fn benchy() {
        use std::time::SystemTime;
        let degree = 49;
        let threshold = degree + 1;
        let poly = Poly::<Sc>::new(degree);
        let shares = (0..threshold)
            .map(|i| poly.eval(i as Idx))
            .collect::<Vec<Eval<Sc>>>();
        let now = SystemTime::now();
        Poly::<Sc>::recover(threshold as usize, shares).unwrap();
        match now.elapsed() {
            Ok(e) => println!("single recover: time elapsed {:?}", e),
            Err(e) => panic!("{}", e),
        }
        let shares = (0..threshold)
            .map(|i| poly.eval(i as Idx))
            .collect::<Vec<Eval<Sc>>>();

        let now = SystemTime::now();
        Poly::<Sc>::full_recover(threshold as usize, shares).unwrap();
        match now.elapsed() {
            Ok(e) => println!("full_recover: time elapsed {:?}", e),
            Err(e) => panic!("{}", e),
        }
    }

    #[test]
    fn eval() {
        let d = 4;
        let p1 = Poly::<Sc>::new(d);
        // f(1) = SUM( coeffs)
        let f1 = p1.eval(0);
        let exp = p1.c.iter().fold(Sc::new(), |mut acc, coeff| {
            acc.add(coeff);
            acc
        });
        assert_eq!(exp, f1.value);
    }

    #[test]
    fn add() {
        let d = 4;
        let p1 = Poly::<Sc>::new(d);
        let p2 = Poly::<Sc>::new(d);
        let mut p3 = p1.clone();
        p3.add(&p2);
        let mut exp = p1.c[0];
        exp.add(&p2.c[0]);
        assert_eq!(exp, p3.c[0]);
    }
    #[test]
    fn mul() {
        let d = 1;
        let p1 = Poly::<Sc>::new(d);
        let p2 = Poly::<Sc>::new(d);
        let mut p3 = p1.clone();
        p3.mul(&p2);
        assert_eq!(p3.degree(), d + d);
        // f1 = c0 + c1 * x
        // f2 = d0 + d1 * x
        //                   l1            l2                l3
        // f3 = f1 * f2 = (c0*d0) + (c0*d1 + d0*c1) * x + (c1*d1) * x^2
        // f3(1) = l1 + l2 + l3
        let mut l1 = p1.c[0];
        l1.mul(&p2.c[0]);
        // c0 * d1
        let mut l21 = p1.c[0];
        l21.mul(&p2.c[1]);
        // d0 * c1
        let mut l22 = p1.c[1];
        l22.mul(&p2.c[0]);
        let mut l2 = Sc::new();
        l2.add(&l21);
        l2.add(&l22);
        let mut l3 = p1.c[1];
        l3.mul(&p2.c[1]);
        let mut total = Sc::new();
        total.add(&l1);
        total.add(&l2);
        total.add(&l3);
        let res = p3.eval(0);
        assert_eq!(total, res.value);
    }

    #[test]
    fn new_neg_constant() {
        let rd = Sc::rand(&mut thread_rng());
        let p = Poly::<Sc>::new_neg_constant(&rd);
        let res = p.eval(0);
        let mut exp = rd;
        // -rd
        exp.negate();
        // 1 - rd
        exp.add(&Sc::one());
        assert_eq!(exp, res.value);
    }

    #[test]
    fn commit() {
        let secret = Poly::<Sc>::new(5);
        let commitment = secret.commit::<G1>();
        let first = secret.c[0];
        let mut p = G1::one();
        p.mul(&first);
        // TODO make polynomial implement equal
        assert_eq!(commitment.c[0], p);
    }
}
