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
pub struct Poly<C>(Vec<C>);

impl<C> Poly<C> {
    /// Returns the degree of the polynomial
    pub fn degree(&self) -> usize {
        // e.g. c_3 * x^3 + c_2 * x^2 + c_1 * x + c_0
        // ^ 4 coefficients correspond to a 3rd degree poly
        self.0.len() - 1
    }

    #[cfg(test)]
    /// Returns the number of coefficients
    fn len(&self) -> usize {
        self.0.len()
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

    fn is_zero(&self) -> bool {
        self.0.is_empty() || self.0.iter().all(|coeff| coeff == &C::zero())
    }

    /// Performs polynomial addition in place
    pub fn add(&mut self, other: &Self) {
        // if we have a smaller degree we should pad with zeros
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), C::zero())
        }

        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| a.add(&b))
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

        let res = self.0.iter().rev().fold(C::zero(), |mut sum, coeff| {
            sum.mul(&xi);
            sum.add(coeff);
            sum
        });

        Eval {
            value: res,
            index: i,
        }
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
            let basis = Poly::<C::RHS>::lagrange_basis(*i, &xs);
            // one element of the linear combination
            // y_j * L_y
            let lin = basis
                .0
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

    pub fn public_key(&self) -> &C {
        &self.0[0]
    }
}

impl<C: Element> From<Vec<C>> for Poly<C> {
    fn from(c: Vec<C>) -> Self {
        Self(c)
    }
}

impl<C: Element> From<Poly<C>> for Vec<C> {
    fn from(poly: Poly<C>) -> Self {
        poly.0
    }
}

/// Adds the multiplication operation for polynomial scalars. Note this is a
/// simple implementation that is suitable for secret sharing schemes, but may
/// be inneficient for other purposes: the degree of the returned polynomial
/// is always the greatest possible, regardless of the actual coefficients
/// given.
impl<X: Scalar<RHS = X>> Poly<X> {
    fn mul(&mut self, other: &Self) {
        if self.is_zero() || other.is_zero() {
            *self = Self::zero();
            return;
        }

        let d3 = self.degree() + other.degree();

        // need to initializes every coeff to zero first
        let mut coeffs = (0..=d3).map(|_| X::zero()).collect::<Vec<X>>();

        for (i, c1) in self.0.iter().enumerate() {
            for (j, c2) in other.0.iter().enumerate() {
                // c_ij += c1 * c2
                let mut tmp = X::one();
                tmp.mul(c1);
                tmp.mul(c2);
                coeffs[i + j].add(&tmp);
            }
        }

        self.0 = coeffs;
    }

    /// Returns the scalar polynomial f(x) = x - c
    fn new_neg_constant(mut c: X) -> Poly<X> {
        c.negate();
        Poly::from(vec![c, X::one()])
    }

    /// Computes the lagrange basis polynomial of index i
    fn lagrange_basis<E: Element<RHS = X>>(i: Idx, xs: &HashMap<Idx, (X, &E)>) -> Poly<X> {
        let mut basis = Poly::<X>::from(vec![X::one()]);

        // accumulator of the denominator values
        let mut acc = X::one();

        // TODO remove that cloning due to borrowing issue with the map
        let xi = xs.get(&i).unwrap().clone().0;
        for (idx, sc) in xs.iter() {
            if *idx == i {
                continue;
            }

            // basis * (x - sc)
            let minus_sc = Poly::<X>::new_neg_constant(sc.0.clone());
            basis.mul(&minus_sc);

            // den = xi - sc
            let mut den = X::zero();
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

    /// Commits the scalar polynomial to the group and returns a polynomial over the group
    ///
    /// This is done by multiplying each coefficient of the polynomial with the
    /// group's generator.
    pub fn commit<P: Point<RHS = X>>(&self) -> Poly<P> {
        let commits = self
            .0
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
            .0
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

    use quickcheck_macros::quickcheck;

    #[test]
    fn poly_degree() {
        let s = 5;
        let p = Poly::<Sc>::new(s);
        assert_eq!(p.0.len(), s + 1);
        assert_eq!(p.degree(), s);
    }

    // the coefficients up to the smaller polynomial's degree should be summed up,
    // after that they should be the same as the largest one
    #[quickcheck]
    fn addition(deg1: usize, deg2: usize) {
        let p1 = Poly::<Sc>::new(deg1);
        let p2 = Poly::<Sc>::new(deg2);
        let mut res = p1.clone();
        res.add(&p2);

        let (larger, smaller) = if p1.degree() > p2.degree() {
            (&p1, &p2)
        } else {
            (&p2, &p1)
        };

        for i in 0..larger.len() {
            if i < smaller.len() {
                let mut coeff_sum = p1.0[i].clone();
                coeff_sum.add(&p2.0[i]);
                assert_eq!(res.0[i], coeff_sum);
            } else {
                // (this code branch will never get hit when p1.length = p2.length)
                assert_eq!(res.0[i], larger.0[i]);
            }
        }

        // the result has the largest degree
        assert_eq!(res.degree(), larger.degree());
    }

    #[test]
    fn add_zero() {
        let p1 = Poly::<Sc>::new(3);
        let p2 = Poly::<Sc>::zero();
        let mut res = p1.clone();
        res.add(&p2);
        assert_eq!(res, p1);

        let p1 = Poly::<Sc>::zero();
        let p2 = Poly::<Sc>::new(3);
        let mut res = p1.clone();
        res.add(&p2);
        assert_eq!(res, p2);
    }

    #[test]
    fn mul_by_zero() {
        let p1 = Poly::<Sc>::new(3);
        let p2 = Poly::<Sc>::zero();
        let mut res = p1.clone();
        res.mul(&p2);
        assert_eq!(res, Poly::<Sc>::zero());

        let p1 = Poly::<Sc>::zero();
        let p2 = Poly::<Sc>::new(3);
        let mut res = p1.clone();
        res.mul(&p2);
        assert_eq!(res, Poly::<Sc>::zero());
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

        let expected = poly.0[0];
        let computed = recovered.0[0];
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
        let expected = poly.0[0];
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
        let exp = p1.0.iter().fold(Sc::new(), |mut acc, coeff| {
            acc.add(coeff);
            acc
        });
        assert_eq!(exp, f1.value);
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
        let mut l1 = p1.0[0];
        l1.mul(&p2.0[0]);

        // c0 * d1
        let mut l21 = p1.0[0];
        l21.mul(&p2.0[1]);

        // d0 * c1
        let mut l22 = p1.0[1];
        l22.mul(&p2.0[0]);
        let mut l2 = Sc::new();
        l2.add(&l21);
        l2.add(&l22);
        let mut l3 = p1.0[1];
        l3.mul(&p2.0[1]);

        let mut total = Sc::new();
        total.add(&l1);
        total.add(&l2);
        total.add(&l3);
        let res = p3.eval(0);
        assert_eq!(total, res.value);
    }

    #[test]
    fn new_neg_constant() {
        let mut constant = Sc::rand(&mut thread_rng());
        let p = Poly::<Sc>::new_neg_constant(constant);

        constant.negate();
        let v = vec![constant, Sc::one()];
        let res = Poly::from(v);

        assert_eq!(res, p);
    }

    #[test]
    fn commit() {
        let secret = Poly::<Sc>::new(5);

        let coeffs = secret.0.clone();
        let commitment = coeffs
            .iter()
            .map(|coeff| {
                let mut p = G1::one();
                p.mul(coeff);
                p
            })
            .collect::<Vec<_>>();
        let commitment = Poly::from(commitment);

        assert_eq!(commitment, secret.commit::<G1>());
    }
}
