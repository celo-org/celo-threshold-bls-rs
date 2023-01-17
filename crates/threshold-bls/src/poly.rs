use crate::group::{Curve, Element, Point, Scalar};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// get returns the given coefficient at the requested index. It will panic
    /// if the index is out of range,i.e. `if i > self.degree()`.
    pub fn get(&self, i: Idx) -> C {
        self.0[i as usize].clone()
    }

    /// set the given element at the specified index. The index 0 is the free
    /// coefficient of the polynomial. It panics if the index is out of range.
    pub fn set(&mut self, index: usize, value: C) {
        self.0[index] = value;
    }

    /// Returns a new polynomial of the given degree where each coefficients is
    /// sampled at random.
    ///
    /// In the context of secret sharing, the threshold is the degree + 1.
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

        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| a.add(b))
    }
}

#[derive(Debug, Error)]
pub enum PolyError {
    #[error("Invalid recovery: only has {0}/{1} shares")]
    InvalidRecovery(usize, usize),
    #[error("Could not invert scalar")]
    NoInverse,
}

impl<C> Poly<C>
where
    C: Element,
    C::RHS: Scalar<RHS = C::RHS>,
{
    /// Evaluates the polynomial at the specified value.
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

    /// Given at least `t` polynomial evaluations, it will recover the polynomial's
    /// constant term
    pub fn recover(t: usize, shares: Vec<Eval<C>>) -> Result<C, PolyError> {
        let xs = Self::share_map(t, shares)?;

        // iterate over all indices and for each multiply the lagrange basis
        // with the value of the share
        let mut acc = C::zero();
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

            let inv = den.inverse().ok_or(PolyError::NoInverse)?;
            num.mul(&inv);
            yi.mul(&num);
            acc.add(&yi);
        }

        Ok(acc)
    }

    /// Given at least `t` polynomial evaluations, it will recover the entire polynomial
    pub fn full_recover(t: usize, shares: Vec<Eval<C>>) -> Result<Self, PolyError> {
        let xs = Self::share_map(t, shares)?;

        // iterate over all indices and for each multiply the lagrange basis
        // with the value of the share
        let res = xs
            .iter()
            // get the share and the lagrange basis
            .map(|(i, share)| (share, Poly::<C::RHS>::lagrange_basis(*i, &xs)))
            // get the linear combination poly
            .map(|(share, basis)| {
                // calculate the linear combination coefficients
                let linear_coeffs = basis
                    .0
                    .into_iter()
                    .map(move |c| {
                        // y_j * L_y
                        // TODO: Can we avoid allocating here?
                        let mut s = share.1.clone();
                        s.mul(&c);
                        s
                    })
                    .collect::<Vec<_>>();

                Self::from(linear_coeffs)
            })
            .fold(Self::zero(), |mut acc, poly| {
                acc.add(&poly);
                acc
            });

        Ok(res)
    }

    fn share_map(
        t: usize,
        mut shares: Vec<Eval<C>>,
    ) -> Result<BTreeMap<Idx, (C::RHS, C)>, PolyError> {
        if shares.len() < t {
            return Err(PolyError::InvalidRecovery(shares.len(), t));
        }

        // first sort the shares as it can happens recovery happens for
        // non-correlated shares so the subset chosen becomes important
        shares.sort_by(|a, b| a.index.cmp(&b.index));

        // convert the indexes of the shares into scalars
        let xs = shares
            .into_iter()
            .take(t)
            .fold(BTreeMap::new(), |mut m, sh| {
                let mut xi = C::RHS::new();
                xi.set_int((sh.index + 1).into());
                m.insert(sh.index, (xi, sh.value));
                m
            });

        debug_assert_eq!(xs.len(), t);

        Ok(xs)
    }

    /// Returns the constant term of the polynomial which can be interpreted as
    /// the threshold public key
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

impl<X: Scalar<RHS = X>> Poly<X> {
    /// Performs the multiplication operation.
    ///
    /// Note this is a simple implementation that is suitable for secret sharing schemes,
    /// but may be inneficient for other purposes: the degree of the returned polynomial
    /// is always the greatest possible, regardless of the actual coefficients
    /// given.
    // TODO: Implement divide and conquer algorithm
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
    fn lagrange_basis<E: Element<RHS = X>>(i: Idx, xs: &BTreeMap<Idx, (X, E)>) -> Poly<X> {
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

    /// Commits the scalar polynomial to the group and returns a polynomial over
    /// the group
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::curve::bls12377::Scalar as Sc;
    use crate::curve::bls12377::G1;
    use rand::prelude::*;

    #[test]
    fn poly_degree() {
        let s = 5;
        let p = Poly::<Sc>::new(s);
        assert_eq!(p.0.len(), s + 1);
        assert_eq!(p.degree(), s);
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
        let mut res = p1;
        res.add(&p2);
        assert_eq!(res, p2);
    }

    #[test]
    fn mul_by_zero() {
        let p1 = Poly::<Sc>::new(3);
        let p2 = Poly::<Sc>::zero();
        let mut res = p1;
        res.mul(&p2);
        assert_eq!(res, Poly::<Sc>::zero());

        let p1 = Poly::<Sc>::zero();
        let p2 = Poly::<Sc>::new(3);
        let mut res = p1;
        res.mul(&p2);
        assert_eq!(res, Poly::<Sc>::zero());
    }

    use proptest::prelude::*;

    proptest! {

    // the coefficients up to the smaller polynomial's degree should be summed up,
    // after that they should be the same as the largest one
    #[test]
    fn addition(deg1 in 0..100usize, deg2 in 0..100usize) {
        dbg!(deg1, deg2);
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
                let mut coeff_sum = p1.0[i];
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
    fn interpolation(degree in 0..100usize, num_evals in 0..100usize) {
        let poly = Poly::<Sc>::new(degree);
        let expected = poly.0[0];

        let shares = (0..num_evals)
            .map(|i| poly.eval(i as Idx))
            .collect::<Vec<_>>();

        let recovered_poly = Poly::<Sc>::full_recover(num_evals, shares.clone()).unwrap();
        let computed = recovered_poly.0[0];

        let recovered_constant = Poly::<Sc>::recover(num_evals, shares).unwrap();

        // if we had enough evaluations we must get the correct term
        if num_evals > degree {
            assert_eq!(expected, computed);
            assert_eq!(expected, recovered_constant);
        } else {
            // if there were not enough evaluations, then the call will still succeed
            // but will return a mismatching recovered term
            assert_ne!(expected, computed);
            assert_ne!(expected, recovered_constant);
        }
    }

    #[test]
    fn eval(d in 0..100usize, idx in 0..100_u32) {
        let mut x = Sc::new();
        x.set_int(idx as u64 + 1);

        let p1 = Poly::<Sc>::new(d);
        let evaluation = p1.eval(idx).value;

        // Naively calculate \sum c_i * x^i
        let coeffs = p1.0;
        let mut sum = coeffs[0];
        for (i, coeff) in coeffs.into_iter().enumerate().take(d + 1).skip(1) {
            let xi = pow(x, i);
            let mut var = coeff;
            var.mul(&xi);
            sum.add(&var);
        }

        assert_eq!(sum, evaluation);

        // helper to calculate the power of x
        fn pow(base: Sc, pow: usize) -> Sc {
            let mut res = Sc::one();
            for _ in 0..pow {
                res.mul(&base)
            }
            res
        }
    }

    }

    #[test]
    fn interpolation_insufficient_shares() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = Poly::<Sc>::new(degree);

        // insufficient shares gathered
        let shares = (0..threshold - 1)
            .map(|i| poly.eval(i as Idx))
            .collect::<Vec<_>>();

        Poly::<Sc>::recover(threshold, shares.clone()).unwrap_err();
        Poly::<Sc>::full_recover(threshold, shares).unwrap_err();
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
