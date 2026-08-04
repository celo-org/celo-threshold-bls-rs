use crate::group::{Element, Point, Scalar};
use crate::serialization;
use crate::sig::bls::{common::BLSScheme, BLSError};
use crate::sig::{BlindScheme, Scheme};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// BlindError are errors which may be returned from a blind signature scheme
#[derive(Debug, Error)]
pub enum BlindError {
    /// InvalidToken is thrown out when the token used to unblind can not be
    /// inversed. This error should not happen if you use the Token that was
    /// returned by the blind operation.
    #[error("invalid token")]
    InvalidToken,

    /// Raised when (de)serialization fails
    #[error("could not deserialize: {0}")]
    BincodeError(#[from] bincode::Error),

    #[error("invalid signature verification: {0}")]
    SignatureError(#[from] BLSError),
}

/// Blinding a message before requesting a signature requires the usage of a
/// private blinding factor that is called a Token. To unblind the signature
/// afterwards, one needs the same token as what the blinding method returned.
/// In this blind signature scheme, the token is simply a field element.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "S: Serialize + serde::de::DeserializeOwned")]
pub struct Token<S: Scalar>(S);

impl<S: Scalar> Default for Token<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Scalar> Token<S> {
    /// Instantiates a token with the `Zero` element of the underlying scalar
    pub fn new() -> Self {
        Self(S::new())
    }
}

/// The blinder follows the protocol described
/// in this [paper](https://eprint.iacr.org/2018/733.pdf).
impl<I> BlindScheme for I
where
    I: Scheme + BLSScheme,
{
    type Token = Token<I::Private>;
    type Error = BlindError;

    fn blind_msg<R: RngCore>(
        msg: &[u8],
        rng: &mut R,
    ) -> Result<(Self::Token, Vec<u8>), Self::Error> {
        let r = I::Private::rand(rng);

        let mut h = I::Signature::new();

        // r * H(m)
        h.map(msg).map_err(|_| BLSError::HashingError)?;
        h.mul(&r);

        let serialized = bincode::serialize(&h)?;
        Ok((Token(r), serialized))
    }

    fn unblind_sig(t: &Self::Token, sigbuff: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut sig: I::Signature = serialization::deserialize(sigbuff)?;

        // r^-1 * ( r * H(m)^x) = H(m)^x
        let ri = t.0.inverse().ok_or(BlindError::InvalidToken)?;
        sig.mul(&ri);

        let serialized = bincode::serialize(&sig)?;
        Ok(serialized)
    }

    fn blind_verify(
        public: &I::Public,
        blinded_msg: &[u8],
        blinded_sig: &[u8],
    ) -> Result<(), Self::Error> {
        // message point
        let blinded_msg: I::Signature = serialization::deserialize(blinded_msg)?;
        // signature point
        let blinded_sig: I::Signature = serialization::deserialize(blinded_sig)?;

        I::check_pairing(public, &blinded_sig, &blinded_msg).map_err(BlindError::from)
    }

    fn blind_sign(private: &I::Private, blinded_msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // (r * H(m))^x
        let mut hm: I::Signature = serialization::deserialize(blinded_msg)?;
        hm.mul(private);
        Ok(bincode::serialize(&hm)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls12377::PairingCurve as PCurve;
    use crate::sig::bls::{G1Scheme, G2Scheme};
    use crate::sig::SignatureScheme;
    use rand::thread_rng;

    #[test]
    fn blind_g1() {
        blind_test::<G1Scheme<PCurve>>();
    }

    #[test]
    fn blind_g2() {
        blind_test::<G2Scheme<PCurve>>();
    }

    fn blind_test<B>()
    where
        B: BlindScheme + SignatureScheme,
    {
        let (private, public) = B::keypair(&mut thread_rng());
        let msg = vec![1, 9, 6, 9];

        let (token, blinded) = B::blind_msg(&msg, &mut thread_rng()).unwrap();

        // signs the blinded message w/o hashing
        let blinded_sig = B::blind_sign(&private, &blinded).unwrap();
        B::blind_verify(&public, &blinded, &blinded_sig).unwrap();

        let clear_sig = B::unblind_sig(&token, &blinded_sig).expect("unblind should go well");
        B::verify(&public, &msg, &clear_sig).unwrap();
    }

    #[test]
    fn blind_identity_g1() {
        identity_operands_rejected::<G1Scheme<PCurve>>();
    }

    #[test]
    fn blind_identity_g2() {
        identity_operands_rejected::<G2Scheme<PCurve>>();
    }

    /// Unlike plain BLS, `blind_verify` takes the message point from the wire
    /// rather than from `hash_to_curve`. An identity there pairs to 1 on both
    /// sides, so it would otherwise verify under *any* public key, including
    /// honest ones.
    fn identity_operands_rejected<B>()
    where
        B: BlindScheme<Error = BlindError>,
    {
        let (_, public) = B::keypair(&mut thread_rng());
        let identity = bincode::serialize(&B::Signature::new()).unwrap();
        let (_, blinded_msg) = B::blind_msg(&[1, 9, 6, 9], &mut thread_rng()).unwrap();

        assert!(
            matches!(
                B::blind_verify(&public, &identity, &identity),
                Err(BlindError::SignatureError(BLSError::InvalidMessagePoint))
            ),
            "identity blinded message forged a signature under an honest key"
        );

        assert!(matches!(
            B::blind_verify(&B::Public::new(), &blinded_msg, &identity),
            Err(BlindError::SignatureError(BLSError::InvalidPublicKey))
        ));
    }
}
