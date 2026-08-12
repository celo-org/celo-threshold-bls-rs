//! # BLS12-377 FFI Bindings for Blind Threshold Signatures.
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use serde::{Serialize, de::DeserializeOwned};
use threshold_bls::{
    poly::Poly,
    serialization,
    sig::{
        BlindScheme, BlindThresholdScheme, Scheme, Share, SignatureScheme, ThresholdScheme, Token,
    },
};

use crate::*;

// Only the test-only `threshold_keygen` deals in share indices.
#[cfg(test)]
use threshold_bls::poly::Idx as Index;

/// FFI buffer for passing variable-length data across the C boundary.
#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct Buffer {
    /// Pointer to the data
    pub ptr: *const u8,
    /// Length of the data in bytes
    pub len: usize,
}

impl From<&[u8]> for Buffer {
    fn from(src: &[u8]) -> Self {
        Self {
            ptr: src.as_ptr(),
            len: src.len(),
        }
    }
}

/// Borrows a buffer the caller supplied as a slice.
///
/// This is the single place where a caller-supplied pointer becomes something
/// Rust reads, so it is where the buffer contract is enforced. A buffer is
/// rejected if the `Buffer` itself is NULL, or if it claims a non-zero length
/// behind a NULL pointer: `slice::from_raw_parts` is undefined behaviour on a
/// NULL pointer, and reading such a buffer as empty would sign or verify a
/// message the caller never supplied. A length of zero is an empty message, the
/// usual C spelling of which is a NULL pointer.
///
/// # Safety
/// A non-NULL `ptr` must point to `len` initialized bytes that stay valid, and
/// unwritten, for as long as the returned slice is used. The lifetime is the
/// caller's to choose, because a raw pointer carries none.
unsafe fn buffer_slice<'a>(buffer: *const Buffer) -> Option<&'a [u8]> {
    let buffer = unsafe { buffer.as_ref() }?;

    if buffer.len == 0 {
        return Some(&[]);
    }
    if buffer.ptr.is_null() {
        return None;
    }

    Some(unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) })
}

/// Hands a Rust allocation to C, giving up ownership of it.
///
/// The vector becomes a boxed slice first because `free_vector` rebuilds the
/// allocation from the pointer and the length alone: it has to be exactly `len`
/// bytes, while a `Vec` only promises to allocate *at least* the capacity it
/// was asked for. `into_boxed_slice` drops any excess.
fn into_raw_bytes(bytes: Vec<u8>) -> (*mut u8, usize) {
    let bytes = bytes.into_boxed_slice();
    let len = bytes.len();

    (Box::into_raw(bytes).cast::<u8>(), len)
}

/// Hands a Rust allocation to C as a `Buffer`, to be freed with `free_vector`.
fn into_buffer(bytes: Vec<u8>) -> Buffer {
    let (ptr, len) = into_raw_bytes(bytes);

    Buffer { ptr, len }
}

/// Opaque handle to a blinding factor produced by `blind`.
///
/// The C surface names this instead of `Token<PrivateKey>`: cbindgen cannot
/// render a generic from another crate — it emits the Rust syntax verbatim,
/// which is not C — and resolving it needs `parse_deps`, which panics on the
/// arkworks generics underneath.
///
/// `repr(transparent)` makes "a pointer to the wrapper is a pointer to the
/// inner value" a guarantee rather than an artefact of the current layout
/// algorithm.
///
/// A blinding factor is the one value the C API hands back that has no
/// serialized form, so it is the only handle here. Everything else crosses the
/// boundary as bytes.
#[repr(transparent)]
pub struct BlindingFactor(Token<PrivateKey>);

///////////////////////////////////////////////////////////////////////////
// User -> Library
///////////////////////////////////////////////////////////////////////////

/// Given a message and a seed, it will blind it and return the blinded message
///
/// * message: A cleartext message which you want to blind
/// * seed: A `SEED_LEN` byte seed for randomness. You can get one securely via
///   `crypto.randomBytes(32)`
/// * blinded_message_out : Pointer to the memory where the blinded message will be written to
/// * blinding_factor_out : Pointer to the object storing the blinding factor
///
/// The `blinding_factor_out` should be saved for unblinding any
/// signatures on `blinded_message_out`. It lives in-memory.
///
/// You should use `free_vector` to free `blinded_message_out` and `destroy_token` to destroy
/// `blinding_factor_out`.
///
/// # Safety
/// - If the same seed is used twice, the blinded result WILL be the same
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
/// - If the seed is shorter than `SEED_LEN` bytes, the function will return false
/// - If the message cannot be blinded, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn blind(
    message: *const Buffer,
    seed: *const Buffer,
    blinded_message_out: *mut Buffer,
    blinding_factor_out: *mut *mut BlindingFactor,
) -> bool {
    if blinded_message_out.is_null() || blinding_factor_out.is_null() {
        return false;
    }
    let Some(message) = (unsafe { buffer_slice(message) }) else {
        return false;
    };
    let Some(seed) = (unsafe { buffer_slice(seed) }) else {
        return false;
    };

    // convert the seed to randomness
    let Some(mut rng) = get_rng(seed) else {
        return false;
    };

    // blind the message with this randomness
    let (blinding_factor, blinded_message_bytes) = match SigScheme::blind_msg(message, &mut rng) {
        Ok(blinded) => blinded,
        Err(_) => return false,
    };

    unsafe { *blinded_message_out = into_buffer(blinded_message_bytes) };
    unsafe { *blinding_factor_out = Box::into_raw(Box::new(BlindingFactor(blinding_factor))) };

    true
}

/// Given a blinded signature and a blinding_factor used for blinding, it returns the signature
/// unblinded
///
/// * blinded_signature: A message which has been blinded or a blind signature
/// * blinding_factor: The blinding_factor used to blind the message
/// * unblinded_signature: Pointer to the memory where the unblinded signature will be written to
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unblind(
    blinded_signature: *const Buffer,
    blinding_factor: *const BlindingFactor,
    unblinded_signature: *mut Buffer,
) -> bool {
    if blinding_factor.is_null() || unblinded_signature.is_null() {
        return false;
    }
    let Some(blinded_signature) = (unsafe { buffer_slice(blinded_signature) }) else {
        return false;
    };

    let blinding_factor = &unsafe { &*blinding_factor }.0;

    let sig = match SigScheme::unblind_sig(blinding_factor, blinded_signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe { *unblinded_signature = into_buffer(sig) };

    true
}

/// Verifies the signature after it has been unblinded. Users will call this on the
/// threshold signature against the full public key
///
/// * public_key: The public key used to sign the message
/// * message: The message which was signed
/// * signature: The signature which was produced on the message
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verify(
    public_key: *const PublicKey,
    message: *const Buffer,
    signature: *const Buffer,
) -> bool {
    if public_key.is_null() {
        return false;
    }
    let Some(message) = (unsafe { buffer_slice(message) }) else {
        return false;
    };
    let Some(signature) = (unsafe { buffer_slice(signature) }) else {
        return false;
    };

    let public_key = unsafe { &*public_key };

    // checks the signature on the message hash
    SigScheme::verify(public_key, message, signature).is_ok()
}

///////////////////////////////////////////////////////////////////////////
// Service -> Library
///////////////////////////////////////////////////////////////////////////

/// Signs the message with the provided private key and returns the signature
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sign(
    private_key: *const PrivateKey,
    message: *const Buffer,
    signature: *mut Buffer,
) -> bool {
    if private_key.is_null() || signature.is_null() {
        return false;
    }
    let Some(message) = (unsafe { buffer_slice(message) }) else {
        return false;
    };

    let private_key = unsafe { &*private_key };

    let sig = match SigScheme::sign(private_key, message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe { *signature = into_buffer(sig) };

    true
}

/// Signs a *blinded* message with the provided private key and returns the signature
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sign_blinded_message(
    private_key: *const PrivateKey,
    message: *const Buffer,
    signature: *mut Buffer,
) -> bool {
    if private_key.is_null() || signature.is_null() {
        return false;
    }
    let Some(message) = (unsafe { buffer_slice(message) }) else {
        return false;
    };

    let private_key = unsafe { &*private_key };

    let sig = match SigScheme::blind_sign(private_key, message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe { *signature = into_buffer(sig) };

    true
}

/// Signs the message with the provided **share** of the private key and returns the **partial**
/// signature.
///
/// * share: The serialized share of the private key, as the holder received it from key
///   generation
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partial_sign(
    share: *const Buffer,
    message: *const Buffer,
    signature: *mut Buffer,
) -> bool {
    if signature.is_null() {
        return false;
    }
    let Some(share) = (unsafe { buffer_slice(share) }) else {
        return false;
    };
    let Some(message) = (unsafe { buffer_slice(message) }) else {
        return false;
    };

    let share: Share<PrivateKey> = match serialization::deserialize(share) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = match SigScheme::partial_sign(&share, message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe { *signature = into_buffer(sig) };

    true
}

/// Signs a *blinded* message with the provided *share* of the private key and returns the
/// *partial blind* signature.
///
/// * share: The serialized share of the private key, as the holder received it from key
///   generation
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partial_sign_blinded_message(
    share: *const Buffer,
    blinded_message: *const Buffer,
    signature: *mut Buffer,
) -> bool {
    if signature.is_null() {
        return false;
    }
    let Some(share) = (unsafe { buffer_slice(share) }) else {
        return false;
    };
    let Some(blinded_message) = (unsafe { buffer_slice(blinded_message) }) else {
        return false;
    };

    let share: Share<PrivateKey> = match serialization::deserialize(share) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = match SigScheme::sign_blind_partial(&share, blinded_message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe { *signature = into_buffer(sig) };

    true
}

///////////////////////////////////////////////////////////////////////////
// Combiner -> Library
///////////////////////////////////////////////////////////////////////////

/// Verifies a partial signature against the public key corresponding to the secret shared
/// polynomial.
///
/// * polynomial: The serialized public commitment polynomial from key generation. It carries
///   its own length, so a separate length argument is not needed.
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partial_verify(
    polynomial: *const Buffer,
    blinded_message: *const Buffer,
    signature: *const Buffer,
) -> bool {
    let Some(polynomial) = (unsafe { buffer_slice(polynomial) }) else {
        return false;
    };
    let Some(blinded_message) = (unsafe { buffer_slice(blinded_message) }) else {
        return false;
    };
    let Some(signature) = (unsafe { buffer_slice(signature) }) else {
        return false;
    };

    let polynomial: Poly<PublicKey> = match serialization::deserialize(polynomial) {
        Ok(p) => p,
        Err(_) => return false,
    };

    SigScheme::partial_verify(&polynomial, blinded_message, signature).is_ok()
}

/// Verifies a partial *blinded* signature against the public key corresponding to the secret shared
/// polynomial.
///
/// * polynomial: The serialized public commitment polynomial from key generation. It carries
///   its own length, so a separate length argument is not needed.
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn partial_verify_blind_signature(
    polynomial: *const Buffer,
    blinded_message: *const Buffer,
    signature: *const Buffer,
) -> bool {
    let Some(polynomial) = (unsafe { buffer_slice(polynomial) }) else {
        return false;
    };
    let Some(blinded_message) = (unsafe { buffer_slice(blinded_message) }) else {
        return false;
    };
    let Some(signature) = (unsafe { buffer_slice(signature) }) else {
        return false;
    };

    let polynomial: Poly<PublicKey> = match serialization::deserialize(polynomial) {
        Ok(p) => p,
        Err(_) => return false,
    };

    SigScheme::verify_blind_partial(&polynomial, blinded_message, signature).is_ok()
}

/// Combines a flattened vector of partial signatures to a single threshold signature
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
/// - If the flattened buffer is not a whole number of `PARTIAL_SIG_LENGTH` chunks, the function
///   will return false
/// - This function does not check if the signatures are valid!
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn combine(
    threshold: usize,
    signatures: *const Buffer,
    asig: *mut Buffer,
) -> bool {
    if asig.is_null() {
        return false;
    }
    let Some(signatures) = (unsafe { buffer_slice(signatures) }) else {
        return false;
    };

    // The caller flattens the partial signatures, so the boundaries between
    // them are implied by the length alone. A remainder means the flattening
    // was wrong, and every chunk after the first mistake is cut from the middle
    // of two partials.
    if !signatures.len().is_multiple_of(PARTIAL_SIG_LENGTH) {
        return false;
    }

    // split the flattened vector to a Vec<Vec<u8>> where each element is a serialized signature
    let sigs = signatures
        .chunks(PARTIAL_SIG_LENGTH)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let signature = match SigScheme::aggregate(threshold, &sigs) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe { *asig = into_buffer(signature) };

    true
}

///////////////////////////////////////////////////////////////////////////
// Serialization
///////////////////////////////////////////////////////////////////////////

#[unsafe(no_mangle)]
/// Deserializes a public key from the provided buffer
///
/// * pubkey_buf: A buffer of exactly `PUBKEY_LEN` bytes
/// * pubkey: Pointer to the memory where the public key handle will be written to
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
/// - If the buffer does not hold exactly `PUBKEY_LEN` bytes, the function will return false
///
/// Returns true if successful, otherwise false.
pub unsafe extern "C" fn deserialize_pubkey(
    pubkey_buf: *const Buffer,
    pubkey: *mut *mut PublicKey,
) -> bool {
    unsafe { deserialize(pubkey_buf, PUBKEY_LEN, pubkey) }
}

#[unsafe(no_mangle)]
/// Deserializes a private key from the provided buffer
///
/// * privkey_buf: A buffer of exactly `PRIVKEY_LEN` bytes
/// * privkey: Pointer to the memory where the private key handle will be written to
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
/// - If the buffer does not hold exactly `PRIVKEY_LEN` bytes, the function will return false
///
/// Returns true if successful, otherwise false.
pub unsafe extern "C" fn deserialize_privkey(
    privkey_buf: *const Buffer,
    privkey: *mut *mut PrivateKey,
) -> bool {
    unsafe { deserialize(privkey_buf, PRIVKEY_LEN, privkey) }
}

#[unsafe(no_mangle)]
/// Deserializes a signature from the provided buffer
///
/// * sig_buf: A buffer of exactly `SIGNATURE_LEN` bytes
/// * sig: Pointer to the memory where the signature handle will be written to
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
/// - If the buffer does not hold exactly `SIGNATURE_LEN` bytes, the function will return false
///
/// Returns true if successful, otherwise false.
pub unsafe extern "C" fn deserialize_sig(sig_buf: *const Buffer, sig: *mut *mut Signature) -> bool {
    unsafe { deserialize(sig_buf, SIGNATURE_LEN, sig) }
}

#[unsafe(no_mangle)]
/// Serializes a public key to the provided buffer
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
pub unsafe extern "C" fn serialize_pubkey(
    pubkey: *const PublicKey,
    pubkey_buf: *mut *mut u8,
) -> bool {
    unsafe { serialize(pubkey, PUBKEY_LEN, pubkey_buf) }
}

#[unsafe(no_mangle)]
/// Serializes a private key to the provided buffer
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
pub unsafe extern "C" fn serialize_privkey(
    privkey: *const PrivateKey,
    privkey_buf: *mut *mut u8,
) -> bool {
    unsafe { serialize(privkey, PRIVKEY_LEN, privkey_buf) }
}

#[unsafe(no_mangle)]
/// Serializes a signature to the provided buffer
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
///
/// Returns true if successful, otherwise false.
pub unsafe extern "C" fn serialize_sig(sig: *const Signature, sig_buf: *mut *mut u8) -> bool {
    unsafe { serialize(sig, SIGNATURE_LEN, sig_buf) }
}

// The null and length checks live here rather than in the six exported wrappers
// so that no call site can omit them; every wrapper documents both.
//
// `len` is the serialized size of `T`, and the buffer has to hold exactly that.
// All three values are fixed-size, so a buffer of any other length is the
// caller holding something else — and reading `len` bytes from it, which a
// pointer without a length left no way to avoid, runs off the end of their
// allocation.
unsafe fn deserialize<T: DeserializeOwned>(
    in_buf: *const Buffer,
    len: usize,
    out: *mut *mut T,
) -> bool {
    if out.is_null() {
        return false;
    }

    let Some(buf) = (unsafe { buffer_slice(in_buf) }) else {
        return false;
    };
    if buf.len() != len {
        return false;
    }

    let obj = if let Ok(res) = serialization::deserialize(buf) {
        res
    } else {
        return false;
    };

    unsafe { *out = Box::into_raw(Box::new(obj)) };

    true
}

// `len` is the size the caller will hand to `free_vector`, which it takes from
// the constant in the header rather than from this function — nothing here
// reports a length. Serializing to any other size would leave the caller freeing
// an allocation of the wrong size, so refuse instead.
unsafe fn serialize<T: Serialize>(in_obj: *const T, len: usize, out_bytes: *mut *mut u8) -> bool {
    if in_obj.is_null() || out_bytes.is_null() {
        return false;
    }

    let obj = unsafe { &*in_obj };
    let marshalled = if let Ok(res) = bincode::serialize(obj) {
        res
    } else {
        return false;
    };
    if marshalled.len() != len {
        return false;
    }

    let (bytes, _) = into_raw_bytes(marshalled);
    unsafe {
        *out_bytes = bytes;
    };

    true
}

#[unsafe(no_mangle)]
/// Frees the memory allocated for the blinding factor
///
/// # Safety
///
/// The pointer must be NULL, or point to a valid instance of the data type that
/// has not already been freed. Freeing a pointer twice corrupts the heap; NULL
/// does nothing.
pub unsafe extern "C" fn destroy_token(token: *mut BlindingFactor) {
    if token.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(token) });
}

#[unsafe(no_mangle)]
/// Frees the memory allocated for the keypair helper
///
/// This also frees the keys behind `public_key_ptr` and `private_key_ptr`, which
/// borrow from the keypair rather than owning their memory.
///
/// # Safety
///
/// The pointer must be NULL, or point to a valid instance of the data type that
/// has not already been freed. Freeing a pointer twice corrupts the heap; NULL
/// does nothing.
pub unsafe extern "C" fn destroy_keypair(keypair: *mut Keypair) {
    if keypair.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(keypair) });
}

#[unsafe(no_mangle)]
/// Frees the memory allocated for a private key
///
/// # Safety
///
/// The pointer must be NULL, or come from `deserialize_privkey` and not have
/// been freed already. In particular it must not come from `private_key_ptr`,
/// which borrows from a keypair instead of allocating. Freeing a pointer twice
/// corrupts the heap; NULL does nothing.
pub unsafe extern "C" fn destroy_privkey(private_key: *mut PrivateKey) {
    if private_key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(private_key) });
}

#[unsafe(no_mangle)]
/// Frees the memory allocated for a vector
///
/// Takes a const pointer so that a caller can pass `Buffer::ptr` straight back
/// without casting away the qualifier to free its own buffer.
///
/// # Safety
///
/// The pointer must be NULL, or be one this library handed out together with
/// the exact length it reported for it: the allocation is reconstructed from
/// the two, so a different length frees a different allocation. Freeing a
/// pointer twice corrupts the heap; NULL does nothing.
pub unsafe extern "C" fn free_vector(bytes: *const u8, len: usize) {
    if bytes.is_null() {
        return;
    }
    // Reconstructed as the boxed slice `into_raw_bytes` handed out, whose
    // allocation is exactly `len` bytes.
    let bytes = std::ptr::slice_from_raw_parts_mut(bytes as *mut u8, len);
    drop(unsafe { Box::from_raw(bytes) });
}

#[unsafe(no_mangle)]
/// Frees the memory allocated for a public key
///
/// # Safety
///
/// The pointer must be NULL, or come from `deserialize_pubkey` and not have
/// been freed already. In particular it must not come from `public_key_ptr`,
/// which borrows from a keypair instead of allocating. Freeing a pointer twice
/// corrupts the heap; NULL does nothing.
pub unsafe extern "C" fn destroy_pubkey(public_key: *mut PublicKey) {
    if public_key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(public_key) });
}

#[unsafe(no_mangle)]
/// Frees the memory allocated for a signature
///
/// # Safety
///
/// The pointer must be NULL, or point to a valid instance of the data type that
/// has not already been freed. Freeing a pointer twice corrupts the heap; NULL
/// does nothing.
pub unsafe extern "C" fn destroy_sig(signature: *mut Signature) {
    if signature.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(signature) });
}

///////////////////////////////////////////////////////////////////////////
// Helpers
//
// These should be exposed behind a helper module and should not be made part
// of the public API
///////////////////////////////////////////////////////////////////////////

/// Generates a t-of-n polynomial and private key shares.
///
/// WARNING: Trustful central keygen — intended only for local testing. Production
/// deployments should use a DKG protocol so no single party ever holds the master
/// secret.
#[cfg(test)]
fn threshold_keygen(n: usize, t: usize, seed: &[u8]) -> Keys {
    let mut rng = get_rng(seed).expect("the tests seed this with at least SEED_LEN bytes");
    let private = Poly::<PrivateKey>::new_from(t - 1, &mut rng);
    let shares = (0..n)
        .map(|i| private.eval(i as Index))
        .map(|e| Share {
            index: e.index,
            private: e.value,
        })
        .collect();
    let polynomial: Poly<PublicKey> = private.commit();
    let threshold_public_key = polynomial.public_key().clone();

    Keys {
        shares,
        polynomial,
        threshold_public_key,
    }
}

/// Generates a single private key from the provided seed.
///
/// The return value should be destroyed with `destroy_keypair`.
///
/// # Safety
/// - **This function will dereference the provided pointers. If any invalid pointers are passed
///   then the software will crash**.
/// - If NULL pointers are passed, the function will return false
/// - If the seed is shorter than `SEED_LEN` bytes, the function will return false
///
/// Returns true if successful, otherwise false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keygen(seed: *const Buffer, keypair: *mut *mut Keypair) -> bool {
    if keypair.is_null() {
        return false;
    }
    let Some(seed) = (unsafe { buffer_slice(seed) }) else {
        return false;
    };

    let Some(mut rng) = get_rng(seed) else {
        return false;
    };
    let (private, public) = SigScheme::keypair(&mut rng);
    let keypair_local = Keypair { private, public };
    unsafe { *keypair = Box::into_raw(Box::new(keypair_local)) };

    true
}

/// Gets a pointer to the public key corresponding to the provided `KeyPair` pointer
///
/// The key is **borrowed from the keypair**, not a separate allocation: it stays
/// valid until `destroy_keypair` and must never be passed to `destroy_pubkey`,
/// which would free memory that was never allocated on its own and leave
/// `destroy_keypair` to free it a second time.
///
/// # Safety
/// The provided pointer will be dereferenced, so there must be valid data beneath it.
/// Returns NULL if a NULL keypair is passed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn public_key_ptr(keypair: *const Keypair) -> *const PublicKey {
    match unsafe { keypair.as_ref() } {
        Some(keypair) => &keypair.public,
        None => std::ptr::null(),
    }
}

/// Gets a pointer to the private key corresponding to the provided `KeyPair` pointer
///
/// The key is **borrowed from the keypair**, not a separate allocation: it stays
/// valid until `destroy_keypair` and must never be passed to `destroy_privkey`,
/// which would free memory that was never allocated on its own and leave
/// `destroy_keypair` to free it a second time.
///
/// # Safety
/// The provided pointer will be dereferenced, so there must be valid data beneath it.
/// Returns NULL if a NULL keypair is passed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn private_key_ptr(keypair: *const Keypair) -> *const PrivateKey {
    match unsafe { keypair.as_ref() } {
        Some(keypair) => &keypair.private,
        None => std::ptr::null(),
    }
}

/// T-of-n threshold key parameters. Test-only helper produced by the central
/// `threshold_keygen` — not exposed across the FFI boundary.
#[cfg(test)]
#[derive(Debug, Clone)]
struct Keys {
    shares: Vec<Share<PrivateKey>>,
    polynomial: Poly<PublicKey>,
    threshold_public_key: PublicKey,
}

#[derive(Clone)]
// Deliberately not `repr(C)`: the fields are arkworks-backed types that are not
// themselves `repr(C)`, and no C code is entitled to their offsets. C only ever
// holds a `Keypair *` and reaches the keys through `public_key_ptr` /
// `private_key_ptr`, which do Rust field projection inside this crate.
/// A BLS12-377 Keypair
pub struct Keypair {
    /// The private key
    private: PrivateKey,
    /// The public key
    public: PublicKey,
}

/// Seeds the RNG, reporting a seed shorter than `SEED_LEN` as `None`, which the
/// exports turn into `false`. See [`crate::seed_from_slice`].
fn get_rng(digest: &[u8]) -> Option<impl RngCore> {
    Some(ChaChaRng::from_seed(seed_from_slice(digest)?))
}

// The general pattern in these FFI tests is:
// 1. create a MaybeUninit pointer
// 2. pass it to the function
// 3. assert that the function call was successful
// 4. assume the pointer is now initialized
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn threshold_verify_ffi() {
        threshold_verify_ffi_should_blind(true);
        threshold_verify_ffi_should_blind(false);
    }

    fn threshold_verify_ffi_should_blind(should_blind: bool) {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let msg = vec![1u8, 2, 3, 4, 6];
        let user_seed = &b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"[..];
        let empty_token = BlindingFactor(Token::new());
        let partial_sign_fn = if should_blind {
            partial_sign_blinded_message
        } else {
            partial_sign
        };
        let partial_verify_fn = if should_blind {
            partial_verify_blind_signature
        } else {
            partial_verify
        };

        let (n, t) = (5, 3);
        let keys = threshold_keygen(n, t, &seed[..]);

        let (message_to_sign, blinding_factor) = if should_blind {
            let mut blinded_message = MaybeUninit::<Buffer>::uninit();
            let mut blinding_factor = MaybeUninit::<*mut BlindingFactor>::uninit();
            assert!(unsafe {
                blind(
                    &Buffer::from(msg.as_ref()),
                    &Buffer::from(user_seed),
                    blinded_message.as_mut_ptr(),
                    blinding_factor.as_mut_ptr(),
                )
            });
            let blinded_message = unsafe { blinded_message.assume_init() };
            let blinding_factor = unsafe { &*blinding_factor.assume_init() };

            (blinded_message, blinding_factor)
        } else {
            (Buffer::from(&msg[..]), &empty_token)
        };

        // 2. partially sign the blinded message
        //
        // The C surface takes the share as bytes, the form a signer receives it
        // in from key generation.
        let shares: Vec<Vec<u8>> = keys
            .shares
            .iter()
            .map(|share| bincode::serialize(share).unwrap())
            .collect();
        let mut sigs = Vec::new();
        for share in shares.iter().take(t) {
            let share = Buffer::from(&share[..]);
            let mut partial_sig = MaybeUninit::<Buffer>::uninit();
            let ret =
                unsafe { partial_sign_fn(&share, &message_to_sign, partial_sig.as_mut_ptr()) };
            assert!(ret);

            let partial_sig = unsafe { partial_sig.assume_init() };
            sigs.push(partial_sig);
        }

        // 3. verify the partial signatures & concatenate them
        let polynomial = bincode::serialize(&keys.polynomial).unwrap();
        let public_poly = Buffer::from(&polynomial[..]);
        let public_key = &public_poly as *const _;
        let mut concatenated = Vec::new();
        for sig in &sigs {
            let sig_slice = unsafe { buffer_slice(sig) }.unwrap();
            concatenated.extend_from_slice(sig_slice);
            let ret = unsafe { partial_verify_fn(public_key, &message_to_sign, sig) };
            assert!(ret);
        }
        let concatenated = Buffer::from(&concatenated[..]);

        // 4. generate the threshold signature
        let mut asig = MaybeUninit::<Buffer>::uninit();
        let ret = unsafe { combine(t, &concatenated, asig.as_mut_ptr()) };
        assert!(ret);
        let asig = unsafe { asig.assume_init() };

        // 5. unblind the threshold signature
        let asig = if should_blind {
            let mut unblinded = MaybeUninit::<Buffer>::uninit();
            let ret = unsafe { unblind(&asig, blinding_factor, unblinded.as_mut_ptr()) };
            assert!(ret);
            unsafe { unblinded.assume_init() }
        } else {
            asig
        };

        // 6. verify the threshold signature against the public key
        let ret = unsafe {
            verify(
                &keys.threshold_public_key as *const _,
                &Buffer::from(&msg[..]),
                &asig,
            )
        };
        assert!(ret);
    }

    // `combine` splits its input into PARTIAL_SIG_LENGTH chunks, so the
    // boundaries between partials are implied by the length alone. A remainder
    // means the caller flattened them wrongly, and chunking it anyway cuts the
    // tail from the middle of two partials.
    //
    // This pins the contract rather than guarding the check: the misaligned
    // tail fails to deserialize as well, and `bool` carries no message to tell
    // the two apart. The wasm test asserts on the error text, which does.
    #[test]
    fn combine_rejects_a_partial_chunk() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let msg = Buffer::from(&[1u8, 9, 6, 9][..]);
        let (n, t) = (5, 3);
        let keys = threshold_keygen(n, t, &seed[..]);

        let mut concatenated = Vec::new();
        for share in keys.shares.iter().take(t) {
            let share = bincode::serialize(share).unwrap();
            let mut partial = MaybeUninit::<Buffer>::uninit();
            assert!(unsafe { partial_sign(&Buffer::from(&share[..]), &msg, partial.as_mut_ptr()) });
            let partial = unsafe { partial.assume_init() };
            concatenated.extend_from_slice(unsafe { buffer_slice(&partial) }.unwrap());
        }
        assert_eq!(concatenated.len(), t * PARTIAL_SIG_LENGTH);

        let mut asig = MaybeUninit::<Buffer>::uninit();
        assert!(unsafe { combine(t, &Buffer::from(&concatenated[..]), asig.as_mut_ptr()) });

        let mut one_over = concatenated.clone();
        one_over.push(0);
        let one_short = &concatenated[..concatenated.len() - 1];
        let mut half_a_partial = concatenated.clone();
        half_a_partial.extend(vec![0u8; PARTIAL_SIG_LENGTH / 2]);

        for wrong in [&one_over[..], one_short, &half_a_partial[..]] {
            let ret = unsafe { combine(t, &Buffer::from(wrong), asig.as_mut_ptr()) };
            assert!(!ret, "combine accepted {} bytes", wrong.len());
        }
    }

    #[test]
    fn verify_ffi() {
        verify_ffi_should_blind(true);
        verify_ffi_should_blind(false);
    }

    fn verify_ffi_should_blind(should_blind: bool) {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let msg = vec![1u8, 2, 3, 4, 6];
        let user_seed = &b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"[..];
        let empty_token = BlindingFactor(Token::new());

        let sign_fn = if should_blind {
            sign_blinded_message
        } else {
            sign
        };

        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
        assert!(unsafe { keygen(&Buffer::from(&seed[..]), keypair.as_mut_ptr()) });
        let keypair = unsafe { &*keypair.assume_init() };

        let (message_to_sign, blinding_factor) = if should_blind {
            let mut blinded_message = MaybeUninit::<Buffer>::uninit();
            let mut blinding_factor = MaybeUninit::<*mut BlindingFactor>::uninit();
            assert!(unsafe {
                blind(
                    &Buffer::from(msg.as_ref()),
                    &Buffer::from(user_seed),
                    blinded_message.as_mut_ptr(),
                    blinding_factor.as_mut_ptr(),
                )
            });
            let blinded_message = unsafe { blinded_message.assume_init() };
            let blinding_factor = unsafe { &*blinding_factor.assume_init() };

            (blinded_message, blinding_factor)
        } else {
            (Buffer::from(&msg[..]), &empty_token)
        };

        let mut sig = MaybeUninit::<Buffer>::uninit();
        let ret = unsafe { sign_fn(private_key_ptr(keypair), &message_to_sign, sig.as_mut_ptr()) };
        assert!(ret);
        let sig = unsafe { sig.assume_init() };

        let sig = if should_blind {
            let mut unblinded = MaybeUninit::<Buffer>::uninit();
            let ret = unsafe { unblind(&sig, blinding_factor, unblinded.as_mut_ptr()) };
            assert!(ret);

            unsafe { unblinded.assume_init() }
        } else {
            sig
        };

        let ret = unsafe { verify(public_key_ptr(keypair), &Buffer::from(&msg[..]), &sig) };
        assert!(ret);
    }

    #[test]
    fn private_key_serialization() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
        assert!(unsafe { keygen(&Buffer::from(&seed[..]), keypair.as_mut_ptr()) });
        let keypair = unsafe { &*keypair.assume_init() };

        let private_key_ptr = unsafe { private_key_ptr(keypair) };
        let private_key = unsafe { &*private_key_ptr };
        let marshalled = bincode::serialize(private_key).unwrap();

        let mut privkey_buf = MaybeUninit::<*mut u8>::uninit();

        let ret = unsafe { serialize_privkey(private_key_ptr, privkey_buf.as_mut_ptr()) };
        assert!(ret);

        let privkey_buf = unsafe { privkey_buf.assume_init() };
        let message = unsafe { std::slice::from_raw_parts(privkey_buf, PRIVKEY_LEN) };
        assert_eq!(marshalled, message);

        let unmarshalled: PrivateKey = serialization::deserialize(message).unwrap();
        assert_eq!(&unmarshalled, private_key);

        let mut de = MaybeUninit::<*mut PrivateKey>::uninit();
        let ret = unsafe { deserialize_privkey(&Buffer::from(message), de.as_mut_ptr()) };
        assert!(ret);
        let de = unsafe { de.assume_init() };

        assert_eq!(private_key, unsafe { &*de });
    }

    #[test]
    fn public_key_serialization() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
        assert!(unsafe { keygen(&Buffer::from(&seed[..]), keypair.as_mut_ptr()) });
        let keypair = unsafe { &*keypair.assume_init() };

        let public_key_ptr = unsafe { public_key_ptr(keypair) };
        let public_key = unsafe { &*public_key_ptr };

        let marshalled = bincode::serialize(public_key).unwrap();

        let mut pubkey_buf = MaybeUninit::<*mut u8>::uninit();

        let ret = unsafe { serialize_pubkey(public_key_ptr, pubkey_buf.as_mut_ptr()) };
        assert!(ret);

        let pubkey_buf = unsafe { pubkey_buf.assume_init() };
        // the serialized result
        let message = unsafe { std::slice::from_raw_parts(pubkey_buf, PUBKEY_LEN) };
        assert_eq!(marshalled, message);

        let unmarshalled: PublicKey = serialization::deserialize(message).unwrap();
        assert_eq!(&unmarshalled, public_key);

        let mut de = MaybeUninit::<*mut PublicKey>::uninit();
        let ret = unsafe { deserialize_pubkey(&Buffer::from(message), de.as_mut_ptr()) };
        assert!(ret);
        let de = unsafe { de.assume_init() };

        assert_eq!(public_key, unsafe { &*de });
    }

    /// The identity is a well-formed encoding, so it still deserializes — the
    /// C ABI's existing guards only cover malformed input. Verification is what
    /// has to reject it.
    #[test]
    fn identity_public_key_verifies_nothing() {
        use threshold_bls::group::Element;

        let identity = bincode::serialize(&PublicKey::new()).unwrap();
        assert_eq!(identity.len(), PUBKEY_LEN);

        let mut pubkey = MaybeUninit::<*mut PublicKey>::uninit();
        let ret = unsafe { deserialize_pubkey(&Buffer::from(&identity[..]), pubkey.as_mut_ptr()) };
        assert!(ret, "the identity encoding is well-formed");
        let pubkey = unsafe { pubkey.assume_init() };

        let identity_sig = bincode::serialize(&Signature::new()).unwrap();
        for msg in [&b"attack at dawn"[..], b"totally different", b""] {
            let ret =
                unsafe { verify(pubkey, &Buffer::from(msg), &Buffer::from(&identity_sig[..])) };
            assert!(!ret, "identity public key verified {msg:?}");
        }
    }

    // The six serialize/deserialize functions document that a NULL argument
    // returns false. Before the guards landed in the shared helpers they
    // dereferenced it instead, so `deserialize_pubkey(NULL, &out)` read 96
    // bytes from address zero.
    #[test]
    fn serialization_rejects_null() {
        let mut pubkey_out = MaybeUninit::<*mut PublicKey>::uninit();
        let mut privkey_out = MaybeUninit::<*mut PrivateKey>::uninit();
        let mut sig_out = MaybeUninit::<*mut Signature>::uninit();
        let mut bytes_out = MaybeUninit::<*mut u8>::uninit();

        unsafe {
            assert!(!deserialize_pubkey(
                std::ptr::null(),
                pubkey_out.as_mut_ptr()
            ));
            assert!(!deserialize_privkey(
                std::ptr::null(),
                privkey_out.as_mut_ptr()
            ));
            assert!(!deserialize_sig(std::ptr::null(), sig_out.as_mut_ptr()));

            assert!(!serialize_pubkey(std::ptr::null(), bytes_out.as_mut_ptr()));
            assert!(!serialize_privkey(std::ptr::null(), bytes_out.as_mut_ptr()));
            assert!(!serialize_sig(std::ptr::null(), bytes_out.as_mut_ptr()));
        }
    }

    #[test]
    fn serialization_rejects_null_output() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
        assert!(unsafe { keygen(&Buffer::from(&seed[..]), keypair.as_mut_ptr()) });
        let keypair = unsafe { &*keypair.assume_init() };
        let pubkey = unsafe { public_key_ptr(keypair) };
        let marshalled = bincode::serialize(unsafe { &*pubkey }).unwrap();

        unsafe {
            assert!(!serialize_pubkey(pubkey, std::ptr::null_mut()));
            assert!(!deserialize_pubkey(
                &Buffer::from(&marshalled[..]),
                std::ptr::null_mut()
            ));
        }
    }

    // The three fixed-size deserializes read a constant number of bytes. While
    // they took a bare pointer, a caller holding fewer than that had no way to
    // say so and the read ran off the end of their allocation.
    #[test]
    fn deserialization_rejects_a_wrong_length_buffer() {
        use threshold_bls::group::Element;

        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
        assert!(unsafe { keygen(&Buffer::from(&seed[..]), keypair.as_mut_ptr()) });
        let keypair = unsafe { &*keypair.assume_init() };

        let pubkey = bincode::serialize(unsafe { &*public_key_ptr(keypair) }).unwrap();
        let privkey = bincode::serialize(unsafe { &*private_key_ptr(keypair) }).unwrap();
        let sig = bincode::serialize(&Signature::new()).unwrap();
        let encodings = [
            (pubkey, PUBKEY_LEN),
            (privkey, PRIVKEY_LEN),
            (sig, SIGNATURE_LEN),
        ];

        let mut pubkey_out = MaybeUninit::<*mut PublicKey>::uninit();
        let mut privkey_out = MaybeUninit::<*mut PrivateKey>::uninit();
        let mut sig_out = MaybeUninit::<*mut Signature>::uninit();

        // Each encoding is exactly the length the header states, and is
        // accepted at that length — so the rejections below are the length and
        // nothing else.
        for (encoding, len) in &encodings {
            assert_eq!(encoding.len(), *len);
        }
        unsafe {
            assert!(deserialize_pubkey(
                &Buffer::from(&encodings[0].0[..]),
                pubkey_out.as_mut_ptr()
            ));
            assert!(deserialize_privkey(
                &Buffer::from(&encodings[1].0[..]),
                privkey_out.as_mut_ptr()
            ));
            assert!(deserialize_sig(
                &Buffer::from(&encodings[2].0[..]),
                sig_out.as_mut_ptr()
            ));
        }

        for (encoding, len) in &encodings {
            let mut too_long = encoding.clone();
            too_long.push(0);

            for wrong in [&encoding[..0], &encoding[..len - 1], &too_long[..]] {
                let buffer = Buffer::from(wrong);
                unsafe {
                    assert!(!deserialize_pubkey(&buffer, pubkey_out.as_mut_ptr()));
                    assert!(!deserialize_privkey(&buffer, privkey_out.as_mut_ptr()));
                    assert!(!deserialize_sig(&buffer, sig_out.as_mut_ptr()));
                }
            }
        }
    }

    // Every buffer argument on the C surface reaches Rust through
    // `buffer_slice`, so the whole surface inherits what it rejects.
    #[test]
    fn buffer_slice_validates_the_buffer() {
        let bytes = [1u8, 2, 3];

        assert_eq!(unsafe { buffer_slice(std::ptr::null()) }, None);

        // A length behind a NULL pointer describes memory the caller does not
        // have. Reading it as empty would sign or verify the empty message.
        let lying = Buffer {
            ptr: std::ptr::null(),
            len: bytes.len(),
        };
        assert_eq!(unsafe { buffer_slice(&lying) }, None);

        // An empty buffer, however the caller spells it.
        let empty = Buffer {
            ptr: std::ptr::null(),
            len: 0,
        };
        assert_eq!(unsafe { buffer_slice(&empty) }, Some(&[][..]));
        assert_eq!(
            unsafe { buffer_slice(&Buffer::from(&bytes[..0])) },
            Some(&[][..])
        );

        assert_eq!(
            unsafe { buffer_slice(&Buffer::from(&bytes[..])) },
            Some(&bytes[..])
        );
    }

    /// A buffer claiming a length behind a NULL pointer must be refused by
    /// every entry point that takes one, rather than dereferenced.
    #[test]
    fn entry_points_reject_a_buffer_with_no_memory() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let user_seed = &b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"[..];
        let msg = [1u8, 2, 3, 4, 6];
        let (n, t) = (5, 3);

        // Arguments that work. Every call below is asserted to succeed with
        // these, then repeated with one buffer swapped for one that has no
        // memory behind it, so a `false` is attributable to that swap and not
        // to an argument that would have been rejected anyway.
        let keys = threshold_keygen(n, t, &seed[..]);
        let share_bytes = bincode::serialize(&keys.shares[0]).unwrap();
        let polynomial_bytes = bincode::serialize(&keys.polynomial).unwrap();
        let seed_buffer = Buffer::from(&seed[..]);
        let message = Buffer::from(&msg[..]);
        let share = Buffer::from(&share_bytes[..]);
        let polynomial = Buffer::from(&polynomial_bytes[..]);

        let no_memory = Buffer {
            ptr: std::ptr::null(),
            len: msg.len(),
        };
        let mut out = MaybeUninit::<Buffer>::uninit();
        let mut factor = MaybeUninit::<*mut BlindingFactor>::uninit();

        unsafe {
            let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
            assert!(keygen(&seed_buffer, keypair.as_mut_ptr()));
            assert!(!keygen(&no_memory, keypair.as_mut_ptr()));
            let keypair = keypair.assume_init();
            let (privkey, pubkey) = (private_key_ptr(keypair), public_key_ptr(keypair));

            assert!(sign(privkey, &message, out.as_mut_ptr()));
            assert!(!sign(privkey, &no_memory, out.as_mut_ptr()));
            let signature = out.assume_init_read();

            assert!(verify(pubkey, &message, &signature));
            assert!(!verify(pubkey, &no_memory, &signature));
            assert!(!verify(pubkey, &message, &no_memory));

            assert!(blind(
                &message,
                &Buffer::from(user_seed),
                out.as_mut_ptr(),
                factor.as_mut_ptr()
            ));
            assert!(!blind(
                &no_memory,
                &Buffer::from(user_seed),
                out.as_mut_ptr(),
                factor.as_mut_ptr()
            ));
            assert!(!blind(
                &message,
                &no_memory,
                out.as_mut_ptr(),
                factor.as_mut_ptr()
            ));
            let blinded = out.assume_init_read();
            let blinding_factor = factor.assume_init();

            assert!(sign_blinded_message(privkey, &blinded, out.as_mut_ptr()));
            assert!(!sign_blinded_message(privkey, &no_memory, out.as_mut_ptr()));
            let blind_signature = out.assume_init_read();

            assert!(unblind(&blind_signature, blinding_factor, out.as_mut_ptr()));
            assert!(!unblind(&no_memory, blinding_factor, out.as_mut_ptr()));
            let unblinded = out.assume_init_read();

            assert!(partial_sign(&share, &message, out.as_mut_ptr()));
            assert!(!partial_sign(&no_memory, &message, out.as_mut_ptr()));
            assert!(!partial_sign(&share, &no_memory, out.as_mut_ptr()));
            let partial = out.assume_init_read();

            assert!(partial_verify(&polynomial, &message, &partial));
            assert!(!partial_verify(&no_memory, &message, &partial));
            assert!(!partial_verify(&polynomial, &no_memory, &partial));
            assert!(!partial_verify(&polynomial, &message, &no_memory));

            assert!(partial_sign_blinded_message(
                &share,
                &blinded,
                out.as_mut_ptr()
            ));
            assert!(!partial_sign_blinded_message(
                &no_memory,
                &blinded,
                out.as_mut_ptr()
            ));
            assert!(!partial_sign_blinded_message(
                &share,
                &no_memory,
                out.as_mut_ptr()
            ));
            let blind_partial = out.assume_init_read();

            assert!(partial_verify_blind_signature(
                &polynomial,
                &blinded,
                &blind_partial
            ));
            assert!(!partial_verify_blind_signature(
                &no_memory,
                &blinded,
                &blind_partial
            ));
            assert!(!partial_verify_blind_signature(
                &polynomial,
                &no_memory,
                &blind_partial
            ));
            assert!(!partial_verify_blind_signature(
                &polynomial,
                &blinded,
                &no_memory
            ));

            // `combine` needs a threshold's worth of partials, so build them
            // from the remaining shares.
            let mut concatenated = Vec::new();
            for share in keys.shares.iter().take(t) {
                let share_bytes = bincode::serialize(share).unwrap();
                assert!(partial_sign(
                    &Buffer::from(&share_bytes[..]),
                    &message,
                    out.as_mut_ptr()
                ));
                let partial = out.assume_init_read();
                concatenated.extend_from_slice(buffer_slice(&partial).unwrap());
                free_vector(partial.ptr, partial.len);
            }
            let partials = Buffer::from(&concatenated[..]);
            assert!(combine(t, &partials, out.as_mut_ptr()));
            assert!(!combine(t, &no_memory, out.as_mut_ptr()));
            let combined = out.assume_init_read();

            for buffer in [
                signature,
                blinded,
                blind_signature,
                unblinded,
                partial,
                blind_partial,
                combined,
            ] {
                free_vector(buffer.ptr, buffer.len);
            }
            destroy_token(blinding_factor);
            destroy_keypair(keypair);
        }
    }

    // A seed too short to fill the RNG's state used to be sliced to length,
    // which panicked — and a panic crossing `extern "C"` aborts the process the
    // library was called from, which for the mobile consumer is the whole app.
    #[test]
    fn a_short_seed_is_rejected() {
        let short = [7u8; SEED_LEN - 1];
        let msg = [1u8, 2, 3, 4, 6];
        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();
        let mut blinded = MaybeUninit::<Buffer>::uninit();
        let mut blinding_factor = MaybeUninit::<*mut BlindingFactor>::uninit();

        unsafe {
            assert!(!keygen(&Buffer::from(&short[..]), keypair.as_mut_ptr()));
            assert!(!keygen(&Buffer::from(&short[..0]), keypair.as_mut_ptr()));

            assert!(!blind(
                &Buffer::from(&msg[..]),
                &Buffer::from(&short[..]),
                blinded.as_mut_ptr(),
                blinding_factor.as_mut_ptr()
            ));
        }
    }

    // The whole seed is consumed, so the exact length is enough: the check is
    // not off by one in the other direction.
    #[test]
    fn a_seed_of_exactly_the_required_length_is_accepted() {
        let seed = [7u8; SEED_LEN];
        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();

        unsafe {
            assert!(keygen(&Buffer::from(&seed[..]), keypair.as_mut_ptr()));
            destroy_keypair(keypair.assume_init());
        }
    }

    // `keygen` used to return void, so a caller had no way to learn that it had
    // written nothing.
    #[test]
    fn keygen_reports_failure() {
        let seed = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut keypair = MaybeUninit::<*mut Keypair>::uninit();

        unsafe {
            assert!(!keygen(std::ptr::null(), keypair.as_mut_ptr()));
            assert!(!keygen(&Buffer::from(&seed[..]), std::ptr::null_mut()));
        }
    }

    #[test]
    fn key_accessors_reject_null() {
        unsafe {
            assert!(public_key_ptr(std::ptr::null()).is_null());
            assert!(private_key_ptr(std::ptr::null()).is_null());
        }
    }

    // Freeing NULL is a no-op in C, and callers rely on it: a cleanup path that
    // runs after a failed allocation has nothing else to pass.
    #[test]
    fn destructors_accept_null() {
        unsafe {
            destroy_token(std::ptr::null_mut());
            destroy_keypair(std::ptr::null_mut());
            destroy_privkey(std::ptr::null_mut());
            destroy_pubkey(std::ptr::null_mut());
            destroy_sig(std::ptr::null_mut());
            free_vector(std::ptr::null(), 0);
            free_vector(std::ptr::null(), 32);
        }
    }

    // `free_vector` rebuilds the allocation from the pointer and the length, so
    // handing C a `Vec` with spare capacity would free fewer bytes than were
    // allocated. Only a sanitizer sees the mismatch, so what this test pins is
    // that the slack is gone before the pointer leaves Rust.
    #[test]
    fn buffers_handed_to_c_are_exactly_sized() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[1, 2, 3]);
        assert!(
            bytes.capacity() > bytes.len(),
            "the test needs a vector with spare capacity"
        );

        let buffer = into_buffer(bytes);
        assert_eq!(buffer.len, 3);
        assert_eq!(unsafe { buffer_slice(&buffer) }, Some(&[1u8, 2, 3][..]));

        unsafe { free_vector(buffer.ptr, buffer.len) };
    }
}
