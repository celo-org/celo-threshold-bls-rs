/*
 * Exercises every function in threshold.h against the real library.
 *
 * This is a regression test that the generated header and the library it
 * describes agree. It catches what the symbol manifest cannot: that compares
 * names, while this compiles against prototypes and checks return values.
 *
 * It guards the bug class that went unnoticed for five years. Reintroducing
 * the old `void keygen(const Buffer *, Keypair *)` declaration makes this file
 * fail to compile — "incompatible pointer types passing 'struct Keypair **' to
 * parameter of type 'struct Keypair *'" — because the calls here are written
 * to the shape the library actually implements. The check is the compiler's
 * type rules, not undefined behaviour at runtime, so it is deterministic.
 *
 * Build and run via `just check-abi`.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "threshold.h"

/*
 * Not assert(): under NDEBUG the standard requires assert to expand to nothing,
 * taking its argument expression with it. Every library call below is made
 * inside one of these, while the free_vector and destroy_* calls that follow
 * are not — so compiling with NDEBUG would skip the calls under test and then
 * free the uninitialised pointers they were meant to fill. CHECK always
 * evaluates its argument.
 */
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #cond); \
            abort();                                                           \
        }                                                                      \
    } while (0)

static const uint8_t SEED[32] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const uint8_t USER_SEED[32] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const uint8_t MESSAGE[5] = {1, 2, 3, 4, 6};

_Static_assert(sizeof SEED == SEED_LEN, "the seeds here must be full length");
_Static_assert(sizeof USER_SEED == SEED_LEN, "the seeds here must be full length");

/*
 * A 3-of-5 threshold key. Key generation is not part of the C API — a trustful
 * central keygen has no place in production — so a signer receives its share
 * out of band, and this vector stands in for that. Only the three shares the
 * test uses are here.
 *
 * Nothing needs to be trusted about these bytes: the final `verify` against
 * THRESHOLD_PUBKEY fails if any of them is wrong. Regenerate with the
 * `threshold_keygen(5, 3, seed)` test helper in ffi.rs, seeded with
 * "threshold-bls C ABI smoke test vector seed, do not reuse".
 */
#define THRESHOLD 3

static const uint8_t SHARE_0[36] = {
    0x00, 0x00, 0x00, 0x00, 0x77, 0xcc, 0xf4, 0x94, 0x36, 0xeb, 0x72, 0xf4,
    0x7d, 0xed, 0xa3, 0x87, 0x8f, 0xdc, 0x30, 0x56, 0x0a, 0xa4, 0xa5, 0xb3,
    0x90, 0x83, 0xa8, 0x9f, 0xbe, 0x79, 0xdd, 0x7e, 0xd9, 0xcf, 0x47, 0x10,
};
static const uint8_t SHARE_1[36] = {
    0x01, 0x00, 0x00, 0x00, 0x16, 0x49, 0x8e, 0x58, 0xf4, 0x4f, 0x16, 0x12,
    0xa4, 0xa1, 0x21, 0x69, 0x07, 0x30, 0x0c, 0xe2, 0x9c, 0xe1, 0x95, 0x68,
    0x54, 0xf6, 0x3a, 0x4a, 0xd2, 0x11, 0x52, 0x0b, 0x79, 0xfc, 0x0d, 0x06,
};
static const uint8_t SHARE_2[36] = {
    0x02, 0x00, 0x00, 0x00, 0x7c, 0x4f, 0x1c, 0x53, 0x85, 0xa6, 0xea, 0x80,
    0x7f, 0xdd, 0x57, 0x75, 0xc3, 0xe7, 0x07, 0xea, 0x61, 0x37, 0x3b, 0xf7,
    0x50, 0x7d, 0x09, 0xe3, 0xc1, 0x08, 0x59, 0x95, 0x11, 0xa1, 0xa4, 0x06,
};
static const uint8_t PUBLIC_POLY[296] = {
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xca, 0x28, 0x04, 0x1f,
    0x03, 0x51, 0x78, 0x78, 0x74, 0x08, 0xa4, 0xa7, 0x79, 0xe6, 0x1a, 0x3b,
    0x9d, 0x6a, 0x34, 0x45, 0x62, 0x5e, 0xc5, 0x23, 0xef, 0xc3, 0xfe, 0xa1,
    0xd8, 0x53, 0xa1, 0x7f, 0x16, 0x90, 0x9b, 0x49, 0xaf, 0x10, 0xe3, 0xd1,
    0x9b, 0xcd, 0x08, 0xf2, 0xd1, 0x1f, 0x37, 0x01, 0x14, 0x2b, 0x54, 0x59,
    0xdc, 0x24, 0x8d, 0x6a, 0x2f, 0x82, 0x41, 0xab, 0x76, 0x23, 0xa3, 0x05,
    0xbc, 0x3a, 0x16, 0xb2, 0xbe, 0x17, 0x23, 0x66, 0x80, 0x28, 0x31, 0xa3,
    0x3b, 0x24, 0xd9, 0xf7, 0xe5, 0x65, 0xa1, 0x80, 0x54, 0xd5, 0xc0, 0xb2,
    0x6f, 0x3c, 0x20, 0xf0, 0xe5, 0x7a, 0x35, 0x81, 0xf5, 0xcc, 0xff, 0xb2,
    0x4b, 0xe4, 0xe8, 0x2f, 0x5a, 0x25, 0xbf, 0xb4, 0xb5, 0x80, 0x84, 0x60,
    0x73, 0x6b, 0x87, 0xf7, 0x5c, 0xd8, 0x90, 0x25, 0xcb, 0x56, 0xf0, 0x1e,
    0x32, 0x17, 0x7f, 0x3d, 0x44, 0xd8, 0xc9, 0x45, 0xa1, 0x92, 0xb0, 0x3d,
    0x35, 0x6b, 0x08, 0x36, 0x3c, 0x2d, 0x88, 0x00, 0xfb, 0x0e, 0x26, 0xe4,
    0x6a, 0x09, 0x3e, 0x32, 0x47, 0x62, 0x96, 0xc7, 0x1f, 0x48, 0xf2, 0x6a,
    0x66, 0x6a, 0xab, 0x2f, 0x2d, 0x0f, 0x80, 0xfa, 0x96, 0x3b, 0xf2, 0x46,
    0x52, 0x74, 0xfb, 0x24, 0x23, 0x92, 0xdf, 0xfa, 0xca, 0x3e, 0x18, 0x0c,
    0x95, 0xf0, 0x1d, 0x7d, 0x60, 0x90, 0x4a, 0x01, 0x5f, 0x8d, 0x69, 0x98,
    0x0e, 0x0f, 0xb0, 0xe8, 0xa6, 0x37, 0x63, 0x47, 0xf3, 0x13, 0x88, 0x80,
    0xae, 0x74, 0x11, 0xb8, 0x10, 0x48, 0x1d, 0x20, 0xef, 0x95, 0x50, 0xd8,
    0x27, 0x76, 0x04, 0x2a, 0x86, 0x52, 0x12, 0xc2, 0xc5, 0x92, 0x01, 0x97,
    0x76, 0x12, 0xad, 0x4f, 0x28, 0x4d, 0x09, 0x00, 0xb0, 0xb5, 0x18, 0xe6,
    0xec, 0x4f, 0x1e, 0x8b, 0xf0, 0x9b, 0xe5, 0xbf, 0x8f, 0xe5, 0x43, 0xb1,
    0x14, 0x26, 0x9f, 0x68, 0xf0, 0x77, 0xe0, 0xbb, 0x9b, 0x80, 0x2f, 0x2d,
    0x5c, 0x20, 0x46, 0xe6, 0xac, 0x88, 0xb2, 0xaf, 0xf0, 0xc1, 0x52, 0x9e,
    0x69, 0x1b, 0xd1, 0x2e, 0x3f, 0xd5, 0xa1, 0x01,
};
static const uint8_t THRESHOLD_PUBKEY[96] = {
    0xca, 0x28, 0x04, 0x1f, 0x03, 0x51, 0x78, 0x78, 0x74, 0x08, 0xa4, 0xa7,
    0x79, 0xe6, 0x1a, 0x3b, 0x9d, 0x6a, 0x34, 0x45, 0x62, 0x5e, 0xc5, 0x23,
    0xef, 0xc3, 0xfe, 0xa1, 0xd8, 0x53, 0xa1, 0x7f, 0x16, 0x90, 0x9b, 0x49,
    0xaf, 0x10, 0xe3, 0xd1, 0x9b, 0xcd, 0x08, 0xf2, 0xd1, 0x1f, 0x37, 0x01,
    0x14, 0x2b, 0x54, 0x59, 0xdc, 0x24, 0x8d, 0x6a, 0x2f, 0x82, 0x41, 0xab,
    0x76, 0x23, 0xa3, 0x05, 0xbc, 0x3a, 0x16, 0xb2, 0xbe, 0x17, 0x23, 0x66,
    0x80, 0x28, 0x31, 0xa3, 0x3b, 0x24, 0xd9, 0xf7, 0xe5, 0x65, 0xa1, 0x80,
    0x54, 0xd5, 0xc0, 0xb2, 0x6f, 0x3c, 0x20, 0xf0, 0xe5, 0x7a, 0x35, 0x81,
};

static const uint8_t *const SHARES[THRESHOLD] = {SHARE_0, SHARE_1, SHARE_2};

static Buffer buf(const uint8_t *ptr, size_t len) {
    Buffer b = {ptr, len};
    return b;
}

/* keygen, the two accessors, sign, verify, destroy_keypair. */
static void plain_signing(void) {
    Buffer seed = buf(SEED, sizeof SEED);
    struct Keypair *keypair = NULL;
    CHECK(keygen(&seed, &keypair));
    CHECK(keypair != NULL);

    const PrivateKey *priv = private_key_ptr(keypair);
    const PublicKey *pub = public_key_ptr(keypair);
    CHECK(priv != NULL && pub != NULL);

    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer signature;
    CHECK(sign(priv, &message, &signature));
    CHECK(verify(pub, &message, &signature));

    /* A signature over a different message must not verify. */
    uint8_t other[sizeof MESSAGE];
    memcpy(other, MESSAGE, sizeof MESSAGE);
    other[0] ^= 0xff;
    Buffer other_message = buf(other, sizeof other);
    CHECK(!verify(pub, &other_message, &signature));

    free_vector(signature.ptr, signature.len);
    destroy_keypair(keypair);
}

/* blind, sign_blinded_message, unblind, destroy_token. */
static void blind_signing(void) {
    Buffer seed = buf(SEED, sizeof SEED);
    struct Keypair *keypair = NULL;
    CHECK(keygen(&seed, &keypair));

    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer user_seed = buf(USER_SEED, sizeof USER_SEED);
    Buffer blinded;
    BlindingFactor *blinding_factor = NULL;
    CHECK(blind(&message, &user_seed, &blinded, &blinding_factor));
    CHECK(blinding_factor != NULL);

    Buffer blind_sig;
    CHECK(sign_blinded_message(private_key_ptr(keypair), &blinded, &blind_sig));

    Buffer signature;
    CHECK(unblind(&blind_sig, blinding_factor, &signature));
    CHECK(verify(public_key_ptr(keypair), &message, &signature));

    free_vector(signature.ptr, signature.len);
    free_vector(blind_sig.ptr, blind_sig.len);
    free_vector(blinded.ptr, blinded.len);
    destroy_token(blinding_factor);
    destroy_keypair(keypair);
}

/* The three serialize/deserialize/destroy triples. */
static void serialization(void) {
    Buffer seed = buf(SEED, sizeof SEED);
    struct Keypair *keypair = NULL;
    CHECK(keygen(&seed, &keypair));

    uint8_t *pub_bytes = NULL;
    CHECK(serialize_pubkey(public_key_ptr(keypair), &pub_bytes));
    Buffer pub_buf = buf(pub_bytes, PUBKEY_LEN);
    PublicKey *pub = NULL;
    CHECK(deserialize_pubkey(&pub_buf, &pub));

    uint8_t *priv_bytes = NULL;
    CHECK(serialize_privkey(private_key_ptr(keypair), &priv_bytes));
    Buffer priv_buf = buf(priv_bytes, PRIVKEY_LEN);
    PrivateKey *priv = NULL;
    CHECK(deserialize_privkey(&priv_buf, &priv));

    /* Round-tripped keys must still work together. */
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer signature;
    CHECK(sign(priv, &message, &signature));
    CHECK(verify(pub, &message, &signature));

    uint8_t *sig_bytes = NULL;
    Signature *sig = NULL;
    CHECK(deserialize_sig(&signature, &sig));
    CHECK(serialize_sig(sig, &sig_bytes));
    CHECK(memcmp(sig_bytes, signature.ptr, SIGNATURE_LEN) == 0);

    free_vector(sig_bytes, SIGNATURE_LEN);
    free_vector(pub_bytes, PUBKEY_LEN);
    free_vector(priv_bytes, PRIVKEY_LEN);
    free_vector(signature.ptr, signature.len);
    destroy_sig(sig);
    destroy_pubkey(pub);
    destroy_privkey(priv);
    destroy_keypair(keypair);
}

/*
 * Signs a message under the threshold key: each share produces a partial, the
 * combiner checks every partial against the public polynomial, and combine
 * interpolates them into one signature that verifies under the threshold
 * public key.
 *
 * combine splits its input into PARTIAL_SIG_LENGTH chunks, so the concatenation
 * below is the reason that constant has to reach C.
 */
static void threshold_signing(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer polynomial = buf(PUBLIC_POLY, sizeof PUBLIC_POLY);
    uint8_t concatenated[THRESHOLD * PARTIAL_SIG_LENGTH];
    Buffer partials[THRESHOLD];

    for (size_t i = 0; i < THRESHOLD; i++) {
        Buffer share = buf(SHARES[i], 36);
        CHECK(partial_sign(&share, &message, &partials[i]));
        CHECK(partials[i].len == PARTIAL_SIG_LENGTH);
        CHECK(partial_verify(&polynomial, &message, &partials[i]));
        memcpy(concatenated + i * PARTIAL_SIG_LENGTH, partials[i].ptr,
               PARTIAL_SIG_LENGTH);
    }

    Buffer flattened = buf(concatenated, sizeof concatenated);
    Buffer threshold_sig;
    CHECK(combine(THRESHOLD, &flattened, &threshold_sig));

    Buffer threshold_pubkey = buf(THRESHOLD_PUBKEY, sizeof THRESHOLD_PUBKEY);
    PublicKey *pub = NULL;
    CHECK(deserialize_pubkey(&threshold_pubkey, &pub));
    CHECK(verify(pub, &message, &threshold_sig));

    /* A partial from one signer is not a signature under the threshold key. */
    CHECK(!verify(pub, &message, &partials[0]));

    free_vector(threshold_sig.ptr, threshold_sig.len);
    for (size_t i = 0; i < THRESHOLD; i++) {
        free_vector(partials[i].ptr, partials[i].len);
    }
    destroy_pubkey(pub);
}

/*
 * The same flow on a blinded message: the signers never see the plaintext, and
 * the combined signature is unblinded before it verifies against it.
 */
static void blind_threshold_signing(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer user_seed = buf(USER_SEED, sizeof USER_SEED);
    Buffer polynomial = buf(PUBLIC_POLY, sizeof PUBLIC_POLY);

    Buffer blinded;
    BlindingFactor *blinding_factor = NULL;
    CHECK(blind(&message, &user_seed, &blinded, &blinding_factor));

    uint8_t concatenated[THRESHOLD * PARTIAL_SIG_LENGTH];
    Buffer partials[THRESHOLD];
    for (size_t i = 0; i < THRESHOLD; i++) {
        Buffer share = buf(SHARES[i], 36);
        CHECK(partial_sign_blinded_message(&share, &blinded, &partials[i]));
        CHECK(partial_verify_blind_signature(&polynomial, &blinded, &partials[i]));
        memcpy(concatenated + i * PARTIAL_SIG_LENGTH, partials[i].ptr,
               PARTIAL_SIG_LENGTH);
    }

    Buffer flattened = buf(concatenated, sizeof concatenated);
    Buffer blinded_sig;
    CHECK(combine(THRESHOLD, &flattened, &blinded_sig));

    Buffer signature;
    CHECK(unblind(&blinded_sig, blinding_factor, &signature));

    Buffer threshold_pubkey = buf(THRESHOLD_PUBKEY, sizeof THRESHOLD_PUBKEY);
    PublicKey *pub = NULL;
    CHECK(deserialize_pubkey(&threshold_pubkey, &pub));
    CHECK(verify(pub, &message, &signature));

    free_vector(signature.ptr, signature.len);
    free_vector(blinded_sig.ptr, blinded_sig.len);
    for (size_t i = 0; i < THRESHOLD; i++) {
        free_vector(partials[i].ptr, partials[i].len);
    }
    free_vector(blinded.ptr, blinded.len);
    destroy_token(blinding_factor);
    destroy_pubkey(pub);
}

/* The threshold operations reject a NULL share or polynomial. */
static void threshold_operations_reject_null(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer signature;

    CHECK(!partial_sign(NULL, &message, &signature));
    CHECK(!partial_sign_blinded_message(NULL, &message, &signature));
    CHECK(!partial_verify(NULL, &message, &message));
    CHECK(!partial_verify_blind_signature(NULL, &message, &message));
    CHECK(!combine(3, NULL, &signature));

    /* Bytes that are not a share or a polynomial are rejected, not trusted. */
    Buffer garbage = buf(MESSAGE, sizeof MESSAGE);
    CHECK(!partial_sign(&garbage, &message, &signature));
    CHECK(!partial_verify(&garbage, &message, &message));
}

/* The NULL contract the header now documents, checked from C. */
static void null_arguments_are_rejected(void) {
    Buffer seed = buf(SEED, sizeof SEED);
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer out;
    BlindingFactor *factor = NULL;
    PublicKey *pub = NULL;
    struct Keypair *keypair = NULL;
    uint8_t *bytes = NULL;

    CHECK(!blind(NULL, &message, &out, &factor));
    CHECK(!unblind(NULL, NULL, &out));
    CHECK(!verify(NULL, &message, &message));
    CHECK(!sign(NULL, &message, &out));
    CHECK(!sign_blinded_message(NULL, &message, &out));
    CHECK(!keygen(NULL, &keypair));
    CHECK(!keygen(&seed, NULL));

    CHECK(!deserialize_pubkey(NULL, &pub));
    CHECK(!deserialize_privkey(NULL, (PrivateKey **)&pub));
    CHECK(!deserialize_sig(NULL, (Signature **)&pub));
    CHECK(!serialize_pubkey(NULL, &bytes));
    CHECK(!serialize_privkey(NULL, &bytes));
    CHECK(!serialize_sig(NULL, &bytes));

    CHECK(public_key_ptr(NULL) == NULL);
    CHECK(private_key_ptr(NULL) == NULL);
}

/*
 * A buffer that claims a length behind a NULL pointer describes memory the
 * caller does not have. Reading it as an empty message would sign or verify
 * something the caller never supplied, so every entry point refuses it.
 *
 * Each call is made once with arguments that work, then again with one buffer
 * replaced, so that `false` means the replacement was caught rather than that
 * the other arguments were bad anyway.
 */
static void buffers_with_no_memory_are_rejected(void) {
    Buffer no_memory = buf(NULL, sizeof MESSAGE);
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer seed = buf(SEED, sizeof SEED);
    Buffer user_seed = buf(USER_SEED, sizeof USER_SEED);
    Buffer share = buf(SHARE_0, 36);
    Buffer polynomial = buf(PUBLIC_POLY, sizeof PUBLIC_POLY);
    BlindingFactor *factor = NULL;
    struct Keypair *keypair = NULL;

    CHECK(keygen(&seed, &keypair));
    CHECK(!keygen(&no_memory, &keypair));

    Buffer signature;
    CHECK(sign(private_key_ptr(keypair), &message, &signature));
    CHECK(!sign(private_key_ptr(keypair), &no_memory, &signature));

    CHECK(verify(public_key_ptr(keypair), &message, &signature));
    CHECK(!verify(public_key_ptr(keypair), &no_memory, &signature));
    CHECK(!verify(public_key_ptr(keypair), &message, &no_memory));

    Buffer blinded;
    CHECK(blind(&message, &user_seed, &blinded, &factor));
    CHECK(!blind(&no_memory, &user_seed, &blinded, &factor));
    CHECK(!blind(&message, &no_memory, &blinded, &factor));

    Buffer partial;
    CHECK(partial_sign(&share, &message, &partial));
    CHECK(!partial_sign(&no_memory, &message, &partial));
    CHECK(!partial_sign(&share, &no_memory, &partial));

    CHECK(partial_verify(&polynomial, &message, &partial));
    CHECK(!partial_verify(&no_memory, &message, &partial));
    CHECK(!partial_verify(&polynomial, &no_memory, &partial));
    CHECK(!partial_verify(&polynomial, &message, &no_memory));

    CHECK(!combine(THRESHOLD, &no_memory, &signature));

    free_vector(partial.ptr, partial.len);
    free_vector(blinded.ptr, blinded.len);
    free_vector(signature.ptr, signature.len);
    destroy_token(factor);
    destroy_keypair(keypair);
}

/*
 * combine splits its input into PARTIAL_SIG_LENGTH chunks, so a caller that
 * flattens the partials wrongly is only visible in the length. The full input
 * is combined first, so `false` means the added byte was caught.
 */
static void misaligned_partials_are_rejected(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    uint8_t concatenated[THRESHOLD * PARTIAL_SIG_LENGTH + 1];
    Buffer partials[THRESHOLD];

    for (size_t i = 0; i < THRESHOLD; i++) {
        Buffer share = buf(SHARES[i], 36);
        CHECK(partial_sign(&share, &message, &partials[i]));
        memcpy(concatenated + i * PARTIAL_SIG_LENGTH, partials[i].ptr,
               PARTIAL_SIG_LENGTH);
    }
    concatenated[THRESHOLD * PARTIAL_SIG_LENGTH] = 0;

    Buffer whole = buf(concatenated, THRESHOLD * PARTIAL_SIG_LENGTH);
    Buffer one_over = buf(concatenated, sizeof concatenated);
    Buffer one_short = buf(concatenated, THRESHOLD * PARTIAL_SIG_LENGTH - 1);

    Buffer threshold_sig;
    CHECK(combine(THRESHOLD, &whole, &threshold_sig));
    CHECK(!combine(THRESHOLD, &one_over, &threshold_sig));
    CHECK(!combine(THRESHOLD, &one_short, &threshold_sig));

    free_vector(threshold_sig.ptr, threshold_sig.len);
    for (size_t i = 0; i < THRESHOLD; i++) {
        free_vector(partials[i].ptr, partials[i].len);
    }
}

/*
 * The three fixed-size deserializes read PUBKEY_LEN, PRIVKEY_LEN and
 * SIGNATURE_LEN bytes. They used to take a bare pointer, so a caller holding
 * fewer bytes than that could not say so and the read ran past the end of their
 * allocation. Each is called with the right length first, so `false` means the
 * length was caught rather than the bytes being wrong anyway.
 */
static void wrong_length_buffers_are_rejected(void) {
    Buffer seed = buf(SEED, sizeof SEED);
    struct Keypair *keypair = NULL;
    CHECK(keygen(&seed, &keypair));

    uint8_t *pub_bytes = NULL;
    uint8_t *priv_bytes = NULL;
    CHECK(serialize_pubkey(public_key_ptr(keypair), &pub_bytes));
    CHECK(serialize_privkey(private_key_ptr(keypair), &priv_bytes));

    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer signature;
    CHECK(sign(private_key_ptr(keypair), &message, &signature));

    PublicKey *pub = NULL;
    PrivateKey *priv = NULL;
    Signature *sig = NULL;

    Buffer pub_buf = buf(pub_bytes, PUBKEY_LEN);
    Buffer priv_buf = buf(priv_bytes, PRIVKEY_LEN);
    CHECK(deserialize_pubkey(&pub_buf, &pub));
    CHECK(deserialize_privkey(&priv_buf, &priv));
    CHECK(deserialize_sig(&signature, &sig));

    /* One byte short, and empty. */
    Buffer pub_short = buf(pub_bytes, PUBKEY_LEN - 1);
    Buffer priv_short = buf(priv_bytes, PRIVKEY_LEN - 1);
    Buffer sig_short = buf(signature.ptr, SIGNATURE_LEN - 1);
    Buffer empty = buf(pub_bytes, 0);

    CHECK(!deserialize_pubkey(&pub_short, &pub));
    CHECK(!deserialize_privkey(&priv_short, &priv));
    CHECK(!deserialize_sig(&sig_short, &sig));
    CHECK(!deserialize_pubkey(&empty, &pub));
    CHECK(!deserialize_privkey(&empty, &priv));
    CHECK(!deserialize_sig(&empty, &sig));

    /*
     * And too long: a valid encoding with one byte appended. This is the case
     * that needs the length check rather than the parser — bincode reads the
     * leading bytes it needs and ignores the rest, so without it a trailing
     * byte would be accepted and the caller told nothing.
     */
    uint8_t pub_long[PUBKEY_LEN + 1];
    uint8_t priv_long[PRIVKEY_LEN + 1];
    uint8_t sig_long[SIGNATURE_LEN + 1];
    memcpy(pub_long, pub_bytes, PUBKEY_LEN);
    memcpy(priv_long, priv_bytes, PRIVKEY_LEN);
    memcpy(sig_long, signature.ptr, SIGNATURE_LEN);
    pub_long[PUBKEY_LEN] = 0;
    priv_long[PRIVKEY_LEN] = 0;
    sig_long[SIGNATURE_LEN] = 0;

    Buffer pub_over = buf(pub_long, sizeof pub_long);
    Buffer priv_over = buf(priv_long, sizeof priv_long);
    Buffer sig_over = buf(sig_long, sizeof sig_long);
    CHECK(!deserialize_pubkey(&pub_over, &pub));
    CHECK(!deserialize_privkey(&priv_over, &priv));
    CHECK(!deserialize_sig(&sig_over, &sig));

    free_vector(signature.ptr, signature.len);
    free_vector(priv_bytes, PRIVKEY_LEN);
    free_vector(pub_bytes, PUBKEY_LEN);
    destroy_sig(sig);
    destroy_privkey(priv);
    destroy_pubkey(pub);
    destroy_keypair(keypair);
}

/*
 * The header asks for a seed of SEED_LEN bytes, and the library now holds
 * callers to it. A shorter one used to be sliced to length, which panicked, and
 * a panic crossing `extern "C"` aborts the process that made the call. Each
 * call is made with a full seed first, so `false` means the short seed was
 * caught.
 */
static void short_seeds_are_rejected(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer full = buf(SEED, SEED_LEN);
    Buffer one_short = buf(SEED, SEED_LEN - 1);
    Buffer none = buf(SEED, 0);
    BlindingFactor *factor = NULL;
    struct Keypair *keypair = NULL;
    Buffer blinded;

    CHECK(keygen(&full, &keypair));
    CHECK(!keygen(&one_short, &keypair));
    CHECK(!keygen(&none, &keypair));

    CHECK(blind(&message, &full, &blinded, &factor));
    CHECK(!blind(&message, &one_short, &blinded, &factor));
    CHECK(!blind(&message, &none, &blinded, &factor));

    free_vector(blinded.ptr, blinded.len);
    destroy_token(factor);
    destroy_keypair(keypair);
}

/*
 * A polynomial with no coefficients is a bare 8-byte length prefix. Two things
 * refuse it now — Poly at deserialization, the identity key check at
 * verification — so this pins the contract, not either mechanism.
 */
static void empty_polynomials_are_rejected(void) {
    static const uint8_t NO_COEFFICIENTS[8] = {0};
    Buffer empty = buf(NO_COEFFICIENTS, sizeof NO_COEFFICIENTS);
    Buffer polynomial = buf(PUBLIC_POLY, sizeof PUBLIC_POLY);
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer share = buf(SHARE_0, sizeof SHARE_0);
    Buffer partial;

    CHECK(partial_sign(&share, &message, &partial));
    CHECK(partial_verify(&polynomial, &message, &partial));
    CHECK(!partial_verify(&empty, &message, &partial));
    CHECK(!partial_verify_blind_signature(&empty, &message, &partial));

    free_vector(partial.ptr, partial.len);
}

/* Freeing NULL is a no-op, as it is for free(3). */
static void destructors_accept_null(void) {
    destroy_token(NULL);
    destroy_keypair(NULL);
    destroy_privkey(NULL);
    destroy_pubkey(NULL);
    destroy_sig(NULL);
    free_vector(NULL, 0);
    free_vector(NULL, PUBKEY_LEN);
}

int main(void) {
    plain_signing();
    blind_signing();
    serialization();
    threshold_signing();
    blind_threshold_signing();
    threshold_operations_reject_null();
    null_arguments_are_rejected();
    buffers_with_no_memory_are_rejected();
    wrong_length_buffers_are_rejected();
    misaligned_partials_are_rejected();
    short_seeds_are_rejected();
    empty_polynomials_are_rejected();
    destructors_accept_null();

    printf("threshold.h agrees with the library\n");
    return 0;
}
