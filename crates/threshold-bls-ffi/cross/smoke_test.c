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

static Buffer buf(const uint8_t *ptr, size_t len) {
    Buffer b = {ptr, len};
    return b;
}

/* keygen, the two accessors, sign, verify, destroy_keypair. */
static void plain_signing(void) {
    Buffer seed = buf(SEED, sizeof SEED);
    struct Keypair *keypair = NULL;
    keygen(&seed, &keypair);
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
    keygen(&seed, &keypair);

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
    keygen(&seed, &keypair);

    uint8_t *pub_bytes = NULL;
    CHECK(serialize_pubkey(public_key_ptr(keypair), &pub_bytes));
    PublicKey *pub = NULL;
    CHECK(deserialize_pubkey(pub_bytes, &pub));

    uint8_t *priv_bytes = NULL;
    CHECK(serialize_privkey(private_key_ptr(keypair), &priv_bytes));
    PrivateKey *priv = NULL;
    CHECK(deserialize_privkey(priv_bytes, &priv));

    /* Round-tripped keys must still work together. */
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer signature;
    CHECK(sign(priv, &message, &signature));
    CHECK(verify(pub, &message, &signature));

    uint8_t *sig_bytes = NULL;
    Signature *sig = NULL;
    CHECK(deserialize_sig(signature.ptr, &sig));
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
 * combine and the four partial operations take a KeyShare or a PublicPoly, and
 * nothing in the C API produces either — threshold_keygen is test-only in Rust.
 * They are unreachable from C today, so drive their documented NULL paths
 * instead: that still executes the calling convention and the bool return,
 * which is what a prototype mismatch would break.
 */
static void unreachable_operations_reject_null(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer signature;

    CHECK(!partial_sign(NULL, &message, &signature));
    CHECK(!partial_sign_blinded_message(NULL, &message, &signature));
    CHECK(!partial_verify(NULL, &message, &message));
    CHECK(!partial_verify_blind_signature(NULL, &message, &message));
    CHECK(!combine(3, NULL, &signature));
}

/* The NULL contract the header now documents, checked from C. */
static void null_arguments_are_rejected(void) {
    Buffer message = buf(MESSAGE, sizeof MESSAGE);
    Buffer out;
    BlindingFactor *factor = NULL;
    PublicKey *pub = NULL;
    uint8_t *bytes = NULL;

    CHECK(!blind(NULL, &message, &out, &factor));
    CHECK(!unblind(NULL, NULL, &out));
    CHECK(!verify(NULL, &message, &message));
    CHECK(!sign(NULL, &message, &out));
    CHECK(!sign_blinded_message(NULL, &message, &out));

    CHECK(!deserialize_pubkey(NULL, &pub));
    CHECK(!deserialize_privkey(NULL, (PrivateKey **)&pub));
    CHECK(!deserialize_sig(NULL, (Signature **)&pub));
    CHECK(!serialize_pubkey(NULL, &bytes));
    CHECK(!serialize_privkey(NULL, &bytes));
    CHECK(!serialize_sig(NULL, &bytes));
}

int main(void) {
    plain_signing();
    blind_signing();
    serialization();
    unreachable_operations_reject_null();
    null_arguments_are_rejected();

    printf("threshold.h agrees with the library\n");
    return 0;
}
