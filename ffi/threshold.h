#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * A BLS12-377 Keypair
 */
typedef struct Keypair Keypair;

typedef struct Keys Keys;

/**
 * A polynomial that is using a scalar for the variable x and a generic
 * element for the coefficients. The coefficients must be able to multiply
 * the type of the variable, which is always a scalar.
 */
typedef struct Poly_PrivateKey__PublicKey Poly_PrivateKey__PublicKey;

typedef struct Share_PrivateKey Share_PrivateKey;

/**
 * Blinding a message before requesting a signature requires the usage of a
 * private blinding factor that is called a Token. To unblind the signature
 * afterwards, one needs the same token as what the blinding method returned.
 * In this blind signature scheme, the token is simply a field element.
 */
typedef struct Token_PrivateKey Token_PrivateKey;

/**
 * A blinded message along with the blinding_factor used to produce it
 */
typedef struct {
  /**
   * The resulting blinded message
   */
  Buffer message;
  /**
   * The blinding_factor which was used to generate the blinded message. This will be used
   * to unblind the signature received on the blinded message to a valid signature
   * on the unblinded message
   */
  Token_PrivateKey blinding_factor;
} BlindedMessage;

typedef Private PrivateKey;

typedef Public PublicKey;

/**
 * Given a message and a seed, it will blind it and return the blinded message
 *
 * * message: A cleartext message which you want to blind
 * * seed: A 32 byte seed for randomness. You can get one securely via `crypto.randomBytes(32)`
 * * blinded_message: Pointer to the memory where the blinded message will be written to
 *
 * The `BlindedMessage.blinding_factor` should be saved for unblinding any
 * signatures on `BlindedMessage.message`
 *
 * # Safety
 * - If the same seed is used twice, the blinded result WILL be the same
 *
 * Returns true if successful, otherwise false.
 */
void blind(const Buffer *message, const Buffer *seed, BlindedMessage *blinded_message);

/**
 * Combines a flattened vector of partial signatures to a single threshold signature
 *
 * # Safety
 * - This function does not check if the signatures are valid!
 */
bool combine(uintptr_t threshold, const Buffer *signatures, Buffer *asig);

bool deserialize_privkey(const uint8_t *privkey_buf, PrivateKey **privkey);

bool deserialize_pubkey(const uint8_t *pubkey_buf, PublicKey **pubkey);

/**
 * Generates a single private key from the provided seed.
 *
 * # Safety
 *
 * The seed MUST be at least 32 bytes long
 */
void keygen(const Buffer *seed, Keypair *keypair);

/**
 * Gets the number of shares corresponding to the provided `Keys` pointer
 */
uintptr_t num_shares(const Keys *keys);

/**
 * Signs the message with the provided **share** of the private key and returns the **partial**
 * signature.
 */
bool partial_sign(const Share_PrivateKey *share, const Buffer *message, Buffer *signature);

/**
 * Verifies a partial signature against the public key corresponding to the secret shared
 * polynomial.
 */
bool partial_verify(const Poly_PrivateKey__PublicKey *polynomial,
                    const Buffer *blinded_message,
                    const Buffer *sig);

/**
 * Gets a pointer to the polynomial corresponding to the provided `Keys` pointer
 */
const Poly_PrivateKey__PublicKey *polynomial_ptr(const Keys *keys);

/**
 * Gets a pointer to the private key corresponding to the provided `KeyPair` pointer
 */
const PrivateKey *private_key_ptr(const Keypair *keypair);

/**
 * Gets a pointer to the public key corresponding to the provided `KeyPair` pointer
 */
const PublicKey *public_key_ptr(const Keypair *keypair);

void serialize_privkey(const PrivateKey *privkey, uint8_t **privkey_buf);

void serialize_pubkey(const PublicKey *pubkey, uint8_t **pubkey_buf);

/**
 * Gets the `index`'th share corresponding to the provided `Keys` pointer
 */
const Share_PrivateKey *share_ptr(const Keys *keys, uintptr_t index);

/**
 * Signs the message with the provided private key and returns the signature
 *
 * # Throws
 *
 * - If signing fails
 */
bool sign(const PrivateKey *private_key, const Buffer *message, Buffer *signature);

/**
 * Gets a pointer to the threshold public key corresponding to the provided `Keys` pointer
 */
const PublicKey *threshold_public_key_ptr(const Keys *keys);

/**
 * Given a blinded signature and a blinding_factor used for blinding, it returns the signature
 * unblinded
 *
 * * blinded_signature: A message which has been blinded or a blind signature
 * * blinding_factor: The blinding_factor used to blind the message
 * * unblinded_signature: Pointer to the memory where the unblinded signature will be written to
 *
 * Returns true if successful, otherwise false.
 */
bool unblind(const Buffer *blinded_signature,
             const Token_PrivateKey *blinding_factor,
             Buffer *unblinded_signature);

/**
 * Verifies the signature after it has been unblinded. Users will call this on the
 * threshold signature against the full public key
 *
 * * public_key: The public key used to sign the message
 * * message: The message which was signed
 * * signature: The signature which was produced on the message
 *
 * Returns true if successful, otherwise false.
 */
bool verify(const PublicKey *public_key, const Buffer *message, const Buffer *signature);
