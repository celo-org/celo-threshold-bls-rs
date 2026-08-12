const threshold = require('../src/blind_threshold_bls');

const STATIC_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const OTHER_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000002', 'hex');
const STATIC_THRESHOLD_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000003', 'hex');
const STATIC_MESSAGE = Buffer.from('test message', 'utf8');

// Returns a copy of the buffer with the byte at `index` flipped
function flipByte(buf, index) {
  const copy = Uint8Array.from(buf);
  copy[index] ^= 0xff;
  return copy;
}

describe('Invalid inputs', () => {
  describe('verify', () => {
    const keypair = threshold.keygen(STATIC_SEED);
    const otherKeypair = threshold.keygen(OTHER_SEED);
    const signature = threshold.sign(keypair.privateKey, STATIC_MESSAGE);

    it('throws on a tampered signature', () => {
      expect(() =>
        threshold.verify(keypair.publicKey, STATIC_MESSAGE, flipByte(signature, 0))
      ).toThrow();
    });

    it('throws on the wrong public key', () => {
      expect(() =>
        threshold.verify(otherKeypair.publicKey, STATIC_MESSAGE, signature)
      ).toThrow('signature verification failed');
    });

    it('throws on the wrong message', () => {
      expect(() =>
        threshold.verify(keypair.publicKey, Buffer.from('other message'), signature)
      ).toThrow('signature verification failed');
    });

    it('throws on a truncated signature', () => {
      expect(() =>
        threshold.verify(keypair.publicKey, STATIC_MESSAGE, signature.slice(0, -1))
      ).toThrow('signature verification failed');
    });

    it('throws on a truncated public key', () => {
      expect(() =>
        threshold.verify(keypair.publicKey.slice(0, -1), STATIC_MESSAGE, signature)
      ).toThrow('could not deserialize public key');
    });
  });

  describe('threshold operations', () => {
    const t = 3;
    const n = 5;
    const keys = threshold.thresholdKeygen(n, t, STATIC_THRESHOLD_SEED);
    const partialSigs = [];
    for (let i = 0; i < t; i++) {
      partialSigs.push(threshold.partialSign(keys.getShare(i), STATIC_MESSAGE));
    }

    it('partialVerify throws on a tampered partial signature', () => {
      // Byte 8 is the first byte of the signature value, after the
      // 8-byte length prefix
      expect(() =>
        threshold.partialVerify(keys.polynomial, STATIC_MESSAGE, flipByte(partialSigs[0], 8))
      ).toThrow('could not partially verify message');
    });

    it('partialVerify throws on a partial signature with a corrupted index', () => {
      // The share index is the trailing 4 bytes; point the signature of
      // share 0 at share 4
      const corrupted = Uint8Array.from(partialSigs[0]);
      corrupted[corrupted.length - 4] = 4;
      expect(() =>
        threshold.partialVerify(keys.polynomial, STATIC_MESSAGE, corrupted)
      ).toThrow('could not partially verify message');
    });

    it('partialVerify throws on a truncated polynomial', () => {
      expect(() =>
        threshold.partialVerify(keys.polynomial.slice(0, -1), STATIC_MESSAGE, partialSigs[0])
      ).toThrow('could not deserialize polynomial');
    });

    it('combine throws when given fewer partial signatures than the threshold', () => {
      const flattened = Uint8Array.from([...partialSigs[0], ...partialSigs[1]]);
      expect(() => threshold.combine(t, flattened)).toThrow('could not aggregate sigs');
    });

    // combine infers the boundaries between partials from the length, so a
    // caller whose flattening is off by a byte is only visible here.
    it('combine throws when the flattened input is not whole partial signatures', () => {
      const flattened = Uint8Array.from(
        partialSigs.slice(0, t).reduce((all, sig) => [...all, ...sig], [])
      );
      expect(() => threshold.combine(t, flattened)).not.toThrow();

      expect(() =>
        threshold.combine(t, Uint8Array.from([...flattened, 0]))
      ).toThrow('expected a multiple of');
      expect(() =>
        threshold.combine(t, flattened.slice(0, -1))
      ).toThrow('expected a multiple of');
    });
  });

  // These arguments used to panic, which in wasm traps and leaves the instance
  // unusable. Testing them from Rust cannot show that they now reach JS as
  // exceptions: those tests run natively, where building a JsValue aborts the
  // process. So the boundary itself is only covered here.
  describe('caller arguments', () => {
    const SHORT_SEED = STATIC_SEED.slice(0, 31);

    it('keygen throws on a seed shorter than 32 bytes', () => {
      expect(() => threshold.keygen(SHORT_SEED)).toThrow('seed must be at least 32 bytes');
    });

    it('blind throws on a seed shorter than 32 bytes', () => {
      expect(() =>
        threshold.blind(STATIC_MESSAGE, SHORT_SEED)
      ).toThrow('seed must be at least 32 bytes');
    });

    it('thresholdKeygen throws on a seed shorter than 32 bytes', () => {
      expect(() =>
        threshold.thresholdKeygen(5, 3, SHORT_SEED)
      ).toThrow('seed must be at least 32 bytes');
    });

    it('thresholdKeygen throws on a threshold outside 1..=n', () => {
      expect(() =>
        threshold.thresholdKeygen(5, 0, STATIC_THRESHOLD_SEED)
      ).toThrow('threshold must be between 1 and 5');
      expect(() =>
        threshold.thresholdKeygen(5, 6, STATIC_THRESHOLD_SEED)
      ).toThrow('threshold must be between 1 and 5');
    });

    it('thresholdKeygen throws on a group larger than the maximum', () => {
      expect(() =>
        threshold.thresholdKeygen(1000000000, 3, STATIC_THRESHOLD_SEED)
      ).toThrow('the number of shares must be between 1 and 1024');
    });

    it('getShare throws past the last share', () => {
      const keys = threshold.thresholdKeygen(5, 3, STATIC_THRESHOLD_SEED);
      expect(keys.numShares()).toBe(5);
      expect(() => keys.getShare(5)).toThrow('no share at index 5');
    });

    // A thrown exception must leave the module usable. A panic would not have:
    // it poisons the instance, and every later call fails too.
    it('leaves the module usable afterwards', () => {
      const keypair = threshold.keygen(STATIC_SEED);
      const signature = threshold.sign(keypair.privateKey, STATIC_MESSAGE);
      expect(() => threshold.verify(keypair.publicKey, STATIC_MESSAGE, signature)).not.toThrow();
    });
  });

  describe('unblind', () => {
    const keypair = threshold.keygen(STATIC_SEED);
    const blinded = threshold.blind(STATIC_MESSAGE, OTHER_SEED);
    const blindSignature = threshold.signBlindedMessage(keypair.privateKey, blinded.message);

    it('throws on a truncated blinding factor', () => {
      expect(() =>
        threshold.unblind(blindSignature, blinded.blindingFactor.slice(0, -1))
      ).toThrow('could not deserialize blinding factor');
    });

    it('throws on a truncated blinded signature', () => {
      expect(() =>
        threshold.unblind(blindSignature.slice(0, -1), blinded.blindingFactor)
      ).toThrow('could not unblind signature');
    });
  });
});
