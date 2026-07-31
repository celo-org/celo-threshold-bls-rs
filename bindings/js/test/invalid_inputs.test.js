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
