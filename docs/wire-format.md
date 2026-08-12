# Wire format

Every value that crosses a binding boundary does so as bytes. The WASM functions
take and return `Uint8Array`, the C functions take and return `Buffer`s, and
neither says what is inside them. This document does.

**These byte layouts are public API.** A consumer stores keys and shares, sends
signatures over a network, and concatenates partial signatures by offset. Changing
an encoding breaks them with no compile error anywhere, so a change here is a
breaking change and belongs in `CHANGELOG.md`.

## The encoder

bincode 1.x with the default configuration: **fixed-width integers,
little-endian**, no varints, structs encoded field by field in declaration order
with no padding, sequences prefixed by a `u64` length.

Deserialization goes through `threshold_bls::serialization`, which adds a
**1 MiB ceiling** (`MAX_DESERIALIZE_BYTES`) so an attacker-supplied length prefix
cannot make the library allocate arbitrarily. Trailing bytes are **allowed**: a
value followed by extra bytes deserializes, and the extra bytes are ignored. The
fixed-length entry points reject them anyway by checking the length first.

## The values

| Value | Bytes | Layout |
|---|---|---|
| Private key | 32 | scalar |
| Public key | 96 | G2 point, compressed |
| Signature | 48 | G1 point, compressed |
| Blinded message | 48 | G1 point, compressed — a signature-group point, not a hash |
| Blinding factor | 32 | scalar |
| Share | 36 | `u32` index ‖ 32-byte scalar |
| Partial signature | 60 | `u64` length (always 48) ‖ 48-byte signature ‖ `u32` index |
| Public polynomial | 8 + 96·n | `u64` coefficient count ‖ n × 96-byte G2 point |

The C header exports the four that callers need to size buffers with:
`PRIVKEY_LEN`, `PUBKEY_LEN`, `SIGNATURE_LEN`, `PARTIAL_SIG_LENGTH`, and
`SEED_LEN` for the 32 bytes of entropy `keygen` and `blind` require.

### Worked examples

A share of index 1 — the index leads:

```
01000000 222c…                    4-byte index, then the scalar
```

A partial signature of index 1 — the index trails, behind a length prefix that
belongs to the signature inside it:

```
3000000000000000 b0e78815… 01000000
└ u64 = 48 ────┘ └ sig ──┘ └ index ┘
```

A public polynomial of degree 2 — three coefficients, 296 bytes:

```
0300000000000000 30ad… (3 × 96 bytes)
└ u64 = 3 ─────┘
```

## Things that catch people out

- **The index is at opposite ends of a share and a partial signature.** A share
  is `index ‖ scalar`; a partial is `length ‖ signature ‖ index`. That follows
  from the field order of the two Rust structs and nothing else.
- **A signature on its own has no length prefix.** The 8 bytes at the front of a
  partial signature are the length of the signature *inside* it. Serializing a
  signature that is already bytes prepends a second, phantom prefix — which the
  test vectors did until they were corrected.
- **`combine` splits its input by offset.** It takes the partial signatures
  concatenated, and requires an exact multiple of `PARTIAL_SIG_LENGTH`. There is
  no delimiter and no per-element length; a byte out of place shifts every
  boundary after it.
- **A polynomial's coefficient count bounds the group.** At 1 MiB, a public
  polynomial can hold at most 10,922 coefficients; a larger one is refused at
  deserialization rather than allocated.
- **`PARTIAL_SIG_LENGTH` embeds a Rust type width.** It is
  `VEC_LENGTH + SIGNATURE_LEN + size_of::<Idx>()`, so widening `Idx` from `u32`
  changes a wire format that C and JS callers chunk against.
- **Point compression comes from arkworks.** The 48- and 96-byte figures are
  BLS12-377 compressed points as ark-serialize writes them. An arkworks change to
  compression or flag bits would change every encoding here.

## What pins this

Three checks cover different halves, and it is worth knowing which is which:

- **`crates/threshold-bls/src/test_vectors.rs` is the compatibility gate.** It
  fixes a seed and pins the resulting keys, signatures, shares, partial
  signatures and polynomial as hex. If an encoding changes, this file fails.
  **Regenerating it to make it pass is how a silent break happens** — the failure
  is the point, and a new value means consumers must migrate.
- **`crates/threshold-bls-ffi/cross/threshold.h`**, regenerated and diffed by
  `just check-header`, pins the *lengths* the C API works in. It says how big a
  buffer is, not what is in it.
- **`crates/threshold-bls-ffi/cross/smoke_test.c`**, run by `just check-abi`,
  pins that a C caller can build these layouts and get them back: it concatenates
  partials at `PARTIAL_SIG_LENGTH`, deserializes at the fixed lengths, and checks
  what comes out.
- **`bindings/js/test`** pins the JS-visible shapes and the thrown messages.

None of them alone is the format. The bytes are pinned by the vectors, their
sizes by the header, and their use by the two consumer-side suites.

## Versioning

The crates are not published to crates.io and the repository carries no release
tags, so consumers pin a git revision or an npm version of
`@celo/blind-threshold-bls`. There is no format version field in any of these
encodings: a consumer cannot detect a format change at runtime, which is the
reason for the gate above.
