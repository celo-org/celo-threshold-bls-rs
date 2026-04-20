#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod bls12_377_vectors {
        use crate::poly::{Eval, Idx, Poly};
        use crate::schemes::bls12_377::G2Scheme;
        use crate::serialization;
        use crate::sig::{Scheme, Share, SignatureScheme, ThresholdScheme};
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaChaRng;

        // Define concrete types to avoid ambiguity
        type PrivateKey = <G2Scheme as Scheme>::Private;
        type PublicKey = <G2Scheme as Scheme>::Public;

        // Test vectors with fixed seed
        const SEED: [u8; 32] = [42u8; 32];
        const MESSAGES: [&[u8; 32]; 3] = [&[0x00; 32], &[0x56; 32], &[0xab; 32]];

        // Expected outputs for each operation with seed [42; 32]
        const EXPECTED_PRIVATE_KEYS: [&str; 3] = [
            "d3538152f5f1570c1f21a6246665637c11153594e4220eec8e8d72be00706303",
            "7ca094ae6cbf48061b12121ef92160eafe996bc2d8a9a1336b00801120a87211",
            "922be46d5fa7d1bd43152a3cab829dc32ed1076e4c2be136f4e8846895557b02",
        ];

        const EXPECTED_PUBLIC_KEYS: [&str; 3] = [
            "203e261e640d22e0daed558229493c95fb5016c1c8dc5a22dfedb22f14fcb2958466446beb9c309dffa4b4ba52894000f9cab42d8570af09233b9ba06c0fb1c266a866f0e6384edbf176fcb76619f01da297480be4d7b8551b8fa3b9a08e1100",
            "82ad47f04edc28f22a3c47e2aaf642912d9b710c57c254ef78081a39f2eaeec97a95873789f15555503a1f885fea0e0190826f11ac8e09339391dcf499347db8cd48ae453b0882ea652177b6f73bb673b1381ed7cd91c8f6a0763f4dc9754901",
            "1a95b30e8dee662342c87ca88914890fba6b376344fbf8669abb4ce5ea62ac1dbd2935320efe5c6ebe5ceee9534187002ae20deb4445768a023d8d499fb1f49608942e0047ec82993fe6447a2abace036352eb6878fae17d5c0b992c7ba74800",
        ];

        const EXPECTED_SIGNATURES: [[&str; 3]; 3] = [
            // First private key with each message
            [
                "3000000000000000e2dac33c610f0a247a82c98324188070164206c0151be6a98d8666e63a36c3804bfcb682f6764ad2307406292f2d2281",
                "3000000000000000f07921d52176cc4f6528005c19eab9d230900b531780e9ddfd1d13f020cf4b559a96a6909c33bfb16bd0e3ca0cdf5d01",
                "30000000000000007711c1febaa06af30f0c9bb19e942b642d21354c25ad392b1c4c3cf4eb0375809afa05bf7defaa17684202e036cfd480",
            ],
            // Second private key with each message
            [
                "30000000000000001b4827907e476d060382874380fbd600605662c7eb80de9d0fc55cfc26a3efea6f596f18bc13e91353b87f4ec4c2b980",
                "30000000000000007cfb12face29af9d65638bd4430f5d95f10796eaaba9c91d594685780dda98f3870ed1d01a13356a308cdc24312f5a01",
                "30000000000000006dd334350a2e502b2b2880c9d58c1c3281dc4343b36d57de0541f29c2f77d29c39c4475a2368a6a4dff9702e5ba29d81",
            ],
            // Third private key with each message
            [
                "30000000000000005eb1a349270e162e0e7c2fc027759d751e91765d27693591273a25737616516d431fddad37e94fe45714e5caca370b01",
                "3000000000000000d4829581cdd53438721641e1a6893ef92e62dbbd3bca21cb5dd74b6c685c9aaf905b81c544fb3b07031a917602647101",
                "3000000000000000bfff68378c234eeb81604dfe320c09cdacb0c7521cb0563d79789a1ba217397998be539204f4d6b0077511f0c14a0600",
            ],
        ];

        const EXPECTED_AGGREGATED_SIGNATURES: [&str; 3] = [
            "3000000000000000e2dac33c610f0a247a82c98324188070164206c0151be6a98d8666e63a36c3804bfcb682f6764ad2307406292f2d2281",
            "3000000000000000f07921d52176cc4f6528005c19eab9d230900b531780e9ddfd1d13f020cf4b559a96a6909c33bfb16bd0e3ca0cdf5d01",
            "30000000000000007711c1febaa06af30f0c9bb19e942b642d21354c25ad392b1c4c3cf4eb0375809afa05bf7defaa17684202e036cfd480",
        ];

        // Expected bincode encoding of `Poly<PublicKey>` committed from the
        // three-coefficient private polynomial whose coefficients are the first
        // three private keys above. Pins the on-the-wire format for a public
        // polynomial at threshold=3.
        const EXPECTED_PUBLIC_POLYNOMIAL: &str = "0300000000000000203e261e640d22e0daed558229493c95fb5016c1c8dc5a22dfedb22f14fcb2958466446beb9c309dffa4b4ba52894000f9cab42d8570af09233b9ba06c0fb1c266a866f0e6384edbf176fcb76619f01da297480be4d7b8551b8fa3b9a08e110082ad47f04edc28f22a3c47e2aaf642912d9b710c57c254ef78081a39f2eaeec97a95873789f15555503a1f885fea0e0190826f11ac8e09339391dcf499347db8cd48ae453b0882ea652177b6f73bb673b1381ed7cd91c8f6a0763f4dc97549011a95b30e8dee662342c87ca88914890fba6b376344fbf8669abb4ce5ea62ac1dbd2935320efe5c6ebe5ceee9534187002ae20deb4445768a023d8d499fb1f49608942e0047ec82993fe6447a2abace036352eb6878fae17d5c0b992c7ba74800";

        // Expected bincode encoding of each `Share<PrivateKey>` produced by
        // evaluating the same three-coefficient private polynomial at indices
        // 0, 1, 2. Pins the on-the-wire format for threshold-secret shares.
        const EXPECTED_SHARES: [&str; 3] = [
            "00000000e01ffa6ec1d860c67c48e2ae0b93b6d03dd07068ebaadcf597d14a9e5708a604",
            "0100000011433b674c0e0dfc619a72b107c644acc72dbc188b896d6d89e72c4fd94bdf0a",
            "0200000065bd443b96124ba3cd16575c5b8763b5ad7ddf48a5710cf20c2aec3627d56303",
        ];

        // Expected bincode encoding of each partial signature
        // (output of `partial_sign`) on MESSAGES[0] with the three shares
        // above. Pins the on-the-wire format for partial signatures (the
        // `Eval<Vec<u8>>` shape).
        const EXPECTED_PARTIAL_SIGS_ON_MSG0: [&str; 3] = [
            "300000000000000005f9fc64775de3052bf866d04e40244f81320dc327e98f7e2fb85f2b7d723f5029d0985a26f6a530d390548f096e1a0100000000",
            "3000000000000000370ee2fc7404010fb6035e4161d5665aa1a50e1ab8fb1dd9c8cd5016adea63914a2d9dd0425cceeefba02ef0d7dd9f0001000000",
            "300000000000000019d05eff2062b7266f803c83b84321ad92c34aa794b69c3f31e75e8f3e33c2925929a7f926f32c97a2276c1541735e0102000000",
        ];

        // Create a deterministic RNG for reproducible key generation
        fn get_deterministic_rng() -> ChaChaRng {
            ChaChaRng::from_seed(SEED)
        }

        fn get_keypair(index: usize) -> (PrivateKey, PublicKey) {
            let mut rng = get_deterministic_rng();
            // Skip to the desired index
            for _ in 0..index {
                G2Scheme::keypair(&mut rng);
            }
            G2Scheme::keypair(&mut rng)
        }

        #[test]
        fn sign_and_verify() {
            // Test basic signing and verification with deterministic outputs
            for i in 0..3 {
                let (privkey, pubkey) = get_keypair(i);

                let priv_hex = hex::encode(bincode::serialize(&privkey).unwrap());
                let pub_hex = hex::encode(bincode::serialize(&pubkey).unwrap());

                assert_eq!(
                    priv_hex, EXPECTED_PRIVATE_KEYS[i],
                    "Private key {} mismatch",
                    i
                );
                assert_eq!(
                    pub_hex, EXPECTED_PUBLIC_KEYS[i],
                    "Public key {} mismatch",
                    i
                );

                for (j, &msg) in MESSAGES.iter().enumerate() {
                    // Sign the message
                    let sig = G2Scheme::sign(&privkey, msg).expect("Error signing");
                    let sig_hex = hex::encode(bincode::serialize(&sig).unwrap());
                    assert_eq!(
                        sig_hex, EXPECTED_SIGNATURES[i][j],
                        "Signature for key[{}] and message[{}] mismatch",
                        i, j
                    );

                    assert!(
                        G2Scheme::verify(&pubkey, msg, &sig).is_ok(),
                        "Signature verification failed for key[{}] and message[{}]",
                        i,
                        j
                    );
                }
            }
        }

        /// Builds the fixed-coefficient private polynomial, derives the matching
        /// shares and public polynomial, and returns everything needed by the
        /// wire-format tests.
        fn fixed_threshold_setup() -> (Vec<Share<PrivateKey>>, Poly<PublicKey>) {
            let n = 3;
            let private_keys: Vec<PrivateKey> = (0..n)
                .map(get_keypair)
                .map(|(priv_key, _)| priv_key)
                .collect();
            let private_poly = Poly::<PrivateKey>::from(private_keys);
            let shares = (0..n)
                .map(|i| {
                    let eval = private_poly.eval(i as Idx);
                    Share {
                        index: eval.index,
                        private: eval.value,
                    }
                })
                .collect::<Vec<Share<PrivateKey>>>();
            let public_poly = private_poly.commit();
            (shares, public_poly)
        }

        #[test]
        fn test_wire_format_public_polynomial() {
            let (_, public_poly) = fixed_threshold_setup();

            // encode side: the top-level bincode output matches the pinned hex
            let encoded = hex::encode(bincode::serialize(&public_poly).unwrap());
            assert_eq!(encoded, EXPECTED_PUBLIC_POLYNOMIAL);

            // decode side: the bounded helper accepts the same bytes and
            // reconstructs the equivalent value
            let bytes = hex::decode(EXPECTED_PUBLIC_POLYNOMIAL).unwrap();
            let decoded: Poly<PublicKey> = serialization::deserialize(&bytes)
                .expect("bounded deserialize must accept pinned wire data");
            assert_eq!(decoded, public_poly);
        }

        #[test]
        fn test_wire_format_shares() {
            let (shares, _) = fixed_threshold_setup();
            for (i, share) in shares.iter().enumerate() {
                let encoded = hex::encode(bincode::serialize(share).unwrap());
                assert_eq!(encoded, EXPECTED_SHARES[i], "share {} wire format drift", i);

                let bytes = hex::decode(EXPECTED_SHARES[i]).unwrap();
                let decoded: Share<PrivateKey> = serialization::deserialize(&bytes)
                    .expect("bounded deserialize must accept pinned wire data");
                assert_eq!(&decoded, share);
            }
        }

        #[test]
        fn test_wire_format_partial_signatures() {
            let (shares, _) = fixed_threshold_setup();
            let msg = MESSAGES[0];
            for (i, share) in shares.iter().enumerate() {
                let partial = G2Scheme::partial_sign(share, msg).unwrap();
                let encoded = hex::encode(&partial);
                assert_eq!(
                    encoded, EXPECTED_PARTIAL_SIGS_ON_MSG0[i],
                    "partial signature {} wire format drift",
                    i
                );

                let bytes = hex::decode(EXPECTED_PARTIAL_SIGS_ON_MSG0[i]).unwrap();
                let decoded: Eval<Vec<u8>> = serialization::deserialize(&bytes)
                    .expect("bounded deserialize must accept pinned wire data");
                assert_eq!(decoded.index, share.index);
                // Re-serialize the decoded value and confirm the bytes round-trip
                // back to the pinned hex.
                assert_eq!(bincode::serialize(&decoded).unwrap(), bytes);
            }
        }

        #[test]
        fn test_signature_aggregation() {
            // Test threshold signatures with deterministic outputs
            for (msg_idx, &msg) in MESSAGES.iter().enumerate() {
                let n = 3;

                // Create private keys using deterministic generation
                let private_keys: Vec<PrivateKey> = (0..n)
                    .map(get_keypair)
                    .map(|(priv_key, _)| priv_key)
                    .collect();

                // Create a private polynomial from our private keys
                let private_poly = Poly::<PrivateKey>::from(private_keys);

                // Generate the shares from the polynomial
                let shares = (0..n)
                    .map(|i| {
                        let eval = private_poly.eval(i as Idx);
                        Share {
                            index: eval.index,
                            private: eval.value,
                        }
                    })
                    .collect::<Vec<Share<PrivateKey>>>();

                // Get the public polynomial
                let public_poly = private_poly.commit();
                let threshold_pubkey = public_poly.public_key();

                // Generate partial signatures
                let partials = shares
                    .iter()
                    .map(|s| G2Scheme::partial_sign(s, msg).unwrap())
                    .collect::<Vec<_>>();

                // Verify each partial signature
                for (i, partial) in partials.iter().enumerate() {
                    assert!(
                        G2Scheme::partial_verify(&public_poly, msg, partial).is_ok(),
                        "Partial signature verification failed for share {}",
                        i
                    );
                }

                // Aggregate signatures
                let aggregated = G2Scheme::aggregate(n, &partials).expect("Failed to aggregate");
                let agg_hex = hex::encode(bincode::serialize(&aggregated).unwrap());
                assert_eq!(
                    agg_hex, EXPECTED_AGGREGATED_SIGNATURES[msg_idx],
                    "Aggregated signature for message {} mismatch",
                    msg_idx
                );

                assert!(
                    G2Scheme::verify(threshold_pubkey, msg, &aggregated).is_ok(),
                    "Aggregated signature verification failed for message {}",
                    msg_idx
                );
            }
        }
    }
}
