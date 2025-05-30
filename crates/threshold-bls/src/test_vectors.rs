#[cfg(test)]
mod tests {
    #[cfg(feature = "bls12_381")]
    mod bls12_381_vectors {
        use crate::curve::bls12381::{Scalar, G1};
        use crate::poly::{Idx, Poly};
        use crate::schemes::bls12_381::G1Scheme;
        use crate::sig::{Scheme, Share, SignatureScheme, ThresholdScheme};
        use rand::SeedableRng;
        use rand_chacha::ChaChaRng;

        type PrivateKey = Scalar;
        type PublicKey = G1;

        // Test vectors with fixed seed
        const SEED: [u8; 32] = [42u8; 32];
        const MESSAGES: [&[u8; 32]; 3] = [&[0x00; 32], &[0x56; 32], &[0xab; 32]];

        const EXPECTED_PRIVATE_KEYS: [&str; 3] = [
            "013abcff335703fb2f065483dba2cb40526f21e871c10d5f4e8ed5ddd079e750",
            "8ae9e96e9b11b58272914cb8d508ae9523ef57f70e786ee2f0f35ba484c82945",
            "28e3388629b01282d49de4ac4f3451690195bb569ef73c7de722d9f04e4d405e",
        ];

        const EXPECTED_PUBLIC_KEYS: [&str; 3] = [
            "b22bcac0cbc3fa2c720784b0bde1d8a678bc35d8bb3deecff85ae6a13416d95e82ed18e08ed0f864cd90cb0cb018a39a",
            "b1ad7db5da4d357d7e680229f2a5e099ef10ee87489c0f685431c56d67a2b0890bacef1097047d77a326af3465be2b70",
            "a8b33f1d332eb0d593bcaee2ce201b0c4a47823b0b6cc10ebbdbeeb9466ac87e937afdd9ce4a085198630d3518caf25d",
        ];

        const EXPECTED_SIGNATURES: [[&str; 3]; 3] = [
            // First private key with each message
            [
                "6000000000000000b5f821ce57ee9a9a1c79f8ff4197b2c6c63adbdd3a2d6e771cd5f6748347d33ae5fa290c67115e24c5e8d9a47f19788e065b3a65bb90c71eddf200276496a5cde7dab19cb10f7180dd505f54eebec6433441f35ebc79d1986fc285ba13893f4f",
                "6000000000000000851cab1c75c2f5fa67dac6ebb65712a798e5ed293d890ef8b59dd1ebb2a315175c01dd718316ea98e51ef47d915424b31471a4119eb3f3007e48843e3544c192376d54f6cdf376699311c51aad547bf092285bad478c2268df4cd81d7d00cdef",
                "6000000000000000b91f177e50083ebd0a5b711da530578d73c623c0be88469b02e96a620a597d7f980c0b19f1dbef16918e564fb8fe37050a7ce3b7b8c2b01718a9b98900db97f75d302bd7bdcba2d8979dba714230afca74d65d34ee24a8f96c3b787d2f0a531e",
            ],
            // Second private key with each message
            [
                "6000000000000000b5607557b0ef065ecc35869cd263221bf40c964d835490d62e7576ea24940f1a0599754e91b1371bbf9dc9c631cc03010c739bf8e1a113a458e99304dcaa29ead1799cb095eb0d9c38a16077f825a31f64b22e15708791cc12baae57a73a96d7",
                "6000000000000000aadc03db054c6a8931f1ea9d345464fa029b1caf32bff9b5c1cfbfb45884da77b6ec861817ab7c34c93c3b617e78527111f3450b6a1a6444fd698f78ea3a7e827aba2cf2d1aa984dbfdd649c9424351ac130888954f27667ef0361f50db06049",
                "60000000000000008475a405e7e30f0350a5cdd1e0b4c36fdd17d5f315e1be2c06ed6b0695d5983af344cb388d0db2621a8832f5f171cb910058b99d2d84b0141b0f0edf19d996e9cb592c0a50600d59358623f5114efb766e93d77df02ce6836550e1a8ed06b0f1"
            ],
            // Third private key with each message
            [
                "6000000000000000b0f192df6e929b2d52f8c952baa6731e97e38a3232cdaf854abb958856eca7bd5d416343dc843232e59cb81a2993844f14841b07f274c78cd3e1cd60c716feebce7b1d1134048c7dd0d8305d896b9ebcd841fc395729a520478052ec4a53f11c",
                "60000000000000008536c724d442e299a0b4ef97e3249d0b27749b30d33a5c5c7930a00279085d7498ed4e42fe56e399e096e8944f5d70d2171236df5397ada1cb69038517f2f360f174ff8271ff2e59039afb39c3f1c3ed6b4c7a05f1788b4c4958450439e30e15",
                "600000000000000089c78160bb51cd0bd63e580ac1563944ffd33e416d4bae7a91e366ca5fe7601da74de5f43faf8d9e228faeb47587496a0c4c2cf75662aef4b3ec87b61a298a46f2bc89a57b8cd43aa8949f30ec9284367884a1afe1bc61cfa81068dc91a6bb50"
            ]
        ];

        const EXPECTED_AGGREGATED_SIGNATURES: [&str; 3] = [
            "6000000000000000b5f821ce57ee9a9a1c79f8ff4197b2c6c63adbdd3a2d6e771cd5f6748347d33ae5fa290c67115e24c5e8d9a47f19788e065b3a65bb90c71eddf200276496a5cde7dab19cb10f7180dd505f54eebec6433441f35ebc79d1986fc285ba13893f4f",
            "6000000000000000851cab1c75c2f5fa67dac6ebb65712a798e5ed293d890ef8b59dd1ebb2a315175c01dd718316ea98e51ef47d915424b31471a4119eb3f3007e48843e3544c192376d54f6cdf376699311c51aad547bf092285bad478c2268df4cd81d7d00cdef",
            "6000000000000000b91f177e50083ebd0a5b711da530578d73c623c0be88469b02e96a620a597d7f980c0b19f1dbef16918e564fb8fe37050a7ce3b7b8c2b01718a9b98900db97f75d302bd7bdcba2d8979dba714230afca74d65d34ee24a8f96c3b787d2f0a531e"
        ];

        // Create a deterministic RNG for reproducible key generation
        fn get_deterministic_rng() -> ChaChaRng {
            ChaChaRng::from_seed(SEED)
        }

        fn get_keypair(index: usize) -> (PrivateKey, PublicKey) {
            let mut rng = get_deterministic_rng();
            // Skip to the desired index
            for _ in 0..index {
                G1Scheme::keypair(&mut rng);
            }
            G1Scheme::keypair(&mut rng)
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
                    let sig = G1Scheme::sign(&privkey, msg).expect("Error signing");
                    let sig_hex = hex::encode(bincode::serialize(&sig).unwrap());
                    assert_eq!(
                        sig_hex, EXPECTED_SIGNATURES[i][j],
                        "Signature for key[{}] and message[{}] mismatch",
                        i, j
                    );

                    assert!(
                        G1Scheme::verify(&pubkey, msg, &sig).is_ok(),
                        "Signature verification failed for key[{}] and message[{}]",
                        i,
                        j
                    );
                }
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
                    .map(|s| G1Scheme::partial_sign(s, msg).unwrap())
                    .collect::<Vec<_>>();

                // Verify each partial signature
                for (i, partial) in partials.iter().enumerate() {
                    assert!(
                        G1Scheme::partial_verify(&public_poly, msg, partial).is_ok(),
                        "Partial signature verification failed for share {}",
                        i
                    );
                }

                // Aggregate signatures
                let aggregated = G1Scheme::aggregate(n, &partials).expect("Failed to aggregate");
                let agg_hex = hex::encode(bincode::serialize(&aggregated).unwrap());
                assert_eq!(
                    agg_hex, EXPECTED_AGGREGATED_SIGNATURES[msg_idx],
                    "Aggregated signature for message {} mismatch",
                    msg_idx
                );

                assert!(
                    G1Scheme::verify(threshold_pubkey, msg, &aggregated).is_ok(),
                    "Aggregated signature verification failed for message {}",
                    msg_idx
                );
            }
        }
    }

    #[cfg(feature = "bls12_377")]
    #[cfg(test)]
    mod bls12_377_vectors {
        use crate::poly::{Idx, Poly};
        use crate::schemes::bls12_377::G2Scheme;
        use crate::sig::{Scheme, Share, SignatureScheme, ThresholdScheme};
        use rand::SeedableRng;
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
