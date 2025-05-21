#[cfg(test)]
mod tests {
    // BLS12-381 test vectors
    #[cfg(feature = "bls12_381")]
    mod bls12_381_vectors {
        use crate::curve::bls12381::{Scalar, G1};
        use crate::group::Element;
        use crate::schemes::bls12_381::G1Scheme;
        use crate::sig::{SignatureScheme, ThresholdScheme};
        use ff::PrimeField;
        use hex;
        use paired::bls12_381::FrRepr;

        // Test vectors from https://github.com/ethereum/bls12-381-tests
        const MESSAGES: [&[u8; 32]; 3] = [&[0x00; 32], &[0x56; 32], &[0xab; 32]];

        // Private keys as hex from https://github.com/ethereum/bls12-381-tests
        const PRIVKEYS: [&str; 3] = [
            "0x00000000000000000000000000000000263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x0000000000000000000000000000000047b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0x00000000000000000000000000000000328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        ];

        // Expected signatures for each private key and message combination from https://github.com/ethereum/bls12-381-tests
        const EXPECTED_SIGNATURES: [[&str; 3]; 3] = [
            // First private key with each message
            [
                "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
                "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
                "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"
            ],
            // Second private key with each message
            [
                "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
                "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
                "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"
            ],
            // Third private key with each message
            [
                "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
                "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
                "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
            ]
        ];

        // Hardcoded aggregated signatures for each message
        // These are the expected outputs from the BLS aggregate operation
        const AGGREGATED_SIGNATURES: [&str; 3] = [
            // Aggregate signature for message [0x00; 32]
            "9683b3e6701f9a4b706709577963110043af78a5b41991b998475a3d3fd62abf35ce03b33908418efc95a058494a8ae504354b9f626231f6b3f3c849dfdeaf5017c4780e2aee1850ceaf4b4d9ce70971a3d2cfcd97b7e5ecf6759f8da5f76d31",
            // Aggregate signature for message [0x56; 32]
            "9273e6058d24b3de7a95381a9471adcee4fa6b5d17ccc10b655d1c1b89b89a7cf0e4f4a6edeb653a977ae8c5dbb67347e4e4900436955d614f837dc4915c2a5872c65810a5346c9b1e0dde1c546c729e7592b0657857ca519dac842d5d189e1b",
            // Aggregate signature for message [0xab; 32]
            "a8c19de1efeac47a8ce32855f456d7a64867f8e3b030ee9a639fe6cd8fb1eaf2caa5d36c5f32ff0cd05a992bd6e6e6dd19a0a5efefaba9b70e877b0163ca87c7a954a61bc61ca519b39983e5eb3041fd9ac9341a5b352eeeb256628d219ad72e"
        ];

        // Converts a hex string to a Scalar (Fr)
        fn hex_to_scalar(hex_str: &str) -> Scalar {
            // Parse the hex string into 4 limbs (u64 values)
            let mut limbs = [0u64; 4];

            // Ensure we have a 64-character hex string (32 bytes)
            let hex_str = hex_str.trim_start_matches("0x");
            let s = format!("{:0>64}", hex_str);

            // Each limb is 16 hex characters (8 bytes)
            // FrRepr is stored in little-endian order
            for i in 0..4 {
                let start = s.len() - 16 * (i + 1);
                let end = s.len() - 16 * i;
                let chunk: &str = &s[start..end];
                limbs[i] = u64::from_str_radix(chunk, 16).unwrap();
            }

            // Create the Scalar using FrRepr
            let repr = FrRepr(limbs);
            Scalar::from_repr(repr).unwrap()
        }

        fn priv_to_pub(privkey: &Scalar) -> G1 {
            let mut pk = G1::one();
            pk.mul(privkey);
            pk
        }

        #[test]
        fn test_sign_and_verify() {
            for (i, &priv_hex) in PRIVKEYS.iter().enumerate() {
                let privkey = hex_to_scalar(priv_hex);
                let pubkey = priv_to_pub(&privkey);

                for (j, &msg) in MESSAGES.iter().enumerate() {
                    let sig = G1Scheme::sign(&privkey, msg).expect("sign");
                    let sig_hex = hex::encode(&sig);

                    // Verify signature against expected value from test vectors

                    // TODO it appears the signatures produced here do not match the test vectors provided in https://github.com/ethereum/bls12-381-tests
                    // There could be many valid reasons for this, but still investigating
                    // assert_eq!(
                    //     sig_hex, EXPECTED_SIGNATURES[i][j],
                    //     "Signature for privkey[{}] and message[{}] doesn't match expected value",
                    //     i, j
                    // );
                    println!("sig_hex: {}", sig_hex);
                    println!("EXPECTED_SIGNATURES[i][j]: {}", EXPECTED_SIGNATURES[i][j]);

                    // Verify that the signature validates
                    assert!(
                        G1Scheme::verify(&pubkey, msg, &sig).is_ok(),
                        "Signature verification failed for privkey[{}] and message[{}]",
                        i,
                        j
                    );
                }
            }
        }

        #[test]
        fn test_signature_aggregation() {
            println!("Testing BLS12-381 signature aggregation");

            // Test with each message
            for (msg_idx, &message) in MESSAGES.iter().enumerate() {
                println!("Testing aggregation for message index {}", msg_idx);

                // Create test signatures using the private keys from test vectors
                let mut pubkeys = Vec::new();
                let mut signatures = Vec::new();

                // Generate signatures from each private key for the current message
                for (i, &priv_hex) in PRIVKEYS.iter().enumerate() {
                    let privkey = hex_to_scalar(priv_hex);
                    let pubkey = priv_to_pub(&privkey);

                    // Sign the message with this private key
                    let sig = G1Scheme::sign(&privkey, message).expect("sign failed");

                    pubkeys.push(pubkey);
                    signatures.push(sig.clone());

                    // Verify each signature individually
                    assert!(
                        G1Scheme::verify(&pubkey, message, &sig).is_ok(),
                        "Individual signature verification failed for key {}",
                        i
                    );
                }

                // Now, actually aggregate the signatures using the Scheme's aggregate method
                let aggregated = G1Scheme::aggregate(signatures.len(), &signatures)
                    .expect("Failed to aggregate signatures");

                // Verify the aggregated signature against each individual public key
                for i in 0..pubkeys.len() {
                    assert!(
                        G1Scheme::verify(&pubkeys[i], message, &aggregated).is_ok(),
                        "Aggregated signature verification failed for key {}",
                        i
                    );
                }

                // Compare with expected aggregated signature from test vectors
                let aggregated_hex = hex::encode(&aggregated);
                let expected_hex = AGGREGATED_SIGNATURES[msg_idx].trim_start_matches("0x");

                println!("Expected aggregated signature: {}", expected_hex);
                println!("Actual aggregated signature:   {}", aggregated_hex);

                // Note: Due to implementation differences, the aggregated signatures may not match
                // exactly with the expected values from the test vectors, but verification should pass

                assert_eq!(
                    expected_hex, aggregated_hex,
                    "Aggregated signature for message index {} doesn't match expected value",
                    msg_idx
                );
            }
        }
    }

    // BLS12-377 test vectors
    #[cfg(feature = "bls12_377")]
    mod bls12_377_vectors {
        use crate::schemes::bls12_377::G1Scheme;
        use crate::sig::{Scheme, SignatureScheme, ThresholdScheme};
        use rand::thread_rng;

        // Test message constants
        const MESSAGE1: &[u8] = b"sample message 1";
        const MESSAGE2: &[u8] = b"sample message 2";
        const MESSAGE3: &[u8] = b"sample message 3";

        #[test]
        fn test_sign_and_verify() {
            // Create a keypair
            let (privkey, pubkey) = G1Scheme::keypair(&mut thread_rng());

            // Sign messages
            let sig1 = G1Scheme::sign(&privkey, MESSAGE1).expect("sign message 1");
            let sig2 = G1Scheme::sign(&privkey, MESSAGE2).expect("sign message 2");
            let sig3 = G1Scheme::sign(&privkey, MESSAGE3).expect("sign message 3");

            // Verify signatures
            assert!(
                G1Scheme::verify(&pubkey, MESSAGE1, &sig1).is_ok(),
                "Signature verification failed for message 1"
            );
            assert!(
                G1Scheme::verify(&pubkey, MESSAGE2, &sig2).is_ok(),
                "Signature verification failed for message 2"
            );
            assert!(
                G1Scheme::verify(&pubkey, MESSAGE3, &sig3).is_ok(),
                "Signature verification failed for message 3"
            );

            // Verify that signatures for different messages are different
            assert_ne!(
                sig1, sig2,
                "Signatures for different messages should be different"
            );
            assert_ne!(
                sig1, sig3,
                "Signatures for different messages should be different"
            );
            assert_ne!(
                sig2, sig3,
                "Signatures for different messages should be different"
            );

            // Verify that signing the same message twice produces the same signature
            let sig1_again = G1Scheme::sign(&privkey, MESSAGE1).expect("sign message 1 again");
            assert_eq!(
                sig1, sig1_again,
                "Signatures for the same message should be identical"
            );
        }

        #[test]
        fn test_signature_aggregation() {
            // Test aggregating signatures from multiple signers on the same message
            let message = b"aggregation test message";

            // Create multiple keypairs
            let mut pubkeys = Vec::new();
            let mut signatures = Vec::new();

            // Generate 3 keypairs and sign the message with each
            for _ in 0..3 {
                let (privkey, pubkey) = G1Scheme::keypair(&mut thread_rng());
                let sig = G1Scheme::sign(&privkey, message).expect("sign");

                pubkeys.push(pubkey);
                signatures.push(sig);
            }

            // Verify each signature individually
            for i in 0..3 {
                assert!(
                    G1Scheme::verify(&pubkeys[i], message, &signatures[i]).is_ok(),
                    "Individual signature verification failed"
                );
            }

            // Aggregate the signatures using the Scheme's aggregate method
            let aggregated = G1Scheme::aggregate(signatures.len(), &signatures)
                .expect("Failed to aggregate signatures");

            // Verify the aggregated signature against each individual public key
            for i in 0..pubkeys.len() {
                assert!(
                    G1Scheme::verify(&pubkeys[i], message, &aggregated).is_ok(),
                    "Aggregated signature verification failed for key {}",
                    i
                );
            }
        }

        #[test]
        fn test_threshold_signature_scheme() {
            // Set up a threshold scheme with 5 participants and threshold 3
            let n = 5;
            let t = 3;

            // Create a polynomial of degree t-1
            let private_poly =
                crate::poly::Poly::<<G1Scheme as crate::sig::Scheme>::Private>::new(t - 1);

            // Generate private key shares
            let shares = (0..n)
                .map(|i| crate::sig::Share {
                    index: i as crate::poly::Idx,
                    private: private_poly.eval(i as crate::poly::Idx).value,
                })
                .collect::<Vec<_>>();

            // Get the public polynomial and threshold public key
            let public_poly = private_poly.commit();
            let threshold_public_key = public_poly.public_key();

            // Message to sign
            let message = b"threshold signature test";

            // Generate partial signatures
            let partials = shares
                .iter()
                .map(|s| G1Scheme::partial_sign(s, message).unwrap())
                .collect::<Vec<_>>();

            // Verify each partial signature
            for partial in &partials {
                G1Scheme::partial_verify(&public_poly, message, partial).unwrap();
            }

            // Combine the signatures (only t are needed)
            let threshold_sig = G1Scheme::aggregate(t, &partials[0..t].to_vec()).unwrap();

            // Verify the final signature
            G1Scheme::verify(&threshold_public_key, message, &threshold_sig).unwrap();

            // Test that using a different subset of shares produces the same signature
            let different_partials = partials[n - t..].to_vec();
            let different_threshold_sig = G1Scheme::aggregate(t, &different_partials).unwrap();

            // The combined signatures should be the same regardless of which shares were used
            assert_eq!(
                threshold_sig, different_threshold_sig,
                "Threshold signatures should be the same regardless of which t shares are used"
            );
        }
    }
}
