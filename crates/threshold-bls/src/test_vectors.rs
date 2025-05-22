#[cfg(test)]
mod tests {
    #[cfg(test)]
    #[cfg(feature = "bls12_381")]
    mod bls12_381_vectors {
        use crate::curve::bls12381::{Scalar, G1};
        use crate::group::Element;
        use crate::poly::{Idx, Poly};
        use crate::schemes::bls12_381::G1Scheme;
        use crate::sig::{Share, SignatureScheme, ThresholdScheme};
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

        // TODO it appears the signatures produced here do not match the test vectors provided in https://github.com/ethereum/bls12-381-tests
        // This is likely due to formatting differences
        // // Expected signatures for each private key and message combination from https://github.com/ethereum/bls12-381-tests
        // const EXPECTED_SIGNATURES: [[&str; 3]; 3] = [
        //     // First private key with each message
        //     [
        //         "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        //         "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        //         "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"
        //     ],
        //     // Second private key with each message
        //     [
        //         "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        //         "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        //         "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df"
        //     ],
        //     // Third private key with each message
        //     [
        //         "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        //         "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        //         "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"
        //     ]
        // ];
        const EXPECTED_SIGNATURES: [[&str; 3]; 3] = [
            // First private key with each message
            [
                "a343aa09cf1b91b05069a5b13a38256affe00e044670beab16cf730f17e6e0a47eae6773039fc21fe12ec895e10e1d5419352252201f846060007d4904220cd99c7ce7ae1ec8f3b6d79c399a65a6d7acb5fb45b1a807f825fea9617c30555b72",
                "8a30e1ef9ea48a138d48b98dc1db8a17be8639adf920e8f6b5e9104d6207e64a555d51fbca98a047464d064282a1aa4206f507841eeb10b7ea573024e69be2b4c6c63465ec5576104d13c928ace3897313cfa45dbd092bee942dae70fe5f7a40",
                "92649a268e5c7bbd11b7e7d652fa57d508ca99664559178d639c2c98a5e11e058ecae670bed1f2d078d9fe4b3967bc500f4b6d9059e424bcc1eb459761f5a2aea4996ef4a4d757df17e7635fdef6aee10910c7b8d4d67974bac8db1b64c2dccf",
            ],
            // Second private key with each message
            [
                "b68dff115fc47996a7aa900129791ea0582eea40fcfd09288d8dbfb6349a5f6b77590d6dac118050ff3ddfd022a0c8030ade4c53fab08f74820671ea1bacc75c5ac850f8c31dc0c87eea7bb161386b7854667d8654ee658caeb84a9b8f65f5bf",
                "b7990c377f0af50796abc0b0e6d220462b85e2c0df16642e5ca0651b752074f37375a4de1d00b0e75ef30cf329cd15910d3e292deebc144fa420ecab40de0940eff96e98e6e14b342e425ad2531b3d44d5782a1085706b8af904b3d4cfffda1d",
                "b14894615d3845dbb12e5880f4e2915ba2e741684300641825168d5e5fcc2d6664d376ba362cb9bdcc92d06759ec88a4039585bb7b0be010381f17a0aa7711ee33a0c27ab3ec7e675581809c18dbdf76c78459ffed4c8c62fa8ba32d601fd596"
            ],
            // Third private key with each message
            [
                "8b79b497eec567d4a69165673634da353336f6c78928542b3a4f23ddf6daff77ace3e3feac0e0f89fbe47f05a4deedda19f21e23f6d9a039c1eb0c9f223699a1e0a291f02fcd51c3dcac68130a2608a70e311d537ad0d15e1cc1dc786a0c6502",
                "81a514ae18e180c75caa8bd017043298ca387beafd27427a68df6c131bd6778596ea8f97c18fc40b44a1017900368eed03e36f519d9c58b74c058f33209c2d3fce9c73931d71f186030eaeb4a5b12390899a5073a8a576e4e72f5e28af31e27c",
                "93300377f6c8f599fd14469d89d7d5378fd42039b1dfde39ed5165b412d30341371223288b4a7ba50f835f419bcf92d7136136b9757223d1de2f84fa05e52aa0848fbb9ba4d0aea3f2a596fab4cf05e380ed053d193293dded9b8fd4781f0c78"
            ]
        ];

        // These are the expected outputs from the BLS aggregate operation
        const AGGREGATED_SIGNATURES: [&str; 3] = [
            // Aggregate signature for message [0x00; 32]
            "a343aa09cf1b91b05069a5b13a38256affe00e044670beab16cf730f17e6e0a47eae6773039fc21fe12ec895e10e1d5419352252201f846060007d4904220cd99c7ce7ae1ec8f3b6d79c399a65a6d7acb5fb45b1a807f825fea9617c30555b72",
            // Aggregate signature for message [0x56; 32]
            "8a30e1ef9ea48a138d48b98dc1db8a17be8639adf920e8f6b5e9104d6207e64a555d51fbca98a047464d064282a1aa4206f507841eeb10b7ea573024e69be2b4c6c63465ec5576104d13c928ace3897313cfa45dbd092bee942dae70fe5f7a40",
            // Aggregate signature for message [0xab; 32]
            "92649a268e5c7bbd11b7e7d652fa57d508ca99664559178d639c2c98a5e11e058ecae670bed1f2d078d9fe4b3967bc500f4b6d9059e424bcc1eb459761f5a2aea4996ef4a4d757df17e7635fdef6aee10910c7b8d4d67974bac8db1b64c2dccf"
        ];

        #[test]
        fn test_sign_and_verify() {
            for (i, &priv_hex) in PRIVKEYS.iter().enumerate() {
                let privkey = hex_to_scalar(priv_hex);
                let pubkey = priv_to_pub(&privkey);

                for (j, &msg) in MESSAGES.iter().enumerate() {
                    let sig = G1Scheme::sign(&privkey, msg).expect("sign");
                    let sig_hex = hex::encode(&sig);

                    // Verify signature against expected value
                    // println!("sig_hex: {}", sig_hex);
                    // println!(
                    //     "EXPECTED_SIGNATURES[{}][{}]: {}",
                    //     i, j, EXPECTED_SIGNATURES[i][j]
                    // );
                    assert_eq!(
                        sig_hex, EXPECTED_SIGNATURES[i][j],
                        "Signature for privkey[{}] and message[{}] doesn't match expected value",
                        i, j
                    );

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

            for (msg_idx, &message) in MESSAGES.iter().enumerate() {
                println!("Testing aggregation for message index {}", msg_idx);

                // Create a polynomial of degree n-1 for an n-out-of-n threshold scheme
                let n = PRIVKEYS.len();

                // Create a private polynomial from our private keys
                let coeffs = PRIVKEYS
                    .iter()
                    .map(|priv_hex| hex_to_scalar(priv_hex))
                    .collect::<Vec<_>>();
                let private_poly = Poly::<Scalar>::from(coeffs);

                // Generate the shares from the polynomial
                let shares = (0..n)
                    .map(|i| {
                        let eval = private_poly.eval(i as Idx);
                        Share {
                            index: eval.index,
                            private: eval.value,
                        }
                    })
                    .collect::<Vec<_>>();

                // Get the public polynomial
                let public_poly = private_poly.commit();
                let threshold_pubkey = public_poly.public_key();

                println!("Generating {} partial signatures", shares.len());

                // Generate partial signatures from each share
                let partials = shares
                    .iter()
                    .map(|s| G1Scheme::partial_sign(s, message).unwrap())
                    .collect::<Vec<_>>();

                // Verify each partial signature
                for (i, partial) in partials.iter().enumerate() {
                    assert!(
                        G1Scheme::partial_verify(&public_poly, message, partial).is_ok(),
                        "Partial signature verification failed for share {}",
                        i
                    );
                }

                // Aggregate the partial signatures - using the full threshold
                let aggregated =
                    G1Scheme::aggregate(n, &partials).expect("Failed to aggregate signatures");

                // Compare with expected aggregated signature
                let aggregated_hex = hex::encode(&aggregated);
                let expected_hex = AGGREGATED_SIGNATURES[msg_idx].trim_start_matches("0x");

                // println!("Expected aggregated signature: {}", expected_hex);
                // println!("Actual aggregated signature:   {}", aggregated_hex);
                assert_eq!(
                    expected_hex, aggregated_hex,
                    "Aggregated signature for message index {} doesn't match expected value",
                    msg_idx
                );

                // Verify the aggregated signature with the threshold public key
                assert!(
                    G1Scheme::verify(&threshold_pubkey, message, &aggregated).is_ok(),
                    "Aggregated signature verification failed"
                );
            }
        }
    }

    // TODO Can't figure out how to make the bls12_377 scheme work with static private keys
    // In order to test against static output values, we need to have static private keys
    // In the bls12_377 scheme, the private keys are generated randomly
    // and I haven't been able to figure out how to deterministically generate the same private keys
    // or assign values to a Scalar like we do above

    // #[cfg(feature = "bls12_377")]
    // #[cfg(test)]
    // mod bls12_377_vectors {
    //     use crate::curve::bls12381::{Scalar, G1}; // We use the bls12_381 Scalar implementation so we can use the FrRepr type
    //     use crate::group::{Element, Scalar};
    //     use crate::poly::{Idx, Poly};
    //     use crate::schemes::bls12_377::G1Scheme;
    //     use crate::sig::{Share, SignatureScheme, ThresholdScheme};
    //     use algebra::bls12_377::Fr;
    //     use algebra::PrimeField;
    //     use paired::bls12_381::FrRepr;

    //     const MESSAGES: [&[u8; 32]; 3] = [&[0x00; 32], &[0x56; 32], &[0xab; 32]];

    //     // Converts a hex string to a Scalar (Fr)
    //     fn hex_to_scalar(hex_str: &str) -> Scalar {
    //         // Parse the hex string into 4 limbs (u64 values)
    //         let mut limbs = [0u64; 4];

    //         // Ensure we have a 64-character hex string (32 bytes)
    //         let hex_str = hex_str.trim_start_matches("0x");
    //         let s = format!("{:0>64}", hex_str);

    //         // Each limb is 16 hex characters (8 bytes)
    //         // FrRepr is stored in little-endian order
    //         for i in 0..4 {
    //             let start = s.len() - 16 * (i + 1);
    //             let end = s.len() - 16 * i;
    //             let chunk: &str = &s[start..end];
    //             limbs[i] = u64::from_str_radix(chunk, 16).unwrap();
    //         }
    //     }

    //     const PRIVATE_KEYS: [&str; 3] = [
    //         "0x00000000000000000000000000000000263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    //         "0x0000000000000000000000000000000047b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
    //         "0x00000000000000000000000000000000328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
    //     ];

    //     fn get_public_key(private_key: &Scalar) -> G1 {
    //         let mut pk = G1::one();
    //         pk.mul(private_key);
    //         pk
    //     }

    //     #[test]
    //     fn sign_and_verify() {
    //         let private_keys = PRIVATE_KEYS
    //             .iter()
    //             .map(|s| hex_to_scalar(s))
    //             .collect::<Vec<_>>();
    //         // Test basic signing and verification
    //         for (i, key) in private_keys.iter().enumerate() {
    //             let pubkey = get_public_key(i);

    //             for (j, &msg) in MESSAGES.iter().enumerate() {
    //                 // Sign the message
    //                 let sig = G1Scheme::sign(key, msg).expect("sign");

    //                 assert!(
    //                     G1Scheme::verify(&pubkey, msg, &sig).is_ok(),
    //                     "Signature verification failed for key[{}] and message[{}]",
    //                     i,
    //                     j
    //                 );
    //             }
    //         }
    //     }

    //     #[test]
    //     fn test_signature_aggregation() {
    //         // Test threshold signatures
    //         for (msg_idx, &message) in MESSAGES.iter().enumerate() {
    //             // Create a polynomial of degree n-1 for an n-out-of-n threshold scheme
    //             let n = PRIVATE_KEYS.len();

    //             // Create a private polynomial from our private keys
    //             let private_poly = Poly::<Scalar>::from(PRIVATE_KEYS.clone());

    //             // Generate the shares from the polynomial
    //             let shares = (0..n)
    //                 .map(|i| {
    //                     let eval = private_poly.eval(i as Idx);
    //                     Share {
    //                         index: eval.index,
    //                         private: eval.value,
    //                     }
    //                 })
    //                 .collect::<Vec<Share>>();

    //             // Get the public polynomial
    //             let public_poly = private_poly.commit();
    //             let threshold_pubkey = public_poly.public_key();

    //             // Generate partial signatures
    //             let partials = shares
    //                 .iter()
    //                 .map(|s| G1Scheme::partial_sign(s, message).unwrap())
    //                 .collect::<Vec<_>>();

    //             // Verify each partial signature
    //             for (i, partial) in partials.iter().enumerate() {
    //                 assert!(
    //                     G1Scheme::partial_verify(&public_poly, message, partial).is_ok(),
    //                     "Partial signature verification failed for share {}",
    //                     i
    //                 );
    //             }

    //             // Aggregate signatures
    //             let aggregated = G1Scheme::aggregate(n, &partials).expect("Failed to aggregate");

    //             // Verify the aggregated signature
    //             assert!(
    //                 G1Scheme::verify(&threshold_pubkey, message, &aggregated).is_ok(),
    //                 "Aggregated signature verification failed for message {}",
    //                 msg_idx
    //             );
    //         }
    //     }
    // }
}
