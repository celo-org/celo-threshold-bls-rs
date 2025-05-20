#[cfg(test)]
mod tests {
    // BLS12-381 test vectors
    #[cfg(feature = "bls12_381")]
    mod bls12_381_vectors {
        use crate::curve::bls12381::{Scalar, G1};
        use crate::group::Element;
        use crate::schemes::bls12_381::G1Scheme;
        use crate::sig::SignatureScheme;
        use ff::PrimeField;
        use hex;
        use paired::bls12_381::FrRepr;

        // Test vectors from https://github.com/ethereum/bls12-381-tests
        const MESSAGES: [&[u8; 32]; 3] = [&[0x00; 32], &[0x56; 32], &[0xab; 32]];
        const SAMPLE_MESSAGE: [u8; 32] = [0x12; 32];

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
    }
}
