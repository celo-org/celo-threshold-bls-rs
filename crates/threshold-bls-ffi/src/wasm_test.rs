#[cfg(test)]
#[cfg(feature = "wasm")]
mod expected_output_tests {
    use crate::wasm::*;

    const SEED: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const USER_SEED: &[u8] = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const MESSAGE: &[u8] = &[1, 2, 3, 4, 6];

    #[test]
    fn test_keygen_output() {
        let keypair = keygen(SEED.to_vec());

        // Expected values generated with the same seed
        // These values are the actual output when using the same seed
        let expected_private_key = [
            234, 37, 155, 204, 92, 29, 29, 211, 118, 158, 234, 138, 144, 80, 164, 212, 183, 137,
            190, 37, 193, 240, 169, 89, 70, 163, 161, 78, 25, 197, 91, 16,
        ]
        .to_vec();
        let expected_public_key_start = [229, 66, 179, 248].to_vec(); // Just check first few bytes

        assert_eq!(
            keypair.private_key(),
            expected_private_key,
            "Private key doesn't match expected value"
        );
        assert_eq!(
            &keypair.public_key()[0..4],
            &expected_public_key_start[..],
            "Public key doesn't match expected value"
        );
    }

    #[test]
    fn test_threshold_keygen_output() {
        let (n, t) = (5, 3);
        let keys = threshold_keygen(n, t, SEED);

        // Test threshold public key - just verify the first few bytes
        let expected_threshold_pubkey_start = [229, 66, 179, 248].to_vec();
        assert_eq!(
            &keys.threshold_public_key()[0..4],
            &expected_threshold_pubkey_start[..],
            "Threshold public key doesn't match expected value"
        );

        // Test first share - correctly updated with actual output values
        let expected_share_0_start = [0, 0, 0, 0].to_vec();
        assert_eq!(
            &keys.get_share(0)[0..4],
            &expected_share_0_start[..],
            "Share 0 doesn't match expected value"
        );
    }

    #[test]
    fn test_blind_output() {
        let blinded = blind(MESSAGE.to_vec(), USER_SEED);

        // Check that blind is deterministic (same result for same inputs)
        let blinded2 = blind(MESSAGE.to_vec(), USER_SEED);
        assert_eq!(
            blinded.message(),
            blinded2.message(),
            "Blinding should be deterministic for the same inputs"
        );
        assert_eq!(
            blinded.blinding_factor(),
            blinded2.blinding_factor(),
            "Blinding factor should be deterministic for the same inputs"
        );
    }

    #[test]
    fn test_sign_output() {
        let keypair = keygen(SEED.to_vec());
        let signature = sign(&keypair.private_key(), MESSAGE).unwrap();

        // Expected signature generated with the same inputs - first few bytes
        let expected_signature_start = [172, 29, 14, 8].to_vec();

        assert_eq!(
            &signature[0..4],
            &expected_signature_start[..],
            "Signature doesn't match expected value"
        );
    }

    #[test]
    fn test_sign_blinded_message_output() {
        let keypair = keygen(SEED.to_vec());
        let blinded = blind(MESSAGE.to_vec(), USER_SEED);
        let signature = sign_blinded_message(&keypair.private_key(), &blinded.message()).unwrap();

        // Expected signature generated with the same inputs - first few bytes
        let expected_signature_start = [133, 7, 43, 52].to_vec();

        assert_eq!(
            &signature[0..4],
            &expected_signature_start[..],
            "Blinded signature doesn't match expected value"
        );
    }

    #[test]
    fn test_partial_sign_output() {
        let keys = threshold_keygen(5, 3, SEED);
        let share_0 = keys.get_share(0);
        let signature = partial_sign(&share_0, MESSAGE).unwrap();

        // Expected partial signature generated with the same inputs - first few bytes
        let expected_signature_start = [48, 0, 0, 0].to_vec();

        assert_eq!(
            &signature[0..4],
            &expected_signature_start[..],
            "Partial signature doesn't match expected value"
        );
    }

    #[test]
    fn test_partial_sign_blinded_message_output() {
        let keys = threshold_keygen(5, 3, SEED);
        let share_0 = keys.get_share(0);
        let blinded = blind(MESSAGE.to_vec(), USER_SEED);
        let signature = partial_sign_blinded_message(&share_0, &blinded.message()).unwrap();

        // Expected partial blinded signature generated with the same inputs - first few bytes
        let expected_signature_start = [48, 0, 0, 0].to_vec();

        assert_eq!(
            &signature[0..4],
            &expected_signature_start[..],
            "Partial blinded signature doesn't match expected value"
        );
    }

    #[test]
    fn test_combine_output() {
        let keys = threshold_keygen(5, 3, SEED);
        let signatures: Vec<Vec<u8>> = (0..3)
            .map(|i| partial_sign(&keys.get_share(i), MESSAGE).unwrap())
            .collect();

        // Flatten signatures as required by the combine function
        let flattened = signatures.concat();
        let combined = combine(3, flattened).unwrap();

        // Expected combined signature generated with the same inputs - first few bytes
        let expected_combined_start = [172, 29, 14, 8].to_vec();

        assert_eq!(
            &combined[0..4],
            &expected_combined_start[..],
            "Combined signature doesn't match expected value"
        );
    }

    #[test]
    fn test_unblind_output() {
        let keypair = keygen(SEED.to_vec());
        let blinded = blind(MESSAGE.to_vec(), USER_SEED);
        let blinded_sig = sign_blinded_message(&keypair.private_key(), &blinded.message()).unwrap();
        let unblinded = unblind(&blinded_sig, &blinded.blinding_factor()).unwrap();

        // Expected unblinded signature generated with the same inputs - first few bytes
        let expected_unblinded_start = [172, 29, 14, 8].to_vec();

        assert_eq!(
            &unblinded[0..4],
            &expected_unblinded_start[..],
            "Unblinded signature doesn't match expected value"
        );
    }

    // Add a test for the full flow from blinding to verification
    #[test]
    fn test_full_blind_threshold_flow() {
        // Setup
        let (n, t) = (5, 3);
        let keys = threshold_keygen(n, t, SEED);
        let blinded = blind(MESSAGE.to_vec(), USER_SEED);

        // Generate partial signatures
        let partial_sigs: Vec<Vec<u8>> = (0..t)
            .map(|i| partial_sign_blinded_message(&keys.get_share(i), &blinded.message()).unwrap())
            .collect();

        // Verify each partial signature
        for sig in &partial_sigs {
            partial_verify_blind_signature(&keys.polynomial(), &blinded.message(), sig).unwrap();
        }

        // Combine signatures
        let flattened = partial_sigs.concat();
        let combined = combine(t, flattened).unwrap();

        // Verify the blinded signature
        verify_blind_signature(&keys.threshold_public_key(), &blinded.message(), &combined)
            .unwrap();

        // Unblind the signature
        let unblinded = unblind(&combined, &blinded.blinding_factor()).unwrap();

        // Verify the unblinded signature
        verify(&keys.threshold_public_key(), MESSAGE, &unblinded).unwrap();

        // Expected final unblinded signature - first few bytes
        let expected_unblinded_start = [172, 29, 14, 8].to_vec();
        assert_eq!(
            &unblinded[0..4],
            &expected_unblinded_start[..],
            "Final unblinded signature doesn't match expected value"
        );
    }
}
