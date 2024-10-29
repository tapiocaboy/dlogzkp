use super::*;
use k256::elliptic_curve::Field;

mod hash_points_tests {
    use super::*;

    #[test]
    fn test_hash_points_basic() {
        // Test that the hash of a list of points is not zero.
        // The hash should not be zero for a non-empty list of points.
        let sid = "test_session";
        let pid = 1;
        let points = vec![
            ProjectivePoint::GENERATOR,
            ProjectivePoint::GENERATOR * Scalar::ONE,
        ];
        let hash = DLogProof::hash_points(sid, pid, &points).expect("Hash computation failed");
        assert_ne!(hash, Scalar::ZERO, "Hash should not be zero");
    }

    #[test]
    fn test_hash_points_different_sids() {
        // Test that the hash of a list of points is different for different session IDs.
        // The hash should be different for different session IDs.
        let pid = 1;
        let points = vec![ProjectivePoint::GENERATOR];
        let hash1 = DLogProof::hash_points("session1", pid, &points).expect("Hash computation failed");
        let hash2 = DLogProof::hash_points("session2", pid, &points).expect("Hash computation failed");
        assert_ne!(hash1, hash2, "Different session IDs should produce different hashes");
    }

    #[test]
    fn test_hash_points_different_pids() {
        // Test that the hash of a list of points is different for different participant IDs.
        // The hash should be different for different participant IDs.
        let sid = "test_session";
        let points = vec![ProjectivePoint::GENERATOR];
        let hash1 = DLogProof::hash_points(sid, 1, &points).expect("Hash computation failed");
        let hash2 = DLogProof::hash_points(sid, 2, &points).expect("Hash computation failed");
        assert_ne!(hash1, hash2, "Different PIDs should produce different hashes");
    }

    #[test]
    fn test_hash_points_empty_list() {
        // Test that the hash of an empty list of points is not zero.
        // The hash should not be zero for an empty list of points.
        let sid = "test_session";
        let pid = 1;
        let points = vec![];
        let hash = DLogProof::hash_points(sid, pid, &points).expect("Hash computation failed");
        assert_ne!(hash, Scalar::ZERO, "Hash of empty points list should not be zero");
    }
}

mod prove_verify_tests {
    use super::*;

    #[test]
    fn test_basic_prove_and_verify() {
        // Test that a DLog proof can be generated and verified.
        // The proof should verify if it was generated correctly.
        let sid = "test_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
        let result = proof.verify(sid, pid, &y, &base_point).expect("Verification failed");
        assert!(result, "Valid proof should verify");
    }

    #[test]
    fn test_verify_with_wrong_session() {
        // Test that a DLog proof does not verify with the wrong session ID.
        // The proof should not verify if the session ID is incorrect.
        let sid = "test_session";
        let wrong_sid = "wrong_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
        let result = proof
            .verify(wrong_sid, pid, &y, &base_point)
            .expect("Verification failed");
        assert!(!result, "Proof should not verify with wrong session ID");
    }

    #[test]
    fn test_verify_with_wrong_pid() {
        // Test that a DLog proof does not verify with the wrong participant ID.
        // The proof should not verify if the participant ID is incorrect.
        let sid = "test_session";
        let pid = 1;
        let wrong_pid = 2;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
        let result = proof
            .verify(sid, wrong_pid, &y, &base_point)
            .expect("Verification failed");
        assert!(!result, "Proof should not verify with wrong PID");
    }

    #[test]
    fn test_verify_with_wrong_public_key() {
        // Test that a DLog proof does not verify with the wrong public key.
        // The proof should not verify if the public key is incorrect.
        let sid = "test_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        // Create wrong public key by using different scalar
        let wrong_y = base_point * (x + Scalar::ONE);

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
        let result = proof
            .verify(sid, pid, &wrong_y, &base_point)
            .expect("Verification failed");
        assert!(!result, "Proof should not verify with wrong public key");
    }

    #[test]
    fn test_multiple_proofs_same_secret() {
        let sid = "test_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof1 = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("First proof generation failed");
        let proof2 = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Second proof generation failed");

        assert_ne!(proof1, proof2, "Different proofs for same secret should be different");
        
        let result1 = proof1.verify(sid, pid, &y, &base_point).expect("First verification failed");
        let result2 = proof2.verify(sid, pid, &y, &base_point).expect("Second verification failed");
        
        assert!(result1, "First proof should verify");
        assert!(result2, "Second proof should verify");
    }
}

mod random_scalar_tests {
    use super::*;

    #[test]
    fn test_random_scalar_uniqueness() {
        // Test that the generated random scalars are unique.
        // The generated scalars should be different from each other.
        let mut scalars = Vec::new();
        for _ in 0..100 {
            scalars.push(generate_random_scalar());
        }

        // Check that all generated scalars are different
        for i in 0..scalars.len() {
            for j in (i + 1)..scalars.len() {
                assert_ne!(scalars[i], scalars[j], "Generated scalars should be unique");
            }
        }
    }

    #[test]
    fn test_random_scalar_range() {
        // Test that the generated random scalar is within the correct range.
        // The scalar should be greater than zero and less than the curve order.
        for _ in 0..100 {
            let scalar = generate_random_scalar();
            assert_ne!(scalar, Scalar::ZERO, "Random scalar should not be zero");
        }
    }
}

#[test]
fn test_proof_tamper_resistance() {
    // Test that the DLog proof is resistant to tampering.
    // This test should fail if the proof is not resistant to tampering.
    // The proof should not verify if any of the proof values are tampered with.
    let sid = "test_session";
    let pid = 1;
    let x = Scalar::random(&mut OsRng);
    let base_point = ProjectivePoint::GENERATOR;
    let y = base_point * x;

    let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
    let test_scalar = Scalar::ONE.add(&Scalar::ONE);

    // Test different tampering scenarios
    let tampered_proofs = vec![
        DLogProof {
            t: proof.t,
            s: proof.s + Scalar::ONE,
        },
        DLogProof {
            t: proof.t * test_scalar,
            s: proof.s,
        },
        DLogProof {
            t: proof.t + base_point,
            s: proof.s,
        },
    ];

    for (i, tampered_proof) in tampered_proofs.iter().enumerate() {
        let result = tampered_proof
            .verify(sid, pid, &y, &base_point)
            .expect("Verification failed");
        assert!(!result, "Tampered proof {} should not verify", i);
    }
}
