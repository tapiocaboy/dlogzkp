use super::*;
use k256::elliptic_curve::Field;

mod hash_points_tests {
    use super::*;

    #[test]
    fn test_hash_points_basic() {
        let sid = "test_session";
        let pid = 1;
        let points = vec![
            ProjectivePoint::GENERATOR,
            ProjectivePoint::GENERATOR * Scalar::ONE,
        ];
        let hash = DLogProof::hash_points(sid, pid, &points);
        assert!(hash != Scalar::ZERO, "Hash should not be zero");
    }

    #[test]
    fn test_hash_points_different_sids() {
        let pid = 1;
        let points = vec![ProjectivePoint::GENERATOR];
        let hash1 = DLogProof::hash_points("session1", pid, &points);
        let hash2 = DLogProof::hash_points("session2", pid, &points);
        assert!(hash1 != hash2, "Different session IDs should produce different hashes");
    }

    #[test]
    fn test_hash_points_different_pids() {
        let sid = "test_session";
        let points = vec![ProjectivePoint::GENERATOR];
        let hash1 = DLogProof::hash_points(sid, 1, &points);
        let hash2 = DLogProof::hash_points(sid, 2, &points);
        assert!(hash1 != hash2, "Different PIDs should produce different hashes");
    }

    #[test]
    fn test_hash_points_empty_list() {
        let sid = "test_session";
        let pid = 1;
        let points = vec![];
        let hash = DLogProof::hash_points(sid, pid, &points);
        assert!(hash != Scalar::ZERO, "Hash of empty points list should not be zero");
    }
}

mod prove_verify_tests {
    use super::*;

    #[test]
    fn test_basic_prove_and_verify() {
        let sid = "test_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point);
        assert!(proof.verify(sid, pid, &y, &base_point), "Valid proof should verify");
    }

    #[test]
    fn test_verify_with_wrong_session() {
        let sid = "test_session";
        let wrong_sid = "wrong_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point);
        assert!(!proof.verify(wrong_sid, pid, &y, &base_point), 
            "Proof should not verify with wrong session ID");
    }

    #[test]
    fn test_verify_with_wrong_pid() {
        let sid = "test_session";
        let pid = 1;
        let wrong_pid = 2;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point);
        assert!(!proof.verify(sid, wrong_pid, &y, &base_point), 
            "Proof should not verify with wrong PID");
    }

    #[test]
    fn test_verify_with_wrong_public_key() {
        let sid = "test_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;
        
        // Create wrong public key by using different scalar
        let wrong_y = base_point * (x + Scalar::ONE);

        let proof = DLogProof::prove(sid, pid, &x, &y, &base_point);
        assert!(!proof.verify(sid, pid, &wrong_y, &base_point), 
            "Proof should not verify with wrong public key");
    }

    #[test]
    fn test_multiple_proofs_same_secret() {
        let sid = "test_session";
        let pid = 1;
        let x = Scalar::random(&mut OsRng);
        let base_point = ProjectivePoint::GENERATOR;
        let y = base_point * x;

        let proof1 = DLogProof::prove(sid, pid, &x, &y, &base_point);
        let proof2 = DLogProof::prove(sid, pid, &x, &y, &base_point);

        assert!(proof1 != proof2, "Different proofs for same secret should be different");
        assert!(proof1.verify(sid, pid, &y, &base_point), "First proof should verify");
        assert!(proof2.verify(sid, pid, &y, &base_point), "Second proof should verify");
    }
}

mod random_scalar_tests {
    use super::*;

    #[test]
    fn test_random_scalar_uniqueness() {
        let mut scalars = Vec::new();
        for _ in 0..100 {
            scalars.push(generate_random_scalar());
        }

        // Check that all generated scalars are different
        for i in 0..scalars.len() {
            for j in (i + 1)..scalars.len() {
                assert!(scalars[i] != scalars[j], 
                    "Generated scalars should be unique");
            }
        }
    }

    #[test]
    fn test_random_scalar_range() {
        for _ in 0..100 {
            let scalar = generate_random_scalar();
            assert!(scalar != Scalar::ZERO, "Random scalar should not be zero");
        }
    }
}

#[test]
fn test_proof_tamper_resistance() {
    let sid = "test_session";
    let pid = 1;
    let x = Scalar::random(&mut OsRng);
    let base_point = ProjectivePoint::GENERATOR;
    let y = base_point * x;

    let proof = DLogProof::prove(sid, pid, &x, &y, &base_point);

    let test_scalar = Scalar::ONE.add(&Scalar::ONE);
    
    // Test different tampering scenarios
    let tampered_proofs = vec![
        DLogProof { t: proof.t, s: proof.s + Scalar::ONE },
        DLogProof { t: proof.t * test_scalar, s: proof.s },
        DLogProof { t: proof.t + base_point, s: proof.s },
    ];

    for (i, tampered_proof) in tampered_proofs.iter().enumerate() {
        assert!(!tampered_proof.verify(sid, pid, &y, &base_point), 
            "Tampered proof {} should not verify", i);
    }
}
