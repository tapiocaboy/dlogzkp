use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, PrimeField},
    ProjectivePoint, Scalar,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::io::Error;

/// Trait that defines a Discrete Logarithm (DLOG) proof using the Schnorr protocol.
pub trait DiscreteLogProof {
    /// Hashes a list of points along with a session ID and participant ID.
    fn hash_points(sid: &str, pid: u32, points: &[ProjectivePoint]) -> Result<Scalar, Error>;

    /// Generates a DLOG proof.
    fn prove(
        sid: &str,
        pid: u32,
        x: &Scalar,
        y: &ProjectivePoint,
        base_point: &ProjectivePoint,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    /// Verifies a DLOG proof.
    fn verify(
        &self,
        sid: &str,
        pid: u32,
        y: &ProjectivePoint,
        base_point: &ProjectivePoint,
    ) -> Result<bool, Error>;
}

/// Represents a Discrete Logarithm (DLOG) proof using the Schnorr protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DLogProof {
    /// The commitment value t
    pub t: ProjectivePoint,
    /// The response value s
    pub s: Scalar,
}

impl DiscreteLogProof for DLogProof {
    /// Hashes a list of points along with a session ID and participant ID.
    /// # Arguments
    /// * `sid` - The session ID
    /// * `pid` - The participant ID
    /// * `points` - A list of points to hash
    /// # Returns
    /// A scalar value
    /// # Example
    /// ```rust
    /// use k256::{ProjectivePoint, Scalar};
    /// use schnorr_zk_dlog::dlog::{DiscreteLogProof, DLogProof};
    /// let sid = "test_session";
    /// let pid = 1;
    /// let points = vec![];
    /// let hash = DLogProof::hash_points(sid, pid, &points).expect("Hash computation failed");
    /// ```
    fn hash_points(sid: &str, pid: u32, points: &[ProjectivePoint]) -> Result<Scalar, Error> {
        let mut hasher = Sha256::new();
        hasher.update(sid.as_bytes());
        hasher.update(pid.to_be_bytes());

        for point in points {
            let encoded = point.to_affine().to_encoded_point(false);
            hasher.update(encoded.as_bytes());
        }

        let digest = hasher.finalize();
        Scalar::from_repr(digest)
            .into_option()
            .ok_or_else(|| Error::new(std::io::ErrorKind::InvalidData, "Invalid scalar value"))
    }

    /// Generates a DLOG proof.
    /// # Arguments
    /// * `sid` - The session ID
    /// * `pid` - The participant ID
    /// * `x` - The secret scalar value
    /// * `y` - The public key value
    /// * `base_point` - The base point value
    /// # Returns
    /// A DLOG proof
    /// # Example
    /// ```rust
    /// use k256::{ProjectivePoint, Scalar};
    /// use k256::elliptic_curve::{Field, Group};
    /// use rand_core::OsRng;
    /// use schnorr_zk_dlog::dlog::{DiscreteLogProof, DLogProof};
    /// let sid = "test_session";
    /// let pid = 1;
    /// let x = Scalar::random(&mut OsRng);
    /// let base_point = ProjectivePoint::GENERATOR;
    /// let y = base_point * x;
    /// let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
    /// ```
    fn prove(
        sid: &str,
        pid: u32,
        x: &Scalar,
        y: &ProjectivePoint,
        base_point: &ProjectivePoint,
    ) -> Result<Self, Error> {
        let r = Scalar::random(&mut OsRng);
        let t = base_point * &r;

        let c = Self::hash_points(sid, pid, &[*base_point, *y, t])?;
        let s = r + (c * x);

        Ok(DLogProof { t, s })
    }

    /// Verifies a DLOG proof.
    /// # Arguments
    /// * `sid` - The session ID
    /// * `pid` - The participant ID
    /// * `y` - The public key value
    /// * `base_point` - The base point value
    /// # Returns
    /// A boolean indicating if the proof is valid
    /// # Example
    /// ```rust
    /// use k256::{ProjectivePoint, Scalar};
    /// use k256::elliptic_curve::{Field, Group};
    /// use rand_core::OsRng;
    /// use schnorr_zk_dlog::dlog::{DiscreteLogProof, DLogProof};
    /// let sid = "test_session";
    /// let pid = 1;
    /// let x = Scalar::random(&mut OsRng);
    /// let base_point = ProjectivePoint::GENERATOR;
    /// let y = base_point * x;
    /// let proof = DLogProof::prove(sid, pid, &x, &y, &base_point).expect("Proof generation failed");
    /// let result = proof.verify(sid, pid, &y, &base_point).expect("Verification failed");
    /// assert!(result, "Proof should verify");
    /// ```
    fn verify(
        &self,
        sid: &str,
        pid: u32,
        y: &ProjectivePoint,
        base_point: &ProjectivePoint,
    ) -> Result<bool, Error> {
        let c = Self::hash_points(sid, pid, &[*base_point, *y, self.t])?;
        let lhs = base_point * &self.s;
        let rhs = self.t + y * &c;
        Ok(lhs == rhs)
    }
}

impl DLogProof {
    /// Creates a new DLOG proof.
    /// # Arguments
    /// * `t` - The commitment value t
    /// * `s` - The response value s
    /// # Returns
    /// A new DLOG proof
    /// # Example
    /// ```rust
    /// use k256::{ProjectivePoint, Scalar};
    /// use k256::elliptic_curve::{Field, Group};
    /// use rand_core::OsRng;
    /// use schnorr_zk_dlog::dlog::DLogProof;
    /// let t = ProjectivePoint::random(&mut OsRng);
    /// let s = Scalar::random(&mut OsRng);
    /// let proof = DLogProof::new(t, s);
    /// ```
    pub fn new(t: ProjectivePoint, s: Scalar) -> Self {
        DLogProof { t, s }
    }
}
