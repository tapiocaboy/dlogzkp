use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, PrimeField},
    ProjectivePoint, Scalar,
};
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use env_logger::Env;
use log::info;

#[cfg(test)]
mod tests;

/// Represents a Discrete Logarithm (DLOG) proof using the Schnorr protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DLogProof {
    /// The commitment value t
    t: ProjectivePoint,
    /// The response value s
    s: Scalar,
}

impl DLogProof {
    /// Hashes a list of points along with a session ID and participant ID.
    ///
    /// # Arguments
    ///
    /// * `sid` - A string slice that holds the session ID
    /// * `pid` - An unsigned 32-bit integer representing the participant ID
    /// * `points` - A slice of ProjectivePoints to be hashed
    ///
    /// # Returns
    ///
    /// A `Scalar` value representing the hash of the inputs
    ///
    /// # Example
    ///
    /// ```
    /// let sid = "session1";
    /// let pid = 1;
    /// let points = vec![ProjectivePoint::GENERATOR, ProjectivePoint::GENERATOR * Scalar::ONE];
    /// let hash = DLogProof::hash_points(sid, pid, &points);
    /// ```
    fn hash_points(sid: &str, pid: u32, points: &[ProjectivePoint]) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(sid.as_bytes());
        hasher.update(&pid.to_be_bytes());
        for point in points {
            let encoded = point.to_affine().to_encoded_point(false);
            hasher.update(encoded.as_bytes());
        }
        let digest = hasher.finalize();
        Scalar::from_repr(digest.into()).unwrap()
    }

    /// Generates a DLOG proof.
    ///
    /// # Arguments
    ///
    /// * `sid` - A string slice that holds the session ID
    /// * `pid` - An unsigned 32-bit integer representing the participant ID
    /// * `x` - A reference to the secret Scalar value
    /// * `y` - A reference to the public ProjectivePoint (y = x * base_point)
    /// * `base_point` - A reference to the base point (usually the generator)
    ///
    /// # Returns
    ///
    /// A `DLogProof` instance
    ///
    /// # Example
    ///
    /// ```
    /// let sid = "session1";
    /// let pid = 1;
    /// let x = Scalar::random(&mut OsRng);
    /// let y = ProjectivePoint::GENERATOR * x;
    /// let proof = DLogProof::prove(sid, pid, &x, &y, &ProjectivePoint::GENERATOR);
    /// ```
    fn prove(sid: &str, pid: u32, x: &Scalar, y: &ProjectivePoint, base_point: &ProjectivePoint) -> Self {
        let r = Scalar::random(&mut OsRng);
        let t = base_point * &r;
        let c = Self::hash_points(sid, pid, &[*base_point, *y, t]);
        let s = r + c * x;
        DLogProof { t, s }
    }

    /// Verifies a DLOG proof.
    ///
    /// # Arguments
    ///
    /// * `sid` - A string slice that holds the session ID
    /// * `pid` - An unsigned 32-bit integer representing the participant ID
    /// * `y` - A reference to the public ProjectivePoint (y = x * base_point)
    /// * `base_point` - A reference to the base point (usually the generator)
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the proof is valid (true) or not (false)
    ///
    /// # Example
    ///
    /// ```
    /// let sid = "session1";
    /// let pid = 1;
    /// let x = Scalar::random(&mut OsRng);
    /// let y = ProjectivePoint::GENERATOR * x;
    /// let proof = DLogProof::prove(sid, pid, &x, &y, &ProjectivePoint::GENERATOR);
    /// let is_valid = proof.verify(sid, pid, &y, &ProjectivePoint::GENERATOR);
    /// assert!(is_valid);
    /// ```
    fn verify(&self, sid: &str, pid: u32, y: &ProjectivePoint, base_point: &ProjectivePoint) -> bool {
        let c = Self::hash_points(sid, pid, &[*base_point, *y, self.t]);
        let lhs = base_point * &self.s;
        let rhs = self.t + y * &c;
        lhs == rhs
    }
}

/// Generates a random Scalar value.
///
/// # Returns
///
/// A random `Scalar` value
///
/// # Example
///
/// ```
/// let random_scalar = generate_random_scalar();
/// ```
fn generate_random_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

fn main() {
    // Initialize the logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let sid = "sid";
    let pid = 1;

    let x = generate_random_scalar();
    info!("x: {:?}", x);
    let base_point = ProjectivePoint::GENERATOR;
    let y = base_point * x;

    let start_proof = std::time::Instant::now();
    let dlog_proof = DLogProof::prove(sid, pid, &x, &y, &base_point);
    info!(
        "Proof computation time: {} ms",
        start_proof.elapsed().as_millis()
    );

    info!("\nt: {:?}", dlog_proof.t);
    info!("s: {:?}", dlog_proof.s);

    let start_verify = std::time::Instant::now();
    let result = dlog_proof.verify(sid, pid, &y, &base_point);
    info!(
        "Verify computation time: {} ms",
        start_verify.elapsed().as_millis()
    );

    if result {
        info!("DLOG proof is correct");
    } else {
        info!("DLOG proof is not correct");
    }
}
