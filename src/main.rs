use env_logger::Env;
use k256::{
    elliptic_curve::Field,
    ProjectivePoint, Scalar,
};
use log::info;
use rand_core::OsRng;
use schnorr_zk_dlog::dlog::DLogProof;
use schnorr_zk_dlog::dlog::DiscreteLogProof;
#[cfg(test)]
mod tests;


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
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let sid = "sid";
    let pid = 1;

    let x = generate_random_scalar();
    info!("x: {:?}", x);
    let base_point = ProjectivePoint::GENERATOR;
    let y = base_point * x;

    let start_proof = std::time::Instant::now();
    match DLogProof::prove(sid, pid, &x, &y, &base_point) {
        Ok(dlog_proof) => {
            info!(
                "Proof computation time: {} ms",
                start_proof.elapsed().as_millis()
            );

            info!("\nt: {:?}", dlog_proof.t);
            info!("s: {:?}", dlog_proof.s);

            let start_verify = std::time::Instant::now();
            match dlog_proof.verify(sid, pid, &y, &base_point) {
                Ok(result) => {
                    info!(
                        "Verify computation time: {} ms",
                        start_verify.elapsed().as_millis()
                    );
                    if result {
                        info!("DLOG proof is correct");
                    } else {
                        info!("DLOG proof is incorrect");
                    }
                }
                Err(e) => info!("Verification error: {}", e),
            }
        }
        Err(e) => info!("Proof generation error: {}", e),
    }
}
