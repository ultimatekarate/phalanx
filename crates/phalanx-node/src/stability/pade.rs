use nalgebra::DMatrix;

// =====================================================================
// MATRIX EXPONENTIAL — Padé(13) Scaling & Squaring (Higham 2005)
// =====================================================================

/// Padé(13) coefficients for the matrix exponential.
const PADE13_B: [f64; 14] = [
    64764752532480000.0,
    32382376266240000.0,
    7771770303897600.0,
    1187353796428800.0,
    129060195264000.0,
    10559470521600.0,
    670442572800.0,
    33522128640.0,
    1323241920.0,
    40840800.0,
    960960.0,
    16380.0,
    182.0,
    1.0,
];

/// Padé(13) scaling-and-squaring matrix exponential.
///
/// Computes exp(A) for a square matrix A using the Higham (2005) algorithm.
/// All linear solves use LU factorization — no explicit matrix inversions.
pub fn mat_exp(a: &DMatrix<f64>) -> DMatrix<f64> {
    let n = a.nrows();
    assert_eq!(n, a.ncols(), "mat_exp requires a square matrix");

    // 1-norm for scaling decision
    let norm1: f64 = (0..n)
        .map(|col| (0..n).map(|row| a[(row, col)].abs()).sum::<f64>())
        .fold(0.0_f64, f64::max);

    // Scaling: s = max(0, ceil(log2(norm1 / theta_13)))
    const THETA_13: f64 = 5.371920351148152;
    let s = if norm1 > THETA_13 {
        (norm1 / THETA_13).log2().ceil() as u32
    } else {
        0
    };

    let a_scaled = if s > 0 {
        a / (2.0_f64.powi(s as i32))
    } else {
        a.clone()
    };

    // Compute matrix powers: A², A⁴, A⁶
    let id = DMatrix::identity(n, n);
    let a2 = &a_scaled * &a_scaled;
    let a4 = &a2 * &a2;
    let a6 = &a4 * &a2;

    // Build U₁₃ and V₁₃ from Padé coefficients
    // V₁₃ = b₀·I + b₂·A² + b₄·A⁴ + b₆·A⁶ + (b₈·A² + b₁₀·A⁴ + b₁₂·A⁶)·A⁶
    // U₁₃ = A·(b₁·I + b₃·A² + b₅·A⁴ + b₇·A⁶ + (b₉·A² + b₁₁·A⁴ + b₁₃·A⁶)·A⁶)
    let v_inner = &a6 * PADE13_B[12] + &a4 * PADE13_B[10] + &a2 * PADE13_B[8];
    let v13 = &v_inner * &a6
        + &a6 * PADE13_B[6]
        + &a4 * PADE13_B[4]
        + &a2 * PADE13_B[2]
        + &id * PADE13_B[0];

    let u_inner = &a6 * PADE13_B[13] + &a4 * PADE13_B[11] + &a2 * PADE13_B[9];
    let u13 = &a_scaled
        * &(&u_inner * &a6
            + &a6 * PADE13_B[7]
            + &a4 * PADE13_B[5]
            + &a2 * PADE13_B[3]
            + &id * PADE13_B[1]);

    // Solve (V₁₃ − U₁₃)·R = V₁₃ + U₁₃ via LU factorization
    let lhs = &v13 - &u13;
    let rhs = &v13 + &u13;
    let lu = lhs.lu();
    let mut result = lu.solve(&rhs).expect("Padé denominator is singular");

    // Repeated squaring: R = R² done s times
    for _ in 0..s {
        result = &result * &result;
    }

    result
}

// =====================================================================
// TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use crate::stability::*;
    use crate::vitals::HomeostaticConfig;
    use nalgebra::DMatrix;

    fn default_cfg() -> HomeostaticConfig {
        HomeostaticConfig::default()
    }

    #[test]
    fn test_mat_exp_identity() {
        // exp(0) = I
        let zero = DMatrix::zeros(DIM, DIM);
        let result = mat_exp(&zero);
        let id = DMatrix::identity(DIM, DIM);
        assert!(
            (&result - &id).norm() < 1e-12,
            "exp(0) should be identity, got norm diff = {}",
            (&result - &id).norm()
        );
    }

    #[test]
    fn test_mat_exp_diagonal() {
        // exp(diag(λ)) = diag(exp(λ))
        // Shout out to Dr. Turc for forcing me to learn this shit.
        let lambdas = [-4.0, -0.5, -0.1, -1.0, -0.3, -0.05, -0.5, -0.2];
        let mut diag = DMatrix::zeros(DIM, DIM);
        for i in 0..DIM {
            diag[(i, i)] = lambdas[i];
        }
        let result = mat_exp(&diag);
        for i in 0..DIM {
            let expected = lambdas[i].exp();
            assert!(
                (result[(i, i)] - expected).abs() < 1e-12,
                "exp(diag)[{},{}] = {}, expected {}",
                i,
                i,
                result[(i, i)],
                expected
            );
            // Off-diagonal should be zero
            for k in 0..DIM {
                if k != i {
                    assert!(
                        result[(i, k)].abs() < 1e-12,
                        "exp(diag)[{},{}] = {}, expected 0",
                        i,
                        k,
                        result[(i, k)]
                    );
                }
            }
        }
    }

    #[test]
    fn test_mat_exp_known_2x2() {
        // exp([[0, 1], [0, 0]]) = [[1, 1], [0, 1]] (nilpotent matrix)
        let mut a = DMatrix::zeros(2, 2);
        a[(0, 1)] = 1.0;
        let result = mat_exp(&a);
        assert!((result[(0, 0)] - 1.0).abs() < 1e-12);
        assert!((result[(0, 1)] - 1.0).abs() < 1e-12);
        assert!((result[(1, 0)] - 0.0).abs() < 1e-12);
        assert!((result[(1, 1)] - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_free_propagator_decays() {
        // ‖G₀(t)‖ → 0 as t → ∞ (all eigenvalues have Re < 0).
        //
        // Note: because J is non-normal (Jsym is NOT negative definite),
        // the propagator norm can experience transient growth before decaying.
        // We test the asymptotic regime (t ≥ 30s) where all modes have decayed.
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());

        let g_30 = mat_exp(&(&j * 30.0));
        let g_60 = mat_exp(&(&j * 60.0));
        let g_120 = mat_exp(&(&j * 120.0));

        assert!(
            g_60.norm() < g_30.norm(),
            "G₀(60) should have smaller norm than G₀(30): {:.6} vs {:.6}",
            g_60.norm(),
            g_30.norm()
        );
        assert!(
            g_120.norm() < g_60.norm(),
            "G₀(120) should have smaller norm than G₀(60)"
        );
        assert!(
            g_120.norm() < 0.01,
            "G₀(120) should be near zero, got ‖G₀‖ = {}",
            g_120.norm()
        );
    }
}
