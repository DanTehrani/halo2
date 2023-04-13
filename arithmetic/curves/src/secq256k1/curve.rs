use crate::secq256k1::Fp;
use crate::secq256k1::Fq;
use crate::{Coordinates, CurveAffine, CurveAffineExt, CurveExt, Group};
use core::cmp;
use core::fmt::Debug;
use core::iter::Sum;
use core::ops::{Add, Mul, Neg, Sub};
use ff::{Field, PrimeField};
use group::Curve;
use group::{prime::PrimeCurveAffine, Group as _, GroupEncoding};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

impl Secq256k1 {
    fn endomorphism_base(&self) -> Self {
        unimplemented!();
    }
}

impl group::cofactor::CofactorGroup for Secq256k1 {
    type Subgroup = Secq256k1;

    fn clear_cofactor(&self) -> Self {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self, 1.into())
    }

    fn is_torsion_free(&self) -> Choice {
        1.into()
    }
}

const SECQ_GENERATOR_X: Fp = Fp::from_raw([
    0x860fee175831bb20,
    0x2cabb9347a25101b,
    0xe7590cbef17c26fc,
    0x9214b8774eb1412b,
]);
const SECQ_GENERATOR_Y: Fp = Fp::from_raw([
    0x14a1bc519466eb6b,
    0x836a6e341a88892a,
    0xecc5b53440a7598a,
    0x28cb5b51a30b5532,
]);
const SECQ_B: Fp = Fp::from_raw([7, 0, 0, 0]);

use crate::{
    batch_add, impl_add_binop_specify_output, impl_binops_additive,
    impl_binops_additive_specify_output, impl_binops_multiplicative,
    impl_binops_multiplicative_mixed, impl_sub_binop_specify_output, new_curve_impl,
};

new_curve_impl!(
    (pub),
    Secq256k1,
    Secq256k1Affine,
    Secq256k1Compressed,
    33,
    Fp,
    Fq,
    (SECQ_GENERATOR_X,SECQ_GENERATOR_Y),
    SECQ_B,
    "secq256k1",
);

impl CurveAffineExt for Secq256k1Affine {
    batch_add!();

    fn into_coordinates(self) -> (Self::Base, Self::Base) {
        (self.x, self.y)
    }
}

#[test]
fn test_curve() {
    crate::tests::curve::curve_tests::<Secq256k1>();
}

#[test]
fn test_serialization() {
    crate::tests::curve::random_serialization_test::<Secq256k1>();
}

#[test]
fn ecdsa_example() {
    use crate::group::Curve;
    use crate::{CurveAffine, FieldExt};
    use rand_core::OsRng;

    fn mod_n(x: Fp) -> Fq {
        let mut x_repr = [0u8; 32];
        x_repr.copy_from_slice(x.to_repr().as_ref());
        let mut x_bytes = [0u8; 64];
        x_bytes[..32].copy_from_slice(&x_repr[..]);
        Fq::from_bytes_wide(&x_bytes)
    }

    let g = Secq256k1::generator();

    for _ in 0..1000 {
        // Generate a key pair
        let sk = Fq::random(OsRng);
        let pk = (g * sk).to_affine();

        // Generate a valid signature
        // Suppose `m_hash` is the message hash
        let msg_hash = Fq::random(OsRng);

        let (r, s) = {
            // Draw arandomness
            let k = Fq::random(OsRng);
            let k_inv = k.invert().unwrap();

            // Calculate `r`
            let r_point = (g * k).to_affine().coordinates().unwrap();
            let x = r_point.x();
            let r = mod_n(*x);

            // Calculate `s`
            let s = k_inv * (msg_hash + (r * sk));

            (r, s)
        };

        {
            // Verify
            let s_inv = s.invert().unwrap();
            let u_1 = msg_hash * s_inv;
            let u_2 = r * s_inv;

            let v_1 = g * u_1;
            let v_2 = pk * u_2;

            let r_point = (v_1 + v_2).to_affine().coordinates().unwrap();
            let x_candidate = r_point.x();
            let r_candidate = mod_n(*x_candidate);

            assert_eq!(r, r_candidate);
        }
    }
}
