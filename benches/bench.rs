// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bn254::{Bn254, Fr as BnFr};
use ark_crypto_primitives::snark::SNARK;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub f_phantom: PhantomData<F>,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            f_phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let (ark, mds) =
            find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8u64, 31u64, 0u64);

        let sponge_params = PoseidonConfig {
            full_rounds: 8usize,
            partial_rounds: 31usize,
            alpha: 17u64,
            ark,
            mds,
            rate: 2,
            capacity: 1,
        };

        let mut constraint_sponge = PoseidonSpongeVar::<F>::new(cs.clone(), &sponge_params);

        let rng = &mut ark_std::test_rng();

        for _ in 0..500 {
            let a = F::rand(rng);
            let b = F::rand(rng);

            let a_var = FpVar::new_witness(cs.clone(), || Ok(a))?;
            let b_var = FpVar::new_witness(cs.clone(), || Ok(b))?;

            constraint_sponge.absorb(&a_var)?;
            constraint_sponge.absorb(&b_var)?;
            constraint_sponge.squeeze_field_elements(1)?;
        }

        Ok(())
    }
}

macro_rules! groth16_prove_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
        let c = DummyCircuit::<$bench_field> {
            f_phantom: PhantomData,
        };

        let (pk, _) = Groth16::<$bench_pairing_engine>::circuit_specific_setup(c, rng).unwrap();

        let start = ark_std::time::Instant::now();

        for i in 0..10 {
            println!("doing {}", i);
            let _ = Groth16::<$bench_pairing_engine>::prove(&pk, c.clone(), rng).unwrap();
        }

        println!(
            "proving time for {}: {} s",
            stringify!($bench_pairing_engine),
            start.elapsed().as_secs_f64() / 10
        );
    };
}

fn bench_prove() {
    use ark_std::rand::SeedableRng;
    groth16_prove_bench!(bn, BnFr, Bn254);
}

fn main() {
    bench_prove();
}
