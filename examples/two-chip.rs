extern crate halo2;

use std::marker::PhantomData;

use halo2::{
    arithmetic::FieldExt,
    circuit::{layouter::SingleChipLayouter, Cell, Chip, Layouter, Region},
    dev::VerifyFailure,
    plonk::{
        Advice, Assignment, Circuit, Column, ConstraintSystem, Error, Instance, Permutation,
        Selector,
    },
    poly::Rotation,
};

// ANCHOR: field-instructions
/// A variable representing a number.
#[derive(Clone)]
struct Number<F: FieldExt> {
    cell: Cell,
    value: Option<F>,
}

trait FieldInstructions<F: FieldExt>: AddInstructions<F> + MulInstructions<F> {
    /// Variable representing a number.
    type Num;

    /// Loads a number into the circuit as a private input.
    fn load_private(
        &self,
        layouter: impl Layouter<F>,
        a: Option<F>,
    ) -> Result<<Self as FieldInstructions<F>>::Num, Error>;

    /// Returns `d = (a + b) * c`.
    fn add_and_mul(
        &self,
        layouter: &mut impl Layouter<F>,
        a: <Self as FieldInstructions<F>>::Num,
        b: <Self as FieldInstructions<F>>::Num,
        c: <Self as FieldInstructions<F>>::Num,
    ) -> Result<<Self as FieldInstructions<F>>::Num, Error>;

    /// Exposes a number as a public input to the circuit.
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: <Self as FieldInstructions<F>>::Num,
    ) -> Result<(), Error>;
}
// ANCHOR_END: field-instructions

// ANCHOR: add-instructions
trait AddInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Num;

    /// Returns `c = a + b`.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;
}
// ANCHOR_END: add-instructions

// ANCHOR: mul-instructions
trait MulInstructions<F: FieldExt>: Chip<F> {
    /// Variable representing a number.
    type Num;

    /// Returns `c = a * b`.
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;
}
// ANCHOR_END: mul-instructions

// ANCHOR: field-config
// The top-level config that provides all necessary columns and permutations
// for the other configs.
#[derive(Clone, Debug)]
struct FieldConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    // We need to create a permutation between our advice columns. This allows us to
    // copy numbers within these columns from arbitrary rows, which we can use to load
    // inputs into our instruction regions.
    perm: Permutation,

    // The selector for the public-input gate, which uses one of the advice columns.
    s_pub: Selector,

    add_config: AddConfig,
    mul_config: MulConfig,
}
// ANCHOR END: field-config

// ANCHOR: add-config
#[derive(Clone, Debug)]
struct AddConfig {
    advice: [Column<Advice>; 2],
    perm: Permutation,
    s_add: Selector,
}
// ANCHOR_END: add-config

// ANCHOR: mul-config
#[derive(Clone, Debug)]
struct MulConfig {
    advice: [Column<Advice>; 2],
    perm: Permutation,
    s_mul: Selector,
}
// ANCHOR END: mul-config

// ANCHOR: field-chip
/// The top-level chip that will implement the `FieldInstructions`.
struct FieldChip<F: FieldExt> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}
// ANCHOR_END: field-chip

// ANCHOR: add-chip
struct AddChip<F: FieldExt> {
    config: AddConfig,
    _marker: PhantomData<F>,
}
// ANCHOR END: add-chip

// ANCHOR: mul-chip
struct MulChip<F: FieldExt> {
    config: MulConfig,
    _marker: PhantomData<F>,
}
// ANCHOR_END: mul-chip

// ANCHOR: add-chip-trait-impl
impl<F: FieldExt> Chip<F> for AddChip<F> {
    type Config = AddConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
// ANCHOR END: add-chip-trait-impl

// ANCHOR: add-chip-impl
impl<F: FieldExt> AddChip<F> {
    fn construct(config: <Self as Chip<F>>::Config, _loaded: <Self as Chip<F>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        perm: Permutation,
    ) -> <Self as Chip<F>>::Config {
        let s_add = meta.selector();

        // Define our addition gate!
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add, Rotation::cur());

            vec![s_add * (lhs + rhs + out * -F::one())]
        });

        AddConfig {
            advice,
            perm,
            s_add,
        }
    }
}
// ANCHOR END: add-chip-impl

// ANCHOR: add-instructions-impl
impl<F: FieldExt> AddInstructions<F> for FieldChip<F> {
    type Num = Number<F>;
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config().add_config.clone();

        let add_chip = AddChip::<F>::construct(config, ());
        add_chip.add(layouter, a, b)
    }
}

impl<F: FieldExt> AddInstructions<F> for AddChip<F> {
    type Num = Number<F>;

    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        let mut out = None;
        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_add.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                let lhs = region.assign_advice(
                    || "lhs",
                    config.advice[0],
                    0,
                    || a.value.ok_or(Error::SynthesisError),
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    config.advice[1],
                    0,
                    || b.value.ok_or(Error::SynthesisError),
                )?;
                region.constrain_equal(&config.perm, a.cell, lhs)?;
                region.constrain_equal(&config.perm, b.cell, rhs)?;

                // Now we can assign the multiplication result into the output position.
                let value = a.value.and_then(|a| b.value.map(|b| a + b));
                let cell = region.assign_advice(
                    || "lhs * rhs",
                    config.advice[0],
                    1,
                    || value.ok_or(Error::SynthesisError),
                )?;

                // Finally, we return a variable representing the output,
                // to be used in another part of the circuit.
                out = Some(Number { cell, value });
                Ok(())
            },
        )?;

        Ok(out.unwrap())
    }
}
// ANCHOR END: add-instructions-impl

// ANCHOR: mul-chip-trait-impl
impl<F: FieldExt> Chip<F> for MulChip<F> {
    type Config = MulConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
// ANCHOR END: mul-chip-trait-impl

// ANCHOR: mul-chip-impl
impl<F: FieldExt> MulChip<F> {
    fn construct(config: <Self as Chip<F>>::Config, _loaded: <Self as Chip<F>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        perm: Permutation,
    ) -> <Self as Chip<F>>::Config {
        let s_mul = meta.selector();

        // Define our multiplication gate!
        meta.create_gate("mul", |meta| {
            // To implement multiplication, we need three advice cells and a selector
            // cell. We arrange them like so:
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            // Gates may refer to any relative offsets we want, but each distinct
            // offset adds a cost to the proof. The most common offsets are 0 (the
            // current row), 1 (the next row), and -1 (the previous row), for which
            // `Rotation` has specific constructors.
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul, Rotation::cur());

            // The polynomial expression returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            // has the following properties:
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs + out * -F::one())]
        });

        MulConfig {
            advice,
            perm,
            s_mul,
        }
    }
}
// ANCHOR_END: mul-chip-impl

// ANCHOR: mul-instructions-impl
impl<F: FieldExt> MulInstructions<F> for FieldChip<F> {
    type Num = Number<F>;
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config().mul_config.clone();
        let mul_chip = MulChip::<F>::construct(config, ());
        mul_chip.mul(layouter, a, b)
    }
}

impl<F: FieldExt> MulInstructions<F> for MulChip<F> {
    type Num = Number<F>;

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        let mut out = None;
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                let lhs = region.assign_advice(
                    || "lhs",
                    config.advice[0],
                    0,
                    || a.value.ok_or(Error::SynthesisError),
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    config.advice[1],
                    0,
                    || b.value.ok_or(Error::SynthesisError),
                )?;
                region.constrain_equal(&config.perm, a.cell, lhs)?;
                region.constrain_equal(&config.perm, b.cell, rhs)?;

                // Now we can assign the multiplication result into the output position.
                let value = a.value.and_then(|a| b.value.map(|b| a * b));
                let cell = region.assign_advice(
                    || "lhs * rhs",
                    config.advice[0],
                    1,
                    || value.ok_or(Error::SynthesisError),
                )?;

                // Finally, we return a variable representing the output,
                // to be used in another part of the circuit.
                out = Some(Number { cell, value });
                Ok(())
            },
        )?;

        Ok(out.unwrap())
    }
}
// ANCHOR END: mul-instructions-impl

// ANCHOR: field-chip-trait-impl
impl<F: FieldExt> Chip<F> for FieldChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
// ANCHOR_END: field-chip-trait-impl

// ANCHOR: field-chip-impl
impl<F: FieldExt> FieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config, _loaded: <Self as Chip<F>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        let perm = Permutation::new(
            meta,
            &advice
                .iter()
                .map(|column| (*column).into())
                .collect::<Vec<_>>(),
        );
        let s_pub = meta.selector();

        // Define our public-input gate!
        meta.create_gate("public input", |meta| {
            // We choose somewhat-arbitrarily that we will use the second advice
            // column for exposing numbers as public inputs.
            let a = meta.query_advice(advice[1], Rotation::cur());
            let p = meta.query_instance(instance, Rotation::cur());
            let s = meta.query_selector(s_pub, Rotation::cur());

            // We simply constrain the advice cell to be equal to the instance cell,
            // when the selector is enabled.
            vec![s * (p + a * -F::one())]
        });

        let add_config = AddChip::configure(meta, advice, perm.clone());
        let mul_config = MulChip::configure(meta, advice, perm.clone());

        FieldConfig {
            advice,
            perm,
            s_pub,
            add_config,
            mul_config,
        }
    }
}
// ANCHOR_END: field-chip-impl

// ANCHOR: field-instructions-impl
impl<F: FieldExt> FieldInstructions<F> for FieldChip<F> {
    type Num = Number<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Option<F>,
    ) -> Result<<Self as FieldInstructions<F>>::Num, Error> {
        let config = self.config();

        let mut num = None;
        layouter.assign_region(
            || "load private",
            |mut region| {
                let cell = region.assign_advice(
                    || "private input",
                    config.advice[0],
                    0,
                    || value.ok_or(Error::SynthesisError),
                )?;
                num = Some(Number { cell, value });
                Ok(())
            },
        )?;
        Ok(num.unwrap())
    }

    /// Returns `d = (a + b) * c`.
    fn add_and_mul(
        &self,
        layouter: &mut impl Layouter<F>,
        a: <Self as FieldInstructions<F>>::Num,
        b: <Self as FieldInstructions<F>>::Num,
        c: <Self as FieldInstructions<F>>::Num,
    ) -> Result<<Self as FieldInstructions<F>>::Num, Error> {
        let ab = self.add(layouter.namespace(|| "a + b"), a, b)?;
        self.mul(layouter.namespace(|| "(a + b) * c"), ab, c)
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: <Self as FieldInstructions<F>>::Num,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.assign_region(
            || "expose public",
            |mut region: Region<'_, F>| {
                // Enable the public-input gate.
                config.s_pub.enable(&mut region, 0)?;

                // Load the output into the correct advice column.
                let out = region.assign_advice(
                    || "public advice",
                    config.advice[1],
                    0,
                    || num.value.ok_or(Error::SynthesisError),
                )?;
                region.constrain_equal(&config.perm, num.cell, out)?;

                // We don't assign to the instance column inside the circuit;
                // the mapping of public inputs to cells is provided to the prover.
                Ok(())
            },
        )
    }
}
// ANCHOR_END: field-instructions-impl

// ANCHOR: circuit
/// The full circuit implementation.
///
/// In this struct we store the private input variables. We use `Option<F>` because
/// they won't have any value during key generation. During proving, if any of these
/// were `None` we would get an error.
struct MyCircuit<F: FieldExt> {
    a: Option<F>,
    b: Option<F>,
    c: Option<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = FieldConfig;

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        FieldChip::configure(meta, advice, instance)
    }

    fn synthesize(&self, cs: &mut impl Assignment<F>, config: Self::Config) -> Result<(), Error> {
        let mut layouter = SingleChipLayouter::new(cs)?;
        let field_chip = FieldChip::<F>::construct(config, ());

        // Load our private values into the circuit.
        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let c = field_chip.load_private(layouter.namespace(|| "load c"), self.c)?;

        // Use `add_and_mul` to get `d = (a + b) * c`.
        let d = field_chip.add_and_mul(&mut layouter, a, b, c)?;

        // Expose the result as a public input to the circuit.
        field_chip.expose_public(layouter.namespace(|| "expose d"), d)
    }
}
// ANCHOR_END: circuit

#[allow(clippy::many_single_char_names)]
fn main() {
    use halo2::{dev::MockProver, pasta::Fp};

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 3;

    // Prepare the private and public inputs to the circuit!
    let a = Fp::rand();
    let b = Fp::rand();
    let c = Fp::rand();
    let d = (a + b) * c;

    // Instantiate the circuit with the private inputs.
    let circuit = MyCircuit {
        a: Some(a),
        b: Some(b),
        c: Some(c),
    };

    // Arrange the public input. We expose the multiplication result in row 6
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs = vec![Fp::zero(); 1 << k];
    public_inputs[7] = d;

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[7] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert_eq!(
        prover.verify(),
        Err(vec![VerifyFailure::Constraint {
            gate_index: 0,
            gate_name: "public input",
            constraint_index: 0,
            constraint_name: "",
            row: 7,
        }])
    );
    // ANCHOR_END: test-circuit
}