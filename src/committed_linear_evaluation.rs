// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#![allow(clippy::type_complexity)]

use std::{array, marker::PhantomData};

use commitment::{HomomorphicCommitmentScheme, MultiPedersen};
use crypto_bigint::{Encoding, NonZero, Uint};
use group::{
    direct_product, helpers::FlatMapResults, self_product, GroupElement, KnownOrderGroupElement,
    Reduce,
};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{language::GroupsPublicParameters, Error, SOUND_PROOFS_REPETITIONS};
use serde::{Deserialize, Serialize};

use crate::{language::DecomposableWitness, EnhanceableLanguage};

/// Committed Linear Evaluation Maurer Language
///
/// This language allows to prove a linear combination have been homomorphically evaluated on a
/// vector of ciphertexts. If one wishes to prove an affine evaluation instead of a linear one,
/// as is required in the paper, the first ciphertexts should be set to an encryption of one with
/// randomness zero ($\Enc(1; 0)$). This would allow the first coefficient to be evaluated as the
/// free variable of an affine transformation.
///
/// SECURITY NOTICE:
/// This language implicitly assumes that the plaintext space of the encryption scheme and the
/// scalar group coincide (same exponent). Using generic encryption schemes is permitted if and only
/// if we use this language in its enhanced form, i.e. `EnhancedLanguage`.
///
/// Because correctness and zero-knowledge is guaranteed for any group and additively homomorphic
/// encryption scheme in this language, we choose to provide a fully generic
/// implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Committed Linear Evaluation Maurer Language
pub type WitnessSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::FourWayGroupElement<
    self_product::GroupElement<
        DIMENSION,
        homomorphic_encryption::PlaintextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
    >,
    self_product::GroupElement<DIMENSION, group::Scalar<SCALAR_LIMBS, GroupElement>>,
    homomorphic_encryption::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
>;

/// The Statement Space Group Element Committed Linear Evaluation Maurer Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::GroupElement<
    homomorphic_encryption::CiphertextSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    self_product::GroupElement<DIMENSION, GroupElement>,
>;

/// The Public Parameters of the Committed Linear Evaluation Maurer Language.
///
/// In order to prove an affine transformation, set `ciphertexts[0]` to an encryption of one with
/// randomness zero ($\Enc(1; 0)$).
///
/// The corresponding `lower_bounds` in `ciphertexts_and_lower_bounds` should be verified
/// independently, e.g. by verifying (and following) a sequence of enhanced proofs over the
/// homomorphic computations that yields them.
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = private::PublicParameters<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    DIMENSION,
    group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
    group::PublicParameters<GroupElement>,
    group::Value<GroupElement>,
    homomorphic_encryption::PlaintextSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::RandomnessSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::CiphertextSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
>;

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > maurer::Language<SOUND_PROOFS_REPETITIONS>
    for Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
{
    type WitnessSpaceGroupElement = WitnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    const NAME: &'static str = "Committed Linear Evaluation";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> maurer::Result<Self::StatementSpaceGroupElement> {
        if SCALAR_LIMBS >= PLAINTEXT_SPACE_SCALAR_LIMBS {
            return Err(Error::InvalidPublicParameters);
        }

        let group_order = GroupElement::Scalar::order_from_public_parameters(
            language_public_parameters.scalar_group_public_parameters(),
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)
                .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let commitment_scheme =
            MultiPedersen::new(&language_public_parameters.commitment_scheme_public_parameters)
                .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let ciphertexts_and_upper_bounds = language_public_parameters
            .ciphertexts_and_upper_bounds
            .map(|(value, upper_bound)| {
                homomorphic_encryption::CiphertextSpaceGroupElement::<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    EncryptionKey,
                >::new(
                    value,
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
                .map(|ciphertext| (ciphertext, upper_bound))
                .map_err(|_| maurer::Error::InvalidPublicParameters)
            })
            .flat_map_results()?;

        let evaluated_ciphertext = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                witness.coefficients().into(),
                ciphertexts_and_upper_bounds,
                &((&group_order).into()),
                witness.mask(),
                witness.encryption_randomness(),
                &language_public_parameters.encryption_scheme_public_parameters,
            )
            .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let coefficients: [_; DIMENSION] = (*witness.coefficients()).into();

        let group_order = Option::<_>::from(NonZero::new(group_order))
            .ok_or(maurer::Error::InternalError)
            .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let coefficients = coefficients
            .map(|coefficient| {
                let coefficient = coefficient.value().into().reduce(&group_order).into();

                GroupElement::Scalar::new(
                    coefficient,
                    language_public_parameters.scalar_group_public_parameters(),
                )
                .map_err(|_| maurer::Error::InvalidPublicParameters)
            })
            .flat_map_results()?;

        let commitment =
            commitment_scheme.commit(&coefficients.into(), witness.commitment_randomness());

        Ok((evaluated_ciphertext, commitment).into())
    }
}

impl<
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >,
    >
    for Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        tiresias::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        unbounded_witness: direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        if NUM_RANGE_CLAIMS != RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        let mut decomposed_witness = decomposed_witness.into_iter();

        let coefficients: [[_; RANGE_CLAIMS_PER_SCALAR]; DIMENSION] = array::from_fn(|_| {
            array::from_fn(|_| {
                decomposed_witness
                    .next()
                    .ok_or(maurer::Error::InvalidPublicParameters)
            })
            .flat_map_results()
        })
        .flat_map_results()?;

        let coefficients = coefficients
            .map(|coefficient| {
                <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
                    RANGE_CLAIMS_PER_SCALAR,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
                >>::compose(
                    &coefficient,
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                    range_claim_bits,
                )
            })
            .flat_map_results()?
            .into();

        let mask: [_; RANGE_CLAIMS_PER_MASK] = array::from_fn(|_| {
            decomposed_witness
                .next()
                .ok_or(maurer::Error::InvalidParameters)
        })
        .flat_map_results()?;

        let mask = <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_MASK,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            &mask,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        let (commitment_randomness, encryption_randomness) = unbounded_witness.into();

        Ok((
            coefficients,
            commitment_randomness,
            mask,
            encryption_randomness,
        )
            .into())
    }

    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >,
    )> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        if NUM_RANGE_CLAIMS != (RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK) {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        let (coefficients, commitment_randomness, mask, encryption_randomness) = witness.into();

        let coefficients: [_; DIMENSION] = coefficients.into();

        let range_proof_commitment_message = coefficients
            .map(|coefficient| coefficient.decompose(range_claim_bits))
            .flat_map_results()?
            .into_iter()
            .flat_map(<[_; RANGE_CLAIMS_PER_SCALAR]>::from);

        let decomposed_mask: [_; RANGE_CLAIMS_PER_MASK] = mask.decompose(range_claim_bits)?;

        let range_proof_commitment_message: Vec<_> = range_proof_commitment_message
            .chain(decomposed_mask)
            .collect();

        let range_proof_commitment_message: [_; NUM_RANGE_CLAIMS] =
            range_proof_commitment_message.try_into().ok().unwrap();

        Ok((
            range_proof_commitment_message,
            (commitment_randomness, encryption_randomness).into(),
        ))
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::FourWayPublicParameters<
                self_product::PublicParameters<DIMENSION, PlaintextSpacePublicParameters>,
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
    >
    for private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::FourWayPublicParameters<
            self_product::PublicParameters<DIMENSION, PlaintextSpacePublicParameters>,
            self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CiphertextSpacePublicParameters,
            self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
        >,
    > {
        &self.groups_public_parameters
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
{
    pub fn new<const SCALAR_LIMBS: usize, GroupElement, EncryptionKey>(
        scalar_group_public_parameters: ScalarPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        commitment_scheme_public_parameters: commitment::PublicParameters<
            SCALAR_LIMBS,
            MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        ciphertexts_and_upper_bounds: [(
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
    ) -> Self
    where
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + KnownOrderGroupElement<SCALAR_LIMBS>,
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::PlaintextSpaceGroupElement:
            group::GroupElement<PublicParameters = PlaintextSpacePublicParameters>,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<
            Value = CiphertextSpaceValue,
            PublicParameters = CiphertextSpacePublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    self_product::PublicParameters::<DIMENSION, _>::new(
                        encryption_scheme_public_parameters
                            .plaintext_space_public_parameters()
                            .clone(),
                    ),
                    self_product::PublicParameters::<DIMENSION, _>::new(
                        scalar_group_public_parameters,
                    ),
                    encryption_scheme_public_parameters
                        .plaintext_space_public_parameters()
                        .clone(),
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                    self_product::PublicParameters::<DIMENSION, _>::new(group_public_parameters),
                )
                    .into(),
            },
            encryption_scheme_public_parameters,
            commitment_scheme_public_parameters,
            ciphertexts_and_upper_bounds,
        }
    }

    pub fn plaintext_space_public_parameters(&self) -> &PlaintextSpacePublicParameters {
        let (_, _, plaintext_space_public_parameters, _): (&_, &_, &_, &_) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        plaintext_space_public_parameters
    }

    pub fn randomness_space_public_parameters(&self) -> &RandomnessSpacePublicParameters {
        let (_, randomness_space_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        randomness_space_public_parameters
    }

    pub fn scalar_group_public_parameters(&self) -> &ScalarPublicParameters {
        let (_, scalar_group_public_parameters, ..): (&_, &_, &_, &_) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        &scalar_group_public_parameters.public_parameters
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        &group_public_parameters.public_parameters
    }
}

pub trait WitnessAccessors<
    const DIMENSION: usize,
    Scalar: group::GroupElement,
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn coefficients(&self) -> &self_product::GroupElement<DIMENSION, PlaintextSpaceGroupElement>;

    fn mask(&self) -> &PlaintextSpaceGroupElement;
    fn commitment_randomness(&self) -> &self_product::GroupElement<DIMENSION, Scalar>;
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        const DIMENSION: usize,
        Scalar: group::GroupElement,
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<DIMENSION, Scalar, PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::FourWayGroupElement<
        self_product::GroupElement<DIMENSION, PlaintextSpaceGroupElement>,
        self_product::GroupElement<DIMENSION, Scalar>,
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
    >
{
    fn coefficients(&self) -> &self_product::GroupElement<DIMENSION, PlaintextSpaceGroupElement> {
        let (coefficients, ..): (&_, &_, &_, &_) = self.into();

        coefficients
    }

    fn mask(&self) -> &PlaintextSpaceGroupElement {
        let (_, _, mask, _): (&_, &_, &_, &_) = self.into();

        mask
    }
    fn commitment_randomness(&self) -> &self_product::GroupElement<DIMENSION, Scalar> {
        let (_, commitment_randomness, ..): (&_, &_, &_, &_) = self.into();

        commitment_randomness
    }
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (.., encryption_randomness): (&_, &_, &_, &_) = self.into();

        encryption_randomness
    }
}

pub trait StatementAccessors<
    const DIMENSION: usize,
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn evaluated_ciphertext(&self) -> &CiphertextSpaceGroupElement;

    fn commitments(&self) -> &self_product::GroupElement<DIMENSION, GroupElement>;
}

impl<
        const DIMENSION: usize,
        CiphertextSpaceGroupElement: group::GroupElement,
        GroupElement: group::GroupElement,
    > StatementAccessors<DIMENSION, CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<
        CiphertextSpaceGroupElement,
        self_product::GroupElement<DIMENSION, GroupElement>,
    >
{
    fn evaluated_ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn commitments(&self) -> &self_product::GroupElement<DIMENSION, GroupElement> {
        let (_, commitments): (&_, &_) = self.into();

        commitments
    }
}

pub(super) mod private {
    use commitment::multipedersen;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Clone)]
    pub struct PublicParameters<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    {
        pub groups_public_parameters: GroupsPublicParameters<
            direct_product::FourWayPublicParameters<
                self_product::PublicParameters<DIMENSION, PlaintextSpacePublicParameters>,
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        pub commitment_scheme_public_parameters: multipedersen::PublicParameters<
            DIMENSION,
            GroupElementValue,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,

        #[serde(with = "group::helpers::const_generic_array_serialization")]
        pub ciphertexts_and_upper_bounds:
            [(CiphertextSpaceValue, Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>); DIMENSION],
    }
}

pub type Proof<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    ProtocolContext,
> = crate::Proof<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

#[cfg(test)]
pub(crate) mod tests {
    use core::iter;

    use commitment::pedersen;
    use crypto_bigint::{Random, U256, U64};
    use group::{secp256k1, Samplable, StatisticalSecuritySizedNumber};
    use maurer::language;
    use proof::range::{bulletproofs, bulletproofs::RANGE_CLAIM_BITS};
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::test_exports::N;

    use super::*;
    use crate::{
        aggregation::tests::setup_aggregation,
        language::tests::{generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR},
    };

    pub(crate) const MASK_LIMBS: usize =
        secp256k1::SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

    pub(crate) const DIMENSION: usize = 2;

    pub(crate) const RANGE_CLAIMS_PER_MASK: usize =
        Uint::<MASK_LIMBS>::BITS / bulletproofs::RANGE_CLAIM_BITS;

    pub(crate) const NUM_RANGE_CLAIMS: usize =
        DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK;

    pub type Lang = Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        { RANGE_CLAIMS_PER_SCALAR },
        { RANGE_CLAIMS_PER_MASK },
        { DIMENSION },
        secp256k1::GroupElement,
        tiresias::EncryptionKey,
    >;
    pub(crate) fn public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            tiresias::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let upper_bound = Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(
            u64::try_from(RANGE_CLAIMS_PER_SCALAR * RANGE_CLAIM_BITS).unwrap(),
        );

        let ciphertexts_and_upper_bounds = array::from_fn(|_| (&U256::random(&mut OsRng)).into())
            .map(|plaintext| {
                tiresias::PlaintextSpaceGroupElement::new(
                    plaintext,
                    paillier_public_parameters.plaintext_space_public_parameters(),
                )
                .unwrap()
            })
            .map(|plaintext| {
                let ciphertext = paillier_encryption_key
                    .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
                    .unwrap()
                    .1
                    .value();

                (ciphertext, upper_bound)
            });

        let pedersen_public_parameters = pedersen::PublicParameters::derive::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
        )
        .unwrap()
        .into();

        PublicParameters::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { DIMENSION },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
        >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, tiresias::EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters,
            pedersen_public_parameters,
            ciphertexts_and_upper_bounds,
        )
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let coefficients = array::from_fn(|_| generate_scalar_plaintext()).into();

            let first_commitment_randomness = secp256k1::Scalar::sample(
                language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let second_commitment_randomness = secp256k1::Scalar::sample(
                language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let mask = Uint::<MASK_LIMBS>::random(&mut OsRng);
            let mask = tiresias::PlaintextSpaceGroupElement::new(
                (&mask).into(),
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            )
            .unwrap();

            let encryption_randomness = tiresias::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (
                coefficients,
                [first_commitment_randomness, second_commitment_randomness].into(),
                mask,
                encryption_randomness,
            )
                .into()
        })
        .take(batch_size)
        .collect()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::proof::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_out_of_range_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_valid_range_proof_over_wrong_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_valid_range_proof_over_wrong_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::aggregation::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 3)]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: MismatchingRangeProofMaurerCommitments([2])"
    )]
    fn party_mismatching_maurer_range_proof_statements_aborts_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::aggregation::tests::party_mismatching_maurer_range_proof_statements_aborts_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn wrong_decommitment_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::wrong_decommitment_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn failed_proof_share_verification_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters.clone(),
            witnesses,
        );

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let wrong_commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::failed_proof_share_verification_aborts_session_identifiably(
            commitment_round_parties, wrong_commitment_round_parties
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn unresponsive_parties_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::unresponsive_parties_aborts_session_identifiably(
            commitment_round_parties,
        );
    }
}
