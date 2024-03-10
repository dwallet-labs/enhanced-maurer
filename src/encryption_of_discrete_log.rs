// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::marker::PhantomData;

use crypto_bigint::Uint;
use group::{direct_product, CyclicGroupElement, GroupElement, KnownOrderGroupElement};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{language::GroupsPublicParameters, SOUND_PROOFS_REPETITIONS};
use serde::Serialize;

use crate::{language::DecomposableWitness, EnhanceableLanguage};

/// Encryption of Discrete Log Maurer Language
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
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Encryption of Discrete Log Maurer Language.
pub type WitnessSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, EncryptionKey> =
    direct_product::GroupElement<
        homomorphic_encryption::PlaintextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
        homomorphic_encryption::RandomnessSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
    >;

/// The Statement Space Group Element of the Encryption of Discrete Log Maurer Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::GroupElement<
    homomorphic_encryption::CiphertextSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    GroupElement,
>;

/// The Public Parameters of the Encryption of Discrete Log Maurer Language.
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = private::PublicParameters<
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
    homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > maurer::Language<SOUND_PROOFS_REPETITIONS>
    for Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>
{
    type WitnessSpaceGroupElement =
        WitnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>;

    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >;

    type PublicParameters =
        PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>;

    const NAME: &'static str = "Encryption of Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> maurer::Result<Self::StatementSpaceGroupElement> {
        let base = GroupElement::new(
            language_public_parameters.generator,
            language_public_parameters.group_public_parameters(),
        )?;

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)
                .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let encrypted_discrete_log = encryption_key.encrypt_with_randomness(
            witness.discrete_log(),
            witness.randomness(),
            &language_public_parameters.encryption_scheme_public_parameters,
        );

        let base_by_discrete_log = base.scalar_mul(&witness.discrete_log().value().into());

        Ok((encrypted_discrete_log, base_by_discrete_log).into())
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        tiresias::RandomnessSpaceGroupElement,
    >
    for Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        GroupElement,
        tiresias::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR],
        randomness: tiresias::RandomnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            tiresias::RandomnessSpaceGroupElement,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        let discrete_log = <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            &decomposed_witness,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        Ok((discrete_log, randomness).into())
    }

    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR],
        tiresias::RandomnessSpaceGroupElement,
    )> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            tiresias::RandomnessSpaceGroupElement,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        Ok((
            witness.discrete_log().decompose(range_claim_bits)?,
            *witness.randomness(),
        ))
    }
}

pub(super) mod private {
    use maurer::language::GroupsPublicParameters;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Clone)]
    pub struct PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    > {
        pub groups_public_parameters: GroupsPublicParameters<
            direct_product::PublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
        pub scalar_group_public_parameters: ScalarPublicParameters,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        // The base of the discrete log
        pub generator: GroupElementValue,
    }
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for private::PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    private::PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    pub fn new<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement,
        EncryptionKey,
    >(
        scalar_group_public_parameters: ScalarPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        generator: GroupElementValue,
    ) -> Self
    where
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + CyclicGroupElement
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
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<PublicParameters = CiphertextSpacePublicParameters>,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
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
                    group_public_parameters,
                )
                    .into(),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            generator,
        }
    }

    pub fn plaintext_space_public_parameters(&self) -> &PlaintextSpacePublicParameters {
        let (plaintext_space_public_parameters, _) = (&self
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

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        group_public_parameters
    }
}

pub trait WitnessAccessors<
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement;

    fn randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::GroupElement<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement {
        let (plaintext, _): (&_, &_) = self.into();

        plaintext
    }

    fn randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness): (&_, &_) = self.into();

        randomness
    }
}

pub trait StatementAccessors<
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn encrypted_discrete_log(&self) -> &CiphertextSpaceGroupElement;

    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>
{
    fn encrypted_discrete_log(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let (_, base_by_discrete_log): (&_, &_) = self.into();

        base_by_discrete_log
    }
}

pub type Proof<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
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
    Language<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey>,
    ProtocolContext,
>;

#[cfg(test)]
pub(crate) mod tests {
    use core::iter;

    use crypto_bigint::U256;
    use group::{secp256k1, Samplable};
    use maurer::language;
    use rand_core::OsRng;
    use rstest::rstest;
    use tiresias::test_exports::N;

    use super::*;
    use crate::{
        aggregation::tests::setup_aggregation,
        language::tests::{generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR},
    };

    pub type Lang = Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
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

        let generator = secp256k1_group_public_parameters.generator;

        PublicParameters::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
        >::new::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters,
            generator,
        )
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let discrete_log = generate_scalar_plaintext();

            let randomness = tiresias::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (discrete_log, randomness).into()
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::proof::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_out_of_range_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_valid_range_proof_over_wrong_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::aggregation::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::aggregation::tests::party_mismatching_maurer_range_proof_statements_aborts_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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
