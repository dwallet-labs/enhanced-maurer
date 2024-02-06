// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use core::{array, marker::PhantomData};

use commitment::{GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme};
use crypto_bigint::{rand_core::CryptoRngCore, CheckedMul, Uint, U64};
use group::{
    direct_product, helpers::FlatMapResults, self_product, BoundedGroupElement,
    ComputationalSecuritySizedNumber, GroupElement, KnownOrderScalar, Samplable,
    StatisticalSecuritySizedNumber,
};
use maurer::language::{GroupsPublicParameters, GroupsPublicParametersAccessors};
use proof::range::{
    CommitmentSchemeCommitmentSpaceGroupElement, CommitmentSchemeCommitmentSpacePublicParameters,
    CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemePublicParameters,
    CommitmentSchemeRandomnessSpaceGroupElement, CommitmentSchemeRandomnessSpacePublicParameters,
    PublicParametersAccessors,
};
use serde::Serialize;
use tiresias::secret_sharing::shamir::Polynomial;

use crate::{Error, Result};

/// An Enhanced Maurer Zero-Knowledge Proof Language.
/// Can be generically used to generate a batched Maurer zero-knowledge `Proof` with range claims.
/// As defined in Appendix B. Maurer Protocols in the paper [TODO: cite].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnhancedLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> {
    _unbounded_witness_choice: PhantomData<UnboundedWitnessSpaceGroupElement>,
    _language_choice: PhantomData<Language>,
    _range_proof_choice: PhantomData<RangeProof>,
}

/// An Enhanceable Maurer Language.
/// By itself implements the `maurer::Language` trait, although it might not actually be a valid
/// language with no range claims. Defines transition methods to compose and decompose its witness
/// from and to what we call a _decomposed witness_, which is a list of range claims of the range
/// proof's commitment scheme message space.
pub trait EnhanceableLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: GroupElement + Samplable,
>: maurer::Language<REPETITIONS>
{
    /// Compose a language witness from the message of a corresponding commitment.
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        unbounded_witness: UnboundedWitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement>;

    /// Decompose a language witness to a message of a commitment on which a range proof can be
    /// formed.
    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        UnboundedWitnessSpaceGroupElement,
    )>;
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    > maurer::Language<REPETITIONS>
    for EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
{
    type WitnessSpaceGroupElement = direct_product::ThreeWayGroupElement<
        CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        UnboundedWitnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement = direct_product::GroupElement<
        CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        Language::StatementSpaceGroupElement,
    >;

    type PublicParameters = PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        group::PublicParameters<RangeProof::RangeClaimGroupElement>,
        CommitmentSchemeRandomnessSpacePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        CommitmentSchemeCommitmentSpacePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
        UnboundedWitnessSpaceGroupElement::PublicParameters,
        group::PublicParameters<Language::StatementSpaceGroupElement>,
        Language::PublicParameters,
    >;

    const NAME: &'static str = Language::NAME;

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &Self::PublicParameters,
    ) -> maurer::Result<Self::StatementSpaceGroupElement> {
        let decomposed_witness: [_; NUM_RANGE_CLAIMS] =
            witness.range_proof_commitment_message().clone().into();

        let decomposed_witness = decomposed_witness
            .map(Into::<Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::into);

        let language_witness = Language::compose_witness(
            decomposed_witness,
            witness.unbounded_witness().clone(),
            &enhanced_language_public_parameters.language_public_parameters,
            RangeProof::RANGE_CLAIM_BITS,
        )?;

        let language_statement = Language::homomorphose(
            &language_witness,
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters(),
        )
        .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let commitment_message_value =
            <[_; NUM_RANGE_CLAIMS]>::from(witness.range_proof_commitment_message().value()).into();

        let commitment_message = CommitmentSchemeMessageSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::new(
            commitment_message_value,
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .message_space_public_parameters(),
        )?;

        let range_proof_commitment = commitment_scheme.commit(
            &commitment_message,
            witness.range_proof_commitment_randomness(),
        );

        Ok((range_proof_commitment, language_statement).into())
    }
}

pub trait DecomposableWitness<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_LIMBS: usize,
>: KnownOrderScalar<WITNESS_LIMBS>
{
    fn decompose(
        self,
        range_claim_bits: usize,
    ) -> Result<[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR]> {
        let witness: Uint<WITNESS_LIMBS> = self.into();

        // TODO: any checks on RANGE_CLAIMS_PER_SCALAR?
        if range_claim_bits == 0
            || Uint::<WITNESS_LIMBS>::BITS <= range_claim_bits
            || Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS <= range_claim_bits
        {
            return Err(Error::InvalidPublicParameters);
        }

        let mask = (Uint::<WITNESS_LIMBS>::ONE << range_claim_bits)
            .wrapping_sub(&Uint::<WITNESS_LIMBS>::ONE);

        Ok(array::from_fn(|i| {
            Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
                &((witness >> (i * range_claim_bits)) & mask),
            )
        }))
    }

    fn compose(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
             RANGE_CLAIMS_PER_SCALAR],
        public_parameters: &Self::PublicParameters,
        range_claim_bits: usize,
    ) -> Result<Self> {
        let delta: Uint<WITNESS_LIMBS> = Uint::<WITNESS_LIMBS>::ONE << range_claim_bits;
        let delta = Self::new(delta.into(), public_parameters)?;

        // TODO: decompose checks too?

        let decomposed_witness = decomposed_witness
            .into_iter()
            .map(|witness| {
                Self::new(
                    // TODO: need to check this is ok?
                    Uint::<WITNESS_LIMBS>::from(&Uint::<
                        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    >::from(witness))
                    .into(),
                    public_parameters,
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let polynomial =
            Polynomial::try_from(decomposed_witness).map_err(|_| Error::InvalidParameters)?;

        Ok(polynomial.evaluate(&delta))
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const WITNESS_LIMBS: usize,
        Witness: KnownOrderScalar<WITNESS_LIMBS>,
    >
    DecomposableWitness<
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        WITNESS_LIMBS,
    > for Witness
{
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    >
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
{
    pub fn generate_witness(
        witness: Language::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &maurer::language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        maurer::language::WitnessSpaceGroupElement<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    > {
        let (decomposed_witness, unbounded_element) = Language::decompose_witness(
            witness,
            &enhanced_language_public_parameters.language_public_parameters,
            RangeProof::RANGE_CLAIM_BITS,
        )?;

        let range_proof_commitment_message = decomposed_witness
            .map(group::Value::<RangeProof::RangeClaimGroupElement>::from)
            .map(|value| {
                RangeProof::RangeClaimGroupElement::new(
                    value,
                    enhanced_language_public_parameters
                        .range_proof_public_parameters
                        .range_claim_public_parameters(),
                )
            })
            .flat_map_results()?
            .into();

        let commitment_randomness = CommitmentSchemeRandomnessSpaceGroupElement::<
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::sample(
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .randomness_space_public_parameters(),
            rng,
        )?;

        Ok((
            range_proof_commitment_message,
            commitment_randomness,
            unbounded_element,
        )
            .into())
    }

    pub fn generate_witnesses(
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        enhanced_language_public_parameters: &maurer::language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        Vec<
            maurer::language::WitnessSpaceGroupElement<
                REPETITIONS,
                EnhancedLanguage<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Language,
                >,
            >,
        >,
    > {
        witnesses
            .into_iter()
            .map(|witness| {
                Self::generate_witness(witness, enhanced_language_public_parameters, rng)
            })
            .collect::<Result<Vec<_>>>()
    }
}

#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeClaimPublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    RangeProofPublicParameters,
    UnboundedWitnessSpacePublicParameters,
    LanguageStatementSpacePublicParameters,
    LanguagePublicParameters,
> {
    groups_public_parameters: GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    >,
    pub range_proof_public_parameters: RangeProofPublicParameters,
    language_public_parameters: LanguagePublicParameters,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeClaimPublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        RangeProofPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters: Clone,
        LanguagePublicParameters,
    >
    PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
{
    pub fn new<RangeProof, UnboundedWitnessSpaceGroupElement, Language>(
        unbounded_witness_public_parameters: UnboundedWitnessSpacePublicParameters,
        range_proof_public_parameters: RangeProofPublicParameters,
        language_public_parameters: LanguagePublicParameters,
    ) -> Result<Self>
    where
        RangeProof: proof::RangeProof<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters<NUM_RANGE_CLAIMS> = RangeProofPublicParameters,
        >,
        CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        RangeProof::RangeClaimGroupElement:
            GroupElement<PublicParameters = RangeClaimPublicParameters>,
        CommitmentSchemePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: AsRef<
            commitment::GroupsPublicParameters<
                self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
        RangeProofPublicParameters: AsRef<
            CommitmentSchemePublicParameters<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >,
        >,
        UnboundedWitnessSpaceGroupElement:
            GroupElement<PublicParameters = UnboundedWitnessSpacePublicParameters>,
        Language: maurer::Language<REPETITIONS, PublicParameters = LanguagePublicParameters>,
        LanguagePublicParameters: AsRef<
            GroupsPublicParameters<
                group::PublicParameters<Language::WitnessSpaceGroupElement>,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    {
        // We require $$ |\calM_\pp| >\hat{\Delta} \cdot d \cdot (\ell + \ell_\omega) \cdot
        // 2^{\kappa+s+1} $$.
        //
        // In practice, we allow working over bounded groups of unknown order, in which case we use
        // a lower bound on the group order to perform this check.
        let order_lower_bound = CommitmentSchemeMessageSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::lower_bound(
            range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .message_space_public_parameters(),
        );

        let delta: Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS> =
            Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE
                << RangeProof::RANGE_CLAIM_BITS;
        // We multiply by two for the + 1
        let number_of_range_claims = U64::from(
            u64::try_from(2 * NUM_RANGE_CLAIMS).map_err(|_| Error::InvalidPublicParameters)?,
        );

        if COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS <= ComputationalSecuritySizedNumber::LIMBS
            || COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS <= StatisticalSecuritySizedNumber::LIMBS
        {
            return Err(Error::InvalidPublicParameters);
        }

        let bound = Option::from(
            delta
                .checked_mul(&number_of_range_claims)
                .and_then(|bound| {
                    bound.checked_mul(
                        &(Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE
                            << ComputationalSecuritySizedNumber::BITS),
                    )
                })
                .and_then(|bound| {
                    bound.checked_mul(
                        &(Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE
                            << StatisticalSecuritySizedNumber::BITS),
                    )
                }),
        )
        .ok_or(Error::InvalidPublicParameters)?;

        if order_lower_bound <= bound {
            return Err(Error::InvalidPublicParameters);
        }

        Ok(Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .message_space_public_parameters()
                        .clone(),
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .randomness_space_public_parameters()
                        .clone(),
                    unbounded_witness_public_parameters,
                )
                    .into(),
                statement_space_public_parameters: (
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .commitment_space_public_parameters()
                        .clone(),
                    language_public_parameters
                        .statement_space_public_parameters()
                        .clone(),
                )
                    .into(),
            },
            range_proof_public_parameters,
            language_public_parameters,
        })
    }

    pub fn unbounded_witness_public_parameters(&self) -> &UnboundedWitnessSpacePublicParameters {
        let (_, _, unbounded_witness_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        unbounded_witness_public_parameters
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
                RandomnessSpacePublicParameters,
                UnboundedWitnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CommitmentSpacePublicParameters,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    >
    for PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    > {
        &self.groups_public_parameters
    }
}

pub trait EnhancedLanguageWitnessAccessors<
    MessageSpaceGroupElement: GroupElement,
    RandomnessSpaceGroupElement: GroupElement,
    UnboundedWitnessSpaceGroupElement: GroupElement,
>
{
    fn range_proof_commitment_message(&self) -> &MessageSpaceGroupElement;

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement;
}

impl<
        MessageSpaceGroupElement: GroupElement,
        RandomnessSpaceGroupElement: GroupElement,
        UnboundedWitnessSpaceGroupElement: GroupElement,
    >
    EnhancedLanguageWitnessAccessors<
        MessageSpaceGroupElement,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
    for direct_product::ThreeWayGroupElement<
        MessageSpaceGroupElement,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
{
    fn range_proof_commitment_message(&self) -> &MessageSpaceGroupElement {
        let (range_proof_commitment_message, ..): (_, _, _) = self.into();

        range_proof_commitment_message
    }

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness, _) = self.into();

        randomness
    }

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement {
        let (_, _, unbounded_witness) = self.into();

        unbounded_witness
    }
}

pub trait EnhancedLanguageStatementAccessors<
    CommitmentSpaceGroupElement: GroupElement,
    LanguageStatementSpaceGroupElement: GroupElement,
>
{
    fn range_proof_commitment(&self) -> &CommitmentSpaceGroupElement;

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement;
}

impl<
        CommitmentSpaceGroupElement: GroupElement,
        LanguageStatementSpaceGroupElement: GroupElement,
    >
    EnhancedLanguageStatementAccessors<
        CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
    for direct_product::GroupElement<
        CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
{
    fn range_proof_commitment(&self) -> &CommitmentSpaceGroupElement {
        let (range_proof_commitment, _) = self.into();

        range_proof_commitment
    }

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement {
        let (_, language_statement) = self.into();

        language_statement
    }
}

pub type EnhancedPublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = maurer::language::PublicParameters<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

pub type WitnessSpaceGroupElement<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = maurer::language::WitnessSpaceGroupElement<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

pub type StatementSpaceGroupElement<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = maurer::language::StatementSpaceGroupElement<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;