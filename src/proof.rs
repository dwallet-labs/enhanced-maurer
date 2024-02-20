// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#![allow(clippy::type_complexity)]

use core::array;

use commitment::GroupsPublicParametersAccessors as _;
use crypto_bigint::{rand_core::CryptoRngCore, NonZero, RandomMod, Uint};
use group::{helpers::FlatMapResults, GroupElement, Samplable, StatisticalSecuritySizedNumber};
use maurer::Language;
use merlin::Transcript;
use proof::{
    range::{
        CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement,
        PublicParametersAccessors,
    },
    TranscriptProtocol,
};
use serde::{Deserialize, Serialize};

use crate::{
    language::{
        EnhancedLanguageStatementAccessors, EnhancedLanguageWitnessAccessors,
        EnhancedPublicParameters, StatementSpaceGroupElement, WitnessSpaceGroupElement,
    },
    EnhanceableLanguage, EnhancedLanguage, Error, Result,
};

/// An Enhanced Batched Maurer Zero-Knowledge Proof.
/// Implements Section 4. Enhanced Batch Schnorr Protocols in the paper.
pub type Proof<
    // Number of times this proof should be repeated to achieve sufficient security.
    const REPETITIONS: usize,
    // The number of witnesses with range claims.
    const NUM_RANGE_CLAIMS: usize,
    // The range proof commitment scheme's message space scalar size in limbs.
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The corresponding range proof.
    RangeProof,
    // The unbounded witness group element.
    UnboundedWitnessSpaceGroupElement,
    // The enhanceable language we are proving.
    Language,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript.
    ProtocolContext,
> = private::Proof<
    maurer::Proof<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,
    RangeProof,
>;

mod private {
    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Proof<MaurerProof, RangeProof> {
        pub(crate) maurer_proof: MaurerProof,
        pub(crate) range_proof: RangeProof,
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >
    Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    /// Prove an enhanced batched Maurer zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        witnesses: Vec<
            WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        Self,
        Vec<
            StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    )> {
        let transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let (commitment_messages, commitment_randomnesses): (Vec<_>, Vec<_>) = witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                (
                    witness.range_proof_commitment_message().clone(),
                    witness.range_proof_commitment_randomness().clone(),
                )
            })
            .unzip();

        let (range_proof, _) = RangeProof::prove(
            &enhanced_language_public_parameters.range_proof_public_parameters,
            commitment_messages,
            commitment_randomnesses,
            transcript,
            rng,
        )?;

        let (randomizers, statement_masks) =
            Self::sample_randomizers_and_statement_masks(enhanced_language_public_parameters, rng)?;

        let (maurer_proof, statements) = maurer::Proof::<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
            ProtocolContext,
        >::prove_with_randomizers(
            protocol_context,
            enhanced_language_public_parameters,
            witnesses,
            randomizers,
            statement_masks,
        )?;

        Ok((
            Proof {
                maurer_proof,
                range_proof,
            },
            statements,
        ))
    }

    /// Verify an enhanced batched Maurer zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        statements: Vec<
            StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let commitments: Vec<_> = statements
            .clone()
            .into_iter()
            .map(|statement| statement.range_proof_commitment().clone())
            .collect();

        // Range check:
        // Z < delta_hat * NUM_CONSTRAINED_WITNESS * (2^(kappa+s+1)
        // Range check for enhanced Maurer. Protocol~7 suggests the formula below for non-batched
        // version: $$ Z < \Delta \cdot n_{max} \cdot d \cdot (\ell + \ell_\omega) \cdot
        // 2^{\kappa+s+1} $$ The range check for the batched protocol with batch size = m,
        // appears in Appendix~K. Seemingly, to get a 2^-s' statistical zk, one must use
        // $2^s = m2^s'$ throughout the protocol (sampling a greater mask, checking a
        // broader range, and requiring a greater lower bound for the range-proof commitment
        // space). Nevertheless, this is also the case when running m non-batched zk protocols in
        // parallel. So in general, setting s should take into consideration the number of signing
        // protocols expected in the whole system, regardless of whether proofs are batched
        // or not.

        let bound = crate::language::commitment_message_space_lower_bound::<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        >(true, RangeProof::RANGE_CLAIM_BITS)?;

        if !self.maurer_proof.responses.into_iter().all(|response| {
            let (commitment_message, ..): (_, _) = response.into();
            let (commitment_message, _) = commitment_message.into();

            <[_; NUM_RANGE_CLAIMS]>::from(commitment_message)
                .into_iter()
                .all(|range_claim| range_claim.into() < bound)
        }) {
            return Err(Error::OutOfRange);
        }

        Ok(self
            .maurer_proof
            .verify(
                protocol_context,
                enhanced_language_public_parameters,
                statements,
            )
            .and(Ok(self.range_proof.verify(
                &enhanced_language_public_parameters.range_proof_public_parameters,
                commitments,
                transcript,
                rng,
            )?))?)
    }

    pub(crate) fn setup_range_proof(
        protocol_context: &ProtocolContext,
        range_proof_public_parameters: &proof::range::PublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.append_message(
            b"range proof used for the enhanced Maurer proof",
            RangeProof::NAME.as_bytes(),
        );

        transcript.serialize_to_transcript_as_json(
            b"range proof public parameters",
            range_proof_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        Ok(transcript)
    }

    pub(crate) fn sample_randomizers_and_statement_masks(
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        [WitnessSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >; REPETITIONS],
        [StatementSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >; REPETITIONS],
    )> {
        // This is an upper bound on the number of bits, as `ilog2` rounds down.
        let num_range_claims_bits = usize::try_from(NUM_RANGE_CLAIMS.ilog2())
            .ok()
            .and_then(|log_lower_bound| log_lower_bound.checked_add(1))
            .ok_or(Error::InvalidPublicParameters)?;

        let challenge_bits = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >::challenge_bits()?;

        // $ [0,\Delta \cdot d(\ell+1+\omegalen) \cdot 2^{\kappa+s}) $
        let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
            .checked_add(num_range_claims_bits)
            .and_then(|bits| bits.checked_add(challenge_bits))
            .and_then(|bits| bits.checked_add(StatisticalSecuritySizedNumber::BITS))
            .ok_or(Error::InvalidPublicParameters)?;

        if Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS <= sampling_bit_size {
            return Err(Error::InvalidPublicParameters);
        }

        let sampling_range_upper_bound = NonZero::new(
            Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE << sampling_bit_size,
        )
        .unwrap();

        let commitment_messages: [CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >; REPETITIONS] = array::from_fn(|_| {
            array::from_fn(|_| {
                let value = Uint::<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>::random_mod(
                    rng,
                    &sampling_range_upper_bound,
                )
                .into();

                RangeProof::RangeClaimGroupElement::new(
                    value,
                    &enhanced_language_public_parameters
                        .range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .message_space_public_parameters()
                        .public_parameters,
                )
            })
            .flat_map_results()
            .map(|decomposed_witness| decomposed_witness.into())
        })
        .flat_map_results()?;

        let unbounded_witnesses: [_; REPETITIONS] = array::from_fn(|_| {
            UnboundedWitnessSpaceGroupElement::sample(
                enhanced_language_public_parameters.unbounded_witness_public_parameters(),
                rng,
            )
        })
        .flat_map_results()?;

        let commitment_randomnesses: [_; REPETITIONS] = array::from_fn(|_| {
            CommitmentSchemeRandomnessSpaceGroupElement::<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >::sample(
                enhanced_language_public_parameters
                    .range_proof_public_parameters
                    .commitment_scheme_public_parameters()
                    .randomness_space_public_parameters(),
                rng,
            )
        })
        .flat_map_results()?;

        let randomizers: [_; REPETITIONS] = commitment_messages
            .into_iter()
            .zip(commitment_randomnesses.into_iter())
            .zip(unbounded_witnesses.into_iter())
            .map(
                |((commitment_message, commitment_randomness), unbounded_witness)| {
                    (commitment_message, commitment_randomness, unbounded_witness).into()
                },
            )
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let statement_masks = randomizers
            .clone()
            .map(|randomizer| {
                EnhancedLanguage::<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Language,
                >::homomorphose(&randomizer, enhanced_language_public_parameters)
            })
            .flat_map_results()?;

        Ok((randomizers, statement_masks))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::marker::PhantomData;

    use maurer::language::GroupsPublicParametersAccessors;
    use proof::range::{bulletproofs, bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS};
    use rand_core::OsRng;

    use super::*;
    use crate::language::tests::enhanced_language_public_parameters;

    // TODO: invalid_proof_fails_verification

    pub(crate) fn valid_proof_verifies<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::generate_witnesses(
            witnesses, &enhanced_language_public_parameters, &mut OsRng
        )
        .unwrap();

        let (proof, statements) = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses,
            &mut OsRng,
        )
        .unwrap();

        assert!(
            proof
                .verify(
                    &PhantomData,
                    &enhanced_language_public_parameters,
                    statements,
                    &mut OsRng,
                )
                .is_ok(),
            "valid enhanced proofs should verify",
        );
    }

    pub(crate) fn proof_with_out_of_range_witness_fails<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses = vec![WitnessSpaceGroupElement::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::sample(
            enhanced_language_public_parameters.witness_space_public_parameters(),
            &mut OsRng,
        )
        .unwrap()];

        let res = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses,
            &mut OsRng,
        );

        assert!(
            matches!(
                res.err().unwrap(),
                Error::Proof(proof::Error::InvalidParameters)
            ),
            "shouldn't be able to verify proofs on out of range witnesses"
        );
    }
}
