// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use core::array;

use commitment::GroupsPublicParametersAccessors as _;
use crypto_bigint::{rand_core::CryptoRngCore, CheckedMul, Random, Uint, U64};
use group::{
    helpers::FlatMapResults, ComputationalSecuritySizedNumber, GroupElement, Samplable,
    StatisticalSecuritySizedNumber,
};
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
/// Implements Appendix B. Maurer Protocols in the paper.
pub type Proof<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The number of witnesses with range claims
    const NUM_RANGE_CLAIMS: usize,
    // The range proof commitment scheme's message space scalar size in limbs
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The corresponding range proof
    RangeProof,
    // The unbounded witness group element
    UnboundedWitnessSpaceGroupElement,
    // The enhanceable language we are proving
    Language,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
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
    pub struct Proof<SchnorrProof, RangeProof> {
        pub(crate) schnorr_proof: SchnorrProof,
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

        // TODO: commitment are being computed twice. Change bulletproofs.
        let (range_proof, _) = RangeProof::prove(
            &enhanced_language_public_parameters.range_proof_public_parameters,
            commitment_messages,
            commitment_randomnesses,
            transcript,
            rng,
        )?;

        let batch_size = witnesses.len();

        let (randomizers, statement_masks) = Self::sample_randomizers_and_statement_masks(
            batch_size,
            enhanced_language_public_parameters,
            rng,
        )?;

        let (schnorr_proof, statements) = maurer::Proof::<
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
                schnorr_proof,
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
        // TODO: here we should validate all the sizes are good etc. for example WITNESS_MASK_LIMBS
        // and RANGE_CLAIM_LIMBS and the message space thingy

        let transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let commitments: Vec<_> = statements
            .clone()
            .into_iter()
            .map(|statement| statement.range_proof_commitment().clone())
            .collect();

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

        // TODO: this looks like the same bound in the public parameters right? so I should move
        // this to a function.
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

        // TODO: put this in a function, so we can call this from the aggregation
        // TODO:  delta_hat = delta * MAX_NUM_PARTIES
        // Z < delta_hat * NUM_CONSTRAINED_WITNESS * (2^(kappa+s+1)
        // $$ Z < \Delta \cdot n_{max} \cdot d \cdot (\ell + \ell_\omega) \cdot 2^{\kappa+s+1} $$
        if !self.schnorr_proof.responses.into_iter().all(|response| {
            let (commitment_message, ..): (_, _) = response.into();
            let (commitment_message, _) = commitment_message.into();

            <[_; NUM_RANGE_CLAIMS]>::from(commitment_message)
                .into_iter()
                .all(|range_claim| range_claim.into() < bound)
        }) {
            return Err(Error::OutOfRange);
        }

        Ok(self
            .schnorr_proof
            .verify(
                protocol_context,
                &enhanced_language_public_parameters,
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
        // TODO: choice of parameters, batching conversation in airport.
        // if WITNESS_MASK_LIMBS
        //     != RANGE_CLAIM_LIMBS
        //         + super::ChallengeSizedNumber::LIMBS
        //         + StatisticalSecuritySizedNumber::LIMBS
        //     || WITNESS_MASK_LIMBS > COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS
        //     || Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
        //         &Uint::<WITNESS_MASK_LIMBS>::MAX,
        //     ) >= language::enhanced::RangeProofCommitmentSchemeMessageSpaceGroupElement::<
        //       COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS,
        //         Language,
        //     >::lower_bound_from_public_parameters(
        //         &range_proof_public_parameters
        //             .as_ref()
        //             .as_ref()
        //             .message_space_public_parameters,
        //     )
        // {
        //     // TODO: the lower bound check fails
        //     // TODO: dedicated error?
        //     return Err(Error::InvalidParameters);
        // }

        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.append_message(
            b"range proof used for the enhanced Maurer proof",
            RangeProof::NAME.as_bytes(),
        );

        // TODO: serialize the public parameters?

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        Ok(transcript)
    }

    pub(crate) fn sample_randomizers_and_statement_masks(
        batch_size: usize,
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
        // TODO
        // let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
        // + ComputationalSecuritySizedNumber::BITS
        // + StatisticalSecuritySizedNumber::BITS;

        // 6. randomizer should be bigger than the witness max size by 128-bit + challenge size.
        //    witness max size should be defined in the public paramters, and then randomizer size
        //    is bigger than that using above formula and is also dynamic. so the sampling should be
        //    bounded. And then it doesn't need to be the phi(n) bullshit, we just need to have the
        //    witness group be of size range claim upper bound + 128 + challenge size.

        // TODO: check that this is < SCALAR_LIMBS?
        // TODO: formula + challenge : in lightning its 1, in bp 128
        let sampling_bit_size: usize = RangeProof::RANGE_CLAIM_BITS
            + StatisticalSecuritySizedNumber::BITS
            + EnhancedLanguage::<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >::challenge_bits(batch_size)?;

        // TODO: verify
        let mask = Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::MAX
            >> (Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS - sampling_bit_size);

        let commitment_messages: [CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >; REPETITIONS] = array::from_fn(|_| {
            array::from_fn(|_| {
                let value = (Uint::<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>::random(rng)
                    & mask)
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
