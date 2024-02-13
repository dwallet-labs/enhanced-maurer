// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use commitment::Commitment;
use crypto_bigint::rand_core::CryptoRngCore;
use group::{PartyID, Samplable};
use proof::{range, AggregatableRangeProof};
use serde::Serialize;

use crate::{
    aggregation::{decommitment_round, Output},
    language::{EnhancedPublicParameters, WitnessSpaceGroupElement},
    EnhanceableLanguage, Error, Result,
};

pub struct Party<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: Samplable,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize,
> {
    pub party_id: PartyID,
    pub threshold: PartyID,
    pub number_of_parties: PartyID,
    pub language_public_parameters: EnhancedPublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
    pub protocol_context: ProtocolContext,
    pub witnesses: Vec<
        WitnessSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
    >,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        UnboundedWitnessSpaceGroupElement: Samplable,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize,
    >
    proof::aggregation::CommitmentRoundParty<
        Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
            RangeProof,
            Language,
            ProtocolContext,
        >,
    >
    for Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        RangeProof,
        Language,
        ProtocolContext,
    >
{
    type Error = Error;
    type Commitment = (
        Commitment,
        range::Commitment<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    );

    type DecommitmentRoundParty = decommitment_round::Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        RangeProof,
        Language,
        ProtocolContext,
    >;

    fn commit_statements_and_statement_mask(
        self,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        todo!()
    }
}
