// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use crypto_bigint::rand_core::CryptoRngCore;
use group::{PartyID, Samplable};
use proof::{range, AggregatableRangeProof};
use serde::Serialize;

use crate::{
    aggregation::{proof_aggregation_round, Output},
    language::{EnhancedPublicParameters, WitnessSpaceGroupElement},
    EnhanceableLanguage, Error,
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
    proof::aggregation::ProofShareRoundParty<
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

    type Decommitment = (
        maurer::aggregation::Decommitment<REPETITIONS, Language>,
        range::Decommitment<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    );

    type ProofShare = (
        maurer::aggregation::ProofShare<REPETITIONS, Language>,
        range::ProofShare<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    );

    type ProofAggregationRoundParty = proof_aggregation_round::Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
        RangeProof,
        Language,
        ProtocolContext,
    >;

    fn generate_proof_share(
        self,
        _decommitments: HashMap<PartyID, Self::Decommitment>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ProofShare, Self::ProofAggregationRoundParty), Self::Error> {
        todo!()
    }
}
