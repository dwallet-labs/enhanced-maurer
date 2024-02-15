// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod aggregation;
pub mod language;
pub mod proof;

use group::PartyID;
pub use language::{EnhanceableLanguage, EnhancedLanguage};
pub use proof::Proof;

/// Maurer error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("proof error")]
    Maurer(#[from] maurer::Error),
    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),
    #[error("randomizer(s) out of range: proof verification failed")]
    OutOfRange, // TODO: should name this modulation occurred?
    #[error("parties {:?} sent mismatching range proof commitments in the Maurer aggregation and range proof aggregation protocols", .0)]
    MismatchingRangeProofMaurerCommitments(Vec<PartyID>),
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// Maurer result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<::proof::aggregation::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<::proof::aggregation::Error, Self::Error> {
        match self {
            Error::Proof(::proof::Error::Aggregation(e)) => Ok(e),
            Error::Maurer(maurer::Error::Aggregation(e)) => Ok(e),
            e => Err(e),
        }
    }
}
