use core::byte_array::ByteArray;
use starkware_utils::errors::{Describable, ErrorDisplay};

/// Error types for the Attestation contract.
/// These errors are used to handle various attestation-related failure cases.
#[derive(Copy, Drop, starknet::Store)]
pub enum Error {
    /// Error raised when attempting to attest for an epoch that has already been attested
    ATTEST_IS_DONE: (),
    /// Error raised when attempting to attest outside the allowed window
    ATTEST_OUT_OF_WINDOW: (),
    /// Error raised when the provided block hash doesn't match the expected hash
    ATTEST_WRONG_BLOCK_HASH: (),
    /// Error raised when attempting to set an attestation window smaller than the minimum allowed
    ATTEST_WINDOW_TOO_SMALL: (),
    /// Error raised when attempting to attest for epoch 0 (starting epoch)
    ATTEST_STARTING_EPOCH: (),
    /// Error raised when attempting to change the attestation window during active attestations
    CANNOT_CHANGE_WINDOW_DURING_ACTIVE_ATTESTATIONS: (),
}

/// Implementation of the Describable trait for Error enum.
/// This provides human-readable error messages for each error type.
impl DescribableError of Describable<Error> {
    /// Returns a human-readable error message for the given error.
    /// The messages are designed to be clear and actionable for users.
    fn describe(self: @Error) -> ByteArray {
        match self {
            Error::ATTEST_IS_DONE(_) => "Attestation is done for this epoch",
            Error::ATTEST_OUT_OF_WINDOW(_) => "Attestation is out of window",
            Error::ATTEST_WRONG_BLOCK_HASH(_) => "Attestation with wrong block hash",
            Error::ATTEST_WINDOW_TOO_SMALL(_) => "Attestation window is too small, must be larger then 10 blocks",
            Error::ATTEST_STARTING_EPOCH(_) => "Attestation for epoch 0 is not allowed",
            Error::CANNOT_CHANGE_WINDOW_DURING_ACTIVE_ATTESTATIONS(_) => "Cannot change window during active attestations",
        }
    }
}
