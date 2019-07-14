//! Provides the `Generator` trait and an enumeration of all algorithm used.

/// Common trait of all OTP value generators of this trait.
/// 
/// You may use it to define custom OTP value generator if you wish so.
pub trait Generator {
    /// The error type associated with the OTP value generator.
    type Error;

    /// Computes an OTP value of an generator.
    fn get_value(&mut self) -> Result<String, Self::Error>;

    /// Retrieves the OTP auth URI of an generator.
    fn get_otp_auth_uri(&self) -> Result<String, Self::Error>;
}

/// The different cryptographic algorithms used by the generators
#[derive(Debug, PartialEq)]
pub enum GeneratorAlgorithm {
    /// The HMAC-SHA1 algorithm.
    HmacSha1,

    /// The HMAC-SHA-256 algorithm.
    HmacSha256,

    /// THE HMAC-SHA-512 algorithm.
    HmacSha512,
}
