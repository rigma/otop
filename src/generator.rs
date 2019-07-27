// Copyright 2019 Romain Failla
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

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

/// Transcribe an OTP counter from an unsigned 64 bits integer to an 8-bytes array.
pub fn encode_counter(counter: &u64) -> [u8; 8] {
    let mut message: [u8; 8] = [0; 8];
    for i in (0..8).rev() {
        message[i] = ((counter >> (8 * i)) & 0xff) as u8;
    }

    message
}

/// Computes the OTP offset of an HMAC vector.
pub fn otp_offset(hmac: &[u8]) -> u64 {
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;

    (u64::from(hmac[offset] & 0x7f) << 24) | (u64::from(hmac[offset + 1]) << 16) | (u64::from(hmac[offset + 2]) << 8) | u64::from(hmac[offset + 3])
}

/// Converts an OTP value into a string representation.
pub fn otp_value_to_string(value: &u64, digits: &u8) -> String {
    let output = if *digits == 8 {
        *value % 100_000_000_000
    } else {
        *value % 1_000_000_000
    };

    let mut output = output.to_string();
    while output.len() != *digits as usize {
        if output.len() < *digits as usize {
            output.insert(0, '0');
        } else {
            output.pop();
        }
    }

    output
}
