// Copyright 2019 Romain Failla
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides an HOTP value generator.
//!
//! This generator can be used to generate HOTP value to perform a 2FA authentication
//! or to generate an OTP auth URI which can be encoded into a QR code.
//!
//! ## Example
//! ```
//! use otop::hotp::HotpGenerator;
//! use otop::Generator;
//!
//! // It is important to define a mutable reference if you want to generate values
//! // because of the internal counter of the generator
//! let mut generator = HotpGenerator::new("Kitten", "Tacocat", b"tacocat");
//!
//! // Compute an HOTP value
//! let value = generator.get_value();
//! assert!(value.is_ok());
//!
//! // Retrieves the URI of this generator
//! let uri = generator.get_otp_auth_uri();
//! assert!(value.is_ok());
//! ```

use crate::crypto;
use crate::generator::*;
use std::default::Default;
use std::error::Error;
use std::fmt;
use url::Url;

/// The default cryptographic algorithm for HOTP value generation.
pub const DEFAULT_ALGORITHM: GeneratorAlgorithm = GeneratorAlgorithm::HmacSha1;

/// The default HOTP value's number of digits.
pub const DEFAULT_DIGITS: u8 = 6;

/// The default initial value of HOTP generator's counter.
pub const DEFAULT_INITIAL_COUNTER: u64 = 0;

/// Defines an error which has occured during runtime with the HOTP value generator.
#[derive(Debug)]
pub struct HotpError {
    kind: String,
}

impl fmt::Display for HotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error occured in HOTP value generator: {}", self.kind)
    }
}

impl Error for HotpError {
    fn description(&self) -> &str {
        "Error occured in HOTP value generator"
    }
}

/// An HOTP value generator which implements [IETF RFC 4226](https://tools.ietf.org/html/rfc4226) specification.
#[derive(Debug)]
pub struct HotpGenerator {
    /// The name of the account associated with this generator.
    pub account: String,

    /// The name of the provider associated with this generator.
    pub provider: String,
    secret: Vec<u8>,

    /// The optional HOTP token issuer's name.
    pub issuer: Option<String>,

    /// The algorithm used by the generator.
    pub algorithm: GeneratorAlgorithm,
    initial_counter: u64,
    counter: u64,
    digits: u8,
}

impl HotpGenerator {
    /// Instanciates a new instance of an HOTP generator.
    ///
    /// > Be awared that it instanciates a new generator! For now, there is no generator persistence.
    pub fn new(account: &str, provider: &str, secret: &[u8]) -> Self {
        HotpGenerator {
            account: String::from(account),
            provider: String::from(provider),
            secret: Vec::from(secret),
            issuer: None,
            algorithm: DEFAULT_ALGORITHM,
            initial_counter: DEFAULT_INITIAL_COUNTER,
            counter: DEFAULT_INITIAL_COUNTER,
            digits: DEFAULT_DIGITS,
        }
    }

    /// Sets the initial counter value and resets the internal counter.
    pub fn set_initial_counter(&mut self, value: u64) {
        self.initial_counter = value;
        self.counter = value;
    }

    /// Resets the internal counter value to the initial one.
    pub fn reset_counter(&mut self) {
        self.counter = self.initial_counter;
    }

    fn generate_value(&self, message: &[u8]) -> Result<Vec<u8>, crypto::CryptoError> {
        match self.algorithm {
            GeneratorAlgorithm::HmacSha1 => crypto::hmac_sha1(&self.secret, message),
            GeneratorAlgorithm::HmacSha256 => crypto::hmac_sha256(&self.secret, message),
            GeneratorAlgorithm::HmacSha512 => crypto::hmac_sha512(&self.secret, message),
        }
    }
}

impl Default for HotpGenerator {
    fn default() -> Self {
        HotpGenerator {
            account: String::from(""),
            provider: String::from(""),
            secret: vec![],
            issuer: None,
            algorithm: DEFAULT_ALGORITHM,
            initial_counter: DEFAULT_INITIAL_COUNTER,
            counter: DEFAULT_INITIAL_COUNTER,
            digits: DEFAULT_DIGITS,
        }
    }
}

impl Generator for HotpGenerator {
    type Error = HotpError;

    /// Sets the number of digits of generated HOTP values.
    fn set_digits(&mut self, value: u8) -> Result<(), Self::Error> {
        if value != 6 && value != 8 {
            return Err(Self::Error {
                kind: String::from("Wrong number of digits value"),
            });
        }

        self.digits = value;
        Ok(())
    }

    /// Gets the number of digits of generated HOTP values.
    fn get_digits(&self) -> &u8 {
        &self.digits
    }

    /// Computes the next HOTP value based on the internal counter value.
    fn get_value(&mut self) -> Result<String, Self::Error> {
        // Parsing the counter value into an HMAC-SHA message
        let message = encode_counter(&self.counter);

        // Generates the HMAC-SHA hashe
        let hmac = self.generate_value(&message);
        if let Err(_) = hmac {
            return Err(Self::Error {
                kind: String::from("HMAC-SHA cipher error"),
            });
        }

        // Applying the RFC 4226 offset
        let value = otp_offset(&hmac.unwrap());

        // Applying modulus based on number of digits
        let value = otp_value_to_string(&value, &self.digits);

        self.counter += 1;
        Ok(value)
    }

    /// Retrieves the OTP auth URI value of this generator
    fn get_otp_auth_uri(&self) -> Result<String, Self::Error> {
        use data_encoding::BASE32;

        let mut uri = Url::parse("otpauth://hotp/").unwrap();

        // Setting label part (Provider and account)
        match uri.path_segments_mut() {
            Ok(mut path) => path.push(&format!("{}:{}", self.provider, self.account)),
            _ => {
                return Err(HotpError {
                    kind: String::from("Wrong URI base"),
                });
            }
        };

        // Setting URI parameters
        uri.query_pairs_mut()
            .append_pair("secret", &BASE32.encode(&self.secret))
            .append_pair(
                "algorithm",
                match self.algorithm {
                    GeneratorAlgorithm::HmacSha1 => "SHA1",
                    GeneratorAlgorithm::HmacSha256 => "SHA256",
                    GeneratorAlgorithm::HmacSha512 => "SHA512",
                },
            )
            .append_pair("counter", &self.initial_counter.to_string())
            .append_pair("digits", &self.digits.to_string());

        if let Some(issuer) = &self.issuer {
            uri.query_pairs_mut().append_pair("issuer", &issuer);
        }

        Ok(String::from(uri.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_compute_hotp_value() {
        let mut generator = HotpGenerator::new("Kitten", "Tacocat", b"tacocat");
        let expected = "994752";

        let value = generator.get_value();
        assert!(value.is_ok());
        assert_eq!(expected, value.unwrap());
    }

    #[test]
    fn should_compute_hotp_value_sha256() {
        let mut generator = HotpGenerator::new("Kitten", "Tacocat", b"tacocat");
        generator.algorithm = GeneratorAlgorithm::HmacSha256;

        let expected = "559555";
        let value = generator.get_value();

        assert!(value.is_ok());
        assert_eq!(expected, value.unwrap());
    }

    #[test]
    fn should_compute_hotp_value_sha512() {
        let mut generator = HotpGenerator::new("Kitten", "Tacocat", b"tacocat");
        generator.algorithm = GeneratorAlgorithm::HmacSha512;

        let expected = "464093";
        let value = generator.get_value();

        assert!(value.is_ok());
        assert_eq!(expected, value.unwrap());
    }

    #[test]
    fn should_compute_hotp_value_with_8_digits() {
        let mut generator = HotpGenerator::new("Kittent", "Tacocat", b"tacocat");
        generator.set_digits(8).unwrap();

        let expected = "99475239";
        let value = generator.get_value();

        assert!(value.is_ok());
        assert_eq!(expected, value.unwrap());
    }

    #[test]
    fn should_generate_otp_auth_uri() {
        let generator = HotpGenerator::new("Kitten", "Tacocat", b"tacocat");
        let expected = "otpauth://hotp/Tacocat:Kitten?secret=ORQWG33DMF2A%3D%3D%3D%3D&algorithm=SHA1&counter=0&digits=6";

        let uri = generator.get_otp_auth_uri();
        assert!(uri.is_ok());
        assert_eq!(expected, uri.unwrap());
    }
}
