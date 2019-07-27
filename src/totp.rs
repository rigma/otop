// Copyright 2019 Romain Failla
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides a TOTP value generator.
//! 
//! This generator can be used to generate Time-base One Time Password (TOTP) to perform a two-factor authentication
//! or to generate an OTP auth URI which can be encoded in a QR code.
//! 
//! ## Example
//! ```
//! use otop::totp::TotpGenerator;
//! use otop::Generator;
//! 
//! // Even if this generator does not use an internal counter, it shares the same trait as
//! // `HotpGenerator`. As a result it has to be a mutable variable.
//! let mut generator = TotpGenerator::new("Kitten", "Tacocat", b"tacocat");
//! 
//! // Compute a TOTP value.
//! let value = generator.get_value();
//! assert!(value.is_ok());
//! 
//! // Generates an URI to serialize this generator
//! let uri = generator.get_otp_auth_uri();
//! assert!(uri.is_ok());
//! ```

use crate::crypto;
use crate::generator::*;
use std::error::Error;
use std::fmt;
use std::time::*;
use url::Url;

/// The default cryptographic algorithm for TOTP value generation.
pub const DEFAULT_ALGORITHM: GeneratorAlgorithm = GeneratorAlgorithm::HmacSha1;

/// The default TOTP value's number of digits.
pub const DEFAULT_DIGITS: u8 = 6;

/// The default epoch to use with generator which is the Unix epoch.
pub const DEFAULT_EPOCH: SystemTime = UNIX_EPOCH;

/// The default period (in seconds) between each generator's _tick_.
pub const DEFAULT_PERIOD: u64 = 30;

/// Defines an error which has occured during runtime with the TOTP value generator.
#[derive(Debug)]
pub struct TotpError {
    kind: String,
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error occured in TOTP value generator: {}", self.kind)
    }
}

impl Error for TotpError {
    fn description(&self) -> &str {
        "Error occured in HOTP value generator"
    }
}

/// A TOTP value generator which implements [IETF RFC 6238](https://tools.ietf.org/html/rfc6238) specification.
#[derive(Debug)]
pub struct TotpGenerator {
    /// The name of the account associated with this generator.
    pub account: String,

    /// The name of the provider associated with this generator.
    pub provider: String,
    secret: Vec<u8>,

    /// The optional TOTP token issuer's name.
    pub issuer: Option<String>,

    /// The algorithm used by the generator.
    pub algorithm: GeneratorAlgorithm,
    digits: u8,
    epoch: SystemTime,
    period: u64,
}

impl TotpGenerator {
    // Instanciates a **new** instance of a TOTP value generator.
    pub fn new(account: &str, provider: &str, secret: &[u8]) -> Self {
        TotpGenerator {
            account: String::from(account),
            provider: String::from(provider),
            secret: Vec::from(secret),
            issuer: None,
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            epoch: DEFAULT_EPOCH,
            period: DEFAULT_PERIOD,
        }
    }

    /// Sets the number of digits of generated TOTP values.
    pub fn set_digits(&mut self, value: u8) -> Result<(), TotpError> {
        if value != 6 && value != 8 {
            return Err(TotpError {
                kind: String::from("Wrong number of digits value"),
            });
        }

        self.digits = value;
        Ok(())
    }

    /// Gets the number of digits of generated TOTP values.
    pub fn get_digits(&self) -> &u8 {
        &self.digits
    }

    /// Sets the epoch (eg. the beginning of time) of the generator.
    pub fn set_epoch(&mut self, epoch: u64) -> Result<(), TotpError> {
        self.epoch = DEFAULT_EPOCH + Duration::from_secs(epoch);
        Ok(())
    }

    /// Gets the epoch of the generator.
    pub fn get_epoch(&self) -> &SystemTime {
        &self.epoch
    }

    /// Sets the period between each generator's _tick_. See Section 4.2 of [RFC 6238](https://tools.ietf.org/html/rfc6238)
    /// for futher informations.
    pub fn set_period(&mut self, step: u64) -> Result<(), TotpError> {
        if step == 0 {
            return Err(TotpError {
                kind: String::from("TOTP time step cannot be null!"),
            });
        }

        self.period = step;
        Ok(())
    }

    /// Retrieves the period between each generator's _tick_.
    pub fn get_period(&self) -> &u64 {
        &self.period
    }

    /// Retrieves the current _tick_ of this generator based on the system current time.
    pub fn get_time_counter(&self) -> Result<u64, SystemTimeError> {
        let duration = SystemTime::now().duration_since(self.epoch)?;

        Ok((duration.as_secs() as f64 / self.period as f64).floor() as u64)
    }

    fn generate_value(&self, message: &[u8]) -> Result<Vec<u8>, crypto::CryptoError> {
        match self.algorithm {
            GeneratorAlgorithm::HmacSha1 => crypto::hmac_sha1(&self.secret, message),
            GeneratorAlgorithm::HmacSha256 => crypto::hmac_sha256(&self.secret, message),
            GeneratorAlgorithm::HmacSha512 => crypto::hmac_sha512(&self.secret, message),
        }
    }
}

impl Generator for TotpGenerator {
    type Error = TotpError;

    /// Computes the next TOTP value based on the system current time.
    fn get_value(&mut self) -> Result<String, Self::Error> {
        // Generates the current time counter
        let time_counter = self.get_time_counter();
        if let Err(_) = time_counter {
            return Err(Self::Error {
                kind: String::from("Current time counter cannot be generated!"),
            });
        }

        // Parsing time counter value into a HMAC-SHA message
        let message = encode_counter(&time_counter.unwrap());

        // Generates HMAC-SHA hashe
        let hmac = self.generate_value(&message);
        if let Err(_) = hmac {
            return Err(Self::Error {
                kind: String::from("HMAC-SHA cipher error"),
            });
        }

        // Applying the RFC 4226 offset
        let value = otp_offset(&hmac.unwrap());

        // Serializing value into a string representation
        Ok(otp_value_to_string(&value, &self.digits))
    }

    /// Retrieves the OTP auth URI value of this generator.
    fn get_otp_auth_uri(&self) -> Result<String, Self::Error> {
        use data_encoding::BASE32;

        let mut uri = Url::parse("otpauth://totp/").unwrap();

        // Setting label part (Provider and account)
        match uri.path_segments_mut() {
            Ok(mut path) => path.push(&format!("{}:{}", self.provider, self.account)),
            _ => {
                return Err(Self::Error {
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
            .append_pair("period", &self.period.to_string())
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
    fn should_generate_otp_auth_uri() {
        let generator = TotpGenerator::new("Kitten", "Tacocat", b"tacocat");
        let expected = "otpauth://totp/Tacocat:Kitten?secret=ORQWG33DMF2A%3D%3D%3D%3D&algorithm=SHA1&period=30&digits=6";

        let uri = generator.get_otp_auth_uri();
        assert!(uri.is_ok());
        assert_eq!(expected, uri.unwrap());
    }
}
