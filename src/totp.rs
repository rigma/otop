// Copyright 2019 Romain Failla
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::crypto;
use crate::generator::*;
use std::default::Default;
use std::error::Error;
use std::fmt;
use std::time::*;
use url::Url;

pub const DEFAULT_ALGORITHM: GeneratorAlgorithm = GeneratorAlgorithm::HmacSha1;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_EPOCH: SystemTime = UNIX_EPOCH;
pub const DEFAULT_TIME_STEP: u64 = 30;

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

#[derive(Debug)]
pub struct TotpGenerator {
     /// The name of the account associated with this generator.
    pub account: String,

    /// The name of the provider associated with this generator.
    pub provider: String,
    secret: Vec<u8>,

    /// The optional HOTP token issuer's name.
    pub issuer: Option<String>,

    /// The algorithm used by the generator.
    pub algorithm: GeneratorAlgorithm,
    digits: u8,
    epoch: SystemTime,
    time_step: u64
}

impl TotpGenerator {
    pub fn new(account: &str, provider: &str, secret: &[u8]) -> Self {
        TotpGenerator {
            account: String::from(account),
            provider: String::from(provider),
            secret: Vec::from(secret),
            issuer: None,
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            epoch: DEFAULT_EPOCH,
            time_step: DEFAULT_TIME_STEP,
        }
    }

    pub fn set_digits(&mut self, value: u8) -> Result<(), TotpError> {
        if value != 6 && value != 8 {
            return Err(TotpError {
                kind: String::from("Wrong number of digits value"),
            });
        }

        self.digits = value;
        Ok(())
    }

    pub fn get_digits(&self) -> &u8 {
        &self.digits
    }

    pub fn set_epoch(&mut self, epoch: u64) -> Result<(), TotpError> {
        self.epoch = DEFAULT_EPOCH + Duration::from_secs(epoch);
        Ok(())
    }

    pub fn get_epoch(&self) -> &SystemTime {
        &self.epoch
    }

    pub fn set_time_step(&mut self, step: u64) -> Result<(), TotpError> {
        if step == 0 {
            return Err(TotpError {
                kind: String::from("TOTP time step cannot be null!"),
            });
        }

        self.time_step = step;
        Ok(())
    }

    pub fn get_time_step(&self) -> &u64 {
        &self.time_step
    }
}
