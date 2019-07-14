use crate::crypto;
use crate::generator::*;
use std::error::Error;
use std::fmt;

pub const DEFAULT_ALGORITHM: GeneratorAlgorithm = GeneratorAlgorithm::HmacSha1;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_INITIAL_COUNTER: u64 = 0;

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

pub struct HotpGenerator {
    label: String,
    secret: Vec<u8>,
    issuer: Option<String>,
    algorithm: GeneratorAlgorithm,
    counter: u64,
    digits: u8,
}

impl HotpGenerator {
    pub fn new(secret: &[u8], label: &str) -> Self {
        HotpGenerator {
            label: String::from(label),
            secret: Vec::from(secret),
            issuer: None,
            algorithm: DEFAULT_ALGORITHM,
            counter: DEFAULT_INITIAL_COUNTER,
            digits: DEFAULT_DIGITS,
        }
    }

    fn generate_value(
        &self,
        secret: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, crypto::CryptoError> {
        match self.algorithm {
            GeneratorAlgorithm::HmacSha1 => crypto::hmac_sha1(secret, message),
            GeneratorAlgorithm::HmacSha256 => crypto::hmac_sha256(secret, message),
            GeneratorAlgorithm::HmacSha512 => crypto::hmac_sha512(secret, message),
        }
    }
}

impl Generator for HotpGenerator {
    type Error = HotpError;

    fn get_value(&mut self) -> Result<String, Self::Error> {
        let mut message: [u8; 8] = [0; 8];
        for i in (0..8).rev() {
            message[i] = ((self.counter >> (8 * i)) & 0xff) as u8;
        }
        self.counter += 1;

        let hmac = self.generate_value(&self.secret, &message);
        if hmac.is_err() {
            return Err(HotpError {
                kind: String::from("HMAC-SHA cipher error"),
            });
        }

        let hmac = hmac.unwrap();
        let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
        let value: u64 = (u64::from(hmac[offset] & 0x7f) << 24)
            | (u64::from(hmac[offset + 1]) << 16)
            | (u64::from(hmac[offset + 2]) << 8)
            | u64::from(hmac[offset + 3]);

        let value = if self.digits == 8 {
            value % 100_000_000_000
        } else {
            value % 1_000_000_000
        };

        let mut value = value.to_string();
        while value.len() < self.digits as usize {
            value.insert(0, '0');
        }

        Ok(value)
    }

    fn get_otp_auth_uri(&self) -> Result<String, Self::Error> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_compute_hotp_value() {
        let mut generator = HotpGenerator::new(b"tacocat", "Tacocat");
        let expected = "994752391";

        let value = generator.get_value();
        assert!(value.is_ok());
        assert_eq!(expected, value.unwrap());
    }

    #[test]
    fn should_generate_otp_auth_uri() {
        let generator = HotpGenerator::new(b"tacocat", "Tacocat");

        assert!(generator.get_otp_auth_uri().is_ok());
    }
}
