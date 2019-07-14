use crate::crypto;
use crate::generator::*;
use std::default::Default;
use std::error::Error;
use std::fmt;
use url::Url;

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

#[derive(Debug)]
pub struct HotpGenerator {
    pub account: String,
    pub provider: String,
    secret: Vec<u8>,
    pub issuer: Option<String>,
    pub algorithm: GeneratorAlgorithm,
    initial_counter: u64,
    counter: u64,
    digits: u8,
}

impl HotpGenerator {
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

    pub fn set_digits(&mut self, value: u8) -> Result<(), HotpError> {
        if value != 6 && value != 8 {
            return Err(HotpError {
                kind: String::from("Wrong number of digits value"),
            });
        }

        self.digits = value;
        Ok(())
    }

    pub fn set_initial_counter(&mut self, value: u64) {
        self.initial_counter = value;
        self.counter = value;
    }

    pub fn reset_counter(&mut self) {
        self.counter = self.initial_counter;
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
    fn should_generate_otp_auth_uri() {
        let generator = HotpGenerator::new("Kitten", "Tacocat", b"tacocat");
        let expected = "otpauth://hotp/Tacocat:Kitten?secret=ORQWG33DMF2A%3D%3D%3D%3D&algorithm=SHA1&counter=0&digits=6";

        let uri = generator.get_otp_auth_uri();
        assert!(uri.is_ok());
        assert_eq!(expected, uri.unwrap());
    }
}
