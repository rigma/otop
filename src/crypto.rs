// Copyright 2019 Romain Failla
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use hmac::{Hmac, Mac};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct CryptoError {
    kind: String,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error occured during crypto process: {}", self.kind)
    }
}

impl Error for CryptoError {
    fn description(&self) -> &str {
        "Error occured during crypto process"
    }
}

#[cfg(feature = "sha1")]
pub fn hmac_sha1(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let digest = HmacSha1::new_varkey(secret);
    if digest.is_err() {
        return Err(CryptoError {
            kind: String::from("Invalid secret length"),
        });
    }

    let mut digest = digest.unwrap();
    digest.input(message);

    Ok(digest.result().code().to_vec())
}

#[cfg(not(feature = "sha1"))]
pub fn hmac_sha1(_secret: &[u8], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    panic!("HMAC-SHA1 cipher algorithm is not implemented with your features");
}

#[cfg(feature = "sha256")]
pub fn hmac_sha256(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let digest = HmacSha256::new_varkey(secret);
    if digest.is_err() {
        return Err(CryptoError {
            kind: String::from("Invalid secret length"),
        });
    }

    let mut digest = digest.unwrap();
    digest.input(message);

    Ok(digest.result().code().to_vec())
}

#[cfg(not(feature = "sha256"))]
pub fn hmac_sha256(_secret: &[u8], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    panic!("HMAC-SHA-256 cipher algorithm is not implemented with your features");
}

#[cfg(feature = "sha512")]
pub fn hmac_sha512(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let digest = HmacSha512::new_varkey(secret);
    if digest.is_err() {
        return Err(CryptoError {
            kind: String::from("Invalid secret length"),
        });
    }

    let mut digest = digest.unwrap();
    digest.input(message);

    Ok(digest.result().code().to_vec())
}

#[cfg(not(feature = "sha512"))]
pub fn hmac_sha512(_secret: &[u8], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    panic!("HMAC-SHA1 cipher algorithm is not implemented with your features");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sha1")]
    #[test]
    fn should_compute_hmac_sha1() {
        let output = hmac_sha1(b"tacocat", b"hello");
        let expected = vec![
            0x81, 0x8d, 0xe8, 0x9f, 0x4b, 0xa5, 0xdd, 0x1d, 0x89, 0xd8, 0xa8, 0x1c, 0xdb, 0x7c,
            0x88, 0x4d, 0x44, 0x04, 0xee, 0xd9,
        ];

        assert!(output.is_ok());
        assert_eq!(expected, output.unwrap());
    }

    #[cfg(feature = "sha256")]
    #[test]
    fn should_compute_hmac_sha256() {
        let output = hmac_sha256(b"tacocat", b"hello");
        let expected = vec![
            0xd8, 0xd6, 0x62, 0xc5, 0xa5, 0xfd, 0xd8, 0xc5, 0xe8, 0x50, 0x77, 0x02, 0xf7, 0x69,
            0x93, 0x45, 0xeb, 0x42, 0x56, 0xd4, 0xeb, 0x0d, 0xeb, 0xe1, 0x26, 0x71, 0x86, 0xb4,
            0x2c, 0xe4, 0xb1, 0xb0,
        ];

        assert!(output.is_ok());
        assert_eq!(expected, output.unwrap());
    }

    #[cfg(feature = "sha512")]
    #[test]
    fn should_compute_hmac_sha512() {
        let output = hmac_sha512(b"tacocat", b"hello");
        let expected = vec![
            0x9f, 0xa8, 0xc8, 0x98, 0xf0, 0xc2, 0x3b, 0x7d, 0xdb, 0xd1, 0x0e, 0xc3, 0x07, 0x7a,
            0x53, 0xc4, 0x92, 0x14, 0xb4, 0x09, 0xe9, 0x7f, 0xd2, 0x27, 0xf0, 0x2f, 0xae, 0x8c,
            0x74, 0x8d, 0xce, 0xf5, 0xd3, 0x7a, 0x8b, 0x4d, 0x7d, 0x6a, 0xd0, 0x63, 0x00, 0x51,
            0x33, 0x70, 0x17, 0x21, 0x9c, 0x72, 0x60, 0xf1, 0x9b, 0x5c, 0x63, 0xa0, 0xc9, 0xe4,
            0xf7, 0xf5, 0x1d, 0x3f, 0xaa, 0x13, 0x34, 0x4f,
        ];

        assert!(output.is_ok());
        assert_eq!(expected, output.unwrap());
    }
}
