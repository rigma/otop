// Copyright 2019 Romain Failla
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # `otop`

extern crate data_encoding;
extern crate hmac;
#[cfg(feature = "sha1")]
extern crate sha1;
#[cfg(any(feature = "sha256", feature = "sha512"))]
extern crate sha2;
extern crate url;

pub mod hotp;
pub mod totp;

mod crypto;
mod generator;

pub use generator::{Generator, GeneratorAlgorithm};
