pub trait Generator {
    type Error;

    fn get_value(&mut self) -> Result<String, Self::Error>;

    fn get_otp_auth_uri(&self) -> Result<String, Self::Error>;
}

#[derive(PartialEq)]
pub enum GeneratorAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}
