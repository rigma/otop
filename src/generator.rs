pub trait Generator {
    type Error;

    fn get_value(&mut self) -> Result<&str, Self::Error>;

    fn get_otp_auth_uri(&self) -> Result<&str, Self::Error>;
}

pub enum GeneratorAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}
