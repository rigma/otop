trait Generator {
    type Error;

    fn get_value(&self) -> Result<&str, Self::Error>;

    fn get_otp_auth_uri(&self) -> Result<&str, Self::Error>;
}
