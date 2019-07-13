#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_compute_hotp_value() {
        let generator = HotpGenerator::new(b"tacocat", "Tacocat");

        assert!(generator.get_value().is_ok());
    }

    #[test]
    fn should_generate_otp_auth_uri() {
        let generator = HotpGenerator::new(b"tacocat", "Tacocat");

        assert!(generator.get_otp_auth_uri().is_ok());
    }
}
