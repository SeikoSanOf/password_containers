#[cfg(test)]
mod tests {
    use crate::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::Aes256Gcm;
    use aes_gcm::Nonce;

    #[test]
    fn test_derive_key_deterministic() {
        let password = "test_password";
        let salt = [0u8; 16];

        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);

        assert_eq!(key1, key2, "Same password and salt should produce same key");
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0u8; 16];
        let key1 = derive_key("password1", &salt);
        let key2 = derive_key("password2", &salt);

        assert_ne!(key1, key2, "Different passwords should produce different keys");
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = "test_password";
        let salt1 = [0u8; 16];
        let mut salt2 = [0u8; 16];
        salt2[0] = 1;

        let key1 = derive_key(password, &salt1);
        let key2 = derive_key(password, &salt2);

        assert_ne!(key1, key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "master_password";
        let salt = [42u8; 16];
        let nonce_bytes = [7u8; 12];

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = b"secret data here";
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("Failed to encrypt");

        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("Failed to decrypt");

        assert_eq!(plaintext, decrypted.as_slice(), "Decrypted data should match plaintext");
    }

    #[test]
    fn test_different_nonces_different_ciphertext() {
        let password = "master_password";
        let salt = [42u8; 16];
        let plaintext = b"secret data here";

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new(&key.into());

        let nonce1 = Nonce::from_slice(&[0u8; 12]);
        let nonce2 = Nonce::from_slice(&[1u8; 12]);

        let ciphertext1 = cipher
            .encrypt(nonce1, plaintext.as_ref())
            .expect("Failed to encrypt");

        let ciphertext2 = cipher
            .encrypt(nonce2, plaintext.as_ref())
            .expect("Failed to encrypt");

        assert_ne!(ciphertext1, ciphertext2, "Different nonces should produce different ciphertexts");
    }

    #[test]
    fn test_wrong_password_decryption_fails() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let salt = [42u8; 16];
        let nonce_bytes = [7u8; 12];

        let plaintext = b"secret data";

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("Failed to encrypt");

        let wrong_key = derive_key(wrong_password, &salt);
        let wrong_cipher = Aes256Gcm::new(&wrong_key.into());
        let result = wrong_cipher.decrypt(nonce, ciphertext.as_ref());

        assert!(result.is_err(), "Decryption with wrong password should fail");
    }
}
