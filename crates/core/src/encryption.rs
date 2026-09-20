use age::{secrecy::ExposeSecret, x25519};
use thiserror::Error;

/// Errors returned by the age encryption helpers.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid age public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid age private key: {0}")]
    InvalidPrivateKey(String),
    #[error("age encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("age decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("encrypted age payload is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// An age X25519 key pair represented in the text format used by age.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

/// Generate a new age X25519 key pair.
pub fn generate_keypair() -> KeyPair {
    let identity = x25519::Identity::generate();
    KeyPair {
        private_key: identity.to_string().expose_secret().to_owned(),
        public_key: identity.to_public().to_string(),
    }
}

/// Derive the public age key from a private age key.
pub fn public_key(private_key: &str) -> Result<String> {
    let identity = private_key
        .parse::<x25519::Identity>()
        .map_err(|error| Error::InvalidPrivateKey(error.to_string()))?;
    Ok(identity.to_public().to_string())
}

/// Encrypt plaintext for an age X25519 public key and return ASCII-armored text.
pub fn encrypt(public_key: &str, plaintext: impl AsRef<[u8]>) -> Result<String> {
    let recipient = public_key
        .parse::<x25519::Recipient>()
        .map_err(|error| Error::InvalidPublicKey(error.to_string()))?;

    Ok(age::encrypt_and_armor(&recipient, plaintext.as_ref())?)
}

/// Decrypt an ASCII-armored age payload with an age X25519 private key.
pub fn decrypt(private_key: &str, ciphertext: &str) -> Result<Vec<u8>> {
    let identity = private_key
        .parse::<x25519::Identity>()
        .map_err(|error| Error::InvalidPrivateKey(error.to_string()))?;

    Ok(age::decrypt(&identity, ciphertext.as_bytes())?)
}

/// Decrypt an ASCII-armored age payload as UTF-8 text.
pub fn decrypt_to_string(private_key: &str, ciphertext: &str) -> Result<String> {
    Ok(String::from_utf8(decrypt(private_key, ciphertext)?)?)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, decrypt_to_string, encrypt, generate_keypair};

    #[test]
    fn round_trip_preserves_plaintext() -> super::Result<()> {
        let keys = generate_keypair();
        let ciphertext = encrypt(&keys.public_key, b"DB_URL=postgres://example")?;

        assert_eq!(
            decrypt(&keys.private_key, &ciphertext)?,
            b"DB_URL=postgres://example"
        );
        Ok(())
    }

    #[test]
    fn round_trip_supports_text_output() -> super::Result<()> {
        let keys = generate_keypair();
        let ciphertext = encrypt(&keys.public_key, "secret value")?;

        assert_eq!(
            decrypt_to_string(&keys.private_key, &ciphertext)?,
            "secret value"
        );
        Ok(())
    }

    #[test]
    fn wrong_private_key_cannot_decrypt() -> super::Result<()> {
        let recipient = generate_keypair();
        let other = generate_keypair();
        let ciphertext = encrypt(&recipient.public_key, "secret")?;

        assert!(decrypt(&other.private_key, &ciphertext).is_err());
        Ok(())
    }
}
