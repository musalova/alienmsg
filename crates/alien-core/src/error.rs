#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("serialization error")]
    Serde,
    #[error("invalid contact card")]
    InvalidCard,
    #[error("signature verification failed")]
    BadSignature,
    #[error("decryption failed (bad key, corrupted data or wrong recipient)")]
    Decrypt,
    #[error("ratchet error: {0}")]
    Ratchet(&'static str),
    #[error("invalid mnemonic phrase")]
    Mnemonic,
    #[error("key derivation failed")]
    Kdf,
    #[error("KEM operation failed")]
    Kem,
    #[error("group error: {0}")]
    Group(&'static str),
    #[error("unknown or unsupported envelope")]
    BadEnvelope,
    #[error("invalid argument: {0}")]
    InvalidArg(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
