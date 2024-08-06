use serde::{Serialize, Deserialize};

pub mod client;
pub mod stronghold;
pub mod types;


/// Encrypted data packet.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptedData {
    /// Sender pub key
    pub public_key: [u8; 32],
    /// Nonce for encryption
    pub nonce: [u8; 12],
    /// Packet tag
    pub tag: [u8; 16],
    /// Cipher text
    pub ciphertext: [u8; 32],
}

impl EncryptedData {
    /// Creates a new `EncryptedData` instance.
    pub fn new(
        public_key: [u8; 32],
        nonce: [u8; 12],
        tag: [u8;16],
        ciphertext: [u8; 32],
    ) -> Self {

        Self {
            public_key,
            nonce,
            tag,
            ciphertext,
        }
    }
}