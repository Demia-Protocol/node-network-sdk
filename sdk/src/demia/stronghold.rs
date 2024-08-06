use iota_stronghold::{procedures::{self, AeadCipher, KeyType, Sha2Hash}, ClientVault, Location};
use crypto::{
    ciphers::{traits::Aead, aes_gcm::Aes256Gcm},
    keys::x25519,
};
use crate::client::stronghold::{Error, StrongholdAdapter, PRIVATE_DATA_CLIENT_PATH};

use super::EncryptedData;

/// The client path for X25519 shared keys
pub(super) const DIFFIE_HELLMAN_SHARED_KEY_PATH: &[u8] = b"dh-shared_key";
/// The client path for X25519 output
pub(super) const DIFFIE_HELLMAN_OUTPUT_PATH: &[u8] = b"dh-output";
/// Aead encryption salt
pub(super) const AEAD_SALT: &[u8] = b"stronghold-adapter-encrypt";

type Result<T> = std::result::Result<T, Error>;

impl StrongholdAdapter {
    /// Retrieve a vault client
    pub async fn vault_client<P: AsRef<[u8]>>(&mut self, path: P) -> Result<ClientVault> {
        // Modified stronghold to pub(crate)
        self.stronghold.lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)
            .map(|client| Ok(client.vault(path)))?
    }

    /// Encrypt a data packet
    pub async fn x25519_encrypt(&mut self, public_key: x25519::PublicKey, private_key: Location, msg: Vec<u8>) -> Result<EncryptedData> {
        let client = self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?;

        let shared_key_path = Location::generic(DIFFIE_HELLMAN_SHARED_KEY_PATH, DIFFIE_HELLMAN_SHARED_KEY_PATH);
        let shared_output_path = Location::generic(DIFFIE_HELLMAN_OUTPUT_PATH, DIFFIE_HELLMAN_OUTPUT_PATH);

        // Retrieve the sender public key for inclusion in EncryptedData
        let pub_key_proc = procedures::PublicKey {
            ty: KeyType::X25519,
            private_key: private_key.clone(),
        };

        let sender_pub_key = client.execute_procedure(pub_key_proc)?;
        let mut pub_key_slice = [0u8; 32];
        pub_key_slice.clone_from_slice(sender_pub_key.as_slice());

        // Create a diffie hellman shared key exchange
        let dh_proc = procedures::X25519DiffieHellman {
            public_key: public_key.to_bytes(),
            private_key: private_key.clone(),
            shared_key: shared_key_path.clone(),
        };

        // Complete a KDF Concat procedure and encrypt the output with AEAD to make
        // pass to recipient in serialized form
        let kdf_proc = procedures::ConcatKdf {
            hash: Sha2Hash::Sha256,
            algorithm_id: "ECDH-ES".to_string(),
            shared_secret: shared_key_path,
            key_len: 32,
            apu: vec![],
            apv: vec![],
            pub_info: vec![],
            priv_info: vec![],
            output: shared_output_path.clone(),
        };

        let mut nonce = [0_u8; 12];
        crypto::utils::rand::fill(&mut nonce)?;

        let aed_encrypt = procedures::AeadEncrypt {
            cipher: AeadCipher::Aes256Gcm,
            associated_data: AEAD_SALT.to_vec(),
            plaintext: msg,
            nonce: nonce.to_vec(),
            key: shared_output_path,
        };

        client.execute_procedure_chained(vec![dh_proc.into(), kdf_proc.into()])?;
        let mut resp = client.execute_procedure(aed_encrypt)?;

        let mut tag = [0u8; 16];
        let mut data = [0u8; 32];
        tag.clone_from_slice(&resp.drain(..Aes256Gcm::TAG_LENGTH).collect::<Vec<u8>>());
        data.clone_from_slice(resp.as_slice());

        Ok(EncryptedData::new(
            pub_key_slice,
            nonce,
            tag,
            data,
        ))
    }

    /// Decrypt a data packet
    pub async fn x25519_decrypt(&mut self, private_key: Location, msg: EncryptedData) -> Result<Vec<u8>> {
        let client = self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?;

        let shared_key_path = Location::generic(DIFFIE_HELLMAN_SHARED_KEY_PATH, DIFFIE_HELLMAN_SHARED_KEY_PATH);
        let shared_output_path = Location::generic(DIFFIE_HELLMAN_OUTPUT_PATH, DIFFIE_HELLMAN_OUTPUT_PATH);

        // Create a diffie hellman shared key exchange
        let dh_proc = procedures::X25519DiffieHellman {
            public_key: msg.public_key,
            private_key: private_key.clone(),
            shared_key: shared_key_path.clone(),
        };

        // Complete a KDF Concat procedure
        let kdf_proc = procedures::ConcatKdf {
            hash: Sha2Hash::Sha256,
            algorithm_id: "ECDH-ES".to_string(),
            shared_secret: shared_key_path,
            key_len: 32,
            apu: vec![],
            apv: vec![],
            pub_info: vec![],
            priv_info: vec![],
            output: shared_output_path.clone(),
        };

        client.execute_procedure_chained(vec![dh_proc.into(), kdf_proc.into()])?;

        // Decrypt AEAD Encrypted Data packet and return the message within
        let aed_decrypt = procedures::AeadDecrypt {
            cipher: AeadCipher::Aes256Gcm,
            associated_data: AEAD_SALT.as_ref().to_vec(),
            ciphertext: msg.ciphertext.to_vec(),
            tag: msg.tag.to_vec(),
            nonce: msg.nonce.to_vec(),
            key: shared_output_path,
        };

        Ok(client.execute_procedure(aed_decrypt)?)
    }
}
