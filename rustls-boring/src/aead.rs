use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use rustls::crypto::cipher::{self, AeadKey, Iv, NONCE_LEN, UnsupportedOperationError};
use rustls::internal::msgs::base::Payload;

use boring::symm::Cipher;

pub struct Aes128GcmAead;

impl cipher::Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageEncrypter> {
        Box::new(Tls13Cipher(key, iv))
    }

    fn decrypter(&self, key: cipher::AeadKey, iv: cipher::Iv) -> Box<dyn cipher::MessageDecrypter> {
        Box::new(Tls13Cipher(key, iv))
    }

    fn key_len(&self) -> usize {
        Cipher::aes_128_gcm().key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

struct Tls13Cipher(cipher::AeadKey, cipher::Iv);

impl cipher::MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &self,
        m: cipher::BorrowedPlainMessage,
        seq: u64,
    ) -> Result<cipher::OpaqueMessage, rustls::Error> {

        // Is 16 bytes overhead correct here?
        let total_len = m.payload.len() + 1 + CHACHAPOLY1305_OVERHEAD;

        // construct a TLSInnerPlaintext
        let mut payload = Vec::with_capacity(total_len);
        payload.extend_from_slice(m.payload);
        payload.push(m.typ.get_u8());

        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.1, seq).0);
        let aad = cipher::make_tls13_aad(total_len);
        let mut actual_tag = [0; 16];
        match boring::symm::encrypt_aead(
            Cipher::aes_128_gcm(),
            self.0.as_ref(),
            Some(self.1.as_ref()),
            &aad,
            &payload,
            &mut actual_tag,
        ) {
            Err(_) => Err(rustls::Error::EncryptError),
            Ok(payload) => Ok(cipher::OpaqueMessage::new(m.typ, m.version, payload))
        }
    }
}

impl cipher::MessageDecrypter for Tls13Cipher {
    fn decrypt(
        &self,
        mut m: cipher::OpaqueMessage,
        seq: u64,
    ) -> Result<cipher::PlainMessage, rustls::Error> {
        let payload = m.payload_mut();
        let tag_size: usize = 16;
        if payload.len() < tag_size {
            return Err(rustls::Error::DecryptError);
        }
        let aad = cipher::make_tls13_aad(payload.len());

        let tag_pos = payload.len() - tag_size;
        let (msg, tag) = payload.split_at_mut(tag_pos);

        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.1, seq).0);

        match boring::symm::decrypt_aead(
            Cipher::aes_128_gcm(),
            self.0.as_ref(),
            Some(self.1.as_ref()),
            &aad,
            &msg,
            &tag,
        ) {
            Err(_) => Err(rustls::Error::EncryptError),
            Ok(payload) => Ok(cipher::PlainMessage {
                typ: m.typ,
                version: m.version,
                payload: Payload(payload),
            })
        }
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
