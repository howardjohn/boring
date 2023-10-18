use std::sync::Arc;

mod aead;
mod hash;
mod hmac;
mod kx;
mod verify;

pub static PROVIDER: &'static dyn rustls::crypto::CryptoProvider = &Provider;

#[derive(Debug)]
struct Provider;

impl rustls::crypto::CryptoProvider for Provider {
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }

    fn default_cipher_suites(&self) -> &'static [rustls::SupportedCipherSuite] {
        ALL_CIPHER_SUITES
    }

    fn default_kx_groups(&self) -> &'static [&'static dyn rustls::crypto::SupportedKxGroup] {
        kx::ALL_KX_GROUPS
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS_RSA_WITH_AES_128_GCM_SHA256,
];

pub static TLS_RSA_WITH_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::cipher_suite::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &hash::Sha256,
        },
        hmac_provider: &hmac::Sha256Hmac,
        aead_alg: &aead::Aes128GcmAead,
    });

pub fn certificate_verifier(
    roots: rustls::RootCertStore,
) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
    Arc::new(rustls::client::WebPkiServerVerifier::new_with_algorithms(
        roots,
        verify::ALGORITHMS,
    ))
}
