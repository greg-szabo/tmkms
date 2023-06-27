//! Ed25519 signing keys

pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};

use crate::{
    error::Error,
    keyring::SigningProvider,
};
use std::sync::Arc;
use tendermint::TendermintKey;

#[allow(clippy::redundant_allocation)]

/// Ed25519 signer
#[derive(Clone)]
pub struct Signer {
    /// Provider for this signer
    provider: SigningProvider,

    /// Tendermint public key
    public_key: PublicKey,

    /// Signer trait object
    signer: Arc<Box<ed25519_dalek::ExpandedSecretKey>>,
}

impl Signer {
    /// Create a new signer
    pub fn new(
        provider: SigningProvider,
        public_key: PublicKey,
        signer: Box<ed25519_dalek::ExpandedSecretKey>,
    ) -> Self {
        Self {
            provider,
            public_key,
            signer: Arc::new(signer),
        }
    }

    /// Get the Tendermint public key for this signer
    pub fn public_key(&self) -> TendermintKey {
        TendermintKey::ConsensusKey(self.public_key.into())
    }

    /// Get the provider for this signer
    pub fn provider(&self) -> SigningProvider {
        self.provider
    }

    /// Sign the given message using this signer
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(self
            .signer
            .sign(msg, &self.public_key))
    }
}
