use pqcrypto_kyber::kyber1024::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};

/// Generate a Kyber1024 quantum-resistant keypair
pub fn generate_keys() -> (PublicKey, SecretKey) {
    kyber1024::keypair()
}

/// Encrypt a message using Kyber1024
pub fn encrypt_message(pk: &PublicKey) -> (Ciphertext, SharedSecret) {
    kyber1024::encapsulate(pk)
}

/// Decrypt a message using Kyber1024
pub fn decrypt_message(sk: &SecretKey, ciphertext: &Ciphertext) -> SharedSecret {
    kyber1024::decapsulate(ciphertext, sk)
}
