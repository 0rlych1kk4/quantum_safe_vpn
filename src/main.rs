mod quantum_crypto;
mod secure_comm;
mod vpn_core;
mod config;
mod utils;

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use quantum_crypto::{generate_keys, encrypt_message, decrypt_message};
use pqcrypto_kyber::kyber1024::Ciphertext;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Quantum-Safe VPN is running on port 8080");

    // Generate a quantum-safe key pair
    let (server_public_key, server_secret_key) = generate_keys();

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("Connection from: {}", addr);

        let server_pk = server_public_key.clone();
        let server_sk = server_secret_key.clone();

        tokio::spawn(async move {
            let mut buf = [0; 1024];
            match socket.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    println!("Received handshake request: {:?}", &buf[..n]);

                    // Perform Quantum-Safe Key Exchange
                    let (ciphertext, shared_secret_enc) = encrypt_message(&server_pk);
                    let shared_secret_dec = decrypt_message(&server_sk, &ciphertext);

                    // Ensure the shared secret matches
                    if shared_secret_enc.as_bytes() == shared_secret_dec.as_bytes() {
                        println!("Quantum-Safe Key Exchange Successful");
                        socket.write_all(b"Secure Connection Established").await.ok();
                    } else {
                        println!("Key Exchange Failed");
                        socket.write_all(b"Key Exchange Failed").await.ok();
                    }
                }
                _ => {}
            }
        });
    }
}
