//! Disposable test signer, never an operator key store or production signer.
use nostr::prelude::*;
use std::io::{Read, Write};

fn main() {
    const {
        assert!(
            cfg!(debug_assertions),
            "synthetic signer requires a debug build"
        );
    }
    let keys = Keys::new(SecretKey::from_slice(&[37; 32]).unwrap());
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--public-key") {
        println!("{}", keys.public_key().to_hex());
        return;
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 128 * 1024);
    let request: UnsignedEvent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(request.pubkey, keys.public_key());
    let signed = request.finalize(&keys).unwrap();
    if args.get(1).map(String::as_str) == Some("--record") {
        let mut record = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args[2])
            .unwrap();
        record.write_all(b"signed\n").unwrap();
    }
    println!("{}", signed.as_json());
}
