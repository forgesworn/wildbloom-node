//! Verify actual updater bytes against the public key pinned in source.
//! Accept Tauri's base64-wrapped minisign signature and plain minisign files.
use base64::{Engine, engine::general_purpose::STANDARD};
use minisign_verify::{PublicKey, Signature};
use std::{error::Error, fs, io::Read, path::Path};

fn unwrap_text(text: &str) -> Result<String, Box<dyn Error>> {
    if text.starts_with("untrusted comment:") {
        Ok(text.to_owned())
    } else {
        Ok(String::from_utf8(STANDARD.decode(text.trim())?)?)
    }
}

fn verify(config: &Path, artifact: &Path, signature: &Path) -> Result<(), Box<dyn Error>> {
    let config: serde_json::Value = serde_json::from_slice(&fs::read(config)?)?;
    let key = config["plugins"]["updater"]["pubkey"]
        .as_str()
        .ok_or("missing public key")?;
    let key = PublicKey::decode(&unwrap_text(key)?)?;
    let signature = Signature::decode(&unwrap_text(&fs::read_to_string(signature)?)?)?;
    let mut verifier = key.verify_stream(&signature)?;
    let mut file = fs::File::open(artifact)?;
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        verifier.update(&buffer[..read]);
    }
    verifier.finalize()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: wildbloom-release-verify <tauri.conf.json> <artifact> <signature>".into(),
        );
    }
    verify(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )?;
    println!("Release signature and artifact bytes verified against the pinned updater key");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_fixture_and_refuses_tampered_bytes_and_wrong_key() {
        // Public synthetic prehashed vector from minisign-verify 0.2.5 (MIT).
        let key = "untrusted comment: synthetic test key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
        let signature = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.json");
        let artifact = temp.path().join("artifact");
        let sig = temp.path().join("artifact.sig");
        fs::write(
            &config,
            serde_json::json!({"plugins":{"updater":{"pubkey":STANDARD.encode(key)}}}).to_string(),
        )
        .unwrap();
        fs::write(&artifact, b"test").unwrap();
        for value in [signature.to_owned(), STANDARD.encode(signature)] {
            fs::write(&sig, value).unwrap();
            verify(&config, &artifact, &sig).unwrap();
        }
        fs::write(&artifact, b"tampered").unwrap();
        assert!(verify(&config, &artifact, &sig).is_err());
        fs::write(&artifact, b"test").unwrap();
        fs::write(&config, serde_json::json!({"plugins":{"updater":{"pubkey":STANDARD.encode(key.replace("RWQf6", "RWQg6"))}}}).to_string()).unwrap();
        assert!(verify(&config, &artifact, &sig).is_err());
    }
    #[test]
    fn accepts_plain_and_tauri_wrapped_text_rejects_invalid_encoding() {
        let text = "untrusted comment: synthetic fixture\nkey\n";
        assert_eq!(unwrap_text(text).unwrap(), text);
        assert_eq!(unwrap_text(&STANDARD.encode(text)).unwrap(), text);
        assert!(unwrap_text("not base64!").is_err());
    }
}
