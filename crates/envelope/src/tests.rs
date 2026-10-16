//! Known-answer vectors, round trips and refusals.

use crate::stream::{Fresh, Padding, decrypt, encrypt_with};
use crate::*;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::ops::ControlFlow;

/// Copied byte for byte from `forgesworn/wildbloom` `test-vectors/`.
const PER_FILE: &[u8] = include_bytes!("../tests/fixtures/fswnenc2-per-file.json");
const VAULT: &[u8] = include_bytes!("../tests/fixtures/fswnenc2-vault.json");
const PER_FILE_SHA256: &str = "20bca2117ed63e02d417ef0fa2a7be694a5f9e3bd6a5eff6d8f39b8d8b39aa4d";
const VAULT_SHA256: &str = "d54a7226948c35ffbb9f8a3e72b817aa8cce690f049a2c298f6f0481bdf0e06d";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn counting(from: u8) -> InputKey {
    InputKey::from_bytes(std::array::from_fn(|i| from.wrapping_add(i as u8)))
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn go() -> impl FnMut(u64, u64) -> ControlFlow<()> {
    |_, _| ControlFlow::Continue(())
}

fn open(key: &InputKey, envelope: &[u8]) -> Result<(Metadata, Vec<u8>), Error> {
    open_bytes(key, envelope, Limits::BROWSER).map(|(m, b)| (m, b.to_vec()))
}

fn seal(key: &InputKey, name: &str, media_type: &str, bytes: &[u8]) -> Vec<u8> {
    seal_bytes(key, name, media_type, bytes, Limits::BROWSER).unwrap()
}

fn check_vector(fixture: &[u8], fixture_sha256: &str, mode: &str) {
    assert_eq!(
        sha256_hex(fixture),
        fixture_sha256,
        "fixture is not the frozen file"
    );
    let v: serde_json::Value = serde_json::from_slice(fixture).unwrap();
    let s = |k: &str| v[k].as_str().unwrap().to_string();
    assert_eq!(s("magic"), "FSWNENC2");
    assert_eq!(s("scheme"), SCHEME);
    assert_eq!(s("mode"), mode);
    assert_eq!(s("hkdfInfo").as_bytes(), HKDF_INFO);
    assert_eq!(HKDF_INFO.len(), 33);

    let key = InputKey::from_bytes(hex_array(&s("testOnlyInputKeyHex")));
    let salt: [u8; 32] = hex_array(&s("saltHex"));
    let nonce_prefix: [u8; 8] = hex_array(&s("noncePrefixHex"));
    assert_eq!(
        hex::encode(*derive_envelope_key(&key, &salt)),
        s("testOnlyDerivedKeyHex")
    );

    let expected = base64::engine::general_purpose::STANDARD
        .decode(s("envelopeBase64"))
        .unwrap();
    assert_eq!(expected.len() as u64, v["envelopeBytes"].as_u64().unwrap());
    assert_eq!(sha256_hex(&expected), s("envelopeSha256"));

    let source = v["source"]["utf8"].as_str().unwrap().as_bytes();
    assert_eq!(sha256_hex(source), v["source"]["sha256"].as_str().unwrap());
    let name = v["source"]["name"].as_str().unwrap();
    let media_type = v["source"]["type"].as_str().unwrap();

    // The streaming encoder reproduces the frozen bytes exactly.
    let mut out = Vec::new();
    let sealed = encrypt_with(
        &key,
        source,
        source.len() as u64,
        name,
        media_type,
        Limits::BROWSER,
        Fresh {
            nonce_prefix,
            salt,
            padding: Padding::KnownAnswer,
        },
        &mut out,
        &mut go(),
    )
    .unwrap();
    assert_eq!(hex::encode(&out[..HEADER_BYTES]), s("headerHex"));
    assert_eq!(out, expected, "envelope bytes");
    assert_eq!(hex::encode(sealed.sha256), s("envelopeSha256"));
    assert_eq!(sealed.envelope_bytes, expected.len() as u64);
    assert_eq!(
        envelope_bytes(name, media_type, source.len() as u64).unwrap(),
        expected.len() as u64
    );
    let record = &v["records"][0];
    assert_eq!(
        hex::encode(&out[out.len() - TAG_BYTES..]),
        record["authenticationTagHex"].as_str().unwrap()
    );
    assert_eq!(
        serde_json::to_string(&sealed.metadata).unwrap(),
        v["metadata"]["canonicalUtf8"].as_str().unwrap()
    );

    // The streaming decoder opens the frozen bytes.
    let (metadata, plaintext) = open(&key, &expected).unwrap();
    assert_eq!(plaintext, source);
    assert_eq!(metadata.name, name);
    assert_eq!(metadata.media_type, media_type);
    assert_eq!(metadata.size, source.len() as u64);
}

#[test]
fn per_file_vector() {
    check_vector(PER_FILE, PER_FILE_SHA256, "per-file");
}

#[test]
fn vault_vector() {
    check_vector(VAULT, VAULT_SHA256, "vault");
}

#[test]
fn the_two_modes_differ_only_in_the_input_key() {
    let decode = |fixture: &[u8]| {
        let v: serde_json::Value = serde_json::from_slice(fixture).unwrap();
        base64::engine::general_purpose::STANDARD
            .decode(v["envelopeBase64"].as_str().unwrap())
            .unwrap()
    };
    let per_file = decode(PER_FILE);
    let vault = decode(VAULT);
    assert_eq!(per_file[..HEADER_BYTES], vault[..HEADER_BYTES]);
    assert_ne!(per_file, vault);
    assert!(matches!(
        open(&counting(0x40), &per_file),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        open(&counting(0), &vault),
        Err(Error::Authentication)
    ));
}

#[test]
fn every_envelope_draws_a_fresh_salt_and_nonce_prefix() {
    let key = counting(0x40);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let envelope = seal(&key, "item", "text/plain", b"x");
        assert!(
            seen.insert(envelope[16..56].to_vec()),
            "salt or prefix reused"
        );
    }
}

#[test]
fn round_trips_across_record_boundaries_through_private_temp_files() {
    let work = tempfile::tempdir().unwrap();
    let temp_dir = work.path().join("private");
    let key = InputKey::random().unwrap();
    for size in [0usize, 1, 65_000, 1_048_576, 1_048_577, 2_200_000] {
        let source_path = work.path().join(format!("source-{size}"));
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(&source_path, &bytes).unwrap();

        let mut calls = 0;
        let (sealed, envelope) = encrypt_file_to_private_temp(
            &key,
            &source_path,
            "holiday/photos.zip",
            "Application/Zip",
            Limits::BROWSER,
            &temp_dir,
            &mut |done, total| {
                calls += 1;
                assert!(done <= total);
                ControlFlow::Continue(())
            },
        )
        .unwrap();
        assert!(calls >= 1);
        let on_disk = std::fs::read(envelope.path()).unwrap();
        assert_eq!(on_disk.len() as u64, sealed.envelope_bytes);
        assert_eq!(Sha256::digest(&on_disk).as_slice(), sealed.sha256);
        assert_eq!(sealed.metadata.name, "photos.zip");
        assert_eq!(sealed.metadata.media_type, "application/zip");
        assert_eq!(
            envelope_bytes("photos.zip", "application/zip", size as u64).unwrap(),
            sealed.envelope_bytes
        );

        let (metadata, plain) = decrypt_file_to_private_temp(
            &key,
            envelope.path(),
            Limits::BROWSER,
            &temp_dir,
            &mut go(),
        )
        .unwrap();
        assert_eq!(metadata, sealed.metadata);
        assert_eq!(std::fs::read(plain.path()).unwrap(), bytes, "size {size}");
    }
}

#[cfg(unix)]
#[test]
fn temp_files_are_private_and_a_broad_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let work = tempfile::tempdir().unwrap();
    let source = work.path().join("source");
    std::fs::write(&source, b"bytes").unwrap();
    let dir = work.path().join("private");
    let key = counting(1);
    let (_, envelope) =
        encrypt_file_to_private_temp(&key, &source, "s", "", Limits::BROWSER, &dir, &mut go())
            .unwrap();
    let mode = std::fs::metadata(envelope.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "temp file mode {mode:o}");
    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o077, 0, "temp dir mode {dir_mode:o}");

    let broad = work.path().join("broad");
    std::fs::create_dir(&broad).unwrap();
    std::fs::set_permissions(&broad, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        encrypt_file_to_private_temp(&key, &source, "s", "", Limits::BROWSER, &broad, &mut go()),
        Err(Error::PrivateState(_))
    ));
}

#[test]
fn a_failed_decryption_leaves_no_plaintext_behind() {
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("private");
    let key = counting(2);
    // Two records: the first authenticates and is written, the second fails.
    let mut envelope = seal(&key, "big.bin", "", &vec![7u8; 1_200_000]);
    let last = envelope.len() - 1;
    envelope[last] ^= 1;
    let path = work.path().join("envelope");
    std::fs::write(&path, &envelope).unwrap();
    let result = decrypt_file_to_private_temp(&key, &path, Limits::BROWSER, &dir, &mut go());
    assert!(matches!(result, Err(Error::Authentication)));
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "temp file left"
    );
}

#[test]
fn a_wrong_key_is_refused() {
    let envelope = seal(&counting(1), "item", "text/plain", b"secret");
    assert!(matches!(
        open(&counting(2), &envelope),
        Err(Error::Authentication)
    ));
}

#[test]
fn modified_bytes_anywhere_are_refused() {
    let key = counting(5);
    let envelope = seal(&key, "item", "text/plain", b"secret");
    // Nonce prefix, both ends of the salt, a ciphertext byte, the tag.
    for at in [16usize, 23, 24, 55, 56, 1000, envelope.len() - 1] {
        let mut tampered = envelope.clone();
        tampered[at] ^= 0x01;
        assert!(
            matches!(open(&key, &tampered), Err(Error::Authentication)),
            "byte {at}"
        );
    }
}

#[test]
fn header_fields_are_range_checked() {
    let key = counting(6);
    let envelope = seal(&key, "item", "text/plain", b"secret");
    let mut chunk = envelope.clone();
    chunk[10] ^= 0x01;
    assert!(matches!(open(&key, &chunk), Err(Error::Header)));
    let mut zero = envelope.clone();
    zero[12..16].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(open(&key, &zero), Err(Error::Header)));
    let mut many = envelope.clone();
    many[12..16].copy_from_slice(&258u32.to_be_bytes());
    assert!(matches!(open(&key, &many), Err(Error::Header)));
    // A count of two with one record's bytes is a length error, before any tag.
    let mut two = envelope.clone();
    two[12..16].copy_from_slice(&2u32.to_be_bytes());
    assert!(matches!(open(&key, &two), Err(Error::Length)));
}

#[test]
fn other_magics_are_refused() {
    let key = counting(7);
    let envelope = seal(&key, "item", "text/plain", b"secret");
    for magic in [b"FSWNENC1", b"WBLMENC1", b"STSH\x02\0\0\0"] {
        let mut relabelled = envelope.clone();
        relabelled[..8].copy_from_slice(magic);
        assert!(matches!(open(&key, &relabelled), Err(Error::Magic)));
    }
}

#[test]
fn truncated_and_over_long_envelopes_are_refused() {
    let key = counting(9);
    let envelope = seal(&key, "item", "text/plain", b"secret");
    for cut in [0, 7, 8, 40, 56, 57, envelope.len() - 1] {
        assert!(
            matches!(
                open(&key, &envelope[..cut]),
                Err(Error::Length | Error::Magic | Error::Authentication)
            ),
            "cut {cut}"
        );
    }
    // One byte over still fits the header's one-record bound, so the shifted
    // tag fails: the published length-or-authentication class.
    let mut long = envelope.clone();
    long.push(0);
    assert!(matches!(open(&key, &long), Err(Error::Authentication)));
    // A reader that holds more than the declared length is also refused.
    let mut out = Vec::new();
    let result = decrypt(
        &key,
        Cursor::new(&long),
        envelope.len() as u64,
        Limits::BROWSER,
        &mut out,
        &mut go(),
    );
    assert!(matches!(result, Err(Error::Length)));
}

#[test]
fn reordered_records_are_refused() {
    let key = counting(8);
    let envelope = seal(&key, "item", "", &vec![9u8; 1_200_000]);
    let r0 = HEADER_BYTES..HEADER_BYTES + CHUNK_BYTES + TAG_BYTES;
    let r1 = r0.end..envelope.len();
    assert_eq!(r0.len(), r1.len());
    let mut swapped = envelope[..HEADER_BYTES].to_vec();
    swapped.extend_from_slice(&envelope[r1]);
    swapped.extend_from_slice(&envelope[r0]);
    assert!(matches!(open(&key, &swapped), Err(Error::Authentication)));
}

#[test]
fn the_name_and_type_stay_inside_the_ciphertext() {
    let envelope = seal(
        &counting(2),
        "my-private-world.dat",
        "application/x-secret",
        b"b",
    );
    let haystack = String::from_utf8_lossy(&envelope);
    assert!(!haystack.contains("my-private-world"));
    assert!(!haystack.contains("x-secret"));
}

#[test]
fn small_sources_share_the_64_kib_bucket() {
    let key = counting(7);
    let a = seal(&key, "a", "", b"x");
    let b = seal(&key, "b", "", &vec![0u8; 40_000]);
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len() as u64, MIN_ENVELOPE_BYTES);
}

#[test]
fn a_source_that_changes_length_is_refused() {
    let key = counting(3);
    let mut out = Vec::new();
    let short = encrypt(
        &key,
        &b"abc"[..],
        4,
        "s",
        "",
        Limits::BROWSER,
        &mut out,
        &mut go(),
    );
    assert!(matches!(short, Err(Error::SourceChanged)));
    let mut out = Vec::new();
    let long = encrypt(
        &key,
        &b"abcde"[..],
        4,
        "s",
        "",
        Limits::BROWSER,
        &mut out,
        &mut go(),
    );
    assert!(matches!(long, Err(Error::SourceChanged)));
}

#[test]
fn limits_bound_both_directions() {
    let key = counting(4);
    let small = Limits::new(10);
    let mut out = Vec::new();
    let refused = encrypt(
        &key,
        &[0u8; 11][..],
        11,
        "s",
        "",
        small,
        &mut out,
        &mut go(),
    );
    assert!(matches!(refused, Err(Error::TooLarge)));
    let envelope = seal(&key, "s", "", &[0u8; 11]);
    assert!(matches!(
        open_bytes(&key, &envelope, small),
        Err(Error::TooLarge)
    ));
    // A large drop limit lifts the record ceiling with it.
    assert_eq!(Limits::new(1024 * 1024 * 1024).max_records(), 1025);
}

#[test]
fn progress_can_cancel() {
    let key = counting(4);
    let mut out = Vec::new();
    let result = encrypt(
        &key,
        &[0u8; 5][..],
        5,
        "s",
        "",
        Limits::BROWSER,
        &mut out,
        &mut |_, _| ControlFlow::Break(()),
    );
    assert!(matches!(result, Err(Error::Cancelled)));
}

/// Seals arbitrary authenticated logical plaintext, computed independently of
/// the crate's own record loop, so semantic checks are reached past the AEAD.
fn authenticated(key: &InputKey, logical: &[u8]) -> Vec<u8> {
    assert!(logical.len() <= CHUNK_BYTES);
    let prefix = [0x31u8; 8];
    let salt = [0x42u8; 32];
    let mut header = b"FSWNENC2".to_vec();
    header.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    header.extend_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&prefix);
    header.extend_from_slice(&salt);
    let mut aad = header.clone();
    aad.extend_from_slice(&0u32.to_be_bytes());
    let mut nonce = prefix.to_vec();
    nonce.extend_from_slice(&0u32.to_be_bytes());
    let derived = derive_envelope_key(key, &salt);
    let mut ciphertext = logical.to_vec();
    let tag = Aes256Gcm::new_from_slice(derived.as_ref())
        .unwrap()
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ciphertext)
        .unwrap();
    header.extend_from_slice(&ciphertext);
    header.extend_from_slice(&tag);
    header
}

fn logical(json: &str, source: &[u8], padded: usize) -> Vec<u8> {
    let mut out = (json.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(json.as_bytes());
    out.extend_from_slice(source);
    out.resize(padded, 0);
    out
}

#[test]
fn the_independent_builder_agrees_with_the_crate() {
    let key = counting(0x11);
    let json = r#"{"name":"item","size":5,"type":"text/plain"}"#;
    let envelope = authenticated(&key, &logical(json, b"bytes", MIN_PADDING_BUCKET));
    let (metadata, bytes) = open(&key, &envelope).unwrap();
    assert_eq!(metadata.name, "item");
    assert_eq!(bytes, b"bytes");
}

#[test]
fn non_canonical_metadata_is_refused_after_authentication() {
    let key = counting(0x11);
    for json in [
        r#"{"size":5,"name":"item","type":"text/plain"}"#,
        r#"{"name":"item", "size":5,"type":"text/plain"}"#,
        r#"{"name":"item","size":5,"type":"text/plain","x":1}"#,
        r#"{"name":"item","size":5}"#,
        r#"{"name":"\u0069tem","size":5,"type":"text/plain"}"#,
        r#"{"name":"item","size":5.0,"type":"text/plain"}"#,
        r#"{"name":"item","size":05,"type":"text/plain"}"#,
        r#"{"name":"item","name":"item","size":5,"type":"text/plain"}"#,
        r#"{"name":".item","size":5,"type":"text/plain"}"#,
        r#"{"name":"","size":5,"type":"text/plain"}"#,
        r#"{"name":"cafe\u0301","size":5,"type":"text/plain"}"#,
        r#"{"name":"item","size":5,"type":"Text/Plain"}"#,
        r#"{"name":"item","size":5,"type":""}"#,
        "[]",
    ] {
        let envelope = authenticated(&key, &logical(json, b"bytes", MIN_PADDING_BUCKET));
        assert!(
            matches!(open(&key, &envelope), Err(Error::Metadata(_))),
            "{json}"
        );
    }
    // A literal non-NFC name (not escaped) is refused as a non-fixed-point too.
    let json = "{\"name\":\"cafe\u{301}\",\"size\":5,\"type\":\"text/plain\"}";
    let envelope = authenticated(&key, &logical(json, b"bytes", MIN_PADDING_BUCKET));
    assert!(matches!(
        open(&key, &envelope),
        Err(Error::Metadata("name"))
    ));
}

#[test]
fn the_wrong_padding_bucket_is_refused() {
    let key = counting(0x12);
    let json = r#"{"name":"item","size":5,"type":"text/plain"}"#;
    // 128 KiB of plaintext for a source whose bucket is 64 KiB.
    let envelope = authenticated(&key, &logical(json, b"bytes", 2 * MIN_PADDING_BUCKET));
    assert!(matches!(open(&key, &envelope), Err(Error::Padding)));
    // A declared size larger than the bytes present.
    let json = r#"{"name":"item","size":70000,"type":"text/plain"}"#;
    let envelope = authenticated(&key, &logical(json, b"bytes", MIN_PADDING_BUCKET));
    assert!(matches!(open(&key, &envelope), Err(Error::Padding)));
}

#[test]
fn an_authenticated_oversized_size_is_refused_without_panicking() {
    let key = counting(0x13);
    for size in [u64::MAX, u64::MAX - 8192] {
        let json = format!(r#"{{"name":"item","size":{size},"type":"text/plain"}}"#);
        let envelope = authenticated(&key, &logical(&json, b"", MIN_PADDING_BUCKET));
        assert!(matches!(open(&key, &envelope), Err(Error::Padding)));
    }
}

#[test]
fn metadata_length_is_bounded() {
    let key = counting(0x14);
    for length in [0u32, 1, 4097, 70_000] {
        let mut logical = length.to_be_bytes().to_vec();
        logical.resize(MIN_PADDING_BUCKET, b' ');
        let envelope = authenticated(&key, &logical);
        assert!(
            matches!(open(&key, &envelope), Err(Error::Metadata("length"))),
            "{length}"
        );
    }
    // The longest legal name and type still fit well under 4096 bytes.
    let longest = seal(&key, &"\u{10000}".repeat(400), &"b".repeat(255), b"");
    assert_eq!(
        open(&key, &longest).unwrap().0.name.encode_utf16().count(),
        180
    );
}
