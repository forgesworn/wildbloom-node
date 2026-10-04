//! Disk-backed implementation of the browser's version-1 GF(256) contract.
//! Only the explicitly selected owner repair process calls this module.
use super::{Error, pool::Manifest, state::StateError};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
type Matrix = Vec<Vec<u8>>;
const STRIPE: usize = 64 * 1024;
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        a = (a << 1) ^ if a & 128 != 0 { 0x1d } else { 0 };
        b >>= 1;
    }
    out
}
fn power(a: u8, n: usize) -> u8 {
    (0..n).fold(1, |v, _| mul(v, a))
}
fn invert(matrix: &Matrix) -> Result<Matrix, Error> {
    let n = matrix.len();
    let mut work: Matrix = matrix
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let mut result = row.clone();
            result.extend((0..n).map(|c| u8::from(r == c)));
            result
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n)
            .find(|r| work[*r][col] != 0)
            .ok_or(Error::Internal)?;
        work.swap(col, pivot);
        let scale = power(work[col][col], 254);
        for v in &mut work[col] {
            *v = mul(*v, scale);
        }
        let pivot_row = work[col].clone();
        for (r, row) in work.iter_mut().enumerate() {
            if r == col {
                continue;
            }
            let factor = row[col];
            for (value, pivot_value) in row.iter_mut().zip(&pivot_row) {
                *value ^= mul(factor, *pivot_value);
            }
        }
    }
    Ok(work.into_iter().map(|row| row[n..].to_vec()).collect())
}
fn product(a: &Matrix, b: &Matrix) -> Matrix {
    a.iter()
        .map(|row| {
            (0..b[0].len())
                .map(|c| {
                    row.iter()
                        .enumerate()
                        .fold(0, |s, (i, v)| s ^ mul(*v, b[i][c]))
                })
                .collect()
        })
        .collect()
}
fn generator(k: usize, n: usize) -> Result<Matrix, Error> {
    if k < 2 || k >= n || n > 16 {
        return Err(Error::Internal);
    }
    let v: Matrix = (0..n)
        .map(|r| (0..k).map(|c| power(r as u8, c)).collect())
        .collect();
    Ok(product(&v, &invert(&v[..k].to_vec())?))
}
fn combine(row: &[u8], inputs: &[Vec<u8>], count: usize) -> Vec<u8> {
    let mut out = vec![0; count];
    for (coefficient, input) in row.iter().zip(inputs) {
        if *coefficient == 0 {
            continue;
        }
        // One small multiplication table per coefficient, outside the byte loop.
        let table: Vec<u8> = (0..=255).map(|b| mul(*coefficient, b)).collect();
        for (dst, src) in out.iter_mut().zip(input) {
            *dst ^= table[*src as usize];
        }
    }
    out
}
fn io<T>(value: std::io::Result<T>) -> Result<T, Error> {
    value.map_err(|_| StateError::Io.into())
}

/// Regenerate all parts directly from k verified files. No full envelope is
/// buffered. The systematic output is hashed in order before any upload.
pub(super) async fn regenerate(
    manifest: &Manifest,
    sources: &[(usize, std::path::PathBuf)],
    root: &Path,
) -> Result<Vec<std::path::PathBuf>, Error> {
    let k = manifest.required;
    if sources.len() != k {
        return Err(Error::Internal);
    }
    let matrix = generator(k, manifest.total)?;
    let decode = invert(&sources.iter().map(|(i, _)| matrix[*i].clone()).collect())?;
    let transform = product(&matrix, &decode);
    let mut readers: Vec<File> = sources
        .iter()
        .map(|(_, p)| io(File::open(p)))
        .collect::<Result<_, _>>()?;
    let paths: Vec<_> = (0..manifest.total)
        .map(|i| root.join(format!("coded-{i}")))
        .collect();
    let mut writers: Vec<_> = paths
        .iter()
        .map(|p| {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            io(opts.open(p))
        })
        .collect::<Result<_, _>>()?;
    let size = manifest.parts[0].size;
    let mut hashes = vec![Sha256::new(); manifest.total];
    let mut offset = 0;
    while offset < size {
        tokio::task::yield_now().await;
        let count = STRIPE.min((size - offset) as usize);
        let mut inputs = vec![vec![0; count]; k];
        for (reader, input) in readers.iter_mut().zip(&mut inputs) {
            io(reader.read_exact(input))?;
        }
        for i in 0..manifest.total {
            let bytes = combine(&transform[i], &inputs, count);
            hashes[i].update(&bytes);
            io(writers[i].write_all(&bytes))?;
        }
        offset += count as u64;
    }
    drop(writers);
    for (hash, part) in hashes.into_iter().zip(&manifest.parts) {
        if hex::encode(hash.finalize()) != part.sha256 {
            return Err(Error::Configuration(
                "regenerated part hash differs from signed receipt",
            ));
        }
    }
    let mut payload = Sha256::new();
    let mut remaining = manifest.payload.size;
    let mut header = Vec::new();
    for path in paths.iter().take(k) {
        let mut file = io(File::open(path))?;
        let mut bytes = vec![0; STRIPE];
        let mut left = size.min(remaining);
        while left > 0 {
            tokio::task::yield_now().await;
            let count = STRIPE.min(left as usize);
            io(file.read_exact(&mut bytes[..count]))?;
            if header.len() < 8 {
                header.extend_from_slice(&bytes[..count.min(8 - header.len())]);
            }
            payload.update(&bytes[..count]);
            left -= count as u64;
            remaining -= count as u64;
        }
    }
    if remaining != 0
        || hex::encode(payload.finalize()) != manifest.payload.sha256
        || header != b"FSWNENC2"
    {
        return Err(Error::Configuration(
            "reconstructed ciphertext does not match signed encrypted payload",
        ));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disk_reconstruction_crosses_stripes_and_rejects_bad_signed_hashes() {
        let root = tempfile::tempdir().unwrap();
        let mut payload = b"FSWNENC2".to_vec();
        payload.extend((0..393_217).map(|i| (i % 251) as u8));
        let size = payload.len().div_ceil(3);
        let inputs: Vec<_> = (0..3)
            .map(|i| {
                let mut bytes = payload[i * size..((i + 1) * size).min(payload.len())].to_vec();
                bytes.resize(size, 0);
                bytes
            })
            .collect();
        let encoded: Vec<_> = generator(3, 5)
            .unwrap()
            .iter()
            .map(|row| combine(row, &inputs, size))
            .collect();
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "type":"wildbloom.pool", "version":1, "mode":"erasure", "profile":"direct",
            "payload":{"sha256":hex::encode(Sha256::digest(&payload)), "size":payload.len(), "encryption":"forgesworn-aes-256-gcm-chunked-v2"},
            "required":3,"total":5,"copies":1,
            "parts":encoded.iter().enumerate().map(|(i,bytes)|serde_json::json!({"index":i,"sha256":hex::encode(Sha256::digest(bytes)),"size":size,"targets":[]})).collect::<Vec<_>>()
        })).unwrap();
        let sources: Vec<_> = [4, 0, 3]
            .into_iter()
            .map(|i| {
                let path = root.path().join(format!("input-{i}"));
                std::fs::write(&path, &encoded[i]).unwrap();
                (i, path)
            })
            .collect();
        let out = tempfile::tempdir_in(root.path()).unwrap();
        let files = regenerate(&manifest, &sources, out.path()).await.unwrap();
        for (i, path) in files.iter().enumerate() {
            assert_eq!(std::fs::read(path).unwrap(), encoded[i]);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                    0
                );
            }
        }
        for change_payload in [false, true] {
            let mut bad = manifest.clone();
            if change_payload {
                bad.payload.sha256 = "00".repeat(32);
            } else {
                bad.parts[4].sha256 = "00".repeat(32);
            }
            let out = tempfile::tempdir_in(root.path()).unwrap();
            assert!(regenerate(&bad, &sources, out.path()).await.is_err());
        }
        assert!(
            regenerate(&manifest, &sources[..2], root.path())
                .await
                .is_err()
        );
        std::fs::write(&sources[0].1, b"short").unwrap();
        let out = tempfile::tempdir_in(root.path()).unwrap();
        assert!(regenerate(&manifest, &sources, out.path()).await.is_err());
    }

    #[test]
    fn independent_vector_and_every_threshold_subset() {
        let inputs = vec![vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9, 10, 0]];
        let g = generator(3, 5).unwrap();
        let encoded: Vec<_> = g.iter().map(|row| combine(row, &inputs, 4)).collect();
        assert_eq!(
            encoded,
            vec![
                vec![0, 1, 2, 3],
                vec![4, 5, 6, 7],
                vec![8, 9, 10, 0],
                vec![12, 13, 14, 4],
                vec![16, 17, 18, 41]
            ]
        );
        for (k, n) in [(2, 4), (3, 6), (4, 7), (7, 8), (15, 16)] {
            let g = generator(k, n).unwrap();
            for mask in 0..(1_u32 << n) {
                if mask.count_ones() as usize != k {
                    continue;
                }
                let chosen: Matrix = (0..n)
                    .filter(|i| mask & (1 << i) != 0)
                    .map(|i| g[i].clone())
                    .collect();
                let identity = product(&invert(&chosen).unwrap(), &chosen);
                for (r, row) in identity.iter().enumerate() {
                    for (c, v) in row.iter().enumerate() {
                        assert_eq!(*v, u8::from(r == c));
                    }
                }
            }
        }
    }
}
