//! Import an owner-signed private browser pool receipt without changing custody.
//! Nodes store ordinary blobs. Only the owner client reconstructs coded files.
use std::collections::BTreeSet;

use nostr::prelude::UnsignedEvent;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{Error, policy, transport::Profile};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Node {
    pub(super) id: String,
    pub(super) origin: String,
    pub(super) failure_group: String,
    pub(super) weight: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Part {
    pub(super) index: usize,
    pub(super) sha256: String,
    pub(super) size: u64,
    pub(super) targets: Vec<Node>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    pub(super) sha256: String,
    pub(super) size: u64,
    pub(super) encryption: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    #[serde(rename = "type")]
    pub(super) manifest_type: String,
    pub(super) version: u8,
    pub(super) mode: String,
    pub(super) profile: String,
    pub(super) payload: Payload,
    pub(super) required: usize,
    pub(super) total: usize,
    pub(super) copies: u8,
    pub(super) parts: Vec<Part>,
}

#[derive(Serialize)]
pub struct Templates {
    receipt_id: String,
    mode: String,
    required_parts: usize,
    total_parts: usize,
    /// Always false: mirror maintenance never collects other coded parts.
    reconstructs_ciphertext: bool,
    /// A receipt is intent. No storage observation is made by this command.
    storage_verified: bool,
    unsigned_policies: Vec<UnsignedEvent>,
}

fn invalid() -> Error {
    Error::Configuration("invalid pool receipt, placement or transport profile")
}

/// Produce exact unsigned maintenance policies for an external signer. This
/// function never contacts a node/signer or modifies coordinator state.
pub fn templates(
    bytes: &[u8],
    owner: &str,
    revision: u64,
    expires_at: u64,
    now: u64,
    permit_loopback: bool,
) -> Result<Templates, Error> {
    let event = policy::signed_event(bytes, owner, 128 * 1024)?;
    let manifest: Manifest = serde_json::from_str(&event.content).map_err(|_| invalid())?;
    let erasure = manifest.mode == "erasure";
    if event.kind.as_u16() != 30078
        || event.created_at.as_secs() > now
        || manifest.manifest_type != "wildbloom.pool"
        || manifest.version != 1
        || !policy::canonical_hex(&manifest.payload.sha256, 32)
        || manifest.payload.encryption != "forgesworn-aes-256-gcm-chunked-v2"
        || manifest.payload.size == 0
        || manifest.payload.size > 258 * 1024 * 1024
        || manifest.required == 0
        || manifest.total > 16
        || manifest.parts.len() != manifest.total
        || revision == 0
        || expires_at <= now
        || expires_at - now > 365 * 86_400
    {
        return Err(invalid());
    }
    if erasure {
        if manifest.required < 2
            || manifest.required >= manifest.total
            || manifest.copies != 1
            || manifest.payload.size < manifest.required as u64
        {
            return Err(invalid());
        }
    } else if manifest.mode != "replicas"
        || manifest.required != 1
        || manifest.total != 1
        || !(2..=3).contains(&manifest.copies)
    {
        return Err(invalid());
    }
    let expected_tag = vec![
        "d".to_owned(),
        format!("wildbloom.pool.v1:{}", manifest.payload.sha256),
    ];
    if event.tags.len() != 1
        || event.tags.iter().next().map(|tag| tag.as_slice()) != Some(expected_tag.as_slice())
    {
        return Err(invalid());
    }
    let profile = match manifest.profile.as_str() {
        "tor" if !permit_loopback => Profile::TorOnly,
        "direct" if permit_loopback => Profile::LoopbackDevelopment,
        "direct" => Profile::DirectHttps,
        _ => return Err(invalid()),
    };
    let mut ids = BTreeSet::new();
    let mut origins = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut assigned_groups = BTreeSet::new();
    let mut policies = Vec::new();
    for (index, part) in manifest.parts.iter().enumerate() {
        if part.index != index
            || !policy::canonical_hex(&part.sha256, 32)
            || part.size != manifest.payload.size.div_ceil(manifest.required as u64)
            || (!erasure && part.sha256 != manifest.payload.sha256)
            || part.targets.is_empty()
        {
            return Err(invalid());
        }
        let mut groups = BTreeSet::new();
        let mut targets = Vec::new();
        for node in &part.targets {
            let url = Url::parse(&node.origin).map_err(|_| invalid())?;
            let host = if permit_loopback {
                node.origin.clone()
            } else {
                url.host_str().ok_or_else(invalid)?.to_owned()
            };
            if !policy::identifier(&node.id)
                || node.id.len() > 40
                || !policy::identifier(&node.failure_group)
                || node.failure_group.len() > 40
                || !(1..=1000).contains(&node.weight)
                || node.origin.len() > 256
                || url.as_str() != node.origin
                || !profile.accepts(&url)
                || !ids.insert(node.id.clone())
                || !origins.insert(node.origin.clone())
                || !hosts.insert(host)
                || ids.len() > 16
                || assigned_groups.contains(&node.failure_group)
            {
                return Err(invalid());
            }
            groups.insert(node.failure_group.clone());
            targets.push(policy::Target {
                id: node.id.clone(),
                origin: node.origin.clone(),
                failure_group: node.failure_group.clone(),
                retention: policy::Retention::Owner,
            });
        }
        assigned_groups.extend(groups);
        let content = policy::Policy {
            policy_type: "wildbloom.replica-policy".to_owned(),
            version: 1,
            id: format!("pool-{}-{index}", &event.id.to_hex()[..40]),
            revision,
            expires_at,
            profile,
            desired_groups: manifest.copies,
            targets,
            blobs: vec![policy::Blob {
                sha256: part.sha256.clone(),
                size: part.size,
            }],
        };
        policies.push(policy::policy_template(content, owner, now)?);
    }
    Ok(Templates {
        receipt_id: event.id.to_hex(),
        mode: manifest.mode,
        required_parts: manifest.required,
        total_parts: manifest.total,
        reconstructs_ciphertext: false,
        storage_verified: false,
        unsigned_policies: policies,
    })
}

/// Reuse the exact importer validation before granting owner-side reconstruction.
pub(super) fn receipt(
    bytes: &[u8],
    owner: &str,
    expected_id: &str,
    now: u64,
    permit_loopback: bool,
) -> Result<(Manifest, Profile), Error> {
    let validated = templates(
        bytes,
        owner,
        1,
        now.saturating_add(3600),
        now,
        permit_loopback,
    )?;
    if validated.receipt_id != expected_id {
        return Err(invalid());
    }
    let event = policy::signed_event(bytes, owner, 128 * 1024)?;
    let manifest: Manifest = serde_json::from_str(&event.content).map_err(|_| invalid())?;
    let profile = if permit_loopback {
        Profile::LoopbackDevelopment
    } else if manifest.profile == "tor" {
        Profile::TorOnly
    } else {
        Profile::DirectHttps
    };
    Ok((manifest, profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::*;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;
    fn fixture() -> (Keys, serde_json::Value) {
        let keys = Keys::generate();
        let manifest = json!({"type":"wildbloom.pool", "version":1, "mode":"erasure", "profile":"direct",
            "payload":{"sha256":"ab".repeat(32), "size":101, "encryption":"forgesworn-aes-256-gcm-chunked-v2"},
            "required":2, "total":4, "copies":1,
            "parts":(0..4).map(|i| json!({"index":i, "sha256":format!("{i:064x}"), "size":51,
                "targets":[{"id":format!("node-{i}"), "origin":format!("https://n{i}.example/"), "failure_group":format!("site-{i}"), "weight":1}]})).collect::<Vec<_>>()});
        (keys, manifest)
    }
    fn signed(keys: &Keys, manifest: &serde_json::Value) -> Vec<u8> {
        EventBuilder::new(Kind::from(30078), manifest.to_string())
            .tag(Tag::identifier(format!(
                "wildbloom.pool.v1:{}",
                manifest["payload"]["sha256"].as_str().unwrap()
            )))
            .custom_created_at(Timestamp::from(NOW - 1))
            .finalize(keys)
            .unwrap()
            .as_json()
            .into_bytes()
    }
    #[test]
    fn produces_isolated_part_policies_without_reconstruction_or_storage_claims() {
        let (keys, manifest) = fixture();
        let output = templates(
            &signed(&keys, &manifest),
            &keys.public_key().to_hex(),
            1,
            NOW + 3600,
            NOW,
            false,
        )
        .unwrap();
        assert!(!output.reconstructs_ciphertext && !output.storage_verified);
        assert_eq!(output.unsigned_policies.len(), 4);
        for (i, unsigned) in output.unsigned_policies.iter().enumerate() {
            let p: policy::Policy = serde_json::from_str(&unsigned.content).unwrap();
            assert_eq!(p.targets.len(), 1);
            assert_eq!(p.blobs[0].sha256, format!("{i:064x}"));
            assert_eq!(p.desired_groups, 1);
            p.validate().unwrap();
        }
    }
    #[test]
    fn refuses_shared_groups_malformed_coding_wrong_owner_and_profile() {
        let (keys, original) = fixture();
        let owner = keys.public_key().to_hex();
        for field in ["required", "total", "copies", "version"] {
            let mut m = original.clone();
            m[field] = json!(0);
            assert!(templates(&signed(&keys, &m), &owner, 1, NOW + 3600, NOW, false).is_err());
        }
        let mut m = original.clone();
        m["parts"][1]["targets"][0]["failure_group"] = json!("site-0");
        assert!(templates(&signed(&keys, &m), &owner, 1, NOW + 3600, NOW, false).is_err());
        let bytes = signed(&keys, &original);
        assert!(templates(&bytes, &owner, 1, NOW + 3600, NOW, true).is_err());
        assert!(
            templates(
                &bytes,
                &Keys::generate().public_key().to_hex(),
                1,
                NOW + 3600,
                NOW,
                false
            )
            .is_err()
        );
        assert!(templates(&bytes, &owner, 0, NOW + 3600, NOW, false).is_err());
        assert!(templates(&bytes, &owner, 1, NOW, NOW, false).is_err());
    }
}
