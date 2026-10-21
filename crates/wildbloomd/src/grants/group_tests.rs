//! Group mode tests.  Synthetic keys, hosts and hashes only.
use super::{
    Enrolment, Grants, GrantsConfig, GrantsError, GroupConfig,
    group::core_group_grant_id,
    group_db::{self, GroupKey},
};
use nostr::prelude::Keys;
use std::{collections::BTreeSet, path::Path, sync::Arc};

const SERVER: &str = "grove.example.net";

fn keys(n: u64) -> String {
    Keys::parse(&format!("{n:064x}"))
        .unwrap()
        .public_key()
        .to_hex()
}

fn open(root: &Path, owners: &[u64], friends: &[u64], reserved: &[u64]) -> Grants {
    std::fs::create_dir_all(root).unwrap();
    Grants::open(
        root,
        GrantsConfig {
            owners: owners.iter().map(|n| keys(*n)).collect(),
            server_names: vec![SERVER.into()],
            origin: format!("https://{SERVER}/"),
            cli_friend_grants: friends
                .iter()
                .map(|n| wildbloom_core::FriendGrant {
                    pubkey: keys(*n),
                    byte_limit: 1024,
                    expires_at: 4_000_000_000,
                    grant_id: format!("local:{n}"),
                    issuer: None,
                })
                .collect(),
            reserved_keys: reserved.iter().map(|n| keys(*n)).collect(),
        },
        Arc::new(|| 1_800_000_000),
    )
    .unwrap()
}

fn enrol(keeper: u64, ceiling: u64) -> Enrolment {
    Enrolment {
        keeper: keys(keeper),
        ceiling,
        rooms: BTreeSet::new(),
    }
}

fn config(enrolments: Vec<Enrolment>) -> GroupConfig {
    GroupConfig { enrolments }
}

#[test]
fn the_state_file_is_private_and_a_group_keys_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let grants = open(&root, &[1], &[], &[]);
    grants
        .enable_group(&root, config(vec![enrol(10, 1 << 30)]))
        .unwrap();
    let path = Grants::group_database_path(&root);
    assert_eq!(path.file_name().unwrap(), "group-grants.sqlite3");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(grants.group_friend_grants().is_empty());
    {
        let state = grants.inner.group.get().unwrap();
        let db = state.db.lock().unwrap();
        group_db::write_key(
            &db,
            &keys(20),
            &GroupKey {
                keeper: keys(10),
                room: "a".repeat(64),
                byte_limit: Some(4096),
            },
        )
        .unwrap();
        group_db::write_key(
            &db,
            &keys(21),
            &GroupKey {
                keeper: keys(10),
                room: "a".repeat(64),
                byte_limit: None,
            },
        )
        .unwrap();
    }
    drop(grants);

    let grants = open(&root, &[1], &[], &[]);
    grants
        .enable_group(&root, config(vec![enrol(10, 1 << 30)]))
        .unwrap();
    // Only a key that ever had an upload grant is a core friend; a read-only
    // member is a group key but holds no claims.
    let friends = grants.core_friend_grants();
    assert_eq!(friends.len(), 1);
    assert_eq!(friends[0].pubkey, keys(20));
    assert_eq!(friends[0].byte_limit, 4096);
    assert_eq!(friends[0].expires_at, super::CORE_GRANT_SENTINEL);
    assert_eq!(
        friends[0].grant_id,
        core_group_grant_id(&keys(10), &"a".repeat(64))
    );
    assert_eq!(friends[0].issuer, Some(keys(10)));
    assert!(grants.group_claims_key(&keys(21)));
    assert!(grants.group_claims_key(&keys(10)));
    assert!(!grants.group_claims_key(&keys(1)));
}

#[test]
fn a_keeper_cannot_also_be_an_owner_friend_service_or_group_key() {
    for (owners, friends, reserved) in [
        (vec![10], vec![], vec![]),
        (vec![1], vec![10], vec![]),
        (vec![1], vec![], vec![10]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let grants = open(&root, &owners, &friends, &reserved);
        assert!(matches!(
            grants.enable_group(&root, config(vec![enrol(10, 1024)])),
            Err(GrantsError::Conflict)
        ));
    }
    // A persisted group device that is now an owner stops the node starting.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let grants = open(&root, &[1], &[], &[]);
    grants
        .enable_group(&root, config(vec![enrol(10, 1024)]))
        .unwrap();
    {
        let state = grants.inner.group.get().unwrap();
        let db = state.db.lock().unwrap();
        group_db::write_key(
            &db,
            &keys(1),
            &GroupKey {
                keeper: keys(10),
                room: "a".repeat(64),
                byte_limit: None,
            },
        )
        .unwrap();
    }
    drop(grants);
    let grants = open(&root, &[1], &[], &[]);
    assert!(matches!(
        grants.enable_group(&root, config(vec![enrol(10, 1024)])),
        Err(GrantsError::Conflict)
    ));
}

#[test]
fn enrolments_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let grants = open(&root, &[1], &[], &[]);
    for bad in [
        config(vec![]),
        config(vec![enrol(10, 0)]),
        config(vec![enrol(10, u64::MAX)]),
        config(vec![enrol(10, 1), enrol(10, 2)]),
        config(vec![Enrolment {
            keeper: "AB".repeat(32),
            ceiling: 1,
            rooms: BTreeSet::new(),
        }]),
        config(vec![Enrolment {
            keeper: keys(10),
            ceiling: 1,
            rooms: BTreeSet::from(["short".to_owned()]),
        }]),
    ] {
        assert!(matches!(
            grants.enable_group(&root, bad),
            Err(GrantsError::Group(_))
        ));
    }
    grants
        .enable_group(&root, config(vec![enrol(10, 1)]))
        .unwrap();
    assert!(matches!(
        grants.enable_group(&root, config(vec![enrol(11, 1)])),
        Err(GrantsError::Group(_))
    ));
}
