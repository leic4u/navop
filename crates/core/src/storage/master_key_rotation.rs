use anyhow::Result;
use rusqlite::{Transaction, TransactionBehavior, params};

use crate::crypto;

use super::connection::SqliteConnection;
use super::models::re_encrypt_sensitive_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasterKeyRotationStats {
    pub connections: usize,
    pub credentials: usize,
    /// 本地缓存的团队密钥条数（用主密钥加密保存，必须随主密钥一起轮换）
    pub team_key_caches: usize,
    /// 个人同步冲突快照条数（快照里可能携带云端密文记录）
    pub personal_conflicts: usize,
}

struct CredentialSecrets {
    id: i64,
    password: Option<String>,
    private_key_content: Option<String>,
    passphrase: Option<String>,
    ssh_expect: Option<String>,
}

/// 本地团队密钥缓存行：主键为 (cloud_environment, user_id, team_id)
struct TeamKeySecret {
    environment: String,
    user_id: String,
    team_id: String,
    encrypted_team_key: String,
}

/// 个人同步冲突行：主键为 (backend_profile_id, data_type, record_id)
struct PersonalConflictSnapshots {
    backend_profile_id: String,
    data_type: String,
    record_id: String,
    local_snapshot: Option<String>,
    remote_snapshot: Option<String>,
}

pub fn re_encrypt_secrets(
    connection: &SqliteConnection,
    old_key: &str,
    new_key: &str,
) -> Result<MasterKeyRotationStats> {
    connection.with_connection_mut(|connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let connections = load_connections(&transaction)?;
        let credentials = load_credentials(&transaction)?;
        let team_keys = load_team_key_caches(&transaction)?;
        let conflicts = load_personal_conflicts(&transaction)?;
        let credential_count = credentials.len();
        let team_key_count = team_keys.len();
        let conflict_count = conflicts.len();
        rotate_connections(&transaction, &connections, old_key, new_key)?;
        rotate_credentials(&transaction, credentials, old_key, new_key)?;
        rotate_team_key_caches(&transaction, &team_keys, old_key, new_key)?;
        rotate_personal_conflicts(&transaction, &conflicts, old_key, new_key)?;
        let stats = MasterKeyRotationStats {
            connections: connections.len(),
            credentials: credential_count,
            team_key_caches: team_key_count,
            personal_conflicts: conflict_count,
        };
        transaction.commit()?;
        Ok(stats)
    })
}

fn load_connections(transaction: &Transaction<'_>) -> Result<Vec<(i64, String)>> {
    let mut statement = transaction.prepare("SELECT id, params FROM connections ORDER BY id")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn load_credentials(transaction: &Transaction<'_>) -> Result<Vec<CredentialSecrets>> {
    let mut statement = transaction.prepare(
        "SELECT id, password, private_key_content, passphrase, ssh_expect
         FROM credential_entries ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(CredentialSecrets {
            id: row.get(0)?,
            password: row.get(1)?,
            private_key_content: row.get(2)?,
            passphrase: row.get(3)?,
            ssh_expect: row.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn rotate_connections(
    transaction: &Transaction<'_>,
    connections: &[(i64, String)],
    old_key: &str,
    new_key: &str,
) -> Result<()> {
    let mut statement = transaction.prepare("UPDATE connections SET params = ?1 WHERE id = ?2")?;
    for (id, params) in connections {
        let rotated = re_encrypt_sensitive_json(params, old_key, new_key)?;
        statement.execute(params![rotated, id])?;
    }
    Ok(())
}

fn rotate_credentials(
    transaction: &Transaction<'_>,
    credentials: Vec<CredentialSecrets>,
    old_key: &str,
    new_key: &str,
) -> Result<()> {
    let mut statement = transaction.prepare(
        "UPDATE credential_entries
         SET password = ?1, private_key_content = ?2, passphrase = ?3, ssh_expect = ?4
         WHERE id = ?5",
    )?;
    for credential in credentials {
        let password = rotate_optional(credential.password, old_key, new_key)?;
        let private_key = rotate_optional(credential.private_key_content, old_key, new_key)?;
        let passphrase = rotate_optional(credential.passphrase, old_key, new_key)?;
        let ssh_expect = rotate_optional(credential.ssh_expect, old_key, new_key)?;
        statement.execute(params![
            password,
            private_key,
            passphrase,
            ssh_expect,
            credential.id
        ])?;
    }
    Ok(())
}

fn rotate_optional(value: Option<String>, old_key: &str, new_key: &str) -> Result<Option<String>> {
    value
        .map(|value| {
            if value.is_empty() {
                Ok(value)
            } else {
                Ok(crypto::re_encrypt_data(&value, old_key, new_key)?)
            }
        })
        .transpose()
}

/// 读取本地团队密钥缓存。
///
/// 团队密钥本体由团队口令（Argon2id 信封）保护，但落盘到本机时是用当前
/// 主密钥再包一层，所以主密钥变更必须同步轮换，否则改完密钥就再也解不开缓存。
/// 缓存表是后续迁移才加入的，旧库可能没有该表，此时直接返回空列表。
fn load_team_key_caches(transaction: &Transaction<'_>) -> Result<Vec<TeamKeySecret>> {
    let mut statement = match transaction.prepare(
        "SELECT cloud_environment, user_id, team_id, encrypted_team_key
           FROM team_key_cache
          ORDER BY cloud_environment, user_id, team_id",
    ) {
        Ok(statement) => statement,
        Err(_) => return Ok(Vec::new()),
    };
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;

    let mut secrets = Vec::new();
    for row in rows {
        let (environment, user_id, team_id, encrypted) = row?;
        let Some(encrypted) = encrypted else {
            continue;
        };
        if encrypted.is_empty() {
            continue;
        }
        secrets.push(TeamKeySecret {
            environment,
            user_id,
            team_id,
            encrypted_team_key: encrypted,
        });
    }
    Ok(secrets)
}

fn rotate_team_key_caches(
    transaction: &Transaction<'_>,
    caches: &[TeamKeySecret],
    old_key: &str,
    new_key: &str,
) -> Result<()> {
    if caches.is_empty() {
        return Ok(());
    }
    let mut statement = transaction.prepare(
        "UPDATE team_key_cache SET encrypted_team_key = ?1
          WHERE cloud_environment = ?2 AND user_id = ?3 AND team_id = ?4",
    )?;
    for cache in caches {
        let rotated = crypto::re_encrypt_data(&cache.encrypted_team_key, old_key, new_key)?;
        statement.execute(params![
            rotated,
            cache.environment,
            cache.user_id,
            cache.team_id
        ])?;
    }
    Ok(())
}

fn load_personal_conflicts(
    transaction: &Transaction<'_>,
) -> Result<Vec<PersonalConflictSnapshots>> {
    let mut statement = match transaction.prepare(
        "SELECT backend_profile_id, data_type, record_id, local_snapshot, remote_snapshot
           FROM personal_sync_conflicts
          ORDER BY backend_profile_id, data_type, record_id",
    ) {
        Ok(statement) => statement,
        Err(_) => return Ok(Vec::new()),
    };
    let rows = statement.query_map([], |row| {
        Ok(PersonalConflictSnapshots {
            backend_profile_id: row.get::<_, String>(0)?,
            data_type: row.get::<_, String>(1)?,
            record_id: row.get::<_, String>(2)?,
            local_snapshot: row.get::<_, Option<String>>(3)?,
            remote_snapshot: row.get::<_, Option<String>>(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn rotate_personal_conflicts(
    transaction: &Transaction<'_>,
    conflicts: &[PersonalConflictSnapshots],
    old_key: &str,
    new_key: &str,
) -> Result<()> {
    if conflicts.is_empty() {
        return Ok(());
    }
    let mut statement = transaction.prepare(
        "UPDATE personal_sync_conflicts SET local_snapshot = ?1, remote_snapshot = ?2
          WHERE backend_profile_id = ?3 AND data_type = ?4 AND record_id = ?5",
    )?;
    for conflict in conflicts {
        let local = rotate_snapshot(conflict.local_snapshot.as_deref(), old_key, new_key)?;
        let remote = rotate_snapshot(conflict.remote_snapshot.as_deref(), old_key, new_key)?;
        statement.execute(params![
            local,
            remote,
            conflict.backend_profile_id,
            conflict.data_type,
            conflict.record_id
        ])?;
    }
    Ok(())
}

/// 轮换单条冲突快照里的云端密文。
///
/// 快照是 `CloudSyncData` 的 JSON 序列化，其中 `encrypted_data` 由主密钥加密。
/// 非 JSON 或不带 `encrypted_data` 的快照原样保留。
fn rotate_snapshot(
    snapshot: Option<&str>,
    old_key: &str,
    new_key: &str,
) -> Result<Option<String>> {
    let Some(snapshot) = snapshot else {
        return Ok(None);
    };
    if snapshot.is_empty() {
        return Ok(Some(snapshot.to_string()));
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(snapshot) else {
        return Ok(Some(snapshot.to_string()));
    };
    let Some(encrypted) = value
        .get("encrypted_data")
        .and_then(|value| value.as_str())
        .map(str::to_string)
    else {
        return Ok(Some(snapshot.to_string()));
    };
    if !crypto::is_encrypted(&encrypted) {
        return Ok(Some(snapshot.to_string()));
    }
    let rotated = crypto::re_encrypt_data(&encrypted, old_key, new_key)?;
    if let Some(field) = value.get_mut("encrypted_data") {
        *field = serde_json::Value::String(rotated);
    }
    Ok(Some(serde_json::to_string(&value)?))
}
