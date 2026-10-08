//! 主密钥元信息（版本号与云端待办标记）
//!
//! 与 `key_verification`（验证数据）不同，这个文件只记录与「多设备密钥一致性」
//! 相关的状态，不参与任何加解密，因此内容不是机密：
//!
//! - `key_version`：本地主密钥版本。每次修改主密钥 +1，云端 `user_configs`
//!   同步维护同一个版本号，其他设备据此判断"云端密钥被改过"而不是"自己输错"。
//! - `personal_key_version`：个人同步（Folder/Git/WebDAV）侧的版本号。个人同步
//!   没有云端验证数据，设备间靠解密抽样判断，这里只记录本机最后一次写入的版本。
//! - `pending_cloud_reencrypt` / `pending_cloud_wipe`：云端重加密 / 清空未完成。
//!   网络中断时先记标记，下次同步前补做，避免把本地已经切好的密钥回滚掉。

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const KEY_META_FILE: &str = "key_meta.json";

/// 首次设置主密钥时的起始版本号
pub const DEFAULT_KEY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterKeyMeta {
    #[serde(default = "default_key_version")]
    pub key_version: u32,
    #[serde(default = "default_key_version")]
    pub personal_key_version: u32,
    #[serde(default)]
    pub pending_cloud_reencrypt: bool,
    #[serde(default)]
    pub pending_cloud_wipe: bool,
}

fn default_key_version() -> u32 {
    DEFAULT_KEY_VERSION
}

impl Default for MasterKeyMeta {
    fn default() -> Self {
        Self {
            key_version: DEFAULT_KEY_VERSION,
            personal_key_version: DEFAULT_KEY_VERSION,
            pending_cloud_reencrypt: false,
            pending_cloud_wipe: false,
        }
    }
}

fn get_data_dir() -> Option<PathBuf> {
    crate::app_dirs::data_dir()
}

fn key_meta_path() -> Option<PathBuf> {
    get_data_dir().map(|data_dir| data_dir.join(KEY_META_FILE))
}

/// 读取主密钥元信息。文件缺失或损坏时返回默认值（存量安装视为版本 1）。
pub fn load() -> MasterKeyMeta {
    let Some(path) = key_meta_path() else {
        return MasterKeyMeta::default();
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return MasterKeyMeta::default();
    };
    serde_json::from_str(&contents).unwrap_or_default()
}

/// 写入主密钥元信息
pub fn save(meta: &MasterKeyMeta) -> Result<(), String> {
    let path = key_meta_path().ok_or_else(|| "无法获取密钥元信息路径".to_string())?;
    let contents = serde_json::to_string(meta).map_err(|error| format!("序列化密钥元信息失败: {error}"))?;
    crate::key_storage::atomic_write_file(&path, contents.as_bytes())
        .map_err(|error| format!("写入密钥元信息失败: {error}"))
}

/// 当前主密钥版本号
pub fn key_version() -> u32 {
    load().key_version.max(DEFAULT_KEY_VERSION)
}

/// 本机是否存在密钥版本记录
///
/// 老版本安装升级上来时还没有这个文件，此时不该拿默认版本去和云端比对，
/// 否则会把"云端本来就更高级"误判成"别人的密钥比我新"。
pub fn exists() -> bool {
    key_meta_path().is_some_and(|path| path.exists())
}

/// 递增主密钥版本号并返回新版本
pub fn bump_key_version() -> u32 {
    let mut meta = load();
    meta.key_version = meta.key_version.max(DEFAULT_KEY_VERSION) + 1;
    meta.personal_key_version = meta.key_version;
    let version = meta.key_version;
    if save(&meta).is_err() {
        return version;
    }
    version
}

/// 记录云端重加密待办（网络中断后补做）
pub fn set_pending_cloud_reencrypt(pending: bool) {
    let mut meta = load();
    meta.pending_cloud_reencrypt = pending;
    let _ = save(&meta);
}

/// 记录云端清空待办（重置时网络失败后补做）
pub fn set_pending_cloud_wipe(pending: bool) {
    let mut meta = load();
    meta.pending_cloud_wipe = pending;
    let _ = save(&meta);
}

pub fn pending_cloud_reencrypt() -> bool {
    load().pending_cloud_reencrypt
}

pub fn pending_cloud_wipe() -> bool {
    load().pending_cloud_wipe
}

/// 删除元信息文件：重置主密钥后本机回到全新安装状态
pub fn clear() {
    if let Some(path) = key_meta_path() {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::{MasterKeyMeta, DEFAULT_KEY_VERSION, load, save};

    #[test]
    fn default_meta_starts_at_version_one() {
        let meta = MasterKeyMeta::default();

        assert_eq!(DEFAULT_KEY_VERSION, meta.key_version);
        assert_eq!(DEFAULT_KEY_VERSION, meta.personal_key_version);
        assert!(!meta.pending_cloud_reencrypt);
        assert!(!meta.pending_cloud_wipe);
    }

    #[test]
    fn meta_round_trips_through_json() {
        let meta = MasterKeyMeta {
            key_version: 7,
            personal_key_version: 7,
            pending_cloud_reencrypt: true,
            pending_cloud_wipe: false,
        };

        let json = serde_json::to_string(&meta).expect("serialize meta");
        let parsed: MasterKeyMeta = serde_json::from_str(&json).expect("deserialize meta");

        assert_eq!(meta, parsed);
    }

    #[test]
    fn legacy_meta_without_pending_fields_deserializes() {
        let parsed: MasterKeyMeta =
            serde_json::from_str(r#"{"key_version": 3}"#).expect("deserialize legacy meta");

        assert_eq!(3, parsed.key_version);
        assert_eq!(DEFAULT_KEY_VERSION, parsed.personal_key_version);
        assert!(!parsed.pending_cloud_reencrypt);
        assert!(!parsed.pending_cloud_wipe);
    }

    #[test]
    fn corrupted_meta_falls_back_to_defaults() {
        let parsed: MasterKeyMeta = serde_json::from_str("not-json").unwrap_or_default();

        assert_eq!(MasterKeyMeta::default(), parsed);
        // load() 在真实环境下同样不会 panic
        let _ = load();
        let _ = save(&MasterKeyMeta::default());
    }
}
