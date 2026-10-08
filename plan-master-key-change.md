# 主密钥变更方案（修改 / 重置）—— 调研结论与实施设计（v2）

> 状态：**v2，已按 2026-10-09 决策结论修订，待再次确认**（未实施任何代码改动）
> 范围：Navop Cloud Sync（OnetCloud/Supabase）与 Personal Sync（Folder/Git/WebDAV）两类同步方式全覆盖
> v1 → v2 变更：D1-D6 决策结论落入设计（见 6.2 决策记录），重置改为勾选项清单（D2）、新增版本信息同步机制（D5）、GUI 双入口布局（D6）

---

## 一、现状机制梳理

### 1.1 密钥派生与加密原语（crates/core/src/crypto.rs）

- 派生：`derive_key()` = `SHA-256(master_key || "onehub_password_encryption_salt_v1")` → 32B AES-256 密钥（L147）。
- 密文格式：`ENC:base64(nonce(12B) + AES-256-GCM(ct+tag(16B)))`（`ENCRYPTED_PREFIX`，L75）。
- 全局内存态：`ENCRYPTION_KEY`（派生密钥）+ `RAW_MASTER_KEY`（原始密钥，供云同步使用，L99-102）。
- 验证机制：`key_verification` 文件 = `base64(nonce + AES-GCM("ONEHUB_KEY_VERIFY_V1"))`；`verify_master_key()` 尝试解密验证（L162-210）。
- **现有主密钥格式要求：仅非空**（GUI 层 encryption.rs L123 检查空串；crypto 层无长度/字符集约束）。
- 已有 API：
  - `set_master_key` / `set_master_key_for_session`（首次设置，session 模式删除持久化副本）
  - `verify_and_set_master_key`（解锁）
  - `change_master_key(_for_session)`（L552：验证旧密钥 → 更新 key_storage + key_verification，原子带回滚；**不重加密数据，注释明确留给调用方**）
  - `re_encrypt_data(old, new)`（L518：解旧密 → 加新密）
  - `reset_repo_password()`（L667：清内存 + 删验证文件；**全仓无 GUI 调用，重置入口不存在**）
  - `try_restore_master_key()`（L692：启动自动恢复，verify 失败则删除存储并要求手输）

### 1.2 密钥本地持久化（crates/core/src/key_storage.rs）

- `LocalFileStorage`：主密钥经**内置固定 key**（`LOCAL_STORAGE_FIXED_KEY`，L27，硬编码）AES-256-GCM 加密后原子写入 `<data_dir>/key_storage`（0600、临时文件替换）。
- `KeyStorage` trait 可换后端；`persistent_storage_allowed()` 由 `AppPaths::allows_persistent_master_key()`（app_paths.rs L43，当前恒 true）控制。
- 启动策略（main/src/home_tab/lifecycle.rs L119-141）：`require_master_key_on_startup`（settings.rs L1126）/便携模式 `portable_remember_master_key`（L1129）→ 决定 forget/restore/prompt 三态。
- **当前无 key_version 本地持久化**（v2 新增，见 3.5）。

### 1.3 本地受主密钥保护的数据面（4 处）

| # | 数据 | 位置 | 加密方式 |
|---|------|------|----------|
| 1 | 连接敏感字段 | SQLite `connections.params`（JSON 中 password/passphrase/private_key(_content)/send/*_password 等，models.rs L3574） | 主密钥派生 key，`encrypt_json_passwords` |
| 2 | 钥匙串条目 | SQLite `credential_entries`（password/private_key_content/passphrase/ssh_expect） | 同上 |
| 3 | **团队密钥缓存** | SQLite `team_key_cache.encrypted_team_key` | `crypto::encrypt_with_key(team_key, personal_key)`（team_key_manager.rs L98）；读取用主密钥解（L158） |
| 4 | WebDAV 登录密码 | `settings.json`（webdav_secret.rs：主密钥可用时用主密钥 seal；否则退化为内置 fallback key） | 两级策略 |

> 注意：#3、#4 目前**不在**现有轮换流程的覆盖范围内（见 1.7 Gap）。

### 1.4 云端加密结构

**Navop Cloud Sync（Supabase，crates/core/src/cloud_sync/supabase.rs）**

- `user_configs` 表：`user_id + key_verification + key_version`（get/save L1493-1533）。
- `sync_data` 表：`CloudSyncData{id, owner_id, team_id, data_type, encrypted_data, key_version, checksum, version, updated_at, deleted_at}`（models.rs L206）。
  - `encrypted_data` = 整个明文 JSON blob 的 `ENC:` 密文；个人数据用主密钥派生 key，团队数据用**团队 data_key**（service.rs `encrypt_blob` L311 / `select_encrypt_key` L287）。
  - 明文结构：`ConnectionPlainData`（含 params）/ `WorkspacePlainData` / `CredentialPlainData`。
- 上传：`prepare_*_upload` → `create/update_sync_data`；下载：`decrypt_sync_data_*`（service.rs L339-621）。
- 同步引擎（engine.rs L174）：`ensure_unlocked`（L141）——本地 crypto 解锁后 `set_master_key_directly` 注入，**从不与云端 user_configs 交互**。
- 同步前跳过本地解密失败的连接（connection_sync.rs L42，`list_sync_decrypt_failures`，repository.rs L578）。

**Personal Sync（Folder/Git/WebDAV，crates/core/src/cloud_sync/personal/）**

- 数据格式与 OnetCloud 完全同构：`CloudSyncData` 记录 JSON 写入 `.onetcli-sync/records/<type>/<id>.json`（file_format.rs）。
- 加密同样走 `CloudSyncService`（personal_sync_runtime.rs 独立实例，L902 `set_master_key_directly` 注入主密钥）→ 同一主密钥派生 key。
- 目录结构：`manifest.json + records/ + tombstones/ + state/ + lock`；`PersonalSyncManifest{schema_version, app, profile_id, created_at, updated_at}`（models.rs L8）**无 key_verification、无 key_version**（v2 扩展，见 3.5）。
- worker（worker.rs L181 `run_pass`）：事件驱动（本地变更/远端变更/全量扫描）+ 60s 周期；planner 以 `updated_at`/`last_synced_at`/checksum 决定增量。

### 1.5 校验发生环节（实际生效的）

| 环节 | 机制 | 位置 |
|------|------|------|
| 解锁/首次设置 | 本地 `key_verification` 文件 verify | crypto.rs `verify_master_key` |
| 启动自动恢复 | load + verify，失败删除存储并要求手输 | crypto.rs `try_restore_master_key` |
| **云端拉取恢复** | **无前置校验**，直接尝试 `decrypt_blob`，解密失败 = 密钥不匹配 | generic_sync.rs L650、local_source.rs L215/253/294 |
| 云端 user_configs.key_verification | **已定义但无生产调用（死链路）**：`CloudSyncService::unlock`（L163）、`setup_master_key`（L181）仅测试使用 | service.rs |

> 用户认知中的"从云端恢复校验密钥是否匹配"实际由**解密尝试**实现；`KeyVersionMismatch` 错误全仓无产生点；`key_version` 字段只写不读。v2 激活版本机制（D5）。

### 1.6 现有"修改主密钥"链路（唯一入口）

GUI：main/src/home_tab/encryption.rs

- `show_encryption_key_dialog`（L54）：三合一弹窗（首次设置 / 修改 / 解锁），由 `has_repo_password_set() && has_master_key()` 区分。
- 修改模式：**单输入框**，用户直接输入新密钥；旧密钥取自内存 `get_raw_master_key()`（L151），无旧密钥输入、无确认输入。
- `rotate_master_key`（L335）：`validate_master_key_change` → `storage::re_encrypt_secrets`（本地 DB 单事务：connections.params + credential_entries，master_key_rotation.rs L23）→ `crypto::change_master_key`；后者失败则反向 `re_encrypt_secrets(new→old)` 手动回滚（回滚再失败则报双错）。
- 成功关闭弹窗后：刷新连接列表 + 自动触发云同步（L208-223）。
- 入口：account_menu.rs L231（账户菜单"个人密钥"）、workbench.rs L128（侧边栏状态卡片密钥行）。

### 1.7 Gap 分析（本方案要解决的问题）

| # | 问题 | 影响 |
|---|------|------|
| G1 | **云端存量数据不随密钥变更重加密**：本地轮换不改变业务 `updated_at`，同步 planner 判定"已同步"，旧密文记录不会重传 | OnetCloud 与 Personal 的云端残留旧密钥密文；其他设备、重装恢复时解密失败 |
| G2 | `CloudSyncService::change_master_key`（service.rs L205，云端重加密 + key_version+1）**无调用方（死代码）**；且其对团队记录也会尝试用主密钥解密（团队数据用 team_key 加密），会失败 | 云端重加密无可用编排，且直接启用该 API 有 bug 隐患 |
| G3 | **team_key_cache.encrypted_team_key 未轮换** | 改密钥后本地团队密钥缓存解不开 → 触发重新输入团队密钥（有降级路径但体验受损） |
| G4 | **WebDAV 凭证未轮换**：以主密钥 seal 的密文在新密钥下解不开（open 先主密钥后 fallback key，均失败→密码为空） | WebDAV 后端 NotConfigured，需用户重输密码 |
| G5 | 修改流程无旧密钥输入/无确认/无进度/无失败恢复路径 | 安全与健壮性不足 |
| G6 | **重置功能缺失**：`reset_repo_password` 无 GUI、只删验证文件，不清本地密文数据、不清云端 | 无法安全重置 |
| G7 | **多设备一致性无机制**：无版本协商；decrypt 失败只有笼统 `CryptoError`，用户无法区分"密钥被改"与"自己输错" | 密钥变更期间其他设备产生混合密文、无引导 |
| G8 | Personal Sync 冲突表（SQLite conflict repository）中缓存的旧密文记录未纳入轮换/清理 | 冲突恢复路径可能拿到解不开的数据 |

---

## 二、涉及文件清单与职责

### 2.1 现有文件（职责 + 本次改动性质）

**后端（one-core）**

| 文件 | 现职责 | 本次改动 |
|------|--------|---------|
| `crates/core/src/crypto.rs` | 派生/加解密/验证/密钥生命周期 | 新增 `key_meta` 读写（key_version 本地持久化，见 3.5）；复用其余 |
| `crates/core/src/key_storage.rs` | 主密钥本地持久化 | 不动 |
| `crates/core/src/storage/master_key_rotation.rs` | 本地 DB 单事务轮换（connections + credential_entries） | **扩展**：同一事务内加入 `team_key_cache.encrypted_team_key` 与 `personal_sync_conflicts` 密文轮换 |
| `crates/core/src/storage/models.rs` | `re_encrypt_sensitive_json` / 敏感字段判定 / 解密失败检测 | 不动（复用） |
| `crates/core/src/cloud_sync/service.rs` | blob 加解密、上传准备、下载解密、（死）change_master_key | **改造**：`re_encrypt_sync_data` 复用；新增 `reencrypt_cloud_pass` 编排（仅 team_id=None 记录）；废弃/修正死代码 change_master_key（R8） |
| `crates/core/src/cloud_sync/supabase.rs` / `client.rs` | REST 客户端（user_configs、sync_data、teams RPC） | 复用 `list/update/delete_sync_data`、`get/save_user_config`（**激活为生产链路**，D4/D5）；可能新增批量删除便捷方法 |
| `crates/core/src/cloud_sync/engine.rs` | 同步引擎、团队密钥缓存刷新 | 复用 `sync_execution_lock`；同步开始处新增 user_configs 版本比对钩子（3.4/3.5） |
| `crates/core/src/cloud_sync/team_key_manager.rs` | 团队密钥缓存（信封与主密钥双轨） | 逻辑不动；仅 `team_key_cache` 表数据随本地轮换 |
| `crates/core/src/cloud_sync/personal/models.rs` | manifest/tombstone/错误模型 | **扩展**：`PersonalSyncManifest` 增加 `key_version: Option<u32>`（serde default，向后兼容） |
| `crates/core/src/cloud_sync/personal/file_format.rs` / `directory_store.rs` / `git_store.rs` / `webdav_store.rs` / `configured_store.rs` / `store.rs` | Personal Sync 存取抽象 | manifest 读写随 key_version 扩展；复用 `list_records/upsert_record/tombstone/delete` 实现云端重加密与清空 pass |
| `crates/core/src/cloud_sync/personal/worker.rs` | 事件驱动同步 pass | pass 收尾写 manifest（含 key_version）；`run_pass` 起点读 manifest 比对版本 |
| `crates/core/src/cloud_sync/personal/webdav_secret.rs` | WebDAV 密码 seal/open | 新增：主密钥轮换时对主密钥密文的重加密函数 |
| `crates/core/src/settings.rs` | `require_master_key_on_startup` 等 | 新增 `pending_cloud_reencrypt` / `pending_cloud_wipe`（bool + 时间戳）与重置相关配置清理 |

**GUI（main）**

| 文件 | 现职责 | 本次改动 |
|------|--------|---------|
| `main/src/home_tab/encryption.rs` | 三合一密钥弹窗 + `rotate_master_key` | **重构**：拆分为 ①首次设置/解锁 ②修改（旧密钥+新密钥×2+警示，D1）③重置入口；`rotate_master_key` 扩展为完整编排 |
| `main/src/home_tab/workbench.rs` | 侧边栏状态卡片（`home-navigation-status`：账户/同步/密钥三行，L67-133） | **D6**：同步状态行下方新增「修改主密钥」「重置主密钥」两行，点击弹窗弹出表单；密钥行保留为解锁/首次设置 |
| `main/src/home_tab/account_menu.rs` | 账户菜单（头像 popover） | 新增「修改主密钥」「重置主密钥」菜单项（重置 danger 样式） |
| `main/src/setting_tab.rs` | 设置面板（已有 `Settings.Account.title` 账户页 L998） | **D6**：账户页新增「修改主密钥」「重置主密钥」入口（按钮组） |
| `main/src/home_tab/cloud_sync.rs` | `trigger_sync` | 修改成功后触发云端重加密 pass + 全量同步（D5）；失败进入 pending 提示 |
| `main/src/personal_sync_runtime.rs` | Personal Sync 运行时 | 新增 personal 云端重加密 pass 与停机/清空接口（重置时） |
| `main/src/home_tab/lifecycle.rs` | 启动密钥策略 | pending 标记存在时启动即提示"云端数据待重加密" |
| `main/locales/main.yml` | 文案 | 新增 Encryption.* 全部新文案（zh/en 等） |

### 2.2 新增文件

| 文件 | 职责 |
|------|------|
| `main/src/master_key/change_flow.rs`（或并入 encryption.rs） | 修改主密钥全流程编排：本地轮换 → 切换密钥 → OnetCloud 重加密 → Personal 重加密 → 版本同步 → 验证 → pending/重试 |
| `main/src/master_key/reset_flow.rs` | 重置编排：停同步 → 勾选项确认 → 按勾选清本地 → 清云端（OnetCloud + Personal）→ 回初始态 |
| `crates/core/src/cloud_sync/master_key_reencrypt.rs` | 云端重加密核心（拉取全量 → 过滤个人记录 → re_encrypt → 回写 → 校验），OnetCloud 与 Personal 共用 |
| 对应测试：`master_key_reencrypt_tests.rs`、`master_key_rotation_tests.rs` 扩展 | 覆盖：团队记录跳过、部分失败重试、pending 幂等、manifest key_version 兼容 |

---

## 三、场景 1：修改主密钥

### 3.1 流程总览

```
[0] 前置：确保已解锁；建议先做一次常规同步（把云端最新数据拉回本地，减少轮换窗口内的并发写）
[1] GUI 修改弹窗（D1）：输入旧密钥 + 新密钥 ×2 + 警示确认
[2] validate_master_key_change(old, new, confirm)          —— crypto.rs 已有
    （新密钥校验与现状一致：仅非空，不新增长度/格式约束）
[3] 本地 DB 轮换（单 SQLite 事务）                          —— re_encrypt_secrets 扩展版
    connections.params + credential_entries + team_key_cache + personal_sync_conflicts
[4] WebDAV 凭证重加密（settings.json，主密钥密文分支）      —— 新增
[5] crypto::change_master_key(old, new, new)                —— 切换 key_storage + key_verification（内建回滚）
    + key_version 本地持久化 +1（key_meta，见 3.5）
[6] OnetCloud 云端重加密 pass（D3 方案甲）：
    list_sync_data(个人) → re_encrypt_sync_data(old→new) → update_sync_data 逐条
    → save_user_config(新 key_verification, key_version+1)（D4/D5：激活 user_configs 链路）
[7] Personal 云端重加密 pass：
    store.list_records → re_encrypt → upsert_record（Folder/Git/WebDAV 同一 trait 路径）
    → manifest.json 写入 key_version（D5）
[8] 验证：随机抽 1 条 decrypt 新密文成功（OnetCloud + Personal 各一）
[9] 自动触发全量同步（D5）→ 其他设备侧流程见 3.4
```

### 3.2 关键设计决策（已定稿）

1. **[D1] 修改弹窗强制输入旧主密钥**，不再默认信任内存密钥；与本地 key_verification 校验，不一致即时拦截。
2. **[D1] 新密钥要求与现状一致：仅非空**。不引入额外长度下限/字符集约束（现状 `set_master_key` 即此标准），弹窗对新密钥做两次输入一致性确认。
3. **[D3] OnetCloud 云端重加密采用方案甲（主动遍历重写）**：复用已有 `re_encrypt_sync_data`（service.rs L624，checksum 不变、仅换密文与 key_version）与 client 的 list/upsert API。网络失败不切换方案，走 **pending 幂等补做**（对已是新密文且 key_version 正确的记录跳过）。理由：方案乙（planner 感知 key_version 强制重传）需改动 generic_sync/personal planner 的比较逻辑，与冲突解决策略纠缠，影响面大。
4. **只重加密 `team_id = None` 的记录**。团队数据用 team data_key 加密（与主密钥无关），用主密钥去解会必然失败——这是现有死代码 `CloudSyncService::change_master_key` 的潜在 bug，本次实现必须过滤。
5. **本地先行、云端幂等、失败不回滚本地**。步骤 [3]-[5] 完成后本地在新密钥下自洽；[6][7] 网络失败只记 pending，由下次同步前/启动时补做。
6. **[D5] 修改成功后自动触发全量同步 + 同步版本信息**，使设备 B 能明确区分"云端主密钥已被修改"与"自己输入错误"（机制见 3.4/3.5）。
7. **改密钥前置一次拉取同步**（若已登录且开启同步）：先把云端最新数据解密回本地（此时旧密钥仍有效），避免"轮换期间其他设备上传的新数据"永远停留在旧密钥密文。此步失败（网络）仅警告，不阻断本地轮换，但明确提示多设备风险。

### 3.3 中途失败处理与回滚矩阵

| 失败点 | 状态 | 处理 |
|--------|------|------|
| [2] 旧密钥校验失败 | 无改动 | 弹窗内提示，可重试 |
| [3] 本地轮换失败 | SQLite 单事务自动整体回滚 | 中止流程，本地保持旧密钥自洽 |
| [4] WebDAV 重加密失败 | 本地 DB 已轮换 | 记 warning，不阻断（WebDAV 凭证走"用户重输"降级路径），流程继续 |
| [5] change_master_key 失败 | crypto 内建回滚（恢复 key_storage 旧值） | 需回滚 [3]：反向 `re_encrypt_secrets(new→old)`；若回滚也失败→红色错误提示（本地 DB 新密钥 + key_storage 旧密钥不一致，需用户按提示修复，实际概率极低：两步均为本地操作） |
| [6]/[7] 网络中断/部分失败 | 本地已切换，云端混合密文 | **不回滚**；写 pending 标记 + 失败 ID 清单；下次同步前自动补做（幂等）；UI 顶部横幅"云端数据重加密未完成" |
| [8] 抽验解密失败 | 理论不可达（re_encrypt 自带 AES-GCM 完整性） | 视为严重错误，中止并保留 pending 标记 |
| 多设备并发写 | 云端可能出现旧密钥新记录 | 见 3.4 |

### 3.4 多设备密钥一致性（含 D4/D5）

- **设备 A（发起方）**：完成 3.1 后——
  - OnetCloud：云端个人数据全部为新密钥、`sync_data.key_version = N+1`、`user_configs{key_verification=新, key_version=N+1}` 更新（[6]）。
  - Personal：records 全部新密钥、`manifest.json.key_version = N+1`（[7]）。
  - [9] 自动全量同步，确保版本信息先行可见（user_configs / manifest 均随 pass 一并更新）。
- **设备 B（其他设备）检测**——优先级从高到低：
  1. **OnetCloud：user_configs 版本比对（[D4]）**。同步开始时拉 `user_configs`，若 `cloud.key_version > 本地 key_meta.key_version` → **明确提示"主密钥已在其他设备修改，请输入新主密钥"**。此时本地密钥刚通过本地 key_verification 解锁校验，"自己输错"的解释被排除——这是 D5 要求的"区分"核心。
  2. **Personal：manifest 版本比对**。全量扫描读 `manifest.key_version`，与本地 key_meta 不一致 → 同上提示。
  3. **兜底：抽样解密（[D4] Personal 主通道）**。manifest 为旧版本/字段缺失时，抽取 1 条 record 尝试 `decrypt_blob`，失败 → 同上提示。OnetCloud 同样保留解密失败兜底。
  4. 现有"decrypt 失败 → 笼统 CryptoError"映射改为专门错误码 + 上述文案（generic_sync.rs 错误映射、personal worker 错误传播）。
- **设备 B 的 adopt 流程**：
  1. 用户输入新密钥 → **[D4] OnetCloud：用云端 `user_configs.key_verification` 校验**（激活 `CloudSyncService::unlock` L163 或新增轻量校验函数）；**Personal：抽样解密校验**。
  2. 校验通过 → 设备 B 本地执行与 3.1 [3]-[5] 相同的**本地轮换**（旧密钥 = B 本地已有），key_version 同步为 N+1。
  3. 完成后正常同步（云端已是新密文，B 直接拉取无障碍）。
  - B 若处于启动锁定/离线状态：解锁弹窗输入旧密钥成功（本地 verification 仍旧）→ 同步触发后才走到检测步骤，UI 引导两步。
- **一致性窗口**：A 完成本地轮换到云端重加密完成之间，B 上传的数据仍是旧密钥密文。缓解：
  - A 的 pass 先 list 后逐条 update；B 中途上传的旧密钥新记录会被 A 的 pending 补做捕获（pending 持续到"全量 list 校验无旧密文"为止）；
  - B 端 decrypt 失败即中断该轮 pass 上传（现状已如此），不会持续产生旧密文。

### 3.5 [D5 新增] key_version 版本信息机制

| 项 | 设计 |
|----|------|
| 本地持久化 | 新增 `<data_dir>/key_meta.json`：`{"key_version": N}`。首次设置主密钥时创建（version=1）；每次修改 +1；重置删除。读写函数放 crypto.rs 或新 `key_meta.rs`。缺文件视为 version=1（向后兼容存量安装）。 |
| OnetCloud | 每条 `sync_data.key_version` 已有字段，激活写入路径（上传时带上当前版本）；`user_configs` 通过 `save_user_config`（supabase.rs L1519，已实现 upsert）写入新 verification + version，由修改流程 [6] 与 adopt 流程维护。 |
| Personal | `PersonalSyncManifest` 增加 `#[serde(default)] key_version: Option<u32>`（不提升 `SUPPORTED_SCHEMA_VERSION`：旧客户端 serde 反序列化自动忽略未知字段，新客户端读旧 manifest 得 None 视为 1）；manifest 更新点随个人同步 pass 收尾写入。 |
| 读取时机 | 设备 B：OnetCloud 同步开始（engine.sync 入口）拉 user_configs 比对；Personal 全量扫描读 manifest 比对。 |

---

## 四、场景 2：重置主密钥（清空数据）—— 按 D2 修订

### 4.1 流程总览

```
[1] 入口（D6）：设置-账户页 / 侧边栏同步状态下方 / 账户菜单 → 「重置主密钥…」（danger 样式）
[2] 弹窗一（强提示）：
    - 红色警告：默认将删除勾选的全部数据且不可恢复；云端已同步数据将被清除；
      重置后多设备其他终端需以新密钥重新设置
    - 要求输入确认词 RESET 才能继续（不依赖旧密钥——支持"忘记密钥"场景）
[3] 弹窗二（二次确认，D2 勾选项清单）：
    - 勾选 = 删除该项（默认全部勾选）；取消勾选 = 保留该项
    - 见 4.2 数据范围与勾选项映射
    - 按钮"我已知晓，永久删除"
[4] 停止同步运行时：置 syncing 屏障（OnetCloud）+ 停 Personal runtime（GlobalPersonalSyncRuntime）
[5] 清本地（必清项）：
    - SQLite：connections、credential_entries、workspaces、team_key_cache、
      team_membership_cache、personal_sync_conflicts、同步状态字段（cloud_id/last_synced_at）
    - 删 <data_dir>/key_storage、<data_dir>/key_verification、<data_dir>/key_meta.json
    - settings.json：清 WebDAV 密码、清 pending 标记
    - 内存：clear_master_key()
[6] 清本地（勾选项）+ 清云端（勾选项），逐项见 4.2
[7] 结果：has_repo_password_set() == false → 下次进入触发"首次设置主密钥"弹窗（等同全新安装）
```

### 4.2 [D2] 重置数据范围与勾选项映射（勾选=删除，默认全勾）

**固定必清项**（与主密钥强绑定，保留会产生永久解不开的密文，不提供勾选）：

| 数据 | 位置 |
|------|------|
| 连接（含 params 密文） | SQLite `connections` |
| 钥匙串条目 | SQLite `credential_entries` |
| 工作区/分组 | SQLite `workspaces` |
| 本地团队密钥缓存 + 团队成员缓存 | SQLite `team_key_cache`、`team_membership_cache`（主密钥加密 / 可自动重建） |
| 主密钥文件 / 验证文件 / 版本文件 | `<data_dir>/key_storage`、`key_verification`、`key_meta.json` |
| WebDAV 凭证 | settings.json（主密钥密文分支重置后不可解，fallback 分支一并清理，语义统一） |

**可勾选项**（默认全部勾选=删除，用户可取消保留）：

| # | 勾选项 | 数据 | 取消勾选（保留）后的语义 |
|---|--------|------|--------------------------|
| C1 | **团队数据** | OnetCloud `sync_data` 中 `team_id != None` 的云端记录（团队共享资产） | 云端团队数据不动；重置后用户需重新输入**团队密钥**（信封 passphrase 与主密钥无关）才能继续同步团队数据 |
| C2 | **查询历史** | SQLite `sql_execution_history`（migration 20260817000002） | 本地保留，与密钥无关，重置后可正常查看 |
| C3 | **命令历史** | SQLite `terminal_command_history`、`quick_commands`（migration 20260705000001/20260707000001） | 同上 |
| C4 | **笔记** | notes crate **文件存储**（markdown 文件 + document_index，用户可配置根目录，非 SQLite） | 文件不动；⚠️ 弹窗文案单独强调：删除即删磁盘文件 |
| C5 | **云同步数据与版本** | ① OnetCloud：个人 `sync_data` 记录 + `user_configs`（key_verification/key_version）② Personal：`.onetcli-sync/` records + tombstones + manifest.key_version ③ 本地同步状态 | 云端旧密文数据保留——**重置后以任何密钥都不可解**，仅作"墓地"存留（弹窗明示）；本地同步状态保留会在下次同步时触发解密失败提示，引导用户再次重置或清除 |

> 勾选项实现：`ResetScope` 结构体（5 个 bool + 序列化记录用户选择），传给 reset_flow 编排；每个可勾选项对应独立的清理函数，互不耦合。

### 4.3 失败处理

- 云端清除失败（网络）：本地已清空（不可逆，弹窗已三重警示），云端残留旧密文。按后端记录 `pending_cloud_wipe` 标记，下次登录后补删；期间云端数据对任何人（包括用户自己新密钥）都不可解，无泄露扩面。
- 本地清库失败（文件锁等）：中止并报错，保持现状不半清——SQLite 表清空用单事务，文件删除逐个校验。
- C4 笔记删除失败（文件占用）：跳过并在结果中列出未删项，不阻断其余清理。

---

## 五、实施阶段划分

| 阶段 | 内容 | 主要文件 | 验证 |
|------|------|---------|------|
| S1 | 本地轮换扩展：team_key_cache + personal_sync_conflicts 入事务；WebDAV 密文重加密；key_meta 读写 | master_key_rotation.rs、webdav_secret.rs、crypto.rs（key_meta）、settings.rs | 单测：轮换后 team key 可解、WebDAV 凭证 round-trip、key_meta 兼容缺省；`master_key_rotation_tests.rs` 扩展 |
| S2 | 云端重加密核心（OnetCloud + Personal 共用）+ pending 标记与幂等重试 + manifest key_version 扩展 | cloud_sync/master_key_reencrypt.rs（新）、service.rs、client.rs、supabase.rs、personal/{models,file_format,worker,store*}、engine.rs | 单测：个人记录重加密、团队记录跳过、部分失败重试只补失败项、旧/新 manifest 兼容；集成：webdav/git 假后端跑全 pass |
| S3 | GUI 修改弹窗重构（D1：旧密钥+新密钥×2）+ 双入口布局（D6：设置-账户页 + 侧边栏同步状态下方 + 账户菜单）+ 流程编排接线 + 自动全量同步（D5） | encryption.rs、workbench.rs、account_menu.rs、setting_tab.rs（账户页）、cloud_sync.rs、lifecycle.rs、main.yml | 手工视觉验证 + 现有 source-level 测试（encryption.rs 内嵌 include_str 断言）更新 |
| S4 | 重置流程：RESET 确认词弹窗 + 勾选项清单弹窗（D2）+ ResetScope 分项清理 + 回初始态 | reset_flow.rs（新）、personal_sync_runtime.rs、main.yml | 单测：ResetScope 各组合清理范围（临时 data_dir + 假云端后端）；手工：重置后等同全新安装、保留项可见 |
| S5 | 多设备 adopt + 版本检测（D4/D5）：user_configs 比对、manifest 比对、抽样解密兜底、decrypt 失败专门提示与解锁重试引导 | engine.rs（同步入口版本钩子）、generic_sync.rs 错误映射、encryption.rs 解锁分支、personal worker 错误传播、cloud_sync.rs | 单测：错误映射、版本比对分支；集成：双 service 模拟双设备（A 改 → B 检测 → adopt） |

依赖关系：S1 → S2 → S3；S4 依赖 S2 的 client/store 复用；S5 依赖 S3+S2。S2 完成前 S3 可并行开发弹窗 UI。

测试策略对照 AGENTS.md 分层：S1/S2/S5 属 Level 2（TDD：先写"团队记录被跳过""pending 幂等""版本比对分支"等行为测试再实现）；S3/S4 GUI 层以定向验证 + 手工视觉为主；整体收尾跑 `cargo check -p one-core -p main` + 相关单测。

---

## 六、风险点与决策记录

### 6.1 风险点

| # | 风险 | 缓解 |
|---|------|------|
| R1 | 云端重加密窗口内的多设备并发写 → 混合密文 | pending 持续补做 + B 端 decrypt 失败即中断上传 + 修改前先拉取同步 + 版本比对前置提示 |
| R2 | 云端记录量大时逐条 update 慢/触发限流 | 分批 + 进度提示；Supabase 侧确认 rate limit；必要时批量 RPC |
| R3 | 重置清库范围遗漏或误删 | ResetScope 白名单逐表/逐文件清理，不使用 DROP DATABASE；勾选项组合有单测覆盖 |
| R4 | 笔记为磁盘文件删除，不可恢复性最高 | 弹窗二次确认文案单独强调；删除失败跳过不阻断 |
| R5 | Portable 模式 data_dir 差异 | key_storage/key_verification/key_meta 路径全部走 `app_dirs::data_dir()`，无硬编码，天然兼容 |
| R6 | key_storage 内置固定 key 的既有安全短板（主密钥本地静态加密） | 本次不改（超范围），记录为后续议题 |
| R7 | Personal Git 后端重加密产生大 commit / WebDAV 大量请求 | 逐条 upsert 已是现状路径；Git 可合并为单 commit；进度 UI 提示 |
| R8 | 死代码 `CloudSyncService::change_master_key/setup_master_key/unlock` 的去留 | `unlock` 在 D4 中激活为 adopt 校验通道；change_master_key/setup_master_key 修正或标注 deprecated，避免误用 |
| R9 | manifest 增加 key_version 的向后兼容 | `#[serde(default)] Option<u32>`，不提升 schema_version；新旧客户端互读单测覆盖 |
| R10 | adopt 流程中 B 设备本地轮换失败（本地数据已部分损坏） | 本地轮换单事务保证原子；失败则停在旧密钥态，可重试 |

### 6.2 决策结论记录（2026-10-09，曹哥确认）

| # | 决策 | 结论 | 落入设计 |
|---|------|------|---------|
| D1 | 修改弹窗旧密钥与新密钥要求 | 强制输入旧主密钥；新密钥长度/格式要求与原主密钥一致（现状=仅非空），不单独加严 | 3.2-1/2、3.1-[1][2] |
| D2 | 重置清库范围 | 范围包含所有数据，但以勾选项支持保留；**默认全部勾选（删除）**，包括团队数据、查询历史、命令历史、笔记、云同步版本数据 | 4.2 勾选项清单（C1-C5） |
| D3 | OnetCloud 云端重加密 | 方案甲：主动遍历重写 | 3.2-3、3.1-[6] |
| D4 | 设备 B adopt 校验 | OnetCloud 用 user_configs（key_verification）校验；Personal 用抽样解密 | 3.4 adopt 流程 |
| D5 | 修改后自动同步 | 自动触发全量同步，并同步版本信息（user_configs + manifest.key_version + 本地 key_meta），使设备 B 能区分"云端密钥被修改"与"输入错误" | 3.1-[9]、3.4、3.5 |
| D6 | GUI 入口布局 | ① 设置-账户-「修改主密钥/重置主密钥」② 主页侧边栏同步状态下方新增「修改主密钥/重置主密钥」，弹窗弹出表单 | 2.1 GUI 表、S3、4.1-[1] |

---

以上为 v2 修订版，未改动任何代码。确认后按 S1→S5 顺序实施。
