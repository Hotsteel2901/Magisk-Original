# Magisk 功能扩展规格书 (FEATURE.md)

> 本文档为 AI Agent 提供三个高级功能的完整实现规格，涵盖架构设计、高级实现方式、回退方案及涉及文件清单。

---

## 目录

1. [DenyList 智能模式](#1-denylist-智能模式)
2. [安全审计仪表盘](#2-安全审计仪表盘)
3. [属性浏览器 / Boot 分析器](#3-属性浏览器--boot-分析器)

---

## 1. DenyList 智能模式

### 1.1 功能概述

在现有 DenyList 手动逐应用添加的基础上，引入智能自动检测机制：
- **预设规则库**：社区维护的敏感应用分类（银行、支付、企业 MDM、DRM 流媒体等）
- **自动检测**：基于应用类别、权限特征、SELinux 上下文自动识别需要隐藏 Root 的应用
- **一键批量**：按分类一键添加/移除 DenyList
- **社区规则订阅**：支持从远程 URL 订阅规则列表，定期更新

### 1.2 现有架构回顾

#### 核心数据流

```
App UI (DenyListViewModel)
  → Shell.cmd("magisk --denylist add <pkg> '<name>'")
  → denylist_cli() [cli.cpp]
  → connect_daemon(RequestCode::DENYLIST)
  → denylist_handler(fd) [cli.cpp]
  → add_list(client) [utils.cpp]
    → validate → ensure_data → add_hide_set
    → INSERT INTO denylist (package_name, process) VALUES(...)
```

#### 关键数据结构 (`native/src/core/deny/utils.cpp`)

- `pkg_to_procs_`: `map<string, set<string>>` — 包名 → 进程名集合
- `app_id_to_pkgs_`: `map<int, set<string_view>>` — app ID → 包名集合
- `denylist_enforced`: `atomic<bool>` — 全局执行标志
- `ISOLATED_MAGIC = "isolated"` — 隔离进程的特殊包名

#### DB Schema (`native/src/core/sqlite.cpp` 迁移步骤 11)

```sql
CREATE TABLE IF NOT EXISTS denylist (
    package_name TEXT,
    process TEXT,
    PRIMARY KEY(package_name, process)
);
```

设置表键：`DbEntryKey::DenylistConfig` → 字符串 `"denylist"`，默认值 0。

#### 执行路径

| Zygisk 状态 | 执行方式 | 代码位置 |
|-------------|---------|---------|
| 启用 | Zygote fork 时 hook，race-free | `native/src/core/zygisk/module.cpp` `app_specialize_pre()` |
| 禁用 | logcat 线程轮询 `am_proc_start` 事件 | `native/src/core/deny/logcat.cpp` |

#### App 侧 UI 结构

- `DenyListFragment.kt` — 带搜索、系统应用过滤的列表
- `DenyListViewModel.kt` — 异步加载 `magisk --denylist ls` + `PackageManager` 合并
- `DenyListRvItem.kt` — 三态复选框（开/关/不确定），折叠时仅操作 `defaultSelection` 进程
- `AppProcessInfo.kt` — 解析 Activity/Service/Receiver/Provider 进程名，识别隔离进程和 App Zygote

### 1.3 高级实现方案

#### 1.3.1 预设规则库（App 侧）

**新增文件**：`app/core/src/main/java/com/topjohnwu/magisk/core/deny/Presets.kt`

```kotlin
object DenyListPresets {

    enum class Category(val displayRes: Int) {
        BANKING(R.string.deny_preset_banking),
        PAYMENT(R.string.deny_preset_payment),
        ENTERPRISE(R.string.deny_preset_enterprise),
        STREAMING(R.string.deny_preset_streaming),
        GAMING(R.string.deny_preset_gaming),
        SOCIAL(R.string.deny_preset_social)
    }

    // 内置规则，按类别分组
    // 格式: 包名 → 建议的进程名列表（空列表表示使用主进程）
    val builtin: Map<Category, Map<String, List<String>>> = mapOf(
        Category.BANKING to mapOf(
            "com.chase.sig.android" to listOf(),           // Chase
            "com.bankofamerica.mobilebanking" to listOf(),  // Bank of America
            "com.wf.wellsfargo" to listOf(),                // Wells Fargo
            "com.usaa.mobile.android" to listOf(),          // USAA
            "com.capitalone.mobile" to listOf(),            // Capital One
            // ... 更多银行应用
        ),
        Category.PAYMENT to mapOf(
            "com.google.android.apps.nbu.paisa.user" to listOf(), // Google Pay (India)
            "com.samsung.android.spay" to listOf(),               // Samsung Pay
            "com.spotify.music" to listOf(),                      // Spotify (DRM)
        ),
        // ... 更多类别
    )

    // 远程订阅 URL 列表
    const val DEFAULT_SUBSCRIPTION_URL = "https://raw.githubusercontent.com/topjohnwu/magisk-denylist-presets/main/presets.json"
}
```

**规则 JSON 格式**：

```json
{
  "version": 1,
  "updated": "2026-06-26T00:00:00Z",
  "categories": {
    "banking": [
      {"pkg": "com.chase.sig.android", "procs": []},
      {"pkg": "com.bankofamerica.mobilebanking", "procs": []}
    ],
    "payment": [
      {"pkg": "com.google.android.apps.nbu.paisa.user", "procs": []}
    ]
  }
}
```

#### 1.3.2 自动检测引擎（App 侧）

**新增文件**：`app/core/src/main/java/com/topjohnwu/magisk/core/deny/AutoDetector.kt`

```kotlin
object DenyListAutoDetector {

    /**
     * 启发式规则：基于应用权限和特征自动判断是否应该加入 DenyList
     * 返回置信度 0.0~1.0
     */
    fun detectRiskLevel(info: ApplicationInfo, pm: PackageManager): Double {
        var score = 0.0

        // 规则1: 使用 SafetyNet/Play Integrity API 的应用
        // 检查是否声明了 com.google.android.gms.permission.SAFETY_NET
        if (hasPermission(info, pm, "com.google.android.gms.permission.SAFETY_NET")) {
            score += 0.4
        }

        // 规则2: 具有支付相关权限
        if (info.permission?.contains("android.permission.NFC") == true &&
            hasPermission(info, pm, "android.permission.BIND_NFC_SERVICE")) {
            score += 0.3
        }

        // 规则3: 应用类别为财务类
        when (info.category) {
            ApplicationInfo.CATEGORY_FINANCE -> score += 0.3
            ApplicationInfo.CATEGORY_PRODUCTIVITY -> score += 0.1
        }

        // 规则4: 包名匹配已知银行/支付模式
        val pkg = info.packageName.lowercase()
        val bankingPatterns = listOf("bank", "pay", "wallet", "finance", "chase", "wells", "fargo")
        if (bankingPatterns.any { pkg.contains(it) }) {
            score += 0.2
        }

        // 规则5: 应用使用 DRM 前端
        if (info.metaData?.containsKey("com.google.android.gms.car.application") == true) {
            score += 0.1
        }

        return score.coerceIn(0.0, 1.0)
    }

    /**
     * 扫描设备上所有已安装应用，返回建议加入 DenyList 的应用列表
     */
    suspend fun scanInstalledApps(
        pm: PackageManager,
        threshold: Double = 0.5
    ): List<Pair<ApplicationInfo, Double>> = withContext(Dispatchers.IO) {
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        apps.asSequence()
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 } // 排除系统应用
            .map { it to detectRiskLevel(it, pm) }
            .filter { it.second >= threshold }
            .sortedByDescending { it.second }
            .toList()
    }
}
```

#### 1.3.3 批量操作 API（Native 侧扩展）

**修改文件**：`native/src/core/deny/cli.cpp`

在 `DenyRequest` 枚举中新增批量操作码：

```cpp
// deny.hpp 新增
enum class DenyRequest {
    ENFORCE,
    DISABLE,
    ADD,
    REMOVE,
    LIST,
    STATUS,
    // 新增
    ADD_BATCH,    // 批量添加：客户端发送多个 pkg|proc 对
    REMOVE_BATCH, // 批量移除
    CLEAR_ALL,    // 清空 DenyList
    IMPORT,       // 从 JSON 导入
    EXPORT,       // 导出为 JSON
};
```

**批量添加实现** (`utils.cpp` 新增)：

```cpp
DenyResponse add_batch_list(int client) {
    mutex_guard lock(data_lock);
    ensure_data();

    int count;
    read_int(client, &count);

    int added = 0;
    for (int i = 0; i < count; i++) {
        string pkg = read_string(client);
        string proc = read_string(client);

        // 验证
        if (!validate(pkg, proc)) continue;

        // 检查是否已存在
        auto it = pkg_to_procs_.find(pkg);
        if (it != pkg_to_procs_.end() && it->second.count(proc)) continue;

        // 添加到内存和数据库
        auto &procs = pkg_to_procs_[pkg];
        if (procs.empty()) {
            // 新包，需要解析 app_id
            int app_id = get_app_id(pkg.data());
            if (app_id == 0) continue; // 未安装，跳过
            app_id_to_pkgs_[app_id].insert(pkg_to_procs_.find(pkg)->first);
        }
        procs.insert(proc);

        // 数据库插入（批量事务）
        sql_exec("INSERT OR IGNORE INTO denylist VALUES('%s','%s')",
                 pkg.c_str(), proc.c_str());
        added++;
    }

    // 如果正在执行，杀掉相关进程
    if (denylist_enforced) {
        // 重新扫描并杀进程
        scan_deny_apps();
    }

    return added > 0 ? DenyResponse::OK : DenyResponse::ERROR;
}
```

#### 1.3.4 社区规则订阅

**新增文件**：`app/core/src/main/java/com/topjohnwu/magisk/core/deny/RuleSubscription.kt`

```kotlin
class RuleSubscription(
    private val svc: NetworkService
) {
    // 订阅的 URL 列表（用户可配置）
    var subscriptionUrls by Config.preferenceStringSet("deny_subscriptions")

    // 上次更新时间
    var lastUpdate by Config.preferenceStrLong("deny_sub_last_update", 0L)

    /**
     * 拉取并合并所有订阅的规则
     */
    suspend fun fetchAndMerge(): Map<Category, List<PresetEntry>> = withContext(Dispatchers.IO) {
        val allRules = mutableMapOf<Category, MutableList<PresetEntry>>()

        // 合并内置规则
        DenyListPresets.builtin.forEach { (cat, entries) ->
            allRules.getOrPut(cat) { mutableListOf() }
                .addAll(entries.map { (pkg, procs) -> PresetEntry(pkg, procs) })
        }

        // 拉取远程订阅
        for (url in subscriptionUrls) {
            try {
                val json = svc.fetchText(url)
                val parsed = parsePresetsJson(json)
                parsed.forEach { (cat, entries) ->
                    allRules.getOrPut(cat) { mutableListOf() }.addAll(entries)
                }
            } catch (e: Exception) {
                // 记录失败但继续其他订阅
                Timber.w(e, "Failed to fetch denylist subscription: $url")
            }
        }

        allRules
    }

    /**
     * 应用规则到 DenyList
     */
    suspend fun applyRules(rules: Map<Category, List<PresetEntry>>) {
        val installedApps = pm.getInstalledApplications(0).map { it.packageName }.toSet()

        val toAdd = mutableListOf<Pair<String, String>>()
        rules.values.flatten().forEach { entry ->
            if (entry.pkg in installedApps) {
                if (entry.procs.isEmpty()) {
                    toAdd.add(entry.pkg to entry.pkg) // 主进程
                } else {
                    entry.procs.forEach { proc ->
                        toAdd.add(entry.pkg to proc)
                    }
                }
            }
        }

        // 通过新的批量 API 一次性添加
        Shell.cmd("magisk --denylist add_batch ${toAdd.size} " +
            toAdd.joinToString(" ") { "${it.first}|${it.second}" }
        ).submit()
    }
}
```

#### 1.3.5 UI 扩展

**修改文件**：`app/apk/src/main/java/com/topjohnwu/magisk/ui/deny/DenyListFragment.kt`

在现有菜单 `menu_deny_md2.xml` 中新增：

```xml
<!-- menu_deny_md2.xml 新增 -->
<item
    android:id="@+id/action_smart_detect"
    android:title="@string/deny_smart_detect"
    app:showAsAction="never" />

<item
    android:id="@+id/action_presets"
    android:title="@string/deny_presets"
    app:showAsAction="never" />
```

**新增 Dialog**：`app/apk/src/main/java/com/topjohnwu/magisk/dialog/SmartDetectDialog.kt`

展示自动检测结果，按风险等级排序，支持批量勾选。

### 1.4 回退实现方案

如果上述高级方案因 Android 版本限制或性能问题不可行，采用以下回退方案：

#### 回退方案 A：纯预设列表（无自动检测）

移除 `AutoDetector` 的权限分析逻辑，仅依赖硬编码包名列表：

```kotlin
object DenyListPresets {
    // 简化为纯包名列表，不做任何运行时分析
    val banking = setOf(
        "com.chase.sig.android",
        "com.bankofamerica.mobilebanking",
        // ...
    )

    fun applyPreset(category: String, installedApps: Set<String>) {
        val targets = when (category) {
            "banking" -> banking
            else -> emptySet()
        }.intersect(installedApps)

        // 逐个添加（回退到现有 add 命令，不使用批量 API）
        targets.forEach { pkg ->
            Shell.cmd("magisk --denylist add $pkg").submit()
        }
    }
}
```

**优点**：无需修改 native 层，完全复用现有 `add` 命令。
**缺点**：无自动检测能力，列表需手动维护。

#### 回退方案 B：基于 Intent Filter 的简单分类

```kotlin
fun detectByIntentFilter(pm: PackageManager, info: ApplicationInfo): Boolean {
    // 检查应用是否声明了支付相关 Intent
    val paymentActions = listOf(
        "android.intent.action.PAYMENT",
        "android.nfc.action.TECH_DISCOVERED"
    )
    return pm.queryIntentActivitiesAsUser(
        Intent("android.intent.action.PAYMENT"),
        PackageManager.GET_RESOLVED_FILTER, 0
    ).any { it.activityInfo.packageName == info.packageName }
}
```

#### 回退方案 C：用户手动导入/导出

不实现自动检测，仅提供导入/导出 DenyList 配置的能力：

```kotlin
// 导出当前 DenyList 为 JSON
fun exportDenyList(): String {
    val list = Shell.cmd("magisk --denylist ls").exec().out
    val entries = list.map { line ->
        val (pkg, proc) = line.split("|")
        JsonObject().apply {
            put("pkg", pkg)
            put("proc", proc)
        }
    }
    return JsonObject().apply {
        put("version", 1)
        put("entries", JsonArray(entries))
    }.toString()
}

// 从 JSON 导入
fun importDenyList(json: String) {
    val arr = JsonObject(json).getJsonArray("entries")
    arr?.forEach { entry ->
        val obj = entry.asJsonObject
        Shell.cmd("magisk --denylist add ${obj.getString("pkg")} '${obj.getString("proc")}'").submit()
    }
}
```

### 1.5 涉及文件清单

| 操作 | 文件路径 | 说明 |
|------|---------|------|
| 新增 | `app/core/src/main/java/com/topjohnwu/magisk/core/deny/Presets.kt` | 预设规则库 |
| 新增 | `app/core/src/main/java/com/topjohnwu/magisk/core/deny/AutoDetector.kt` | 自动检测引擎 |
| 新增 | `app/core/src/main/java/com/topjohnwu/magisk/core/deny/RuleSubscription.kt` | 社区规则订阅 |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/dialog/SmartDetectDialog.kt` | 智能检测对话框 |
| 修改 | `native/src/core/deny/deny.hpp` | 新增批量请求枚举 |
| 修改 | `native/src/core/deny/cli.cpp` | 批量命令处理 |
| 修改 | `native/src/core/deny/utils.cpp` | `add_batch_list`、`clear_all` 实现 |
| 修改 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/deny/DenyListFragment.kt` | 菜单入口 |
| 修改 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/deny/DenyListViewModel.kt` | 智能检测逻辑 |
| 修改 | `app/apk/src/main/res/menu/menu_deny_md2.xml` | 新增菜单项 |
| 修改 | `app/core/src/main/res/values/strings.xml` | 新增字符串资源 |
| 修改 | `app/core/src/main/java/com/topjohnwu/magisk/core/Config.kt` | 订阅配置项 |

---

## 2. 安全审计仪表盘

### 2.1 功能概述

在首页或独立页面中增加安全状态面板，集中展示：
- Magisk 运行状态（版本、守护进程、环境完整性）
- SELinux 状态（Enforcing/Permissive、上下文）
- 磁盘加密类型（FDE/FBE/None）
- Zygisk 状态与已加载模块
- DenyList 执行状态
- Root 授权统计（已授权/已拒绝应用数）
- Boot 布局信息（SAR、A/B、Slot、Ramdisk）
- 潜在风险提醒（模拟器、未锁屏、旧版本等）

### 2.2 现有架构回顾

#### 已采集但未展示的安全数据

| 数据 | 来源 | 当前是否展示 |
|------|------|-------------|
| Magisk 版本/版本码 | `Info.env` (via `magisk -v`/`-V`) | 首页展示 |
| Zygisk 启用状态 | `Info.isZygiskEnabled` (via `ZYGISK_ENABLED` 环境变量) | 首页展示 |
| Ramdisk 存在 | `Info.ramdisk` (via `app_init`) | 首页展示 |
| SELinux 状态 | **未采集** | ❌ |
| 加密类型 | `Info.crypto` / `Info.isFDE` (via `app_init` 的 `CRYPTOTYPE`) | ❌ |
| DenyList 状态 | `Config.denyList` (via `magisk --denylist status`) | 设置页展示 |
| SAR 布局 | `Info.isSAR` / `Info.legacySAR` | ❌ |
| A/B 分区 | `Info.isAB` / `Info.slot` | ❌ |
| Vendor Boot | `Info.isVendorBoot` | ❌ |
| VbMeta 补丁标志 | `Info.patchBootVbmeta` | ❌ |
| 模拟器检测 | `Info.isEmulator` | ❌ |
| 设备安全（锁屏） | `Info.isDeviceSecure` | ❌ |
| SU 授权统计 | `settings` DB 中的 `root_access` + `su` 表 | ❌ |
| Bootloop 计数 | `Config.bootloop` (DB) | ❌ |
| Magisk 路径 | `magisk --path` → `get_magisk_tmp()` | ❌ |

#### App ↔ Native 通信通道

**通道1：Shell (libsu)**
- `fastCmd(shell, "magisk -v")` → 版本字符串
- `fastCmdResult(shell, "magisk --denylist status")` → 布尔值
- `shell.newJob().add("(app_init)").to(list).exec()` → 批量环境变量

**通道2：Daemon Unix Socket** (`<magisk_tmp>/.magisk/socket`)
- `RequestCode` 枚举分发
- 每连接检查 `peer_cred` + `SO_PEERSEC` (SELinux 上下文)
- 同步请求：`CHECK_VERSION`、`CHECK_VERSION_CODE`
- 异步请求：`DENYLIST`、`SQLITE_CMD`、`ZYGISK`

#### SELinux 相关代码 (`native/src/core/selinux.rs`)

```rust
const UNLABEL_CON: &str = "u:object_r:unlabeled:s0";
const SYSTEM_CON: &str = "u:object_r:system_file:s0";
const ADB_CON: &str = "u:object_r:adb_data_file:s0";
const ROOT_CON: &str = "u:object_r:rootfs:s0";

// restorecon() — 重标记 SECURE_DIR、MODULEROOT、DATABIN
// restore_tmpcon() — 重标记 tmpfs (/sbin → ROOT_CON)
// lgetfilecon/setfilecon — 安全包装
```

#### 首页布局 (`app/apk/src/main/res/layout/include_home_magisk.xml`)

当前仅展示三行信息：Installed Version、Zygisk、Ramdisk。已导入 `Info` 类可直接绑定新数据。

### 2.3 高级实现方案

#### 2.3.1 安全数据采集层

**新增文件**：`app/core/src/main/java/com/topjohnwu/magisk/core/security/SecurityAudit.kt`

```kotlin
object SecurityAudit {

    data class AuditReport(
        val magiskStatus: MagiskStatus,
        val selinuxStatus: SelinuxStatus,
        val encryptionStatus: EncryptionStatus,
        val bootLayout: BootLayout,
        val zygiskStatus: ZygiskStatus,
        val denyListStatus: DenyListStatus,
        val suStatistics: SuStatistics,
        val riskAssessment: List<RiskItem>
    )

    data class MagiskStatus(
        val version: String,
        val versionCode: Int,
        val isActive: Boolean,
        val isDebug: Boolean,
        val isUnsupported: Boolean,
        val magiskPath: String,
        val envValid: Boolean
    )

    data class SelinuxStatus(
        val mode: SelinuxMode,       // ENFORCING / PERMISSIVE / DISABLED
        val context: String,         // 当前进程的 SELinux 上下文
        val isMagiskDomain: Boolean  // 守护进程是否运行在 magisk 域
    )

    enum class SelinuxMode { ENFORCING, PERMISSIVE, DISABLED }

    data class EncryptionStatus(
        val type: EncryptionType,    // FDE / FBE / NONE
        val cryptoType: String       // 原始值: "block", "file", "aes-xts", etc.
    )

    enum class EncryptionType { FDE, FBE, NONE }

    data class BootLayout(
        val isSAR: Boolean,
        val isLegacySAR: Boolean,
        val isAB: Boolean,
        val slot: String,
        val hasRamdisk: Boolean,
        val isVendorBoot: Boolean,
        val patchBootVbmeta: Boolean
    )

    data class ZygiskStatus(
        val enabled: Boolean,
        val loadedModuleCount: Int,
        val moduleNames: List<String>
    )

    data class DenyListStatus(
        val enforced: Boolean,
        val targetCount: Int,
        val enforcementMode: String  // "zygisk" or "logcat"
    )

    data class SuStatistics(
        val rootAccessMode: Int,     // Config.Value.ROOT_ACCESS_*
        val allowedApps: Int,
        val deniedApps: Int,
        val totalRequests: Int,
        val multiuserMode: Int,
        val namespaceMode: Int,
        val biometricEnabled: Boolean,
        val reauthEnabled: Boolean
    )

    data class RiskItem(
        val level: RiskLevel,        // HIGH / MEDIUM / LOW
        val title: String,
        val description: String,
        val action: String?          // 可选的修复动作描述
    )

    enum class RiskLevel { HIGH, MEDIUM, LOW }

    /**
     * 收集完整安全审计报告
     */
    suspend fun collect(shell: Shell, context: Context): AuditReport = withContext(Dispatchers.IO) {
        val magiskStatus = collectMagiskStatus(shell)
        val selinuxStatus = collectSelinuxStatus(shell)
        val encryptionStatus = collectEncryptionStatus()
        val bootLayout = collectBootLayout()
        val zygiskStatus = collectZygiskStatus(shell)
        val denyListStatus = collectDenyListStatus(shell)
        val suStatistics = collectSuStatistics(shell)
        val riskAssessment = assessRisks(
            magiskStatus, selinuxStatus, encryptionStatus,
            bootLayout, zygiskStatus, denyListStatus, suStatistics
        )

        AuditReport(
            magiskStatus, selinuxStatus, encryptionStatus,
            bootLayout, zygiskStatus, denyListStatus, suStatistics,
            riskAssessment
        )
    }

    private fun collectSelinuxStatus(shell: Shell): SelinuxStatus {
        // 读取 /sys/fs/selinux/enforce
        val enforce = fastCmd(shell, "cat /sys/fs/selinux/enforce").trim()
        val mode = when (enforce) {
            "1" -> SelinuxMode.ENFORCING
            "0" -> SelinuxMode.PERMISSIVE
            else -> SelinuxMode.DISABLED
        }

        // 读取当前进程上下文
        val context = fastCmd(shell, "cat /proc/self/attr/current").trim()

        // 检查 magisk 守护进程是否在 magisk 域
        val magiskCon = fastCmd(shell, "cat /proc/\$(pidof magiskd)/attr/current 2>/dev/null").trim()
        val isMagiskDomain = magiskCon.contains("magisk")

        return SelinuxStatus(mode, context, isMagiskDomain)
    }

    private fun collectZygiskStatus(shell: Shell): ZygiskStatus {
        val enabled = Info.isZygiskEnabled

        // 列出已加载的 Zygisk 模块
        val modules = if (enabled) {
            val moduleDir = File(Const.MODULE_PATH)
            moduleDir.listFiles()
                ?.filter { it.isDirectory && File(it, "zygisk").isDirectory }
                ?.mapNotNull { dir ->
                    val prop = File(dir, "module.prop")
                    if (prop.exists()) {
                        prop.readLines()
                            .firstOrNull { it.startsWith("name=") }
                            ?.removePrefix("name=")
                    } else null
                } ?: emptyList()
        } else emptyList()

        return ZygiskStatus(enabled, modules.size, modules)
    }

    private fun collectSuStatistics(shell: Shell): SuStatistics {
        // 查询 magisk 数据库中的 SU 策略
        val result = Shell.cmd("magisk --sqlite 'SELECT policy, COUNT(*) FROM su GROUP BY policy'").exec()
        var allowed = 0
        var denied = 0
        result.out.forEach { line ->
            // 解析 "policy=2|count=5" 格式
            val parts = line.split("|")
            val policy = parts.firstOrNull { it.startsWith("policy=") }?.removePrefix("policy=")?.toIntOrNull()
            val count = parts.firstOrNull { it.startsWith("count=") }?.removePrefix("count=")?.toIntOrNull() ?: 0
            when (policy) {
                Config.Value.SU_AUTO_ALLOW -> allowed = count
                Config.Value.SU_AUTO_DENY -> denied = count
            }
        }

        return SuStatistics(
            rootAccessMode = Config.rootMode,
            allowedApps = allowed,
            deniedApps = denied,
            totalRequests = allowed + denied,
            multiuserMode = Config.suMultiuserMode,
            namespaceMode = Config.suMntNamespaceMode,
            biometricEnabled = Config.suAuth,
            reauthEnabled = Config.suReAuth
        )
    }

    private fun assessRisks(
        magisk: MagiskStatus,
        selinux: SelinuxStatus,
        encryption: EncryptionStatus,
        boot: BootLayout,
        zygisk: ZygiskStatus,
        denyList: DenyListStatus,
        su: SuStatistics
    ): List<RiskItem> {
        val risks = mutableListOf<RiskItem>()

        // 风险1: SELinux 处于 Permissive 模式
        if (selinux.mode == SelinuxMode.PERMISSIVE) {
            risks.add(RiskItem(
                RiskLevel.HIGH,
                "SELinux Permissive",
                "SELinux 处于宽容模式，系统安全防护被削弱",
                "将 SELinux 恢复为 Enforcing 模式"
            ))
        }

        // 风险2: SELinux 被禁用
        if (selinux.mode == SelinuxMode.DISABLED) {
            risks.add(RiskItem(
                RiskLevel.HIGH,
                "SELinux Disabled",
                "SELinux 已被完全禁用，极度危险",
                null
            ))
        }

        // 风险3: Magisk 版本过低
        if (magisk.isUnsupported) {
            risks.add(RiskItem(
                RiskLevel.HIGH,
                "Outdated Magisk",
                "当前 Magisk 版本过低，可能存在安全漏洞",
                "升级到最新版本"
            ))
        }

        // 风险4: Root 对所有应用开放且无认证
        if (su.rootAccessMode == Config.Value.ROOT_ACCESS_APPS_AND_ADB &&
            !su.biometricEnabled && su.reauthEnabled.not()
        ) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "Root Access Without Authentication",
                "Root 权限对所有应用开放且未启用生物认证",
                "启用 SU 生物认证或限制 Root 访问范围"
            ))
        }

        // 风险5: 模拟器环境
        if (Info.isEmulator) {
            risks.add(RiskItem(
                RiskLevel.LOW,
                "Emulator Environment",
                "检测到模拟器环境，部分功能可能受限",
                null
            ))
        }

        // 风险6: Zygisk 已启用但 DenyList 未执行
        if (zygisk.enabled && !denyList.enforced) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "Zygisk Without DenyList",
                "Zygisk 已启用但 DenyList 未执行，Magisk 可能被检测",
                "启用 DenyList 执行"
            ))
        }

        // 风险7: 设备未设置锁屏
        if (!Info.isDeviceSecure) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "No Screen Lock",
                "设备未设置锁屏，Root 权限无物理保护",
                "设置屏幕锁定"
            ))
        }

        // 风险8: Bootloop 计数器异常
        if (Config.bootloop > 2) {
            risks.add(RiskItem(
                RiskLevel.MEDIUM,
                "Bootloop Detected",
                "检测到多次启动失败 (${Config.bootloop} 次)，可能由模块引起",
                "检查最近安装的模块或进入安全模式"
            ))
        }

        return risks.sortedBy { it.level.ordinal }
    }
}
```

#### 2.3.2 UI 布局

**新增布局文件**：`app/apk/src/main/res/layout/include_security_audit.xml`

```xml
<!-- 安全审计面板，嵌入到首页或作为独立 Fragment -->
<com.google.android.material.card.MaterialCardView
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    app:cardCornerRadius="@dimen/l2">

    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:orientation="vertical"
        android:padding="@dimen/l2">

        <!-- 标题栏 -->
        <LinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:orientation="horizontal">

            <TextView
                android:layout_width="0dp"
                android:layout_weight="1"
                android:layout_height="wrap_content"
                android:text="@string/security_audit_title"
                android:textAppearance="@style/AppearanceTitle" />

            <!-- 风险等级徽章 -->
            <com.google.android.material.chip.Chip
                android:id="@+id/risk_badge"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="@string/risk_low" />
        </LinearLayout>

        <!-- 安全状态网格 -->
        <androidx.gridlayout.widget.GridLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            app:columnCount="2">

            <!-- SELinux 状态 -->
            <include layout="@layout/item_security_status"
                app:layout_columnWeight="1"
                bind:title="@{@string/selinux_status}"
                bind:value="@{viewModel.selinuxMode}"
                bind:statusColor="@{viewModel.selinuxColor}" />

            <!-- 加密状态 -->
            <include layout="@layout/item_security_status"
                app:layout_columnWeight="1"
                bind:title="@{@string/encryption_status}"
                bind:value="@{viewModel.encryptionType}"
                bind:statusColor="@{viewModel.encryptionColor}" />

            <!-- Root 授权模式 -->
            <include layout="@layout/item_security_status"
                app:layout_columnWeight="1"
                bind:title="@{@string/root_access_mode}"
                bind:value="@{viewModel.rootAccessModeText}"
                bind:statusColor="@{viewModel.rootAccessColor}" />

            <!-- DenyList 状态 -->
            <include layout="@layout/item_security_status"
                app:layout_columnWeight="1"
                bind:title="@{@string/denylist_status}"
                bind:value="@{viewModel.denyListStatusText}"
                bind:statusColor="@{viewModel.denyListColor}" />

        </androidx.gridlayout.widget.GridLayout>

        <!-- 风险提醒列表 -->
        <androidx.recyclerview.widget.RecyclerView
            android:id="@+id/risk_list"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:nestedScrollingEnabled="false"
            bind:items="@{viewModel.riskItems}" />

        <!-- Boot 布局信息（可折叠） -->
        <com.google.android.material.expandable.ExpandableLinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content">

            <include layout="@layout/include_boot_layout_info"
                bind:isSAR="@{Info.isSAR}"
                bind:isAB="@{Info.isAB}"
                bind:slot="@{Info.slot}"
                bind:hasRamdisk="@{Info.ramdisk}"
                bind:isVendorBoot="@{Info.isVendorBoot}" />

        </com.google.android.material.expandable.ExpandableLinearLayout>

    </LinearLayout>
</com.google.android.material.card.MaterialCardView>
```

#### 2.3.3 ViewModel 集成

**修改文件**：`app/apk/src/main/java/com/topjohnwu/magisk/ui/home/HomeViewModel.kt`

```kotlin
// 新增字段
val auditReport = MutableLiveData<SecurityAudit.AuditReport>()
val selinuxMode: String get() = auditReport.value?.selinuxStatus?.mode?.name ?: "UNKNOWN"
val selinuxColor: Int get() = when (auditReport.value?.selinuxStatus?.mode) {
    SecurityAudit.SelinuxMode.ENFORCING -> color(R.color.status_ok)
    SecurityAudit.SelinuxMode.PERMISSIVE -> color(R.color.status_warning)
    SecurityAudit.SelinuxMode.DISABLED -> color(R.color.status_error)
    else -> color(R.color.status_unknown)
}
val riskItems: LiveData<List<RiskRvItem>> = auditReport.map { report ->
    report.riskAssessment.map { RiskRvItem(it) }
}

// 在 doLoadWork 中添加审计收集
override suspend fun doLoadWork() {
    // ... 现有逻辑 ...

    // 收集安全审计数据
    if (Info.isRooted) {
        SecurityAudit.collect(Shell.getShell(), AppContext).let { report ->
            auditReport.postValue(report)
        }
    }
}
```

### 2.4 回退实现方案

#### 回退方案 A：简化数据采集（不查询数据库）

如果 `magisk --sqlite` 查询性能不佳或不可用，移除 SU 统计部分，仅使用已有 `Info` 字段：

```kotlin
object SecurityAudit {
    suspend fun collectBasic(): AuditReport {
        // 完全不新增 shell 命令，仅使用 Info 中已采集的数据
        val selinuxMode = try {
            val enforce = File("/sys/fs/selinux/enforce").readText().trim()
            if (enforce == "1") SelinuxMode.ENFORCING else SelinuxMode.PERMISSIVE
        } catch (e: Exception) {
            SelinuxMode.DISABLED
        }

        return AuditReport(
            magiskStatus = MagiskStatus(
                version = Info.env.versionString,
                versionCode = Info.env.versionCode,
                isActive = Info.env.isActive,
                isDebug = Info.env.isDebug,
                isUnsupported = Info.env.isUnsupported,
                magiskPath = "",
                envValid = true
            ),
            selinuxStatus = SelinuxStatus(selinuxMode, "", false),
            encryptionStatus = EncryptionStatus(
                if (Info.isFDE) EncryptionType.FDE
                else if (Info.crypto.isNotEmpty()) EncryptionType.FBE
                else EncryptionType.NONE,
                Info.crypto
            ),
            bootLayout = BootLayout(
                Info.isSAR, Info.legacySAR, Info.isAB, Info.slot,
                Info.ramdisk, Info.isVendorBoot, Info.patchBootVbmeta
            ),
            zygiskStatus = ZygiskStatus(Info.isZygiskEnabled, 0, emptyList()),
            denyListStatus = DenyListStatus(Config.denyList, 0, ""),
            suStatistics = SuStatistics(
                Config.rootMode, 0, 0, 0,
                Config.suMultiuserMode, Config.suMntNamespaceMode,
                Config.suAuth, Config.suReAuth
            ),
            riskAssessment = emptyList()
        )
    }
}
```

**优点**：零额外 shell 调用，启动无延迟。
**缺点**：无 SELinux 上下文、无 Zygisk 模块列表、无 SU 统计、无风险评估。

#### 回退方案 B：延迟加载（先展示骨架，后台填充）

```kotlin
// 先用 Info 立即填充已知数据
fun loadQuickAudit(): AuditReport {
    // 使用 Info 中的数据立即返回（同回退方案 A）
}

// 后台异步补充需要 shell 的数据
fun loadFullAudit(shell: Shell, onComplete: (AuditReport) -> Unit) {
    viewModelScope.launch {
        val quick = loadQuickAudit()
        auditReport.value = quick  // 立即展示

        // 异步补充
        val selinux = async { collectSelinuxStatus(shell) }
        val zygisk = async { collectZygiskStatus(shell) }
        val denyList = async { collectDenyListStatus(shell) }
        val suStats = async { collectSuStatistics(shell) }

        val full = quick.copy(
            selinuxStatus = selinux.await(),
            zygiskStatus = zygisk.await(),
            denyListStatus = denyList.await(),
            suStatistics = suStats.await()
        )
        auditReport.value = full  // 更新为完整数据
        onComplete(full)
    }
}
```

#### 回退方案 C：独立 Fragment（不修改首页）

不将审计面板嵌入首页，而是创建独立 Fragment 并在导航图中添加入口：

```xml
<!-- navigation/main.xml 新增 -->
<fragment
    android:id="@+id/securityAuditFragment"
    android:name="com.topjohnwu.magisk.ui.security.SecurityAuditFragment"
    android:label="SecurityAuditFragment" />
```

在设置页添加入口项，避免首页布局过于拥挤。

### 2.5 涉及文件清单

| 操作 | 文件路径 | 说明 |
|------|---------|------|
| 新增 | `app/core/src/main/java/com/topjohnwu/magisk/core/security/SecurityAudit.kt` | 审计数据采集 |
| 新增 | `app/apk/src/main/res/layout/include_security_audit.xml` | 审计面板布局 |
| 新增 | `app/apk/src/main/res/layout/item_security_status.xml` | 单项状态布局 |
| 新增 | `app/apk/src/main/res/layout/include_boot_layout_info.xml` | Boot 布局信息 |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/security/RiskRvItem.kt` | 风险项 RecyclerView 项 |
| 修改 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/home/HomeViewModel.kt` | 审计数据绑定 |
| 修改 | `app/apk/src/main/res/layout/fragment_home_md2.xml` | 嵌入审计面板 |
| 修改 | `app/core/src/main/res/values/strings.xml` | 新增字符串 |
| 修改 | `app/core/src/main/res/values/colors.xml` | 状态颜色 (ok/warning/error) |

---

## 3. 属性浏览器 / Boot 分析器

### 3.1 功能概述

将现有的 `resetprop`（属性操作）和 `magiskboot`（启动镜像分析）命令行工具以可视化 UI 形式呈现：

**属性浏览器**：
- 浏览所有系统属性（分组：`ro.`、`persist.`、`sys.`、`hw.`、`dalvik.` 等）
- 搜索/过滤属性
- 查看属性 SELinux 上下文
- 修改/删除/持久化属性（需 Root）
- 收藏常用属性

**Boot 分析器**：
- 选择并解析本地 boot image 文件
- 展示 header 信息（版本、页大小、OS 版本、cmdline）
- 展示分区结构（kernel、ramdisk、dtb 等的大小和压缩格式）
- 展示 OEM 特殊标志（ChromeOS、Samsung DHTB、MTK 等）
- 展示 ramdisk 内容树（cpio 文件列表）
- 展示 DTB fstab 信息
- 预览 Magisk 补丁将要应用的修改

### 3.2 现有架构回顾

#### 3.2.1 resetprop 架构

**CLI 入口** (`native/src/core/resetprop/cli.rs`):

| 参数 | 功能 |
|------|------|
| `-v` | 详细输出 |
| `-w` | 等待属性变化 |
| `-p` | 同时操作持久化存储 |
| `-P` | 仅操作持久化存储 |
| `-Z` | 获取 SELinux 上下文 |
| `-n` | 绕过 property_service（直接内存修改） |
| `-f FILE` | 从文件加载属性 |
| `-d NAME` | 删除属性 |

**核心 API** (`native/src/core/resetprop/mod.rs`):

```rust
pub struct SysProp {
    set: fn(*const c_char, *const c_char) -> i32,
    find: fn(*const c_char) -> *const PropInfo,
    read_callback: fn(*const PropInfo, ...),
    foreach: fn(...),
    wait: fn(*const PropInfo, *const PropInfo),
}
```

- `find`/`find_mut` — 使用 `__system_property_find2`
- `add` — `__system_property_add2`
- `update` — `__system_property_update2`
- `delete` — `__system_property_delete(key, prune)`
- `for_each` — 遍历所有属性
- `get_context` — 获取属性的 SELinux 上下文

**持久化后端** (`native/src/core/resetprop/persist.rs`):
- Android Q+：Protobuf 格式 (`/data/property/persistent_properties`)
- Pre-Q：纯文本文件 (`/data/property/<name>`)

**App 侧当前无 resetprop UI**，仅在安装流程中通过 shell 间接使用。

#### 3.2.2 magiskboot 架构

**CLI 子命令** (`native/src/boot/cli.rs`):

| 子命令 | 功能 |
|--------|------|
| `unpack [-n] [-h] <bootimg>` | 解包 boot image |
| `repack [-n] <orig> [out]` | 重新打包 |
| `verify <bootimg> [cert]` | 验证 AVB 1.0 签名 |
| `sign <bootimg> [name] [cert key]` | 签名 |
| `extract <payload.bin> [part] [out]` | 从 payload.bin 提取分区 |
| `hexpatch <file> <pat1> <pat2>` | 十六进制搜索替换 |
| `cpio <incpio> [cmds...]` | cpio 操作 |
| `dtb <file> <action>` | DTB 操作 |
| `split [-n] <file>` | 分离 kernel 和 kernel_dtb |
| `sha1 <file>` | 计算 SHA1 |
| `cleanup` | 清理生成文件 |
| `compress[=fmt] <in> [out]` | 压缩 |
| `decompress <in> [out]` | 解压 |

**支持的 Boot Image Header 版本** (`native/src/boot/bootimg.hpp`):
- AOSP v0/v1/v2/v3/v4
- AOSP vendor v3/v4
- Samsung PXA

**OEM 特殊格式检测** (`native/src/boot/bootimg.cpp` flags):
- ChromeOS (`CHROMEOS`)
- Samsung DHTB (`DHTB_MAGIC`)
- Tegra BLOB (`TEGRABLOB_MAGIC`)
- MTK kernel/ramdisk (`MTK_MAGIC`)
- NOOKHD / ACCLAIM / AMONET（预头部偏移）
- SEANDROID trailer
- LG BUMP trailer
- zImage kernel (`ZIMAGE_MAGIC`)
- AVB 1.0 签名
- AVB footer + vbmeta

**压缩格式** (`native/src/boot/format.rs`):
- 可解压：GZIP、ZOPFLI、XZ、LZMA、BZIP2、LZ4、LZ4_LEGACY、LZ4_LG
- 可检测：LZOP

**当前 App 调用方式** (`app/core/src/main/java/com/topjohnwu/magisk/core/tasks/MagiskInstaller.kt`):

```
extractFiles() → 解压 libmagiskboot.so 和脚本到 installDir
processFile(uri) → 嗅探文件类型 (tar/payload.bin/zip/raw)
patchBoot() → 执行 sh boot_patch.sh $srcBoot
```

`boot_patch.sh` 依次调用：`unpack` → `cpio test` → `cpio patch` → `cpio add` → `dtb test/patch` → `hexpatch` → `repack`

### 3.3 高级实现方案

#### 3.3.1 属性浏览器

##### A. Native 侧：新增结构化输出命令

**修改文件**：`native/src/core/resetprop/cli.rs`

新增 `--json` 参数支持，输出 JSON 格式便于 App 解析：

```rust
// 在 ResetProp 结构体中新增
struct ResetProp {
    // ... 现有字段 ...
    #[argh(switch, short = 'j')]
    json: bool,       // JSON 格式输出
    #[argh(switch, short = 'a')]
    all: bool,        // 列出所有属性
}

// 列出所有属性的 JSON 输出
fn list_all_json() {
    let mut props: BTreeMap<String, PropInfo> = BTreeMap::new();

    SYS_PROP.for_each(|key, val| {
        let context = SYS_PROP.get_context(key).unwrap_or_default();
        props.insert(key.to_string(), PropInfo {
            value: val.to_string(),
            context: context.to_string(),
            persistent: key.starts_with("persist."),
        });
    });

    // 也读取持久化存储中的属性
    for (key, val) in persist_get_all_props() {
        props.entry(key).or_insert_with(|| PropInfo {
            value: val,
            context: String::new(),
            persistent: true,
        });
    }

    let json = serde_json::to_string_pretty(&props).unwrap();
    println!("{}", json);
}
```

##### B. App 侧：属性浏览器 ViewModel

**新增文件**：`app/apk/src/main/java/com/topjohnwu/magisk/ui/props/PropsViewModel.kt`

```kotlin
class PropsViewModel : AsyncLoadViewModel() {

    data class PropItem(
        val key: String,
        val value: String,
        val context: String,
        val isPersistent: Boolean,
        val isReadOnly: Boolean,
        var isFavorite: Boolean
    ) : ComparableRvItem<PropItem>() {
        override val layoutRes = R.layout.item_prop
        // ... binding 逻辑 ...

        val category: String get() = key.substringBefore(".", key)
        val displayValue: String get() = if (value.length > 100) value.take(97) + "..." else value
    }

    val items = filterList<PropItem>(viewModelScope)
    val query = MutableLiveData("")

    // 分类过滤
    val categories = MutableLiveData<List<String>>()
    val selectedCategory = MutableLiveData<String?>(null)

    // 收藏列表（持久化到 SharedPreferences）
    private val favorites = AppContext.getSharedPreferences("prop_favorites", 0)
        .getStringSet("keys", emptySet()) ?: emptySet()

    override suspend fun doLoadWork() {
        val shell = Shell.getShell()

        // 获取所有属性（使用新增的 --json --all 模式）
        val result = shell.newJob()
            .add("magisk --resetprop -j -a")
            .to(ArrayList<String>())
            .exec()

        val json = result.out.joinToString("")
        val allProps = parsePropsJson(json)

        // 按类别分组
        val cats = allProps.map { it.category }.distinct().sorted()
        categories.postValue(cats)

        items.postValue(allProps)
    }

    fun modifyProp(key: String, newValue: String, persist: Boolean, bypassSvc: Boolean) {
        val cmd = buildString {
            append("magisk --resetprop")
            if (persist) append(" -p")
            if (bypassSvc) append(" -n")
            append(" \"$key\" \"$newValue\"")
        }
        Shell.cmd(cmd).submit { result ->
            if (result.isSuccess) {
                // 刷新列表
                doLoadWork()
            }
        }
    }

    fun deleteProp(key: String, persist: Boolean) {
        val cmd = "magisk --resetprop -d${if (persist) " -p" else ""} \"$key\""
        Shell.cmd(cmd).submit {
            doLoadWork()
        }
    }

    fun toggleFavorite(key: String) {
        val set = favorites.toMutableSet()
        if (key in set) set.remove(key) else set.add(key)
        AppContext.getSharedPreferences("prop_favorites", 0)
            .edit().putStringSet("keys", set).apply()
        doLoadWork()
    }
}
```

##### C. 属性浏览器 UI

**新增布局**：`app/apk/src/main/res/layout/fragment_props_md2.xml`

```xml
<LinearLayout orientation="vertical">
    <!-- 搜索栏 + 类别筛选 -->
    <com.google.android.material.textfield.TextInputLayout>
        <com.google.android.material.textfield.TextInputEditText
            android:id="@+id/search_bar"
            bind:text="@={viewModel.query}" />
    </com.google.android.material.textfield.TextInputLayout>

    <!-- 类别 Chip 横向滚动 -->
    <com.google.android.material.chip.ChipGroup
        android:id="@+id/category_chips"
        app:singleSelection="true"
        bind:items="@{viewModel.categoryChips}" />

    <!-- 属性列表 -->
    <androidx.recyclerview.widget.RecyclerView
        android:id="@+id/props_list"
        bind:items="@{viewModel.items}" />
</LinearLayout>
```

**新增布局**：`app/apk/src/main/res/layout/item_prop.xml`

```xml
<MaterialCardView>
    <LinearLayout orientation="vertical">
        <!-- Key + 类别标签 + 收藏按钮 -->
        <LinearLayout orientation="horizontal">
            <TextView bind:text="@{item.key}" />
            <Chip bind:text="@{item.category}" />
            <ImageButton bind:src="@{item.isFavorite ? @ic_star : @ic_star_outline}"
                bind:onClick="@{() -> item.toggleFavorite()}" />
        </LinearLayout>

        <!-- Value -->
        <TextView bind:text="@{item.displayValue}" />

        <!-- SELinux 上下文（展开时显示） -->
        <TextView bind:text="@{item.context}"
            bind:visible="@{item.expanded}"
            android:fontFamily="monospace" />

        <!-- 操作按钮（展开时显示） -->
        <LinearLayout bind:visible="@{item.expanded}">
            <Button android:text="@{item.isReadOnly ? @string/modify_bypass : @string/modify}"
                bind:onClick="@{() -> viewModel.showModifyDialog(item)}" />
            <Button android:text="@string/delete"
                bind:onClick="@{() -> viewModel.showDeleteDialog(item)}" />
        </LinearLayout>
    </LinearLayout>
</MaterialCardView>
```

#### 3.3.2 Boot 分析器

##### A. Native 侧：新增 analyze 子命令

**修改文件**：`native/src/boot/cli.rs`

```rust
// 新增 Action 枚举变体
enum Action {
    Unpack(UnpackArgs),
    Repack(RepackArgs),
    // ... 现有变体 ...
    Analyze(AnalyzeArgs),  // 新增
}

/// 分析 boot image 并输出 JSON
struct AnalyzeArgs {
    #[argh(positional)]
    bootimg: PathBuf,

    #[argh(switch, short = 'j')]
    json: bool,  // JSON 输出

    #[argh(switch, short = 'r')]
    ramdisk_listing: bool,  // 包含 ramdisk 文件列表

    #[argh(switch, short = 'd')]
    dtb_info: bool,  // 包含 DTB 信息
}

fn analyze(args: &AnalyzeArgs) -> ! {
    let mut boot = BootImage::new(args.bootimg.as_path());

    let report = BootAnalysisReport {
        header_version: boot.header_version(),
        is_vendor: boot.is_vendor_boot(),
        page_size: boot.page_size(),
        os_version: boot.os_version(),
        os_patch_level: boot.os_patch_level(),
        name: boot.name(),
        cmdline: boot.cmdline(),
        id: boot.id_hex(),
        sha256: boot.is_sha256(),

        // 分区信息
        kernel: SectionInfo {
            size: boot.kernel_size(),
            format: boot.kernel_format(),
        },
        ramdisk: SectionInfo {
            size: boot.ramdisk_size(),
            format: boot.ramdisk_format(),
        },
        second: SectionInfo {
            size: boot.second_size(),
            format: boot.second_format(),
        },
        dtb: SectionInfo {
            size: boot.dtb_size(),
            format: boot.dtb_format(),
        },
        recovery_dtbo: SectionInfo {
            size: boot.recovery_dtbo_size(),
            format: None,
        },

        // OEM 标志
        flags: boot.flags_names(),

        // AVB 信息
        avb_signed: boot.is_signed(),
        avb_footer: boot.has_avb_footer(),
        vbmeta_offset: boot.vbmeta_offset(),
        vbmeta_size: boot.vbmeta_size(),

        // ramdisk 状态
        ramdisk_status: check_ramdisk_status(boot),  // stock / magisk / unsupported
    };

    if args.ramdisk_listing {
        report.ramdisk_files = list_ramdisk_files(boot);
    }

    if args.dtb_info {
        report.dtb_fstabs = analyze_dtb(boot);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        report.print_human();
    }

    exit(0);
}
```

##### B. App 侧：Boot 分析器 ViewModel

**新增文件**：`app/apk/src/main/java/com/topjohnwu/magisk/ui/boot/BootAnalyzerViewModel.kt`

```kotlin
class BootAnalyzerViewModel : BaseViewModel() {

    data class BootAnalysis(
        val headerVersion: String,
        val isVendor: Boolean,
        val pageSize: Int,
        val osVersion: String,
        val osPatchLevel: String,
        val name: String,
        val cmdline: String,
        val id: String,
        val isSha256: Boolean,

        val sections: List<SectionInfo>,
        val oemFlags: List<String>,
        val avbSigned: Boolean,
        val avbFooter: Boolean,
        val ramdiskStatus: String,
        val ramdiskFiles: List<RamdiskFileEntry>?,
        val dtbFstabs: List<FstabEntry>?,
        val patchPreview: PatchPreview?
    )

    data class SectionInfo(
        val name: String,
        val size: Long,
        val format: String,
        val sizeFormatted: String
    )

    data class RamdiskFileEntry(
        val path: String,
        val mode: String,
        val uid: Int,
        val gid: Int,
        val size: Long
    )

    data class FstabEntry(
        val source: String,
        val mountPoint: String,
        val fsType: String,
        val flags: List<String>
    )

    data class PatchPreview(
        val willPatchVerity: Boolean,
        val willPatchEncryption: Boolean,
        val willPatchLegacySAR: Boolean,
        val kernelPatches: List<String>,
        val willPatchVbmeta: Boolean,
        val ramdiskHasMagisk: Boolean
    )

    val analysis = MutableLiveData<BootAnalysis>()
    val loading = MutableLiveData(false)

    fun analyzeBootImage(uri: Uri) {
        loading.value = true

        viewModelScope.launch {
            try {
                // 1. 将文件复制到临时目录
                val tmpFile = File(AppContext.cacheDir, "boot_analysis.img")
                AppContext.contentResolver.openInputStream(uri)?.use { input ->
                    tmpFile.outputStream().use { output -> input.copyTo(output) }
                }

                // 2. 调用 magiskboot analyze
                val shell = Shell.getShell()
                val result = shell.newJob()
                    .add("cd ${AppContext.cacheDir} && magiskboot analyze -j -r -d boot_analysis.img")
                    .to(ArrayList<String>())
                    .exec()

                val json = result.out.joinToString("")
                val parsed = parseAnalysisJson(json)

                // 3. 生成补丁预览
                val preview = generatePatchPreview(parsed)
                val full = parsed.copy(patchPreview = preview)

                analysis.postValue(full)
            } catch (e: Exception) {
                Timber.e(e, "Boot analysis failed")
            } finally {
                loading.postValue(false)
            }
        }
    }

    private fun generatePatchPreview(report: BootAnalysis): PatchPreview {
        return PatchPreview(
            willPatchVerity = !Config.keepVerity,
            willPatchEncryption = !Config.keepEnc,
            willPatchLegacySAR = Info.legacySAR,
            kernelPatches = detectKernelPatches(report),
            willPatchVbmeta = Info.patchBootVbmeta,
            ramdiskHasMagisk = report.ramdiskStatus == "magisk"
        )
    }

    private fun detectKernelPatches(report: BootAnalysis): List<String> {
        val patches = mutableListOf<String>()
        // 这些信息需要从 analyze 命令的内核分析部分获取
        // 或者可以额外执行 magiskboot hexpatch 的 dry-run
        patches
    }
}
```

##### C. Boot 分析器 UI

**新增布局**：`app/apk/src/main/res/layout/fragment_boot_analyzer_md2.xml`

```xml
<ScrollView>
    <LinearLayout orientation="vertical" padding="@dimen/l2">

        <!-- 文件选择区 -->
        <MaterialCardView>
            <LinearLayout orientation="vertical">
                <Button
                    android:text="@string/select_boot_image"
                    bind:onClick="@{() -> viewModel.selectFile()}" />
                <TextView bind:text="@{viewModel.selectedFileName}"
                    bind:visible="@{viewModel.hasFile}" />
            </LinearLayout>
        </MaterialCardView>

        <!-- 分析结果 -->
        <LinearLayout bind:visible="@{viewModel.analysis != null}">

            <!-- Header 信息卡片 -->
            <MaterialCardView>
                <LinearLayout orientation="vertical">
                    <TextView android:text="@string/boot_header_info" style="Title" />

                    <!-- 版本、页大小、OS版本表格 -->
                    <include layout="@layout/include_boot_header_table"
                        bind:analysis="@{viewModel.analysis}" />
                </LinearLayout>
            </MaterialCardView>

            <!-- 分区结构卡片 -->
            <MaterialCardView>
                <LinearLayout orientation="vertical">
                    <TextView android:text="@string/boot_sections" style="Title" />
                    <androidx.recyclerview.widget.RecyclerView
                        bind:items="@{viewModel.analysis.sections}" />
                </LinearLayout>
            </MaterialCardView>

            <!-- OEM 标志卡片 -->
            <MaterialCardView bind:visible="@{!viewModel.analysis.oemFlags.empty}">
                <LinearLayout orientation="vertical">
                    <TextView android:text="@string/oem_flags" style="Title" />
                    <LinearLayout>
                        <Chip bind:text="@{flag}"
                            bind:items="@{viewModel.analysis.oemFlags}" />
                    </LinearLayout>
                </LinearLayout>
            </MaterialCardView>

            <!-- Ramdisk 状态卡片 -->
            <MaterialCardView>
                <LinearLayout orientation="vertical">
                    <TextView android:text="@string/ramdisk_status" style="Title" />
                    <TextView bind:text="@{viewModel.analysis.ramdiskStatus}" />
                    <androidx.recyclerview.widget.RecyclerView
                        bind:items="@{viewModel.analysis.ramdiskFiles}" />
                </LinearLayout>
            </MaterialCardView>

            <!-- 补丁预览卡片 -->
            <MaterialCardView>
                <LinearLayout orientation="vertical">
                    <TextView android:text="@string/patch_preview" style="Title" />
                    <include layout="@layout/include_patch_preview"
                        bind:preview="@{viewModel.analysis.patchPreview}" />
                </LinearLayout>
            </MaterialCardView>

        </LinearLayout>

    </LinearLayout>
</ScrollView>
```

#### 3.3.3 导航集成

**修改文件**：`app/apk/src/main/res/navigation/main.xml`

```xml
<!-- 新增目的地 -->
<fragment
    android:id="@+id/propsFragment"
    android:name="com.topjohnwu.magisk.ui.props.PropsFragment"
    android:label="PropsFragment"
    tools:layout="@layout/fragment_props_md2" />

<fragment
    android:id="@+id/bootAnalyzerFragment"
    android:name="com.topjohnwu.magisk.ui.boot.BootAnalyzerFragment"
    android:label="BootAnalyzerFragment"
    tools:layout="@layout/fragment_boot_analyzer_md2" />

<!-- 新增导航 Action -->
<action
    android:id="@+id/action_propsFragment"
    app:destination="@id/propsFragment"
    app:popUpTo="@id/homeFragment" />

<action
    android:id="@+id/action_bootAnalyzerFragment"
    app:destination="@id/bootAnalyzerFragment"
    app:popUpTo="@id/homeFragment" />
```

### 3.4 回退实现方案

#### 回退方案 A：Shell 输出解析（不修改 Native 层）

如果不方便修改 native 代码，完全通过解析现有命令的文本输出来实现：

```kotlin
class PropsViewModel : AsyncLoadViewModel() {

    override suspend fun doLoadWork() {
        val shell = Shell.getShell()

        // 使用 getprop 列出所有属性（无需修改 native）
        val result = shell.newJob()
            .add("getprop")
            .to(ArrayList<String>())
            .exec()

        // 解析 "[key]: [value]" 格式
        val props = result.out.mapNotNull { line ->
            // 格式: [ro.build.version.sdk]: [33]
            val match = Regex("""^\[(.+?)\]:\s*\[(.*)\]$""").find(line)
            match?.let {
                PropItem(
                    key = it.groupValues[1],
                    value = it.groupValues[2],
                    context = "",  // getprop 不返回上下文，需要额外命令
                    isPersistent = it.groupValues[1].startsWith("persist."),
                    isReadOnly = it.groupValues[1].startsWith("ro."),
                    isFavorite = it.groupValues[1] in favorites
                )
            }
        }

        items.postValue(props)
    }

    fun modifyProp(key: String, value: String) {
        // 使用 resetprop 命令（已存在）
        Shell.cmd("magisk --resetprop \"$key\" \"$value\"").submit {
            doLoadWork()
        }
    }
}
```

**Boot 分析器回退** — 解析 `magiskboot unpack` 的 stderr 输出：

```kotlin
class BootAnalyzerViewModel : BaseViewModel() {

    fun analyzeBootImage(uri: Uri) {
        viewModelScope.launch {
            val tmpDir = File(AppContext.cacheDir, "boot_analysis")
            tmpDir.mkdirs()
            val tmpFile = File(tmpDir, "boot.img")

            // 复制文件
            copyUriToFile(uri, tmpFile)

            val shell = Shell.getShell()

            // 1. 解包并捕获输出
            val result = shell.newJob()
                .add("cd $tmpDir && magiskboot unpack -h boot.img")
                .to(ArrayList<String>())
                .exec()

            // 解析 stderr 中的 header 信息
            // magiskboot 的 print() 输出格式：
            // "Header version: v4"
            // "Page size: 4096"
            // "Kernel size: 12345678"
            // "Ramdisk size: 87654321"
            // ...
            val headerInfo = parseUnpackOutput(result.err)

            // 2. 检查 ramdisk 状态
            val ramdiskTest = shell.newJob()
                .add("cd $tmpDir && magiskboot cpio ramdisk.cpio test")
                .exec()
            val ramdiskStatus = when (ramdiskTest.code) {
                0 -> "stock"
                1 -> "magisk"
                2 -> "unsupported"
                else -> "unknown"
            }

            // 3. 列出 ramdisk 文件
            val ramdiskList = shell.newJob()
                .add("cd $tmpDir && magiskboot cpio ramdisk.cpio ls -r")
                .to(ArrayList<String>())
                .exec()
            val files = parseCpioListing(ramdiskList.out)

            // 4. 分析 DTB
            val dtbTest = shell.newJob()
                .add("cd $tmpDir && magiskboot dtb dtb test 2>&1; magiskboot dtb dtb print -f 2>&1")
                .to(ArrayList<String>())
                .exec()
            val fstabs = parseDtbOutput(dtbTest.out)

            // 5. 读取 header 文件（unpack -h 生成的）
            val headerFile = File(tmpDir, "header")
            val headerProps = if (headerFile.exists()) {
                parseHeaderFile(headerFile.readText())
            } else emptyMap()

            // 组装结果
            val analysis = BootAnalysis(
                headerVersion = headerInfo["version"] ?: "unknown",
                isVendor = headerInfo["is_vendor"]?.toBoolean() ?: false,
                pageSize = headerInfo["page_size"]?.toIntOrNull() ?: 4096,
                // ... 其他字段 ...
                ramdiskStatus = ramdiskStatus,
                ramdiskFiles = files,
                dtbFstabs = fstabs,
                patchPreview = null  // 回退方案不生成补丁预览
            )

            // 清理
            shell.newJob().add("cd $tmpDir && magiskboot cleanup").exec()

            _analysis.postValue(analysis)
        }
    }

    private fun parseUnpackOutput(err: List<String>): Map<String, String> {
        val map = mutableMapOf<String, String>()
        err.forEach { line ->
            // 解析 "Header version: v4" 等格式
            val idx = line.indexOf(": ")
            if (idx > 0) {
                map[line.substring(0, idx).trim().lowercase().replace(" ", "_")] =
                    line.substring(idx + 2).trim()
            }
        }
        return map
    }
}
```

**优点**：完全不需要修改 native 代码。
**缺点**：
- 依赖文本输出格式，版本更新可能破坏解析
- 无法获取 SELinux 上下文（需额外 `magisk --resetprop -Z` 调用）
- 无法获取 OEM flags 的结构化数据（需要从文本中猜测）
- 性能较差（多次 shell 调用）

#### 回退方案 B：只读浏览器（不支持修改）

移除属性修改功能，仅展示属性列表：

```kotlin
class PropsViewModel : AsyncLoadViewModel() {
    // 仅使用 getprop，不提供修改功能
    // 修改操作仍然引导用户使用终端

    val canModify: Boolean get() = Info.isRooted

    fun modifyProp(key: String, value: String) {
        // 如果有 root，打开终端对话框引导用户手动操作
        showTerminalDialog("magisk --resetprop \"$key\" \"$value\"")
    }
}
```

#### 回退方案 C：Boot 分析器仅展示基本信息

不执行 `unpack`，仅通过读取文件头部字节判断格式：

```kotlin
fun quickAnalyze(file: File): BootAnalysis {
    val header = file.inputStream().use { it.readBytes() }.copyOfRange(0, minOf(4096, file.length().toInt()))

    // 检查 magic
    val magic = String(header, 0, 8, Charsets.US_ASCII).trimEnd('\u0000')
    val isVendor = magic == "VNDRBOOT"

    // 检查页大小（offset 36-40 for v0/v1/v2）
    val pageSize = ByteBuffer.wrap(header, 36, 4).order(ByteOrder.LITTLE_ENDIAN).int

    // 检查 OEM 特殊 magic
    val oemFlags = mutableListOf<String>()
    if (String(header, 0, 8).startsWith("CHROMEOS")) oemFlags.add("ChromeOS")
    // ... 更多 magic 检测 ...

    // 返回基本信息，不做完整解包
    return BootAnalysis(
        headerVersion = detectVersion(header),
        isVendor = isVendor,
        pageSize = if (pageSize > 0) pageSize else 4096,
        // ... 仅可从头部获取的字段 ...
        sections = emptyList(),     // 需要完整解包
        ramdiskFiles = null,        // 需要 cpio 操作
        dtbFstabs = null,           // 需要 dtb 操作
        patchPreview = null
    )
}
```

**优点**：极快，不需要 root shell 调用。
**缺点**：只能展示 header 基本信息，无法展示 ramdisk/DTB 内容。

### 3.5 涉及文件清单

#### 属性浏览器

| 操作 | 文件路径 | 说明 |
|------|---------|------|
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/props/PropsFragment.kt` | 属性浏览器 Fragment |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/props/PropsViewModel.kt` | 属性浏览器 ViewModel |
| 新增 | `app/apk/src/main/res/layout/fragment_props_md2.xml` | 属性浏览器布局 |
| 新增 | `app/apk/src/main/res/layout/item_prop.xml` | 属性列表项布局 |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/dialog/PropEditDialog.kt` | 属性编辑对话框 |
| 修改 | `native/src/core/resetprop/cli.rs` | 新增 `-j`/`-a` JSON 输出 |
| 修改 | `app/apk/src/main/res/navigation/main.xml` | 导航入口 |
| 修改 | `app/apk/src/main/res/menu/menu_bottom_nav.xml` | 底栏入口（可选） |
| 修改 | `app/core/src/main/res/values/strings.xml` | 字符串资源 |

#### Boot 分析器

| 操作 | 文件路径 | 说明 |
|------|---------|------|
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/boot/BootAnalyzerFragment.kt` | Boot 分析器 Fragment |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/boot/BootAnalyzerViewModel.kt` | Boot 分析器 ViewModel |
| 新增 | `app/apk/src/main/res/layout/fragment_boot_analyzer_md2.xml` | 分析器布局 |
| 新增 | `app/apk/src/main/res/layout/include_boot_header_table.xml` | Header 信息表格 |
| 新增 | `app/apk/src/main/res/layout/include_patch_preview.xml` | 补丁预览布局 |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/boot/SectionRvItem.kt` | 分区信息 RV 项 |
| 新增 | `app/apk/src/main/java/com/topjohnwu/magisk/ui/boot/RamdiskFileRvItem.kt` | Ramdisk 文件 RV 项 |
| 修改 | `native/src/boot/cli.rs` | 新增 `analyze` 子命令 |
| 修改 | `native/src/boot/lib.rs` | 暴露 `BootImage` 字段到 FFI |
| 修改 | `app/apk/src/main/res/navigation/main.xml` | 导航入口 |
| 修改 | `app/core/src/main/res/values/strings.xml` | 字符串资源 |

---

## 附录：通用注意事项

### A.1 权限要求

所有三个功能均需要 Root 权限才能完整工作。未 Root 时：
- **DenyList 智能模式**：可展示预设列表，但不能应用
- **安全审计仪表盘**：可展示设备基本信息，但缺少 Magisk 状态
- **属性浏览器**：可读取属性（`getprop` 无需 root），但不能修改
- **Boot 分析器**：可分析文件（`magiskboot` 运行不需要 root shell），但 MagiskInstaller 中的 patch 需要 root

### A.2 构建验证

根据 [AGENTS.md](file:///e:/Magisk-Original/AGENTS.md) 的要求：
- App 修改后需在 `app` 目录运行 `./gradlew :apk:assembleDebug` 验证编译
- Native 修改后需运行 `python build.py native` 验证编译
- 所有命令前缀 `scripts/env.py`

### A.3 国际化

所有新增用户可见字符串需添加到：
- `app/core/src/main/res/values/strings.xml`（默认英文）
- 对应的 `values-<lang>/strings.xml`（翻译）

当前项目已支持 40+ 语言。

### A.4 兼容性

- 最低支持 Android 6.0 (API 23)
- Gradle 构建系统使用 Kotlin DSL
- Native 层使用 Rust 2024 edition + C++ 混合
- 新代码应优先使用 Kotlin（App）和 Rust（Native）

### A.5 测试

- App 层：参考 `app/core/src/test/` 下的测试结构
- Native 层：参考 `native/src/core/` 中的测试模块
- 集成测试：可使用 `build.py emulator` 设置 AVD 测试环境
