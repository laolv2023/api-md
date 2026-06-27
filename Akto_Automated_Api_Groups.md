# Akto Automated API Groups 模块详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/automated-api-groups
> 代码文件：`automated-api-groups/automated-api-groups.csv`（1 个 CSV 文件）+ `AutomatedApiGroupsUtils.java`
> 执行模块：`apps/dashboard`

---

## 1. 功能定位

Automated API Groups 是 Akto 的**自动 API 分组功能**，通过预定义的正则表达式自动将 API 端点归类到逻辑分组中（如"Payment APIs"、"OAuth APIs"等），无需用户手动分类。

### 核心能力

| 能力 | 说明 |
|---|---|
| **自动分组** | 通过正则匹配 URL，自动将 API 归入预定义分组 |
| **15 个内置分组** | 覆盖常见 API 类别（健康检查、OAuth、支付、搜索等） |
| **定时同步** | 每 4 小时从 GitHub 拉取最新分组定义 |
| **增删改** | CSV 中新增/修改/删除分组时，自动在 MongoDB 中同步 |
| **测试集成** | 分组可直接作为安全测试的目标端点集合 |

---

## 2. 数据来源

### 2.1 CSV 文件

```
路径: automated-api-groups/automated-api-groups.csv
格式: apiCollectionId, groupName, isActive, regex
大小: 4.5 KB
```

### 2.2 加载方式

| 优先级 | 来源 | 路径 |
|---|---|---|
| 1（优先） | GitHub 远程 | `akto-api-security/akto` 仓库的 `automated-api-groups/automated-api-groups.csv` |
| 2（fallback） | 本地 classpath | Dashboard WAR 内置的 `/automated-api-groups.csv` |

```java
// AutomatedApiGroupsUtils.fetchGroups()
GithubFile githubFile = githubSync.syncFile(
    "akto-api-security/akto",
    "automated-api-groups/automated-api-groups.csv",
    null, null
);
if (githubFile == null) {
    // Fallback: 从 classpath 加载
    groupsCsvContent = InitializerListener.convertStreamToString(
        InitializerListener.class.getResourceAsStream("/automated-api-groups.csv")
    );
} else {
    groupsCsvContent = githubFile.getContent();
}
```

---

## 3. 15 个内置 API 分组

| # | apiCollectionId | 分组名 | 正则匹配关键词 |
|---|---|---|---|
| 1 | 111_111_201 | Health Check APIs | health, status, check, monitor, diagnose, heartbeat, ping, uptime, probe |
| 2 | 111_111_202 | OAuth APIs | oauth, authorize, access_token, refresh_token, openid, sso, login, logout, 2fa |
| 3 | 111_111_203 | User Authorization APIs | authorize, authorization, access_control, permissions, roles, acl, privileges |
| 4 | 111_111_204 | Payment APIs | payment, pay, transaction, invoice, billing, checkout, refund, credit, debit, wallet |
| 5 | 111_111_205 | Notification APIs | notify, notification, alert, email, sms, push, message, broadcast, reminder |
| 6 | 111_111_206 | Search APIs | search, find, query, lookup, browse, explore, discover, retrieve, fetch, scan |
| 7 | 111_111_207 | Monitoring APIs | monitoring, track, downtime, availability, alert, log, observability, report |
| 8 | 111_111_208 | Session Management APIs | session, session_id, session_token, session_start, session_end, session_timeout |
| 9 | 111_111_209 | Backup and Restore APIs | backup, restore, recovery, snapshot, database_backup, system_restore |
| 10 | 111_111_210 | Analytics and Reporting APIs | analytics, report, metrics, statistics, dashboard, kpi, insights |
| 11 | 111_111_211 | Admin APIs | admin, administrator, superuser, root, manage, control, config, settings |
| 12 | 111_111_212 | Media APIs | media, image, video, audio, file, upload, download, stream, encode, thumbnail |
| 13 | 111_111_213 | Location APIs | location, geolocation, gps, coordinate, map, address, city, zip, navigation |
| 14 | 111_111_214 | User Management APIs | user, account, profile, member, client, activate, deactivate, identity |
| 15 | 111_111_215 | Checkout APIs | cart, basket, add-to-cart, checkout, checkout-review, checkout-confirm |

> **apiCollectionId 规则**：`111_111_2XX` 格式，下划线会被去掉（`111111201`），作为 MongoDB 中 ApiCollection 的 `_id`。

---

## 4. 正则匹配机制

### 4.1 正则结构

每个分组的正则格式统一：

```
^((https?):\/\/)?(www\.)?.*?(keyword1|keyword2|keyword3|...)(.*?)(\?.*|\/?|#.*?)?$
```

含义：
- `^((https?):\/\/)?(www\.)?` — 可选的协议和 www 前缀
- `.*?(keyword1|keyword2|...)` — URL 中包含任一关键词
- `(.*?)(\?.*|\/?|#.*?)?$` — 后续路径/查询参数/锚点

### 4.2 匹配示例

以 "Payment APIs" 为例：

```
✅ 匹配: https://api.example.com/v1/payments/charge
✅ 匹配: https://api.example.com/billing/invoice/12345
✅ 匹配: api.example.com/wallet/balance
✅ 匹配: /api/transaction/refund
❌ 不匹配: https://api.example.com/v1/users/profile
❌ 不匹配: https://api.example.com/v1/products/list
```

### 4.3 匹配实现

```java
// RegexTestingEndpoints.containsApi()
public boolean containsApi(ApiInfo.ApiInfoKey key) {
    if (pattern == null) {
        pattern = Pattern.compile(regex);
    }
    return pattern.matcher(key.getUrl()).matches();
}
```

---

## 5. 执行模块与调用链

### 5.1 执行模块

**由 Dashboard 模块执行**（不是 api-runtime 或 api-analyser）。

```
Dashboard (InitializerListener)
  │
  ├── 启动时初始化
  │   └── if (backwardCompatibility.getAutomatedApiGroups() == 0):
  │       ├── fetchGroups()          ← 从 GitHub/fallback 加载 CSV
  │       └── processAutomatedGroups()  ← 创建/更新分组
  │
  └── 定时调度（每 4 小时）
      └── setupAutomatedApiGroupsScheduler()
          ├── callDibs("automated-api-groups-cron", 4h, 60s)  ← 分布式锁
          ├── fetchGroups()          ← 重新拉取最新 CSV
          └── AccountTask.executeTask()  ← 对每个账户执行
              └── processAutomatedGroups(apiGroupRecords)
```

### 5.2 代码位置

| 组件 | 文件 | 模块 | 职责 |
|---|---|---|---|
| `AutomatedApiGroupsUtils` | `apps/dashboard/.../utils/AutomatedApiGroupsUtils.java` | **dashboard** | CSV 加载 + 分组创建/更新/删除 |
| `InitializerListener` | `apps/dashboard/.../listener/InitializerListener.java` | **dashboard** | 启动初始化 + 定时调度 |
| `RegexTestingEndpoints` | `libs/dao/.../testing/RegexTestingEndpoints.java` | dao (共享库) | 正则匹配逻辑 |
| `ApiCollection` | `libs/dao/.../ApiCollection.java` | dao (共享库) | 分组数据模型 |

---

## 6. 数据处理流程

### 6.1 processAutomatedGroups() 逻辑

```
对 CSV 中的每条记录:
│
├── isActive == true:
│   ├── 分组不存在 → 创建新 ApiCollection
│   │   ├── id = apiCollectionId (去掉下划线)
│   │   ├── name = groupName
│   │   ├── type = API_GROUP
│   │   ├── automated = true
│   │   └── conditions = [RegexTestingEndpoints(OR, regex)]
│   │
│   └── 分组已存在 → 检查 regex 是否变化
│       └── regex 变化 → 更新 conditions
│
└── isActive == false:
    └── 分组已存在 → 删除 ApiCollection
        └── 异步删除（每 50 个账户暂停 1.5 秒）
```

### 6.2 MongoDB 存储

写入 `api_collections` 集合：

```json
{
  "_id": 111111201,
  "name": "Health Check APIs",
  "type": "API_GROUP",
  "automated": true,
  "conditions": [
    {
      "type": "REGEX",
      "operator": "OR",
      "regex": "^((https?):\\/\\/)?(www\\.)?.*?(health|status|check|...)(.*?)(\\?.*|\\/?|#.*?)?$"
    }
  ]
}
```

---

## 7. 定时调度

| 配置 | 值 |
|---|---|
| 调度器 | `scheduler.scheduleAtFixedRate` |
| 初始延迟 | 0 秒 |
| 执行间隔 | 4 小时 |
| 分布式锁 | `callDibs("automated-api-groups-cron", 4*60*60, 60)` |
| 锁有效期 | 4 小时 |
| 销定等待 | 60 秒 |
| 多账户处理 | `AccountTask.executeTask()` 遍历所有活跃账户 |
| 删除批量大小 | 100 个/批 |
| 删除节流 | 每 50 个账户暂停 1.5 秒 |

---

## 8. 使用方式

### 8.1 用户视角

用户在 Dashboard 中看到 15 个自动创建的 API 分组，每个分组自动包含匹配该正则的所有 API 端点。用户可以：

1. **查看** — Dashboard → API Inventory → 查看自动分组中的 API
2. **测试** — 选择某个自动分组作为安全测试目标（如"对 Payment APIs 运行 BOLA 测试"）
3. **不修改** — 自动分组标记为 `automated: true`，用户不应手动修改（下次同步会覆盖）

### 8.2 更新流程

```
Akto 团队修改 GitHub 上的 CSV
  ↓ (4 小时内)
Dashboard 定时拉取最新 CSV
  ↓
对比 MongoDB 中现有分组
  ↓
新增/修改/删除分组
  ↓
用户 Dashboard 自动看到变化
```

---

## 9. 与其他模块的关系

```
automated-api-groups (CSV 定义)
  │
  ▼
Dashboard (加载 + 同步)
  │
  ├──→ MongoDB: api_collections 集合
  │     └── type=API_GROUP, automated=true
  │
  ├──→ api-runtime: 流量处理时，API 自动归入匹配的分组
  │
  └──→ api-testing: 测试引擎可按分组选择测试目标
        └── TestingEndpoints.containsApi() 正则匹配
```

---

## 10. 局限性

### 10.1 正则匹配

- **URL 粒度** — 只匹配 URL，不考虑 HTTP 方法（GET /api/payments 和 POST /api/payments 归入同一分组）
- **无语义理解** — 纯关键词匹配，`/api/paying-tribute` 会误归入 "Payment APIs"
- **关键词覆盖有限** — 15 个分组的关键词列表是固定的，无法覆盖所有场景

### 10.2 管理限制

- **不可用户自定义** — 用户不能在 CSV 中添加自定义分组（CSV 由 Akto 团队维护）
- **不可禁用单个分组** — 除非 Akto 团队在 CSV 中将 `isActive` 设为 `false`
- **覆盖延迟** — 修改 CSV 后最多 4 小时才生效

### 10.3 ID 冲突

- `apiCollectionId` 使用 `111_111_2XX` 范围，如果用户的 API Collection ID 与之冲突会导致问题

---

## 11. 总结

| 维度 | 值 |
|---|---|
| 文件 | 1 个 CSV (4.5 KB) |
| 内置分组数 | 15 个 |
| 执行模块 | Dashboard |
| 同步频率 | 每 4 小时 |
| 数据来源 | GitHub (primary) + classpath (fallback) |
| 存储集合 | `api_collections` |
| 匹配方式 | Java 正则 (`Pattern.compile`) |
| 匹配粒度 | URL 级别（不区分 HTTP 方法） |
| 是否使用 ML | ❌ 否，纯正则匹配 |
| 用户可自定义 | ❌ 否（由 Akto 团队维护 CSV） |

Automated API Groups 是一个轻量的自动分类功能，通过预定义正则将 API 端点归入 15 个逻辑分组，方便用户按业务类别查看和测试 API。它的设计简单直接，没有复杂算法，本质上是一个定时同步的配置驱动分组规则。
