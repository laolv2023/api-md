# Akto Threat Detection 模块详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/apps/threat-detection
> 代码规模：49 个 Java 文件，8,608 行
> ECR 镜像：`aktosecurity/akto-threat-detection`

---

## 1. 功能定位

Threat Detection 是 Akto 的**实时威胁检测引擎**，从 Kafka 消费 API 流量，应用多层检测策略（YAML 规则 / Hyperscan 正则 / 行为分析），识别恶意请求并生成告警事件。

### 与安全测试的区别

| 维度 | 安全测试 (api-testing) | 威胁检测 (threat-detection) |
|---|---|---|
| **目的** | 主动发请求验证漏洞 | 被动分析实时流量检测攻击 |
| **运行时机** | 用户触发 / 定时调度 | 实时（Kafka 流式消费） |
| **输入** | API 端点 + 测试模板 | 实时 API 流量 |
| **输出** | 漏洞报告 (TestingRunResult) | MaliciousEvent 告警 |
| **MongoDB** | `yaml_templates` / `testing_run_*` | `filter_yaml_templates` / `api_hit_count_info` |

### 核心能力

| 能力 | 说明 |
|---|---|
| **YAML 规则检测** | 5 个内置规则（SQLi/XSS/SSRF/LFI/安全配置错误），字符串匹配 + 聚合告警 |
| **Hyperscan 正则检测** | 56 条 PCRE 正则签名，单次扫描全部模式，覆盖 9 类攻击 |
| **参数枚举检测** | 检测 IP 枚举 URL/路径参数值（如遍历 /users/1, /users/2...） |
| **API 调用分布** | 按 IP+API 统计调用频率，生成分布直方图 |
| **速率限制** | 按 IP+API 维度的请求频率监控和告警 |
| **序列异常检测** | 检测异常的 API 调用序列 |
| **Geo-IP 地理围栏** | 基于 MaxMind GeoIP2 的地理位置限制 |
| **请求 Schema 验证** | 基于 OpenAPI 规范的请求体/参数验证 |
| **聚合告警** | Redis 滑动窗口计数，达到阈值后触发聚合告警 |

---

## 2. 数据流全景

```
                    ┌──────────────────────────────────────────────────────┐
                    │              数据来源                                  │
                    │                                                      │
                    │  Kafka topic: akto.api.logs2                         │
                    │  Broker: AKTO_TRAFFIC_KAFKA_BOOTSTRAP_SERVER          │
                    │  Consumer Group: akto.threat_detection                │
                    │  数据来源: data-ingestion-service / api-runtime       │
                    └──────────────────────────┬───────────────────────────┘
                                               │
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  MaliciousTrafficDetectorTask (核心消费者, 663 行)                             │
│                                                                              │
│  对每条 Kafka 消息:                                                           │
│    1. 解析 Protobuf 消息 → HttpResponseParams                                 │
│    2. ignoreTrafficFilter() — 过滤忽略的流量                                   │
│    3. ThreatConfigurationEvaluator — 解析 Actor ID + 速率限制配置                │
│    4. 双引擎检测（互斥）:                                                       │
│       ├── isHyperscanEnabled = true:                                          │
│       │   └── HyperscanEventHandler.detectAndPushEvents()                      │
│       │       ├── HyperscanThreatMatcher.scan() — 单次扫描 56 条正则             │
│       │       ├── 按 ThreatCategory 分组匹配结果                                  │
│       │       └── 每个 category 生成 EVENT_TYPE_SINGLE 事件                      │
│       │                                                                       │
│       └── isHyperscanEnabled = false:                                         │
│           └── ThreatDetectorWithStrategy.applyFilter()                         │
│               ├── FilterYamlDetectionStrategy → ThreatDetector.applyFilter()   │
│               │   ├── 检查 5 个 YAML 规则 (SQLi/XSS/SSRF/LFI/安全配置错误)       │
│               │   ├── Trie 快速匹配 (LFI/OS命令/SSRF)                           │
│               │   └── 字符串 contains_either 匹配                               │
│               │                                                               │
│               └── 检查 aggregation_rules (Redis 滑动窗口)                       │
│                   ├── 无聚合规则 → EVENT_TYPE_SINGLE                            │
│                   └── 有聚合规则 → Redis 计数 → 达阈值 → EVENT_TYPE_AGGREGATED   │
│                                                                              │
│    5. ParamEnumerationDetector — 参数枚举检测                                   │
│       ├── BloomFilter 去重 (内存, 100万容量, 1% FPR)                             │
│       ├── Count-Min Sketch 计数 (Redis)                                        │
│       └── 滑动窗口 (默认 15 分钟) 超阈值 → 告警                                  │
│                                                                              │
│    6. DistributionCalculator — API 调用分布统计                                 │
│       ├── Redis Stream 按分钟桶记录 IP+API 调用计数                              │
│       └── 超过阈值 → 推送 breach 事件到 Redis Stream                             │
│                                                                              │
│    7. RequestValidator — OpenAPI Schema 验证                                   │
│       └── 验证请求体/参数/头部是否符合 Schema 定义                                │
│                                                                              │
│    8. 生成 MaliciousEvent → Protobuf 序列化                                    │
│       └── 发布到 Kafka: akto.threat_detection.malicious_events                  │
└──────────────────────────────────────────────────────────┬───────────────────┘
                                                           │
                                                           ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  SendMaliciousEventsToBackend                                                 │
│                                                                              │
│  消费 Kafka: akto.threat_detection.malicious_events                            │
│  → 解析 MaliciousEventKafkaEnvelope (Protobuf)                                 │
│  → HTTP POST 到 threat-detection-backend:                                      │
│    POST /api/threat_detection/record_malicious_event                            │
│    Authorization: Bearer ${AKTO_THREAT_PROTECTION_BACKEND_TOKEN}               │
│  → threat-detection-backend 存储告警，供 Dashboard 查询                          │
└──────────────────────────────────────────────────────────────────────────────┘

并行定时任务:
┌──────────────────────────────────────────────────────────────────────────────┐
│  ApiCountInfoRelayCron (每 5 分钟)                                              │
│  ├── 从 Redis 读取 API 调用计数 (按分钟桶)                                       │
│  ├── 聚合为 ApiHitCountInfo { collectionId, url, method, count, ts }            │
│  └── dataActor.bulkInsertApiHitCount() → database-abstractor → MongoDB          │
│      api_hit_count_info 集合 → Dashboard API Call Stats Graph 2                 │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  DistributionDataForwardLayer (定时)                                            │
│  ├── 从 Redis 读取最近 5 分钟的分布数据                                          │
│  └── HTTP POST 到 threat-detection-backend:                                      │
│    /api/threat_detection/fetch_api_distribution_data                             │
│    → Dashboard API Call Stats Graph 2 (分桶统计)                                  │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  PatternUpdateService (每 15 分钟)                                              │
│  ├── 从 Azure Blob 下载 threat-patterns.txt                                     │
│  ├── 解析 56 条正则签名                                                          │
│  └── 原子替换 HyperscanThreatMatcher 实例（热更新）                                │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  ConfigPoller (后台线程)                                                        │
│  ├── 轮询 Cyborg 配置变更                                                        │
│  └── 检测到变更 → 重启服务                                                       │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  DistributionStreamConsumer (后台线程)                                           │
│  ├── 消费 Redis Stream 中的 breach 事件                                          │
│  ├── 处理 API 计数超限 breach                                                     │
│  └── 生成 MaliciousEvent → Kafka                                                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 消费数据来源

### 3.1 Kafka 流量输入

| 配置 | 值 |
|---|---|
| **Topic** | `akto.api.logs2` |
| **Broker** | `AKTO_TRAFFIC_KAFKA_BOOTSTRAP_SERVER` 环境变量 |
| **Consumer Group** | `akto.threat_detection` |
| **Max Poll Records** | 500 |
| **Poll Duration** | 100ms |
| **Fetch Max Bytes** | 100 MB |
| **消息格式** | Protobuf（`byte[]`） |
| **数据来源** | data-ingestion-service / api-runtime |

### 3.2 Redis（本地缓存）

| 配置 | 值 |
|---|---|
| **连接** | `AKTO_THREAT_DETECTION_LOCAL_REDIS_URI` |
| **用途** | 聚合计数 / API 调用分布 / 参数枚举 CMS / 分布数据 Stream |
| **启用条件** | `AGGREGATION_RULES_ENABLED=true`（默认） |

### 3.3 MongoDB

| 配置 | 值 |
|---|---|
| **连接** | `AKTO_MONGO_CONN` |
| **读取集合** | `filter_yaml_templates`（5 个 YAML 威胁规则） |
| **读取集合** | `akto_data_types` / `custom_data_types`（数据类型定义） |
| **写入集合** | `api_hit_count_info`（API 调用计数） |

### 3.4 远程配置

| 来源 | URL | 用途 |
|---|---|---|
| Azure Blob | `https://akto.blob.core.windows.net/threat-config/threat-patterns.txt` | Hyperscan 正则签名（每 15 分钟更新） |
| threat-detection-backend | `AKTO_THREAT_PROTECTION_BACKEND_URL` | 接收告警事件 |

---

## 4. 核心组件详解

### 4.1 Main.java（319 行，启动入口）

初始化顺序：

1. **验证部署模式** — 混合部署等待 Stigg `THREAT_DETECTION` 授权；独立部署连接 MongoDB
2. **Hyperscan 预初始化** — 从 classpath 加载 `threat-patterns-example.txt`，编译正则数据库
3. **PatternUpdateService** — 每 15 分钟从 Azure Blob 拉取更新
4. **Redis 连接** — `AKTO_THREAT_DETECTION_LOCAL_REDIS_URI`
5. **ApiCountInfoRelayCron** — 每 5 分钟将 Redis 中的 API 计数同步到 MongoDB
6. **自定义数据类型调度器** — 每 5 分钟刷新数据类型定义
7. **CmsCounterLayer 初始化** — Count-Min Sketch（RedisBloom）用于参数枚举检测
8. **DistributionDataForwardLayer** — 定时转发分布数据到 backend
9. **DistributionStreamConsumer** — 消费 Redis Stream breach 事件
10. **MaliciousTrafficDetectorTask** — 主消费者，阻塞运行
11. **SendMaliciousEventsToBackend** — 告警转发，阻塞运行

### 4.2 MaliciousTrafficDetectorTask（663 行，核心消费者）

主检测管道，消费 Kafka `akto.api.logs2`：

**每条消息处理流程：**

1. 解析 Protobuf → `HttpResponseParams`
2. `ignoreTrafficFilter()` — 过滤 x-akto-ignore 标记的流量
3. `ThreatConfigurationEvaluator` — 解析 Actor ID（源 IP）和速率限制配置
4. **双引擎检测**（互斥）：
   - Hyperscan 模式：`HyperscanEventHandler.detectAndPushEvents()`
   - YAML 模式：`ThreatDetectorWithStrategy.applyFilter()`
5. **ParamEnumerationDetector** — 参数枚举检测
6. **DistributionCalculator** — API 调用分布统计
7. **RequestValidator** — OpenAPI Schema 验证
8. 生成 `MaliciousEvent` → Kafka

### 4.3 ThreatDetector（721 行，YAML 规则匹配）

YAML 规则检测的核心实现：

| 检测项 | 实现方式 |
|---|---|
| SQL 注入 | 字符串 `contains_either`（`' OR '1'='1` 等 5 种模式） |
| XSS | 字符串 `contains_either`（`<script>`, `javascript:` 等） |
| SSRF | Trie 快速匹配（内网 IP / metadata IP / localhost） |
| LFI | Trie 快速匹配（`/etc/passwd`, `../` 路径遍历） |
| 安全配置错误 | 响应体字符串匹配（`debug:true`, 服务器版本, 堆栈跟踪） |

**Trie 优化**：LFI、OS 命令注入、SSRF 使用 Trie 数据结构快速匹配，避免逐条字符串比较。

### 4.4 HyperscanEventHandler + HyperscanThreatMatcher

高性能正则检测引擎：

| 组件 | 职责 |
|---|---|
| `HyperscanThreatMatcher` | 编译 56 条 PCRE 正则为 Hyperscan 数据库，单次扫描全部模式 |
| `HyperscanEventHandler` | 处理匹配结果，按 `ThreatCategory` 分组，生成告警事件 |
| `PatternUpdateService` | 每 15 分钟从 Azure Blob 拉取 `threat-patterns.txt`，热更新 |
| `ThreatCategory` | 枚举映射前缀 → YAML Filter ID（9 类攻击） |

**与 YAML 的关系**：Hyperscan 启用时，5 个 YAML 默认规则被跳过（`FilterCache` 移除 `DEFAULT_THREAT_PROTECTION_FILTER_IDS`），自定义 YAML 规则继续运行。

### 4.5 ParamEnumerationDetector（参数枚举检测）

检测 IP 遍历 URL/路径参数值的行为（如 `/users/1`, `/users/2`, ..., `/users/50`）：

| 组件 | 技术 | 说明 |
|---|---|---|
| `BloomFilterLayer` | Guava BloomFilter | 内存去重，100 万容量，1% 误判率，每分钟一个 BF，保留 15 分钟 |
| `CmsCounterLayer` | Redis Count-Min Sketch | 唯一值计数，RedisBloom CMS |
| 滑动窗口 | 分钟级 | 默认窗口 15 分钟，超阈值告警 |

**工作流程：**
```
IP 请求 /users/{id} (id=123)
  ├── compositeKey = "ip|collection|GET|/users/{id}|id|123"
  ├── if BloomFilter.mightContain(compositeKey):
  │   └── 已计数，检查 CMS 阈值
  └── else:
      ├── BloomFilter.put(compositeKey)
      ├── CMS.increment(countKey) — 唯一值 +1
      └── if CMS.count > threshold → 告警
```

### 4.6 DistributionCalculator（API 调用分布）

按 IP + API 维度统计调用频率，生成分布直方图：

| 组件 | 说明 |
|---|---|
| Redis Stream | 按分钟桶记录每个 IP 对每个 API 的调用次数 |
| Lua 脚本 | 原子操作：增量计数 + 阈值检查 |
| Breach 事件 | 超过速率限制阈值时推送到 Redis Stream |
| `DistributionStreamConsumer` | 消费 breach 事件，生成 MaliciousEvent |

### 4.7 ThreatConfigurationEvaluator（351 行，配置评估）

| 功能 | 说明 |
|---|---|
| Actor ID 解析 | 从请求中提取源 IP 作为 Actor ID |
| 速率限制配置 | 从 `ThreatConfiguration` 获取全局/API 级别速率限制 |
| API 信息同步 | 15 分钟刷新一次 API 配置缓存 |
| Redis 速率限制 | 将 API 速率限制规则同步到 Redis（p50/p75/p90 百分位） |

### 4.8 RequestValidator（580 行，Schema 验证）

基于 OpenAPI 规范验证 API 请求：

| 验证项 | 说明 |
|---|---|
| 请求体 | JSON Schema 验证（V202012） |
| 查询参数 | 类型和格式验证 |
| 请求头 | Schema 定义参数验证 |
| 路径参数 | URL 模板匹配 |
| 错误报告 | `SchemaConformanceError`（含位置信息） |

### 4.9 WindowBasedThresholdNotifier（聚合告警）

Redis 滑动窗口阈值通知：

| 组件 | 说明 |
|---|---|
| `Config` | threshold + windowInSeconds |
| `shouldNotify()` | 检查窗口内计数是否达到 matchCount |
| `breachFilter` | 额外过滤条件 |
| `distinctIdentifier` | 按 IP/用户等维度区分 |

### 4.10 ApiCountInfoRelayCron（API 调用统计转发）

每 5 分钟将 Redis 中的 API 调用计数同步到 MongoDB：

```
Redis (apiCount|collectionId|url|method|binId → count)
  → 聚合为 ApiHitCountInfo { collectionId, url, method, count, ts }
  → dataActor.bulkInsertApiHitCount()
  → MongoDB: api_hit_count_info
  → Dashboard API Call Stats Graph 2
```

---

## 5. 生产数据去处

### 5.1 Kafka 输出

| Topic | 格式 | 消费者 | 说明 |
|---|---|---|---|
| `akto.threat_detection.malicious_events` | Protobuf | SendMaliciousEventsToBackend | 原始告警事件 |
| `akto.threat_detection.alerts` | Protobuf | SendMaliciousEventsToBackend | 转发到 backend |

### 5.2 HTTP 输出

| 目标 | API | 说明 |
|---|---|---|
| threat-detection-backend | `POST /api/threat_detection/record_malicious_event` | 告警事件存储 |
| threat-detection-backend | `POST /api/threat_detection/fetch_api_distribution_data` | 分布数据转发 |

### 5.3 MongoDB 输出

| 集合 | 写入方 | 内容 |
|---|---|---|
| `api_hit_count_info` | ApiCountInfoRelayCron → database-abstractor | API 调用计数 |

### 5.4 Redis（本地）

| Key 模式 | 用途 |
|---|---|
| `apiCount\|{collectionId}\|{url}\|{method}\|{binId}` | API 调用计数 |
| `apiCountIndex\|{binId}` | API 索引 |
| `{ip}\|{collectionId}\|{method}\|{apiTemplate}\|{paramName}` | 参数枚举 CMS |
| Redis Stream | 分布 breach 事件 |

---

## 6. 使用方式

### 6.1 部署

| 部署模式 | 说明 |
|---|---|
| **独立部署** | 连接 MongoDB，全功能运行 |
| **混合部署** | 通过 DataActor 代理访问 DB，等待 Stigg `THREAT_DETECTION` 授权 |

**Docker 部署：**
```bash
docker run -d \
  -e AKTO_MONGO_CONN=mongodb://mongo:27017 \
  -e AKTO_TRAFFIC_KAFKA_BOOTSTRAP_SERVER=kafka1:19092 \
  -e AKTO_INTERNAL_KAFKA_BOOTSTRAP_SERVER=kafka2:19092 \
  -e AKTO_THREAT_DETECTION_LOCAL_REDIS_URI=redis://localhost:6379 \
  -e AKTO_THREAT_PROTECTION_BACKEND_URL=https://threat-backend:8080 \
  -e AKTO_THREAT_PROTECTION_BACKEND_TOKEN=xxx \
  -e AGGREGATION_RULES_ENABLED=true \
  -e API_DISTRIBUTION_ENABLED=true \
  aktosecurity/akto-threat-detection:latest
```

### 6.2 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AKTO_MONGO_CONN` | — | MongoDB 连接串（独立部署） |
| `AKTO_TRAFFIC_KAFKA_BOOTSTRAP_SERVER` | — | 流量 Kafka broker |
| `AKTO_INTERNAL_KAFKA_BOOTSTRAP_SERVER` | — | 内部 Kafka broker（告警） |
| `AKTO_THREAT_DETECTION_LOCAL_REDIS_URI` | — | 本地 Redis 连接 |
| `AKTO_THREAT_PROTECTION_BACKEND_URL` | — | threat-detection-backend URL |
| `AKTO_THREAT_PROTECTION_BACKEND_TOKEN` | — | backend 认证 token |
| `AGGREGATION_RULES_ENABLED` | `true` | 启用聚合告警（需要 Redis） |
| `API_DISTRIBUTION_ENABLED` | `true` | 启用 API 调用分布统计 |
| `LOCAL_PATTERN_FILE` | `threat-patterns-example.txt` | 本地 Hyperscan 模式 fallback |
| `OVERWRITE_XMX` | — | 覆盖 JVM 最大堆内存 |
| `MEMORY_RESTART_THRESHOLD` | `95` | 内存使用率重启阈值 |

### 6.3 社区版

| 维度 | 值 |
|---|---|
| **社区版** | ❌ 不部署 |
| **企业版** | ✅ 独立容器 |
| **SaaS** | ✅ 独立容器 |

### 6.4 自动恢复

`start.sh` 包含自动重启机制：
- 内存使用率超过 95% → kill Java 进程 → 自动重启
- Java 进程崩溃 → 2 秒后自动重启
- 日志文件超过 `MAX_LOG_SIZE`（100MB）→ 自动轮转

---

## 7. 双引擎架构

### 7.1 引擎对比

| 维度 | YAML 规则引擎 | Hyperscan 正则引擎 |
|---|---|---|
| **模式** | `isHyperscanEnabled = false`（默认） | `isHyperscanEnabled = true` |
| **规则来源** | MongoDB `filter_yaml_templates`（5 个 YAML） | Azure Blob `threat-patterns.txt`（56 条正则） |
| **匹配方式** | 字符串 `contains_either` + Trie | PCRE 正则，Hyperscan 单次扫描 |
| **性能** | 低（逐条字符串比较） | 高（编译为 Hyperscan 数据库，SIMD 加速） |
| **覆盖类别** | 5 类（SQLi/XSS/SSRF/LFI/安全配置错误） | 9 类（+NoSQLi/OS命令/Windows命令） |
| **更新频率** | Dashboard 定时同步 | 每 15 分钟热更新 |
| **切换控制** | Stigg `THREAT_DETECTION_HYPERSCAN` feature flag | 同左 |
| **互斥** | Hyperscan 启用时跳过 5 个默认 YAML 规则 | — |

### 7.2 切换逻辑

```java
// AccountConfigurationCache.java L125
FeatureAccess hyperscanAccess = organization.getFeatureWiseAllowed()
    .getOrDefault("THREAT_DETECTION_HYPERSCAN", FeatureAccess.noAccess);
isHyperscanEnabled = hyperscanAccess.getIsGranted();

// FilterCache.java L75
if (isHyperScanEnabled && apiFilters != null) {
    apiFilters.keySet().removeAll(DEFAULT_THREAT_PROTECTION_FILTER_IDS);
    // 只保留自定义 YAML 规则，跳过 5 个默认规则
}
```

---

## 8. 检测能力矩阵

### 8.1 攻击检测

| 检测类型 | YAML 引擎 | Hyperscan 引擎 | 行为分析 |
|---|---|---|---|
| SQL 注入 | ✅ `SQLInjection` | ✅ 8 条正则 | ❌ |
| XSS | ✅ `XSS` | ✅ 13 条正则 | ❌ |
| SSRF | ✅ `SSRF` | ✅ 4 条正则 | ❌ |
| LFI/路径遍历 | ✅ `LocalFileInclusionLFIRFI` | ✅ 6 条正则 | ❌ |
| 安全配置错误 | ✅ `SecurityMisconfig` | ✅ 6 条正则（含堆栈跟踪） | ❌ |
| NoSQL 注入 | ❌ | ✅ 8 条正则 | ❌ |
| OS 命令注入 | ❌ | ✅ 5 条正则 | ❌ |
| Windows 命令注入 | ❌ | ✅ 6 条正则 | ❌ |
| 参数枚举 | ❌ | ❌ | ✅ BloomFilter + CMS |
| API 速率异常 | ❌ | ❌ | ✅ Redis 滑动窗口 |
| API 调用序列异常 | ❌ | ❌ | ✅ SequenceCache |
| Schema 验证 | ❌ | ❌ | ✅ RequestValidator |

### 8.2 告警类型

| 类型 | 说明 |
|---|---|
| `EVENT_TYPE_SINGLE` | 单次匹配即告警（无聚合规则） |
| `EVENT_TYPE_AGGREGATED` | 达到聚合阈值后告警（如 5 分钟 50 次 SQL 注入） |

### 8.3 威胁类别映射

| Hyperscan 前缀 | YAML Filter ID | 类别名 | 严重程度 |
|---|---|---|---|
| `sqli` | `SQLInjection` | SQL_INJECTION | HIGH |
| `xss` | `XSS` | XSS | HIGH |
| `nosql` | `NoSQLInjection` | NOSQL_INJECTION | HIGH |
| `os_cmd` | `OSCommandInjection` | OS_COMMAND_INJECTION | HIGH |
| `windows` | `WindowsCommandInjection` | COMMAND_INJECTION | HIGH |
| `ssrf` | `SSRF` | SSRF | HIGH |
| `lfi` | `LocalFileInclusionLFIRFI` | LFI_RFI | HIGH |
| `debug`/`version`/`stack_trace` | `SecurityMisconfig` | SecurityMisconfig | LOW |

---

## 9. 依赖关系

### 9.1 Maven 依赖

| 依赖 | 用途 |
|---|---|
| `dao` | MongoDB 数据访问 |
| `utils` | 通用工具 |
| `testing` | 测试支持 |
| `mini-runtime` | 精简运行时 |
| `kafka-clients` | Kafka 消费/生产 |
| `lettuce-core` | Redis 客户端 |
| `hyperscan` | Intel Hyperscan JNI 封装 |
| `libinjection-Java` | SQLi/XSS 注入检测库 |
| `geoip2` | MaxMind GeoIP2 地理位置库 |
| `ahocorasick` | Aho-Corasick 多模式匹配 |
| `caffeine` | 高性能缓存 |
| `flyway-core` | 数据库迁移 |
| `postgresql` | PostgreSQL 驱动 |
| `jackson-dataformat-yaml` | YAML 解析 |
| `json-schema-validator` | JSON Schema 验证 |

### 9.2 运行时依赖

| 依赖 | 说明 |
|---|---|
| Kafka | 流量输入 + 告警输出 |
| Redis | 聚合计数 / 分布统计 / CMS |
| MongoDB | 规则读取 + API 计数写入 |
| threat-detection-backend | 告警存储 |
| Azure Blob | Hyperscan 模式更新 |
| MaxMind GeoIP2 | 地理围栏 |

---

## 10. 算法分析：是否使用了 ML？

**没有使用 ML。** 全部基于规则匹配和统计计数：

| 组件 | 算法 | 类型 |
|---|---|---|
| YAML 规则匹配 | 字符串 `contains_either` + Trie | 规则匹配 |
| Hyperscan | PCRE 正则 + SIMD 加速 | 规则匹配 |
| 参数枚举 | Bloom Filter + Count-Min Sketch | 概率数据结构 |
| 聚合告警 | Redis 滑动窗口计数 | 计数统计 |
| 分布统计 | 按分钟桶计数 + 百分位计算 | 计数统计 |
| Schema 验证 | JSON Schema 验证 | 规则匹配 |
| Geo-IP | MaxMind 数据库查询 | 数据库查询 |

---

## 11. 局限性

### 11.1 架构

- **单进程** — 主消费者 + 告警转发在同一进程，无水平扩展
- **Redis 依赖** — 聚合告警和分布统计强依赖 Redis，Redis 不可用时降级
- **Stigg 依赖** — 混合部署需要等待 Stigg 授权才能启动

### 11.2 检测能力

- **YAML 规则仅 5 个** — 远少于 Hyperscan 的 56 条
- **无自定义 Hyperscan 规则** — 用户只能自定义 YAML 规则
- **参数枚举阈值固定** — 不可按 API 自定义
- **Schema 验证** — 需要 OpenAPI 规范，无规范时跳过

### 11.3 性能

- **Protobuf 解析** — 每条消息需 Protobuf 反序列化
- **Redis 操作** — 每条消息可能多次 Redis 读写
- **50KB Payload 限制** — 超过 50KB 的请求体截断

---

## 12. 总结

| 维度 | 值 |
|---|---|
| 代码规模 | 49 Java 文件 / 8,608 行 |
| 检测引擎 | 双引擎（YAML 5 规则 + Hyperscan 56 正则） |
| 行为分析 | 3 种（参数枚举 / 速率限制 / 序列异常） |
| 告警类型 | 2 种（SINGLE / AGGREGATED） |
| Kafka 消费 | 1 个 topic（`akto.api.logs2`） |
| Kafka 生产 | 2 个 topic（malicious_events / alerts） |
| 定时任务 | 5 个（PatternUpdate / ApiCountRelay / Distribution / ConfigPoller / DataType） |
| 依赖 | Redis + MongoDB + Kafka + Azure Blob + MaxMind GeoIP2 |
| 社区版 | ❌ 不部署 |
| 是否使用 ML | ❌ 否 |

Threat Detection 是 Akto 的**实时威胁检测引擎**——从 Kafka 消费 API 流量，通过双引擎（YAML 规则 + Hyperscan 正则）和行为分析（参数枚举 / 速率限制 / 分布统计）检测恶意请求，生成告警事件推送到 threat-detection-backend。它与安全测试完全独立：安全测试是主动验证漏洞，威胁检测是被动分析实时流量。社区版不部署此模块。
