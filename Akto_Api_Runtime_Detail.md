# Akto api-runtime (Runtime Analyzer) 详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/apps/api-runtime
> 代码文件：29 个 Java 文件，7,195 行
> ECR 镜像：`aktosecurity/akto-api-security-runtime:latest`

---

## 1. 功能定位

Runtime Analyzer 是 Akto 的**实时流量处理引擎**，从 API 流量中提取端点、检测认证策略、发现 API 依赖关系、构建用户行为模型。它是 Akto API 清单的核心构建器，处理速度可达 1M calls/min。

### 与 api-analyser 的分工

| 维度 | api-runtime (Runtime Analyzer) | api-analyser (Context Analyzer) |
|---|---|---|
| **核心输出** | API 目录、认证、依赖、流量指标 | 参数级统计（uniqueCount/publicCount） |
| **处理时机** | 前置（直接消费原始流量） | 后置（读取 api-runtime 的产出） |
| **代码规模** | 7,195 行 / 29 类 | 472 行 / 2 类 |
| **社区版** | ✅ 作为 Dashboard 内嵌库 | ❌ 不启用 |

---

## 2. 数据流全景

```
                    ┌─────────────────────────────────────────────────────┐
                    │              数据来源                                 │
                    │                                                     │
                    │  Kafka topics:                                      │
                    │    1. akto.api.logs (主流量)                         │
                    │    2. har_akto.api.logs (HAR 文件导入)                │
                    │  Broker: kafka1:19092 (或 127.0.0.1:29092 on K8s)   │
                    │                                                     │
                    │  数据来源:                                           │
                    │    - 镜像流量 (AWS VPC Traffic Mirroring)            │
                    │    - HAR 文件上传                                    │
                    │    - Postman 导入                                    │
                    │    - Burp Suite 集成                                 │
                    │    - OpenTelemetry traces                            │
                    │    - Akto Gateway 代理                               │
                    └────────────────────┬────────────────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────────────────┐
                    │           api-runtime 处理流程                       │
                    │                                                     │
                    │  1. 消费 Kafka 消息                                  │
                    │  2. HttpCallParser.parseKafkaMessage() 解析          │
                    │  3. 按 accountId 分组                                │
                    │  4. filterBasedOnHeaders() 头部过滤                  │
                    │  5. HttpCallParser.syncFunction()                    │
                    │     ├── APICatalogSync.processResponse()             │
                    │     │   ├── URL 模板化                               │
                    │     │   ├── URL 合并 (MergeOnSlash, MergeSimilarUrls)│
                    │     │   ├── 参数类型推断 (SingleTypeInfo)             │
                    │     │   ├── 敏感参数检测                              │
                    │     │   └── 认证策略检测 (AuthPolicy)                  │
                    │     ├── DependencyAnalyser.analyse()                 │
                    │     │   └── API 依赖关系图                            │
                    │     ├── Flow (MarkovSync + RelationshipSync)         │
                    │     │   ├── Markov 链 (用户行为序列)                  │
                    │     │   └── 参数关系 (跨 API 参数关联)                │
                    │     ├── PayloadAnalyzer                              │
                    │     ├── RedactSampleData (脱敏)                      │
                    │     └── TrafficMetrics 同步                          │
                    │  6. 批量写入 MongoDB                                 │
                    │  7. MCP 工具同步 (每 24h)                            │
                    │  8. Agent Base Prompt 检测                           │
                    └────────────────────┬────────────────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────────────────┐
                    │              生产数据去处                             │
                    │                                                     │
                    │  MongoDB 集合:                                       │
                    │    ├── single_type_info (参数类型信息)                │
                    │    ├── api_collections (API 集合)                    │
                    │    ├── api_info (API 元信息+认证)                     │
                    │    ├── traffic_metrics (流量指标)                     │
                    │    ├── markov (用户行为 Markov 链)                    │
                    │    ├── relationship (参数关系图)                      │
                    │    ├── filter_sample_data (过滤样本)                  │
                    │    ├── sensitive_param_info (敏感参数)                │
                    │    ├── merged_urls (合并的 URL)                      │
                    │    ├── runtime_filters (运行时过滤器)                 │
                    │    ├── mcp_audit_info (MCP 工具审计)                  │
                    │    └── account_settings (账户配置更新)                │
                    │                                                     │
                    │  HTTP: https://logs.akto.io/traffic-metrics          │
                    │    └── 流量指标上报                                   │
                    └─────────────────────────────────────────────────────┘
```

---

## 3. 消费数据来源

### 3.1 Kafka 配置

| 配置项 | 默认值 | 环境变量 | 说明 |
|---|---|---|---|
| Broker | `kafka1:19092` | 硬编码 | K8s 环境下为 `127.0.0.1:29092` |
| Topic 1 | `akto.api.logs` | `AKTO_KAFKA_TOPIC_NAME` | 主流量主题 |
| Topic 2 | `har_{topicName}` | 自动拼接 | HAR 文件导入流量 |
| Group ID | — | `AKTO_KAFKA_GROUP_ID_CONFIG` | 消费者组 |
| Max Poll | — | `AKTO_KAFKA_MAX_POLL_RECORDS_CONFIG` | 单次拉取最大记录数 |

### 3.2 消息格式

```json
{
  "group_name": "production-apis",
  "vxlanId": 12345,
  "vpc_cidr": ["10.0.0.0/16"],
  "account_id": "1000001",
  // + HTTP 请求/响应数据
  "request": { "method": "GET", "url": "...", "headers": {...}, "body": "..." },
  "response": { "statusCode": 200, "headers": {...}, "body": "..." }
}
```

### 3.3 流量来源（6 种）

| 来源 | 接入方式 | 社区版 |
|---|---|---|
| **AWS VPC Traffic Mirroring** | Kafka `akto.api.logs` | ❌ 企业版 |
| **HAR 文件上传** | Dashboard → Kafka `har_*` | ✅ |
| **Postman 导入** | Dashboard 内嵌 HttpCallParser | ✅ |
| **Burp Suite 集成** | Dashboard 内嵌 HttpCallParser | ✅ |
| **OpenTelemetry** | TraceProcessingService → 内嵌 | ✅ |
| **Akto Gateway** | 代理流量 → Kafka | ✅ |

---

## 4. 核心组件详解

### 4.1 Main.java (440 行) — 入口与 Kafka 消费

**启动流程：**

```
1. 读取环境变量 (AKTO_MONGO_CONN, AKTO_KAFKA_TOPIC_NAME, ...)
2. DaoInit.init() 连接 MongoDB
3. initializeRuntime()
   ├── 初始化 RuntimeFilter
   ├── 更新 API_RUNTIME_VERSION
   └── 创建 Default API Collection (id=0)
4. 创建 KafkaConsumer，订阅 topic
5. 注册 ShutdownHook（优雅关闭）
6. 启动 MCP 工具同步定时任务（每 24h）
7. 进入消费循环
```

**多租户处理：**

```java
// 按 accountId 分组
Map<String, List<HttpResponseParams>> responseParamsToAccountMap = new HashMap<>();
for (ConsumerRecord<String,String> r: records) {
    HttpResponseParams resp = HttpCallParser.parseKafkaMessage(r.value());
    String accountId = resp.getAccountId();
    responseParamsToAccountMap.computeIfAbsent(accountId, k -> new ArrayList<>()).add(resp);
}
// 每个 account 独立处理
handleResponseParams(responseParamsToAccountMap, ...);
```

**STI 数量保护机制：**

```java
// 非 Dashboard 实例且 STI 超过 2000 万条时跳过处理
if (!isDashboardInstance && accountInfo.estimatedCount > 20_000_000) {
    loggerMaker.infoAndAddToDb("STI count is greater than 20M, skipping");
    continue;
}
```

### 4.2 HttpCallParser.java (843 行) — 核心解析器

**职责：** 流量解析、API 集合创建、URL 模板化、参数提取、认证检测、依赖分析触发

**syncFunction 处理流程：**

```
syncFunction(responseParams, syncImmediately, fetchAllSTI, accountSettings)
  │
  ├── 1. 头部过滤 (filterBasedOnHeaders)
  │   └── 按 accountSettings.filterHeaderValueMap 过滤
  │
  ├── 2. API 集合名映射 (changeTargetCollection)
  │   └── 按 apiCollectionNameMapper 正则重写 host
  │
  ├── 3. 创建/查找 API Collection
  │   ├── createCollectionBasedOnHostName() — 按 host 创建
  │   └── createCollectionSimple() — 按 vxlanId 创建
  │
  ├── 4. APICatalogSync.processResponse()
  │   ├── URL 模板化
  │   ├── URL 合并
  │   ├── 参数类型推断
  │   ├── 敏感参数检测
  │   └── 认证策略检测
  │
  ├── 5. DependencyAnalyser.analyse() — 依赖关系
  │
  ├── 6. Flow (Markov + Relationship) — 行为分析
  │
  ├── 7. RedactSampleData.redact() — 脱敏
  │
  └── 8. 批量写入 MongoDB
```

**API 集合创建逻辑：**

```java
// 按 host 创建集合
public int createCollectionBasedOnHostName(int id, String host, List<CollectionTags> tagsToApply)
// → ApiCollectionsDao.instance.getMCollection().updateOne(...)
// → 如果不存在则插入新 ApiCollection

// 按 vxlanId 创建集合
public int createCollectionSimple(int vxlanId, List<CollectionTags> tagsToApply)
```

### 4.3 APICatalogSync.java (2,097 行) — API 目录同步

**最大最复杂的类**，负责 URL 模板化和合并。

**URL 模板化：**

```
原始 URL: /api/users/12345/orders/67890
模板 URL: /api/users/{user_id}/orders/{order_id}

策略:
  - 数字 → INTEGER
  - UUID → UUID
  - 长字符串 → STRING (超过阈值)
  - 版本号 → 保留 (v1, v2, ...)
```

**URL 合并策略（3 种）：**

| 策略 | 类 | 说明 |
|---|---|---|
| MergeOnSlash | `MergeOnSlash.java` | 按 `/` 分段合并相同模式的 URL |
| MergeOnHostOnly | `MergeOnHostOnly.java` | 按 host 合并 |
| MergeSimilarUrls | `MergeSimilarUrls.java` | 相似度合并 |

**Bloom Filter 去重：**

```java
// 100 万容量，0.1% 误判率
BloomFilter<CharSequence> existingAPIsInDb = 
    BloomFilter.create(Funnels.stringFunnel(Charsets.UTF_8), 1_000_000, 0.001);
```

**合并参数：**

```java
public static ApiMergerResult tryMergeURLsInCollection(
    int apiCollectionId,
    Boolean urlRegexMatchingEnabled,
    boolean mergeUrlsBasic,
    BloomFilter<CharSequence> existingAPIsInDb,
    boolean ignoreCaseInsensitiveApis,
    boolean mergeUrlsOnVersions,
    boolean skipMergingOnKnownStaticURLsForVersionedApis
)
```

**敏感参数检测：**

```java
Map<SensitiveParamInfo, Boolean> sensitiveParamInfoBooleanMap;
// 标记 password, token, secret, api_key 等敏感参数
```

### 4.4 DependencyAnalyser.java (470 行) — API 依赖分析

**功能：** 从流量中发现 API 间的数据依赖关系。例如：API A 的响应包含 `orderId`，API B 的请求参数包含 `orderId`，则 A→B 存在依赖。

**工作原理：**

```
1. 提取请求参数值集合 (reqFlattenedValuesSet)
2. 提取响应参数值集合
3. 对每个值，检查是否匹配其他 API 的 URL/参数
4. 构建 nodesMap (依赖图)
5. mergeNodes() 合并重复节点
6. syncWithDb() 写入 MongoDB
```

**数据结构：**

```java
public class DependencyAnalyser {
    Map<Integer, APICatalog> dbState;
    Store store; // BFStore (Bloom Filter) 或 HashSetStore

    // 依赖图节点
    // combinedUrlResp + paramResp → combinedUrlReq + paramReq
    public void updateNodesMap(String combinedUrlResp, String paramResp,
                               String combinedUrlReq, String paramReq,
                               boolean isUrlParam, boolean isHeader)
}
```

**Store 接口（2 种实现）：**

| 实现 | 说明 |
|---|---|
| `BFStore` | Bloom Filter 存储，节省内存，有误判 |
| `HashSetStore` | HashSet 精确存储，内存消耗大 |

### 4.5 MarkovSync.java (151 行) — Markov 链行为建模

**功能：** 构建 API 调用序列的 Markov 链模型，用于检测异常行为。

**工作原理：**

```java
// 每个用户维护上一个 API 调用状态
Map<String, Markov.State> userLastState;

// 记录状态转移: current → next, count++
// 存储为 Markov 文档:
// { current: {url, method}, next: {url, method}, totalCount: N }
```

```
用户 Alice 的调用序列: /login → /api/users → /api/orders → /api/orders/{id}
Markov 链:
  (login) → (users): count=1
  (users) → (orders): count=1
  (orders) → (orders/{id}): count=1
```

**同步阈值：**

```java
private final int counter_thresh;    // 处理条数阈值
private final int last_sync_thresh;  // 时间阈值（秒）
private final int user_thresh;       // 用户数阈值
```

### 4.6 RelationshipSync.java (245 行) — 参数关系分析

**功能：** 发现跨 API 的参数关联关系。例如：API A 的响应字段 `userId` 和 API B 的请求参数 `uid` 包含相同值，则建立关系。

**核心方法：**

```java
public void buildParameterMap(HttpResponseParams, String userIdentifierName)
// 提取所有参数值，建立 param → values 映射

public static boolean uniquenessDetermineFunction(String value)
// 判断值是否唯一（用于过滤公共值）
```

### 4.7 AuthPolicy.java (139 行) — 认证策略检测

**检测的认证类型：**

| 类型 | 检测方式 |
|---|---|
| `BEARER` | `Authorization: Bearer <token>` |
| `BASIC` | `Authorization: Basic <base64>` |
| `AUTHORIZATION_HEADER` | `Authorization` 或 `auth` 头存在 |
| `JWT` | 令牌匹配 JWT 格式 (xxx.yyy.zzz) |
| `COOKIE` | Cookie 头存在 |
| `API_KEY` | 自定义头 (X-API-Key 等) |
| `CUSTOM` | 用户定义的 CustomAuthType |

### 4.8 RedactSampleData.java (375 行) — 数据脱敏

**脱敏策略：**

| 数据类型 | 脱敏方式 |
|---|---|
| 密码 (`password`, `pwd`, `pass`) | `****` |
| Token (`token`, `access_token`, `refresh_token`) | `****` |
| API Key (`api_key`, `apikey`, `x-api-key`) | `****` |
| Cookie | 值替换为 `****` |
| Authorization 头 | 值替换为 `****` |
| 自定义敏感数据类型 | 按用户配置替换 |

### 4.9 McpToolsSyncJobExecutor.java (669 行) — MCP 工具同步

**功能：** 每 24 小时自动同步 MCP (Model Context Protocol) 服务器的工具列表。

```
1. 遍历所有 API Collection 中标记为 MCP 的集合
2. 通过 SSE 或 HTTP 连接 MCP 服务器
3. 调用 tools/list 方法获取工具列表
4. 解析工具描述和参数 schema
5. 写入 mcp_audit_info 集合
```

### 4.10 AgentBasePromptDetectionService.java (389 行) — Agent 基础提示检测

**功能：** 分析 AI Agent 端点的基础提示（system prompt），用于安全评估。

### 4.11 其他组件

| 类 | 行数 | 功能 |
|---|---|---|
| `PayloadAnalyzer` | 95 | 请求体分析 |
| `URLAggregator` | 81 | URL 聚合 |
| `KafkaHealthMetricSyncTask` | 65 | Kafka 健康指标同步 |
| `AktoPolicyNew` | 437 | 策略引擎（认证检测 + 敏感参数 + API 信息） |
| `SetFieldPolicy` | 20 | 字段设置策略 |
| `CalculateJob` | 59 | API 信息更新任务 |
| `CustomAuthUtil` | 147 | 自定义认证工具 |
| `SampleDataToSTI` | 169 | 样本数据转 SingleTypeInfo |
| `DataInsertionUtil` | 21 | 数据插入工具 |

---

## 5. 生产数据去处

### 5.1 MongoDB 集合

| 集合 | 写入者 | 内容 | 社区版 |
|---|---|---|---|
| `single_type_info` | APICatalogSync | 参数类型信息（URL, 方法, 参数名, 数据类型, 子类型） | ✅ |
| `api_collections` | HttpCallParser | API 集合（id, name, host, vxlanId, urls） | ✅ |
| `api_info` | AktoPolicyNew | API 元信息（认证类型, 敏感参数, 状态码, 访问类型） | ✅ |
| `traffic_metrics` | HttpCallParser | 流量指标（请求数, 响应码分布, 时间戳） | ✅ |
| `markov` | MarkovSync | Markov 链状态转移（current, next, count） | ✅ |
| `relationship` | RelationshipSync | 参数关系（paramA → paramB, 关联值） | ✅ |
| `filter_sample_data` | AktoPolicyNew | 过滤样本数据 | ✅ |
| `sensitive_param_info` | APICatalogSync | 敏感参数信息 | ✅ |
| `merged_urls` | APICatalogSync | 合并的 URL 模板 | ✅ |
| `runtime_filters` | Main.initializeRuntime | 运行时过滤器定义 | ✅ |
| `mcp_audit_info` | McpToolsSyncJobExecutor | MCP 工具审计信息 | ✅ |
| `account_settings` | Main | 账户配置（版本更新, CIDR 列表） | ✅ |

### 5.2 SingleTypeInfo 文档结构

```json
{
  "_id": ObjectId("..."),
  "url": "/api/users/{user_id}/orders",
  "method": "GET",
  "apiCollectionId": 5,
  "param": "user_id",          // 参数名（# 分隔嵌套）
  "isUrlParam": true,          // 是否 URL 路径参数
  "isHeader": false,           // 是否请求头参数
  "responseCode": 200,
  "types": {
    "STRING": 10,              // 类型 → 出现次数
    "INTEGER": 5
  },
  "subTypes": {
    "USER_ID": 10,            // 子类型 → 出现次数
    "UUID": 5
  },
  "uniqueCount": 1547,        // ← api-analyser 更新此字段
  "publicCount": 3,           // ← api-analyser 更新此字段
  "timestamp": 1719500000
}
```

### 5.3 外部 HTTP 上报

```
https://logs.akto.io/traffic-metrics
  └── 流量指标上报（请求数、响应码分布）
```

### 5.4 Traffic Metrics（流量指标）完整清单

api-runtime 及相关组件共生成 **12 种流量指标**，存储在 MongoDB `traffic_metrics` 集合中。

#### 5.4.1 指标总览

| # | 指标名称 | 显示名 | 说明 | 生成组件 |
|---|---|---|---|---|
| 1 | `TOTAL_REQUESTS_RUNTIME` | API calls received | Runtime 模块收到的 API 请求总数 | api-runtime (HttpCallParser) |
| 2 | `FILTERED_REQUESTS_RUNTIME` | API calls processed | Runtime 模块成功处理的 API 请求数 | api-runtime (HttpCallParser) |
| 3 | `INCOMING_PACKETS_MIRRORING` | Bytes received | 流量镜像接收到的原始字节数 | Traffic Collector (Go) |
| 4 | `OUTGOING_PACKETS_MIRRORING` | Bytes processed for HTTP data | 成功解析为 HTTP 的字节数 | Traffic Collector (Go) |
| 5 | `OUTGOING_REQUESTS_MIRRORING` | API calls extracted | 从镜像流量中提取出的 API 请求/响应对数 | Traffic Collector (Go) |
| 6 | `TC_CPU_USAGE` | Traffic Collector CPU Usage | Traffic Collector CPU 使用率（百分比） | Traffic Collector (Go) |
| 7 | `TC_MEMORY_USAGE` | Traffic Collector Memory Used | Traffic Collector 内存使用量（MB） | Traffic Collector (Go) |
| 8 | `TC_HOST_MEMORY_USED_MB` | Traffic Collector Host Memory Used | 宿主机已用内存（MB） | Traffic Collector (Go) |
| 9 | `TC_GOROUTINES` | Traffic Collector Goroutines | Go 协程数量 | Traffic Collector (Go) |
| 10 | `TC_SYSTEM_CPU_PERCENT` | Traffic Collector System CPU Percent | 宿主机 CPU 使用率（百分比） | Traffic Collector (Go) |
| 11 | `TC_TOTAL_CPU_USAGE` | Traffic Collector Total CPU Cores | 可用 CPU 核数 | Traffic Collector (Go) |
| 12 | `TC_TOTAL_MEMORY_USAGE` | Traffic Collector Total Memory | 可用总内存（MB） | Traffic Collector (Go) |

#### 5.4.2 三类指标的关系

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Traffic Collector (Go 进程)                        │
│                                                                      │
│  原始流量 → [3] INCOMING_PACKETS_MIRRORING (接收字节)                  │
│           → [4] OUTGOING_PACKETS_MIRRORING (HTTP解析成功字节)           │
│           → [5] OUTGOING_REQUESTS_MIRRORING (提取的API调用数)           │
│                                                                      │
│  系统监控 → [6] TC_CPU_USAGE         (采集器CPU%)                      │
│           → [7] TC_MEMORY_USAGE      (采集器内存MB)                    │
│           → [8] TC_HOST_MEMORY_USED_MB (宿主机内存MB)                  │
│           → [9] TC_GOROUTINES        (Go协程数)                       │
│           → [10] TC_SYSTEM_CPU_PERCENT (宿主机CPU%)                   │
│           → [11] TC_TOTAL_CPU_USAGE  (CPU核数)                        │
│           → [12] TC_TOTAL_MEMORY_USAGE (总内存MB)                     │
└────────────────────────┬─────────────────────────────────────────────┘
                         │ Kafka
                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    api-runtime (Java 进程)                            │
│                                                                      │
│  消费流量 → [1] TOTAL_REQUESTS_RUNTIME (收到的请求总数)                 │
│           → [2] FILTERED_REQUESTS_RUNTIME (有效处理的请求数)            │
│                                                                      │
│  [1] - [2] = 被过滤的无效请求数（无效状态码等）                         │
└──────────────────────────────────────────────────────────────────────┘
```

#### 5.4.3 Runtime 模块指标详解（2 种）

这两种在 `HttpCallParser.syncFunction()` 中对每条来自**流量镜像**的请求计数（Postman/Burp/HAR 导入的流量不计入）：

| 指标 | 代码位置 | 记录条件 | 含义 |
|---|---|---|---|
| `TOTAL_REQUESTS_RUNTIME` | HttpCallParser.java L611 | `Source.MIRRORING` 且收到请求 | Runtime 收到的镜像请求总数 |
| `FILTERED_REQUESTS_RUNTIME` | HttpCallParser.java L736 | `Source.MIRRORING` 且通过 `validHttpResponseCode()` 校验 | 成功处理的有效请求数 |

**差值含义**：`TOTAL - FILTERED = 被过滤的无效请求数`（无效状态码、解析失败等）

#### 5.4.4 Mirroring 模块指标详解（3 种）

由独立的 Go 语言 Traffic Collector 上报，Dashboard 的 `TrafficUpdates` 消费：

| 指标 | 单位 | 说明 |
|---|---|---|
| `INCOMING_PACKETS_MIRRORING` | 字节 | 流量镜像模块接收的原始字节数 |
| `OUTGOING_PACKETS_MIRRORING` | 字节 | 成功解析为 HTTP 数据的字节数 |
| `OUTGOING_REQUESTS_MIRRORING` | 个 | 从镜像流量中提取出的完整 API 请求/响应对数 |

**三者关系**：
- `INCOMING`（原始字节）≥ `OUTGOING_PACKETS`（HTTP 成功字节）— 差值为非 HTTP 流量或解析失败
- `OUTGOING_PACKETS` → `OUTGOING_REQUESTS` — 字节数转换为 API 调用数

#### 5.4.5 Traffic Collector 系统指标详解（7 种）

这些指标反映流量采集器自身的运行状态：

| 指标 | 单位 | 说明 |
|---|---|---|
| `TC_CPU_USAGE` | 百分比 | Traffic Collector 进程的 CPU 使用率 |
| `TC_MEMORY_USAGE` | MB | Traffic Collector 进程的内存使用量 |
| `TC_HOST_MEMORY_USED_MB` | MB | 宿主机已用内存 |
| `TC_GOROUTINES` | 个 | Go 运行时的协程数量（并发度指标） |
| `TC_SYSTEM_CPU_PERCENT` | 百分比 | 宿主机整机 CPU 使用率 |
| `TC_TOTAL_CPU_USAGE` | 核 | 可用 CPU 核数 |
| `TC_TOTAL_MEMORY_USAGE` | MB | 可用总内存 |

#### 5.4.6 数据结构

每个指标的 Key 包含 6 个维度：

```
TrafficMetrics {
    _id: Key {
        ip:                请求来源 IP（如 10.0.1.5）
        host:              Host 头（如 api.example.com，纯 IP 显示为 "ip-host"）
        vxlanID:           API Collection ID（VXLAN 隧道 ID）
        name:              指标名称（12 种之一）
        bucketStartEpoch:  时间桶起始（天级别，epoch / 86400）
        bucketEndEpoch:    时间桶结束（bucketStartEpoch + 1）
    }
    countMap: {
        "1719504000": 1234,   // epochHours → 计数
        "1719507600": 5678,   // 每小时一个 key
        ...
    }
}
```

#### 5.4.7 指标粒度

**指标粒度为 IP + Host + API Collection + 天，不细分到单个 API 端点。**

Key 中的 6 个维度中，没有 URL / endpoint / method 字段，因此 `/api/users/123` 和 `/api/orders/456` 的流量会合并到同一条记录里（只要来源 IP 和 Host 相同）。

| 维度 | 是否区分 | 示例 |
|---|---|---|
| 来源 IP | ✅ 区分 | `10.0.1.5` vs `192.168.1.100` |
| Host | ✅ 区分 | `api.example.com` vs `admin.example.com` |
| API Collection | ✅ 区分 | vxlanID=1 vs vxlanID=2 |
| URL / 端点 | ❌ 不区分 | `/api/users/123` 和 `/api/orders/456` 合并 |
| HTTP 方法 | ❌ 不区分 | GET 和 POST 合并 |
| 状态码 | ❌ 不区分 | 200 和 404 合并 |
| 时间 | ✅ 按小时区分 | countMap 内按 epochHours 分 |

**数据示例：**

```
// 同一天，同 IP + 同 Host = 一条记录，按小时分计
{
  _id: { ip: "10.0.1.5", host: "api.example.com", vxlanID: 1, name: "OUTGOING_REQUESTS_MIRRORING", ... },
  countMap: { "14:00": 342, "15:00": 287, "16:00": 412, ... }
}

// 不同 Host = 不同记录
{
  _id: { ip: "10.0.1.5", host: "admin.example.com", vxlanID: 1, name: "OUTGOING_REQUESTS_MIRRORING", ... },
  countMap: { "14:00": 56, "15:00": 43, "16:00": 61, ... }
}

// 不同来源 IP = 不同记录
{
  _id: { ip: "192.168.1.100", host: "api.example.com", vxlanID: 1, name: "OUTGOING_REQUESTS_MIRRORING", ... },
  countMap: { "14:00": 89, "15:00": 92, "16:00": 78, ... }
}
```

**时间粒度**：
- 桶级别：1 天（`bucketStartEpoch = Context.now() / (3600*24)`）
- 桶内部：按小时计数（`epochHours = System.currentTimeMillis() / (3600*1000)`）

可查看每小时的流量趋势，最长查看每天的明细。

#### 5.4.8 存储与上报

| 去向 | 说明 | 条件 |
|---|---|---|
| MongoDB `traffic_metrics` 集合 | `syncTrafficMetricsWithDB()` 批量 upsert | 始终 |
| `https://logs.akto.io/traffic-metrics` | 遥测数据上报到 Akto 云端 | 仅 `isOnprem == true` |

#### 5.4.9 Dashboard 告警

Dashboard 的 `TrafficUpdates` 监控以下指标，当流量相比历史显著下降时触发告警：

| 告警类型 | 监控指标 | 告警含义 |
|---|---|---|
| `OUTGOING_REQUESTS_MIRRORING` | 镜像提取的请求数下降 | 可能的镜像配置问题或采集器故障 |
| `FILTERED_REQUESTS_RUNTIME` | Runtime 处理的请求数下降 | 可能的 Runtime 服务故障或流量过滤问题 |

---

## 6. 使用方式

### 6.1 部署模式

| 模式 | DASHBOARD_MODE | 运行方式 | 社区版 |
|---|---|---|---|
| **社区版** | `local_deploy` | Dashboard 内嵌库（HttpCallParser） | ✅ |
| **On-Prem** | `on_prem` | 独立容器 + Kafka | 企业版 |
| **SaaS** | `saas` | 独立容器 + Kafka | Akto 云服务 |

**社区版内嵌方式：**

```java
// RuntimeListener.java — Dashboard 启动时创建 HttpCallParser
HttpCallParser callParser = new HttpCallParser("userIdentifier", 1, 1, 1, false);
info.setHttpCallParser(callParser);
RuntimeListener.accountHTTPParserMap.put(accountId, info);

// 当用户上传 HAR/Postman 时
httpCallParser.syncFunction(responseParams, true, false, accountSettings);
```

**企业版容器部署：**

```bash
docker run -d \
  -e AKTO_MONGO_CONN=mongodb://mongo:27017 \
  -e AKTO_KAFKA_TOPIC_NAME=akto.api.logs \
  -e AKTO_KAFKA_GROUP_ID_CONFIG=runtime-group \
  -e AKTO_KAFKA_MAX_POLL_RECORDS_CONFIG=1000 \
  -e AKTO_CONFIG_NAME=staging \
  -e AKTO_INSTANCE_TYPE=RUNTIME \
  aktosecurity/akto-api-security-runtime:latest
```

### 6.2 环境变量

| 变量 | 必需 | 示例 | 说明 |
|---|---|---|---|
| `AKTO_MONGO_CONN` | ✅ | `mongodb://mongo:27017` | MongoDB 连接串 |
| `AKTO_KAFKA_TOPIC_NAME` | ❌ | `akto.api.logs` | Kafka 主题（默认 akto.api.logs） |
| `AKTO_KAFKA_GROUP_ID_CONFIG` | ✅ | `runtime-group-1` | 消费者组 ID |
| `AKTO_KAFKA_MAX_POLL_RECORDS_CONFIG` | ✅ | `1000` | 单次拉取最大记录数 |
| `AKTO_CONFIG_NAME` | ✅ | `staging` | 配置名称 |
| `AKTO_INSTANCE_TYPE` | ❌ | `RUNTIME` / `DASHBOARD` | 实例类型 |
| `IS_KUBERNETES` | ❌ | `true` | K8s 环境标志 |

### 6.3 start.sh

```bash
# 动态检测 cgroup 内存限制
MEM_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory.max)  # cgroup v2
# 或
MEM_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)  # cgroup v1

# 设置 Xmx 为 80% 内存
XMX_MEM=$((MEM_LIMIT_MB * 80 / 100))

exec java -XX:+ExitOnOutOfMemoryError -Xmx${XMX_MEM}m \
  -jar /app/api-runtime-1.0-SNAPSHOT-jar-with-dependencies.jar
```

---

## 7. 核心算法分析

### 7.1 URL 模板化算法

```
输入: /api/users/12345/orders/67890
输出: /api/users/INTEGER/orders/INTEGER

规则:
  - 纯数字 → INTEGER
  - UUID 格式 → UUID
  - 长度 > STRING_MERGING_THRESHOLD(10) → STRING
  - 版本号 (v1, v2, ..., v100) → 保留
  - 已知静态 URL → 不合并
```

### 7.2 URL 合并算法

**MergeOnSlash：**

```
现有: /api/books/1, /api/books/2, /api/books/3, ...
触发: 超过阈值 (默认 10 个不同值)
合并: /api/books/INTEGER
删除: 原始的 /api/books/1, /api/books/2, ...
```

**UUID 合并：**

```java
public static boolean areBothUuidUrls(URLStatic newUrl, URLStatic deltaUrl, URLTemplate mergedTemplate) {
    // 两个 URL 的同位置段都是 UUID → 合并为 /api/{UUID}
}
```

**版本号处理：**

```java
public static final Pattern VERSION_PATTERN = Pattern.compile("\\bv([1-9][0-9]?|100)\\b");
// /api/v1/users 和 /api/v2/users 是否合并取决于 mergeUrlsOnVersions 配置
```

### 7.3 依赖分析算法

```
对每条流量消息:
  1. 展平请求参数: { "userId": 12345, "orderId": "abc-678" }
  2. 展平响应参数: { "orderId": "abc-678", "status": "shipped" }
  3. 对响应中的每个值:
     - 检查是否出现在其他 API 的 URL 中
     - 检查是否出现在其他 API 的请求参数中
  4. 如果匹配:
     - 创建依赖节点: (respUrl, respParam) → (reqUrl, reqParam)
     - 更新 nodesMap
  5. mergeNodes() 合并重复
  6. syncWithDb() 写入 MongoDB
```

### 7.4 Markov 链算法

```
对每条流量:
  1. 提取用户标识 (userIdentifier header)
  2. 获取用户上一个 API 状态: userLastState.get(userId)
  3. 当前 API = {url, method}
  4. 记录转移: (lastState → current, count++)
  5. 更新: userLastState.put(userId, current)
  6. 达到阈值后 syncWithDb()

输出 (Markov 文档):
  {
    current: { url: "/api/login", method: "POST" },
    next: { url: "/api/users", method: "GET" },
    totalCount: 42
  }
```

### 7.5 认证检测算法

```
对每条流量的请求头:
  1. 检查 Authorization 头:
     - "Bearer xxx" → BEARER
     - "Basic xxx" → BASIC
     - JWT 格式 → JWT
     - 其他 → AUTHORIZATION_HEADER
  2. 检查 Cookie 头 → COOKIE
  3. 检查自定义认证类型 (CustomAuthType):
     - 匹配用户定义的 header key → CUSTOM(name)
  4. 检查 API Key 模式 → API_KEY
  5. 记录到 ApiInfo.allAuthTypesFound
```

---

## 8. 算法分析：是否使用了 ML？

### 8.1 代码中的统计/概率组件

| 组件 | 类型 | 是否 ML | 说明 |
|---|---|---|---|
| **Bloom Filter** | 概率数据结构 | ❌ | URL 去重，不是 ML |
| **Markov 链** | 统计模型 | ⚠️ 边界 | 一阶 Markov 链，统计状态转移概率。严格说是统计建模，不是 ML（无训练/推理） |
| **URL 模板化** | 规则匹配 | ❌ | 基于正则和阈值的规则 |
| **依赖分析** | 值匹配 | ❌ | 布隆过滤器 + 字符串匹配 |
| **认证检测** | 规则匹配 | ❌ | 头部字符串匹配 |
| **参数类型推断** | 规则匹配 | ❌ | 正则 + 类型字典 |

### 8.2 Markov 链分析

api-runtime 中的 Markov 链实现：

```java
// 统计 current → next 的转移次数
// 存储: Map<State, Map<State, Integer>>
// 无概率计算，无预测，无训练
```

**与真正 ML Markov 的区别：**

| 维度 | api-runtime 的 Markov | ML Markov 模型 |
|---|---|---|
| 转移概率 | ❌ 只存计数，不计算概率 | ✅ 计算转移概率矩阵 |
| 预测 | ❌ 不预测下一个状态 | ✅ 预测最可能的下一个状态 |
| 异常检测 | ❌ 不做 | ✅ 计算序列概率，低概率=异常 |
| 训练 | ❌ 无训练过程 | ✅ 在训练集上学习参数 |
| 阶数 | 一阶（只看上一个状态） | 可变阶 |

### 8.3 结论

api-runtime **没有使用 ML 算法**。Markov 链是最接近的组件，但实现的是**简单的状态转移计数**，没有概率计算、预测或异常检测。官方文档中 Context Analyzer 声称的 "stats and ML perspective" 对于 api-runtime 同样不适用——实际实现全部基于规则匹配、概率数据结构和计数统计。

---

## 9. 社区版 vs 企业版

### 9.1 功能对比

| 功能 | 社区版（内嵌库） | 企业版（独立容器） |
|---|---|---|
| URL 模板化 | ✅ | ✅ |
| 参数类型推断 | ✅ | ✅ |
| 认证策略检测 | ✅ | ✅ |
| 敏感参数检测 | ✅ | ✅ |
| URL 合并 | ✅ | ✅ |
| 依赖分析 | ✅ | ✅ |
| Markov 链 | ✅ | ✅ |
| 参数关系 | ✅ | ✅ |
| 数据脱敏 | ✅ | ✅ |
| MCP 工具同步 | ✅ | ✅ |
| Agent 提示检测 | ✅ | ✅ |
| **Kafka 实时消费** | ❌ | ✅ |
| **AWS VPC 镜像流量** | ❌ | ✅ |
| **多实例水平扩展** | ❌ | ✅ |
| **STI 2000 万保护** | ❌ (仅 Dashboard) | ✅ |

### 9.2 社区版数据来源

社区版不消费 Kafka，而是通过 Dashboard 内嵌的 `HttpCallParser` 直接处理：

```
用户上传 HAR 文件 → Dashboard Action → HttpCallParser.syncFunction() → MongoDB
用户导入 Postman → Dashboard Action → HttpCallParser.syncFunction() → MongoDB
Burp Suite 集成 → Dashboard Action → HttpCallParser.syncFunction() → MongoDB
OpenTelemetry → TraceProcessingService → HttpCallParser.syncFunction() → MongoDB
```

---

## 10. 依赖关系

### 10.1 Maven 依赖

```xml
<!-- api-runtime pom.xml 依赖 -->
<dependency> dao </dependency>          <!-- 数据访问层 -->
<dependency> utils </dependency>         <!-- 工具库 -->
<dependency> kafka-clients </dependency> <!-- Kafka 客户端 -->
<dependency> httpclient </dependency>    <!-- HTTP 客户端 -->
<dependency> commons-lang3 </dependency>
```

### 10.2 被依赖

| 模块 | 依赖方式 |
|---|---|
| **api-analyser** | Maven 依赖（用于 HttpCallParser.parseKafkaMessage） |
| **dashboard** | Maven 依赖（内嵌为库，社区版核心） |
| **testing** | 间接依赖（通过 dashboard） |

### 10.3 运行时依赖

```
api-runtime 需要:
  1. MongoDB (必需 — 所有数据存此)
  2. Kafka (企业版必需 — 流量来源; 社区版不需要)
  3. Akto Dashboard (社区版 — 作为库嵌入)

api-runtime 被以下模块依赖:
  1. api-analyser — 调用 HttpCallParser.parseKafkaMessage()
  2. akto-api-testing — 读取 single_type_info 执行测试
  3. akto-dashboard — 内嵌运行
```

---

## 11. 局限性与注意事项

### 11.1 STI 数量限制

- 非 Dashboard 实例：STI 超过 **2000 万条**时跳过处理（防止 MongoDB 过载）
- Dashboard 实例：无限制

### 11.2 Kafka Broker 硬编码

```java
String kafkaBrokerUrl = "kafka1:19092"; // 硬编码
// 仅 K8s 环境下切换为 127.0.0.1:29092
```

### 11.3 URL 合并的不可逆性

- URL 合并后原始 URL 被删除
- 合并阈值（STRING_MERGING_THRESHOLD = 10）可能将有意义的 ID 合并
- 版本号合并（mergeUrlsOnVersions）可能导致 v1 和 v2 的端点被混淆

### 11.4 Markov 链的局限

- 只记录一阶转移（只看上一个 API）
- 无概率计算，无法做异常检测
- userLastState 在内存中，重启丢失

### 11.5 依赖分析的误报

- 值匹配可能产生虚假依赖（如公共值 "true", "false", "null"）
- Bloom Filter 的 0.1% 误判率可能导致少量误报

---

## 12. 总结

### 12.1 关键数字

| 维度 | 数量 |
|---|---|
| Java 文件 | 29 |
| 代码行数 | 7,195 |
| 核心类 | HttpCallParser (843), APICatalogSync (2,097), DependencyAnalyser (470), MarkovSync (151) |
| MongoDB 集合（写入） | 12 |
| Kafka 主题 | 2 (akto.api.logs + har_*) |
| 环境变量 | 7 |
| 认证类型检测 | 7 种 (Bearer, Basic, JWT, Cookie, API Key, Auth Header, Custom) |
| URL 合并策略 | 3 种 (OnSlash, OnHostOnly, SimilarUrls) |
| Bloom Filter | 100 万容量, 0.1% 误判率 |
| STI 保护阈值 | 2000 万条 |

### 12.2 核心能力

| 能力 | 实现类 | 算法 |
|---|---|---|
| API 端点发现 | APICatalogSync | URL 模板化 + Bloom Filter 去重 |
| API 合并 | MergeOnSlash/SimilarUrls | 规则匹配 + 阈值 |
| 认证检测 | AuthPolicy | 头部字符串匹配 |
| 参数类型推断 | SingleTypeInfo | 正则 + 类型字典 |
| 依赖分析 | DependencyAnalyser | 值匹配 + Bloom Filter |
| 行为建模 | MarkovSync | 一阶 Markov 链（计数） |
| 参数关系 | RelationshipSync | 值集合交集 |
| 数据脱敏 | RedactSampleData | 字段名匹配 + 值替换 |
| MCP 同步 | McpToolsSyncJobExecutor | MCP 协议 (SSE/HTTP) |

### 12.3 关键结论

1. **api-runtime 是 Akto 流量分析的核心引擎** — 所有 API 发现、认证检测、依赖分析都在这里完成，不是 ML
2. **社区版完整可用** — 作为 Dashboard 内嵌库运行，支持 HAR/Postman/Burp/OTel 导入
3. **企业版增加 Kafka 实时消费** — 支持实时流量处理和水平扩展
4. **Markov 链是唯一接近"统计建模"的组件** — 但只做计数，无概率计算和预测
5. **API 依赖分析是真正的差异化能力** — 通过值匹配发现 API 间数据流，这是 api-analyser 不做的
6. **文档声称的 "ML perspective" 不适用于 api-runtime** — 全部基于规则匹配和计数统计
