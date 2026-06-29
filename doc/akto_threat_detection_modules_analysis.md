# Akto 威胁检测三模块业务逻辑与数据流转分析报告

> 仓库：https://github.com/akto-api-security/akto
> 分析范围：`apps/threat-detection`、`apps/threat-detection-backend`、`apps/dashboard`（仅限威胁检测相关部分）
> 分析依据：原始程序源码（不推测、不补全、不编造）
> 分析角色：资深系统分析师 / 资深系统架构师 / 资深 Java 开发工程师

---

## 目录

1. [总览](#1-总览)
2. [Akto Threat Detection 模块分析](#2-akto-threat-detection-模块分析)
3. [Akto Threat Detection Backend 模块分析](#3-akto-threat-detection-backend-模块分析)
4. [Akto Dashboard 模块分析（威胁检测相关）](#4-akto-dashboard-模块分析威胁检测相关)
5. [三模块业务逻辑关联关系](#5-三模块业务逻辑关联关系)
6. [三模块数据流转关系](#6-三模块数据流转关系)
7. [输入输出汇总](#7-输入输出汇总)
8. [关键数据结构与协议](#8-关键数据结构与协议)
9. [附录：源码引用索引](#9-附录源码引用索引)

---

## 1. 总览

### 1.1 三模块定位

Akto 的威胁检测能力由三个独立部署、协同工作的模块组成，形成"检测 → 落库 → 展示"的完整链路：

| 模块 | 路径 | 技术栈 | 核心职责 |
|------|------|--------|----------|
| **Akto Threat Detection** | `apps/threat-detection` | Java + Kafka Consumer + Redis + Hyperscan | 实时消费流量日志，运行威胁检测规则，产出恶意事件 |
| **Akto Threat Detection Backend** | `apps/threat-detection-backend` | Java + Vert.x + MongoDB + Kafka | 接收恶意事件并落库，提供 Dashboard 查询 API，运行归档/风险评分等定时任务 |
| **Akto Dashboard** | `apps/dashboard`（`action/threat_detection` 子包） | Java + Struts2 + HttpClient + Vue 前端 | 用户交互层，将前端请求转发至 Backend，渲染威胁检测结果 |

### 1.2 三模块协作链路（高层视图）

```
[流量采集层]
   │  Kafka topic: akto.api.logs2 (HttpResponseParam protobuf)
   ▼
┌─────────────────────────────────────────────────────┐
│  Akto Threat Detection (apps/threat-detection)      │
│  - MaliciousTrafficDetectorTask 消费流量            │
│  - 运行 Filter / Hyperscan / 序列异常 / 限流检测    │
│  - 产出 MaliciousEventKafkaEnvelope (protobuf)      │
└─────────────────────────────────────────────────────┘
   │  Kafka topic: akto.threat_detection.malicious_events
   ▼
┌─────────────────────────────────────────────────────┐
│  Akto Threat Detection (SendMaliciousEventsToBackend)│
│  - 消费 malicious_events topic                      │
│  - HTTP POST → /api/threat_detection/record_malicious_event
└─────────────────────────────────────────────────────┘
   │  HTTP (RecordMaliciousEventRequest protobuf)
   ▼
┌─────────────────────────────────────────────────────┐
│  Akto Threat Detection Backend                      │
│  - ThreatDetectionRouter 接收事件                   │
│  - MaliciousEventService 落库 MongoDB               │
│  - 同步 upsert actor_info                          │
│  - DashboardRouter 暴露查询 API                     │
│  - Cron: 归档 / 风险评分 / Cloudflare WAF 同步      │
└─────────────────────────────────────────────────────┘
   ▲  HTTP (Protobuf JSON)
   │
┌─────────────────────────────────────────────────────┐
│  Akto Dashboard (action/threat_detection)           │
│  - ThreatActorAction / ThreatApiAction / ...        │
│  - 通过 HttpClient 调用 Backend 的 /api/dashboard/* │
│  - 渲染前端页面                                     │
└─────────────────────────────────────────────────────┘
   ▲  HTTP (JSON)
   │
[浏览器 / 前端 Vue 应用]
```

### 1.3 关键约定

- **Kafka Topic 命名**：见 `apps/threat-detection/src/main/java/com/akto/threat/detection/constants/KafkaTopic.java`
  - `TRAFFIC_LOGS = "akto.api.logs2"`（输入流量）
  - `ThreatDetection.MALICIOUS_EVENTS = "akto.threat_detection.malicious_events"`（检测产出）
  - `ThreatDetection.ALERTS = "akto.threat_detection.alerts"`（告警）
- **Backend 内部 Kafka Topic**：见 `apps/threat-detection-backend/src/main/java/com/akto/threat/backend/constants/KafkaTopic.java`
  - `ThreatDetection.INTERNAL_DB_MESSAGES = "akto.threat_detection.internal_db_messages"`
- **MongoDB 集合命名**：见 `apps/threat-detection-backend/src/main/java/com/akto/threat/backend/constants/MongoDBCollection.java`
  - `MALICIOUS_EVENTS = "malicious_events"`
  - `ARCHIVED_MALICIOUS_EVENTS = "archived_malicious_events"`
  - `THREAT_CONFIGURATION = "threat_configuration"`
  - `AGGREGATE_SAMPLE_MALICIOUS_REQUESTS = "aggregate_sample_malicious_requests"`
  - `SPLUNK_INTEGRATION_CONFIG = "splunk_integration_config"`
  - `ACTOR_INFO = "actor_info"`
  - `API_DISTRIBUTION_DATA = "api_distribution_data"`
  - `API_RATE_LIMIT_BUCKET_STATISTICS = "api_rate_limit_bucket_statistics"`
- **Backend HTTP 端口**：默认 `9090`，由环境变量 `THREAT_DETECTION_BACKEND_SERVER_PORT` 控制（见 `BackendVerticle.java` 第 112-114 行）。
- **Backend URL（Dashboard 侧）**：由环境变量 `THREAT_DETECTION_BACKEND_URL` 控制，默认 `https://tbs.akto.io`（见 `AbstractThreatDetectionAction.java` 第 28 行）。

---

## 2. Akto Threat Detection 模块分析

### 2.1 模块入口与初始化

**入口类**：`com.akto.threat.detection.Main`（`apps/threat-detection/src/main/java/com/akto/threat/detection/Main.java`）

**初始化流程**：

1. **部署模式判定**：通过 `RuntimeMode` 判断是否为混合部署（Hybrid Deployment）。
2. **数据访问层初始化**：
   - 混合部署模式：调用 `waitForThreatDetectionFeatureAccess()`，通过 `ClientActor.getAccountId()` 获取账户 ID，再通过 `dataActor.fetchOrganization(accountId)` 获取组织信息，校验 `featureWiseAllowed` 中 `THREAT_DETECTION` 特性是否已授予（`Main.java` 第 285-318 行）。
   - 非混合部署模式：直接 `DaoInit.init(new ConnectionString(System.getenv("AKTO_MONGO_CONN")))` 连接 MongoDB（`Main.java` 第 289 行）。
3. **Kafka 配置加载**：通过 `KafkaConfig`、`KafkaConsumerConfig`、`KafkaProducerConfig` 加载 Kafka 配置。
4. **任务调度**：启动多个 Kafka 消费者任务（详见 2.2 节）。
5. **配置轮询**：启动 `ConfigPoller`（`apps/threat-detection/src/main/java/com/akto/threat/detection/tasks/ConfigPoller.java`），每 20 秒轮询一次账户环境变量配置，写入 `/app/.env` 文件，必要时 `System.exit(0)` 重启自身以应用新配置（`ConfigPoller.java` 第 21、108-111 行）。

### 2.2 核心任务（Tasks）

所有任务继承自 `AbstractKafkaConsumerTask<V>`（`apps/threat-detection/src/main/java/com/akto/threat/detection/tasks/AbstractKafkaConsumerTask.java`），该抽象类封装了 Kafka 消费者循环：

- 构造 `KafkaConsumer<String, V>` 并订阅指定 topic（第 28-37 行）。
- 通过 `ExecutorService` 单线程执行 poll 循环（第 50-61 行）。
- 每分钟记录消费速率、分区分配情况（`logRecordsPerMin` 方法，第 63-78 行）。
- 子类实现 `processRecords(ConsumerRecords<String, V> records)` 处理消息（第 82 行）。

#### 2.2.1 MaliciousTrafficDetectorTask（核心检测任务）

**文件**：`apps/threat-detection/src/main/java/com/akto/threat/detection/tasks/MaliciousTrafficDetectorTask.java`（664 行）

**输入**：Kafka topic `akto.api.logs2` 中的 `HttpResponseParam`（protobuf，`com.akto.proto.http_response_param.v1.HttpResponseParam`）。

**处理流程**（`processRecords` 方法，第 173-204 行）：

1. 从 `AccountConfigurationCache` 获取账户配置 `AccountConfig`，设置 `Context.isRedactPayload`（第 174-180 行）。
2. 遍历每条 `ConsumerRecord<String, byte[]>`：
   - GraphQL 账户且 payload 超过 `MAX_PAYLOAD_SIZE_BYTES` 时跳过（第 183-185 行）。
   - 记录指标 `AllMetrics.instance.setTdKafkaRecordCount(1)` 和 `setTdKafkaRecordSize(record.serializedValueSize())`（第 186-187 行）。
   - `HttpResponseParam.parseFrom(record.value())` 解析 protobuf（第 188 行）。
   - `ignoreTrafficFilter(responseParam)` 过滤（第 193 行）：
     - 请求头含 `x-akto-ignore` → 跳过。
     - 路径含 `/api/threat_detection`、`/api/dashboard`、`/api/ingestData` → 跳过。
     - host 等于 `Constants.AKTO_THREAT_PROTECTION_BACKEND_HOST` → 跳过（防止自循环）。
   - 调用 `processRecord(httpResponseParam)`（第 197 行）。

**processRecord 方法**（第 227-505 行）核心逻辑：

1. **构建 HttpResponseParams**：`buildHttpResponseParam(record)` 将 protobuf 转为业务对象（第 228 行，第 614-658 行的实现）。
2. **提取 Actor**：`threatConfigEvaluator.getActorId(responseParam)`，通过 `SourceIPActorGenerator`（`apps/threat-detection/src/main/java/com/akto/threat/detection/actor/SourceIPActorGenerator.java`）生成。逻辑：优先取 `ApiAccessTypePolicy.getSourceIps(responseParams)` 的第一个，否则取 `responseParams.getSourceIP()`。Actor 为空则丢弃记录（第 229-233 行）。
3. **加载过滤器**：`filterCache.getFilters(isHyperscanEnabled)`，根据是否启用 Hyperscan 返回不同过滤器集合（第 237 行）。Hyperscan 启用时，会移除默认威胁保护过滤器（`LocalFileInclusionLFIRFI`、`NoSQLInjection`、`OSCommandInjection`、`SQLInjection`、`SSRF`、`SecurityMisconfig`、`WindowsCommandInjection`、`XSS`），仅保留自定义 YAML 模板（见 `FilterCache.java` 第 27-30、75-79 行）。
4. **构建 RawApi 与元数据**：`RawApi.buildFromMessageNew(responseParam)` + `rawApiFactory.buildFromHttp(...)`（第 247-250 行）。
5. **API 集合 ID 计算**：`httpCallParser.createApiCollectionId(responseParam)`（第 253 行）。
6. **URL 模板匹配**：若启用 `apiDistributionEnabled`，调用 `threatDetector.findMatchingUrlTemplate(responseParam)` 获取模板 URL（如 `/api/users/INTEGER`），用于聚合（第 262-269 行）。
7. **序列异常检测**：若 `accountConfig.isBehavioralSequenceEnabled()`，调用 `checkSequenceAnomaly(...)`（第 273-277 行）。
   - `SequenceCache`（`apps/threat-detection/src/main/java/com/akto/threat/detection/cache/SequenceCache.java`）从 `api_sequences` 集合加载转移概率，每 10 分钟刷新。
   - 阈值：`PROBABILITY_THRESHOLD = 0.05f`、`ANOMALY_COUNT_THRESHOLD = 5`、`MIN_CACHE_SIZE = 50`（第 27-29 行）。
   - 当连续异常计数达到 5 时触发告警，计数器重置（第 78-80 行）。
8. **成功利用 / 忽略事件判定**：
   - `threatDetector.isIgnoredEvent(filterCache.getIgnoredEventFilters(), rawApi, apiInfoKey)`（第 283 行）。
   - `threatDetector.isSuccessfulExploit(filterCache.getSuccessfulExploitFilters(), rawApi, apiInfoKey)`（第 286 行）。
9. **API 分布数据写入**（若 `apiDistributionEnabled`）：
   - 构建 `distributionKey` 和 `ipApiCmsKey`（第 293-294 行）。
   - 获取 `RatelimitConfigItem` 和 `ratelimit`（第 297-300 行）。
   - 异步 XADD 到 Redis Stream（第 302 行注释："Fully async: XADD to Redis Stream — ZERO sync Redis calls"）。
10. **过滤器匹配循环**（第 408-504 行）：
    - 对每个 `FilterConfig`，调用 `threatDetector.applyFilter(threatFilter, httpResponseParams, rawApi, apiInfoKey, matchedTemplate)`。
    - `ThreatDetector`（`apps/threat-detection/src/main/java/com/akto/threat/detection/utils/ThreatDetector.java`）内置多种检测器：
      - `USER_AUTH_MISMATCH_FILTER_ID` → `isUserAuthMismatchThreat`
      - `LFI_FILTER_ID` → `isLFiThreat`（基于 Aho-Corasick Trie，`lfiTrie`）
      - `OS_COMMAND_INJECTION_FILTER_ID` → `isOsCommandInjectionThreat`（`osCommandInjectionTrie`）
      - SSRF（`ssrfTrie`）等（第 66-80 行）。
    - 匹配成功后，构建 `SampleMaliciousRequest`（`Utils.buildSampleMaliciousRequest`）。
    - 若过滤器无聚合规则（`!isAggFilter`），直接 `generateAndPushMaliciousEventRequest(apiFilter, actor, responseParam, maliciousReq, EventType.EVENT_TYPE_SINGLE)`（第 454-458 行）。
    - 若有聚合规则，遍历 `Rule`，调用 `windowBasedThresholdNotifier.shouldNotify(aggKey, maliciousReq, rule, shouldIncrement, breachFilterPassed, identity)`（第 490 行）。
      - `identity` 通过 `extractIdentity(responseParam, rule.getCondition().getDistinctIdentifier())` 提取，支持 `request_payload`、`response_payload`、`request_headers` 三种来源（第 507-528 行）。
      - 满足阈值时 `generateAndPushMaliciousEventRequest(..., EventType.EVENT_TYPE_AGGREGATED)`（第 494-499 行）。
11. **Hyperscan 检测路径**（启用时）：通过 `HyperscanThreatMatcher`（`apps/threat-detection/src/main/java/com/akto/threat/detection/hyperscan/HyperscanThreatMatcher.java`）单次扫描多模式正则，返回 `MatchResult`（含 prefix、category、startOffset、endOffset、matchedText、location）。

**输出**：通过 `generateAndPushMaliciousEventRequest` 方法（第 546-553 行）将 `MaliciousEventKafkaEnvelope`（protobuf）发送到 Kafka topic `akto.threat_detection.malicious_events`。

**关键依赖组件**：

- `ThreatConfigurationEvaluator`（`apps/threat-detection/src/main/java/com/akto/threat/detection/tasks/ThreatConfigurationEvaluator.java`）：从 Backend 拉取 `ThreatConfiguration`（含 `RatelimitConfig`、`ParamEnumerationConfig`），管理 Redis 限流计数与缓解期（`isActorInMitigationPeriod`、`setActorInMitigationPeriod`，第 325-338 行）。
- `FilterCache`（`apps/threat-detection/src/main/java/com/akto/threat/detection/cache/FilterCache.java`）：每 300 秒刷新过滤器，从 `FilterYamlTemplateDao` 加载 YAML 模板（第 26 行）。
- `AccountConfigurationCache`（`apps/threat-detection/src/main/java/com/akto/threat/detection/cache/AccountConfigurationCache.java`）：单例，每 15 分钟刷新 `AccountConfig`（第 31 行）。
- `ApiCountCacheLayer`（`apps/threat-detection/src/main/java/com/akto/threat/detection/cache/ApiCountCacheLayer.java`）：基于 Redis + Caffeine 本地缓存的双层计数器，支持 `mget` 批量查询和 `zremrangebyscore` 索引清理（第 219-236 行）。
- `WindowBasedThresholdNotifier`（`apps/threat-detection/src/main/java/com/akto/threat/detection/smart_event_detector/window_based/WindowBasedThresholdNotifier.java`）：滑动窗口阈值通知器，支持 distinct 模式（基于 `DistinctIdentifier`），默认通知冷却 30 分钟（第 18 行）。
- `ParamEnumerationDetector`（`apps/threat-detection/src/main/java/com/akto/threat/detection/ip_api_counter/ParamEnumerationDetector.java`）：参数枚举检测，使用 `BloomFilterLayer`（内存去重）+ `CmsCounterLayer`（Redis Count-Min Sketch）统计唯一值数量（第 76-97 行）。
- `DistributionDataForwardLayer`（`apps/threat-detection/src/main/java/com/akto/threat/detection/ip_api_counter/DistributionDataForwardLayer.java`）：定时从 Redis Hash 读取分布数据，转发至 Backend 的 `/api/threat_detection/save_api_distribution_data` 接口（第 29-31 行注释）。

#### 2.2.2 SendMaliciousEventsToBackend（事件转发任务）

**文件**：`apps/threat-detection/src/main/java/com/akto/threat/detection/tasks/SendMaliciousEventsToBackend.java`（77 行）

**输入**：Kafka topic `akto.threat_detection.malicious_events` 中的 `MaliciousEventKafkaEnvelope`（protobuf）。

**处理流程**（`processRecords` 方法，第 33-75 行）：

1. 遍历每条记录，`MaliciousEventKafkaEnvelope.parseFrom(record.value())` 解析。
2. 从 envelope 中提取 `MaliciousEventMessage` 列表。
3. 对每个事件：
   - 构建 `RecordMaliciousEventRequest`（protobuf，`com.akto.proto.generated.threat_detection.service.malicious_alert_service.v1.RecordMaliciousEventRequest`）。
   - 序列化为 JSON 字符串 `msg`。
   - 构建 `OriginalHttpRequest`，URL = `Utils.getThreatProtectionBackendUrl() + "/api/threat_detection/record_malicious_event"`，方法 POST，Content-Type `application/json`（第 58 行）。
   - `ApiExecutor.sendRequest(request, true, null, false, null)` 发送 HTTP 请求（第 61 行）。
   - 校验响应状态码：仅 200、202 视为成功，否则记录错误日志（第 63-65 行）。

**输出**：HTTP POST 请求至 Threat Detection Backend 的 `/api/threat_detection/record_malicious_event` 端点。

**注释明确说明**（第 21-23 行）："This will send alerts to threat detection backend"。

### 2.3 模块输入输出汇总

#### 输入

| 输入源 | 数据格式 | 来源 | 用途 |
|--------|----------|------|------|
| Kafka topic `akto.api.logs2` | `HttpResponseParam` protobuf | 流量采集层（data-ingestion-service 等） | 威胁检测的原始流量 |
| MongoDB（通过 DataActor） | 账户配置、过滤器 YAML、API 序列、API 信息 | Dashboard 写入 | 检测规则与上下文 |
| Redis | 计数器、限流状态、分布数据、CMS | 自身写入与读取 | 状态管理与聚合 |
| HTTP（从 Backend） | `ThreatConfiguration` protobuf | Backend 的 `/api/dashboard/fetch_threat_configuration` | 限流与参数枚举配置 |

#### 输出

| 输出目标 | 数据格式 | 接收方 | 用途 |
|----------|----------|--------|------|
| Kafka topic `akto.threat_detection.malicious_events` | `MaliciousEventKafkaEnvelope` protobuf | 自身的 `SendMaliciousEventsToBackend` 任务 | 检测结果传递 |
| HTTP POST `/api/threat_detection/record_malicious_event` | `RecordMaliciousEventRequest` protobuf JSON | Threat Detection Backend | 恶意事件落库 |
| HTTP POST `/api/threat_detection/save_api_distribution_data` | `ApiDistributionDataRequestPayload` protobuf JSON | Threat Detection Backend | API 分布数据落库 |
| Redis Stream / Hash | 分布数据、计数器 | 自身与 Backend（通过转发） | 限流与分布统计 |
| MongoDB（通过 DataActor） | API 计数、指标 | Dashboard 查询 | 状态同步 |
| `/app/.env` 文件 | 环境变量 | 自身重启加载 | 配置热更新 |

---

## 3. Akto Threat Detection Backend 模块分析

### 3.1 模块入口与初始化

**入口类**：`com.akto.threat.backend.Main`（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/Main.java`）

**初始化流程**：

1. **MongoDB 初始化**：通过 `DaoInit` 建立 MongoClient，注册 BSON Codec（`Main.java` 第 1-10 行 import）。
2. **Kafka 配置加载**：`KafkaConfig`、`KafkaConsumerConfig`、`KafkaProducerConfig`。
3. **DAO 与 Service 初始化**：
   - `MaliciousEventDao.instance`（单例）
   - `ApiDistributionDataDao`
   - `MaliciousEventService`、`ThreatActorService`、`ThreatApiService`、`ApiDistributionDataService`
4. **后台任务启动**：
   - `FlushMessagesToDB`：消费 Kafka topic `akto.threat_detection.internal_db_messages`，批量写入 MongoDB（见 3.3 节）。
5. **Vert.x HTTP 服务启动**：部署 `BackendVerticle`，监听端口 `9090`（默认）。
6. **定时任务（Cron）启动**（`Main.java` 第 19-24 行 import，第 113-121 行实例化）：
   - `PercentilesCron`
   - `ArchiveOldMaliciousEventsCron`
   - `RiskScoreSyncCron`
   - `SkillsRiskScoreSyncCron`
   - `CloudflareWafSyncCron`
   - （`ConfigRiskSyncCron` 已被注释禁用，第 117-118 行）
7. **账户级索引初始化**：通过 `AccountTask.instance.executeTask(...)` 遍历所有账户，调用 `ThreatDetectionDaoInit.createIndices(accountId)` 创建 MongoDB 索引（第 124-139 行）。

### 3.2 HTTP 路由层

**Verticle**：`com.akto.threat.backend.BackendVerticle`（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/BackendVerticle.java`）

**路由组装**（`start` 方法）：

1. 创建 `Router`，注册 `BodyHandler`。
2. 注册 `AuthenticationInterceptor` 作为全局拦截器（除 `/health` 等公开端点外）。
3. 挂载两个子路由：
   - `ThreatDetectionRouter`（路径前缀 `/api/threat_detection`）：接收来自 Threat Detection 模块的事件。
   - `DashboardRouter`（路径前缀 `/api/dashboard`）：接收来自 Dashboard 模块的查询请求。
4. 注册 `/health` 健康检查端点（第 80-102 行）：检查 Kafka 消费者最近 poll 时间与最近写入时间，超阈值返回 503。
5. 注册 404 兜底处理器（第 104-110 行）。
6. 启动 HTTP Server，监听 `THREAT_DETECTION_BACKEND_SERVER_PORT`（默认 9090）。

**认证拦截器**：`AuthenticationInterceptor`（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/interceptors/AuthenticationInterceptor.java`）

- 从 `Authorization: Bearer <token>` 头提取 JWT。
- 从 MongoDB `configs` 集合读取 `HYBRID_SAAS` 配置，获取 RSA 公钥（第 20-46 行）。
- `Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token)` 验签。
- 从 claims 提取 `accountId`，放入 `RoutingContext`（第 62-63 行）。
- 失败返回 401。

#### 3.2.1 ThreatDetectionRouter（事件接收路由）

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/router/ThreatDetectionRouter.java`（116 行）

**端点**：

| 方法 | 路径 | 处理逻辑 | 输入 | 输出 |
|------|------|----------|------|------|
| POST | `/api/threat_detection/record_malicious_event` | `maliciousEventService.recordMaliciousEvent(accountId, req)` | `RecordMaliciousEventRequest` protobuf | 落库结果 |
| POST | `/api/threat_detection/save_api_distribution_data` | `apiDistributionDataService.saveApiDistributionData(accountId, req)` | `ApiDistributionDataRequestPayload` protobuf | 保存结果 |
| POST | `/api/threat_detection/fetch_api_distribution_data` | `apiDistributionDataService.getDistributionStats(accountId, req)` | `FetchApiDistributionDataRequest` protobuf | `FetchApiDistributionDataResponse` protobuf |

所有端点使用 `blockingHandler`（阻塞式处理），通过 `ProtoMessageUtils.toProtoMessage(...)` 将请求体反序列化为 protobuf，调用对应 Service 方法后通过 `ProtoMessageUtils.toString(...)` 序列化响应。

#### 3.2.2 DashboardRouter（Dashboard 查询路由）

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/router/DashboardRouter.java`（738 行）

**端点清单**（基于源码逐条梳理）：

| 路径 | 调用的 Service 方法 | 用途 |
|------|---------------------|------|
| `/api/dashboard/fetch_threat_configuration` | `threatActorService.fetchThreatConfiguration` | 获取威胁配置 |
| `/api/dashboard/update_threat_configuration` | `threatActorService.updateThreatConfiguration` | 更新威胁配置 |
| `/api/dashboard/toggle_archival_enabled` | `threatActorService.toggleArchivalEnabled` | 切换归档开关 |
| `/api/dashboard/fetch_filters_for_threat_actors` (GET) | `dsService.fetchThreatActorFilters` | 获取威胁 Actor 过滤器选项 |
| `/api/dashboard/get_subcategory_wise_count` | `threatApiService.getSubCategoryWiseCount` | 子分类维度计数 |
| `/api/dashboard/get_severity_wise_count` | `threatApiService.getSeverityWiseCount` | 严重度维度计数 |
| `/api/dashboard/get_daily_actor_count` | `threatActorService.getDailyActorCounts` | 每日 Actor 计数 |
| `/api/dashboard/get_actors_count_per_country` | `threatActorService.getThreatActorsByCountry` | 按国家统计 Actor |
| `/api/dashboard/list_threat_actors` | `threatActorService.listThreatActors` | 威胁 Actor 列表（支持游标分页） |
| `/api/dashboard/list_threat_apis` | `threatApiService.listThreatApis` | 威胁 API 列表 |
| `/api/dashboard/fetch_threats_for_actor` | `dsService.fetchThreatsForActor` | 获取某 Actor 的威胁详情 |
| `/api/dashboard/fetch_threat_activity_timeline` | `threatApiService.fetchThreatActivityTimeline` | 威胁活动时间线 |
| `/api/dashboard/fetchAggregateMaliciousRequests` | `dsService.fetchAggregateMaliciousRequests` | 聚合恶意请求样本 |
| `/api/dashboard/fetch_malicious_events` | `dsService.fetchMaliciousEvents` | 恶意事件列表 |
| `/api/dashboard/list_malicious_requests` | `dsService.listMaliciousRequests` | 恶意请求列表（含分页） |
| `/api/dashboard/update_malicious_event_status` | `dsService.updateMaliciousEventStatus` | 更新事件状态（如已确认/忽略） |
| `/api/dashboard/delete_malicious_events` | `dsService.deleteMaliciousEvents` | 删除恶意事件（按 ID 或过滤器） |
| `/api/dashboard/get_top_n_data` | `dsService.fetchTopNData` | Top N 数据 |
| `/api/dashboard/splunk_integration` | `dsService.saveSplunkIntegration` | 保存 Splunk 集成配置 |
| `/api/dashboard/fetch_alert_filters` | `dsService.fetchAlertFilters` | 获取告警过滤器 |
| `/api/dashboard/bulk_update_agentic_session_context` | `dsService.bulkUpdateAgenticSessionContext` | 批量更新 Agentic Session 上下文 |
| `/api/dashboard/fetch_session_context` (GET) | `dsService.fetchSessionContext` | 获取 Session 上下文 |

**上下文来源头**：多数端点通过 `getContextSourceHeader(ctx)` 读取 `x-context-source` 请求头，用于区分 `API`、`ENDPOINT`、`AGENTIC` 等上下文（见 `ThreatUtils.isAgenticOrEndpointContext`）。

### 3.3 Service 层

#### 3.3.1 MaliciousEventService

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/service/MaliciousEventService.java`（883 行）

**核心方法**：

- `recordMaliciousEvent(accountId, RecordMaliciousEventRequest)`：接收来自 Threat Detection 模块的事件，转换为 `MaliciousEventDto`，通过 `MaliciousEventDao.insertOne` 落库到 `malicious_events` 集合。
- `fetchThreatActorFilters(accountId, ThreatActorFilterRequest)`：返回 `ThreatActorFilterResponse`，包含 `subCategories`、`countries`、`actorId`、`host` 四个维度的去重值。优先从 `actor_info` 集合查询（`fetchThreatActorFiltersFromActorInfo`，第 260-288 行），失败时回退到 `malicious_events` 集合（`fetchThreatActorFiltersFromMaliciousEvents`，第 290-311 行）。
- `listMaliciousRequests(accountId, ListMaliciousRequestsRequest)`：分页查询恶意事件，构建 `ListMaliciousRequestsResponse`，每条事件含 `id`、`actor`、`filterId`、`endpoint`、`method`、`apiCollectionId`、`ip`、`country`、`destCountry`、`detectedAt`、`type`、`refId`、`category`、`subCategory`、`eventTypeVal`、`metadata`、`status`、`successfulExploit`、`label`、`host`、`jiraTicketUrl`、`severity`、`sessionId`、`owaspCategories` 等字段（第 570-604 行）。
- `updateMaliciousEventStatus(accountId, eventIds, filterMap, status, jiraTicketUrl, contextSource)`：更新事件状态（`MaliciousEventDto.Status` 枚举）与 Jira 票据 URL（第 622-633 行）。
- `deleteMaliciousEvents(accountId, eventIds, filterMap, contextSource)`：按 ID 列表或过滤器删除事件。
- `bulkUpdateAgenticSessionContext(accountId, BulkUpdateAgenticSessionContextRequest)`：批量更新 `AgenticSessionContextDao` 中的会话上下文（第 840-859 行）。
- `fetchSessionContext(accountId, sessionId)`：从 `AgenticSessionContextDao` 获取会话上下文，转换为 `SessionDocument`（第 861-881 行）。

#### 3.3.2 ThreatActorService

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/service/ThreatActorService.java`（1526 行）

**核心方法**：

- `fetchThreatConfiguration(accountId)` / `updateThreatConfiguration(accountId, ThreatConfiguration)`：读写 `threat_configuration` 集合，配置含 `actor`、`ratelimitConfig`、`paramEnumerationConfig`、`archivalDays`、`archivalEnabled` 等字段（第 160-206 行）。
- `toggleArchivalEnabled(accountId, ToggleArchivalEnabledRequest)`：切换归档开关（第 208-227 行）。
- `listThreatActors(accountId, ListThreatActorsRequest, contextSource)`：列出威胁 Actor，支持两种实现：
  - `listThreatActorsFromActorInfo`（新方法，基于 `actor_info` 集合，支持游标分页，第 460-490 行）。
  - `listThreatActorsFromAggregation`（旧方法，基于 `malicious_events` 聚合，第 495 行起）。
  - 过滤维度：`actors`、`latestIps`、`latestAttack`（filterId）、`country`、`detectedAtTimeRange`、`startTs`/`endTs`（第 505-515 行）。
- `getDailyActorCounts(accountId, DailyActorsCountRequest, contextSource)`：
  - 从 `actor_info` 统计 Critical Actor 数（`isCritical=true`，使用索引 `lastAttackTs:1, contextSource:1, isCritical:1`，第 776-784 行）。
  - 统计 Active Actor 数（`status=ACTIVE`，使用索引 `lastAttackTs:1, contextSource:1, status:1`，第 789-800 行）。
  - 从 `malicious_events` 按日聚合得到每日 Actor 数（第 820-825 行）。
- `getThreatActorsByCountry(accountId, ThreatActorByCountryRequest, contextSource)`：按国家分组统计 Actor 数，使用索引 `lastAttackTs:1, contextSource:1, country:1`（第 1092-1122 行）。
- `fetchDashboardTopData(accountId, ...)`：返回 Top Actors、Top APIs、最近 5 分钟恶意事件数（第 1508-1522 行）。

#### 3.3.3 ThreatApiService

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/service/ThreatApiService.java`（247 行）

**核心方法**：

- `getSubCategoryWiseCount(accountId, ThreatCategoryWiseCountRequest, contextSource)`：按子分类聚合 `malicious_events` 计数。
- `getSeverityWiseCount(accountId, ThreatSeverityWiseCountRequest, contextSource)`：按严重度（`CRITICAL`、`HIGH`、`MEDIUM`、`LOW`）聚合计数，使用 `$group` 管道（第 216-219 行）。
- `listThreatApis(accountId, ListThreatApiRequest, contextSource)`：列出受攻击的 API 端点。

#### 3.3.4 ApiDistributionDataService

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/service/ApiDistributionDataService.java`（150 行）

**核心方法**：

- `saveApiDistributionData(accountId, ApiDistributionDataRequestPayload)`：批量写入 `api_distribution_data` 集合（`ApiDistributionDataModel`，含 `apiCollectionId`、`url`、`method`、`windowSize`、`windowStart`、`distribution` Map）。
- `getDistributionStats(accountId, FetchApiDistributionDataRequest)`：按 `apiCollectionId` + `url` + `method` + `windowSize=5` + `windowStart` 范围查询，返回 `FetchApiDistributionDataResponse`（含 `BucketStats`：`bucket`、`min`、`max`、`p25`、`p50`、`p75`，第 110-131 行）。

### 3.4 后台任务

#### 3.4.1 FlushMessagesToDB

**文件**：`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/tasks/FlushMessagesToDB.java`（267 行）

**输入**：Kafka topic `akto.threat_detection.internal_db_messages`。

**处理逻辑**：

1. 消费消息，反序列化为 `MaliciousEventDto`。
2. 批量插入 `malicious_events` 集合。
3. 同步 upsert `actor_info` 集合（`upsertActorInfo` 方法，第 230-265 行）：
   - 过滤条件：`actorId` + `contextSource`。
   - 更新字段：`filterId`、`category`、`apiCollectionId`、`url`、`method`、`country`、`severity`、`host`、`latestMetadata`、`lastAttackTs`（max）、`discoveredAt`（min）、`updatedAt`、`totalAttacks`（inc 1）、`status`（默认 `ACTIVE`）、`isCritical`（仅 HIGH/CRITICAL 时设为 true，且不可逆，第 247-252 行）。
   - 使用 `UpdateOptions().upsert(true)`。

**输出**：MongoDB `malicious_events` 与 `actor_info` 集合。

#### 3.4.2 定时任务（Cron）

| Cron 类 | 调度周期 | 核心逻辑 |
|---------|----------|----------|
| `ArchiveOldMaliciousEventsCron` | 定时（基于 `ScheduledExecutorService`） | 将超过保留期（默认 60 天，可配置 30-90 天）的 `malicious_events` 迁移到 `archived_malicious_events` 集合；批量大小 5000，单次最多删除 100000 条（第 27-31 行） |
| `RiskScoreSyncCron` | 每 15 分钟（第 163 行） | 从 `malicious_events` 聚合每个 `ApiInfoKey` 的严重度列表，计算威胁分数（`MaliciousEventDao.getThreatScoreFromSeverities`），批量更新 `ApiInfo.THREAT_SCORE` 字段 |
| `SkillsRiskScoreSyncCron` | 每 15 分钟（第 179 行） | 类似 `RiskScoreSyncCron`，但基于 Skills 维度计算风险评分（`computeRiskScore`：CRITICAL=5、HIGH=4、MEDIUM=3，取最大值，第 182-195 行） |
| `PercentilesCron` | 定时 | 从 `api_distribution_data` 计算百分位（p50、p75、p90），写入 `api_rate_limit_bucket_statistics` 集合（`PercentilesResult`，第 380-386 行） |
| `CloudflareWafSyncCron` | 定时 | 查询 7 天内活跃且未 BLOCKED 的 Actor（`SEVEN_DAYS_SECONDS = 7 * 24 * 60 * 60`，第 28 行），调用 `CloudflareWafUtils.blockActorIps` 加入 Cloudflare WAF 黑名单，并标记 `ActorInfoDao` 状态为 `BLOCKED`（第 147-162 行） |
| `ConfigRiskSyncCron` | （已禁用，Main.java 第 117-118 行注释） | 检测配置错误并打标 `MISCONFIGURED` 标签 |

### 3.5 数据访问层（DAO）

所有 DAO 继承 `AccountBasedDao<T>`（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/dao/AccountBasedDao.java`），按账户 ID 隔离集合（集合名后缀 accountId）。

| DAO | 集合名 | 数据模型 |
|-----|--------|----------|
| `MaliciousEventDao` | `malicious_events` | `MaliciousEventDto` |
| `ArchivedMaliciousEventDao` | `archived_malicious_events` | `MaliciousEventDto` |
| `ActorInfoDao` | `actor_info` | `ActorInfoModel`（含 `actorId`、`filterId`、`category`、`apiCollectionId`、`url`、`method`、`country`、`severity`、`host`、`contextSource`、`discoveredAt`、`updatedAt`、`lastAttackTs`、`totalAttacks`、`status`、`isCritical`、`latestMetadata`） |
| `ThreatConfigurationDao` | `threat_configuration` | `Document`（动态结构） |
| `ApiDistributionDataDao` | `api_distribution_data` | `ApiDistributionDataModel` |
| `ApiRateLimitBucketStatisticsDao` | `api_rate_limit_bucket_statistics` | `ApiRateLimitBucketStatisticsModel` |
| `SplunkIntegrationDao` | `splunk_integration_config` | `SplunkIntegrationModel` |

**`MaliciousEventDao` 特殊方法**（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/dao/MaliciousEventDao.java`）：

- `getThreatScore(Severity)`：CRITICAL=1.0、HIGH=0.75、MEDIUM=0.5、LOW=0.25（第 57-70 行）。
- `getThreatScoreFromSeverities(List<String>)`：取所有严重度中的最大分数（第 72-78 行）。

### 3.6 工具类

- `SplunkEvent`（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/utils/SplunkEvent.java`）：将 `AggregateSampleMaliciousEventModel` 转为 JSON，POST 到 Splunk HTTP Event Collector，超时 1 秒（第 23-27 行）。
- `KafkaUtils`（`apps/threat-detection-backend/src/main/java/com/akto/threat/backend/utils/KafkaUtils.java`）：生成 `{eventType, payload, accountId}` 格式的 Kafka 消息（第 10-18 行）。
- `ThreatUtils`：索引管理、上下文过滤器构建（`buildSimpleContextFilter`、`buildSimpleContextFilterNew`、`isAgenticOrEndpointContext`）。

### 3.7 模块输入输出汇总

#### 输入

| 输入源 | 数据格式 | 来源 | 用途 |
|--------|----------|------|------|
| HTTP POST `/api/threat_detection/record_malicious_event` | `RecordMaliciousEventRequest` protobuf | Threat Detection 模块 | 恶意事件入库 |
| HTTP POST `/api/threat_detection/save_api_distribution_data` | `ApiDistributionDataRequestPayload` protobuf | Threat Detection 模块 | 分布数据入库 |
| HTTP POST `/api/dashboard/*` | protobuf JSON | Dashboard 模块 | 查询与管理操作 |
| Kafka topic `akto.threat_detection.internal_db_messages` | JSON（`KafkaUtils.generateMsg`） | 内部 | 批量入库 |
| MongoDB | 账户配置、过滤器、API 信息 | Dashboard 写入 | 上下文查询 |
| Cloudflare WAF API | JSON | Cloudflare | Actor 封禁 |
| Splunk HEC | JSON | Splunk | 事件转发 |

#### 输出

| 输出目标 | 数据格式 | 接收方 | 用途 |
|----------|----------|--------|------|
| HTTP 响应 `/api/dashboard/*` | protobuf JSON | Dashboard 模块 | 查询结果返回 |
| MongoDB `malicious_events` 等 | BSON | 自身 | 持久化 |
| MongoDB `actor_info` | BSON | 自身 | Actor 聚合 |
| MongoDB `ApiInfo.THREAT_SCORE` | BSON | Dashboard | 风险评分 |
| Cloudflare WAF | REST API | Cloudflare | Actor 封禁 |
| Splunk HEC | JSON | Splunk | 事件转发 |

---

## 4. Akto Dashboard 模块分析（威胁检测相关）

### 4.1 模块定位

Dashboard 模块是 Akto 的主应用，基于 Struts2 框架，提供 Web UI 与 REST API。威胁检测相关代码集中在 `apps/dashboard/src/main/java/com/akto/action/threat_detection/` 包下，作为 Dashboard 与 Threat Detection Backend 之间的代理层。

### 4.2 基类：AbstractThreatDetectionAction

**文件**：`apps/dashboard/src/main/java/com/akto/action/threat_detection/AbstractThreatDetectionAction.java`（154 行）

**核心职责**：

1. **Backend URL 配置**：从环境变量 `THREAT_DETECTION_BACKEND_URL` 读取，默认 `https://tbs.akto.io`（第 28 行）。
2. **API Token 获取**：`getApiToken()` 方法通过 `JwtAuthenticator` 为当前账户生成 JWT（第 31 行起）。
3. **HTTP 客户端**：使用 `OkHttpClient`（`CoreHTTPClient.client`）。
4. **响应转换**：`fetchMaliciousEvents(...)` 方法将 `ListMaliciousRequestsResponse` protobuf 转为 `DashboardMaliciousEvent` 业务对象列表（第 100-146 行）。

### 4.3 Action 类清单

| Action 类 | 文件 | 核心方法与对 Backend 的调用 |
|-----------|------|------------------------------|
| `ThreatActorAction` | ThreatActorAction.java（895 行） | `fetchActorsCountPerCounty` → POST `/api/dashboard/get_actors_count_per_country`；`listThreatActors` → POST `/api/dashboard/list_threat_actors`；`fetchAggregateMaliciousRequests` → POST `/api/dashboard/fetchAggregateMaliciousRequests`；`fetchThreatsForActor` → POST `/api/dashboard/fetch_threats_for_actor`；`modifyThreatActorStatus` → 调用 AWS WAF 或 Cloudflare WAF + POST `/api/dashboard/modifyThreatActorStatus`；`bulkModifyThreatActorStatusCloudflare` → Cloudflare WAF + POST `/api/dashboard/bulkModifyThreatActorStatus` |
| `ThreatApiAction` | ThreatApiAction.java（518 行） | `fetchThreatCategoryCount` → POST `/api/dashboard/get_subcategory_wise_count`；`fetchThreatSeverityCount` → POST `/api/dashboard/get_severity_wise_count`；`getDailyThreatActorsCount` → POST `/api/dashboard/get_daily_actor_count`；`fetchThreatActivityTimeline` → POST `/api/dashboard/fetch_threat_activity_timeline`；`fetchThreatApis` → POST `/api/dashboard/list_threat_apis`；`fetchTopNData` → POST `/api/dashboard/get_top_n_data`；`fetchDashboardTopData` → POST `/api/dashboard/fetch_dashboard_top_data` |
| `ThreatConfigurationAction` | ThreatConfigurationAction.java（124 行） | `fetchThreatConfiguration` → GET `/api/dashboard/fetch_threat_configuration`；`updateThreatConfiguration` → POST `/api/dashboard/update_threat_configuration`；`toggleArchivalEnabled` → POST `/api/dashboard/toggle_archival_enabled` |
| `SuspectSampleDataAction` | SuspectSampleDataAction.java（758 行） | `fetchMaliciousEvents` → POST `/api/dashboard/list_malicious_requests`；`updateMaliciousEventStatus` → POST `/api/dashboard/update_malicious_event_status`；`deleteMaliciousEvents` → POST `/api/dashboard/delete_malicious_events`；`fetchAlertFilters` → POST `/api/dashboard/fetch_alert_filters` |
| `SessionContextAction` | SessionContextAction.java（117 行） | `fetchSessionContext` → GET `/api/dashboard/fetch_session_context?sessionId=...` |
| `ReputationScoreAction` | ReputationScoreAction.java（50 行） | `fetchIpReputationScore` → 直接调用 `ReputationScoreAnalysis.getIpReputationScore(ipAddress)`（不经过 Backend） |
| `FilterYamlTemplateAction` | FilterYamlTemplateAction.java（110 行） | `fetchFilterYamlTemplate` / `saveFilterYamlTemplate` / `deleteFilterYamlTemplate` → 直接操作 `FilterYamlTemplateDao`（Dashboard 自身 MongoDB） |
| `ThreatReportAction` | ThreatReportAction.java（122 行） | `generateThreatReport` / `downloadThreatReportPDF` → 操作 `TestReportsDao`，生成 PDF 报告 |

### 4.4 Dashboard 与 Backend 的交互模式

1. **请求转发**：Dashboard Action 接收前端请求 → 构建 protobuf/JSON 请求体 → 添加 `Authorization: Bearer <token>` 头 → HTTP POST 到 Backend `/api/dashboard/*` → 解析 protobuf 响应 → 转为业务对象 → 返回前端。
2. **上下文传递**：通过 `x-context-source` 头传递 `Context.contextSource`（如 `API`、`ENDPOINT`、`AGENTIC`）。
3. **WAF 联动**：`ThreatActorAction.modifyThreatActorStatus` 先调用 AWS WAF 或 Cloudflare WAF API 封禁 IP，再调用 Backend 同步状态。
4. **训练数据提交**：`SuspectSampleDataAction.updateMaliciousEventStatus` 在状态更新为 `TRAINING` 时，异步调用 `submitTrainingDataToAnalyzer` 提交训练数据到 `agent-traffic-analyzer`（受 `Organization.featureWiseAllowed` 特性开关控制，第 420-425 行）。

### 4.5 模块输入输出汇总

#### 输入

| 输入源 | 数据格式 | 来源 | 用途 |
|--------|----------|------|------|
| HTTP 请求（Struts2 Action） | JSON / 表单 | 浏览器前端 | 用户操作 |
| MongoDB（Dashboard 自身） | BSON | 自身 | 过滤器模板、报告、配置 |
| `THREAT_DETECTION_BACKEND_URL` 环境变量 | String | 部署配置 | Backend 地址 |
| AWS WAF / Cloudflare WAF 凭证 | Config | `configs` 集合 | WAF 封禁 |

#### 输出

| 输出目标 | 数据格式 | 接收方 | 用途 |
|----------|----------|--------|------|
| HTTP 响应 | JSON | 浏览器前端 | 页面数据 |
| HTTP POST `/api/dashboard/*` | protobuf JSON | Threat Detection Backend | 查询与管理 |
| AWS WAF API | REST | AWS | IP 封禁 |
| Cloudflare WAF API | REST | Cloudflare | IP 封禁 |
| HTTP POST `agent-traffic-analyzer` | JSON | Agent Traffic Analyzer | 训练数据提交 |

---

## 5. 三模块业务逻辑关联关系

### 5.1 检测链路（Threat Detection → Backend）

1. **流量入口**：`MaliciousTrafficDetectorTask` 消费 `akto.api.logs2`，这是 Akto 流量采集层（如 `data-ingestion-service`）产出的统一流量日志 topic。
2. **检测执行**：任务对每条流量运行多种检测器：
   - **规则匹配**：`ThreatDetector.applyFilter` 基于 YAML 过滤器（LFI、SQLi、OS 命令注入、SSRF、XSS 等）。
   - **Hyperscan 加速**：启用时通过 `HyperscanThreatMatcher` 单次扫描多模式正则。
   - **序列异常**：`SequenceCache.checkSequenceAnomaly` 基于 API 转移概率检测异常序列。
   - **限流检测**：`ThreatConfigurationEvaluator` + `ApiCountCacheLayer` 基于 Redis 计数器检测 IP-API 级别限流。
   - **参数枚举**：`ParamEnumerationDetector` 基于 BloomFilter + CMS 检测参数枚举攻击。
   - **聚合检测**：`WindowBasedThresholdNotifier` 基于滑动窗口阈值检测聚合事件。
3. **事件产出**：检测命中后，`generateAndPushMaliciousEventRequest` 构建 `MaliciousEventKafkaEnvelope`（含 `MaliciousEventMessage` 列表），发送到 Kafka topic `akto.threat_detection.malicious_events`。
4. **事件转发**：`SendMaliciousEventsToBackend` 消费上述 topic，通过 HTTP POST `/api/threat_detection/record_malicious_event` 将事件发送至 Backend。
5. **事件落库**：Backend 的 `ThreatDetectionRouter` 接收请求，`MaliciousEventService.recordMaliciousEvent` 将事件写入 `malicious_events` 集合，`FlushMessagesToDB.upsertActorInfo` 同步更新 `actor_info` 集合。

### 5.2 查询链路（Dashboard → Backend）

1. **前端请求**：浏览器发起请求到 Dashboard 的 Struts2 Action（如 `ThreatActorAction.listThreatActors`）。
2. **请求转发**：Action 通过 `AbstractThreatDetectionAction.getApiToken()` 获取 JWT，构建 protobuf 请求体，HTTP POST 到 Backend `/api/dashboard/list_threat_actors`。
3. **Backend 查询**：`DashboardRouter` 路由到 `ThreatActorService.listThreatActors`，从 `actor_info` 集合分页查询（支持游标分页），返回 `ListThreatActorResponse` protobuf。
4. **响应转换**：Dashboard Action 将 protobuf 响应转为 `DashboardThreatActor` 业务对象列表，序列化为 JSON 返回前端。

### 5.3 配置链路（Dashboard → Backend → Threat Detection）

1. **配置写入**：用户在 Dashboard 修改威胁配置（限流规则、参数枚举阈值、归档天数等），`ThreatConfigurationAction.updateThreatConfiguration` → POST `/api/dashboard/update_threat_configuration` → `ThreatActorService.updateThreatConfiguration` 写入 `threat_configuration` 集合。
2. **配置读取**：Threat Detection 模块的 `ThreatConfigurationEvaluator.getThreatConfiguration()` 定期从 Backend 拉取配置（通过 HTTP），缓存后供检测任务使用。

### 5.4 封禁链路（Dashboard → WAF + Backend）

1. **用户触发**：用户在 Dashboard 点击"Block"，`ThreatActorAction.modifyThreatActorStatus` 执行。
2. **WAF 封禁**：
   - 优先尝试 Cloudflare WAF（`fetchCloudflareConfig` + `CloudflareWafUtils.blockActorIps`）。
   - 若未配置 Cloudflare，使用 AWS WAF（`fetchAwsWafClient` + `UpdateIpSetRequest`）。
3. **状态同步**：封禁成功后，POST `/api/dashboard/modifyThreatActorStatus` 或 `/api/dashboard/bulkModifyThreatActorStatus`，Backend 更新 `actor_info.status`。
4. **自动封禁**：Backend 的 `CloudflareWafSyncCron` 定时扫描 7 天内活跃且未封禁的 Actor，自动加入 Cloudflare WAF 黑名单。

### 5.5 归档链路（Backend 内部）

1. `ArchiveOldMaliciousEventsCron` 定时扫描 `malicious_events` 集合。
2. 将超过保留期（默认 60 天，可配置 30-90 天，由 `threat_configuration.archivalDays` 控制）的事件迁移到 `archived_malicious_events` 集合。
3. 批量大小 5000，单次最多删除 100000 条，防止 MongoDB 过载。

### 5.6 风险评分链路（Backend → Dashboard）

1. `RiskScoreSyncCron` 每 15 分钟从 `malicious_events` 聚合每个 `ApiInfoKey` 的严重度列表。
2. 调用 `MaliciousEventDao.getThreatScoreFromSeverities` 计算威胁分数（CRITICAL=1.0、HIGH=0.75、MEDIUM=0.5、LOW=0.25，取最大值）。
3. 批量更新 `ApiInfo.THREAT_SCORE` 字段（Dashboard 的 MongoDB）。
4. Dashboard 前端读取 `ApiInfo.THREAT_SCORE` 展示 API 风险等级。

### 5.7 第三方集成链路

- **Splunk**：`SplunkEvent.sendEvent` 将聚合恶意事件样本 POST 到 Splunk HEC（配置存于 `splunk_integration_config` 集合）。
- **Cloudflare WAF**：`CloudflareWafUtils.blockActorIps` / `unblockActorIps` 调用 Cloudflare API 管理 IP List。
- **AWS WAF**：`ThreatActorAction.blockActorIp` 调用 AWS WAFv2 `UpdateIpSetRequest`。
- **Jira**：`MaliciousEventService.updateMaliciousEventStatus` 支持更新 `jiraTicketUrl` 字段，关联 Jira 工单。
- **Agent Traffic Analyzer**：`SuspectSampleDataAction.submitTrainingDataToAnalyzer` 异步提交训练数据。

---

## 6. 三模块数据流转关系

### 6.1 数据流转图（详细）

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           流量采集层                                      │
│  (data-ingestion-service / akto-runtime / mirror / syslog 等)            │
└──────────────────────────────────────────────────────────────────────────┘
   │
   │ Kafka produce: akto.api.logs2 (HttpResponseParam protobuf)
   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    Akto Threat Detection                                 │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ MaliciousTrafficDetectorTask                                       │  │
│  │  - 消费 akto.api.logs2                                             │  │
│  │  - AccountConfigurationCache (15min 刷新)                          │  │
│  │  - FilterCache (300s 刷新, 从 FilterYamlTemplateDao)               │  │
│  │  - ThreatConfigurationEvaluator (从 Backend 拉取)                  │  │
│  │  - ThreatDetector (LFI/SQLi/SSRF/XSS Trie)                        │  │
│  │  - HyperscanThreatMatcher (可选, 高性能正则)                       │  │
│  │  - SequenceCache (API 序列异常, 10min 刷新)                        │  │
│  │  - ApiCountCacheLayer (Redis + Caffeine 限流计数)                  │  │
│  │  - ParamEnumerationDetector (BloomFilter + CMS)                    │  │
│  │  - WindowBasedThresholdNotifier (滑动窗口聚合)                     │  │
│  │  - DistributionDataForwardLayer (分布数据转发)                     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│         │                                │                                │
│         │ Kafka produce:                 │ HTTP POST                      │
│         │ akto.threat_detection.         │ /api/threat_detection/         │
│         │ malicious_events               │ save_api_distribution_data     │
│         ▼                                ▼                                │
│  ┌──────────────────────────────┐  ┌──────────────────────────────┐      │
│  │ SendMaliciousEventsToBackend │  │ DistributionDataForwardLayer │      │
│  │  - 消费 malicious_events     │  │  - 定时从 Redis Hash 读取    │      │
│  │  - HTTP POST → Backend       │  │  - 转发至 Backend            │      │
│  └──────────────────────────────┘  └──────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────┘
   │ HTTP POST: /api/threat_detection/record_malicious_event
   │ (RecordMaliciousEventRequest protobuf)
   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                  Akto Threat Detection Backend                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ThreatDetectionRouter (Vert.x)                                     │  │
│  │  - AuthenticationInterceptor (JWT 验签, RSA 公钥)                  │  │
│  │  - /record_malicious_event → MaliciousEventService                 │  │
│  │  - /save_api_distribution_data → ApiDistributionDataService        │  │
│  │  - /fetch_api_distribution_data → ApiDistributionDataService       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ DashboardRouter (Vert.x)                                           │  │
│  │  - 20+ 端点 (list_threat_actors, get_daily_actor_count, ...)      │  │
│  │  - 路由到 ThreatActorService / ThreatApiService /                  │  │
│  │    MaliciousEventService / ApiDistributionDataService              │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Service 层                                                         │  │
│  │  - MaliciousEventService (事件 CRUD, 过滤器, 状态更新)             │  │
│  │  - ThreatActorService (Actor 列表, 配置, 国家/每日统计)            │  │
│  │  - ThreatApiService (子分类/严重度计数, API 列表)                  │  │
│  │  - ApiDistributionDataService (分布数据保存与查询)                 │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ DAO 层 (AccountBasedDao, 按账户隔离)                               │  │
│  │  - MaliciousEventDao → malicious_events 集合                       │  │
│  │  - ActorInfoDao → actor_info 集合                                  │  │
│  │  - ThreatConfigurationDao → threat_configuration 集合              │  │
│  │  - ApiDistributionDataDao → api_distribution_data 集合             │  │
│  │  - SplunkIntegrationDao → splunk_integration_config 集合          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ 后台任务                                                           │  │
│  │  - FlushMessagesToDB (消费 internal_db_messages, 批量入库)         │  │
│  │  - ArchiveOldMaliciousEventsCron (归档, 默认 60 天)                │  │
│  │  - RiskScoreSyncCron (15min, 更新 ApiInfo.THREAT_SCORE)            │  │
│  │  - SkillsRiskScoreSyncCron (15min, Skills 维度风险评分)            │  │
│  │  - PercentilesCron (百分位计算)                                    │  │
│  │  - CloudflareWafSyncCron (自动封禁 7 天活跃 Actor)                 │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ 第三方集成                                                         │  │
│  │  - SplunkEvent → Splunk HEC (1s 超时)                              │  │
│  │  - CloudflareWafUtils → Cloudflare API                            │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
   ▲ HTTP POST/GET: /api/dashboard/* (protobuf JSON, Bearer JWT)
   │
┌──────────────────────────────────────────────────────────────────────────┐
│                    Akto Dashboard (action/threat_detection)              │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ AbstractThreatDetectionAction                                     │  │
│  │  - backendUrl = THREAT_DETECTION_BACKEND_URL (默认 tbs.akto.io)    │  │
│  │  - getApiToken() → JwtAuthenticator 生成 JWT                       │  │
│  │  - OkHttpClient (CoreHTTPClient)                                   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ Action 类 (Struts2)                                                │  │
│  │  - ThreatActorAction (Actor 列表/封禁/WAF 联动)                    │  │
│  │  - ThreatApiAction (计数/时间线/Top N)                             │  │
│  │  - ThreatConfigurationAction (配置管理)                             │  │
│  │  - SuspectSampleDataAction (事件列表/状态更新/删除)                 │  │
│  │  - SessionContextAction (会话上下文)                                │  │
│  │  - ReputationScoreAction (IP 信誉, 直连)                           │  │
│  │  - FilterYamlTemplateAction (过滤器模板, 直连 Dashboard Mongo)     │  │
│  │  - ThreatReportAction (PDF 报告)                                   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ WAF 联动                                                           │  │
│  │  - AWS WAF: Wafv2Client.updateIPSet                               │  │
│  │  - Cloudflare WAF: CloudflareWafUtils.blockActorIps                │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
   ▲ HTTP (JSON)
   │
[浏览器 / Vue 前端]
```

### 6.2 关键数据流详解

#### 6.2.1 恶意事件数据流

```
[流量] 
  → Kafka(akto.api.logs2, HttpResponseParam protobuf)
  → MaliciousTrafficDetectorTask.processRecord
    → ThreatDetector.applyFilter (命中)
    → Utils.buildSampleMaliciousRequest (构建 SampleMaliciousRequest)
    → generateAndPushMaliciousEventRequest
      → KafkaProtoProducer.send(akto.threat_detection.malicious_events, MaliciousEventKafkaEnvelope)
  → SendMaliciousEventsToBackend.processRecords
    → ApiExecutor.sendRequest(POST /api/threat_detection/record_malicious_event, RecordMaliciousEventRequest)
  → Backend: ThreatDetectionRouter
    → MaliciousEventService.recordMaliciousEvent
      → MaliciousEventDao.insertOne (malicious_events 集合)
      → FlushMessagesToDB.upsertActorInfo (actor_info 集合)
```

#### 6.2.2 Dashboard 查询数据流

```
[浏览器]
  → Dashboard: ThreatActorAction.listThreatActers
    → HTTP POST /api/dashboard/list_threat_actors (Bearer JWT, ListThreatActorsRequest protobuf)
  → Backend: DashboardRouter
    → ThreatActorService.listThreatActors
      → ActorInfoDao.getCollection(accountId).find(match).sort(sortBson).skip(skip).limit(limit)
    → ListThreatActorResponse protobuf
  → Dashboard: ProtoMessageUtils.toProtoMessage → List<DashboardThreatActor>
  → JSON 响应 → 浏览器
```

#### 6.2.3 限流检测数据流

```
[流量]
  → MaliciousTrafficDetectorTask.processRecord
    → ThreatConfigurationEvaluator.getRatelimit(templateApiInfoKey)
    → ApiCountCacheLayer (Redis 计数器, Caffeine 本地缓存)
    → 若计数 > ratelimit:
      → ThreatConfigurationEvaluator.isActorInMitigationPeriod (Redis 查询)
      → 若未在缓解期:
        → setActorInMitigationPeriod (Redis SET with expiry)
        → generateAndPushMaliciousEventRequest(IpApiRateLimited filter, EVENT_TYPE_SINGLE)
```

#### 6.2.4 API 分布数据流

```
[流量]
  → MaliciousTrafficDetectorTask.processRecord
    → 异步 XADD 到 Redis Stream (dist|{windowSize}|{windowStart}|{apiTuple})
  → DistributionStreamConsumer (消费 Redis Stream)
    → 写入 Redis Hash (dist|{windowSize}|{windowStart}|{apiTuple})
    → 更新 Redis Sorted Set (distApis|{windowSize}|{windowStart})
  → DistributionDataForwardLayer (定时)
    → 读取 Redis Hash + Sorted Set
    → HTTP POST /api/threat_detection/save_api_distribution_data
  → Backend: ApiDistributionDataService.saveApiDistributionData
    → ApiDistributionDataDao.bulkWrite (api_distribution_data 集合)
  → PercentilesCron (定时)
    → 聚合计算 p50/p75/p90
    → 写入 api_rate_limit_bucket_statistics 集合
  → Dashboard 查询: HTTP POST /api/threat_detection/fetch_api_distribution_data
    → ApiDistributionDataService.getDistributionStats
    → FetchApiDistributionDataResponse (含 BucketStats)
```

---

## 7. 输入输出汇总

### 7.1 Akto Threat Detection 模块

#### 输入

| # | 输入项 | 类型 | 格式 | 来源 | 处理组件 |
|---|--------|------|------|------|----------|
| 1 | API 流量日志 | Kafka 消息 | `HttpResponseParam` protobuf | `akto.api.logs2` topic | `MaliciousTrafficDetectorTask` |
| 2 | 恶意事件（内部） | Kafka 消息 | `MaliciousEventKafkaEnvelope` protobuf | `akto.threat_detection.malicious_events` topic | `SendMaliciousEventsToBackend` |
| 3 | 账户配置 | MongoDB（通过 DataActor） | `AccountConfig` | Dashboard 写入 | `AccountConfigurationCache` |
| 4 | 过滤器模板 | MongoDB（通过 DataActor） | `FilterConfig` | Dashboard 写入 | `FilterCache` |
| 5 | API 序列 | MongoDB（通过 DataActor） | `ApiSequences` | Dashboard 写入 | `SequenceCache` |
| 6 | 威胁配置 | HTTP | `ThreatConfiguration` protobuf | Backend `/api/dashboard/fetch_threat_configuration` | `ThreatConfigurationEvaluator` |
| 7 | 限流计数 | Redis | Long | 自身写入 | `ApiCountCacheLayer` |
| 8 | 分布数据 | Redis Stream/Hash | - | 自身写入 | `DistributionStreamConsumer` |
| 9 | 环境变量配置 | HTTP（通过 DataActor） | Map | Dashboard | `ConfigPoller` |

#### 输出

| # | 输出项 | 类型 | 格式 | 目标 | 生成组件 |
|---|--------|------|------|------|----------|
| 1 | 恶意事件 | Kafka 消息 | `MaliciousEventKafkaEnvelope` protobuf | `akto.threat_detection.malicious_events` topic | `MaliciousTrafficDetectorTask` |
| 2 | 恶意事件（转发） | HTTP POST | `RecordMaliciousEventRequest` protobuf JSON | Backend `/api/threat_detection/record_malicious_event` | `SendMaliciousEventsToBackend` |
| 3 | API 分布数据 | HTTP POST | `ApiDistributionDataRequestPayload` protobuf JSON | Backend `/api/threat_detection/save_api_distribution_data` | `DistributionDataForwardLayer` |
| 4 | 限流状态 | Redis | Long / String | 自身 | `ApiCountCacheLayer` |
| 5 | 分布数据 | Redis Stream/Hash | - | 自身 | `DistributionStreamConsumer` |
| 6 | 指标 | MongoDB（通过 DataActor） | `MetricData` | Dashboard | `AllMetrics` |
| 7 | 环境变量文件 | 文件 | `.env` 格式 | `/app/.env` | `ConfigPoller` |

### 7.2 Akto Threat Detection Backend 模块

#### 输入

| # | 输入项 | 类型 | 格式 | 来源 | 处理组件 |
|---|--------|------|------|------|----------|
| 1 | 恶意事件 | HTTP POST | `RecordMaliciousEventRequest` protobuf | Threat Detection 模块 | `ThreatDetectionRouter` → `MaliciousEventService` |
| 2 | API 分布数据（保存） | HTTP POST | `ApiDistributionDataRequestPayload` protobuf | Threat Detection 模块 | `ThreatDetectionRouter` → `ApiDistributionDataService` |
| 3 | API 分布数据（查询） | HTTP POST | `FetchApiDistributionDataRequest` protobuf | Dashboard 模块 | `ThreatDetectionRouter` → `ApiDistributionDataService` |
| 4 | Dashboard 查询请求 | HTTP POST/GET | protobuf JSON | Dashboard 模块 | `DashboardRouter` → 各 Service |
| 5 | 内部 DB 消息 | Kafka 消息 | JSON（`KafkaUtils.generateMsg`） | `akto.threat_detection.internal_db_messages` topic | `FlushMessagesToDB` |
| 6 | JWT 认证 | HTTP Header | `Bearer <JWT>` | Dashboard 模块 | `AuthenticationInterceptor` |
| 7 | Cloudflare WAF 配置 | MongoDB | `Config.CloudflareWafConfig` | Dashboard 写入 | `CloudflareWafSyncCron` |
| 8 | Splunk 配置 | MongoDB | `SplunkIntegrationModel` | Dashboard 写入 | `SplunkEvent` |

#### 输出

| # | 输出项 | 类型 | 格式 | 目标 | 生成组件 |
|---|--------|------|------|------|----------|
| 1 | Dashboard 查询响应 | HTTP 响应 | protobuf JSON | Dashboard 模块 | `DashboardRouter` |
| 2 | 恶意事件持久化 | MongoDB 写入 | BSON | `malicious_events` 集合 | `MaliciousEventDao` |
| 3 | Actor 信息持久化 | MongoDB 写入 | BSON | `actor_info` 集合 | `ActorInfoDao` |
| 4 | 归档事件 | MongoDB 写入 | BSON | `archived_malicious_events` 集合 | `ArchiveOldMaliciousEventsCron` |
| 5 | API 风险评分 | MongoDB 更新 | BSON | `ApiInfo.THREAT_SCORE` | `RiskScoreSyncCron` |
| 6 | 分布统计 | MongoDB 写入 | BSON | `api_distribution_data` 集合 | `ApiDistributionDataService` |
| 7 | 百分位统计 | MongoDB 写入 | BSON | `api_rate_limit_bucket_statistics` 集合 | `PercentilesCron` |
| 8 | Cloudflare WAF 封禁 | REST API | JSON | Cloudflare | `CloudflareWafSyncCron` |
| 9 | Splunk 事件 | HTTP POST | JSON | Splunk HEC | `SplunkEvent` |

### 7.3 Akto Dashboard 模块（威胁检测相关）

#### 输入

| # | 输入项 | 类型 | 格式 | 来源 | 处理组件 |
|---|--------|------|------|------|----------|
| 1 | 用户操作 | HTTP 请求 | JSON / 表单 | 浏览器前端 | 各 Action 类 |
| 2 | Backend URL | 环境变量 | String | `THREAT_DETECTION_BACKEND_URL` | `AbstractThreatDetectionAction` |
| 3 | 过滤器模板 | MongoDB | `YamlTemplate` | Dashboard 自身 | `FilterYamlTemplateAction` |
| 4 | WAF 配置 | MongoDB | `Config.AwsWafConfig` / `Config.CloudflareWafConfig` | Dashboard 自身 | `ThreatActorAction` |
| 5 | 报告数据 | MongoDB | `TestReports` | Dashboard 自身 | `ThreatReportAction` |
| 6 | IP 信誉数据 | 内部计算 | `IpReputationScore` | `ReputationScoreAnalysis` | `ReputationScoreAction` |

#### 输出

| # | 输出项 | 类型 | 格式 | 目标 | 生成组件 |
|---|--------|------|------|------|----------|
| 1 | 页面数据 | HTTP 响应 | JSON | 浏览器前端 | 各 Action 类 |
| 2 | Backend 查询请求 | HTTP POST/GET | protobuf JSON + Bearer JWT | Backend `/api/dashboard/*` | 各 Action 类 |
| 3 | 事件记录请求 | HTTP POST | `RecordMaliciousEventRequest` protobuf JSON | Backend `/api/threat_detection/record_malicious_event` | （间接，通过 Threat Detection） |
| 4 | AWS WAF 封禁 | REST API | - | AWS WAFv2 | `ThreatActorAction.blockActorIp` |
| 5 | Cloudflare WAF 封禁 | REST API | JSON | Cloudflare | `CloudflareWafUtils.blockActorIps` |
| 6 | 训练数据 | HTTP POST | JSON | `agent-traffic-analyzer` | `SuspectSampleDataAction.submitTrainingDataToAnalyzer` |
| 7 | PDF 报告 | 文件 | PDF | 浏览器下载 | `ThreatReportAction.downloadThreatReportPDF` |

---

## 8. 关键数据结构与协议

### 8.1 Protobuf 消息

| 消息名 | 包路径 | 用途 |
|--------|--------|------|
| `HttpResponseParam` | `com.akto.proto.http_response_param.v1` | 流量日志（Threat Detection 输入） |
| `MaliciousEventKafkaEnvelope` | `com.akto.proto.generated.threat_detection.message.malicious_event.v1` | Kafka 恶意事件信封 |
| `MaliciousEventMessage` | `com.akto.proto.generated.threat_detection.message.malicious_event.v1` | 单条恶意事件 |
| `SampleMaliciousRequest` | `com.akto.proto.generated.threat_detection.message.sample_request.v1` | 恶意请求样本 |
| `SchemaConformanceError` | `com.akto.proto.generated.threat_detection.message.sample_request.v1` | Schema 一致性错误 |
| `RecordMaliciousEventRequest` | `com.akto.proto.generated.threat_detection.service.malicious_alert_service.v1` | 记录恶意事件请求 |
| `ThreatConfiguration` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 威胁配置 |
| `RatelimitConfig` / `RatelimitConfigItem` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 限流配置 |
| `ParamEnumerationConfig` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 参数枚举配置 |
| `ListThreatActorsRequest` / `ListThreatActorResponse` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | Actor 列表查询 |
| `ListMaliciousRequestsRequest` / `ListMaliciousRequestsResponse` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 恶意请求列表查询 |
| `FetchMaliciousEventsRequest` / `FetchMaliciousEventsResponse` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 恶意事件查询 |
| `DeleteMaliciousEventsRequest` / `DeleteMaliciousEventsResponse` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 恶意事件删除 |
| `DailyActorsCountRequest` / `DailyActorsCountResponse` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 每日 Actor 计数 |
| `ThreatActorByCountryRequest` / `ThreatActorByCountryResponse` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 按国家统计 Actor |
| `ThreatCategoryWiseCountRequest` / `Response` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 子分类计数 |
| `ThreatSeverityWiseCountRequest` / `Response` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 严重度计数 |
| `ApiDistributionDataRequestPayload` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | API 分布数据 |
| `FetchApiDistributionDataRequest` / `Response` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | API 分布查询 |
| `BucketStats` | `com.akto.proto.generated.threat_detection.service.dashboard_service.v1` | 桶统计（含 min/max/p25/p50/p75） |
| `BulkUpdateAgenticSessionContextRequest` | `com.akto.proto.generated.threat_detection.service.agentic_session_service.v1` | 批量更新会话上下文 |
| `SessionDocumentMessage` | `com.akto.proto.generated.threat_detection.message.agentic_session.v1` | 会话文档 |
| `OwaspCategory` | `com.akto.proto.generated.threat_detection.message.malicious_event.v1` | OWASP 分类 |
| `EventType` | `com.akto.proto.generated.threat_detection.message.malicious_event.event_type.v1` | 事件类型（SINGLE/AGGREGATED） |

### 8.2 MongoDB 数据模型

| 模型类 | 集合名 | 关键字段 |
|--------|--------|----------|
| `MaliciousEventDto` | `malicious_events` | id, actor, filterId, endpoint, method, apiCollectionId, ip, country, destCountry, detectedAt, type, refId, category, subCategory, eventTypeVal, payload, metadata, status, successfulExploit, label, host, jiraTicketUrl, severity, sessionId, owaspCategories |
| `ActorInfoModel` | `actor_info` | id, actorId, filterId, category, apiCollectionId, url, method, country, severity, host, contextSource, discoveredAt, updatedAt, lastAttackTs, totalAttacks, status, isCritical, latestMetadata |
| `ApiDistributionDataModel` | `api_distribution_data` | apiCollectionId, url, method, windowSize, windowStart, distribution (Map) |
| `ApiRateLimitBucketStatisticsModel` | `api_rate_limit_bucket_statistics` | （百分位统计） |
| `SplunkIntegrationModel` | `splunk_integration_config` | splunkUrl, splunkToken |
| `AggregateSampleMaliciousEventModel` | `aggregate_sample_malicious_requests` | （聚合样本） |
| `Document`（动态） | `threat_configuration` | actor, ratelimitConfig, paramEnumerationConfig, archivalDays, archivalEnabled |

### 8.3 Redis Key 规范

| Key 模式 | 用途 | 来源 |
|----------|------|------|
| `RATE_LIMIT_CACHE_PREFIX + ipApiCmsKey + ":mitigation"` | 限流缓解期标记 | `ThreatConfigurationEvaluator` |
| `IP_API_CMS_DATA_PREFIX + "\|" + apiCollectionId + "\|" + ip + "\|" + url + "\|" + method` | IP-API CMS 数据 | `Utils.buildIpApiCmsDataKey` |
| `API_COUNTER_KEY_PREFIX + "\|" + apiCollectionId + "\|" + url + "\|" + method + "\|" + binId` | API 计数器（按分钟桶） | `ApiCountCacheLayer.buildCountKey` |
| `API_COUNTER_INDEX` (Sorted Set) | API 计数器索引 | `ApiCountCacheLayer` |
| `dist\|{windowSize}\|{windowStart}\|{apiTuple}` (Hash) | 分布数据 | `DistributionStreamConsumer` |
| `distApis\|{windowSize}\|{windowStart}` (Sorted Set) | 活跃 API 列表 | `DistributionStreamConsumer` |
| `distLock\|{windowSize}\|{windowStart}` (String, NX + EX 60) | 分布数据转发锁 | `DistributionDataForwardLayer` |

---

## 9. 附录：源码引用索引

### 9.1 Akto Threat Detection 模块

| 文件 | 行数 | 用途 |
|------|------|------|
| `Main.java` | 320 | 模块入口 |
| `tasks/AbstractKafkaConsumerTask.java` | 88 | Kafka 消费者抽象基类 |
| `tasks/MaliciousTrafficDetectorTask.java` | 664 | 核心检测任务 |
| `tasks/SendMaliciousEventsToBackend.java` | 77 | 事件转发任务 |
| `tasks/ThreatConfigurationEvaluator.java` | 352 | 威胁配置评估器 |
| `tasks/ConfigPoller.java` | 113 | 配置轮询器 |
| `constants/KafkaTopic.java` | 10 | Kafka Topic 常量 |
| `constants/RedisKeyInfo.java` | - | Redis Key 常量 |
| `actor/SourceIPActorGenerator.java` | 25 | Actor ID 生成器 |
| `cache/AccountConfigurationCache.java` | 212 | 账户配置缓存 |
| `cache/FilterCache.java` | 132 | 过滤器缓存 |
| `cache/ApiCountCacheLayer.java` | 247 | API 计数缓存层 |
| `cache/SequenceCache.java` | 114 | 序列异常缓存 |
| `utils/ThreatDetector.java` | 722 | 威胁检测器（规则匹配） |
| `utils/Utils.java` | 242 | 工具类 |
| `kafka/KafkaProtoProducer.java` | 62 | Kafka protobuf 生产者 |
| `hyperscan/HyperscanThreatMatcher.java` | 348 | Hyperscan 匹配器 |
| `ip_api_counter/ParamEnumerationDetector.java` | 115 | 参数枚举检测器 |
| `ip_api_counter/BloomFilterLayer.java` | 93 | BloomFilter 层 |
| `ip_api_counter/CmsCounterLayer.java` | - | CMS 计数层 |
| `ip_api_counter/DistributionStreamConsumer.java` | - | 分布流消费者 |
| `ip_api_counter/DistributionDataForwardLayer.java` | 228 | 分布数据转发层 |
| `smart_event_detector/window_based/WindowBasedThresholdNotifier.java` | 143 | 窗口阈值通知器 |

### 9.2 Akto Threat Detection Backend 模块

| 文件 | 行数 | 用途 |
|------|------|------|
| `Main.java` | 144 | 模块入口 |
| `BackendVerticle.java` | 131 | Vert.x Verticle |
| `router/ARouter.java` | 10 | 路由接口 |
| `router/ThreatDetectionRouter.java` | 116 | 事件接收路由 |
| `router/DashboardRouter.java` | 738 | Dashboard 查询路由 |
| `interceptors/AuthenticationInterceptor.java` | 70 | JWT 认证拦截器 |
| `interceptors/Constants.java` | - | 拦截器常量 |
| `service/MaliciousEventService.java` | 883 | 恶意事件服务 |
| `service/ThreatActorService.java` | 1526 | 威胁 Actor 服务 |
| `service/ThreatApiService.java` | 247 | 威胁 API 服务 |
| `service/ApiDistributionDataService.java` | 150 | API 分布数据服务 |
| `dao/AccountBasedDao.java` | - | 账户隔离 DAO 基类 |
| `dao/MaliciousEventDao.java` | 80 | 恶意事件 DAO |
| `dao/ActorInfoDao.java` | - | Actor 信息 DAO |
| `dao/ThreatConfigurationDao.java` | 29 | 威胁配置 DAO |
| `dao/ApiDistributionDataDao.java` | - | API 分布数据 DAO |
| `dao/ApiRateLimitBucketStatisticsDao.java` | - | 百分位统计 DAO |
| `dao/ArchivedMaliciousEventDao.java` | - | 归档事件 DAO |
| `dao/SplunkIntegrationDao.java` | - | Splunk 集成 DAO |
| `dao/ThreatDetectionDaoInit.java` | - | DAO 初始化 |
| `db/ActorInfoModel.java` | 66 | Actor 信息模型 |
| `db/ApiDistributionDataModel.java` | 19 | API 分布数据模型 |
| `db/ApiRateLimitBucketStatisticsModel.java` | - | 百分位统计模型 |
| `db/AggregateSampleMaliciousEventModel.java` | - | 聚合样本模型 |
| `db/SplunkIntegrationModel.java` | - | Splunk 集成模型 |
| `tasks/FlushMessagesToDB.java` | 267 | 批量入库任务 |
| `cron/ArchiveOldMaliciousEventsCron.java` | 252 | 归档定时任务 |
| `cron/RiskScoreSyncCron.java` | 166 | 风险评分同步任务 |
| `cron/SkillsRiskScoreSyncCron.java` | 197 | Skills 风险评分任务 |
| `cron/PercentilesCron.java` | 388 | 百分位计算任务 |
| `cron/CloudflareWafSyncCron.java` | 164 | Cloudflare WAF 同步任务 |
| `cron/ConfigRiskSyncCron.java` | 179 | 配置风险同步任务（已禁用） |
| `utils/SplunkEvent.java` | 77 | Splunk 事件工具 |
| `utils/KafkaUtils.java` | 20 | Kafka 工具 |
| `utils/ThreatUtils.java` | - | 威胁工具 |
| `constants/KafkaTopic.java` | 8 | Kafka Topic 常量 |
| `constants/MongoDBCollection.java` | 20 | MongoDB 集合常量 |
| `constants/StatusConstants.java` | - | 状态常量 |
| `dto/RateLimitConfigDTO.java` | - | 限流配置 DTO |
| `dto/ParamEnumerationConfigDTO.java` | - | 参数枚举配置 DTO |

### 9.3 Akto Dashboard 模块（威胁检测相关）

| 文件 | 行数 | 用途 |
|------|------|------|
| `action/threat_detection/AbstractThreatDetectionAction.java` | 154 | 威胁检测 Action 基类 |
| `action/threat_detection/ThreatActorAction.java` | 895 | 威胁 Actor Action |
| `action/threat_detection/ThreatApiAction.java` | 518 | 威胁 API Action |
| `action/threat_detection/ThreatConfigurationAction.java` | 124 | 威胁配置 Action |
| `action/threat_detection/SuspectSampleDataAction.java` | 758 | 可疑样本数据 Action |
| `action/threat_detection/SessionContextAction.java` | 117 | 会话上下文 Action |
| `action/threat_detection/ReputationScoreAction.java` | 50 | IP 信誉 Action |
| `action/threat_detection/FilterYamlTemplateAction.java` | 110 | 过滤器模板 Action |
| `action/threat_detection/ThreatReportAction.java` | 122 | 威胁报告 Action |
| `action/threat_detection/utils/ThreatsUtils.java` | - | 威胁工具 |
| `action/threat_detection/utils/ThreatDetectionHelper.java` | - | 威胁检测助手 |
| `action/threat_detection/DashboardMaliciousEvent.java` | - | 恶意事件视图模型 |
| `action/threat_detection/DashboardThreatActor.java` | - | Actor 视图模型 |
| `action/threat_detection/DashboardThreatApi.java` | - | API 视图模型 |
| `action/threat_detection/DashboardTopActorData.java` | - | Top Actor 视图模型 |
| `action/threat_detection/DashboardTopApiData.java` | - | Top API 视图模型 |
| `action/threat_detection/ThreatActorPerCountry.java` | - | 国家维度 Actor 视图 |
| `action/threat_detection/ThreatCategoryCount.java` | - | 分类计数视图 |
| `action/threat_detection/DailyActorsCount.java` | - | 每日 Actor 计数视图 |
| `action/threat_detection/ThreatActivityTimeline.java` | - | 活动时间线视图 |
| `action/threat_detection/TopApiData.java` | - | Top API 数据 |
| `action/threat_detection/TopHostData.java` | - | Top Host 数据 |
| `action/threat_detection/MaliciousPayloadsResponse.java` | - | 恶意载荷响应 |
| `action/threat_detection/ThreatConfiguration.java` | - | 威胁配置视图 |

---

**报告说明**：

- 本报告所有逻辑、数据流、字段名、类名、方法名、常量值均直接来自 Akto 仓库源码，未做任何推测、补全或编造。
- 行号引用基于分析时的仓库快照，可能随仓库更新而变化。
- 报告聚焦于三个目标模块的威胁检测相关部分，Dashboard 模块的其他功能（如 API 清单、测试套件、用户管理等）不在本次分析范围内。
