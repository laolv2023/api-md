# Akto api-analyser vs api-runtime 对比分析报告

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto
> 分析模块：`apps/api-analyser/`（Context Analyzer）与 `apps/api-runtime/`（Runtime Analyzer）

---

## 1. 概览

Akto 的流量分析由两个独立模块负责，它们在产品文档中分别被称为 **Context Analyzer** 和 **Runtime Analyzer**。

| 维度 | api-analyser (Context Analyzer) | api-runtime (Runtime Analyzer) |
|---|---|---|
| **产品名** | Context Analyzer | Runtime Analyzer |
| **ECR 镜像** | `aktosecurity/akto-api-context-analyzer` | `aktosecurity/akto-api-security-runtime` |
| **代码路径** | `apps/api-analyser/` | `apps/api-runtime/` |
| **Main-Class** | `com.akto.analyser.Main` | `com.akto.runtime.Main` |
| **Java 文件数** | 2（+1 测试） | 22（+16 测试） |
| **代码行数** | 472 行 | 7,140 行 |
| **社区版** | ❌ 不含（Enterprise only） | ✅ 作为库运行 |
| **文档** | `Documentation/components/context-analyzer.md` | `Documentation/components/runtime-analyzer.md` |

---

## 2. 架构对比

### 2.1 部署架构

```
                    ┌─────────────────────────────────────────┐
                    │              Kafka 消息总线               │
                    │                                         │
                    │   akto.api.logs (主题)                    │
                    │   har_akto.api.logs (HAR 导入)           │
                    │   .*central (企业版镜像主题)              │
                    └────────┬──────────────────┬─────────────┘
                             │                  │
                    订阅: .*central     订阅: akto.api.logs, har_*
                             │                  │
                    ┌────────▼────────┐  ┌──────▼──────────┐
                    │  api-analyser   │  │  api-runtime    │
                    │ (Context)       │  │ (Runtime)       │
                    │                 │  │                  │
                    │ Enterprise only │  │ 社区版+企业版     │
                    │ 独立 ASG        │  │ 独立 ASG/NLB    │
                    │ 私有子网         │  │ 私有子网         │
                    └────────┬────────┘  └──────┬──────────┘
                             │                  │
                    ┌────────▼────────┐  ┌──────▼──────────┐
                    │  MongoDB        │  │  MongoDB         │
                    │  yaml_templates │  │  yaml_templates  │
                    │  SingleTypeInfo │  │  SingleTypeInfo  │
                    │  (统计维度)      │  │  ApiCollections  │
                    │                 │  │  TrafficMetrics  │
                    │                 │  │  AuthPolicy      │
                    │                 │  │  Dependencies    │
                    └─────────────────┘  └──────────────────┘
```

### 2.2 依赖关系

api-analyser **依赖** api-runtime 的库：

```xml
<!-- api-analyser/pom.xml -->
<dependency>
    <groupId>com.akto.apps.api-runtime</groupId>
    <artifactId>api-runtime</artifactId>  <!-- 依赖 api-runtime 的 HttpCallParser, APICatalogSync 等 -->
</dependency>
```

api-runtime 是更底层的模块，api-analyser 在其基础上构建。

---

## 3. 功能对比

### 3.1 api-runtime（Runtime Analyzer）

**核心职责：实时流量处理，构建 API 清单**

| 功能 | 实现类 | 行数 | 说明 |
|---|---|---|---|
| **HTTP 消息解析** | `HttpCallParser` | 843 | 解析 Kafka 消息为 HttpResponseParams |
| **API 目录同步** | `APICatalogSync` | 2,097 | URL 模板化、合并、API 发现 |
| **认证策略检测** | `AuthPolicy` | 139 | 自动检测 Bearer/JWT/Cookie 等认证方式 |
| **API 流程图** | `Flow` | 64 | API 调用顺序分析 |
| **马尔可夫模型** | `MarkovSync` | 151 | API 调用序列的马尔可夫链建模 |
| **API 关系图** | `RelationshipSync` | 245 | API 间数据依赖关系 |
| **依赖分析** | `DependencyAnalyser` | 470 | 参数级依赖分析（A 的响应 → B 的请求） |
| **负载分析** | `PayloadAnalyzer` | 95 | 请求负载结构分析 |
| **URL 聚合** | `URLAggregator` | 81 | URL 去参数化、基础 URL 提取 |
| **URL 合并** | `MergeOnSlash/MergeOnHostOnly/MergeSimilarUrls` | — | 多种 URL 合并策略 |
| **数据采样** | `SampleDataToSTI` | 169 | 流量样本 → SingleTypeInfo |
| **敏感数据脱敏** | `RedactSampleData` | 375 | 请求/响应中的密码、Token 等脱敏 |
| **流量指标** | `TrafficMetrics` | — | API 调用频率、状态码分布 |
| **MCP 工具同步** | `McpToolsSyncJobExecutor` | 669 | MCP 工具发现和同步 |
| **Agent 检测** | `AgentBasePromptDetectionService` | 389 | AI Agent 基础提示检测 |
| **策略引擎** | `AktoPolicyNew` | 437 | 运行时策略（认证、字段设置等） |

**数据处理流程：**

```
Kafka 消息
    │
    ▼
HttpCallParser.parseKafkaMessage()     ← 解析原始消息
    │
    ▼
filterBasedOnHeaders()                 ← 按账户设置过滤
    │
    ▼
HttpCallParser.syncFunction()          ← 核心同步函数
    ├── APICatalogSync.tryParamteresingUrl()   ← URL 模板化
    ├── APICatalogSync.tryMergeUrls()          ← URL 合并
    ├── APICatalogSync.syncWithDB()            ← 写入 MongoDB
    ├── SampleDataToSTI                        ← 采样数据
    ├── RedactSampleData                       ← 脱敏处理
    ├── AuthPolicy                             ← 认证检测
    ├── DependencyAnalyser                     ← 依赖分析
    ├── RelationshipSync                       ← 关系图同步
    ├── MarkovSync                             ← 马尔可夫模型
    └── TrafficMetrics                         ← 流量指标
```

**Kafka 订阅：**
- 主题：`akto.api.logs` + `har_akto.api.logs`（环境变量 `AKTO_KAFKA_TOPIC_NAME`）
- 消费者组：环境变量 `AKTO_KAFKA_GROUP_ID_CONFIG`

**多租户支持：**
- 按 accountId 分组处理
- 每个账户独立维护 `HttpCallParser` 实例
- 定期检查 STI 文档数（超过 2000 万条跳过）

### 3.2 api-analyser（Context Analyzer）

**核心职责：从流量中推断 API 上下文，降低测试误报**

| 功能 | 实现类 | 行数 | 说明 |
|---|---|---|---|
| **Kafka 消费** | `Main` | 99 | 消费 `.*central` 主题 |
| **资源分析** | `ResourceAnalyser` | 373 | 参数级统计：唯一值 vs 公开值 |
| **Bloom Filter 去重** | `ResourceAnalyser` | — | 双 BF：3 亿容量去重 + 1 亿容量值检测 |
| **URL 模板匹配** | `ResourceAnalyser` | — | 匹配流量到已有 URL 模板 |
| **参数移动检测** | `ResourceAnalyser` | — | 检测参数值从"唯一"变为"公开" |
| **批量 DB 同步** | `ResourceAnalyser` | — | 每 120 秒或 20 万条触发批量写入 |

**数据处理流程：**

```
Kafka 消息 (.*central)
    │
    ▼
HttpCallParser.parseKafkaMessage()     ← 复用 api-runtime 的解析器
    │
    ▼
ResourceAnalyser.analyse()             ← 核心分析
    ├── 过滤：只处理 2xx 响应
    ├── 提取 userId（X-Forwarded-For）
    ├── 匹配 URL 到模板/静态 URL
    ├── 分析 URL 路径参数（INTEGER/STRING 部分）
    ├── 分析请求负载参数
    └── 对每个参数值统计：
        ├── checkDuplicate()           ← Bloom Filter 去重（用户×URL×参数×值）
        ├── checkIfPresent()           ← 值是否已被其他用户访问过
        ├── checkIfMoved()             ← 值是否从"唯一"变为"公开"
        ├── incUniqueCount()           ← 唯一值计数 +1
        └── incPublicCount()           ← 公开值计数 +1
    │
    ▼
syncWithDb()                           ← 批量同步到 MongoDB
    ├── buildCatalog()                 ← 从 DB 加载 API 目录
    ├── populateHostNameToIdMap()      ← 主机名→集合 ID 映射
    ├── getDbUpdatesForSingleTypeInfo() ← 生成批量更新
    └── SingleTypeInfoDao.bulkWrite()  ← 写入 MongoDB
```

**Kafka 订阅：**
- 主题：`.*central`（正则匹配，企业版镜像主题）
- 消费者组：`analyzer-group-config`

**多租户支持：**
- 按 accountId 维护独立 `ResourceAnalyser` 实例
- 每个实例有独立的 Bloom Filter

---

## 4. 核心差异

### 4.1 功能差异

| 功能 | api-analyser | api-runtime |
|---|---|---|
| HTTP 消息解析 | ✅（复用 api-runtime） | ✅（自研） |
| API 发现（URL 模板化） | ❌（读取已有） | ✅（创建/合并） |
| 认证策略检测 | ❌ | ✅ |
| API 流程图/马尔可夫 | ❌ | ✅ |
| API 关系/依赖分析 | ❌ | ✅ |
| 参数值统计（唯一/公开） | ✅ | ❌ |
| Bloom Filter 去重 | ✅ | ❌ |
| 敏感数据脱敏 | ❌ | ✅ |
| 流量指标 | ❌ | ✅ |
| MCP 工具同步 | ❌ | ✅ |
| Agent 检测 | ❌ | ✅ |
| URL 合并 | ❌ | ✅ |
| 多租户 | ✅ | ✅ |
| HAR 文件处理 | ❌ | ✅ |

### 4.2 数据写入差异

| MongoDB 集合 | api-analyser | api-runtime |
|---|---|---|
| `single_type_info` | ✅（更新 uniqueCount/publicCount） | ✅（创建/更新完整 STI） |
| `api_collections` | ✅（只读） | ✅（创建/更新） |
| `traffic_metrics` | ❌ | ✅ |
| `auth_policy` | ❌ | ✅ |
| `dependencies` | ❌ | ✅ |
| `sample_data` | ❌ | ✅ |

### 4.3 性能特征差异

| 维度 | api-analyser | api-runtime |
|---|---|---|
| **处理延迟** | 低优先级，可容忍延迟 | 实时（<1s） |
| **吞吐量** | 中等（Batch 处理） | 高（最高 1M calls/min） |
| **更新频率** | 每 120 秒或 20 万条批量同步 | 每条消息实时处理 |
| **内存使用** | 高（双 Bloom Filter：3 亿 + 1 亿条目） | 中等 |
| **运行时长** | 长周期（1 小时+） | 持续运行 |
| **数据处理量** | 数据饥饿型（需要大量数据才有效） | 数据驱动型 |

### 4.4 部署差异

| 维度 | api-analyser | api-runtime |
|---|---|---|
| **社区版** | ❌ 不含 | ✅ 作为库运行（Postman/Burp/HAR 触发） |
| **企业版** | 独立 Docker 容器 | 独立 Docker 容器 |
| **基础设施** | 独立 ASG + 独立 Kafka | 独立 ASG + 私有 NLB |
| **网络** | 私有子网 | 私有子网 |
| **CloudFormation 资源** | `AktoContextAnalyzerAutoScalingGroup` | `AktoRuntimeAnalyzerAutoScalingGroup` |
| **JDK** | OpenJDK 18（ECR 镜像） | OpenJDK（Dockerfile FROM openjdk） |
| **内存管理** | 80% 容器内存（cgroup 检测） | 80% 容器内存（cgroup 检测） |

---

## 5. 协作关系

两个模块并非竞争关系，而是**流水线式的协作**：

```
步骤 1: api-runtime 实时处理流量
    ├── 发现 API 端点 → 写入 SingleTypeInfo
    ├── 检测认证方式 → 写入 AuthPolicy
    ├── 合并 URL → 写入 APICatalog
    └── 分析依赖关系 → 写入 Dependencies

步骤 2: api-analyser 读取 api-runtime 的产出
    ├── 读取 SingleTypeInfo 中的 API 端点（buildCatalog）
    ├── 读取 ApiCollections 中的主机名映射
    └── 对每个 API 的参数值进行统计分析

步骤 3: api-analyser 的产出被测试引擎使用
    ├── uniqueCount（唯一值数）→ 用于判断是否是私有资源
    ├── publicCount（公开值数）→ 用于判断参数是否可枚举
    └── 这些统计值直接降低 BOLA、IDOR 等测试的误报率
```

**具体例子：**

BOLA 测试需要判断 `/api/users/{id}` 中的 `id` 是否是私有资源。如果 api-analyser 统计出 `id` 参数有 1,000 个唯一值（不同用户访问不同的 ID），测试引擎就知道这是一个私有资源，需要进行越权测试。如果没有 api-analyser 的统计，测试引擎无法区分 `/api/users/{id}` 和 `/api/products/{category}` 的差异。

---

## 6. 代码结构对比

### 6.1 api-analyser（472 行，2 个类）

```
apps/api-analyser/
├── Dockerfile
├── pom.xml
├── start.sh
└── src/main/java/com/akto/analyser/
    ├── Main.java              (99 行)  ← 入口：Kafka 消费 + 多租户分发
    └── ResourceAnalyser.java  (373 行) ← 核心：参数值统计 + Bloom Filter + DB 同步
```

### 6.2 api-runtime（7,140 行，22 个类）

```
apps/api-runtime/
├── Dockerfile
├── pom.xml
├── start.sh
└── src/main/java/com/akto/
    ├── parsers/
    │   └── HttpCallParser.java          (843 行)  ← HTTP 消息解析 + 核心同步
    ├── runtime/
    │   ├── Main.java                    (440 行)  ← 入口：Kafka 消费 + 多租户
    │   ├── APICatalogSync.java          (2,097 行) ← API 目录同步 + URL 模板化
    │   ├── Flow.java                    (64 行)   ← API 流程图
    │   ├── MarkovSync.java              (151 行)  ← 马尔可夫模型
    │   ├── RelationshipSync.java        (245 行)  ← API 关系图
    │   ├── PayloadAnalyzer.java         (95 行)   ← 负载分析
    │   ├── URLAggregator.java           (81 行)   ← URL 聚合
    │   ├── McpToolsSyncJobExecutor.java (669 行)  ← MCP 工具同步
    │   ├── AgentBasePromptDetectionService.java (389 行) ← Agent 检测
    │   ├── KafkaHealthMetricSyncTask.java (65 行)
    │   └── merge/                       ← URL 合并策略
    │       ├── MergeOnHostOnly.java
    │       ├── MergeOnSlash.java
    │       └── MergeSimilarUrls.java
    ├── dependency/
    │   ├── DependencyAnalyser.java      (470 行)  ← 依赖分析
    │   └── store/                       ← 依赖存储
    │       ├── BFStore.java             ← Bloom Filter 存储
    │       ├── HashSetStore.java
    │       └── Store.java
    ├── runtime/policies/
    │   ├── AktoPolicyNew.java           (437 行)  ← 策略引擎
    │   ├── AuthPolicy.java              (139 行)  ← 认证策略
    │   └── SetFieldPolicy.java          (20 行)
    └── utils/
        ├── CalculateJob.java
        ├── CustomAuthUtil.java
        ├── DataInsertionUtil.java
        ├── RedactSampleData.java        (375 行)  ← 脱敏
        └── SampleDataToSTI.java         (169 行)  ← 采样
```

---

## 7. 总结

| 维度 | api-analyser (Context Analyzer) | api-runtime (Runtime Analyzer) |
|---|---|---|
| **定位** | 上下文分析器，降低误报 | 运行时分析器，构建 API 清单 |
| **核心输出** | 参数级统计（uniqueCount/publicCount） | API 目录、认证、依赖、流量指标 |
| **处理时机** | 后置（读取 api-runtime 的产出） | 前置（直接消费原始流量） |
| **代码规模** | 472 行（2 类） | 7,140 行（22 类） |
| **社区版** | 不含 | 包含（作为库） |
| **依赖关系** | 依赖 api-runtime | 被 api-analyser 依赖 |
| **数据处理模式** | 批量（120s / 20 万条） | 实时（逐条） |
| **Bloom Filter** | 双 BF（3 亿 + 1 亿） | 无（DependencyAnalyser 有自己的 BF） |
| **Kafka 主题** | `.*central` | `akto.api.logs` + `har_*` |
| **MongoDB 写入** | 仅 `single_type_info`（更新计数） | 多个集合（创建/更新完整数据） |

两个模块形成流水线：**api-runtime 构建 API 清单 → api-analyser 统计参数上下文 → 测试引擎利用统计值降低误报**。社区版只包含 api-runtime（作为库），企业版两者都部署为独立服务。
