# Akto Data Ingestion Service 模块详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/apps/data-ingestion-service
> 代码规模：18 个 Java 文件，2,681 行
> ECR 镜像：`aktosecurity/akto-data-ingestion-service`
> 端口：9091

---

## 1. 功能定位

Data Ingestion Service 是 Akto 的**流量接入网关**，负责接收来自多种数据源的 API 流量，转换格式后发布到 Kafka（或 HTTP ingest API），供下游的 api-runtime 和 guardrails-service 消费。

### 核心职责

| 职责 | 说明 |
|---|---|
| **HTTP 流量接入** | 接收来自 Akto SDK/中间件的 HTTP 流量数据（`/api/ingestData`） |
| **HTTP 代理 + 护栏** | 接收流量并执行 guardrails 策略（`/api/http-proxy`） |
| **Syslog TCP 接入** | 监听 TCP 5140 端口，接收 Apigee 等 syslog 流量 |
| **分块重组** | 支持大消息分块传输，在服务端重组 |
| **MCP 主机重写** | MCP 流量的 Host 头自动重写为真实集合名 |
| **Arcade Webhook** | 接收 Arcade AI Agent 的 pre/post hook |
| **Dify Moderation** | Dify 平台的内容审核代理 |
| **TrueFoundry 代理** | TrueFoundry 平台的请求代理 |
| **双通道发布** | 流量同时发布到主 Kafka topic 和 guardrails topic |

---

## 2. 技术栈

| 技术 | 用途 |
|---|---|
| Jetty 9.4 (JRE 8) | Servlet 容器 |
| Struts2 2.5 | MVC 框架 |
| Kafka Client | 流量发布到 Kafka |
| OkHttp | HTTP ingest 模式 / 外部调用 |
| JWT (jjwt) | 请求认证 |
| MongoDB Driver | 配置查询（MCP 集合解析） |

---

## 3. 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     数据来源                                     │
├─────────────┬──────────────┬──────────────┬────────────────────┤
│ HTTP API    │ HTTP Proxy   │ Syslog TCP   │ Arcade Webhook     │
│ /api/       │ /api/http-   │ :5140        │ /pre, /post        │
│ ingestData  │ proxy        │              │                    │
│             │              │              │                    │
│ Akto SDK    │ AI Agent     │ Apigee       │ Arcade.dev         │
│ 中间件       │ Connector    │ MessageLog   │                    │
└──────┬──────┴──────┬───────┴──────┬───────┴─────────┬──────────┘
       │             │              │                 │
       ▼             ▼              ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Data Ingestion Service                        │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │IngestionAction│  │HttpProxyAction│  │ArcadeWebhookAction  │  │
│  │              │  │              │  │                      │  │
│  │ 批量接入      │  │ 代理+护栏    │  │ Arcade hook → 流量   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                     │              │
│         ▼                 ▼                     ▼              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              TrafficPublisher (接口)                     │  │
│  │                                                          │  │
│  │  ┌─────────────────┐    ┌──────────────────────────┐     │  │
│  │  │ TopicPublisher  │    │ HttpTrafficPublisher     │     │  │
│  │  │ (Kafka 模式)    │    │ (HTTP ingest 模式)       │     │  │
│  │  └─────────────────┘    └──────────────────────────┘     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────────────────────┐   │
│  │SyslogTcpListener │  │McpCollectionResolver             │   │
│  │ :5140            │  │ (每 1 分钟刷新 MCP 集合缓存)      │   │
│  │ → 分块重组        │  │                                  │   │
│  │ → KafkaUtils      │  └──────────────────────────────────┘   │
│  └──────────────────┘                                          │
│                                                                 │
│  ┌──────────────────┐                                          │
│  │ AuthFilter       │  JWT 认证（可选）                         │
│  └──────────────────┘                                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
          ┌─────────────────┐   ┌─────────────────┐
          │ Kafka           │   │ HTTP Ingest API │
          │ akto.api.logs   │   │ /utility/       │
          │ akto.guardrails │   │ ingestTraffic   │
          └─────────────────┘   └─────────────────┘
                    │
                    ▼
          ┌─────────────────┐
          │ api-runtime     │
          │ guardrails-svc  │
          └─────────────────┘
```

---

## 4. API 端点

| 端点 | 方法 | Action 类 | 说明 |
|---|---|---|---|
| `/api/ingestData` | POST | `IngestionAction.ingestData()` | 批量流量接入（主要入口） |
| `/api/http-proxy` | POST | `HttpProxyAction.httpProxy()` | HTTP 代理 + guardrails 策略执行 |
| `/api/http-proxy/dify` | POST | `DifyModerationAction.moderation()` | Dify 平台内容审核 |
| `/api/http-proxy/truefoundry` | POST | `TrueFoundryProxyAction.truefoundry()` | TrueFoundry 平台代理 |
| `/pre` | POST | `ArcadeWebhookAction.arcade()` | Arcade pre-tool hook |
| `/post` | POST | `ArcadeWebhookAction.arcade()` | Arcade post-tool hook |
| `/healthCheck` | GET | `IngestionAction.healthCheck()` | 健康检查 |
| `/api/auth-check` | GET | `IngestionAction.authCheck()` | 认证检查 |
| TCP `:5140` | — | `SyslogTcpListener` | Syslog TCP 流量接入 |

---

## 5. 核心组件详解

### 5.1 IngestionAction（批量流量接入）

**入口**：`POST /api/ingestData`

**数据格式**：
```json
{
  "batchData": [
    {
      "path": "/api/users/123",
      "method": "GET",
      "requestHeaders": "{\"host\":\"api.example.com\"}",
      "responseHeaders": "{\"content-type\":\"application/json\"}",
      "requestPayload": "",
      "responsePayload": "{\"id\":123,\"name\":\"Alice\"}",
      "ip": "10.0.0.1",
      "statusCode": "200",
      "akto_account_id": "1000000",
      "akto_vxlan_id": "0",
      "source": "MIRRORING",
      "tag": "{\"akto_guardrail_mode\":\"OBSERVE\"}"
    }
  ]
}
```

**处理流程**：
1. 接收批量数据（`List<IngestDataBatch>`）
2. 为每条数据设置 `akto_guardrail_mode = OBSERVE`
3. 调用 `KafkaUtils.insertData()` 发布到 Kafka

### 5.2 HttpProxyAction（HTTP 代理 + 护栏）

**入口**：`POST /api/http-proxy`

**功能**：接收 AI Agent 的 HTTP 请求，执行 guardrails 策略，同时将流量 ingest 到 Kafka。

**处理流程**：
1. 构建 `requestData` Map（包含 path/headers/payload 等 25 个字段）
2. 如果 tag 中包含 MCP 标记 → `McpCollectionResolver` 重写 Host 头
3. 调用 `Gateway.processHttpProxy()` 执行 guardrails 策略
4. 根据 connector 类型设置 guardrail mode（OBSERVE 或 INLINE）
5. 失败时发送 Slack 告警

### 5.3 SyslogTcpListener（Syslog TCP 接入）

**端口**：5140（可通过 `SYSLOG_TCP_PORT` 配置）

**功能**：接收 Apigee MessageLogging 等系统的 syslog 流量。

**支持的帧格式**：
- **换行分隔** — 每行一个 JSON 消息
- **RFC6587 octet-counted** — `<长度> <消息内容>`

**分块重组机制**（`SyslogMessageProcessor`）：

大消息会被拆分为多个 chunk 发送：
```json
{
  "aktoChunk": {
    "id": "req-123",
    "idx": 0,
    "total": 3,
    "payload": "{\"batchData\":[{\"path\":\"/api/...",
    "reqId": "req-123",
    "bytes": 1000000,
    "sig": "abc123"
  }
}
```

**重组逻辑**：
| 参数 | 值 | 说明 |
|---|---|---|
| 最大 chunk 数 | 500 | 单条消息最多拆分 500 块 |
| 最大重组大小 | 1,000,000 字节 | 重组后不超过 1MB |
| chunk TTL | 30 秒 | 30 秒未完成的 chunk 被清理 |
| 最大并发 chunk | 5,000 | 同时处理的最大 chunk 消息数 |
| 清理间隔 | 每 200 条消息 | 定期清理过期 chunk |
| 校验 | reqId + bytes + sig | 防止跨请求 chunk 混淆 |

### 5.4 TrafficPublisher（发布接口）

两种实现，通过 `USE_HTTP_INGEST` 环境变量切换：

| 模式 | 实现类 | 目标 | 启用条件 |
|---|---|---|---|
| Kafka | `TopicPublisher` | Kafka topic `akto.api.logs` (+ `akto.guardrails`) | 默认 |
| HTTP | `HttpTrafficPublisher` | `POST {TRAFFIC_INGEST_URL}/utility/ingestTraffic` | `USE_HTTP_INGEST=true` |

**Kafka 模式**（默认）：
```java
// 主 topic
kafkaProducer.send(message, "akto.api.logs");

// 如果 publishToGuardrails=true 且 guardrails 启用
kafkaProducer.send(message, "akto.guardrails");
```

**HTTP 模式**（mini-runtime 场景）：
```java
// POST 到 mini-runtime 的 ingest API
POST http://mini-runtime-svc:8001/utility/ingestTraffic
Content-Type: application/json

<message>
```

> HTTP 模式不支持 guardrails 发布，适合轻量级部署。

### 5.5 ArcadeWebhookAction（Arcade AI Agent Hook）

**入口**：`POST /pre` 和 `POST /post`

**功能**：接收 Arcade.dev 平台的 AI Agent 工具调用 hook，转换为 Akto 流量格式，执行 guardrails 策略。

**三种 hook 类型**：
| Hook 类型 | URL | 说明 |
|---|---|---|
| `tool_access` | `/access` | 工具访问权限检查 |
| `pre_tool_execution` | `/pre` | 工具执行前 hook（执行 guardrails） |
| `post_tool_execution` | `/post` | 工具执行后 hook（响应 guardrails） |

**处理流程**：
1. 从 URL 检测 hook 类型
2. 解析 JSON body（tool/inputs/context/execution_id 等）
3. 转换为 Akto 流量格式（path/method/headers/payload）
4. 设置 tag: `{"gen-ai":"Gen AI", "source":"ARCADE_DEV"}`
5. 设置 `contextSource: AGENTIC`
6. 调用 `Gateway.processHttpProxy()` 执行 guardrails
7. 如果被阻断：ingest 阻断请求（statusCode=403）
8. 如果放行：ingest 允许的响应

### 5.6 McpCollectionResolver（MCP 集合名解析）

**功能**：MCP 流量的 Host 头是临时集合名，需要重写为真实集合名。

**机制**：
- 每 1 分钟从 DataActor 拉取 `EndpointMcpConfig` 列表
- 维护 `tempCollectionName → collectionName` 的 ConcurrentHashMap
- HttpProxyAction 处理 MCP 流量时，自动重写 Host 头

### 5.7 GuardrailsConfig（护栏配置）

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `ENABLE_GUARDRAILS` | `false` | 启用 guardrails topic 发布 |
| `GUARDRAILS_TOPIC` | `akto.guardrails` | guardrails Kafka topic 名称 |

### 5.8 AuthFilter（认证过滤器）

**认证模式**（通过 `AKTO_DI_AUTHENTICATE` 环境变量控制）：

| 配置 | 行为 |
|---|---|
| `AKTO_DI_AUTHENTICATE` 未设置或 `false` | **跳过认证**（所有请求放行） |
| `AKTO_DI_AUTHENTICATE=true` + `RSA_PUBLIC_KEY` | 使用环境变量中的 RSA 公钥验证 JWT |
| `AKTO_DI_AUTHENTICATE=true`（无 RSA_PUBLIC_KEY） | 使用 `JwtAuthenticator`（通过 database-abstractor） |

**Token 撤销**：`AKTO_DI_REVOKED_TOKENS` 环境变量支持逗号分隔的 token 黑名单。

---

## 6. 消费数据来源

| 来源 | 接入方式 | 数据格式 |
|---|---|---|
| Akto SDK（Java/Python/Node/Go/Ruby） | HTTP POST `/api/ingestData` | batchData JSON |
| AI Agent Connector | HTTP POST `/api/http-proxy` | 单条请求/响应 |
| Apigee MessageLogging | Syslog TCP `:5140` | JSON in syslog |
| Arcade.dev | HTTP POST `/pre`, `/post` | Arcade webhook JSON |
| Dify | HTTP POST `/api/http-proxy/dify` | Dify moderation JSON |
| TrueFoundry | HTTP POST `/api/http-proxy/truefoundry` | TrueFoundry JSON |
| HAR 文件导入 | 通过 Dashboard → Kafka | （不直接经过本服务） |

---

## 7. 生产数据去处

| 去向 | 条件 | 说明 |
|---|---|---|
| Kafka `akto.api.logs` | 默认 | 主流量 topic，api-runtime 消费 |
| Kafka `akto.guardrails` | `ENABLE_GUARDRAILS=true` + `publishToGuardrails=true` | guardrails-service 消费 |
| HTTP `{TRAFFIC_INGEST_URL}/utility/ingestTraffic` | `USE_HTTP_INGEST=true` | mini-runtime 消费 |

---

## 8. 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AKTO_MONGO_CONN` | — | MongoDB 连接串（必填） |
| `AKTO_KAFKA_BROKER_URL` | `localhost:29092` | Kafka broker 地址 |
| `AKTO_KAFKA_TOPIC` | `akto.api.logs` | 主流量 Kafka topic |
| `AKTO_KAFKA_USERNAME` | — | Kafka SASL 用户名 |
| `AKTO_KAFKA_PASSWORD` | — | Kafka SASL 密码 |
| `AKTO_KAFKA_SASL_MECHANISM` | `PLAIN` | Kafka SASL 机制 |
| `AKTO_KAFKA_PRODUCER_BATCH_SIZE` | `100` | Kafka 批量大小 |
| `AKTO_KAFKA_PRODUCER_LINGER_MS` | `10` | Kafka linger 毫秒 |
| `USE_HTTP_INGEST` | `false` | 使用 HTTP ingest 替代 Kafka |
| `TRAFFIC_INGEST_URL` | — | HTTP ingest 目标 URL |
| `ENABLE_GUARDRAILS` | `false` | 启用 guardrails topic |
| `GUARDRAILS_TOPIC` | `akto.guardrails` | guardrails topic 名称 |
| `SYSLOG_TCP_ENABLED` | `true` | 启用 Syslog TCP 监听 |
| `SYSLOG_TCP_PORT` | `5140` | Syslog TCP 端口 |
| `AKTO_DI_AUTHENTICATE` | `false` | 启用 JWT 认证 |
| `RSA_PUBLIC_KEY` | — | JWT 验证公钥 |
| `AKTO_DI_REVOKED_TOKENS` | — | 撤销的 token 列表（逗号分隔） |

---

## 9. 代码规模

| 包 | 文件数 | 行数 | 说明 |
|---|---|---|---|
| `action` | 5 | ~1,200 | Struts2 Action（API 端点） |
| `listener` | 4 | ~900 | 初始化 + Syslog 监听 |
| `utils` | 5 | ~500 | Kafka/HTTP 发布工具 |
| `config` | 1 | ~50 | Guardrails 配置 |
| `filters` | 1 | ~100 | JWT 认证过滤器 |
| `publisher` | 1 | ~30 | Kafka 数据发布器 |
| **合计** | **17** | **~2,681** | |

---

## 10. 部署

### 10.1 Docker

```dockerfile
FROM jetty:9.4-jre8
EXPOSE 9091
```

### 10.2 部署模式

| 模式 | 说明 |
|---|---|
| **企业版 SaaS** | 独立容器 + Kafka，多租户 |
| **On-Prem** | 独立容器 + Kafka，单租户 |
| **Mini-Runtime** | `USE_HTTP_INGEST=true`，不依赖 Kafka，发布到 mini-runtime HTTP API |
| **社区版** | 不部署此服务（Dashboard 直接内嵌 api-runtime 处理导入流量） |

---

## 11. 安全发现

### 11.1 硬编码 JWT Token

`IngestionAction.java` 中硬编码了一个 JWT token：

```java
System.setProperty("DATABASE_ABSTRACTOR_SERVICE_TOKEN", 
    "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJBa3RvIiwic3ViIjoiaW52aXRlX3VzZXIiLCJhY2NvdW50SWQiOjE2NjI2ODA0NjMsImlhdCI6MTc2MDU5NzM0OCwiZXhwIjoxNzc2MzIyMTQ4fQ...");
```

这是一个**严重安全问题**——JWT token 硬编码在源码中，有效期到 2026 年（exp=1776322148）。

### 11.2 认证默认关闭

`AKTO_DI_AUTHENTICATE` 默认未设置，**认证默认关闭**，任何能访问 9091 端口的请求都能注入流量。

### 11.3 注释掉的客户名过滤

`sendLogsToCustomAccount()` 中有注释掉的代码，包含特定客户名（hollywoodbets、betsolutions 等）的过滤逻辑，`return true` 硬编码为始终触发。

---

## 12. 局限性

### 12.1 性能

- **单进程** — Jetty 单进程，Syslog TCP 仅 8 线程池
- **Kafka 同步发送** — `kafkaProducer.send()` 可能阻塞
- **无背压** — 流量高峰时可能积压

### 12.2 可靠性

- **无消息确认** — HTTP ingest 失败时消息直接丢弃
- **429 丢弃** — HTTP ingest 返回 429 时消息丢弃
- **分块重组内存** — chunk 重组在内存中，大流量可能 OOM

### 12.3 可维护性

- **硬编码 token** — 安全隐患
- **注释代码** — 客户名过滤逻辑被注释但未删除
- **accountId 硬编码** — `1745303931` 特殊处理（空 method/path 补默认值）

---

## 13. 总结

| 维度 | 值 |
|---|---|
| 代码规模 | 18 Java 文件 / 2,681 行 |
| API 端点 | 8 个（HTTP） + 1 个（TCP） |
| 数据来源 | 7 种（SDK/Agent/Apigee/Arcade/Dify/TrueFoundry/Syslog） |
| 发布目标 | Kafka（2 个 topic）或 HTTP ingest |
| 部署模式 | 企业版 / On-Prem / Mini-Runtime |
| 社区版 | ❌ 不部署（Dashboard 直接处理） |
| 是否使用 ML | ❌ 否 |
| 安全风险 | ⚠️ 硬编码 JWT token + 认证默认关闭 |

Data Ingestion Service 是 Akto 企业版的**流量入口**——所有外部流量（SDK、AI Agent、Apigee、Arcade 等）都经过此服务，转换格式后发布到 Kafka 供下游处理。它不是流量处理器（不提取 API 端点、不做敏感数据识别），而是**数据管道的接入层**。社区版不部署此服务，Dashboard 直接内嵌 api-runtime 处理导入流量。
