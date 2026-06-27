# Akto Threat Detection Backend 模块详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/apps/threat-detection-backend
> 代码规模：41 个 Java 文件，7,240 行
> ECR 镜像：`aktosecurity/akto-threat-detection-backend`
> 端口：9090

---

## 1. 功能定位

Threat Detection Backend 是 Akto 威胁检测系统的**后端服务**，负责接收 threat-detection 模块产生的告警事件，持久化到 MongoDB，并提供 Dashboard 查询 API。它是威胁检测数据的**存储层和查询层**。

### 与 threat-detection 的分工

| 维度 | threat-detection | threat-detection-backend |
|---|---|---|
| **角色** | 检测引擎（生产者） | 存储与查询服务（消费者） |
| **技术栈** | Java + Kafka Consumer + Redis | Java + **Vert.x** + MongoDB |
| **输入** | Kafka 实时流量 | Kafka 告警事件 + HTTP API 请求 |
| **输出** | Kafka 告警事件 + HTTP 转发 | MongoDB 持久化 + HTTP API 响应 |
| **端口** | 无（Kafka 消费者） | 9090（HTTP API） |
| **Web 框架** | 无 | **Vert.x Web**（非 Struts2） |

### 核心能力

| 能力 | 说明 |
|---|---|
| **告警事件存储** | 从 Kafka 消费告警事件，批量写入 MongoDB |
| **Dashboard API** | 提供威胁告警、威胁 Actor、威胁配置等查询接口 |
| **Threat Detection API** | 提供 MaliciousEvent 记录、API 分布数据等接口 |
| **威胁 Actor 管理** | 按 IP 维度聚合告警，计算 Actor 风险评分 |
| [SYSTEM_NOTE: Content compressed. Read the full version if needed.]sCron** | Cron 多但部分被注释（ConfigRiskSyncCron），调度逻辑分散

### 11.2 性能

- **Vert.x 单实例** — 无集群，无水平扩展
- **MongoDB 批量写入** — 5 秒间隔，可能积压
- **无缓存层** — 查询直接打 MongoDB

### 11.3 可靠性

- **双 MongoDB 连接** — 威胁 DB + Dashboard DB，任一不可用影响部分功能
- **Kafka 消费阻塞** — FlushMessagesToDB 单线程，崩溃后需重启
- **健康检查** — `/health` 端点检测 Kafka poll 和 MongoDB write 延迟

---

## 12. 总结

| 维度 | 值 |
|---|---|
| 代码规模 | 41 Java 文件 / 7,240 行 |
| Web 框架 | Vert.x Web（唯一非 Struts2 模块） |
| HTTP API | 2 个 Router（Dashboard 15+ 路由 / ThreatDetection 4 路由） |
| Kafka 消费 | 1 个 topic（`internal_db_messages`） |
| MongoDB 集合 | 8 个（独立威胁 DB） |
| 定时任务 | 6 个 |
| 端口 | 9090 |
| 社区版 | ❌ 不部署 |
| 是否使用 ML | ❌ 否 |

Threat Detection Backend 是 Akto 威胁检测系统的**后端服务**——从 Kafka 消费告警事件写入 MongoDB，通过 Vert.x HTTP API 为 Dashboard 提供威胁查询、Actor 管理、配置管理、分布统计等接口。它是唯一使用 Vert.x（而非 Struts2）的模块，使用独立的威胁 MongoDB（`AKTO_THREAT_PROTECTION_MONGO_CONN`），与 Dashboard 的 MongoDB 分离。社区版不部署此模块。
