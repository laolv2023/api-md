# AIWAF 对接 Akto Kafka 数据源 — 设计方案

> 项目：AIWAF (https://github.com/laolv2023/aiwaf)
> 数据源：Akto (https://github.com/akto-api-security/akto)
> 日期：2026-06-27
> 状态：设计评审

---

## 1. 需求概述

AIWAF 需要从 Akto 的 Kafka Topic `akto.api.logs2` 消费 API 流量数据，经检测引擎处理后，将告警输出到 Kafka Topic `akto.aiwaf.alerts`。

```
┌────────────────────────────────────────────────────────────────┐
│                        Akto 平台                                 │
│                                                                │
│  data-ingestion-service → Kafka: akto.api.logs (JSON)           │
│                                      │                         │
│                    api-runtime 消费 JSON → 处理                  │
│                                      │                         │
│                    ??? 桥梁 ??? → Kafka: akto.api.logs2 (Protobuf) │
│                                                │                │
└────────────────────────────────────────────────┼────────────────┘
                                                 │
                                    ┌────────────┼────────────┐
                                    │            │            │
                                    ▼            ▼            ▼
                          threat-detection   aiwaf (新增)
                          (现有消费者)        (新增消费者)
                                    │            │
                                    ▼            ▼
                          akto.threat_detection   akto.aiwaf.alerts
                          .malicious_events       (新增 Topic)
```

---

## 2. 现状分析

### 2.1 Akto 侧现状

**Topic `akto.api.logs2` 消息格式：Protobuf（非 JSON）**

消息值为 `byte[]`，反序列化为 Protobuf `HttpResponseParam`：

```protobuf
// protobuf/threat_detection/message/http_response_param/v1/http_response_param.proto
message HttpResponseParam {
    string method = 1;
    string path = 2;                    // 含完整 URI（含 query string）
    string type = 3;
    map<string, StringList> request_headers = 4;
    string request_payload = 5;
    int32 api_collection_id = 6;
    int32 status_code = 7;
    string status = 8;
    map<string, StringList> response_headers = 9;
    string response_payload = 10;
    int32 time = 11;                    // Unix timestamp (int32)
    string akto_account_id = 12;
    string ip = 13;                     // 客户端 IP
    string dest_ip = 14;
    string direction = 15;
    bool is_pending = 16;
    string source = 17;
    string akto_vxlan_id = 18;
}
```

**消费端代码验证：**
```java
// MaliciousTrafficDetectorTask.java L188
HttpResponseParam httpResponseParam = HttpResponseParam.parseFrom(record.value());
```

**生产端：** 代码中未找到直接生产到 `akto.api.logs2` 的模块。该 Topic 的生产者可能在 Akto 的 SaaS/On-Prem 基础设施中（cloud-agent 或 infra 层），不在开源仓库中。但消息格式已通过消费端代码确认是 Protobuf。

> **注意：`akto.api.logs`（JSON）和 `akto.api.logs2`（Protobuf）是两个不同的 Topic：**
> - `akto.api.logs` — JSON 格式，data-ingestion-service 生产，api-runtime/api-analyser 消费
> - `akto.api.logs2` — Protobuf 格式，生产者不在开源仓库中，threat-detection 消费

### 2.2 AIWAF 侧现状

| 维度 | 现状 | 差距 |
|---|---|---|
| **Kafka Consumer** | ❌ 无（只有 Producer） | 需新增 |
| **数据格式** | 期望 JSON dict（`process_log(raw_log: dict)`） | 需适配 Protobuf |
| **输入 Topic** | 无配置 | 需新增 `input_topic` |
| **告警输出** | 4 字段 JSON → `alert_topic` | 需丰富字段 |
| **Consumer Group** | 无 | 需新增 group ID |
| **trace_id 生成** | `generate_deterministic_trace_id()` 基于 IP+URI+Body+TS | 需验证对 Akto 数据的适用性 |
| **预处理** | `transform_raw_log()` 期望 dict 输入 | 需在适配层完成 Protobuf→dict |

### 2.3 字段映射关系

| AIWAF 期望字段 | Protobuf 字段 | 类型 | 说明 |
|---|---|---|---|
| `client_ip` | `ip` (field 13) | string | 直接映射 |
| `uri_path` | `path` (field 2) | string | 需用 `urlparse` 拆分 query string |
| `query_keys` | `path` 中解析 | list | `parse_qs(urlparse(path).query).keys()` |
| `query_strings` | `path` 中解析 | list | `["k=v", ...]` |
| `status` / `status_code` | `status_code` (field 7) | int32 | 直接映射 |
| `timestamp` | `time` (field 11) | int32 | 需转 `float()` |
| `method` | `method` (field 1) | string | 直接映射 |
| `request_body` | `request_payload` (field 5) | string | 字段名不同 |
| — | `akto_account_id` (field 12) | string | 扩展字段 |
| — | `akto_vxlan_id` (field 18) | string | 扩展字段 |
| — | `api_collection_id` (field 6) | int32 | 扩展字段 |
| — | `source` (field 17) | string | 扩展字段 |
| — | `direction` (field 15) | string | 扩展字段 |
| — | `dest_ip` (field 14) | string | 扩展字段 |
| — | `response_payload` (field 10) | string | 扩展字段 |
| — | `request_headers` (field 4) | map<string,StringList> | 扩展字段 |
| — | `response_headers` (field 9) | map<string,StringList> | 扩展字段 |

---

## 3. 改造方案

### 3.1 方案总览

```
┌──────────────────────────────────────────────────────────────┐
│                     AIWAF 改造架构                             │
│                                                              │
│  Kafka: akto.api.logs2 (Protobuf bytes)                      │
│      │                                                       │
│      ▼                                                       │
│  AIOKafkaConsumer (新增)                                      │
│      │  raw bytes                                            │
│      ▼                                                       │
│  akto_adapter.py (新增)                                       │
│      │  Protobuf → dict                                      │
│      │  HttpResponseParam.parseFrom(bytes) → std_log dict     │
│      ▼                                                       │
│  preprocessor.py (现有，无需改动)                              │
│      │  transform_raw_log(dict) → std_log                    │
│      │  generate_deterministic_trace_id()                    │
│      ▼                                                       │
│  engine.py (改造)                                             │
│      │  process_log(std_log) → 检测                           │
│      │  _emit_alert() → 丰富字段                              │
│      ▼                                                       │
│  Kafka: akto.aiwaf.alerts (JSON)                             │
│      │                                                       │
│      ├─→ 成功: alert JSON                                    │
│      └─→ 失败: Kafka: akto.aiwaf.dlq (JSON)                  │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 新增文件：`akto_adapter.py`

**职责：** 将 Akto 的 Protobuf `HttpResponseParam` 反序列化为 AIWAF 的 `raw_log` dict 格式。

```python
# akto_adapter.py
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

# 需预编译 Protobuf Python stub
# python -m grpc_tools.protoc -I. --python_out=. \
#   protobuf/threat_detection/message/http_response_param/v1/http_response_param.proto
from threat_detection.message.http_response_param.v1 import http_response_param_pb2


def deserialize_akto_message(raw_bytes: bytes) -> Dict[str, Any]:
    """将 Akto 的 Protobuf HttpResponseParam 反序列化为 AIWAF raw_log 格式。

    Args:
        raw_bytes: Kafka 消息 value（Protobuf 二进制）

    Returns:
        raw_log dict，兼容 preprocessor.transform_raw_log() 的输入格式
    """
    proto_msg = http_response_param_pb2.HttpResponseParam()
    proto_msg.ParseFromString(raw_bytes)

    # path 字段含完整 URI（含 query string），需拆分
    raw_path = proto_msg.path or "/"
    parsed = urlparse(raw_path if "://" in raw_path else f"//{raw_path}")

    query_dict = parse_qs(parsed.query)
    query_keys = list(query_dict.keys())
    query_strings = [f"{k}={v[0]}" for k, v in query_dict.items() if v]

    # 转换 headers map<string, StringList> → dict<string, list<string>>
    request_headers = {k: list(v.values) for k, v in proto_msg.request_headers.items()}
    response_headers = {k: list(v.values) for k, v in proto_msg.response_headers.items()}

    return {
        # AIWAF 核心字段
        "client_ip": proto_msg.ip or "",
        "uri_path": parsed.path or "/",
        "query_keys": query_keys,
        "query_strings": query_strings,
        "status": proto_msg.status_code or 200,
        "status_code": proto_msg.status_code or 200,
        "timestamp": float(proto_msg.time) if proto_msg.time else 0.0,
        "method": proto_msg.method or "GET",
        "request_body": proto_msg.request_payload or "",

        # Akto 扩展字段（透传，供告警上下文使用）
        "akto_account_id": proto_msg.akto_account_id or "",
        "akto_vxlan_id": proto_msg.akto_vxlan_id or "",
        "api_collection_id": proto_msg.api_collection_id or 0,
        "source": proto_msg.source or "",
        "direction": proto_msg.direction or "",
        "dest_ip": proto_msg.dest_ip or "",
        "response_payload": proto_msg.response_payload or "",
        "request_headers": request_headers,
        "response_headers": response_headers,
    }
```

### 3.3 改造 `engine.py`

**改动点：**

1. **新增 `AIOKafkaConsumer`**
2. **新增 `_consume_loop()` 消费循环**
3. **`_emit_alert()` 字段丰富**
4. **`start()` / `shutdown()` 增加 Consumer 生命周期管理**

```python
# engine.py 改造（关键片段）

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from akto_adapter import deserialize_akto_message

class AIWAFStreamEngine:
    def __init__(self, settings, state_mgr, model_path):
        # ... 现有初始化 ...

        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_brokers,
            enable_idempotence=True,
            acks='all',
            compression_type="lz4",  # 与 Akto 对齐
        )

        # 新增 Consumer
        self.consumer = AIOKafkaConsumer(
            settings.input_topic,               # "akto.api.logs2"
            bootstrap_servers=settings.kafka_brokers,
            group_id=settings.consumer_group,    # "aiwaf-consumer-group"
            value_deserializer=lambda v: v,      # 原始 bytes，交给 adapter
            key_deserializer=lambda v: v.decode('utf-8') if v else None,
            auto_offset_reset="earliest",
            enable_auto_commit=False,            # 手动提交
            max_poll_records=500,
        )

    async def start(self):
        await self.producer.start()
        await self.consumer.start()  # 新增

        self._tasks.append(asyncio.create_task(self._consume_loop()))  # 新增
        self._tasks.append(asyncio.create_task(self._batch_dispatcher()))
        self._tasks.append(asyncio.create_task(background_sync_worker(self.facade.mgr, self._cancel_event)))
        self._tasks.append(asyncio.create_task(self._keyword_refresh_worker()))

    async def shutdown(self):
        self._cancel_event.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self.core_executor.shutdown(wait=True)
        try:
            await self.consumer.stop()  # 新增
        except Exception:
            pass
        try:
            await self.producer.stop()
        except Exception:
            pass

    async def _consume_loop(self):
        """Kafka 消费循环 — 从 akto.api.logs2 消费 Protobuf 消息"""
        from preprocessor import transform_raw_log

        async for batch in self.consumer:
            for msg in batch:
                try:
                    # Protobuf → raw_log dict
                    raw_log = deserialize_akto_message(msg.value)

                    # raw_log → std_log（现有预处理逻辑）
                    std_log = transform_raw_log(raw_log)

                    # 检测
                    await self.process_log(std_log)

                except Exception as e:
                    # 反序列化/预处理失败 → DLQ
                    await self._route_to_dlq_raw(msg, e)

            # 手动提交 offset
            await self.consumer.commit()

    async def _route_to_dlq_raw(self, msg, error: Exception):
        """原始消息反序列化失败的 DLQ 路由"""
        METRIC_DLQ_OUT.inc()
        dlq_payload = {
            "trace_id": None,
            "error": f"Deserialization failed: {e}",
            "error_type": type(e).__name__,
            "raw_log": msg.value.hex(),  # 原始 bytes 的 hex
            "topic": msg.topic,
            "partition": msg.partition,
            "offset": msg.offset,
        }
        await self.producer.send_and_wait(
            self.settings.dlq_topic,
            orjson.dumps(dlq_payload)
        )

    async def _emit_alert(self, std_log: dict, rule: str):
        """告警输出（字段丰富）"""
        alert = {
            # 现有字段
            "trace_id": std_log.get("trace_id"),
            "rule_id": rule,
            "alert_timestamp": std_log.get("timestamp"),
            "client_ip": std_log.get("client_ip"),

            # 新增：Akto 上下文
            "akto_account_id": std_log.get("akto_account_id", ""),
            "akto_vxlan_id": std_log.get("akto_vxlan_id", ""),
            "api_collection_id": std_log.get("api_collection_id", 0),
            "source": std_log.get("source", ""),
            "direction": std_log.get("direction", ""),

            # 新增：请求上下文
            "method": std_log.get("method", "GET"),
            "uri_path": std_log.get("uri_path", "/"),
            "status_code": std_log.get("status_code", 200),

            # 新增：检测元数据
            "detected_at": time.time(),
            "severity": self._classify_severity(rule),
        }
        await self.producer.send_and_wait(
            self.settings.alert_topic,  # "akto.aiwaf.alerts"
            orjson.dumps(alert)
        )

    def _classify_severity(self, rule: str) -> str:
        """根据规则类型分类严重程度"""
        if "RateLimit" in rule or "Flood" in rule:
            return "MEDIUM"
        if "Blacklist" in rule:
            return "HIGH"
        if "KeywordBlock" in rule:
            return "HIGH"
        return "LOW"
```

### 3.4 Settings 扩展

```python
# 新增配置项
class Settings:
    # Redis
    redis_cluster_url: str

    # Kafka
    kafka_brokers: str
    input_topic: str = "akto.api.logs2"           # 新增
    alert_topic: str = "akto.aiwaf.alerts"         # 改默认值
    dlq_topic: str = "akto.aiwaf.dlq"              # 改默认值
    consumer_group: str = "aiwaf-consumer-group"   # 新增

    # 进程池
    core_process_pool_size: int
```

**环境变量：**

| 变量 | 默认值 | 说明 |
|---|---|---|
| `KAFKA_INPUT_TOPIC` | `akto.api.logs2` | 消费 Topic |
| `KAFKA_ALERT_TOPIC` | `akto.aiwaf.alerts` | 告警 Topic |
| `KAFKA_DLQ_TOPIC` | `akto.aiwaf.dlq` | 死信 Topic |
| `KAFKA_CONSUMER_GROUP` | `aiwaf-consumer-group` | Consumer Group ID |
| `KAFKA_BROKERS` | — | Kafka Broker 地址 |

### 3.5 Protobuf Python Stub 编译

**前置条件：** 从 Akto 仓库获取 `.proto` 文件并编译。

```bash
# 1. 安装 protobuf 编译工具
pip install grpcio-tools protobuf>=4.25,<5

# 2. 从 Akto 仓库复制 proto 文件
mkdir -p proto/threat_detection/message/http_response_param/v1/
curl -o proto/threat_detection/message/http_response_param/v1/http_response_param.proto \
  https://raw.githubusercontent.com/akto-api-security/akto/master/protobuf/threat_detection/message/http_response_param/v1/http_response_param.proto

# 3. 编译 Python stub
python -m grpc_tools.protoc \
  -I proto/ \
  --python_out=. \
  proto/threat_detection/message/http_response_param/v1/http_response_param.proto

# 4. 验证
python -c "from threat_detection.message.http_response_param.v1 import http_response_param_pb2; print('OK')"
```

### 3.6 requirements.txt 更新

```
# 现有
orjson>=3.9.0
redis>=5.0.0
aiokafka>=0.8.0
cachetools>=5.0.0
prometheus-client>=0.17.0
joblib>=1.3.0

# 新增
protobuf>=4.25,<5
grpcio-tools>=1.60.0
```

---

## 4. 对建议的评估

### 4.1 建议中的正确点

| 建议 | 评估 | 说明 |
|---|---|---|
| Protobuf 反序列化 | ✅ 正确 | `akto.api.logs2` 确实是 Protobuf 格式 |
| 字段映射关系 | ✅ 正确 | proto 字段编号与建议一致 |
| 新增 AIOKafkaConsumer | ✅ 正确 | AIWAF 确实没有 Consumer |
| Consumer Group 独立 | ✅ 正确 | 避免与 threat-detection 抢消息 |
| 手动 commit offset | ✅ 正确 | 与 Akto 的 `enable.auto.commit=false` 对齐 |
| 告警字段丰富 | ✅ 正确 | 现有 4 字段太简陋 |
| DLQ 路由 | ✅ 正确 | 反序列化失败需要兜底 |

### 4.2 建议中的问题

| 问题 | 严重程度 | 说明 |
|---|---|---|
| **生产者不明** | ⚠️ 中 | 建议未说明谁生产到 `akto.api.logs2`。代码中未找到开源的生产者，可能在 SaaS infra 层。需确认 Topic 是否有数据 |
| **`path` 字段格式假设** | ⚠️ 低 | 建议用 `urlparse` 处理，但 Akto 的 `path` 可能是纯路径 `/api/v1`（不含 host）。`urlparse("/api/v1?a=1")` 的 `.path` 返回 `/api/v1`，`.query` 返回 `a=1`，行为正确 |
| **`is_pending` 字段遗漏** | ⚠️ 低 | proto field 16 `is_pending` 未在适配层映射，但 AIWAF 当前不需要此字段 |
| **`type` 字段遗漏** | ⚠️ 低 | proto field 3 `type` 未映射，AIWAF 不使用 |
| **headers 类型转换** | ⚠️ 中 | proto 的 `map<string, StringList>` 在 Python 中是特殊类型，不能直接 `dict()`，需遍历转换（建议代码中已修正） |
| **`preprocessor.transform_raw_log` 兼容性** | ⚠️ 中 | 现有 `transform_raw_log()` 期望 `query_params` dict，但适配层输出 `query_keys` list + `query_strings` list。需确认 `transform_raw_log` 是否已支持，或需调整 |

### 4.3 补充建议

| 补充 | 说明 |
|---|---|
| **Topic 存在性验证** | 部署前需确认 `akto.api.logs2` Topic 在 Kafka 中存在且有数据。该 Topic 的生产者不在 Akto 开源仓库中 |
| **备选方案：消费 `akto.api.logs`（JSON）** | 如果 `akto.api.logs2` 无数据，可改为消费 `akto.api.logs`（JSON 格式），适配层改为 JSON 解析而非 Protobuf。这样更简单且生产者明确 |
| **`transform_raw_log` 调整** | 需确认 `transform_raw_log()` 能处理适配层输出的 dict 格式，或直接在适配层完成 `transform_raw_log` 的全部工作 |
| **压缩对齐** | AIWAF Producer 已加 `compression_type="lz4"`，但 Consumer 不需要指定解压（Kafka 自动处理） |
| **幂等性** | AIWAF 的 `is_duplicate_and_add(trace_id)` 已有幂等去重，Consumer 重复消费不会导致重复告警 |

---

## 5. 改造清单

| # | 文件 | 改动 | 优先级 | 工作量 |
|---|---|---|---|---|
| 1 | **新增** `akto_adapter.py` | Protobuf 反序列化 + 字段映射 | P0 | 2h |
| 2 | `requirements.txt` | 增加 `protobuf>=4.25,<5` + `grpcio-tools` | P0 | 5min |
| 3 | **编译** proto Python stub | 从 Akto 仓库 `.proto` → `_pb2.py` | P0 | 30min |
| 4 | `engine.py` | 新增 `AIOKafkaConsumer` + `_consume_loop()` | P0 | 3h |
| 5 | `engine.py` | `_emit_alert()` 字段丰富 + `_classify_severity()` | P1 | 1h |
| 6 | `Settings` / 环境变量 | `input_topic`, `consumer_group` 等 | P0 | 30min |
| 7 | `preprocessor.py` | 验证 `transform_raw_log()` 对适配层输出的兼容性 | P1 | 1h |
| 8 | **新增** `tests/test_akto_adapter.py` | 适配层单测 + Protobuf round-trip | P0 | 2h |
| 9 | **新增** `tests/test_consume_loop.py` | 消费循环集成测试 | P1 | 2h |
| 10 | `docs/` | 更新部署文档，说明 proto 编译步骤 | P2 | 1h |

**总工作量：** P0 约 8h，P1 约 4h，P2 约 1h，合计约 13h。

---

## 6. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|---|---|---|
| **`akto.api.logs2` 无数据** | AIWAF 收不到任何消息 | 部署前验证 Topic 有数据；备选方案改为消费 `akto.api.logs`（JSON） |
| **Protobuf 版本不匹配** | 反序列化失败 | 锁定 `protobuf>=4.25,<5`，CI 中校验 |
| **Consumer Group 冲突** | 与 threat-detection 抢消息 | group ID 独立设置为 `aiwaf-consumer-group` |
| **大 Payload OOM** | Protobuf 解析大消息时内存溢出 | Consumer 侧限制 `max_poll_records=500`；适配层截断 `request_payload` |
| **offset 重复消费** | 重复告警 | AIWAF 的 `is_duplicate_and_add(trace_id)` SETNX 幂等去重 |
| **Kafka 连接失败** | 服务不可用 | `start()` 中加重试逻辑；Prometheus 指标监控 consumer lag |
| **`path` 格式不确定** | URI 解析错误 | `urlparse` 兼容纯路径和完整 URL；测试真实数据 |

---

## 7. 备选方案：消费 `akto.api.logs`（JSON）而非 `akto.api.logs2`（Protobuf）

如果 `akto.api.logs2` Topic 不可用或无数据，可改为消费 `akto.api.logs`（JSON 格式）。

### 7.1 优劣对比

| 维度 | 方案 A: `akto.api.logs2` (Protobuf) | 方案 B: `akto.api.logs` (JSON) |
|---|---|---|
| **生产者** | 不在开源仓库中（SaaS infra） | data-ingestion-service（开源） |
| **格式** | Protobuf（需要编译 stub） | JSON（原生 Python 解析） |
| **依赖** | protobuf + grpcio-tools | 无额外依赖 |
| **性能** | 更高（二进制，更小更快） | 较低（文本解析） |
| **字段完整性** | 完整（18 个字段） | 完整（22 个字段） |
| **消费者竞争** | 仅 threat-detection（独立 group） | api-runtime + api-analyser（需独立 group） |
| **部署复杂度** | 高（需编译 proto） | 低（直接 JSON 解析） |

### 7.2 方案 B 适配层

```python
# akto_adapter_json.py（方案 B）
import orjson

def deserialize_akto_json_message(raw_bytes: bytes) -> dict:
    """将 Akto 的 JSON 消息反序列化为 AIWAF raw_log 格式。"""
    msg = orjson.loads(raw_bytes)

    # akto.api.logs 的 JSON 格式（IngestDataBatch）
    raw_path = msg.get("path", "/")
    parsed = urlparse(raw_path if "://" in raw_path else f"//{raw_path}")
    query_dict = parse_qs(parsed.query)

    return {
        "client_ip": msg.get("ip", ""),
        "uri_path": parsed.path or "/",
        "query_keys": list(query_dict.keys()),
        "query_strings": [f"{k}={v[0]}" for k, v in query_dict.items() if v],
        "status": int(msg.get("statusCode", 200)),
        "status_code": int(msg.get("statusCode", 200)),
        "timestamp": float(msg.get("time", 0)),
        "method": msg.get("method", "GET"),
        "request_body": msg.get("requestPayload", ""),
        # 扩展字段
        "akto_account_id": msg.get("akto_account_id", ""),
        "akto_vxlan_id": msg.get("akto_vxlan_id", ""),
        "source": msg.get("source", ""),
        "direction": msg.get("direction", ""),
        "dest_ip": msg.get("destIp", ""),
        "response_payload": msg.get("responsePayload", ""),
    }
```

### 7.3 推荐

**推荐方案 A（Protobuf）**，原因：
1. 需求明确要求消费 `akto.api.logs2`
2. Protobuf 性能更好
3. 与 threat-detection 使用相同数据源，结果可对比

**但需在部署前验证 Topic 有数据。** 如果无数据，回退到方案 B。

---

## 8. 测试计划

### 8.1 单元测试

| 测试文件 | 覆盖内容 |
|---|---|
| `tests/test_akto_adapter.py` | Protobuf 序列化/反序列化 round-trip、字段映射、空值处理、大 payload |
| `tests/test_consume_loop.py` | 消费循环、offset 提交、DLQ 路由、异常恢复 |

### 8.2 集成测试

```python
# tests/test_integration_akto.py
async def test_end_to_end():
    """端到端测试：Protobuf 消息 → 消费 → 检测 → 告警输出"""
    # 1. 构造 Protobuf HttpResponseParam 消息
    # 2. 发送到 Kafka input_topic
    # 3. 等待 AIWAF 消费和处理
    # 4. 验证 alert_topic 收到告警
    # 5. 验证告警字段完整性
```

### 8.3 验证清单

- [ ] Protobuf 反序列化正确（所有 18 个字段）
- [ ] URI 拆分正确（纯路径、含 query string、完整 URL）
- [ ] trace_id 生成对 Akto 数据有效
- [ ] Consumer Group 不与 threat-detection 冲突
- [ ] offset 手动提交正常
- [ ] DLQ 路由在反序列化失败时触发
- [ ] 告警输出包含 Akto 上下文字段
- [ ] 大 payload（>1MB）不导致 OOM
- [ ] Consumer lag 指标正常上报
