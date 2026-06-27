# Akto API 安全测试库全面分析报告

> 分析日期：2026-06-27
> 仓库地址：https://github.com/akto-api-security/tests-library
> 分析范围：全部 258 个分支，重点分析代码实际引用的 6 个运行时分支
> 源码参考：https://github.com/akto-api-security/akto（InitializerListener.java）

---

## 1. 仓库概览

Akto 测试库是 Akto API 安全平台的核心组件，包含所有内置安全测试模板。仓库共有 **258 个分支**，其中绝大多数是开发过程中的 feature/fix 分支，仅 **6 个分支**被 Akto 代码在运行时实际引用。

### 1.1 运行时分支总览

| 分支 | 用途 | 代码引用位置 | YAML 模板 | 合规配置 | 修复指南 | 加载条件 |
|---|---|---|---|---|---|---|
| **standard** | 安全测试 | `getAktoDefaultTestLibs()` | 311 | 0 | 0 | 所有用户 |
| **pro** | 安全测试 | `getAktoDefaultTestLibs()` | 408 | 0 | 0 | 所有用户 |
| **agentic-pro** | 安全测试 | `AKTO_TESTS_LIBRARY_AGENTIC` | 4,427 | 1,152 | 1,225 | Agentic 功能授权用户 |
| **threat_policies_pro** | **威胁检测** | `getAktoDefaultThreatPolicies()` | 205 | 993 | 1,004 | SaaS 模式 |
| **mcp-standard** | 安全测试 | 动态加载 | 5 | 0 | 0 | MCP 功能用户 |
| **mcp-pro** | 安全测试 | 动态加载 | 231 | 0 | 0 | MCP Pro 用户 |

> **关键区分**：`threat_policies_pro` 分支用于**威胁检测**（被动分析实时流量），其余 5 个分支用于**安全测试**（主动发送测试请求）。两者在代码中通过不同路径加载、写入不同 MongoDB 集合、由不同服务执行。

> **注意**：代码中使用的是 `standard` 分支，不是 `master` 分支。`master` 分支是旧版（209 模板），已被 `standard` 分支（311 模板）替代。`master` 分支仅在旧版 `TestTemplateUtils.getTestingTemplates()` 中作为 fallback 使用。

### 1.2 源码引用

```java
// InitializerListener.java L2837-2838
public static Set<String> getAktoDefaultTestLibs() {
    return new HashSet<>(Arrays.asList(
        "akto-api-security/tests-library:standard",
        "akto-api-security/tests-library:pro"
    ));
}

// L2835
public static final String AKTO_TESTS_LIBRARY_AGENTIC = "akto-api-security/tests-library:agentic-pro";

// L2920-2922
public static Set<String> getAktoDefaultThreatPolicies() {
    return new HashSet<>(Arrays.asList(
        "akto-api-security/tests-library:threat_policies_pro"
    ));
}
```

### 1.3 分支间关系（按模板 ID 交叉比对）

| 分支对比 | 共有 ID | 说明 |
|---|---|---|
| standard vs pro | **0** | 完全独立 |
| standard vs agentic-pro (API) | **0** | 完全独立 |
| standard vs threat_policies_pro | **0** | 完全独立 |
| pro vs agentic-pro (API) | **0** | 完全独立 |
| pro vs threat_policies_pro | **0** | 完全独立 |
| **agentic-pro (API) vs threat_policies_pro** | **204/205** | threat_policies_pro 是 agentic-pro 的子集 |
| mcp-standard vs mcp-pro | **4/5** | mcp-pro 是 mcp-standard 的超集 |
| standard vs master (旧) | **0** | standard 完全替代了 master |

**关键发现：各分支模板 ID 零重叠（除 threat_policies_pro ⊂ agentic-pro 和 mcp-standard ⊂ mcp-pro），合并使用时不去重也不会冲突。**

### 1.4 全分支去重后总模板数

```
standard (311) + pro (408) + agentic-pro API (274) + agentic-pro AI Agent (4,153)
+ threat_policies_pro (205) + mcp-standard (5) + mcp-pro (231)
= 5,587 个唯一模板
```

---

## 2. standard 分支（311 个模板）

### 2.1 定位

standard 分支是 **master 分支的替代版**，包含更多模板（311 vs 209）和更细的分类。所有模板 `plan: STANDARD`（307 个）或 `FREE`（1 个），面向所有用户。

### 2.2 分类分布

| 分类 | 数量 | 说明 |
|---|---|---|
| Security-Misconfiguration | 118 | Django/Flask/Express debug, Spring Boot Actuator, Tomcat RCE 等 |
| Input-Validation | 70 | 优惠券篡改, 支付绕过, 库存操纵等业务逻辑测试 |
| Server-Side-Request-Forgery | 25 | AWS metadata, localhost, 文件上传 SSRF |
| Broken-User-Authentication | 22 | JWT 攻击, CSRF, SQL 注入认证绕过, 2FA |
| Command-Injection | 13 | OS 命令注入, 内核命令注入 |
| Broken-Object-Level-Authorization | 11 | BOLA 各种变体 |
| Mass-Assignment | 9 | 批量赋值漏洞 |
| Cross-Site-Scripting | 8 | 反射型/存储型 XSS |
| Lack-of-Resources-and-Rate-Limiting | 7 | 速率限制, DoS |
| Local-File-Inclusion | 6 | 路径遍历, XXE |
| Injection-Attacks | 5 | SQL/NoSQL 注入 |
| Verbose-Error-Messages | 4 | 详细错误信息泄露 |
| Broken-Function-Level-Authorization | 4 | BFLA |
| Unnecessary-HTTP-Methods | 2 | TRACE, TRACK |
| Misconfigured-HTTP-Headers | 2 | X-Frame-Options, HSTS |
| 其他 | 5 | CORS, SSTI, LLM, IIM, Server Version |

### 2.3 严重程度分布

| 严重程度 | 数量 |
|---|---|
| LOW | 137 |
| MEDIUM | 78 |
| HIGH | 63 |
| CRITICAL | 32 |

---

## 3. pro 分支（408 个模板）

### 3.1 定位

pro 分支是独立设计的深度测试集，与 standard 零重叠。模板粒度更细，按 HTTP 方法 (GET/DELETE/PATCH) 和数据类型 (Integer/Array/JSONObject) 拆分。所有模板 `plan: PRO`。

### 3.2 分类分布

| 分类 | 数量 | 说明 |
|---|---|---|
| Broken-User-Authentication | 97 | JWT 全变体, GraphQL CSRF, SQL 注入多种变体 |
| Broken-Object-Level-Authorization | 59 | 按 HTTP 方法 × 数据类型拆分的 BOLA |
| LLM-Security | 54 | 提示注入, 数据泄露, 幻觉, 恶意代码生成 |
| Lack-of-Resources-and-Rate-Limiting | 41 | DoS 测试 |
| Injection-Attacks | 39 | SQL/NoSQL/Command 注入扩展 |
| Command-Injection | 38 | 多语言命令注入 |
| Security-Misconfiguration | 27 | |
| Input-Validation | 24 | |
| Local-File-Inclusion | 10 | |
| Cross-Site-Scripting | 7 | |
| Server-Side-Request-Forgery | 6 | |
| Improper Inventory Management | 3 | |
| CRLF-Injection | 2 | |
| Broken-Function-Level-Authorization | 1 | |

### 3.3 严重程度分布

| 严重程度 | 数量 |
|---|---|
| HIGH | 141 |
| MEDIUM | 132 |
| CRITICAL | 84 |
| LOW | 48 |

### 3.4 standard vs pro 设计对比

| 维度 | standard | pro |
|---|---|---|
| BOLA 模板数 | 11 | 59 |
| BOLA 粒度 | 通用场景 | URL 插入 / Cookie 模糊 / JSON Body 数组 / 自定义 Header × DELETE/PATCH |
| 认证测试 | 22 | 97 |
| 严重程度偏重 | LOW (44%) | HIGH+CRITICAL (55%) |
| LLM 安全 | 1 | 54 |

---

## 4. agentic-pro 分支（4,427 个模板）

### 4.1 定位

agentic-pro 分支包含 AI Agent 安全测试和 API 安全测试的 Agent 化版本。仅在用户获得 Agentic 功能授权（Stigg `FEATURE_SECURITY_TYPE_AGENTIC`）时加载。

### 4.2 组成

| 类型 | 数量 | 说明 |
|---|---|---|
| API 安全测试 | 274 | 基于 master 分支模板的 Agent 化版本 + 66 个 `_AGENTIC` 新模板 |
| AI Agent 测试 | 4,153 | 大规模生成式 AI Agent 越狱/绕过测试 |
| 合规配置 | 1,152 | 合规框架映射 |
| 修复指南 | 1,225 | 多语言修复建议 |

### 4.3 API 安全测试（274 个）

与 master 分支的关系：
- 208 个 ID 与 master 共有（其中 187 个内容完全相同，20 个有微调）
- 66 个 `_AGENTIC` 后缀的新增模板（如 `ELASTICSEARCH_DEFAULT_LOGIN_AGENTIC`）
- 与 standard/pro **零重叠**

agentic 独有模板特点：
- `category`: 使用 `_AGENTIC` 后缀（如 `SM_AGENTIC`）
- `plan`: `FREE`
- `strategy`: `run_once`（每个端点只跑一次）
- 适配 POST 方法 + 请求体修改 + 精确响应验证

### 4.4 AI Agent 测试（4,153 个）

4 大漏洞领域 × 15 种攻击技术 = 4,147 个生成测试 + 6 个基础模板

**4 大漏洞领域：**

| 领域 | 测试数 | 说明 |
|---|---|---|
| SECURITY | 2,483 | Agent 安全：提示注入、数据泄露、代码执行、工具发现 |
| BUSINESS | 624 | 业务对齐：竞争对手检查、欺诈行为、目标偏移 |
| SAFETY | 598 | 安全性：有害内容、脏话、越狱 |
| HALLUCINATION | 442 | 幻觉与可信度：妄想、偏执防护 |

**15 种攻击技术：**

| 技术 | 测试数 | 说明 |
|---|---|---|
| LINEAR_JAILBREAKING | ~1,560 | 线性递进越狱 |
| BAD_LIKERT_JUDGE | ~637 | Likert 评分判定绕过 |
| CRESCENDO_JAILBREAKING | ~624 | 渐进式越狱 |
| SEQUENTIAL_JAILBREAKING | ~312 | 顺序越狱 |
| TREE_JAILBREAKING | ~260 | 树形越狱 |
| BASE64 | 74 | Base64 编码绕过 |
| CONTEXT_POISONING | 74 | 上下文投毒 |
| GOAL_REDIRECTION | 74 | 目标重定向 |
| INPUT_BYPASS | 74 | 输入绕过 |
| LEETSPEAK | 74 | Leet 编码绕过 |
| MULTILINGUAL | 74 | 多语言绕过 |
| OVERRIDE | 74 | 覆盖指令 |
| ROLEPLAY | 74 | 角色扮演 |
| ROT13 | 74 | ROT13 编码 |
| SEMANTIC_MANIPULATION | 74 | 语义操纵 |

---

## 5. threat_policies_pro 分支 — 威胁检测规则

### 5.1 定位

`threat_policies_pro` 分支是 Akto **威胁检测**组件的数据源，与安全测试模板有本质区别：

| 维度 | 安全测试模板 (standard/pro/agentic-pro/mcp) | 威胁策略 (threat_policies_pro) |
|---|---|---|
| **目的** | 主动发送测试请求，验证 API 是否存在漏洞 | 被动分析实时流量，检测正在发生的攻击 |
| **MongoDB 集合** | `yaml_templates` | `filter_yaml_templates` |
| **DAO 类** | `YamlTemplateDao` | `FilterYamlTemplateDao` |
| **加载函数** | `processTemplateFilesZip()` | `processThreatFilterTemplateFilesZip()` |
| **AccountSettings 字段** | `testLibraries` | `threatPolicies` |
| **执行服务** | `akto-api-testing` 引擎 | `akto-threat-detection` 服务 + Dashboard `MatchingJob` |
| **运行时机** | 用户触发或定时调度 | 实时（Kafka 流式消费）/ 每 30 分钟批量 |
| **YAML 结构** | `api_selection_filters` → `execute` → `validate` | `filter` → `aggregation_rules` |
| **工作方式** | 修改请求重放，检查响应是否脆弱 | 匹配实时流量中的恶意模式，达到阈值后告警 |
| **日志类别** | `ANALYSER` | `THREAT_DETECTION` |

### 5.2 分支内容构成

threat_policies_pro 分支包含三种内容：

| 内容类型 | 数量 | 说明 |
|---|---|---|
| **威胁检测规则** (Threat-Protection/) | **5 个** | 运行时流量匹配规则，用于威胁检测 |
| **安全测试模板** (其他目录) | 200 个 | 与 agentic-pro API 模板完全相同（200/200 共有 ID），用于安全测试 |
| **合规配置** (compliance/) | 993 个 | 合规框架映射 |
| **修复指南** (remediation/) | 1,004 个 | 多语言修复建议 |

> 只有 `Threat-Protection/` 目录下的 5 个模板是真正的威胁检测规则。其余 200 个模板是安全测试模板的副本（与 agentic-pro 相同），在 `processThreatFilterTemplateFilesZip()` 中会被跳过（代码检查 `if (!entry.getName().contains("Threat-Protection")) continue;`）。

### 5.3 威胁检测规则详解（5 个）

#### 5.3.1 规则结构

```yaml
id: <规则ID>                    # 唯一标识
filter:                         # 流量过滤规则
  or:                           # OR 逻辑
    - request_headers:          # 匹配请求头
        contains_either: [...]  # 包含任一模式
    - query_param:              # 匹配查询参数
        contains_either: [...]
    - request_payload:          # 匹配请求体
        contains_either: [...]
    - response_payload:         # 匹配响应体
        contains_either: [...]
        length:
          gt: 0
info:                           # 元信息
  name / description / details / impact
  category / subCategory / severity
aggregation_rules:              # 聚合告警规则
  - rule:
      name: "Rule 1"
      condition:
        matchCount: 50          # 匹配次数阈值
        windowThreshold: 5      # 时间窗口（分钟）
```

#### 5.3.2 五个规则详情

**1. SQLInjection — SQL 注入检测**

| 字段 | 值 |
|---|---|
| ID | `SQLInjection` |
| 严重程度 | MEDIUM |
| 检测目标 | 请求头 / 查询参数 / 请求体 |
| 匹配模式 | `' OR '1'='1`、`' OR 1=1 -- -`、`%27%20OR%20%271%27%3D%271` (URL编码)、`' OR ASCII('1')=49`、Unicode编码变种 |
| 聚合规则 | 5分钟内 50 次匹配 / 10分钟内 100 次匹配 |

**2. XSS — 跨站脚本检测**

| 字段 | 值 |
|---|---|
| ID | `XSS` |
| 严重程度 | MEDIUM |
| 检测目标 | 请求头 / 查询参数 / 请求体 |
| 匹配模式 | `<script>` 标签、`javascript:` 协议、`onerror=` 事件、`<img src=x onerror=...>` 等 |
| 聚合规则 | 5分钟内 50 次匹配 / 10分钟内 100 次匹配 |

**3. SSRF — 服务端请求伪造检测**

| 字段 | 值 |
|---|---|
| ID | `SSRF` |
| 严重程度 | HIGH |
| 检测目标 | 请求头 / 查询参数 / 请求体 |
| 匹配模式 | 内网 IP (127.0.0.1, 192.168.x.x, 10.x.x.x)、`http://169.254.169.254` (AWS metadata)、localhost 变种 |
| 聚合规则 | 5分钟内 50 次匹配 / 10分钟内 100 次匹配 |

**4. LocalFileInclusion — 本地文件包含检测**

| 字段 | 值 |
|---|---|
| ID | `LocalFileInclusionLFIRFI` |
| 严重程度 | HIGH |
| 检测目标 | 请求头（路径遍历模式）+ 响应体（敏感文件内容） |
| 请求匹配 | `/etc/passwd`、`../` 路径遍历、`..//etc/passwd`、URL编码变种 |
| 响应匹配 | `root:x:0:0:`、`/bin/bash`、`LANG=`、`SHELL=`、`apiVersion: v1`、`kubernetes-admin@`、`client-certificate-data`、`AuthorizedKeysFile`、`/var/log/auth.log` |
| 聚合规则 | 5分钟内 50 次匹配 / 10分钟内 100 次匹配 |

**5. SecurityMisconfiguration — 安全配置错误检测**

| 字段 | 值 |
|---|---|
| ID | `SecurityMisconfig` |
| 严重程度 | MEDIUM |
| 检测目标 | 请求头 / 查询参数 / 请求体 / 响应体 |
| 匹配模式 | HTTP 方法异常、User-Agent 异常、Content-Type 不匹配、服务器版本信息泄露、调试接口暴露 |
| 聚合规则 | 5分钟内 50 次匹配 / 10分钟内 100 次匹配 |

### 5.4 威胁检测工作流程

```
实时流量 (Kafka)
    │
    ▼
┌─────────────────────────────────────┐
│  akto-threat-detection 服务          │
│  MaliciousTrafficDetectorTask       │
│                                     │
│  1. 消费 Kafka 流量消息              │
│  2. 从 filter_yaml_templates 加载    │
│     FilterConfig（5 个威胁规则）      │
│  3. ThreatDetector.applyFilter()     │
│     逐条匹配 filter 中的模式          │
│  4. 匹配成功 → 检查聚合规则           │
│     - 无聚合规则 → EVENT_TYPE_SINGLE  │
│     - 有聚合规则 → Redis 计数         │
│       达到 matchCount 阈值            │
│       → EVENT_TYPE_AGGREGATED        │
│  5. 生成 MaliciousEvent              │
│     推送到 Kafka 告警队列             │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  akto-threat-detection-backend       │
│  消费 MaliciousEvent → 存储告警       │
│  提供 Dashboard 告警查询 API          │
└─────────────────────────────────────┘

同时（Dashboard 侧）:
┌─────────────────────────────────────┐
│  Dashboard MatchingJob               │
│  每 30 分钟批量运行                   │
│  扫描 SuspectSampleData              │
│  匹配 filter_yaml_templates 规则      │
│  标记可疑样本                         │
└─────────────────────────────────────┘
```

### 5.5 聚合规则机制

聚合规则使用 Redis 实现滑动窗口计数：

```java
// MaliciousTrafficDetectorTask.java
AggregationRules aggRules = apiFilter.getAggregationRules();
boolean isAggFilter = aggRules != null && !aggRules.getRule().isEmpty();

if (!isAggFilter) {
    // 无聚合规则 → 立即告警
    generateAndPushMaliciousEventRequest(
        apiFilter, actor, responseParam, maliciousReq,
        EventType.EVENT_TYPE_SINGLE);
} else {
    // 有聚合规则 → Redis 计数
    for (Rule rule : aggRules.getRule()) {
        boolean shouldNotify = windowBasedThresholdNotifier
            .shouldNotify(aggKey, maliciousReq, rule,
                         shouldIncrement, breachFilterPassed, identity);
        if (shouldNotify) {
            generateAndPushMaliciousEventRequest(
                apiFilter, actor, responseParam, maliciousReq,
                EventType.EVENT_TYPE_AGGREGATED);
        }
    }
}
```

**两种告警类型：**
- `EVENT_TYPE_SINGLE` — 单次匹配即告警（无聚合规则的模板）
- `EVENT_TYPE_AGGREGATED` — 达到聚合阈值后告警（如 5 分钟内 50 次 SQL 注入尝试）

### 5.6 合规配置（993 个）

每个安全测试模板映射到多个合规框架，存储在 `compliance/` 目录：

```yaml
# compliance/BOLA_URL_INSERT_API_VERSION_PATCH.conf
SOC 2:
- Logical and Physical Access Controls
ISO 27001:
- A.9.1.2
- A.9.4.1
NIST 800-53:
- AC-6
- AC-3
CSA CCM:
- IAM-02
CIS Controls:
- IG2 Safeguard 4.4
FedRAMP:
- AC-2
- AC-3
NIST 800-171:
- 3.1.1
FISMA:
- AC-3
CMMC:
- AC.1.001
- AC.2.003
OWASP:
- BOLA
```

**覆盖 10 个合规框架：** GDPR、SOC 2、ISO 27001、NIST 800-53、CSA CCM、CIS Controls、FedRAMP、NIST 800-171、FISMA、CMMC

**合规配置分类 Top 15：**

| 分类 | 数量 |
|---|---|
| SENSITIVE | 101 |
| LLM | 45 |
| BOLA | 44 |
| COMMAND | 37 |
| BYPASS | 36 |
| APACHE | 34 |
| UNION | 31 |
| SSRF | 31 |
| GRAPHQL | 28 |
| XXE | 17 |
| DOS | 16 |
| TIME | 15 |
| MANIPULATING | 14 |
| SPRING | 13 |

### 5.7 修复指南（1,004 个）

每个漏洞对应一个 `.md` 文件，包含：
- 漏洞描述与技术原理
- 多语言修复示例（Python/Flask、Java/Spring、Node.js/Express）
- 最佳实践建议

---

## 6. MCP 分支

### 6.1 mcp-standard 分支（5 个模板）

| 模板 | 严重程度 | 说明 |
|---|---|---|
| MCPContextBleed | HIGH | 跨工具上下文泄露 |
| MCPParamOverload | — | 参数过载 |
| MCPResourcePromptInjection | — | 资源提示注入 |
| MCPToolPoisoningToolDesc | — | 工具描述投毒 |
| MCPUnauthorizedToolAccess | — | 未授权工具访问 |

所有模板 `plan: FREE`，`nature: INTRUSIVE`。

### 6.2 mcp-pro 分支（231 个模板）

| 分类 | 数量 | 说明 |
|---|---|---|
| MCP-Security | 118 | MCP 协议安全测试（ANSI 转义、游标操纵、环境变量泄露等） |
| LLM-Security | 63 | LLM 安全测试 |
| MCP-Security-Command-Injection | 19 | MCP 命令注入 |
| MCP Security - LLM based tests | 16 | LLM 驱动的 MCP 测试 |
| MCP-LT | 7 | MCP 逻辑测试 |
| MCP-Security-Tool-Poisoning-Attacks | 4 | 工具投毒攻击 |
| MCP Agentic Tests | 4 | MCP Agent 测试 |

所有模板 `plan: PRO`（206 个）或 `FREE`（4 个）。

### 6.3 MCP 加载机制

MCP 分支未在 `getAktoDefaultTestLibs()` 中硬编码，而是通过 Account Settings 的 `testLibraries` 字段动态加载。用户可在 Dashboard UI 中添加 `akto-api-security/tests-library:mcp-standard` 或 `akto-api-security/tests-library:mcp-pro`。

---

## 7. Dashboard 内置模板（187 个）

### 7.1 定位

Dashboard WAR 包中内置的模板，作为 GitHub 不可达时的 fallback。

| 目录 | 数量 | 说明 |
|---|---|---|
| `inbuilt_test_yaml_files/` | 132 | 传统 API 安全测试 |
| `inbuilt_llm_test_yaml_files/` | 55 | LLM 安全测试 |
| `tests-library-master.zip` | 132 | master 分支的离线副本 |

### 7.2 与 GitHub 分支的关系

Dashboard 内置模板是各分支的**早期快照**：
- 132 个传统模板中，62 个 ID 与 master 共有，但内容全部不同（早期简化版）
- 55 个 LLM 模板中，54 个 ID 与 pro LLM-Security 共有，内容也全部不同
- 运行时 GitHub 拉取的模板会**覆盖**同 ID 的内置模板（`Updates.set(CONTENT, template)`）

---

## 8. 加载机制详解

### 8.1 启动时加载流程

```
Akto Dashboard 启动
  │
  ├── InitializerListener.contextInitialized()
  │   ├── saveLLmTemplates()                    # 加载 Dashboard 内置 LLM 模板
  │   │   └── classpath:/inbuilt_llm_test_yaml_files/ → MongoDB yaml_templates
  │   │
  │   ├── insertStateInAccountSettings()        # 初始化账户设置
  │   │   ├── insertAktoTestLibraries()         # 写入 standard + pro + agentic-pro
  │   │   └── insertAktoThreatPolicies()        # 写入 threat_policies_pro
  │   │
  │   └── 定时同步任务（周期性执行）
  │       ├── syncAllAktoDefaultTestLibraries()
  │       │   ├── GitHub: tests-library:standard → zip → processTemplateFilesZip()
  │       │   ├── GitHub: tests-library:pro → zip → processTemplateFilesZip()
  │       │   ├── GitHub: tests-library:agentic-pro → zip → processTemplateFilesZip()
  │       │   └── 用户自定义 testLibraries（含 mcp-standard, mcp-pro）
  │       │
  │       └── processThreatFilterTemplateFilesZip()  # threat_policies_pro
  │
  └── Fallback（GitHub 不可达时）
      └── tests-library-master.zip → processTemplateFilesZip()
```

### 8.2 模板写入 MongoDB

```java
// processTemplateFilesZip() 核心逻辑
YamlTemplateDao.instance.updateOne(
    Filters.eq("_id", testConfig.getId()),
    Updates.combine(
        Updates.setOnInsert(YamlTemplate.CREATED_AT, createdAt),
        Updates.setOnInsert(YamlTemplate.AUTHOR, author),     // "AKTO"
        Updates.set(YamlTemplate.UPDATED_AT, updatedAt),
        Updates.set(YamlTemplate.CONTENT, template),           // YAML 内容
        Updates.set(YamlTemplate.INFO, testConfig.getInfo()),
        Updates.setOnInsert(YamlTemplate.REPOSITORY_URL, repositoryUrl)
    ),
    new UpdateOptions().upsert(true)
);
```

- `author = "AKTO"`, `source = "AKTO_TEMPLATES"`
- 使用 `upsert`：存在则更新内容，不存在则插入
- 后拉取的分支会覆盖先拉取的同 ID 模板内容

### 8.3 测试引擎读取

```
Akto Testing Engine (akto-api-testing 容器)
  ├── 从 MongoDB yaml_templates 集合读取所有模板
  ├── 按 testConfig 解析 api_selection_filters / execute / validate
  ├── 按测试套件（OWASP/MCP/Agent 等）分组调度
  └── 执行测试 → 写入结果到 testing_run_results
```

---

## 9. 如何使用

### 9.1 部署 Akto 平台

```bash
# 一键部署（Docker）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/akto-api-security/infra/feature/self_hosting/cf-deploy-akto)"
```

部署后 Akto Dashboard 会自动从 GitHub 拉取测试模板。

### 9.2 运行安全测试

1. **接入流量**：通过 Akto Gateway 或 traffic mirroring 捕获 API 流量
2. **查看 API 清单**：Dashboard 自动生成 API Inventory
3. **运行测试**：
   - 选择 API 集合
   - 选择测试套件（OWASP Top 10 / MCP Security / AI Agent 等）
   - 点击 "Run Test"
4. **查看结果**：在 Dashboard 中查看漏洞详情、严重程度、合规映射和修复建议

### 9.3 自定义测试模板

在 Dashboard 的 Test Editor 中创建自定义 YAML 模板，或添加外部 GitHub 仓库：

```yaml
# 示例：添加 MCP 测试库
# 在 Account Settings → Test Libraries 中添加：
akto-api-security/tests-library:mcp-standard
akto-api-security/tests-library:mcp-pro
```

### 9.4 YAML 模板结构

```yaml
id: UNIQUE_TEMPLATE_ID                    # 全局唯一标识
info:
  name: "测试名称"
  description: "测试描述"
  details: "详细说明"
  impact: "影响评估"
  category:
    name: SM                               # 漏洞分类标识
    shortName: Misconfiguration            # 简称
    displayName: Security Misconfiguration # 显示名
  subCategory: APACHE_CONFIG               # 子分类
  severity: HIGH                           # CRITICAL / HIGH / MEDIUM / LOW
  tags: [OWASP top 10, HackerOne top 10]
  references: ["https://..."]
  cwe: [CWE-16]
  cve: [CVE-2021-12345]
attributes:
  nature: INTRUSIVE                        # INTRUSIVE / NON_INTRUSIVE
  plan: STANDARD                           # FREE / STANDARD / PRO
  duration: FAST                           # FAST / SLOW
api_selection_filters:                    # 目标 API 选择条件
  response_code:
    gte: 200
    lt: 300
  method:
    contains_either:
      - GET
  query_param:
    for_one:
      key:
        regex: .*
        extract: changed_key
execute:                                  # 执行逻辑
  type: single                            # single / multiple
  requests:
    - req:
        - modify_query_param:
            changed_key: "attacker_value"
validate:                                 # 漏洞判定条件
  response_code:
    gte: 200
    lt: 300
  response_payload:
    percentage_match:
      gt: 80
strategy:
  run_once: /                             # 每个端点只执行一次
```

### 9.5 测试套件选择

Akto 支持按测试套件分组运行：

| 套件类型 | 模板来源 | 说明 |
|---|---|---|
| OWASP API Top 10 | standard + pro | BOLA, BFLA, SSRF, XSS 等 |
| MCP Security | mcp-standard + mcp-pro | MCP 协议安全、工具投毒、提示注入 |
| AI Agent Security | agentic-pro | Agent 越狱、幻觉、业务对齐 |
| LLM Security | pro + mcp-pro | 提示注入、数据泄露、恶意代码 |
| Threat Protection | threat_policies_pro | SQLi, NoSQLi, SSRF, XSS 威胁检测 |
| Business Logic | standard + pro | 输入验证、批量赋值、速率限制 |

### 9.6 离线/气隙环境

GitHub 不可达时：
1. Dashboard 使用内置 `tests-library-master.zip`（132 模板）作为 fallback
2. 可手动下载分支 zip 并通过 Dashboard Test Editor 导入
3. 自定义模板可直接在 Test Editor 中创建

---

## 10. 模板来源在原仓库的位置

| 打包目录 | GitHub 仓库 | 分支/路径 |
|---|---|---|
| `standard/` | akto-api-security/tests-library | `standard` 分支 |
| `pro/` | akto-api-security/tests-library | `pro` 分支 |
| `agentic-pro/` | akto-api-security/tests-library | `agentic-pro` 分支 |
| `threat_policies_pro/` | akto-api-security/tests-library | `threat_policies_pro` 分支 |
| `mcp-standard/` | akto-api-security/tests-library | `mcp-standard` 分支 |
| `mcp-pro/` | akto-api-security/tests-library | `mcp-pro` 分支 |
| `dashboard-inbuilt-test-yaml-files/` | akto-api-security/akto | `apps/dashboard/src/main/resources/inbuilt_test_yaml_files/` |
| `dashboard-inbuilt-llm-test-yaml-files/` | akto-api-security/akto | `apps/dashboard/src/main/resources/inbuilt_llm_test_yaml_files/` |
| `dashboard-fallback-tests-library-master.zip` | akto-api-security/akto | `apps/dashboard/src/main/resources/tests-library-master.zip` |

---

## 11. 总结

### 11.1 关键数字

| 维度 | 数量 |
|---|---|
| 仓库总分支数 | 258 |
| 运行时使用的分支数 | 6 |
| **安全测试模板总数**（5 个测试分支去重后） | **5,382** |
| **威胁检测规则总数** | **5** |
| standard 分支 | 311 |
| pro 分支 | 408（与 standard 零重叠） |
| agentic-pro 分支 | 4,427（274 API + 4,153 AI Agent） |
| threat_policies_pro 分支 | 5 个威胁规则 + 200 个测试模板（agentic-pro 子集）+ 993 合规 + 1,004 修复 |
| mcp-standard 分支 | 5 |
| mcp-pro 分支 | 231 |
| Dashboard 内置模板 | 187（132 传统 + 55 LLM，早期快照） |
| 合规配置文件 | 2,145（993 + 1,152） |
| 修复指南文件 | 2,229（1,004 + 1,225） |
| 合规框架数 | 10 |
| 攻击技术数 | 15 |
| 覆盖的严重程度 | 4 级 (CRITICAL / HIGH / MEDIUM / LOW) |

### 11.2 安全测试 vs 威胁检测

| 维度 | 安全测试（5 个分支） | 威胁检测（threat_policies_pro） |
|---|---|---|
| **分支** | standard, pro, agentic-pro, mcp-standard, mcp-pro | threat_policies_pro |
| **模板数** | 5,382 | 5 |
| **目的** | 主动发请求验证漏洞 | 被动分析流量检测攻击 |
| **MongoDB** | `yaml_templates` | `filter_yaml_templates` |
| **执行服务** | akto-api-testing | akto-threat-detection + Dashboard MatchingJob |
| **运行方式** | 用户触发 / 定时调度 | Kafka 实时流式 + 每 30 分钟批量 |
| **YAML 结构** | `api_selection_filters` → `execute` → `validate` | `filter` → `aggregation_rules` |
| **输出** | 漏洞报告 (TestingRunResult) | MaliciousEvent 告警 |

### 11.3 分支设计哲学

| 分支 | 用途 | 设计哲学 | 模板粒度 | 计划 |
|---|---|---|---|---|
| standard | 安全测试 | 通用场景覆盖 | 粗（11 个 BOLA） | FREE/STANDARD |
| pro | 安全测试 | 深度测试，按方法/类型拆分 | 细（59 个 BOLA） | PRO |
| agentic-pro | 安全测试 | Agent 化安全测试 | 极细（4,153 个生成测试） | PRO |
| threat_policies_pro | 威胁检测 | 运行时流量匹配 + 聚合告警 | 粗（5 个规则） | PRO |
| mcp-standard | 安全测试 | MCP 基础测试 | 粗（5 个） | FREE |
| mcp-pro | 安全测试 | MCP 深度测试 | 细（231 个） | PRO |

### 11.4 关键结论

1. **代码使用 `standard` 分支，不是 `master`** — master 是旧版，standard 是替代版（311 vs 209 模板），两者 ID 零重叠
2. **安全测试与威胁检测是两个独立系统** — 5 个分支用于安全测试（主动验证），threat_policies_pro 用于威胁检测（被动监控），写入不同 MongoDB 集合，由不同服务执行
3. **threat_policies_pro 仅 5 个真正的威胁检测规则** — 其余 200 个模板是 agentic-pro 的副本，在加载时被代码跳过
4. **威胁检测规则使用聚合告警机制** — Redis 滑动窗口计数，5 分钟内 50 次或 10 分钟内 100 次匹配才触发告警
5. **所有模板运行时从 MongoDB 读取** — 不嵌入任何容器镜像，Dashboard 启动时从 GitHub 拉取
6. **MCP 分支通过 Account Settings 动态加载** — 未在代码中硬编码，用户按需添加
7. **Dashboard 内置 187 个模板仅作 fallback** — GitHub 不可达时使用，运行时会被 GitHub 版本覆盖
8. **pro 的模板不是 standard 的增量** — 两者是独立设计的互补模板集，合并使用

Akto 测试库覆盖了 OWASP API Top 10、OWASP LLM Top 10、MCP 安全和 AI Agent 安全领域，同时提供运行时威胁检测能力，是目前开源社区中最全面的 API 安全平台之一。
