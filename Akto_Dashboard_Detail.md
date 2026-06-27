# Akto Dashboard 模块详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/apps/dashboard
> 代码规模：282 个 Java 文件，73,065 行 + Vue/React 前端
> ECR 镜像：`aktosecurity/akto-api-security-dashboard`

---

## 1. 功能定位

Dashboard 是 Akto 平台的**中央控制台**，是唯一面向用户的 Web 应用。它集 API 清单管理、安全测试配置、威胁检测监控、测试模板管理、用户管理、计费、集成于一体，是所有其他模块的调度中心。

### 核心职责

| 职责 | 说明 |
|---|---|
| **Web UI** | 提供 API 清单、测试结果、威胁告警、设置等全部界面 |
| **流量处理** | 社区版内嵌 api-runtime 库，处理导入的流量 |
| **模板管理** | 从 GitHub 拉取测试模板，写入 MongoDB |
| **任务调度** | 10+ 个定时任务（模板同步、清理、告警、PII 更新等） |
| **多租户** | 支持多账户隔离，每个账户独立的 API 集合和配置 |
| **集成** | Slack/Teams/Jira/ServiceNow/AWS WAF/Cloudflare/GitHub 等 |
| **计费** | Stigg 集成，功能授权和用量追踪 |
| **认证** | SAML SSO + JWT + 用户名密码 |

---

## 2. 技术栈

### 2.1 后端

| 技术 | 版本 | 用途 |
|---|---|---|
| Jetty | 9.4 (JRE 8) | Servlet 容器 |
| Struts2 | 2.5.30 | MVC 框架（所有 API 端点） |
| MongoDB Driver | 4.2.1 | 数据库 |
| Kafka Client | 3.7.2 | 消息队列（社区版不用） |
| Guava | 31.1 | 工具库（Bloom Filter 等） |
| Jackson | 2.16.1 | JSON 处理 |
| jjwt | 0.11.2 | JWT 认证 |
| Java SAML | — | SSO 集成 |
| AWS SDK | — | WAF/CloudFormation/EC2/Lambda |
| SendGrid | — | 邮件通知 |
| Slack API Client | 1.7.1 | Slack 通知 |
| Bucket4j | — | 速率限制 |
| Micrometer + Prometheus | — | 指标监控 |

### 2.2 前端

| 技术 | 用途 |
|---|---|
| React 17 | 主前端框架 |
| Vue 2 | 部分页面（混合使用） |
| Webpack | 构建工具 |

### 2.3 部署

```
Docker 镜像: jetty:9.4-jre8
端口: 8080
WAR: root.war (部署在 Jetty webapps/root)
入口: /entrypoint.sh → set_xmx.sh → docker-entrypoint.sh → java -jar start.jar
```

---

## 3. 代码结构

### 3.1 包结构

```
apps/dashboard/src/main/java/com/akto/
├── action/          191 文件  55,529 行  ← Struts2 Action (API 端点)
├── filter/           11 文件   1,070 行  ← Servlet Filter
├── interceptor/       5 文件     569 行  ← Struts2 Interceptor
├── listener/          6 文件   5,412 行  ← 生命周期监听器
├── otel/              1 文件      49 行  ← OpenTelemetry
├── service/           1 文件     175 行  ← 服务层
├── util/              6 文件   1,052 行  ← 旧工具类
├── utils/            60 文件   9,163 行  ← 新工具类
└── websocket/         1 文件      46 行  ← WebSocket
```

### 3.2 Listener（6 个，5,412 行）

| 类 | 行数 | 职责 |
|---|---|---|
| `InitializerListener` | **4,861** | 核心初始化器，启动所有定时任务，加载模板/PII/合规配置 |
| `RuntimeListener` | ~200 | 社区版内嵌 api-runtime，创建 HttpCallParser 处理导入流量 |
| `KafkaListener` | ~150 | Kafka 消息监听（企业版实时流量） |
| `InfraMetricsListener` | ~100 | 基础设施指标收集 |
| `RequestEventListener` | ~80 | 请求事件追踪 |
| `AfterMongoConnectListener` | ~50 | MongoDB 连接后回调 |

> `InitializerListener.java` 是整个 Akto 系统最复杂的单个文件（4,861 行），包含 10+ 个定时任务、模板同步、PII 加载、合规配置、WAF 集成等全部初始化逻辑。

### 3.3 Action 类（80 个，55,529 行）

按功能分类：

| 分类 | Action 数 | 代表类 | 功能 |
|---|---|---|---|
| **API 清单** | 8 | ApiCollectionsAction, ApiInfoAction, APICatalogAction, DependencyAction | API 集合管理、端点查看、依赖分析 |
| **安全测试** | 6 | TestingAction, TestEditorAction, HarAction, PostmanAction, DastAction | 测试配置、执行、结果查看 |
| **威胁检测** | 4 | ThreatDetectionAction, AuditDataAction, McpAgentAction, MCPScanAction | 威胁告警、审计数据、MCP 扫描 |
| **测试模板** | 5 | TestEditorAction, YamlTemplateAction, CustomDataTypeAction, SensitiveFieldAction, FilterAction | 模板管理、自定义数据类型 |
| **流量导入** | 5 | HarAction, PostmanAction, BurpJarAction, OpenApiAction, SwaggerDependenciesAction | 多种流量来源导入 |
| **用户/认证** | 8 | LoginAction, SignupAction, UserAction, RoleAction, TeamAction, InviteUserAction, AccessTokenAction, ValidateEmailAction | 用户管理、角色、邀请 |
| **集成** | 8 | JiraIntegrationAction, ServiceNowIntegrationAction, AzureBoardsIntegrationAction, SlackAlertsAction, WizIntegrationAction, SentinelOneIntegrationAction, MicrosoftDefenderIntegrationAction, AdxIntegrationAction | 第三方集成 |
| **WAF** | 2 | AwsWafAction, CloudflareWafAction | AWS/Cloudflare WAF 规则推送 |
| **计费** | 3 | AccountAction, BillingAction, UsageMetricsAction | 账户管理、Stigg 计费 |
| **代码分析** | 2 | CodeAnalysisAction, SwaggerDependenciesAction | 源码分析 |
| **Agent/AI** | 5 | AgentImportAction, AIAgentConnectorImportAction, AgenticDashboardAction, AgenticObserveAction, CopilotStudioAction | AI Agent 管理 |
| **MCP** | 5 | MCPReconAction, MCPScanAction, McpAgentAction, McpAllowlistAction, McpRegistryAction | MCP 安全 |
| **其他** | 19 | DashboardAction, HomeAction, ReportAction, LogsAction, CleanAction 等 | 通用功能 |

### 3.4 Filter（11 个）

| Filter | 职责 |
|---|---|
| `AuthorizationFilter` | JWT/Session 认证 |
| `RateLimitFilter` | API 速率限制（Bucket4j） |
| `SecurityHeadersFilter` | 安全响应头（CSP, X-Frame-Options 等） |
| `MongoConnectCheckFilter` | MongoDB 连接检查 |
| `HttpMethodFilter` | HTTP 方法过滤 |
| `LoggingFilter` | 请求日志 |
| `ForbiddenEndpointsFilter` | 禁止端点过滤 |
| `GrowthToolsFilter` | 增长工具过滤 |
| `MetaInfoFilter` | 元信息注入 |
| `InfraMetricsFilter` | 基础设施指标 |

### 3.5 Interceptor（5 个）

| Interceptor | 职责 |
|---|---|
| `UsageInterceptor` | Stigg 用量追踪 |
| `RoleAccessInterceptor` | 角色权限检查 |
| `CollectionInterceptor` | API Collection 上下文注入 |
| `ContextBasedUsageInterceptor` | 基于上下文的用量检查 |
| `UsageInterceptorUtil` | 用量拦截器工具 |

### 3.6 Utils 子包（60 个文件）

| 子包 | 文件数 | 职责 |
|---|---|---|
| `billing/` | — | 计费工具 |
| `cloud/` | — | 云平台集成 |
| `crons/` | — | 定时任务 |
| `jira/` | — | Jira 集成 |
| `jobs/` | — | 后台作业（MatchingJob, CleanInventory 等） |
| `platform/` | — | 平台详情（MirroringStackDetails 等） |
| `scripts/` | — | 脚本工具 |
| `sso/` | — | SSO 集成 |
| `threat_detection/` | — | 威胁检测工具 |
| `wiz/` | — | Wiz 集成 |

### 3.7 资源文件（204 个）

| 类型 | 数量 | 说明 |
|---|---|---|
| `inbuilt_test_yaml_files/` | 132 | 内置传统测试模板 |
| `inbuilt_llm_test_yaml_files/` | 55 | 内置 LLM 测试模板 |
| `tests-library-master.zip` | 1 | 离线 fallback 模板包 |
| `cloud_formation_templates/` | 2 | AWS CloudFormation 模板 |
| `sentinelone/` | 6 | SentinelOne 集成配置 |
| `struts.xml` | 1 | Struts2 配置 |
| 其他 | 7 | JSON/Sample 数据 |

---

## 4. 数据流全景

```
                    ┌──────────────────────────────────────────────────────┐
                    │                  用户请求                              │
                    │                                                      │
                    │  浏览器 → Jetty:8080 → Struts2 → Action → MongoDB     │
                    └──────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────────────┐
                    │                   │                           │
                    ▼                   ▼                           ▼
            ┌──────────────┐  ┌──────────────────┐     ┌──────────────────┐
            │  流量导入      │  │  定时任务调度      │     │  模板/PII 同步     │
            │              │  │                  │     │                  │
            │ HAR/Postman  │  │ InitializerListener│     │ GitHub API       │
            │ Burp/OpenAPI │  │ 10+ schedulers   │     │ → tests-library   │
            │ OTel/PCAP    │  │                  │     │ → pii-types       │
            │              │  │ • 模板同步 (4h)   │     │ → automated-groups│
            │ → Runtime    │  │ • 清理 (daily)   │     │                  │
            │   Listener   │  │ • 告警 (30min)   │     │ → MongoDB         │
            │ → HttpCall   │  │ • PII 更新 (1h)  │     │                  │
            │   Parser     │  │ • WAF 同步       │     │                  │
            │ → MongoDB    │  │ • Webhook (5min) │     │                  │
            └──────────────┘  └──────────────────┘     └──────────────────┘
                                        │
                    ┌───────────────────┼───────────────────────────┐
                    │                   │                           │
                    ▼                   ▼                           ▼
            ┌──────────────┐  ┌──────────────────┐     ┌──────────────────┐
            │  MongoDB      │  │  外部服务          │     │  下游服务          │
            │              │  │                  │     │                  │
            │ 20+ 集合      │  │ • Stigg (计费)   │     │ → api-testing    │
            │              │  │ • Slack (通知)   │     │   (读取模板执行)   │
            │ • api_collections│ • SendGrid (邮件)│     │ → threat-detection│
            │ • single_type_info│ • Jira/ServiceNow│     │   (读取威胁规则)  │
            │ • yaml_templates│ • AWS WAF        │     │ → api-analyser    │
            │ • filter_yaml_  │ • Cloudflare WAF │     │   (读取 STI 统计)  │
            │   templates    │ • Intercom       │     │                  │
            │ • testing_run  │ • GitHub API     │     │                  │
            │ • traffic_metrics│ • Mixpanel      │     │                  │
            │ • sensitive_   │                  │     │                  │
            │   param_info   │  │                  │     │                  │
            │ • ...          │  │                  │     │                  │
            └──────────────┘  └──────────────────┘     └──────────────────┘
```

---

## 5. 定时任务（10+ 个）

| 任务 | 频率 | 功能 |
|---|---|---|
| 模板同步 | 4 小时 | 从 GitHub 拉取 tests-library 各分支模板 |
| Automated API Groups | 4 小时 | 从 GitHub 拉取自动分组 CSV |
| 清理任务 | 1 天 | 清理过期数据、合并冗余 API |
| 流量告警 | 30 分钟 | 检测流量下降并告警 |
| PII/测试源更新 | 1 小时 | 拉取 PII 类型库 |
| Webhook 同步 | 5 分钟 | 推送告警到外部 Webhook |
| 威胁活动同步 | 固定延迟 | 同步威胁检测告警 |
| Mixpanel 事件 | 定时 | 上报使用指标 |
| WAF 同步 | 定时 | 推送威胁策略到 AWS/Cloudflare WAF |
| 数据类型映射 | 定时 | 执行数据类型到模板的映射 |

---

## 6. 社区版 vs 企业版

| 维度 | 社区版 (local_deploy) | 企业版 (on_prem/saas) |
|---|---|---|
| 部署方式 | docker-compose 单机 | 独立容器 + Kafka + NLB |
| 流量处理 | 内嵌 api-runtime 库 | api-runtime 独立容器 |
| Context Analyzer | ❌ 不启用 | ✅ 独立容器 |
| Kafka | ❌ 不需要 | ✅ 必需 |
| Stigg 计费 | ❌ 跳过 | ✅ 功能授权 |
| 实时流量 | ❌ 仅导入 | ✅ 实时消费 |
| 多租户 | ❌ 单账户 | ✅ 多账户隔离 |
| SSO | ❌ | ✅ SAML SSO |
| AWS WAF/Cloudflare | ❌ | ✅ |

---

## 7. 依赖关系

### 7.1 Maven 依赖

| 依赖 | 用途 |
|---|---|
| `api-runtime` | 内嵌流量处理（HttpCallParser, APICatalogSync） |
| `api-analyser` | 依赖 JAR（社区版不实例化 ResourceAnalyser） |
| `dao` | 数据访问层（全部 DAO + DTO） |
| `utils` | 共享工具库（测试执行器, 过滤器等） |
| `testing` | 测试引擎依赖 |
| `integrations` | 第三方集成 |

### 7.2 被依赖

Dashboard 是最终部署单元，不被其他模块依赖。

---

## 8. API 端点规模

- **80 个 Struts2 Action 类**
- **25 个子包**（action/agents, action/billing, action/test_editor 等）
- **5 个 Interceptor**（认证、权限、用量、上下文、集合）
- **11 个 Filter**（认证、限流、安全头、日志等）

主要 API 端点分类：

| 路径前缀 | Action | 功能 |
|---|---|---|
| `/dashboard` | DashboardAction | 首页、概览 |
| `/api-collections` | ApiCollectionsAction | API 集合管理 |
| `/api-info` | ApiInfoAction | API 端点详情 |
| `/testing` | TestingAction | 安全测试 |
| `/test-editor` | TestEditorAction | 测试模板编辑 |
| `/threat-detection` | ThreatDetectionAction | 威胁告警 |
| `/har` / `/postman` | HarAction / PostmanAction | 流量导入 |
| `/account` | AccountAction | 账户管理 |
| `/waf` | AwsWafAction / CloudflareWafAction | WAF 集成 |
| `/mcp` | MCPScanAction / MCPReconAction | MCP 安全 |

---

## 9. MongoDB 集合（20+）

| 集合 | 说明 |
|---|---|
| `api_collections` | API 集合 |
| `single_type_info` | 参数类型信息 |
| `sensitive_param_info` | 敏感参数 |
| `yaml_templates` | 安全测试模板 |
| `filter_yaml_templates` | 威胁检测规则 |
| `testing_run` | 测试运行记录 |
| `testing_run_result` | 测试结果 |
| `testing_run_result_summaries` | 测试结果汇总 |
| `vulnerable_testing_run_result` | 漏洞结果 |
| `testing_run_issues` | 测试问题 |
| `traffic_metrics` | 流量指标 |
| `api_info` | API 元信息 |
| `filter_sample_data` | 过滤后样本数据 |
| `akto_data_types` | Akto 数据类型 |
| `custom_data_types` | 自定义数据类型 |
| `pii_sources` | PII 来源 |
| `accounts` | 账户 |
| `account_settings` | 账户设置 |
| `organizations` | 组织 |
| `compliance_infos` | 合规信息 |
| `threat_compliance_info` | 威胁合规映射 |

---

## 10. 关键特性

### 10.1 多租户

- 每个账户有独立的 API Collection、测试配置、告警
- `AccountTask.executeTask()` 遍历所有活跃账户执行任务
- `Context.accountId` ThreadLocal 隔离账户上下文

### 10.2 认证

| 方式 | 说明 |
|---|---|
| 用户名密码 | 社区版默认 |
| JWT | API Token 认证 |
| SAML SSO | 企业版（java-saml 库） |
| Intercom | SaaS 模式用户支持 |

### 10.3 速率限制

- Bucket4j 实现的 API 速率限制
- `RateLimitFilter` 拦截所有请求
- 防止 API 滥用

### 10.4 集成

| 集成 | 方向 | 说明 |
|---|---|---|
| Slack | 出 | 告警通知 |
| Microsoft Teams | 出 | 告警通知 |
| Jira | 双向 | Issue 创建/同步 |
| ServiceNow | 出 | 工单创建 |
| AWS WAF | 出 | 威胁策略推送 |
| Cloudflare WAF | 出 | 威胁策略推送 |
| SendGrid | 出 | 邮件通知 |
| GitHub | 入 | 模板/PII/分组拉取 |
| Stigg | 双向 | 计费/功能授权 |
| Intercom | 出 | 用户支持 |
| Mixpanel | 出 | 使用分析 |
| Wiz | 入 | 安全态势集成 |
| SentinelOne | 入 | 终端安全集成 |

---

## 11. 局限性

### 11.1 架构

- **InitializerListener 过于庞大** — 4,861 行单文件，包含 10+ 个定时任务和全部初始化逻辑，维护困难
- **Struts2 框架陈旧** — Struts2 2.5.30，框架本身已不活跃，且有历史安全漏洞
- **JRE 8 限制** — 使用 OpenJDK 8，无法使用现代 Java 特性
- **前后端混合** — React + Vue 混用，前端架构不统一

### 11.2 性能

- **单进程** — 所有定时任务在同一个 Jetty 进程中运行，无水平扩展
- **MongoDB 轮询** — 定时任务通过轮询 MongoDB 实现，非事件驱动
- **无消息队列** — 社区版无 Kafka，任务调度依赖内存

### 11.3 安全

- **SQL/NoSQL 注入风险** — 部分 Action 直接拼接 MongoDB 查询
- **Struts2 漏洞历史** — Struts2 有多个 RCE 漏洞历史
- **管理端口暴露** — 8080 端口同时服务 UI 和 API

---

## 12. 总结

| 维度 | 值 |
|---|---|
| 代码规模 | 282 Java 文件 / 73,065 行 + 前端 |
| Action 类 | 80 个 |
| Listener | 6 个（InitializerListener 4,861 行） |
| 定时任务 | 10+ 个 |
| MongoDB 集合 | 20+ 个 |
| 依赖 | 46 个 Maven 依赖 |
| 集成 | 14 个第三方集成 |
| 部署 | Jetty 9.4 + JRE 8 |
| 前端 | React 17 + Vue 2 |
| 执行模块 | Dashboard 自身（不是 api-runtime 或 api-analyser） |
| 是否使用 ML | ❌ 否 |

Dashboard 是 Akto 的"大脑"——所有配置、调度、管理、展示都在这里。它不是流量处理器（那是 api-runtime 的职责），而是**控制平面**：管理 API 清单、调度测试、同步模板、推送告警、管理用户。4,861 行的 `InitializerListener` 是整个系统最复杂的单个文件，承载了几乎所有的初始化和定时任务逻辑。
