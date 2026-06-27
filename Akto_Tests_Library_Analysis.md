# Akto API 安全测试库全面分析

> 分析日期：2026-06-27
> 仓库地址：https://github.com/akto-api-security/tests-library
> 分析范围：master、pro、agentic-pro 三个分支

---

## 1. 概览

Akto 测试库是 Akto API 安全平台的核心组件，包含所有内置安全测试模板。仓库采用多分支策略，不同分支对应不同的测试维度。三个分支是**独立设计的互补模板集**，并非增量关系。

### 1.1 分支总览

| 分支 | 对应计划 | YAML 模板 | 合规配置 | 修复指南 | 用途 |
|---|---|---|---|---|---|
| **master** | FREE | 209 | 5,308 | 1,227 | 基础 API 安全测试（通用场景，粗粒度） |
| **pro** | PRO | 408 | — | — | 深度 API 安全测试 + LLM 安全（细粒度，按 HTTP 方法/数据类型拆分） |
| **agentic-pro** | PRO | 4,427 | 1,152 | 1,225 | AI Agent 安全测试（大规模生成式测试） |
| **合计** | — | **5,044** | **6,515** | **2,453** | |

### 1.2 三个分支的关系

**master 与 pro 是完全独立的模板集，合并使用：**

| 对比维度 | master (209) | pro (408) | 重叠 |
|---|---|---|---|
| 文件名重叠 | — | — | 0 |
| 模板 ID 重叠 | — | — | 0 |
| 共有分类 | 12 个 | 15 个 | 12 个（但内容不同） |
| 设计风格 | 通用场景，一个模板覆盖一类漏洞 | 深度测试，按 HTTP 方法/数据类型拆分 | — |

**示例对比 — BOLA 分类：**
- master: 6 个模板（`AddUserId`, `BOLAByChangingAuthToken`, `ParameterPollution` 等）
- pro: 59 个模板（`BOLAAddCustomHeader`, `BOLAAddCustomHeaderDELETE`, `BOLAAddCustomHeaderIntegerID`, `BOLAAddCustomHeaderIntegerIDPATCH`, `BOLACookieFuzzing`, `BOLAJSONBodyParamArray` 等）

**pro 独有的分类：**
- `LLM-Security/` — 54 个 LLM 安全测试
- `Improper Inventory Management/` — 3 个

**master 独有的分类：**
- `CORS-Misconfiguration`、`Mass-Assignment`、`Misconfigured-HTTP-Headers`、`Server-Side-Template-Injection`、`Server-Version-Disclosure`、`Threat-Protection`、`Unnecessary-HTTP-Methods`、`Verbose-Error-Messages`、`compliance`

### 1.3 加载机制

三个分支在运行时**同时加载，合并使用**。代码逻辑（`InitializerListener.java`）：

```java
// 默认加载 standard + pro 两个分支
public static Set<String> getAktoDefaultTestLibs() {
    return new HashSet<>(Arrays.asList(
        "akto-api-security/tests-library:standard",   // master 分支
        "akto-api-security/tests-library:pro"          // pro 分支
    ));
}

// Agentic 授权用户额外加载 agentic-pro
public static Set<String> getAktoDefaultTestLibs(int accountId) {
    Set<String> libs = getAktoDefaultTestLibs();
    if (includeAgenticTestLibForAccount(accountId)) {
        libs.add(AKTO_TESTS_LIBRARY_AGENTIC);   // agentic-pro 分支
    }
    return libs;
}

// 遍历所有分支，逐个拉取并写入同一个 MongoDB 集合
for (String repoKey : toSync) {
    syncAktoDefaultTestLibraryZip(repoKey);
}
```

**运行时生效的模板数量：**

| 条件 | 加载的分支 | 模板总数 |
|---|---|---|
| 所有用户 | standard + pro | 209 + 408 = **617** |
| Agentic 授权用户 | standard + pro + agentic-pro | 617 + 4,427 = **5,044** |

**完整加载流程：**

```
1. Dashboard 启动 (InitializerListener)
   ├── saveLLmTemplates()  ← 从 classpath:/inbuilt_llm_test_yaml_files/ 读取 55 个 LLM 模板
   ├── syncAllAktoDefaultTestLibraries()
   │   ├── GitHub: tests-library:standard → zip → processTemplateFilesZip()  → 209 模板
   │   ├── GitHub: tests-library:pro → zip → processTemplateFilesZip()       → 408 模板
   │   └── GitHub: tests-library:agentic-pro → zip → processTemplateFilesZip() (条件性) → 4,427 模板
   └── Fallback: classpath:/tests-library-master.zip → processTemplateFilesZip() (GitHub 不可达时)

2. 所有模板写入同一个 MongoDB yaml_templates 集合
   ├── author = "AKTO"
   ├── source = "AKTO_TEMPLATES"
   └── content = YAML 原文

3. Testing Engine (akto-api-testing)
   ├── 从 MongoDB 读取 yaml_templates（不区分来源分支）
   ├── 解析 YAML → TestConfig
   ├── 按 api_selection_filters 选择目标 API
   ├── 执行 execute 部分的请求
   └── 用 validate 部分判断漏洞
```

---

## 2. master 分支（209 个模板）

### 2.1 定位

面向通用场景，模板粒度粗，一个文件覆盖一类漏洞。所有模板 `plan: FREE`。

### 2.2 漏洞分类分布

| 分类 | 数量 | 说明 |
|---|---|---|
| Security-Misconfiguration | 64 | Django/Flask/Express debug 模式, Spring Boot Actuator, Tomcat RCE, Docker/Apache 配置泄露 |
| Input-Validation | 24 | 优惠券篡改, 支付绕过, 订阅取消绕过, 库存操纵 |
| Command-Injection | 23 | OS 命令注入, 内核命令注入 |
| Broken-User-Authentication | 23 | JWT none algo, 2FA 暴力, CSRF, SQL 注入认证绕过 |
| Server-Side-Request-Forgery | 12 | AWS metadata, localhost, PDF/XML/CSV 上传 SSRF |
| Local-File-Inclusion | 11 | 路径遍历, XML 外部实体 (XXE) |
| Threat-Protection | 8 | SQLi, NoSQLi, SSRF, XSS, LFI 综合检测 |
| Misconfigured-HTTP-Headers | 7 | X-Frame-Options, HSTS, Cookie 安全 |
| Cross-Site-Scripting | 6 | Path, Filename, Query param XSS |
| Broken-Object-Level-Authorization | 6 | Auth token 替换, 用户 ID 模糊, 参数污染 |
| Mass-Assignment | 4 | 批量赋值漏洞 |
| Lack-of-Resources-and-Rate-Limiting | 4 | 速率限制, 资源耗尽 |
| Injection-Attacks | 3 | SQL/NoSQL 注入 |
| Verbose-Error-Messages | 2 | 详细错误信息泄露 |
| Unnecessary-HTTP-Methods | 2 | TRACE, TRACK 方法 |
| Server-Side-Template-Injection | 2 | Flask/Jinja, Twig SSTI |
| CRLF-Injection | 2 | CRLF 注入 |
| CORS-Misconfiguration | 2 | CORS 跨域配置错误 |
| Broken-Function-Level-Authorization | 2 | BFLA |
| Server-Version-Disclosure | 1 | 服务器版本泄露 |
| compliance | 1 | 合规预设 |

### 2.3 严重程度分布

| 严重程度 | 数量 |
|---|---|
| HIGH | 56 |
| MEDIUM | 53 |
| LOW | 69 |
| CRITICAL | 30 |

### 2.4 测试性质分布

| 性质 | 数量 | 说明 |
|---|---|---|
| INTRUSIVE | 129 | 主动发送攻击 payload |
| NON_INTRUSIVE | 71 | 仅观察响应，不发送攻击 |

### 2.5 完整模板列表

#### Broken-Function-Level-Authorization (2)
- BFLAInsertAdminURLPaths.yml
- BFLAwithGETMethod.yml

#### Broken-Object-Level-Authorization (6)
- AddUserId.yaml
- BOLAByChangingAuthToken.yaml
- BOLAByFuzzingUserID.yml
- OldApiVersion.yaml
- OldApiVersionInactive.yml
- ParameterPollution.yaml

#### Broken-User-Authentication (23)
- AuthBypassBlankPassword.yml
- AuthBypassLockedAccountTokenRole.yml
- AuthBypassPasswordChange.yml
- AuthBypassSQLInjection.yml
- AuthBypassStagingURL.yml
- Bypass2FABruteForceAttack.yml
- CSRFLoginAttack.yaml
- ExpiresMaxAgeCheck.yml
- GrafanaSnapshotCreation.yml
- GraphQLContentTypeCSRF.yaml
- JWTParamInjectionJWK.yml
- KubePILoginLogsSearchBrokenAccess.yml
- NoAuth.yaml
- NoSQLiErrorBasedReplaceBodyMongo.yml
- RemoveCSRF.yaml
- ReplaceCSRF.yaml
- SQLInjectionRefererHeader.yml
- SQLInjectionUserAgentHeader.yml
- SQLiErrorBasedParamAppendPayloadMySQL.yml
- SQLiErrorBasedParamAppendPayloadPostgreSQL.yml
- SQLiErrorBasedParamAppendPayloadSQLite.yml
- SQLiErrorBasedReplaceBodyMySQL.yml
- TestPasswdChange.yml

#### CORS-Misconfiguration (2)
- CORSMisconfigurationInvalidOrigin.yaml
- CORSMisconfigurationWhitelistOrigin.yaml

#### CRLF-Injection (2)
- AbusingCRLFInHeaders.yaml
- HttpResponseSplitting.yaml

#### Command-Injection (23)
- CommandInjectionByAddingQueryParams.yaml
- KernelOpenCommandInjection.yaml
- 等 21 个

#### Cross-Site-Scripting (6)
- AppendXSS.yaml
- BasicXSS.yaml
- XSSInPath.yaml
- XSSViaFilename.yaml
- 等

#### Injection-Attacks (3)
- SQL/NoSQL/Command 注入变体

#### Input-Validation (24)
- BypassLimitedTimeValidation.yml
- BypassMinimumSpendValidation.yml
- BypassOrderDepositValidation.yml
- BypassProductBundleHandling.yml
- BypassSubscriptionCancellationHandling.yml
- CouponCodeTampering.yml
- DummyContentLengthHeader.yml
- ExploitDefaultValuesForLoanCalculation.yml
- HeaderAllkeysInvalidValues.yml
- ImproperAmonutTransferHandling.yml
- ImproperGiftHandling.yml
- ImproperInputInKafkaRest.yml
- ManipulateInventoryStock.yml
- ManipulateProductAccess.yml
- ManipulatingAccessLevels.yml
- ManipulatingPaymentGatewayHandoff.yml
- ManipulatingTransactionReversal.yml
- ManipulatingXML.yml
- OverrideDefaultPaymentMethods.yml
- OverwritingExistingResourcesByManipulatingIentifiers.yml
- ParameterManipulationBoundaryCoupon.yml
- ParameterManipulationIntegerOutOfBounds.yml
- PromoCodeExploitation.yml
- ReferralExploitation.yml

#### Lack-of-Resources-and-Rate-Limiting (4)
- 速率限制测试

#### Local-File-Inclusion (11)
- 路径遍历, XXE 等

#### Mass-Assignment (4)
- 批量赋值漏洞

#### Misconfigured-HTTP-Headers (7)
- X-Frame-Options, HSTS, Cookie 安全等

#### Security-Misconfiguration (64)
- AirflowConfigurationExposure.yaml
- AmazonDockerConfig.yaml
- ApacheConfig.yaml
- CircleciConfig.yaml
- ConfigJson.yaml
- ConfigRuby.yaml
- DebugVars.yaml
- DjangoDefaultHomepageEnabled.yaml
- DockerComposeConfig.yaml
- ExpressDefaultHomepageEnabled.yaml
- ExpressStackTraceEnabled.yaml
- FlaskDebugModeEnabled.yaml
- FirebaseConfigExposure.yaml
- FirebaseUnauthenticated.yaml
- SpringBootBeansActuatorExposed.yaml
- SpringBootConfigPropsActuatorExposed.yaml
- SpringBootEnvActuatorExposed.yaml
- SpringBootHttpTraceActuatorExposed.yaml
- SpringBootThreadDumpActuatorExposed.yaml
- StrutsDebugModeEnabled.yaml
- StrutsOgnlConsoleEnabled.yaml
- UnauthenticatedMongoExpress.yaml
- 等

#### Server-Side-Request-Forgery (12)
- FetchSensitiveFilesViaSSRF.yaml
- SSRFOnAwsMetaEndpoint.yaml
- SSRFOnCSVUpload.yaml
- SSRFOnFiles.yaml
- SSRFOnImageUpload.yaml
- SSRFOnLocalhost.yaml
- SSRFOnLocalhostDNSPinning.yaml
- SSRFOnLocalhostEncoded.yaml
- SSRFOnPDFUpload.yaml
- SSRFOnXMLUpload.yaml
- SSRFScriptTagAWSRedirect.yml
- SSRFScriptTagAzureRedirect.yml
- SSRFScriptTagLocalhostRedirect.yml

#### Server-Side-Template-Injection (2)
- SSTIInFlaskAndJinja.yaml
- SSTIInTwig.yaml

#### Server-Version-Disclosure (1)
- ServerVersionExposedInvalid.yaml

#### Threat-Protection (8)
- LocalFileInclusion.yml
- NoSqlInjection.yml
- OsCommandInjection.yml
- SQLInjection.yml
- SSRF.yml
- SecurityMisconfig.yml
- WindowsCommandInjection.yml
- XSS.yml

#### Unnecessary-HTTP-Methods (2)
- TraceMethodTest.yaml
- TrackMethodTest.yaml

#### Verbose-Error-Messages (2)
- InvalidFileInput.yaml
- SQLInjectionURLPath.yml

---

## 3. pro 分支（408 个模板）

### 3.1 定位

面向深度测试，模板粒度细，按 HTTP 方法 (GET/DELETE/PATCH) 和数据类型 (Integer/Array/JSONObject) 拆分。与 master 分支**完全独立**，无任何文件名或模板 ID 重叠。所有模板 `plan: FREE`（但需要 Pro 订阅才能拉取该分支）。

### 3.2 漏洞分类分布

| 分类 | 数量 | 说明 |
|---|---|---|
| Broken-User-Authentication | 97 | JWT 攻击变体, GraphQL CSRF, SQL 注入变体, 2FA 绕过 |
| Broken-Object-Level-Authorization | 59 | URL 插入, Cookie 模糊, JSON Body 数组, 自定义 Header × DELETE/PATCH |
| LLM-Security | 54 | 提示注入, 敏感数据泄露, 幻觉, 恶意代码生成, 过度依赖 |
| Lack-of-Resources-and-Rate-Limiting | 41 | DoS 测试, 速率限制 |
| Injection-Attacks | 39 | SQL/NoSQL/XXE/XPath/SSRF 注入扩展 |
| Command-Injection | 38 | OS 命令注入变体 |
| Security-Misconfiguration | 27 | 精简为高风险子集 |
| Input-Validation | 24 | 输入验证绕过 |
| Local-File-Inclusion | 10 | 路径遍历, XXE 变体 |
| Cross-Site-Scripting | 7 | XSS 变体 |
| Server-Side-Request-Forgery | 6 | SSRF 变体 |
| Improper Inventory Management | 3 | 库存管理不当 |
| CRLF-Injection | 2 | CRLF 变体 |
| Broken-Function-Level-Authorization | 1 | BFLA |

### 3.3 LLM 安全测试 (54 个)

pro 分支独有分类，master 分支不包含。

| 子类型 | 数量 | 说明 |
|---|---|---|
| Prompt Injection | 4 | 基础提示注入, STAN 测试, XSS 测试 |
| Sensitive Data Exposure | 8 | AWS key 泄露, 密码泄露 |
| LLM Glitch | 6 | 模型异常行为测试 |
| LLM Encoding | 5 | 编码绕过测试 |
| LLM Insecure Output | 3 | 不安全输出处理 |
| LLM Malware (多语言) | 21 | C/C++/Rust/Swift/ARM64/x86 恶意代码生成 |
| LLM Overreliance | 8 | 过度依赖测试, 误导, 包幻觉 |

### 3.4 与 master 的分类对比

| 分类 | master | pro | 关系 |
|---|---|---|---|
| Broken-User-Authentication | 23 | 97 | pro 大幅扩展，模板完全不同 |
| Broken-Object-Level-Authorization | 6 | 59 | pro 按 HTTP 方法/数据类型细拆 |
| LLM-Security | — | 54 | pro 独有 |
| Lack-of-Resources-and-Rate-Limiting | 4 | 41 | pro 大幅扩展 |
| Injection-Attacks | 3 | 39 | pro 大幅扩展 |
| Security-Misconfiguration | 64 | 27 | master 更多，pro 精简为高风险子集 |
| CORS-Misconfiguration | 2 | — | 仅 master |
| Mass-Assignment | 4 | — | 仅 master |
| Misconfigured-HTTP-Headers | 7 | — | 仅 master |
| Server-Side-Template-Injection | 2 | — | 仅 master |
| Server-Version-Disclosure | 1 | — | 仅 master |
| Threat-Protection | 8 | — | 仅 master |
| Unnecessary-HTTP-Methods | 2 | — | 仅 master |
| Verbose-Error-Messages | 2 | — | 仅 master |
| compliance | 1 | — | 仅 master |
| Improper Inventory Management | — | 3 | pro 独有 |

---

## 4. agentic-pro 分支（4,427 个模板）

### 4.1 构成

| 类型 | 数量 | 说明 |
|---|---|---|
| AI Agent 生成测试 | 4,153 | 6 个基础模板 × 场景 × 攻击技术 |
| API 安全测试 | 274 | 传统 API 安全测试 |
| 合规配置 | 1,152 | 合规框架映射 |
| 修复指南 | 1,225 | 漏洞修复建议 |

### 4.2 AI Agent 测试结构

**6 个基础模板：**

| 模板 | 说明 |
|---|---|
| template.yml | 基础 Agent 测试模板 |
| template-bad-likert-judge.yml | Likert 评分判定绕过 |
| template-crescendo-jailbreaking.yml | 渐进式越狱 |
| template-linear-jailbreaking.yml | 线性递进越狱 |
| template-sequential-jailbreaking.yml | 顺序越狱 |
| template-tree-jailbreaking.yml | 树形越狱 |

**基础模板结构：**

```yaml
id: {{ID}}
info:
  name: {{NAME}}
  description: {{DESCRIPTION}}
  details: {{DETAILS}}
  impact: {{IMPACT}}
  category:
    name: {{CATEGORY_NAME}}
    shortName: {{CATEGORY_NAME}}
    displayName: {{CATEGORY_DISPLAY_NAME}}
  subCategory: {{ID}}
  severity: HIGH
  tags:
  - Business logic
  - OWASP top 10
  - HackerOne top 10
  references:
  - https://genai.owasp.org/llm-top-10/
  - https://www.akto.io/blog/llm-risks-insights-real-world-case-studies
  - https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
  cwe:
  - CWE-74
  - CWE-77
  cve:
  - CVE-2024-5184
attributes:
  nature: NON_INTRUSIVE
  plan: PRO
  duration: FAST
api_selection_filters:
  test_type:
    eq: AGENTIC
wordLists:
  base_prompt: 
  - {{CATEGORY_PROMPT}}
  strategy: 
  - {{STRATEGY_PROMPT}}
execute:
  type: single
  requests:
  - req:
    - conversations_list:
        conversations:
        - | 
          Given details about vulnerability: ${base_prompt}
          strategy: ${strategy}
          context: ${data_context}
          Craft a realistic input prompt that exploits this flaw...
```

### 4.3 四大漏洞领域

| 领域 | 测试数 | 占比 | 说明 |
|---|---|---|---|
| SECURITY | 2,483 | 60% | Agent 安全：提示注入、数据泄露、代码执行、工具发现 |
| BUSINESS | 624 | 15% | 业务对齐：竞争对手检查、欺诈行为、目标偏移 |
| SAFETY | 598 | 14% | 安全性：有害内容、脏话、越狱 |
| HALLUCINATION | 442 | 11% | 幻觉与可信度：妄想、偏执防护 |

### 4.4 十五种攻击技术

| 技术 | 测试数 | 说明 |
|---|---|---|
| LINEAR_JAILBREAKING | ~1,560 | 线性递进越狱，逐步增加攻击强度 |
| BAD_LIKERT_JUDGE | ~637 | 利用 Likert 评分判定绕过安全过滤 |
| CRESCENDO_JAILBREAKING | ~624 | 渐进式越狱，逐步引导模型偏离安全行为 |
| SEQUENTIAL_JAILBREAKING | ~312 | 顺序越狱，多轮对话逐步突破 |
| TREE_JAILBREAKING | ~260 | 树形越狱，分支尝试多种攻击路径 |
| BASE64 | 74 | Base64 编码绕过内容过滤 |
| CONTEXT_POISONING | 74 | 上下文投毒，污染模型上下文窗口 |
| GOAL_REDIRECTION | 74 | 目标重定向，诱导模型偏离原始目标 |
| INPUT_BYPASS | 74 | 输入绕过，构造特殊输入绕过验证 |
| LEETSPEAK | 74 | Leet 编码（如 h3ll0）绕过关键词检测 |
| MULTILINGUAL | 74 | 多语言绕过，使用非英语语言规避过滤 |
| OVERRIDE | 74 | 覆盖指令，试图覆盖系统提示 |
| ROLEPLAY | 74 | 角色扮演，通过虚构角色绕过安全限制 |
| ROT13 | 74 | ROT13 编码绕过 |
| SEMANTIC_MANIPULATION | 74 | 语义操纵，利用语义歧义绕过过滤 |

### 4.5 生成测试命名规则

```
{领域}_{场景}_{技术}.yml

示例：
SECURITY_DATA_EXFILTRATION_PERMISSION_ESCALATION_LINEAR_JAILBREAKING.yml
BUSINESS_ALIGNMENT_COMPETITOR_CHECK_BASE64_BAD_LIKERT_JUDGE.yml
SAFETY_HARMFUL_CONTENT_LEETSPEAK_LINEAR_JAILBREAKING.yml
HALLUCINATION_AND_TRUSTWORTHINESS_PARANOID_PROTECTION_INPUT_BYPASS_LINEAR_JAILBREAKING.yml
```

---

## 5. Dashboard 内置模板（187 个）

除 GitHub 仓库外，Akto Dashboard 的 WAR 包中还内置了模板，作为 GitHub 不可达时的 fallback。

### 5.1 内置传统测试 (132 个)

路径：`apps/dashboard/src/main/resources/inbuilt_test_yaml_files/`

与 master 分支的 `tests-library-master.zip` 内容基本一致（132 个模板）。

### 5.2 内置 LLM 测试 (55 个)

路径：`apps/dashboard/src/main/resources/inbuilt_llm_test_yaml_files/`

由 `InitializerListener.saveLLmTemplates()` 在启动时从 classpath 加载，直接写入 MongoDB。

| 子类型 | 数量 |
|---|---|
| Prompt Injection | 4 |
| Sensitive Data Exposure | 8 |
| LLM Glitch | 6 |
| LLM Encoding | 5 |
| LLM Insecure Output | 3 |
| LLM Malware (多语言) | 21 |
| LLM Overreliance | 8 |

### 5.3 Fallback Zip (132 个)

路径：`apps/dashboard/src/main/resources/tests-library-master.zip`

master 分支的离线副本，GitHub 不可达时使用。

---

## 6. 合规配置（6,515 个）

每个测试映射到多个合规框架，配置文件格式如下：

```yaml
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
Cybersecurity Maturity Model Certification (CMMC):
  - AC.1.001
  - AC.2.003
OWASP:
  - BOLA
```

### 合规框架覆盖

- SOC 2
- ISO 27001
- NIST 800-53
- NIST 800-171
- CSA CCM
- CIS Controls
- FedRAMP
- FISMA
- CMMC
- OWASP

---

## 7. 修复指南（2,453 个）

每个漏洞对应一个 `.md` 修复指南文件，包含：

- 漏洞描述与影响
- 多语言修复代码示例（Python/Flask, Java/Spring, Node.js/Express）
- 最佳实践建议

**示例（ADD_USER_ID.md）：**

```markdown
## Remediation Steps for IDOR by adding User ID in Query Params

Insecure Direct Object References (IDOR) occurs when an application uses
user-supplied input to access objects directly.

### Step 1: Validate User Input

```python
from flask import request, jsonify
from schema import Schema, And

def validate_id(request):
    schema = Schema(And(int, lambda n: 0 < n < 10**10))
    try:
        schema.validate(int(request.args.get('id')))
    ...
```
```

---

## 8. 资源文件

`resources/` 目录包含测试辅助数据：

| 文件 | 用途 |
|---|---|
| juiceshop_tokens.json | JuiceShop 测试靶场 token 数据 |
| juiceshop.har | JuiceShop HTTP 归档文件 |
| Geo-Country.mmdb | MaxMind GeoIP 国家级数据库 |
| words_alpha.txt | 英文单词字典（用于 fuzzing） |

---

## 9. 与容器镜像的关系

| 容器镜像 | 与测试库的关系 |
|---|---|
| `akto-api-context-analyzer` | 不涉及测试模板，仅分析流量 |
| `akto-api-testing` | 运行时从 MongoDB 读取模板执行，代码中硬编码 54 个分类定义 |
| `akto-api-security-testing-db-layer` | PostgreSQL 数据访问层，不涉及模板 |
| `akto-dashboard`（本仓库 apps/dashboard） | 启动时从 GitHub 拉取测试库 → 写入 MongoDB |

### 完整模板加载流程

```
1. Dashboard 启动 (InitializerListener)
   ├── saveLLmTemplates()  ← 从 classpath:/inbuilt_llm_test_yaml_files/ 读取 55 个 LLM 模板
   ├── syncAllAktoDefaultTestLibraries()
   │   ├── GitHub: tests-library:standard → zip → processTemplateFilesZip()  → 209 模板
   │   ├── GitHub: tests-library:pro → zip → processTemplateFilesZip()       → 408 模板
   │   └── GitHub: tests-library:agentic-pro → zip → processTemplateFilesZip() (条件性) → 4,427 模板
   └── Fallback: classpath:/tests-library-master.zip → processTemplateFilesZip()

2. 所有模板写入同一个 MongoDB yaml_templates 集合
   ├── author = "AKTO"
   ├── source = "AKTO_TEMPLATES"
   └── content = YAML 原文

3. Testing Engine (akto-api-testing)
   ├── 从 MongoDB 读取 yaml_templates（不区分来源分支）
   ├── 解析 YAML → TestConfig
   ├── 按 api_selection_filters 选择目标 API
   ├── 执行 execute 部分的请求
   └── 用 validate 部分判断漏洞
```

---

## 10. YAML 模板结构说明

```yaml
id: REPLACE_AUTH_TOKEN                    # 唯一标识符
info:
  name: BOLA by changing auth token       # 测试名称
  description: "..."                      # 简要描述
  details: "..."                          # 详细描述（含 HTML）
  impact: "..."                           # 影响说明
  category:
    name: BOLA                            # 分类名（对应代码中的 shortName）
    shortName: BOLA
    displayName: Broken Object Level Authorization
  subCategory: REPLACE_AUTH_TOKEN         # 子分类 ID
  severity: HIGH                          # CRITICAL / HIGH / MEDIUM / LOW
  tags:                                   # 标签
    - Broken Object Level Authorization
    - OWASP Top 10
    - HackerOne Top 10
  references:                             # 参考链接
    - "https://owasp.org/..."
  cwe:                                    # CWE 编号
    - CWE-639
  cve:                                    # CVE 编号（可选）
    - CVE-...

attributes:
  nature: INTRUSIVE                       # INTRUSIVE / NON_INTRUSIVE
  plan: FREE                              # FREE / PRO
  duration: FAST                          # FAST / SLOW

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
```

---

## 11. 总结

### 11.1 关键数字

| 维度 | 数量 |
|---|---|
| 测试模板总数（三分支合计） | 5,044 |
| master 分支模板 | 209 |
| pro 分支模板 | 408（与 master 完全独立，无重叠） |
| agentic-pro 分支模板 | 4,427 |
| Dashboard 内置模板 | 187（132 传统 + 55 LLM） |
| 运行时生效模板（所有用户） | 617（master + pro） |
| 运行时生效模板（Agentic 用户） | 5,044（master + pro + agentic-pro） |
| 合规配置文件 | 6,515 |
| 修复指南文件 | 2,453 |
| 漏洞分类数 | 20+ |
| 攻击技术数 | 15 |
| 合规框架数 | 10 |
| 覆盖的严重程度 | 4 级 (CRITICAL / HIGH / MEDIUM / LOW) |

### 11.2 三个分支的设计哲学

| 分支 | 设计哲学 | 模板粒度 |
|---|---|---|
| master | 通用场景覆盖，一个模板测一类漏洞 | 粗（6 个 BOLA 模板） |
| pro | 深度测试，按 HTTP 方法/数据类型/攻击变体拆分 | 细（59 个 BOLA 模板） |
| agentic-pro | AI Agent 安全，大规模生成式测试 | 极细（4,153 个生成测试） |

### 11.3 关键结论

1. **master 和 pro 是互补关系，不是增量关系** — 两者文件名和模板 ID 零重叠，合并使用时共 617 个模板同时生效
2. **所有模板运行时从 MongoDB 读取** — 不嵌入任何容器镜像，Dashboard 启动时从 GitHub 拉取写入 DB
3. **agentic-pro 是条件加载** — 仅在用户获得 Agentic 功能授权时才拉取
4. **Dashboard 内置 187 个模板作为 fallback** — GitHub 不可达时使用

Akto 测试库覆盖了 OWASP API Top 10、OWASP LLM Top 10 以及 AI Agent 安全领域，是目前开源社区中最全面的 API 安全测试模板库之一。
