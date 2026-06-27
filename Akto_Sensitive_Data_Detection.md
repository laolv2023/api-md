# Akto 敏感数据识别功能详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto
> 核心代码：`libs/dao/src/main/java/com/akto/dto/type/` + `apps/api-runtime/src/main/java/com/akto/utils/RedactSampleData.java`

---

## 1. 功能概览

Akto 的敏感数据识别功能在 API 流量处理过程中自动发现和分类敏感参数（如信用卡号、SSN、邮箱、JWT 等），并对样本数据进行脱敏处理，防止敏感信息泄露到日志、Dashboard 或测试报告中。

### 核心能力

| 能力 | 说明 |
|---|---|
| **自动识别** | 通过正则匹配 + 字段名匹配，自动识别 API 参数中的敏感数据类型 |
| **内置类型** | 7 种内置敏感数据类型（EMAIL, SSN, CREDIT_CARD, VIN, PHONE_NUMBER, JWT, IP_ADDRESS） |
| **自定义类型** | 支持用户自定义数据类型规则（CustomDataType）和 Akto 数据类型（AktoDataType） |
| **PII 类型库** | 从 GitHub 远程加载 PII 类型定义（PAN 卡、医保号、国民保险号等） |
| **数据脱敏** | 对存储的样本数据自动脱敏，替换敏感值为 `****` |
| **敏感标记** | 在 SingleTypeInfo 中标记参数是否敏感，用于 Dashboard 展示和告警 |
| **多位置支持** | 识别 URL 参数、请求头、请求体、响应头、响应体中的敏感数据 |

---

## 2. 架构

### 2.1 执行模块

敏感数据识别**由 `api-runtime` 模块执行**。核心逻辑代码在 `libs/dao`（共享库）中，但调用入口在 `api-runtime`。

**调用链路：**

```
api-runtime (Runtime Analyzer)
  │
  ├── Main.java
  │   └── 消费 Kafka → HttpCallParser.parseKafkaMessage() 解析消息
  │
  ├── HttpCallParser.syncFunction()               ← 入口
  │   └── 调用 APICatalogSync.syncWithDb()
  │
  ├── APICatalogSync.java                         ← 核心调度
  │   ├── 创建 KeyTypes 对象（每个参数一个）
  │   ├── 调用 KeyTypes.findSubType()              ← 敏感类型识别
  │   │   └── 检查 7 种内置类型 + CustomDataType + AktoDataType
  │   ├── 调用 RedactSampleData.redactIfRequired()  ← 数据脱敏
  │   │   └── 遍历 JSON/XML，替换敏感值为 ****
  │   └── 调用 AktoPolicyNew.process()             ← 策略执行
  │       └── AuthPolicy / SetFieldPolicy          ← 认证检测 + 字段标记
  │
  └── 写入 MongoDB:
      ├── single_type_info (含 subType + isSensitive)
      ├── sensitive_param_info
      └── filter_sample_data (脱敏后的样本)
```

**各组件职责与代码位置：**

| 组件 | 文件 | 所属模块 | 职责 |
|---|---|---|---|
| `KeyTypes.findSubType()` | `libs/dao/.../type/KeyTypes.java` | dao (共享库) | 正则匹配识别敏感类型 |
| `APICatalogSync` | `apps/api-runtime/.../APICatalogSync.java` | **api-runtime** | 调用 findSubType + 调用脱敏 |
| `RedactSampleData` | `apps/api-runtime/.../utils/RedactSampleData.java` | **api-runtime** | 数据脱敏实现 |
| `AktoPolicyNew.process()` | `apps/api-runtime/.../policies/AktoPolicyNew.java` | **api-runtime** | 认证检测 + 字段标记 |
| `AuthPolicy` | `apps/api-runtime/.../policies/AuthPolicy.java` | **api-runtime** | 认证类型识别 |
| `HttpCallParser` | `apps/api-runtime/.../parsers/HttpCallParser.java` | **api-runtime** | 流量解析入口 |

**部署模式对应：**

| 部署模式 | 执行方式 |
|---|---|
| **社区版** | Dashboard 内嵌 api-runtime 库 → `RuntimeListener` 创建 `HttpCallParser` → 处理导入流量时执行 |
| **企业版** | api-runtime 独立容器 → 消费 Kafka 实时流量 → 每条消息都执行 |
| **api-analyser** | ❌ 不执行敏感数据识别（只做参数计数，调用 `HttpCallParser.parseKafkaMessage()` 但不调用 `syncFunction()`） |

> **关键区分**：api-analyser 虽然也依赖 api-runtime 的 JAR，但只调用了 `parseKafkaMessage()`（解析消息），没有调用 `syncFunction()`（执行识别和脱敏）。敏感数据识别的全部流程只在 api-runtime 中触发。

### 2.2 处理流程

```
API 流量 (Kafka/HAR/Postman)
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  HttpCallParser.syncFunction()                           │
│                                                         │
│  对每条流量的每个参数:                                     │
│    1. 提取参数值                                          │
│    2. KeyTypes.findSubType(value, key, paramId)          │
│       ├── 检查 CustomDataType（用户自定义，最高优先级）      │
│       ├── 检查内置 SubType（信用卡、JWT、电话号码等）        │
│       ├── 检查 patternToSubType（正则匹配）                │
│       │   ├── EMAIL: ^[a-zA-Z0-9_+&*-]+@...$             │
│       │   ├── SSN: ^\d{3}-\d{2}-\d{4}$                   │
│       │   ├── URL: ^(https?|ftps?|gopher|...)://...$     │
│       │   └── UUID: ^[A-Z0-9]{8}-...$                    │
│       ├── 检查 AktoDataType（远程 PII 类型库）              │
│       │   ├── general.json (内置 PII)                    │
│       │   ├── fintech.json (金融行业 PII)                 │
│       │   └── filetypes.json (文件类型)                   │
│       └── 返回 SubType（含 isSensitive 标记）              │
│    3. 记录到 SingleTypeInfo                               │
│       ├── subType: 识别出的类型                            │
│       ├── isSensitive: 是否敏感                            │
│       ├── examples: 敏感参数的样本（用于审计）               │
│       └── values: 参数值集合（CappedSet，最多 100 个）      │
└─────────────────────────────────────────────────────────┘
    │
    ├──→ MongoDB: single_type_info 集合（存储类型信息）
    ├──→ MongoDB: sensitive_param_info 集合（存储敏感参数清单）
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  RedactSampleData.redact()                               │
│                                                         │
│  存储样本前，对敏感数据脱敏:                                │
│    1. 遍历 JSON 树的每个字段                               │
│    2. 对每个值调用 KeyTypes.findSubType()                  │
│    3. 如果 isRedacted(subType) == true → 替换为 "****"     │
│    4. 支持 JSON / XML / GraphQL / Cookie / 查询参数        │
│    5. 支持"全部脱敏"和"仅敏感字段脱敏"两种模式               │
└─────────────────────────────────────────────────────────┘
```

---

## 3. 内置敏感数据类型（7 种）

定义位置：`libs/dao/src/main/java/com/akto/dto/type/SingleTypeInfo.java`

| 类型 | 正则/验证方式 | 敏感 | 说明 |
|---|---|---|---|
| **EMAIL** | `^[a-zA-Z0-9_+&*-]+@...$` | ✅ | 电子邮箱地址 |
| **SSN** | `^\d{3}-\d{2}-\d{4}$` | ✅ | 美国社会安全号 |
| **CREDIT_CARD** | Luhn 算法校验 | ✅ | 信用卡号（Visa/MasterCard/Amex 等） |
| **VIN** | 车辆识别号验证 | ✅ | 车辆识别号 |
| **PHONE_NUMBER** | Google libphonenumber | ✅ | 电话号码（国际格式） |
| **JWT** | `^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$` | ❌ | JSON Web Token |
| **IP_ADDRESS** | IPv4/IPv6 正则 | ❌ | IP 地址 |

> "敏感"标记决定是否在 Dashboard 中高亮显示和是否收集样本值。JWT 和 IP_ADDRESS 被标记为非敏感（但仍会被识别和分类）。

### 其他内置类型（非敏感）

| 类型 | 正则 | 说明 |
|---|---|---|
| **URL** | `^(https?|ftps?|gopher|telnet|nntp)://...` | URL 地址 |
| **UUID** | `^[A-Z0-9]{8}-[A-Z0-9]{4}-...$` | UUID 标识符 |
| **INTEGER_32** | 数字判断 | 32 位整数 |
| **INTEGER_64** | 数字判断 | 64 位长整数 |
| **FLOAT** | 数字判断 | 浮点数 |
| **BOOLEAN** | 类型判断 | 布尔值 |
| **NULL** | null 检查 | 空值 |
| **GENERIC** | 默认 | 通用字符串 |
| **OTHER** | 默认 | 其他类型 |

---

## 4. 远程 PII 类型库（3 个文件）

定义位置：`apps/dashboard/src/main/java/com/akto/listener/InitializerListener.java` L2984-3000

Dashboard 启动时从 GitHub 加载 3 个 PII 类型定义文件，存入 MongoDB `pii_sources` 集合：

### 4.1 general.json

- **来源**：`https://raw.githubusercontent.com/akto-api-security/pii-types/master/general.json`
- **仓库**：`akto-api-security/pii-types`（独立仓库）
- **内容**：通用 PII 类型定义

### 4.2 fintech.json

- **来源**：`https://raw.githubusercontent.com/akto-api-security/akto/master/pii-types/fintech.json`
- **仓库**：`akto-api-security/akto`（主仓库 `pii-types/` 目录）
- **内容**：金融行业 PII 类型

当前包含的类型示例：

```json
{
  "name": "PAN CARD",
  "regexPattern": "[A-Z]{5}[0-9]{4}[A-Z]{1}",
  "tagsLists": ["PII", "FINANCE"],
  "dataTypePriority": "CRITICAL"
}
{
  "name": "US Medicare Health Insurance Claim Number",
  "regexPattern": "[0-9]{9}[A-Za-z]{1}[0-9a-zA-Z]?",
  "tagsLists": ["PII", "HEALTHCARE"],
  "dataTypePriority": "HIGH"
}
{
  "name": "Indian Unique Health Identification",
  "regexPattern": "[0-9]{14}",
  "tagsLists": ["HEALTHCARE", "PII"],
  "dataTypePriority": "HIGH"
}
{
  "name": "United Kingdom National Insurance Number",
  "regexPattern": "...",
  "tagsLists": ["PII"],
  "dataTypePriority": "HIGH"
}
```

### 4.3 filetypes.json

- **来源**：`https://raw.githubusercontent.com/akto-api-security/akto/master/pii-types/filetypes.json`
- **内容**：文件类型识别

```json
{
  "name": "IMAGE",
  "regexPattern": "([^\\s]+(\\.(?i)(jpe?g|png|svg))$)",
  "tagsLists": ["PII"],
  "dataTypePriority": "MEDIUM"
}
{
  "name": "DATA FILE",
  "regexPattern": "([^\\s]+(\\.(?i)(pdf|js|css|woff|txt))$)",
  "tagsLists": ["RESOURCE"],
  "dataTypePriority": "MEDIUM"
}
```

### 4.4 PII 类型配置结构

每个 PII 类型定义包含以下字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | String | 类型名称（唯一标识） |
| `regexPattern` | String | 正则表达式 |
| `sensitive` | boolean | 是否敏感 |
| `onKey` | boolean | 是否匹配字段名（key）而非值 |
| `active` | boolean | 是否启用 |
| `tagsLists` | List | 标签列表（如 PII, FINANCE, HEALTHCARE） |
| `dataTypePriority` | String | 优先级（CRITICAL / HIGH / MEDIUM / LOW） |

---

## 5. 自定义数据类型

### 5.1 AktoDataType

定义位置：`libs/dao/src/main/java/com/akto/dto/AktoDataType.java`

用户可通过 Dashboard 创建自定义数据类型，存储在 MongoDB `akto_data_types` 集合：

| 字段 | 说明 |
|---|---|
| `name` | 类型名称 |
| `sensitiveAlways` | 是否始终敏感 |
| `sensitivePosition` | 敏感位置（REQUEST / RESPONSE / BOTH） |
| `redacted` | 是否需要脱敏 |
| `keyConditions` | 字段名匹配条件 |
| `valueConditions` | 值匹配条件 |
| `operator` | 条件组合方式（AND / OR） |
| `categoriesList` | 分类标签 |
| `dataTypePriority` | 优先级 |
| `inactive` | 是否禁用 |

### 5.2 CustomDataType

定义位置：`libs/dao/src/main/java/com/akto/dto/CustomDataType.java`

用户自定义数据类型，存储在 MongoDB `custom_data_types` 集合，**优先级最高**（在内置类型之前匹配）。

### 5.3 匹配优先级

```
1. CustomDataType（用户自定义，最高优先级）
   ↓ 不匹配
2. CREDIT_CARD（Luhn 算法）
   ↓ 不匹配
3. patternToSubType 正则匹配（EMAIL, SSN, URL, UUID）
   ↓ 不匹配
4. AktoDataType（远程 PII 类型库）
   ↓ 不匹配
5. JWT / PHONE_NUMBER / IP_ADDRESS / VIN（专用验证器）
   ↓ 不匹配
6. GENERIC（默认字符串类型）
```

---

## 6. 数据脱敏机制

### 6.1 两种脱敏模式

| 模式 | 触发条件 | 行为 |
|---|---|---|
| **全量脱敏** | `redactAll == true`（账户级或 API Collection 级启用） | 所有参数值替换为 `****`，包括 Cookie、查询参数、请求头 |
| **敏感字段脱敏** | `redactAll == false`（默认） | 仅 `isRedacted(subType) == true` 的字段替换为 `****` |

### 6.2 脱敏覆盖范围

| 数据位置 | 脱敏方式 |
|---|---|
| **JSON 请求体** | 递归遍历 JSON 树，替换敏感叶子节点值 |
| **JSON 响应体** | 同上 |
| **XML 请求/响应体** | 正则匹配 `<tag>value</tag>` 和 `attr="value"`，替换敏感内容 |
| **GraphQL** | 修改 static arguments 的值为 `****`（保留 query 结构） |
| **HTTP 请求头** | 遍历所有头，敏感头替换为 `****`；Cookie 替换每个值为 `****` |
| **HTTP 响应头** | 同上 |
| **URL 查询参数** | 全量模式下所有参数值替换为 `****` |
| **来源 IP** | 全量模式下替换为 `****` |

### 6.3 脱敏流程

```java
// RedactSampleData.java
public static String redact(HttpResponseParams params, boolean redactAll) {
    // 1. 处理响应头
    handleHeaders(responseHeaders, redactAll);
    // 2. 处理请求头
    handleHeaders(requestHeaders, redactAll);
    // 3. 处理响应体（JSON）
    change(null, responseNode, "****", redactAll, false);
    // 4. 处理请求体（JSON）
    change(null, requestNode, "****", redactAll, false);
    // 5. 处理 URL 查询参数
    handleQueryParams(url, redactAll, "****");
    // 6. 处理 XML（如果有）
    redactXmlWithRegex(xmlPayload, "****", redactAll);
    // 7. 处理来源 IP
    if (redactAll) params.setSourceIP("****");
}
```

### 6.4 JSON 遍历逻辑

```java
public static void change(String parentName, JsonNode node, String newValue, boolean redactAll, ...) {
    if (node.isArray()) {
        for (int i = 0; i < node.size(); i++) {
            if (node.get(i).isValueNode()) {
                if (redactAll) {
                    node.set(i, "****");          // 全量替换
                } else {
                    SubType subType = KeyTypes.findSubType(value, parentName, null);
                    if (SingleTypeInfo.isRedacted(subType.getName())) {
                        node.set(i, "****");      // 仅替换敏感值
                    }
                }
            }
        }
    } else {
        // 对象：遍历字段名
        for (String field : node.fieldNames()) {
            if (node.get(field).isValueNode()) {
                if (redactAll) {
                    node.put(field, "****");
                } else {
                    SubType subType = KeyTypes.findSubType(value, field, null);
                    if (SingleTypeInfo.isRedacted(subType.getName())) {
                        node.put(field, "****");
                    }
                }
            }
        }
    }
}
```

---

## 7. 数据存储

### 7.1 SingleTypeInfo

每个 API 参数的类型信息存储在 `single_type_info` MongoDB 集合：

```json
{
  "_id": {
    "url": "/api/users/{id}",
    "method": "GET",
    "responseCode": 200,
    "isHeader": false,
    "param": "user#email",
    "subType": "EMAIL",
    "apiCollectionId": 1,
    "isUrlParam": false
  },
  "subType": "EMAIL",
  "isSensitive": true,
  "examples": ["raw_sample_with_email"],    // 敏感参数的原始样本（用于审计）
  "values": {"alice@example.com": 1, "bob@example.com": 1},  // 值集合 + 计数
  "uniqueCount": 0,                         // Context Analyzer 更新
  "publicCount": 0,                         // Context Analyzer 更新
  "lastSeen": 1719500000
}
```

### 7.2 SensitiveParamInfo

敏感参数清单存储在 `sensitive_param_info` 集合：

```json
{
  "url": "/api/users/{id}",
  "method": "GET",
  "responseCode": 200,
  "isHeader": false,
  "param": "user#email",
  "apiCollectionId": 1,
  "sensitive": true,
  "sampleDataSaved": true,
  "collectionIds": [1]
}
```

### 7.3 AktoDataType

自定义数据类型存储在 `akto_data_types` 集合。

### 7.4 PIISource

PII 类型来源存储在 `pii_sources` 集合：

```json
{
  "_id": "A",
  "fileUrl": "https://raw.githubusercontent.com/akto-api-security/pii-types/master/general.json",
  "fileName": "general.json",
  "timestamp": 1638571050,
  "lastSynced": 1719500000,
  "config": {...},
  "active": true
}
```

---

## 8. 敏感数据识别的触发时机

| 触发场景 | 说明 | 脱敏行为 |
|---|---|---|
| **实时流量处理** | api-runtime 消费 Kafka 流量时 | 自动识别类型 + 按配置脱敏后存储 |
| **HAR 文件导入** | 社区版用户上传 HAR 文件 | 识别 + 脱敏 |
| **Postman 导入** | 通过 Postman 集成导入 | 识别 + 脱敏 |
| **Burp Suite 集成** | Burp 流量导入 | 识别 + 脱敏 |
| **OpenTelemetry** | OTel 数据导入 | 识别 + 脱敏 |
| **PCAP 文件** | 原始抓包文件 | **不脱敏**（`Source.PCAP` 直接返回原文） |

---

## 9. 算法分析：是否使用了 ML？

**没有使用 ML。** 敏感数据识别全部基于：

| 方法 | 说明 |
|---|---|
| **正则表达式匹配** | EMAIL、SSN、UUID、URL、PAN 卡、医保号等 |
| **Luhn 算法** | 信用卡号校验（非 ML，是数学算法） |
| **Google libphonenumber** | 电话号码验证（库函数，非 ML） |
| **字段名匹配** | 通过 `keyConditions` 匹配参数名（如 `password`、`ssn`） |
| **值匹配** | 通过 `valueConditions` 匹配参数值模式 |

没有训练模型、没有推理、没有聚类/分类/异常检测。全部是规则匹配。

---

## 10. 配置与管理

### 10.1 Dashboard UI 操作

| 操作路径 | 功能 |
|---|---|
| **Settings → Data Types** | 创建/编辑/禁用自定义数据类型 |
| **API Inventory → Sensitive Data** | 查看识别到的敏感参数 |
| **API Collection → Settings → Redact** | 启用/禁用 API Collection 级脱敏 |
| **Settings → PII Sources** | 管理 PII 类型来源 |

### 10.2 环境变量

| 变量 | 说明 |
|---|---|
| 账户级 `redact` 设置 | 通过 AccountSettings 控制 |
| API Collection 级 `redact` 设置 | 通过 ApiCollection 配置控制 |

---

## 11. 局限性

### 11.1 识别能力

- **仅基于正则和字段名** — 无法识别语义层面的敏感数据（如非标准格式的身份证号）
- **无上下文感知** — 同一个值在不同上下文中可能有不同敏感性，但系统不区分
- **大消息跳过** — 超过 8192 字符的消息跳过 SubType 检查，只做基本类型判断
  ```java
  if (rawMessage != null && rawMessage.length() > 8192) {
      subType = getBasicSubType(object);  // 跳过敏感检测
  }
  ```

### 11.2 脱敏能力

- **替换为固定值** — 只能替换为 `****`，不支持部分遮罩（如 `4321-****-****-1234`）
- **XML 脱敏较粗糙** — 使用正则而非 XML 解析器，可能误处理嵌套标签
- **GraphQL 限制** — 全量脱敏时保留 query 字段，但其他字段全部替换
- **二进制数据** — 不处理二进制内容（图片、PDF 等）

### 11.3 PII 类型库

- **默认全部 inactive** — fintech.json 和 filetypes.json 中的类型默认 `active: false`，需用户手动启用
- **无自动更新** — PII 类型库不会自动同步最新版本，需 Dashboard 定时触发

---

## 12. 总结

| 维度 | 值 |
|---|---|
| 内置敏感类型 | 7 种（EMAIL, SSN, CREDIT_CARD, VIN, PHONE_NUMBER, JWT, IP_ADDRESS） |
| 内置非敏感类型 | 5+ 种（URL, UUID, INTEGER_32, INTEGER_64, FLOAT, BOOLEAN, NULL, GENERIC, OTHER） |
| 远程 PII 类型库 | 3 个文件（general.json, fintech.json, filetypes.json） |
| 自定义类型 | 支持（AktoDataType + CustomDataType） |
| 脱敏模式 | 2 种（全量脱敏 / 仅敏感字段脱敏） |
| 脱敏覆盖 | JSON / XML / GraphQL / Cookie / 查询参数 / 请求头 / IP |
| 匹配方法 | 正则 + Luhn 算法 + libphonenumber + 字段名匹配 |
| 是否使用 ML | ❌ 否，全部基于规则匹配 |
| 存储集合 | single_type_info / sensitive_param_info / akto_data_types / pii_sources / custom_data_types |
