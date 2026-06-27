# Akto api-analyser (Context Analyzer) 详细分析

> 分析日期：2026-06-27
> 仓库：https://github.com/akto-api-security/akto/tree/master/apps/api-analyser
> 代码文件：`Main.java` (135 行) + `ResourceAnalyser.java` (337 行) = 472 行
> ECR 镜像：`aktosecurity/akto-api-context-analyzer:latest`

---

## 1. 功能定位

Context Analyzer 是 Akto 的**参数级上下文统计引擎**，通过分析历史 API 流量，统计每个端点每个参数的值分布，判断参数是否代表私有资源。这些统计数据被安全测试引擎用于**降低误报率**。

### 核心问题

BOLA（越权访问）测试的逻辑是：用攻击者的 token 重放请求，看能否访问别人的资源。但 `/api/health`、`/api/public/docs` 等公开接口换什么 token 都返回 200，直接测试会产生大量误报。

### 解决方案

Context Analyzer 通过统计回答：**这个端点的参数里有没有"私有资源"？** 测试引擎只对有私有资源的端点执行越权测试。

---

## 2. 数据流全景

```
                    ┌─────────────────────────────────────────────────┐
                    │              数据来源                             │
                    │                                                 │
                    │  Kafka topic: akto.central (正则: .*central)    │
                    │  Broker: kafka1:19092                           │
                    │  消息格式: HttpCallParser.parseKafkaMessage()    │
                    │  内容: HTTP 请求/响应 (含 headers, body, url)    │
                    └──────────────────────┬──────────────────────────┘
                                           │
                                           ▼
                    ┌─────────────────────────────────────────────────┐
                    │           api-analyser 处理                      │
                    │                                                 │
                    │  Main.java                                      │
                    │  ├── KafkaConsumer 消费消息                      │
                    │  ├── 按 accountId 维护 ResourceAnalyser 实例     │
                    │  └── HttpResponseParams → resourceAnalyser      │
                    │                                                 │
                    │  ResourceAnalyser.java                          │
                    │  ├── 1. URL 模板匹配 (matchWithUrlTemplate)     │
                    │  ├── 2. URL 路径参数提取 (tokenize)             │
                    │  ├── 3. 请求体参数展平 (JSONUtils.flatten)       │
                    │  ├── 4. 参数值统计 (Bloom Filter)               │
                    │  │   ├── duplicateCheckerBF: 去重               │
                    │  │   └── valuesBF: 公开/私有判定                │
                    │  └── 5. 累积到 countMap (内存)                  │
                    │                                                 │
                    │  触发同步条件:                                   │
                    │  ├── countMap.size() > 200,000                 │
                    │  └── 距上次同步 > 120 秒                         │
                    └──────────────────────┬──────────────────────────┘
                                           │
                                           ▼
                    ┌─────────────────────────────────────────────────┐
                    │              数据去处                             │
                    │                                                 │
                    │  MongoDB: single_type_info 集合                  │
                    │  操作: bulkWrite (UpdateManyModel)               │
                    │  upsert: false (只更新已存在的记录)              │
                    │                                                 │
                    │  更新字段:                                       │
                    │  ├── uniqueCount: $inc (唯一值计数)             │
                    │  └── publicCount: $inc (公开值计数)             │
                    └─────────────────────────────────────────────────┘
```

---

## 3. 消费数据来源

### 3.1 Kafka 配置

```java
// Main.java
String centralBrokerIp = "kafka1:19092";
String groupIdConfig = "analyzer-group-config";
int maxPollRecordsConfig = 1000;  // DEFAULT_CENTRAL_KAFKA_MAX_POLL_RECORDS_CONFIG

Properties properties = Utils.configProperties(centralBrokerIp, groupIdConfig, maxPollRecordsConfig);
main.consumer = new KafkaConsumer<>(properties);

// 订阅所有以 "central" 结尾的 topic
main.consumer.subscribe(Pattern.compile(".*central"));
```

| 配置项 | 值 | 说明 |
|---|---|---|
| Broker 地址 | `kafka1:19092` | 硬编码（Enterprise 部署的内部 Kafka） |
| Topic 订阅 | `.*central` (正则) | 匹配 `akto.central` 等主题 |
| Consumer Group | `analyzer-group-config` | 固定组名 |
| Max Poll Records | 1000 | 每次最多拉取 1000 条 |
| Poll 超时 | 10000ms | 10 秒 |
| Commit | `commitSync()` | 同步提交 offset |

### 3.2 消息格式

每条 Kafka 消息是一个 JSON 字符串，由 `HttpCallParser.parseKafkaMessage()` 解析为 `HttpResponseParams`：

```java
HttpResponseParams httpResponseParams = HttpCallParser.parseKafkaMessage(r.value());
```

`HttpResponseParams` 包含：

| 字段 | 说明 | 示例 |
|---|---|---|
| `statusCode` | HTTP 状态码 | 200 |
| `requestParams.method` | 请求方法 | GET / POST |
| `requestParams.url` | 完整 URL（含查询参数） | `/api/users/12345?expand=profile` |
| `requestParams.headers` | 请求头 | `{"host": ["api.example.com"], "x-forwarded-for": ["192.168.1.1"]}` |
| `requestParams.body` | 请求体 | `{"user": {"name": "Alice", "company": "Acme"}}` |
| `accountId` | 租户 ID | `1000000` |
| `source` | 流量来源 | MIRRORING / HAR / POSTMAN |

### 3.3 数据来源链路

```
API 流量采集层
  ├── AWS VPC Traffic Mirroring → akto-gateway → Kafka (akto.api.logs)
  ├── HAR 文件上传 → api-runtime 解析 → Kafka
  ├── Postman 导入 → api-runtime 解析 → Kafka
  └── Burp Suite 集成 → api-runtime 解析 → Kafka
                    │
                    ▼
  api-runtime 处理后转发到中央 Kafka:
  topic = akto.central
                    │
                    ▼
  api-analyser 消费 akto.central
```

> **注意**：api-analyser 不直接消费原始流量，而是消费 api-runtime 处理后的数据。这意味着 api-runtime 已经完成了 URL 模板化、API 集合归类等工作，api-analyser 在此基础上做参数统计。

---

## 4. 生产数据去处

### 4.1 MongoDB 写入

```java
// ResourceAnalyser.syncWithDb()
List<WriteModel<SingleTypeInfo>> dbUpdates = getDbUpdatesForSingleTypeInfo();
BulkWriteResult bulkWriteResult = SingleTypeInfoDao.instance.getMCollection().bulkWrite(dbUpdates);
```

| 属性 | 值 |
|---|---|
| **MongoDB 集合** | `single_type_info` |
| **操作类型** | `bulkWrite` (批量写) |
| **写模型** | `UpdateManyModel` (更新匹配的所有文档) |
| **Upsert** | `false` (不创建新文档，只更新已存在的) |

### 4.2 更新的字段

```java
// getDbUpdatesForSingleTypeInfo()
Bson update = Updates.combine(
    Updates.inc(SingleTypeInfo._UNIQUE_COUNT, singleTypeInfo.getUniqueCount()),
    Updates.inc(SingleTypeInfo._PUBLIC_COUNT, singleTypeInfo.getPublicCount())
);
```

只更新两个字段，使用 `$inc` 原子递增：

| 字段 | MongoDB 字段名 | 说明 |
|---|---|---|
| `uniqueCount` | `uniqueCount` | 该参数出现的不同值的数量（私有值） |
| `publicCount` | `publicCount` | 该参数被判定为"公开"的值的数量 |

### 4.3 过滤条件

```java
Bson filter = SingleTypeInfoDao.createFiltersWithoutSubType(singleTypeInfo);
```

匹配条件（不含子类型）：
- `apiCollectionId` — API 集合 ID
- `url` — 模板化 URL（如 `api/books/INTEGER`）
- `method` — HTTP 方法
- `param` — 参数名（如 `user_id`、`user#name`）
- `isHeader` — 是否为请求头参数
- `isUrlParam` — 是否为 URL 路径参数

> **关键**：`upsert: false` 意味着 api-analyser **不会创建新的 SingleTypeInfo 记录**。这些记录由 api-runtime 在处理流量时创建。api-analyser 只在已存在的记录上递增计数。

### 4.4 SingleTypeInfo 文档结构（完整）

```json
{
  "_id": ObjectId("..."),
  "apiCollectionId": 0,
  "url": "api/books/INTEGER",
  "method": "GET",
  "param": "user_id",
  "isHeader": false,
  "isUrlParam": true,
  "responseCode": -1,
  "subType": "GENERIC",
  "uniqueCount": 1547,      ← api-analyser 更新
  "publicCount": 3,          ← api-analyser 更新
  "count": 5000,             ← api-runtime 更新
  "values": ["12345", "67890", ...],  ← api-runtime 更新（CappedSet）
  "domain": "ENUM",
  "maxValue": 99999,
  "minValue": 1
}
```

---

## 5. 核心算法详解

### 5.1 双 Bloom Filter 架构

```java
// 构造函数
public ResourceAnalyser(
    int duplicateCheckerBfSize,      // 300,000,000 (3 亿)
    double duplicateCheckerBfFpp,    // 0.01 (1% 误判率)
    int valuesBfSize,                // 100,000,000 (1 亿)
    double valuesBfFpp               // 0.01 (1% 误判率)
)
```

| Bloom Filter | 容量 | 误判率 | 用途 | 内存占用 |
|---|---|---|---|---|
| `duplicateCheckerBF` | 3 亿 | 1% | 去重：同一用户+同一参数+同一值只计一次 | ~360 MB |
| `valuesBF` | 1 亿 | 1% | 公开/私有判定：值是否跨用户出现 | ~120 MB |

### 5.2 参数值统计流程

```
收到一条 HTTP 请求/响应
    │
    ▼
1. 检查状态码 (只处理 2xx)
    │  if (statusCode < 200 || statusCode >= 300) return;
    ▼
2. 提取用户标识 (x-forwarded-for 头)
    │  userId = headers.get("x-forwarded-for").get(0)
    ▼
3. 确定 API 集合 ID
    │  findTrueApiCollectionId(apiCollectionId, hostName, source)
    ▼
4. URL 模板匹配
    │  matchWithUrlStatic() → 精确匹配
    │  matchWithUrlTemplate() → 模板匹配 (如 /api/books/2 → api/books/INTEGER)
    ▼
5. 提取参数值
    │  a. URL 路径参数: urlTemplate.getTokens() → 提取 INTEGER/STRING 段
    │  b. 请求体参数: JSONUtils.flatten(payload) → 展平嵌套 JSON
    │  c. (请求头参数: 代码已注释，暂不处理)
    ▼
6. 对每个参数值执行 analysePayload()
    │
    ├── 6a. 去重检查: duplicateCheckerBF
    │       key = userId + "$" + combinedUrl + "$" + paramName + "$" + paramValue
    │       if (BF.put(key) == false) → 已存在，跳过
    │
    ├── 6b. 迁移检查: valuesBF (mightContain)
    │       key = combinedUrl + "$" + paramName + "$" + paramValue + "$moved"
    │       if (已迁移) → 跳过
    │
    ├── 6c. 公开值检查: valuesBF (mightContain)
    │       key = combinedUrl + "$" + paramName + "$" + paramValue
    │       if (值已存在):
    │           ├── 标记为迁移: valuesBF.put(key + "$moved")
    │           └── publicCount++ (从 unique → public 迁移)
    │       else:
    │           ├── 加入 BF: valuesBF.put(key)
    │           └── uniqueCount++ (新的唯一值)
    ▼
7. 累积到 countMap (内存)
    │  countMap.computeIfAbsent(paramId.composeKey(), ...)
    ▼
8. 触发同步 (120s 或 20 万条)
    │  syncWithDb() → bulkWrite 到 MongoDB
```

### 5.3 "私有"与"公开"的判定逻辑

这是核心算法，用一个具体例子说明：

**场景**：端点 `/api/users/{user_id}/orders`，参数 `user_id`

| 时间 | 用户 | user_id 值 | 操作 | uniqueCount | publicCount |
|---|---|---|---|---|---|
| t1 | Alice (IP1) | 12345 | 新值 → unique++ | 1 | 0 |
| t2 | Bob (IP2) | 12345 | 值已存在 → 迁移到 public | 0 | 1 |
| t3 | Alice (IP1) | 12345 | 重复（同一用户同一值）→ 跳过 | 0 | 0 |
| t4 | Charlie (IP3) | 67890 | 新值 → unique++ | 1 | 0 |
| t5 | Bob (IP2) | 67890 | 值已存在 → 迁移到 public | 0 | 1 |
| t6 | Alice (IP1) | 99999 | 新值 → unique++ | 1 | 0 |

**最终**：`uniqueCount=1, publicCount=2` → `user_id` 被判定为**私有参数**（多个不同用户使用不同的值，但值有重叠 → 私有资源标识符）

**对比**：端点 `/api/health`，参数 `version`

| 时间 | 用户 | version 值 | 操作 | uniqueCount | publicCount |
|---|---|---|---|---|---|
| t1 | Alice | v1 | 新值 → unique++ | 1 | 0 |
| t2 | Bob | v1 | 迁移 → public++ | 0 | 1 |
| t3 | Charlie | v1 | 迁移（已标记）→ 跳过 | 0 | 0 |

**最终**：`uniqueCount=0, publicCount=1` → `version` 被判定为**公开参数**（所有用户用同一个值）

### 5.4 迁移机制

"迁移"（moved）是核心概念：一个值最初是 unique 的，当另一个用户也使用相同值时，它从 `unique` 迁移到 `public`：

```
值首次出现 (用户A):
  uniqueCount++
  valuesBF.put(key)

值第二次出现 (用户B，不同用户):
  valuesBF.mightContain(key) == true
  → publicCount++
  → valuesBF.put(key + "$moved")  ← 标记为已迁移

值第三次出现 (用户C):
  valuesBF.mightContain(key + "$moved") == true
  → 跳过 (已迁移，不再计数)
```

---

## 6. 使用方式

### 6.1 部署

Context Analyzer 是 **Enterprise Only** 模块，社区版不含。

**Docker 部署：**
```bash
docker run -d \
  -e AKTO_MONGO_CONN=mongodb://mongo:27017 \
  -e AKTO_CURRENT_INSTANCE_IP=10.0.0.5 \
  aktosecurity/akto-api-context-analyzer:latest
```

**环境变量：**

| 变量 | 必需 | 说明 |
|---|---|---|
| `AKTO_MONGO_CONN` | ✅ | MongoDB 连接串 |
| `AKTO_CURRENT_INSTANCE_IP` | ❌ | 当前实例 IP，写入 AccountSettings.centralKafkaIp |

### 6.2 启动流程

```java
// 1. 读取环境变量
String mongoURI = System.getenv("AKTO_MONGO_CONN");
String currentInstanceIp = System.getenv("AKTO_CURRENT_INSTANCE_IP");

// 2. 初始化 MongoDB 连接
DaoInit.init(new ConnectionString(mongoURI));
Context.accountId.set(1_000_000);

// 3. 更新 AccountSettings 中的 centralKafkaIp
if (currentInstanceIp != null) {
    AccountSettingsDao.instance.updateOne(
        AccountSettingsDao.generateFilter(),
        Updates.set(AccountSettings.CENTRAL_KAFKA_IP, currentInstanceIp + ":9092")
    );
}

// 4. 创建 KafkaConsumer，订阅 .*central
main.consumer.subscribe(Pattern.compile(".*central"));

// 5. 按 accountId 维护 ResourceAnalyser 实例
Map<Integer, ResourceAnalyser> resourceAnalyserMap = new HashMap<>();

// 6. 注册 ShutdownHook (优雅关闭)
Runtime.getRuntime().addShutdownHook(new Thread() {
    public void run() {
        main.consumer.wakeup();
        mainThread.join();
    }
});

// 7. 进入消费循环
while (true) {
    ConsumerRecords<String, String> records = main.consumer.poll(Duration.ofMillis(10000));
    main.consumer.commitSync();
    for (ConsumerRecord<String,String> r: records) {
        HttpResponseParams httpResponseParams = HttpCallParser.parseKafkaMessage(r.value());
        int accountId = Integer.parseInt(httpResponseParams.getAccountId());
        ResourceAnalyser resourceAnalyser = resourceAnalyserMap.get(accountId);
        if (resourceAnalyser == null) {
            resourceAnalyser = new ResourceAnalyser(300_000_000, 0.01, 100_000_000, 0.01);
            resourceAnalyserMap.put(accountId, resourceAnalyser);
        }
        resourceAnalyser.analyse(httpResponseParams);
    }
}
```

### 6.3 多租户支持

每个 `accountId` 拥有独立的 `ResourceAnalyser` 实例，各自维护独立的 Bloom Filter：

```java
Map<Integer, ResourceAnalyser> resourceAnalyserMap = new HashMap<>();
// 每个 accountId 一个实例 → 独立的 duplicateCheckerBF 和 valuesBF
```

内存消耗：每个租户约 480 MB（360 MB + 120 MB Bloom Filter），10 个租户约 4.8 GB。

### 6.4 优雅关闭

```java
Runtime.getRuntime().addShutdownHook(new Thread() {
    public void run() {
        main.consumer.wakeup();    // 中断 poll()
        mainThread.join();         // 等待主线程退出
    }
});
```

`wakeup()` 触发 `WakeupException`，主循环捕获后退出，`finally` 块关闭 consumer。

---

## 7. URL 模板匹配

### 7.1 两级匹配策略

```java
// 第一级：精确匹配
URLStatic urlStaticFromDb = matchWithUrlStatic(apiCollectionId, url, method);
if (urlStaticFromDb != null) {
    url = urlStaticFromDb.getUrl();
} else {
    // 第二级：模板匹配
    urlTemplate = matchWithUrlTemplate(apiCollectionId, url, method);
    if (urlTemplate != null) {
        url = urlTemplate.getTemplateString();  // 如 "api/books/INTEGER"
    }
}
```

### 7.2 URL 变体处理

处理 URL 命名不一致问题（前导斜杠、尾随斜杠、大小写）：

```java
List<String> urlVariations = new ArrayList<>();
if (url.startsWith("/")) {
    urlVariations.add(url.substring(1));          // 去掉前导 /
    urlVariations.add(url.substring(1).toLowerCase()); // 去掉前导 / + 小写
}
urlVariations.add(url.toLowerCase());             // 小写
if (url.endsWith("/")) {
    urlVariations.add(url.substring(0, url.length()-1)); // 去掉尾随 /
    urlVariations.add(url.substring(0, url.length()-1).toLowerCase());
}
```

### 7.3 API 集合匹配

通过 `hostName + "$" + vxlanId` 映射到真实的 `apiCollectionId`：

```java
String key = hostName + "$" + originalApiCollectionId;
if (hostNameToIdMap.containsKey(key)) {
    return hostNameToIdMap.get(key);
} else if (hostNameToIdMap.containsKey(hostName + "$0")) {
    return hostNameToIdMap.get(hostName + "$0");  // 默认集合
}
```

---

## 8. 参数提取

### 8.1 URL 路径参数

```java
if (urlTemplate != null) {
    String[] tokens = APICatalogSync.tokenize(baseUrl);  // /api/books/2 → ["api", "books", "2"]
    SingleTypeInfo.SuperType[] types = urlTemplate.getTypes();  // [null, null, INTEGER]
    for (int idx = 0; idx < tokens.length; idx++) {
        if (types[idx] != null) {  // 只分析 INTEGER/STRING 类型的 token
            analysePayload(tokens[idx], idx+"", combinedUrl, userId, ...);
        }
    }
}
```

示例：URL `/api/books/2` → 模板 `api/books/INTEGER` → 提取 `2` 作为参数 `"2"` 的值

### 8.2 请求体参数

```java
BasicDBObject payload = RequestTemplate.parseRequestPayload(requestParams, urlWithParams);
Map<String, Set<Object>> flattened = JSONUtils.flatten(payload);
for (String param: flattened.keySet()) {
    for (Object val: flattened.get(param)) {
        analysePayload(val, param, combinedUrl, ...);
    }
}
```

嵌套 JSON 展平规则：`{"user": {"name": "Alice"}}` → `{"user#name": ["Alice"]}`

### 8.3 请求头参数（已注释）

```java
// 代码中请求头分析部分已被注释掉
// 目前不处理请求头参数
```

---

## 9. 同步机制

### 9.1 触发条件

```java
if (countMap.keySet().size() > 200_000 || (Context.now() - last_sync) > 120) {
    syncWithDb();
}
```

| 条件 | 阈值 | 说明 |
|---|---|---|
| countMap 大小 | > 200,000 条 | 防止内存溢出 |
| 时间间隔 | > 120 秒 | 定时刷新 |

### 9.2 同步流程

```java
public void syncWithDb() {
    // 1. 从 MongoDB 重建 API 目录缓存
    buildCatalog();

    // 2. 重建 hostName → apiCollectionId 映射
    populateHostNameToIdMap();

    // 3. 生成批量更新操作
    List<WriteModel<SingleTypeInfo>> dbUpdates = getDbUpdatesForSingleTypeInfo();

    // 4. 清空 countMap
    countMap = new HashMap<>();

    // 5. 更新时间戳
    last_sync = Context.now();

    // 6. 执行批量写
    if (dbUpdates.size() > 0) {
        SingleTypeInfoDao.instance.getMCollection().bulkWrite(dbUpdates);
    }
}
```

### 9.3 批量更新生成

```java
for (SingleTypeInfo singleTypeInfo: countMap.values()) {
    if (singleTypeInfo.getUniqueCount() == 0 && singleTypeInfo.getPublicCount() == 0) continue;

    Bson filter = SingleTypeInfoDao.createFiltersWithoutSubType(singleTypeInfo);
    Bson update = Updates.combine(
        Updates.inc("uniqueCount", singleTypeInfo.getUniqueCount()),
        Updates.inc("publicCount", singleTypeInfo.getPublicCount())
    );
    bulkUpdates.add(new UpdateManyModel<>(filter, update, new UpdateOptions().upsert(false)));
}
```

> **注意**：`upsert: false` — 只更新 api-runtime 已创建的 SingleTypeInfo 记录。如果 api-analyser 先于 api-runtime 处理某个端点，该端点的统计数据会被丢弃。

---

## 10. 下游消费者

### 10.1 测试引擎 (akto-api-testing)

测试引擎通过 `FilterAction.evaluatePrivateVariables()` 读取 `uniqueCount` 和 `publicCount`：

```java
// FilterAction.java L1317
public DataOperandsFilterResponse evaluatePrivateVariables(FilterActionRequest filterActionRequest) {
    // 查询 SingleTypeInfo
    List<SingleTypeInfo> singleTypeInfos = SingleTypeInfoDao.instance.findAll(filter, 0, 500, null);

    for (SingleTypeInfo singleTypeInfo: singleTypeInfos) {
        // 检查参数值是否为私有
        for (String val: valSet) {
            boolean exists = paramExists(filterActionRequest.getRawApi(), key, val);
            if (!exists && val != null && val.length() > 0) {
                // 找到私有参数值
                paramValues.add(obj);
                break;
            }
        }
    }
}
```

### 10.2 测试模板引用

BOLA 测试模板中使用 `private_variable_context` 过滤器：

```yaml
# BOLAByChangingAuthToken.yaml
api_selection_filters:
  private_variable_context:        ← 只选择有私有参数的端点
    regex: .*
```

效果：只有当端点至少有一个 `uniqueCount > 0` 的参数时，才执行 BOLA 测试。

### 10.3 Dashboard 展示

Dashboard 读取 `single_type_info` 集合，在 API 清单页面展示每个参数的统计信息：
- 参数值数量（uniqueCount + publicCount）
- 是否为私有参数
- 参数值示例（CappedSet 中的值）

---

## 11. 依赖关系

### 11.1 Maven 依赖

```xml
<!-- api-analyser pom.xml -->
<dependency>
    <groupId>com.akto.apps.api-runtime</groupId>
    <artifactId>api-runtime</artifactId>      ← 依赖 api-runtime
</dependency>
<dependency>
    <groupId>com.akto.libs.dao</groupId>
    <artifactId>dao</artifactId>              ← 数据访问层
</dependency>
<dependency>
    <groupId>com.akto.libs.utils</groupId>
    <artifactId>utils</artifactId>            ← 工具库
</dependency>
<dependency>
    <groupId>com.google.guava</groupId>
    <artifactId>guava</artifactId>            ← BloomFilter
</dependency>
<dependency>
    <groupId>org.apache.kafka</groupId>
    <artifactId>kafka-clients</artifactId>    ← Kafka 消费
</dependency>
```

### 11.2 运行时依赖

| 依赖 | 用途 |
|---|---|
| **MongoDB** | 读写 `single_type_info`、`api_collections` 集合 |
| **Kafka** | 消费 `akto.central` 主题 |
| **api-runtime** | 提供 `HttpCallParser`、`APICatalogSync`、`URLAggregator` 等类 |
| **api-runtime 先行运行** | api-analyser 依赖 api-runtime 已创建的 SingleTypeInfo 记录 |

### 11.3 部署依赖

```
部署顺序:
1. MongoDB
2. Kafka
3. api-runtime (创建 SingleTypeInfo 记录)
4. api-analyser (在已存在记录上更新计数)
5. akto-api-testing (读取计数，降低误报)
```

---

## 12. 局限性与注意事项

### 12.1 数据丢失风险

- **upsert: false** — 如果 api-runtime 尚未为某端点创建 SingleTypeInfo 记录，api-analyser 的统计会被丢弃
- **Bloom Filter 误判** — 1% 误判率可能导致少量值被错误判定为"已存在"（public），或被误判为"重复"而跳过
- **内存重启** — Bloom Filter 在内存中，进程重启后全部丢失，需要重新积累

### 12.2 内存消耗

| 组件 | 每租户内存 | 10 租户 |
|---|---|---|
| duplicateCheckerBF | ~360 MB | ~3.6 GB |
| valuesBF | ~120 MB | ~1.2 GB |
| countMap (峰值) | ~50 MB | ~500 MB |
| **合计** | **~530 MB** | **~5.3 GB** |

### 12.3 代码注释掉的特性

- **请求头参数分析** — 代码已写好但被注释掉，目前不统计请求头参数
- **状态码过滤** — 只处理 2xx 响应，非 2xx 的流量被忽略

### 12.4 硬编码值

| 硬编码 | 值 | 说明 |
|---|---|---|
| Kafka Broker | `kafka1:19092` | 不可通过环境变量配置 |
| Kafka Topic | `.*central` (正则) | 不可配置 |
| Consumer Group | `analyzer-group-config` | 不可配置 |
| accountId | `1_000_000` | 固定为 100 万（多租户通过 ResourceAnalyserMap 区分） |
| 同步阈值 | 200,000 条 / 120 秒 | 不可配置 |
| BF 容量 | 3 亿 / 1 亿 | 不可配置 |
