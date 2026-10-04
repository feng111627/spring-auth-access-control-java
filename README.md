# Spring Boot 身份认证与访问控制（本地可运行）

一个不依赖外部安全框架的最小但完整的认证/鉴权实现：登录签发 **访问令牌（access token）** 与
**刷新令牌（refresh token）**，令牌异常、登录异常、权限异常都返回**确定且可区分**的结果；
包含登录失败限流与短时锁定，且并发下计数准确。所有数据保存在进程内存中，无需数据库。

- Java 21 语法级别 / Spring Boot 3.4.x / Spring Web
- 令牌：自实现 `base64url(header).base64url(payload).base64url(HMAC-SHA256)` 签名（JDK 原生，无第三方 JWT 库）
- 密码：PBKDF2-HMAC-SHA256（每口令独立盐、常量时间比较）

---

## 1. 快速开始

```bash
# 编译 + 全量单测（离线环境亦可，依赖已在本地 Maven 缓存）
mvn test

# 打包并以可执行 jar 运行
mvn package -DskipTests
java -jar target/spring-auth-access-control-java-1.0-SNAPSHOT.jar --server.port=8080
```

启动时自动播种 4 个账号，密码均为 `Passw0rd!`（可用 `--app.users.demo.password=xxx` 覆盖）：

| 用户名   | 角色    | 状态   |
|----------|---------|--------|
| admin    | ADMIN   | 启用   |
| editor   | EDITOR  | 启用   |
| viewer   | VIEWER  | 启用   |
| disabled | VIEWER  | 禁用   |

登录：

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","password":"Passw0rd!"}'
# => accessToken / refreshToken / tokenType=Bearer / 两个 expiresInMillis
```

---

## 2. HTTP 接口

| 方法 & 路径                    | 鉴权要求                         | 说明                       |
|--------------------------------|----------------------------------|----------------------------|
| `GET  /api/public/ping`        | 无                               | 公开接口                   |
| `POST /api/auth/login`         | 无                               | 登录，返回令牌对           |
| `POST /api/auth/refresh`       | body 中携带 refresh token        | 刷新（**令牌轮换**）       |
| `POST /api/auth/logout`        | body 中携带 refresh token        | 吊销 refresh token，返回 204 |
| `GET  /api/me`                 | `@RequireAuth`：任意有效登录     | 返回实时身份/权限          |
| `GET  /api/admin/stats`        | `@RequireRole("ADMIN")`          | 角色受限                   |
| `GET  /api/articles/publish`   | `@RequirePermission("article:publish")` | 细粒度权限受限       |

受保护接口使用标准请求头：`Authorization: Bearer <accessToken>`。

### 统一错误体

所有错误都返回稳定的机器码 `code` 与可读 `message`：

```json
{ "code": "TOKEN_SIGNATURE_INVALID",
  "message": "Token signature is invalid (the token was tampered with)",
  "timestamp": "2026-10-03T15:33:05.635Z" }
```

---

## 3. 令牌生命周期与失败原因

### 3.1 结构与载荷

令牌格式为三段式 `header.payload.signature`，载荷字段：

| 字段    | 含义                                                        |
|---------|-------------------------------------------------------------|
| `sub`   | 用户名（令牌只携带**身份**，不携带权限）                    |
| `type`  | `ACCESS` 或 `REFRESH`                                       |
| `iat`   | 签发时间（毫秒）                                            |
| `exp`   | 过期时间（毫秒）                                            |
| `epoch` | 签发时账号的 **令牌纪元**（见 §5）                          |
| `jti`   | 每个令牌唯一 ID（refresh 轮换/吊销以此为准）                |

默认有效期（`application.properties` 可调）：access 5 分钟、refresh 60 分钟。

### 3.2 校验顺序与可区分失败码

校验严格按固定顺序进行，每种失败对应唯一错误码，**绝不合并成一个笼统的“token 无效”**：

| 顺序 | 判定                                   | 错误码                     | HTTP |
|------|----------------------------------------|----------------------------|------|
| 1    | 缺失/分段不对/Base64 无法解析          | `TOKEN_MALFORMED`          | 401  |
| 2    | HMAC 签名不匹配（**payload 或签名被篡改**） | `TOKEN_SIGNATURE_INVALID` | 401  |
| 3    | 当前时间 `>= exp`（**过期**）          | `TOKEN_EXPIRED`            | 401  |
| 4    | 令牌类型与使用场景不符（**类型用错**） | `TOKEN_WRONG_TYPE`         | 401  |
| 5    | refresh 的 `jti` 已被轮换/登出吊销     | `TOKEN_REVOKED`            | 401  |
| 6    | 账号当前已禁用                         | `TOKEN_USER_DISABLED`      | 401  |
| 7    | `epoch` 与账号当前纪元不一致（**账号变更**） | `TOKEN_STALE_EPOCH`    | 401  |

要点：

- **篡改 vs 过期 vs 类型用错** 三者通过 `SIGNATURE_INVALID / EXPIRED / WRONG_TYPE` 明确区分；
  过期判定先于类型判定（一个既过期又用错类型的令牌统一报“过期”，结果仍确定）。
- 用 **refresh token 访问业务接口**，或用 **access token 调刷新接口**，都得到 `TOKEN_WRONG_TYPE`。
- 签名比较使用常量时间比较（`MessageDigest.isEqual`）。

### 3.3 刷新轮换与登出语义（明确且前后一致）

- 每次 `/api/auth/refresh` 都签发**全新令牌对**，并立即吊销本次使用的 refresh token；
  旧 refresh token 再次使用 → `TOKEN_REVOKED`（即使它本身尚未过期）。
- `/api/auth/logout` 吊销传入的 refresh token；access token 不做服务端注销，依赖其短有效期自然失效。
- access token 的权限**永远实时读取**（见下节），因此登出后即使 access token 尚在几分钟有效期内，
  其能做的事也只等于“该账号此刻仍拥有的权限”；账号被禁用或权限被改时，旧 access token 会立即被拒。

---

## 4. 权限模型（角色 + 细粒度权限）

- 令牌只证明“你是谁”，**角色/权限/启用状态全部在每次请求时从存储实时读取**，不信任令牌内的快照。
- 角色到权限的并集映射（`Role` 枚举）：
  - `ADMIN`  → `article:publish`, `article:read`, `admin:stats`
  - `EDITOR` → `article:publish`, `article:read`
  - `VIEWER` → `article:read`
  - 用户还可被直接授予额外的细粒度权限；最终权限 = 角色权限 ∪ 直接权限。
- 方法注解：`@RequireAuth`（登录即可）、`@RequireRole("ADMIN")`、`@RequirePermission("article:publish")`。
- **未认证与权限不足严格区分**：
  - 没带令牌 / 令牌任何一关校验失败 → **401**（身份都无法确立）；
  - 身份有效但缺角色或缺权限 → **403 `ACCESS_DENIED`**，消息明确指出缺的是哪个角色/权限。

### 账号状态/权限变化后，已签发令牌的生效语义（token epoch）

每个账号有一个单调递增的 `tokenEpoch`，令牌签发时嵌入当时值。凡是

- 启用/禁用状态变化、
- 角色集合变化、
- 权限集合变化，

都会使 `tokenEpoch + 1`。请求时若令牌内的 epoch 与账号当前值不同 → 立即 401 `TOKEN_STALE_EPOCH`，
必须重新登录拿到新 epoch 的令牌。因此：

- 权限被收回 → 旧令牌**立刻**失去该权限（而不是等到过期）；
- 权限被授予 → 需重新登录获得携带新 epoch 的令牌后生效；
- 账号禁用 → 旧令牌得到 `TOKEN_USER_DISABLED`；重新启用后，旧令牌因 epoch 仍旧而得 `STALE_EPOCH`，
  仍需重新登录。语义前后一致：**令牌只在“签发时的账号版本”下有效**。

---

## 5. 登录防护：账号维度 + 来源维度（各自独立、结果可区分）

登录失败防护由**两个相互独立的维度**组成，登录请求在密码校验**之前**依次过闸门；
未知用户名与密码错误一样计入失败，避免账号探测。

### 5.1 四种失败结果

| 结果 | 触发条件（默认） | 错误码 | HTTP |
|------|------------------|--------|------|
| 凭据错误 | 用户名不存在或密码错 | `LOGIN_BAD_CREDENTIALS` | 401 |
| 账号锁定（**账号维度**） | 同一用户名连续失败 `max-failures=5` 次 | `LOGIN_ACCOUNT_LOCKED`（锁定 `lock-millis=5 分钟`，消息含剩余毫秒） | 423 |
| 用户名窗口限流（**账号维度**） | 同一用户名在 `window-millis=60s` 内失败达到 `max-attempts-per-window=10` 次 | `LOGIN_RATE_LIMITED`（消息含建议重试等待毫秒） | 429 |
| **来源限流（来源维度，新增）** | 同一来源在 `source-window-millis=5 分钟` 内、**跨所有用户名**（含不存在的用户名）累计失败达到 `max-source-failures=20` 次 | `LOGIN_SOURCE_RATE_LIMITED`（消息含建议重试等待毫秒） | 429 |
| 账号禁用 | 密码正确但账号被禁用 | `LOGIN_ACCOUNT_DISABLED`（不计入任何失败窗口，不发令牌） | 401 |

> 两种 429 的 HTTP 状态码相同，但**机器码不同**（`LOGIN_RATE_LIMITED` vs
> `LOGIN_SOURCE_RATE_LIMITED`），且都与 423 的账号锁、401 的密码错明确可分辨。

### 5.2 来源维度规则（针对"换着用户名爆破"）

- **来源（source）**：按请求方聚合的键。依次取 `X-Forwarded-For` 最左地址、
  `X-Real-IP`、TCP 对端地址（见 `ClientSourceResolver`）。本地用
  `X-Forwarded-For` 请求头即可模拟"同一来源 / 不同来源"，无需改动网络。
- 同一来源在一个**独立滑动窗口**内，对**任意用户名**（包括根本不存在的用户名）的
  每一次真实凭据失败都记一笔；与具体用户名是否被锁定无关。
- 阈值达到后，该来源对**任意用户名**的下一次登录（哪怕密码正确）都返回
  `LOGIN_SOURCE_RATE_LIMITED`，直到窗口滑出足够的旧失败。
- 闸门拦下的请求（已被限流/锁定）**不再记账**，因此被挡期间窗口不会自我续期。
- 来源窗口**不因某账号登录成功而清空**：一个账号登录成功不能抹掉同来源对其它账号
  的爆破证据。（账号自身的计数仍在成功后清零。）

### 5.3 两个维度的关系与固定优先级

- **互相独立、都能真正打出来**：账号维度只看单账号连续失败；来源维度只看同来源的
  整体失败量。把阈值、锁定时长、窗口任意调整，两种结果都可实际触发：
  - 只触发**来源限流**：同一来源、每次换不同用户名（各账号都远不到 5 次）；
  - 只触发**账号锁定**：同一账号、每次换不同来源（每个来源桶最多 1 次失败）。
- **同时满足时优先级固定、前后一致**，判定顺序恒为：

  ```
  来源限流 SOURCE_RATE_LIMITED  →  用户名窗口限流 RATE_LIMITED  →  账号锁定 ACCOUNT_LOCKED
  ```

  即来源闸门最先判定；它只是在两闸门同时生效时"压过"账号结果，并不会顶替或解除
  账号锁——来源窗口滑过后，仍在锁定期的账号继续返回 `ACCOUNT_LOCKED`。
- 任何一次请求在任何时刻只有一个确定结论，不会出现"既像被限流又像被锁定"的矛盾。

### 5.4 并发正确性

- 每个用户名、每个来源各持独立计数状态（`LoginAttemptState` /
  `SourceAttemptState`），其所有方法在自身监视器上 `synchronized`，
  计数不会丢失、重复或互相覆盖。
- 登录流程以**固定加锁顺序**（先来源锁、后用户名锁）把"两道闸门检查 → 密码校验 →
  结果记账"作为一个原子决策；所有调用方加锁顺序一致，不可能形成死锁环；
  不同来源/用户名仍完全并行。
- 因此 N 个并发失败恰好计为 N 次：例如同一来源 40 个并发、各打不同用户名，
  恰好 20 次 `BAD_CREDENTIALS`、其余全部 `SOURCE_RATE_LIMITED`，窗口计数精确停在 20；
  同一账号从 24 个不同来源并发打错密码，恰好 5 次 `BAD_CREDENTIALS`、其余
  `ACCOUNT_LOCKED`。两维同时生效时并发请求结论一致（单测有断言）。

### 5.5 兼容范围

- 登录请求/响应体结构、路径、已有错误码与 HTTP 状态均保持不变；新增的仅是一个
  可分辨结果 `LOGIN_SOURCE_RATE_LIMITED`（429）。
- 所有防护状态仍只存于**进程内存**，重启清空；未引入任何外部服务。
- 新增两个可调配置项（见 §7），默认值下账号维度行为与旧版一致；
  未显式提供来源的编程式调用（旧 `login(username,password)` 入口）归入 `unknown` 来源桶。

---

## 6. 本地验证方法

### 6.1 单元/集成测试

```bash
mvn test
```

- 共 60 个用例，全部通过。测试运行时控制台会逐条打印
  `[业务用例][PASS|FAIL] <场景描述>`，结尾打印
  `========== 业务用例汇总: 通过=N, 失败=M, 跳过=K ==========`，
  可直接看出覆盖了哪些业务及每个用例结果（由 `BusinessCoverageTestListener` 输出）。

覆盖矩阵：

| 测试类 | 覆盖业务 |
|--------|----------|
| `TokenServiceTest` | 合法令牌、payload/签名篡改、异密钥伪造、畸形令牌、access/refresh 过期、类型用错、过期优先于类型 |
| `LoginConcurrencyTest` | 错误密码计数、锁定触发与解除、成功清零、滑动窗口限流、未知用户、禁用账号、**32 线程并发失败恰好计数**、多用户并发互不串扰 |
| `SourceLoginProtectionTest` | **来源维度触发限流（轮换用户名/含不存在用户）、不同来源互不影响、来源窗口到期恢复、成功不清来源窗口、两维各自独立可触发、同时满足时来源优先且账号锁仍在、并发换用户名来源计数精确、并发换来源账号锁定精确、两维同时生效并发结论一致（三结果可分辨）** |
| `AuthFlowIntegrationTest` | HTTP 登录、无令牌/篡改/错类型、刷新轮换重放吊销、登出吊销、权限/角色变更的 epoch 失效、禁用即失效、重新登录恢复 |
| `SourceRateLimitIntegrationTest` | HTTP 下用 `X-Forwarded-For` 模拟同来源爆破→429、不同来源不受影响、换来源打同一账号→423、两维同时满足 429 优先于 423 |
| `AccessControlIntegrationTest` | 公开接口、匿名 401、已认证权限不足 403、角色门、权限门、权限并集、仅认证接口 |

只跑某一类：

```bash
mvn test -Dtest=TokenServiceTest
mvn test -Dtest=LoginConcurrencyTest,SourceLoginProtectionTest
mvn test -Dtest=SourceRateLimitIntegrationTest
mvn test -Dtest=AuthFlowIntegrationTest,AccessControlIntegrationTest
```

### 6.2 curl 手工验证（服务启动后）

来源由 `X-Forwarded-For` 请求头的最左地址决定，用它即可模拟"同一来源"与
"不同来源"。

```bash
B=http://localhost:8080

# 登录拿令牌
TOK=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"Passw0rd!"}')
A=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin)['accessToken'])")

curl -s $B/api/me                                              # 401 TOKEN_MALFORMED
curl -s -H "Authorization: Bearer $A" $B/api/me               # 200
curl -s -H "Authorization: Bearer $A" $B/api/admin/stats      # 403 ACCESS_DENIED

# A) 账号维度：连续错误密码。前 5 次 401 LOGIN_BAD_CREDENTIALS，第 6 次 423 LOGIN_ACCOUNT_LOCKED
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $B/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"viewer","password":"bad"}'
done

# B) 来源维度：同一来源(X-Forwarded-For 固定)每次换不同用户名(都不存在)。
#    前 20 次 401，第 21 次 429 LOGIN_SOURCE_RATE_LIMITED —— 没有任何一个账号被打够 5 次。
for i in $(seq 1 21); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $B/api/auth/login \
    -H 'Content-Type: application/json' -H 'X-Forwarded-For: 198.51.100.77' \
    -d "{\"username\":\"spray-user-$i\",\"password\":\"bad\"}"
done
# 最后一次的完整错误体：
curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 198.51.100.77' \
  -d '{"username":"anything","password":"bad"}'
# => 429 {"code":"LOGIN_SOURCE_RATE_LIMITED", ...}

# C) 不同来源互不影响：换一个 X-Forwarded-For，桶是干净的，仍然只是 401
curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 198.51.100.88' \
  -d '{"username":"spray-user-1","password":"bad"}'
# => 401 LOGIN_BAD_CREDENTIALS

# D) 账号维度独立可达：同一账号每次换来源连错 5 次（每个来源桶只有 1 次），
#    第 6 次用一个全新来源 -> 423 LOGIN_ACCOUNT_LOCKED（而非 429）
for i in $(seq 0 5); do
  curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' \
    -H "X-Forwarded-For: 203.0.113.$i" \
    -d '{"username":"editor","password":"bad"}'; echo
done
```

> 提示：来源/账号状态都在内存里，A/B/D 任一步打满后想重跑，重启服务即可清零。

---

## 7. 配置项（`src/main/resources/application.properties`）

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `app.security.token-secret` | 内置开发密钥 | HMAC 密钥，至少 32 字节；生产必须覆盖 |
| `app.security.access-token-ttl-millis` | 300000 | access token 有效期 |
| `app.security.refresh-token-ttl-millis` | 3600000 | refresh token 有效期 |
| `app.security.pbkdf2-iterations` | 120000 | PBKDF2 迭代次数（测试中可降低以提速） |
| `app.login.max-failures` | 5 | 触发账号锁定的连续失败次数（账号维度） |
| `app.login.lock-millis` | 300000 | 账号锁定时长 |
| `app.login.max-attempts-per-window` | 10 | 同一用户名滑动窗口内最大失败次数（账号维度） |
| `app.login.window-millis` | 60000 | 账号维度滑动窗口长度 |
| `app.login.max-source-failures` | 20 | 同一来源滑动窗口内跨用户名的最大失败次数（来源维度） |
| `app.login.source-window-millis` | 300000 | 来源维度滑动窗口长度 |
| `app.users.demo.password` | `Passw0rd!` | 播种演示账号的统一密码 |

> 说明：本实现面向“本地可运行/教学演示”，令牌密钥、用户与计数均保存在进程内存中，
> 重启即重置；接入生产时应替换为持久化用户库、外部密钥管理与集中式限流存储。
