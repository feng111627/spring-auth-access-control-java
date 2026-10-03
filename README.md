# Spring Auth & Access Control（本地可运行）

一个零外部中间件依赖的 Spring Boot 身份认证与访问控制示例：登录签发令牌、令牌异常分原因拒绝、
基于角色/权限的接口控制、登录失败限流与短时锁定。所有数据保存在内存中，`mvn spring-boot:run`
即可本地运行。

## 1. 快速开始

```bash
# 运行（默认随机端口；也可指定 --server.port=8080）
mvn spring-boot:run

# 运行测试（日志会按“业务模块 + 每条用例 PASS/FAIL + 模块小结”打印）
mvn test
```

启动时自动写入四个演示账号（密码经 PBKDF2-HMAC-SHA256 哈希存储）：

| 用户名 | 密码 | 角色 | 权限 | 状态 |
|--------|------|------|------|------|
| admin | admin123 | ADMIN | user:admin, report:read | 正常 |
| alice | alice123 | USER | report:read | 正常 |
| bob   | bob123   | USER | （无） | 正常 |
| nancy | nancy123 | USER | （无） | 已停用 |

## 2. 令牌生命周期

### 2.1 结构

紧凑三段式：`base64url(header).base64url(payload).base64url(HMAC_SHA256(前两段, 密钥))`

- header：`{"alg":"HS256","typ":"at+jwt"}`（访问令牌）或 `"rt+jwt"`（刷新令牌）
- payload：`{sub(用户名), jti(唯一id), iat(签发秒), exp(过期秒), ver(令牌版本)}`
- **令牌不含角色/权限**——授权信息每次请求实时从用户存储读取，因此权限变更对已签发令牌即时生效。

### 2.2 有效期（可用 `auth.*` 配置覆盖）

| 令牌 | 默认有效期 | 配置项 |
|------|-----------|--------|
| 访问令牌 | 15 分钟 | `auth.access-token-ttl` |
| 刷新令牌 | 12 小时 | `auth.refresh-token-ttl` |

### 2.3 签发、轮换与吊销

- **登录** `POST /api/auth/login`：校验通过后签发一对令牌。
- **刷新** `POST /api/auth/refresh`：必须使用刷新令牌；校验通过后**递增令牌版本并轮换**，
  新令牌对基于新版本签发，旧访问令牌、旧刷新令牌同时失效（下次使用得到 `TOKEN_REVOKED`）。
- **登出** `POST /api/auth/logout`：递增令牌版本，该用户所有已签发令牌立即失效。
- **管理员强制下线** `POST /api/admin/users/{name}/revoke-tokens`：同上。
- 令牌版本（`ver`）不匹配即判定 `TOKEN_REVOKED`，语义明确：登出、强制下线、刷新轮换都会使旧版本作废。

### 2.4 令牌异常的可区分失败原因

校验按固定优先级给出确定结果，错误码（HTTP 状态码）互不混淆：

| 场景 | 错误码 | HTTP |
|------|--------|------|
| 缺少 `Authorization` 头 / 空令牌 | MISSING_TOKEN | 401 |
| 非 Bearer 方案、非三段、Base64/JSON 无法解析 | MALFORMED_TOKEN | 401 |
| 未知签名算法或未知 typ | UNSUPPORTED_TOKEN | 401 |
| 签名不匹配（签名段或载荷被篡改、密钥不符） | BAD_TOKEN_SIGNATURE | 401 |
| 刷新令牌访问接口 / 访问令牌调刷新 | WRONG_TOKEN_TYPE | 401 |
| 超过 exp | TOKEN_EXPIRED | 401 |
| 登出/吊销/刷新轮换后旧版本令牌 | TOKEN_REVOKED | 401 |
| 用户在令牌有效期内被停用 | ACCOUNT_DISABLED | 401 |

> 类型错误优先于过期判定，因此“又过期、类型又用错”时结果稳定为 WRONG_TOKEN_TYPE。

## 3. 权限模型

- 用户拥有 `roles`（角色集合）与 `permissions`（权限集合），均为实时读取的内存状态。
- 接口通过注解声明要求，可标注在方法或类上：
  - `@RequireRole({"ADMIN"})`：拥有任一角色即可（多值 OR）。
  - `@RequirePermission({"report:read"})`：拥有任一权限即可（多值 OR）。
  - 同时标注两类注解时为 AND。
  - 不标注的受保护接口只要求“已认证”。
- **401 与 403 明确区分**：未认证（无令牌/令牌无效）由认证拦截器拦截为 401；
  已认证但不满足角色/权限由授权拦截器拦截为 403（`ACCESS_DENIED`，响应 details 中带所需与实际集合）。
- **变更语义前后一致**：
  - 修改角色/权限：下一个请求立即按新集合判定，无需重新登录；
  - 停用账号：该账号令牌下一次请求即被拒为 `ACCOUNT_DISABLED`；
  - 显式吊销（登出/强制下线/刷新轮换）：旧令牌一律 `TOKEN_REVOKED`。

内置接口：

| 接口 | 访问要求 |
|------|---------|
| `POST /api/auth/login`、`POST /api/auth/refresh` | 公开 |
| `GET /api/public/hello` | 公开 |
| `GET /api/me` | 已认证 |
| `GET /api/admin/ping` | ADMIN 角色 |
| `GET /api/reports/view` | report:read 权限 |
| `POST /api/auth/logout` | 已认证 |
| `/api/admin/users/**`（建用户、改角色/权限、停用/启用、吊销令牌） | user:admin 权限 |

## 4. 登录限流与锁定规则

| 机制 | 默认规则 | 配置项 | 触发结果 |
|------|---------|--------|---------|
| 账号锁定 | 同一用户名连续失败 5 次后锁定 5 分钟 | `auth.max-login-failures`、`auth.lock-duration` | ACCOUNT_LOCKED / 423 |
| 来源 IP 限流 | 滑动窗口 10 分钟内失败 20 次 | `auth.ip-max-failures`、`auth.ip-window` | RATE_LIMITED / 429 |

规则细节：

- 达到阈值的**当次**失败仍返回 `BAD_CREDENTIALS`（401），锁定从**下一次**尝试开始生效，
  因此“凭据错误 / 账号锁定 / IP 限流”三种响应在客户端和日志中可以明确分辨。
- 锁定/限流响应的 `details` 中带 `retryAfterSeconds`；锁定到期后失败计数清零重新开始；
  登录成功清零该账号计数（IP 窗口保留，防止借成功登录重置 IP 限流）。
- 登录流程顺序固定：参数校验 → IP 限流 → 账号锁定 → 凭据校验 → 账号停用，结果确定。
- **并发正确性**：每个用户名、每个 IP 各有独立状态对象；IP 检查、IP 计数、账号锁定复查、
  账号计数在固定加锁顺序（先 IP 后账号）下原子完成，高并发失败不会多记、少记或互相覆盖锁定状态。
- 用户名不存在与密码错误返回相同的 `BAD_CREDENTIALS`，避免账号枚举。

统一错误响应格式：

```json
{ "code": "ACCOUNT_LOCKED", "message": "账号已锁定，请稍后再试",
  "details": { "retryAfterSeconds": 300, "failureCount": 5 } }
```

## 5. 本地验证（curl 示例）

```bash
PORT=8080
# 登录拿令牌
TOKEN=$(curl -s -X POST http://localhost:$PORT/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}')
AT=$(echo "$TOKEN" | python3 -c "import sys,json;print(json.load(sys.stdin)['accessToken'])")

curl -s http://localhost:$PORT/api/me -H "Authorization: Bearer $AT"                 # 200
curl -s http://localhost:$PORT/api/me                                               # 401 MISSING_TOKEN
curl -s http://localhost:$PORT/api/me -H "Authorization: Bearer ${AT}X"             # 401 BAD_TOKEN_SIGNATURE
curl -s http://localhost:$PORT/api/admin/ping -H "Authorization: Bearer $AT"        # 403 ACCESS_DENIED

# 连续失败 5 次后观察锁定（第 5 次 BAD_CREDENTIALS，第 6 次 ACCOUNT_LOCKED/423）
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:$PORT/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"alice","password":"bad"}'
done
```

## 6. 测试

`mvn test` 运行全部 57 条用例，按业务模块组织，控制台逐条打印结果：

| 测试类 | 覆盖业务 |
|--------|---------|
| TokenServiceTest（12） | 合法签发；结构非法/算法不支持/签名篡改/载荷篡改/密钥不符/类型错用/过期及优先级 |
| AuthorizationServiceTest（7） | 角色、权限、OR 语义、权限与角色变更即时生效 |
| LoginAttemptServiceTest（8） | 阈值锁定、到期恢复、成功清零、账号隔离、IP 窗口限流与滑窗过期、20 线程并发计数精确 |
| AuthFlowIntegrationTest（26） | HTTP 端到端：登录各失败原因、令牌各异常码、401/403 区分、权限/停用/吊销即时语义、刷新轮换 |
| ConcurrentLoginIntegrationTest（3） | 30 线程并发错误密码计数精确、锁定稳定性、并发 IP 限流 |
| ApplicationTests（1） | Spring 上下文加载 |

示例日志：

```
================ 业务测试模块: TokenServiceTest ================
  [01] 开始: 签名段被篡改 -> BAD_TOKEN_SIGNATURE，而非过期等其他错误
  [01] PASS  签名段被篡改 -> ...
模块小结 TokenServiceTest: 共 12 条, 通过 12, 失败 0
```

> 测试环境通过 `src/test/resources/application.properties` 将阈值调小
> （访问令牌 2 秒、刷新令牌 5 秒、3 次失败锁定、IP 阈值 10），配合可控时钟
> （`MutableClock`）稳定复现过期与锁定场景；集成测试每用例前重置内存数据，保证相互独立。

## 7. 主要配置项

```properties
auth.hmac-secret=local-dev-secret-please-change-0123456789
auth.access-token-ttl=PT15M
auth.refresh-token-ttl=PT12H
auth.max-login-failures=5
auth.lock-duration=PT5M
auth.ip-max-failures=20
auth.ip-window=PT10M
auth.password.iterations=120000
```

生产部署时至少应通过环境变量覆盖 `auth.hmac-secret`，并将内存实现替换为持久化存储。
