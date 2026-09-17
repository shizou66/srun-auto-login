# 深澜 SRun 认证协议笔记

本文记录 SRun Portal 认证的协议细节，以及**如何用真实抓包数据验证实现是否正确**。

---

## 一、整体流程

SRun 的登录是**两步**的，不能只发一个请求：

```
① GET  /cgi-bin/get_challenge   取一个随机挑战码 token
② GET  /cgi-bin/srun_portal     用 token 加密后提交账号密码
```

**为什么必须两步**：密码不是明文提交，而是用第一步拿到的 `token` 参与加密。每次登录 token 都不同，所以密文每次也不同——**不能把抓包里的密文硬编码进脚本**。

---

## 二、第一步：get_challenge

```
GET http://{host}/cgi-bin/get_challenge
      ?callback=jQuery112409970446182076598_1789276343492
      &username={学号}
      &ip={本机IP}
      &_={毫秒时间戳}
```

响应是 JSONP，剥掉外壳后：

```json
{
  "challenge": "f6d5e1c153aad26b041174447c5816ff2941f80daa17ef1e2aa0182d892d0efe",
  "client_ip": "10.147.124.213",
  "ecode": 0,
  "error": "ok",
  "srun_ver": "SRunCGIAuthIntfSvr V1.18 B20221130"
}
```

`challenge` 就是要用的 `token`。

---

## 三、第二步：srun_portal 的三个关键字段

```
GET http://{host}/cgi-bin/srun_portal
      ?callback=...
      &action=login
      &username={学号}
      &password={MD5}xxxxx          ← 字段1
      &os=Windows+10&name=Windows&double_stack=0
      &chksum=xxxxxxxx              ← 字段2
      &info={SRBX1}xxxxx            ← 字段3
      &ac_id=0&ip={本机IP}&n=200&type=1&_={时间戳}
```

### 字段 1：password

```
password = "{MD5}" + HMAC-MD5(明文密码, token)
```

Python：

```python
hmd5 = hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()
```

> 注意是 **HMAC-MD5**（token 作密钥、密码作消息），不是简单地把两个字符串拼起来做 MD5。

### 字段 2：info

先把用户信息拼成**紧凑 JSON**（无空格，键顺序固定）：

```json
{"username":"20xxxxx","password":"xxxx","ip":"10.x.x.x","acid":"0","enc_ver":"srun_bx1"}
```

- `acid` 用的是 `ac_id` 的值，**类型是字符串**（`"0"` 而非 `0`）——这点会影响长度和密文
- 键顺序会影响加密结果，必须与抓包一致

然后加密并 base64：

```
info = "{SRBX1}" + base64(xencode(JSON明文, token))
```

`xencode` 是深澜的 XXTEA 变体实现，见下节。

### 字段 3：chksum

把各字段拼起来（**每个字段前面都要加一次 token**），再取 SHA1：

```python
chkstr = (token + username
          + token + hmd5
          + token + ac_id
          + token + ip
          + token + n          # "200"
          + token + type       # "1"
          + token + info)
chksum = hashlib.sha1(chkstr.encode()).hexdigest()
```

拼接顺序错一个字段，chksum 就对不上。

---

## 四、xencode：XXTEA 变体

这是深澜魔改过的 XXTEA，和标准 XXTEA 有两处不同：

1. 常数 `delta` 用 `0x9E3779B9`（与标准相同），但轮内运算的**组合方式是加法而非异或**
2. 输入先经过 `sencode` 转成 32 位整数字数组，且**长度会附加在数组末尾**

核心轮运算（Python，已实测）：

```python
while q > 0:
    d = d + c & 0xFFFFFFFF
    e = d >> 2 & 3
    p = 0
    while p < n:
        y = pwd[p + 1]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[p] = pwd[p] + m & 0xFFFFFFFF
        z = pwd[p]
        p = p + 1
    y = pwd[0]
    m = z >> 5 ^ y << 2
    m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
    m = m + (pwdk[(p & 3) ^ e] ^ z)      # 此时 p == n
    pwd[n] = pwd[n] + m & 0xFFFFFFFF
    z = pwd[n]
    q = q - 1
```

### ⚠️ 坑一：必须用「无符号」整数语义

深澜的前端 JS 在这段算法里做的是**无符号**处理。如果用「模拟 JS int32 有符号语义」的方式移植（很多教程这么教），算出来的密文**完全不同**，登录会一直失败。

在 Python 里直接用**天然的大整数 + `& 0xFFFFFFFF` 截断**即可，不要画蛇添足去模拟有符号。

> 这个坑我们实际踩过：先写了有符号版本，用 Node 跑 JS 参照实现"验证"通过，但拿真实抓包数据一比对就露馅了。**结论：以真实数据为准，不要以推理为准。**

### ⚠️ 坑二：base64 字母表有两种

深澜有两种 base64 实现，必须用对：

| 类型 | 字母表 |
|---|---|
| **自定义（多数学校）** | `LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA` |
| **标准** | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |

⚠️ **注意**：自定义字母表里**也包含 `+` 和 `/` 字符**（在索引 16 和 40 的位置），所以"密文里出现了 `+` 或 `/` 就说明用的是标准表"这个推断是**错的**。

配置项 `base64_alphabet` 就是用来切换的。如果登录一直报校验错误，换成另一个试试。

---

## 五、如何验证你的实现是对的（关键方法）

别靠"跑起来没报错"判断，要用**真实抓包数据逐字段比对**。

### 准备材料

抓一次真实登录，记录：

- `get_challenge` 响应里的 `challenge`
- `srun_portal` 请求里的 `password`、`info`、`chksum` 三个字段的原值
- 账号、密码、`ip`、`ac_id`、`n`、`type`

### 验证脚本

```python
TOKEN = "抓来的 challenge"
IP = "抓来的 ip"
EXP_PWD  = "{MD5}抓来的 password 值"        # 去掉 {MD5} 前缀后的部分
EXP_INFO = "抓来的 info 值"                  # 不含 {SRBX1} 前缀
EXP_CHK  = "抓来的 chksum"

# 1) 密码
hmd5 = hmac.new(TOKEN.encode(), PASSWORD.encode(), hashlib.md5).hexdigest()
assert "{MD5}" + hmd5 == EXP_PWD, "password 字段不对"

# 2) info
info = "{SRBX1}" + encode_base64(xencode(build_info(IP), TOKEN), srun_style=True)
assert info == EXP_INFO, "info 字段不对 -> 检查 JSON 格式 / 字母表 / 整数语义"

# 3) chksum
chkstr = (TOKEN + USERNAME + TOKEN + hmd5 + TOKEN + AC_ID + TOKEN + IP
          + TOKEN + "200" + TOKEN + "1" + TOKEN + info)
assert hashlib.sha1(chkstr.encode()).hexdigest() == EXP_CHK, "chksum 不对"
```

### 验证顺序很重要

三个断言**从易到难**，能快速定位问题：

| 哪个失败 | 说明什么 |
|---|---|
| `password` 失败 | HMAC 用法或密码明文不对 |
| `info` 失败 | JSON 格式 / base64 字母表 / 整数语义有问题 |
| `chksum` 失败 | 拼接顺序或字段值不对 |

**先让 password 通过**，它最简单，能确认 token 和密码这两件事是对的；再攻 info。

### 一个额外的校验技巧：长度

即使暂时没抓到 token，也能用**长度**做粗筛：

- info 的 JSON 明文长度 → `sencode` 后字数 = `ceil(len/4) + 1`
- `xencode` 输出字节数 = 字数 × 4
- base64 长度 = `ceil(字节数/3) × 4`，padding 数量 = `(3 - 字节数 % 3) % 3`

拿密文的 base64 长度反推明文长度范围，就能判断自己拼的 JSON 格式（字段名、是否带空格、`acid` 的类型）对不对。

> 实战中就是靠这招先排除了「带空格的 JSON」和「acid 是数字」两种可能。

---

## 六、常见错误码

`srun_portal` 返回的 JSON 里：

| ecode | 常见含义 |
|---|---|
| `0` | 登录成功 |
| 非 0 | 见 `error_msg`，常见有密码错误、校验失败、已达终端上限等 |

调试时打开配置里的 `debug_response`，把服务器响应原文写进日志，比猜有用得多。

---

## 七、为什么用 HTTP 204 探测而不是 ping

很多校园网在**未认证状态下也放行 ICMP**（能 ping 通外网 IP）。如果用 ping 判断"是否在线"，会得到"已在线"的错误结论，从而**跳过登录**——表现为"脚本在跑，但就是不上网"。

正确做法是请求一个返回 `204 No Content` 的探测地址，未认证时该请求会被门户拦截（返回 302 或登录页），拿不到 204：

```
http://connect.rom.miui.com/generate_204
http://connectivitycheck.platform.hicloud.com/generate_204
```
