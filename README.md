# srun-auto-login

深澜（SRun）校园网 Portal 认证的**自动登录脚本**。

适用于使用深澜 SRun 认证系统的校园网。开机自动认证、断网自动重连，配合系统自启可实现无人值守。

> 本项目的加密实现使用**真实抓包数据逐字段核对**过（password / info / chksum 三个字段逐字节一致），不是"看起来能跑"。验证方法见 [docs/protocol.md](docs/protocol.md)。

## 特性

- **协议完整实现**：`get_challenge` → 挑战码加密 → `srun_portal` 三步流程
- **跨平台**：Windows / macOS / Linux 通用，纯 Python，只依赖 `requests`
- **断网自愈**：持续探测网络状态，掉线后自动重新认证
- **开机友好**：识别"网络尚未就绪"状态，不会在 WiFi 还没连上时误报错误
- **配置外置**：账号密码放在 `config.json`，已通过 `.gitignore` 排除，不会误提交
- **日志留痕**：所有认证动作写入 `srun_login.log`，便于排查

## 工作原理

```
每 N 秒循环一次：
    ├─ 探测外网（请求 generate_204 地址，能拿到 204 说明已认证）
    │     └─ 已在线 → 什么都不做，安静待着
    ├─ 拿不到本机 IP？→ 说明网络还没起来，等待（不计入失败）
    └─ 未认证/断网 → 执行登录
          ├─ 1. GET get_challenge      取一个随机挑战码 token
          ├─ 2. 用 token 加密：
          │       password = "{MD5}" + HMAC-MD5(明文密码, token)
          │       info     = "{SRBX1}" + base64(srun_bx1(JSON, token))
          │       chksum   = SHA1(各字段前加 token 后拼接)
          └─ 3. GET srun_portal?action=login&...  提交
```

## 快速开始

### 1. 安装依赖

```bash
pip install requests
```

### 2. 配置

```bash
cp config.example.json config.json
```

编辑 `config.json`，至少填这三项：

```json
{
  "host": "10.0.0.1",             // 认证服务器地址，见下方「抓包」
  "username": "你的学号",
  "password": "你的密码"
}
```

### 3. 运行

```bash
python srun_login.py
```

正常情况下你会看到：

```
INFO ===== SRun 校园网自动认证已启动 =====
INFO 服务器=10.0.0.1 账号=20xxxxxx ac_id=0 字母表=srun
INFO 检测到未认证/断网，尝试登录...
INFO 登录成功（IP=10.147.x.x）
```

### 4. 设为开机自启

**Windows**（任务计划程序，管理员 PowerShell）：

```powershell
$a = New-ScheduledTaskAction -Execute "pythonw.exe" `
     -Argument '"C:\path\to\srun_login.py"' -WorkingDirectory "C:\path\to"
$t1 = New-ScheduledTaskTrigger -AtLogOn
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date) `
      -RepetitionInterval (New-TimeSpan -Minutes 5) `
      -RepetitionDuration (New-TimeSpan -Days 3650)
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
     -DontStopIfGoingOnBatteries -RestartCount 3 `
     -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "校园网自动认证" -Action $a `
     -Trigger $t1,$t2 -Settings $s -RunLevel Highest -Force
```

> `pythonw.exe` 要填**完整路径**（用 `where.exe pythonw` 查），只写文件名会报「系统找不到指定文件」。

**Linux**（systemd）：

```ini
# /etc/systemd/system/srun-login.service
[Unit]
Description=SRun auto login
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/srun-auto-login/srun_login.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now srun-login
```

## 配置项说明

| 字段 | 说明 | 默认 |
|---|---|---|
| `host` | 认证服务器地址（抓包里的「远程地址」） | 必填 |
| `username` | 学号 / 账号 | 必填 |
| `password` | 密码 | 必填 |
| `ac_id` | 认证端口组，多数学校是 `"0"` 或 `"1"` | `"0"` |
| `n` / `type` | 协议固定参数，来自抓包 | `"200"` / `"1"` |
| `enc_ver` | info 字段声明的加密方式 | `"srun_bx1"` |
| `scheme` | 请求协议，个别学校是 `https` | `"http"` |
| `base64_alphabet` | `"srun"`（深澜自定义表）或 `"standard"` | `"srun"` |
| `interval` | 轮询间隔（秒） | `15` |
| `probe_urls` | 联网探测地址（返回 204 即视为在线） | 见示例 |
| `debug_response` | 是否把服务器响应原文写进日志 | `false` |

## 适配你自己的学校

本脚本针对**深澜 SRun** 编写。如果你的学校用的也是深澜，只需按下面步骤取出几个参数。

### 第一步：确认是不是深澜

打开校园网登录页，按 `F12` → Network，登录一次，看请求里有没有：

- 路径含 `srun_portal`、`get_challenge`
- 响应头有 `Srun-Server`

是的话，就是深澜。

### 第二步：抓包

1. 断开网络，让它重新弹登录页（或访问任意 `http://` 网址被重定向）
2. `F12` → **Network** → 勾选 **Preserve log**（保留日志）
3. 输入账号密码，点登录
4. 在请求列表里找 `get_challenge` 和 `srun_portal` 两条

### 第三步：从 URL 里读参数

`get_challenge` 的 URL 长这样：

```
http://10.0.0.1/cgi-bin/get_challenge?callback=...&username=xxx&ip=10.x.x.x&_=...
         ^^^^^^^^ 这就是 host
```

`srun_portal` 的 URL 里能读到 `ac_id`、`n`、`type`、`os`、`name` 等，照抄到 `config.json`。

### 第四步：如果登录一直失败

大概率是 `base64_alphabet` 不对。深澜有两种常见的 base64 字母表：

- **自定义表**：`LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA`
- **标准表**：`ABC...789+/`

试着把配置改成另一个值再跑。判断方法见 [docs/protocol.md](docs/protocol.md) 的「如何确认字母表」。

## 常见问题

**Q：日志里出现「网络尚未就绪」**
正常。开机初期 WiFi 还在连接，脚本会保持 15 秒短间隔快速重试，连上后立即认证。

**Q：出现 `OSError: [WinError 10051]`**
网络不可达。旧版本会有这个问题，当前版本已识别该状态。若仍出现，检查 WiFi 是否真的连上了。

**Q：日志乱码**
本脚本统一用 UTF-8 写日志。若日志文件里混入了旧版本（用系统默认编码）写的内容，删掉日志文件重新生成即可。

**Q：为什么不用 ping 判断是否在线？**
很多校园网在**未认证时也放行 ICMP**，用 ping 会造成"明明没认证却判定已在线"的误判，从而跳过登录。所以只认 HTTP 204。

**Q：为什么删掉了「检查 WiFi 是否连上」的逻辑？**
早期版本用 `netsh wlan show interfaces` 的中文输出做判断，但该命令在权限/编码/驱动状态异常时会返回英文错误信息，导致判断失败——脚本会**静默等待，永远不去登录**，且不留任何日志。这是个危险的"哑火"设计，现已改为只看网络通不通。

## 项目结构

```
srun-auto-login/
├── srun_login.py           # 主脚本
├── config.example.json     # 配置模板
├── config.json             # 你的配置（gitignore，不会上传）
├── srun_login.log          # 运行日志
├── docs/
│   └── protocol.md         # 协议逆向笔记与验证方法
├── LICENSE
└── README.md
```

## 免责声明

- 本项目仅供**个人在自己账号上自动化登录**使用，目的是免去重复手动输入的麻烦。
- 请遵守你所在学校的网络使用规定。**不要**用于账号共享、绕过计费或突破终端数量限制。
- 使用者需自行承担因使用本工具产生的一切后果。

## License

[MIT](LICENSE)
