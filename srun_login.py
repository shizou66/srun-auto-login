# -*- coding: utf-8 -*-
"""
SRun（深澜）校园网 Portal 自动认证脚本

适用于使用「深澜 SRun」认证系统的校园网（Web 网页认证）。
跨平台：Windows / macOS / Linux，只依赖 requests。

用法：
    1. 复制 config.example.json 为 config.json，填好你的信息
    2. pip install requests
    3. python srun_login.py

配置详解与适配其他学校的教程见 README.md 和 docs/protocol.md
"""

import hashlib
import hmac
import json
import logging
import math
import os
import random
import re
import socket
import sys
import time

import requests

# ============================================================
# 路径与日志
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
EXAMPLE_FILE = os.path.join(BASE_DIR, "config.example.json")
LOG_FILE = os.path.join(BASE_DIR, "srun_login.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("srun")

# ============================================================
# 默认配置（config.json 里没写的项会回落到这里）
# ============================================================

DEFAULTS = {
    # 认证服务器地址（抓包里那条请求的「远程地址」）
    "host": "",

    # 账号密码
    "username": "",
    "password": "",

    # 认证端口组，大多数学校是 "0" 或 "1"
    "ac_id": "0",

    # 固定参数，来自抓包
    "n": "200",
    "type": "1",
    "os": "Windows 10",
    "name": "Windows",
    "double_stack": "0",

    # info 字段里声明的加密方式，深澜通常是 srun_bx1
    "enc_ver": "srun_bx1",

    # 请求协议，个别学校是 https
    "scheme": "http",

    # base64 字母表：多数学校用深澜自定义表（srun），少数用标准表（standard）
    # 如果登录一直报校验错误，试试把这里改成另一个
    "base64_alphabet": "srun",

    # 轮询间隔（秒）
    "interval": 15,

    # 联网探测地址：能返回 HTTP 204 才算真在线
    "probe_urls": [
        "http://connect.rom.miui.com/generate_204",
        "http://connectivitycheck.platform.hicloud.com/generate_204",
    ],

    # 请求超时（秒）
    "timeout": 10,

    # 是否把成功/失败的响应原文也写进日志（调试用）
    "debug_response": False,
}

# ============================================================
# SRun 加密（srun_bx1，XXTEA 变体）
# ============================================================

_SRUN_ALPHABET = ("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/"
                  "3dlbfKwv6xztjI7DeBE45QA")
_STD_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 "0123456789+/")


def _make_trans(srun_style=True):
    if srun_style:
        return str.maketrans(_STD_ALPHABET, _SRUN_ALPHABET)
    return None


def encode_base64(data, srun_style=True):
    """按深澜（或标准）字母表做 base64 编码

    data 为「每个字符一个字节」的字符串（latin-1 语义），
    与深澜 JS 实现保持一致。
    """
    r = []
    x = len(data) % 3
    if x:
        data = data + "\0" * (3 - x)
    for i in range(0, len(data), 3):
        d = data[i:i + 3]
        a = ord(d[0]) << 16 | ord(d[1]) << 8 | ord(d[2])
        table = _SRUN_ALPHABET if srun_style else _STD_ALPHABET
        r.append(table[a >> 18])
        r.append(table[a >> 12 & 63])
        r.append(table[a >> 6 & 63])
        r.append(table[a & 63])
    if x == 1:
        r[-1] = "="
        r[-2] = "="
    if x == 2:
        r[-1] = "="
    return "".join(r)


def _ordat(msg, idx):
    return ord(msg[idx]) if len(msg) > idx else 0


def sencode(msg, key):
    """字符串 -> 32 位整数字数组；key=True 时在末尾附加原始长度

    注意：这里刻意使用 Python 天然的「无符号」整数语义。
    深澜前端 JS 在该算法中对整数做无符号处理，用有符号模拟会算出不同的密文。
    """
    out = []
    for i in range(0, len(msg), 4):
        out.append(_ordat(msg, i) | _ordat(msg, i + 1) << 8
                   | _ordat(msg, i + 2) << 16 | _ordat(msg, i + 3) << 24)
    if key:
        out.append(len(msg))
    return out


def lencode(msg, key):
    """32 位整数字数组 -> 字节字符串"""
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return None
        ll = m
    for i in range(0, l):
        msg[i] = (chr(msg[i] & 0xFF) + chr(msg[i] >> 8 & 0xFF)
                  + chr(msg[i] >> 16 & 0xFF) + chr(msg[i] >> 24 & 0xFF))
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def xencode(msg, key):
    """深澜 srun_bx1 加密（XXTEA 变体）

    该实现已用真实抓包数据逐字段核对通过（见 docs/protocol.md 的验证方法）。
    """
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0          # 0x9E3779B9
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


# ============================================================
# 配置加载
# ============================================================

def load_config():
    path = CONFIG_FILE
    if not os.path.exists(path):
        if os.path.exists(EXAMPLE_FILE):
            log.error("未找到 config.json。请先复制 config.example.json "
                      "为 config.json 并填写你的信息。")
        else:
            log.error("未找到 config.json")
        sys.exit(1)
    try:
        with open(path, encoding="utf-8") as f:
            user_cfg = json.load(f)
    except Exception as e:
        log.error("config.json 解析失败：%s", e)
        sys.exit(1)

    cfg = dict(DEFAULTS)
    cfg.update(user_cfg)

    missing = [k for k in ("host", "username", "password") if not cfg.get(k)]
    if missing:
        log.error("config.json 缺少必填项：%s", ", ".join(missing))
        sys.exit(1)
    return cfg


CFG = None


# ============================================================
# 网络状态检测
# ============================================================

def is_online():
    """能拿到 HTTP 204 才算真在线。

    刻意不使用 ping 作为兜底：很多校园网在未认证时也放行 ICMP，
    会造成「明明没认证却判定已在线」的误判。
    """
    for url in CFG["probe_urls"]:
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            return r.status_code == 204
        except Exception:
            continue
    return False


def local_ip():
    """取本机在网络中的 IP（UDP connect 只选路由，不发包）

    网络尚未就绪时返回 None —— 开机初期 WiFi 还在连接时很常见，
    不应该当成错误。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("223.5.5.5", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return None


# ============================================================
# 认证流程
# ============================================================

def _jsonp_to_json(text):
    """剥掉 JSONP 外壳：jQuery123({...}) -> {...}"""
    text = text.strip()
    m = re.search(r"\((.*)\)\s*;?\s*$", text, re.S)
    return m.group(1) if m else text


def _callback():
    return "jQuery%d_%d" % (random.randint(10 ** 10, 10 ** 11),
                            int(time.time() * 1000))


def _api(path):
    return "%s://%s/cgi-bin/%s" % (CFG["scheme"], CFG["host"], path)


def get_challenge(ip):
    """第一步：向服务器申请一个随机挑战码（challenge / token）"""
    params = {
        "callback": _callback(),
        "username": CFG["username"],
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    r = requests.get(_api("get_challenge"), params=params,
                     timeout=CFG["timeout"])
    m = re.search(r'"challenge":"(.*?)"', r.text)
    return m.group(1) if m else None


def build_info(ip, token):
    """构造 info 明文：紧凑 JSON，键顺序固定

    键顺序会影响加密结果，务必与抓包一致。
    """
    info_temp = {
        "username": CFG["username"],
        "password": CFG["password"],
        "ip": ip,
        "acid": CFG["ac_id"],
        "enc_ver": CFG["enc_ver"],
    }
    s = re.sub("'", '"', str(info_temp))
    return re.sub(" ", "", s)


def login():
    """完整登录流程：get_challenge -> 加密 -> srun_portal"""
    try:
        ip = local_ip()
        if not ip:
            log.info("网络尚未就绪（还没拿到本机 IP），稍后重试")
            return False

        token = get_challenge(ip)
        if not token:
            log.warning("获取 challenge 失败（服务器 %s 无响应？）", CFG["host"])
            return False

        # 密码：HMAC-MD5(明文密码, challenge)
        hmd5 = hmac.new(token.encode(), CFG["password"].encode(),
                        hashlib.md5).hexdigest()

        # info：srun_bx1 加密后的紧凑 JSON
        srun_style = CFG["base64_alphabet"] == "srun"
        info = "{SRBX1}" + encode_base64(
            xencode(build_info(ip, token), token), srun_style)

        # chksum：各字段（每个字段前都加 token）拼接后取 SHA1
        chkstr = (token + CFG["username"]
                  + token + hmd5
                  + token + str(CFG["ac_id"])
                  + token + ip
                  + token + CFG["n"]
                  + token + CFG["type"]
                  + token + info)
        chksum = hashlib.sha1(chkstr.encode()).hexdigest()

        params = {
            "callback": _callback(),
            "action": "login",
            "username": CFG["username"],
            "password": "{MD5}" + hmd5,
            "ac_id": str(CFG["ac_id"]),
            "ip": ip,
            "chksum": chksum,
            "info": info,
            "n": CFG["n"],
            "type": CFG["type"],
            "os": CFG["os"],
            "name": CFG["name"],
            "double_stack": CFG["double_stack"],
            "_": int(time.time() * 1000),
        }
        r = requests.get(_api("srun_portal"), params=params,
                         timeout=CFG["timeout"])
        res = json.loads(_jsonp_to_json(r.text))

        if CFG["debug_response"]:
            log.info("登录响应原文: %s", r.text[:500])

        if str(res.get("ecode")) == "0":
            log.info("登录成功（IP=%s）", ip)
            return True

        log.warning("登录被拒: ecode=%s error=%s error_msg=%s",
                    res.get("ecode"), res.get("error"), res.get("error_msg"))
        return False
    except Exception as e:
        log.warning("登录异常: %s: %s", type(e).__name__, e)
        return False


# ============================================================
# 主循环
# ============================================================

def main():
    global CFG
    CFG = load_config()

    log.info("===== SRun 校园网自动认证已启动 =====")
    log.info("服务器=%s 账号=%s ac_id=%s 字母表=%s",
             CFG["host"], CFG["username"], CFG["ac_id"],
             CFG["base64_alphabet"])

    fails = 0
    while True:
        try:
            if is_online():
                fails = 0                       # 一切正常，安静待着
            elif local_ip() is None:
                # 开机初期网络还没起来，不算失败，保持短间隔快速重试
                log.info("网络尚未就绪（WiFi 连接中？），等待...")
                fails = 0
            else:
                log.info("检测到未认证/断网，尝试登录...")
                if login():
                    fails = 0
                else:
                    fails += 1
                    log.warning("登录未成功（连续 %d 次），稍后重试", fails)
        except Exception as e:
            fails += 1
            log.warning("主循环异常: %s: %s", type(e).__name__, e)

        # 连续失败时逐步拉长间隔，避免反复失败刷屏
        time.sleep(CFG["interval"] if fails < 3
                   else min(CFG["interval"] * fails, 60))


if __name__ == "__main__":
    main()
