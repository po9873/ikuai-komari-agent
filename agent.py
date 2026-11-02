#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iKuai-Komari Agent
监控 iKuai (爱快) 路由器并通过 Komari v2 协议上报到 Komari 面板。

认证方式（二选一，优先使用 API Token）：
- API Token（推荐，iKuai 4.0.222+）：在路由器后台
  「登录管理 -> 个人 API 令牌」生成，只需监控相关权限，
  无需账号密码，不触发登录锁定
- 账号密码（iKuai 3.x 兼容模式）：本地 /Action/login 登录换取会话

仅使用 Python 标准库，无第三方依赖。所有配置来自环境变量。

GitHub: https://github.com/po9873/ikuai-komari-agent
"""

import base64
import hashlib
import json
import os
import re
import ssl
import time
import traceback
from datetime import datetime, timedelta
from urllib.parse import quote
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# 配置（全部来自环境变量）
# ---------------------------------------------------------------------------

IKUAI_URL = os.environ.get("IKUAI_URL", "https://192.168.1.1").rstrip("/")
IKUAI_API_TOKEN = os.environ.get("IKUAI_API_TOKEN", "")          # 4.0 个人 API 令牌
IKUAI_USERNAME = os.environ.get("IKUAI_USERNAME", "")             # 3.x 账密模式
IKUAI_PASSWORD = os.environ.get("IKUAI_PASSWORD", "")
IKUAI_VERIFY_SSL = os.environ.get("IKUAI_VERIFY_SSL", "false").lower() in ("1", "true", "yes", "on")
IKUAI_TIMEOUT = int(os.environ.get("IKUAI_TIMEOUT", "10"))

AGENT_VERSION = os.environ.get("AGENT_VERSION", "1.2")            # 面板「客户端版本」列显示的版本号（纯数字格式，与官方 agent 一致）

KOMARI_ENDPOINT = os.environ.get("KOMARI_ENDPOINT", "").rstrip("/")
KOMARI_TOKEN = os.environ.get("KOMARI_TOKEN", "")
REPORT_INTERVAL = float(os.environ.get("REPORT_INTERVAL", "3"))   # 指标上报间隔（秒）
BASIC_INTERVAL = float(os.environ.get("BASIC_INTERVAL", "300"))   # 基础信息上报间隔（秒）
LOCK_BACKOFF = float(os.environ.get("LOCK_BACKOFF", "60"))        # 登录锁定后的等待秒数
MONTH_ROTATE = int(os.environ.get("MONTH_ROTATE", "0"))           # 流量月重置日（0=不重置，1-28=每月N号清零，同官方 --month-rotate）
STATE_FILE = os.environ.get("STATE_FILE", "/data/traffic_state.json")  # 月流量基线持久化文件（建议挂卷）
PUBLIC_IP_APIS = [u for u in os.environ.get(
    "PUBLIC_IP_APIS",
    "https://api.ipify.org,https://api-ipv4.ip.sb/ip,https://ipv4.icanhazip.com,https://ip.3322.net",
).split(",") if u.strip()]                                        # 公网 IPv4 探测服务（CGNAT 环境必须走外部探测）
PUBLIC_IPV6_APIS = [u for u in os.environ.get(
    "PUBLIC_IPV6_APIS",
    "https://api6.ipify.org,https://api-ipv6.ip.sb/ip,https://ipv6.icanhazip.com",
).split(",") if u.strip()]                                        # 公网 IPv6 探测服务（无 IPv6 出口时留空）

CTOX = None if IKUAI_VERIFY_SSL else ssl._create_unverified_context()

TOKEN_MODE = bool(IKUAI_API_TOKEN)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


# ---------------------------------------------------------------------------
# HTTP 基础
# ---------------------------------------------------------------------------

def _open(req, timeout):
    kw = {"context": CTOX} if (CTOX and req.full_url.startswith("https")) else {}
    with urlopen(req, timeout=timeout, **kw) as r:
        return r.read().decode()


def http_json(url, obj, headers=None, timeout=IKUAI_TIMEOUT):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = Request(url, data=json.dumps(obj).encode(), headers=h, method="POST")
    return json.loads(_open(req, timeout))


# ---------------------------------------------------------------------------
# iKuai 数据源：API Token 模式（iKuai 4.0 OpenAPI v4.0）
# ---------------------------------------------------------------------------

class IkuaiTokenClient:
    """通过个人 API 令牌调用 iKuai 4.x REST API（/api/v4.0/...）。"""

    def __init__(self):
        self.base = IKUAI_URL + "/api/v4.0"

    def get(self, path):
        req = Request(
            self.base + path,
            headers={
                "Authorization": "Bearer " + IKUAI_API_TOKEN,
                "Accept": "application/json",
            },
            method="GET",
        )
        body = json.loads(_open(req, IKUAI_TIMEOUT))
        if body.get("code") != 0:
            raise RuntimeError("iKuai API %s error: %s" % (path, body))
        return body.get("results") or {}

    def sysinfo(self):
        return self.get("/monitoring/system").get("sysinfo") or {}

    def wan_ip(self):
        """从接口状态取 WAN 口 IP（用于上报公网/出口地址，而非管理 LAN IP）。"""
        try:
            r = self.get("/monitoring/interfaces-status")
            for it in (r.get("iface_check") or []):
                if not str(it.get("parent_interface") or "").startswith("wan"):
                    continue
                ip = str(it.get("ip_addr") or "").strip()
                if ip:
                    return ip
        except Exception:
            pass
        return ""

    def disk_usage(self):
        """返回 (total_bytes, used_bytes)，由使用率反推总量。"""
        r = self.get("/monitoring/disk")
        samples = r.get("disk_space_used") or []
        if not samples:
            return 0, 0
        last = samples[-1]
        pct = float(last.get("disk_space_use") or 0)
        used_mb = float(last.get("disk_space_used") or 0)
        if pct <= 0:
            return 0, 0
        total_mb = used_mb * 100.0 / pct
        return int(total_mb * 1024 * 1024), int(used_mb * 1024 * 1024)


# ---------------------------------------------------------------------------
# iKuai 数据源：账号密码模式（iKuai 3.x /Action/login + /Action/call）
# ---------------------------------------------------------------------------

class IkuaiLoginLocked(Exception):
    """账号被路由器临时锁定（防爆破）"""


class IkuaiPasswordClient:
    def __init__(self):
        self.sess_key = None

    def login(self):
        md5 = hashlib.md5(IKUAI_PASSWORD.encode()).hexdigest()
        b64 = base64.b64encode(("salt_11" + IKUAI_PASSWORD).encode()).decode()
        payload = {
            "username": IKUAI_USERNAME,
            "passwd": md5,
            "pass": b64,
            "remember_password": "",
        }
        req = Request(
            IKUAI_URL + "/Action/login",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        body = json.loads(_open(req, IKUAI_TIMEOUT))
        if body.get("code") == 1006 or "锁定" in str(body.get("message", "")):
            raise IkuaiLoginLocked(str(body))
        if body.get("Result") != 10000:
            raise RuntimeError("iKuai login failed: %s" % body)
        self.sess_key = "sess_key=" + body.get("sess_key", "")
        log("iKuai login OK (%s)" % IKUAI_URL)

    def call(self, func_name, param):
        if self.sess_key is None:
            self.login()
        body = http_json(
            IKUAI_URL + "/Action/call",
            {"func_name": func_name, "action": "show", "param": param},
            {"Cookie": self.sess_key},
        )
        if body.get("code") == 10014 or body.get("Result") == 10014:
            log("iKuai session expired, re-login")
            self.login()
            return self.call(func_name, param)
        if body.get("code") not in (0, None):
            return None
        return body.get("results")


ik = IkuaiTokenClient() if TOKEN_MODE else IkuaiPasswordClient()


# ---------------------------------------------------------------------------
# 流量月重置（同官方 agent --month-rotate：totalUp/totalDown 报告自上次重置日以来的增量）
# ---------------------------------------------------------------------------

def _last_reset_date(now, day):
    """最近一次月重置日期（官方 GetLastResetDate 同语义）"""
    day = min(max(int(day), 1), 31)
    while True:
        try:
            cand = now.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
            if cand <= now:
                return cand
        except ValueError:
            pass
        now = now.replace(day=1) - timedelta(days=1)


class TrafficReset:
    def __init__(self):
        self.state = {}
        self._load()

    def _load(self):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                self.state = json.load(f)
        except Exception:
            self.state = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.state, f)
        except Exception as e:
            log("save traffic state failed: %s" % e)

    def apply(self, up, down):
        if MONTH_ROTATE <= 0:
            return up, down
        key = _last_reset_date(datetime.now(), MONTH_ROTATE).strftime("%Y-%m-%d")
        if self.state.get("key") != key:
            log("traffic month rotate: %s (baseline from current counters)" % key)
            self.state = {"key": key, "base_up": up, "base_down": down}
        m_up = max(0, up - int(self.state.get("base_up") or 0))
        m_down = max(0, down - int(self.state.get("base_down") or 0))
        self.state["last_up"], self.state["last_down"] = m_up, m_down
        self._save()
        return m_up, m_down


traffic_reset = TrafficReset()


def fetch_public_ip(timeout=6):
    """通过外部服务探测真实出口公网 IP（WAN 口是 CGNAT 100.64/10 时拿不到真公网地址）"""
    for url in PUBLIC_IP_APIS:
        try:
            req = Request(url.strip(), headers={"User-Agent": "curl/8.5.0"})
            ip = _open(req, timeout).strip()
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                return ip
        except Exception:
            continue
    return ""


def fetch_public_ipv6(timeout=5):
    """通过 IPv6-only 服务探测公网 IPv6（无 IPv6 出口时返回空）"""
    for url in PUBLIC_IPV6_APIS:
        try:
            req = Request(url.strip(), headers={"User-Agent": "curl/8.5.0"})
            ip = _open(req, timeout).strip()
            if ":" in ip and re.match(r"^[0-9a-fA-F:.]+$", ip):
                return ip
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------------------
# Komari v2 客户端（JSON-RPC over HTTP）
# ---------------------------------------------------------------------------

def komari_rpc(method, params, rid):
    if not KOMARI_ENDPOINT or not KOMARI_TOKEN:
        raise RuntimeError("KOMARI_ENDPOINT / KOMARI_TOKEN not configured")
    url = KOMARI_ENDPOINT + "/api/clients/v2/rpc?token=" + quote(KOMARI_TOKEN, safe="")
    try:
        r = http_json(url, {"jsonrpc": "2.0", "method": method, "params": params, "id": rid}, timeout=30)
        if r.get("error"):
            log("komari rpc %s error: %s" % (method, r["error"]))
        return r
    except Exception as e:
        log("komari rpc %s failed: %s" % (method, e))
        return None


# ---------------------------------------------------------------------------
# 采集与上报
# ---------------------------------------------------------------------------

HW = {"cpu_name": "iKuai Router", "cores": 1, "mem_total": 0, "disk_total": 0, "ip": "", "ver": ""}


def to_pct(v):
    try:
        return float(str(v).strip().rstrip("%"))
    except (TypeError, ValueError):
        return 0.0


def find_key(obj, name):
    """在任意嵌套结构中查找指定 key（取第一个命中值）"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == name:
                return v
            r = find_key(v, name)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, name)
            if r is not None:
                return r
    return None


def send_basic_info_token(si):
    cores = len(si.get("cpu") or []) or 1
    HW["cores"] = cores
    HW["mem_total"] = int((si.get("memory") or {}).get("total") or 0) * 1024
    pub = fetch_public_ip()
    pub6 = fetch_public_ipv6()
    HW["ip"] = pub or ik.wan_ip() or si.get("ip_addr") or ""
    HW["ip6"] = pub6
    log("public IP: %s | IPv6: %s (wan: %s, lan: %s)" % (pub or "N/A", pub6 or "N/A", ik.wan_ip() or "N/A", si.get("ip_addr") or "N/A"))
    verinfo = si.get("verinfo") or {}
    HW["ver"] = verinfo.get("version") or ""
    disk_total, _ = ik.disk_usage()
    HW["disk_total"] = disk_total

    info = {
        "cpu_name": HW["cpu_name"],
        "cpu_cores": cores,
        "cpu_physical_cores": cores,
        "arch": "x86_64" if verinfo.get("sysbit") == "x64" else (verinfo.get("arch") or "x86"),
        "os": "iKuai " + HW["ver"],
        "kernel_version": verinfo.get("verstring") or HW["ver"],
        "ipv4": HW["ip"],
        "ipv6": HW.get("ip6", ""),
        "mem_total": HW["mem_total"],
        "swap_total": 0,
        "disk_total": disk_total,
        "gpu_name": "",
        "virtualization": "",
        "version": AGENT_VERSION,
    }
    komari_rpc("agent.basicInfo", {"info": info}, "basic-%d" % int(time.time()))
    log("basicInfo sent: iKuai %s | cores=%s | mem=%dMB | disk=%dGB"
        % (HW["ver"], cores, HW["mem_total"] // 1024 // 1024, disk_total // 1024 // 1024 // 1024))


def send_basic_info_password():
    hw = (ik.call("hardwareinfo", {}) or {}).get("hardwareinfo") or {}
    hp = (ik.call("homepage", {"TYPE": "sysstat"}) or {}).get("sysstat") or {}
    vs = (ik.call("sysstat", {"TYPE": "verinfo"}) or {}).get("verinfo") or {}

    HW["cpu_name"] = hw.get("cpumodel") or "iKuai Router"
    HW["cores"] = int(hw.get("cpucores") or 1)
    HW["mem_total"] = int(hw.get("memory") or 0) * 1024 * 1024
    HW["ver"] = vs.get("version", "")
    pub = fetch_public_ip()

    info = {
        "cpu_name": HW["cpu_name"],
        "cpu_cores": HW["cores"],
        "cpu_physical_cores": HW["cores"],
        "arch": "x86_64",
        "os": "iKuai " + HW["ver"],
        "kernel_version": HW["ver"],
        "ipv4": pub or hp.get("ip_addr") or "",
        "ipv6": fetch_public_ipv6(),
        "mem_total": HW["mem_total"],
        "swap_total": 0,
        "disk_total": HW["disk_total"],
        "gpu_name": "",
        "virtualization": "",
        "version": AGENT_VERSION,
    }
    komari_rpc("agent.basicInfo", {"info": info}, "basic-%d" % int(time.time()))
    log("basicInfo sent: %s | cores=%s | iKuai %s" % (HW["cpu_name"], HW["cores"], HW["ver"]))


def collect_report_token():
    si = ik.sysinfo()

    cpu_list = [to_pct(x) for x in (si.get("cpu") or [])]
    usage = round(sum(cpu_list) / len(cpu_list), 2) if cpu_list else 0.0

    mem = si.get("memory") or {}
    mem_total = int(mem.get("total") or 0) * 1024
    avail = mem.get("available")
    if avail is not None:
        mem_used = max(0, mem_total - int(avail) * 1024)
    else:
        mem_used = int(mem_total * to_pct(mem.get("used", 0)) / 100)

    disk_total, disk_used = ik.disk_usage()
    HW["disk_total"] = disk_total

    stream = si.get("stream") or {}
    load = round(usage / 100.0, 2)
    m_up, m_down = traffic_reset.apply(int(stream.get("total_up") or 0), int(stream.get("total_down") or 0))

    return {
        "cpu": {"name": HW["cpu_name"], "cores": HW["cores"], "arch": "x86_64", "usage": usage},
        "ram": {"total": mem_total, "used": mem_used},
        "swap": {"total": 0, "used": 0},
        "load": {"load1": load, "load5": round(load * 0.8, 2), "load15": round(load * 0.6, 2)},
        "disk": {"total": disk_total, "used": disk_used},
        "network": {
            "up": int(stream.get("upload") or 0),
            "down": int(stream.get("download") or 0),
            "totalUp": m_up,
            "totalDown": m_down,
        },
        "connections": {
            "tcp": int(stream.get("tcp_connect_num") or 0),
            "udp": int(stream.get("udp_connect_num") or 0),
        },
        "uptime": int(si.get("uptime") or 0),
        "process": 0,
        "message": "",
    }


def collect_report_password():
    s = ik.call("sysstat", {"TYPE": "cpu,memory,stream"}) or {}
    d = ik.call("disk_mgmt", {"TYPE": "data"}) or {}
    hp = ik.call("homepage", {"TYPE": "sysstat"}) or {}
    sysstat = hp.get("sysstat") or {}

    cpu_list = [to_pct(x) for x in (s.get("cpu") or [])]
    usage = round(sum(cpu_list) / len(cpu_list), 2) if cpu_list else 0.0

    mem = s.get("memory") or {}
    mem_total = int(mem.get("total") or 0) * 1024
    avail = mem.get("available")
    if avail is not None:
        mem_used = max(0, mem_total - int(avail) * 1024)
    else:
        mem_used = int(mem_total * to_pct(mem.get("used", 0)) / 100)

    disk_total = disk_used = 0
    for disk in (d.get("data") or []):
        for part in (disk.get("partition") or []):
            mo = part.get("mounted") or {}
            try:
                disk_total += int(mo.get("mt_total") or 0)
                disk_used += int(mo.get("mt_used") or 0)
            except (TypeError, ValueError):
                pass
    HW["disk_total"] = disk_total

    stream = s.get("stream") or {}
    load = round(usage / 100.0, 2)
    uptime = int(find_key(sysstat, "uptime") or 0)
    m_up, m_down = traffic_reset.apply(int(stream.get("total_up") or 0), int(stream.get("total_down") or 0))

    return {
        "cpu": {"name": HW["cpu_name"], "cores": HW["cores"], "arch": "x86_64", "usage": usage},
        "ram": {"total": mem_total, "used": mem_used},
        "swap": {"total": 0, "used": 0},
        "load": {"load1": load, "load5": round(load * 0.8, 2), "load15": round(load * 0.6, 2)},
        "disk": {"total": disk_total, "used": disk_used},
        "network": {
            "up": int(stream.get("upload") or 0),
            "down": int(stream.get("download") or 0),
            "totalUp": m_up,
            "totalDown": m_down,
        },
        "connections": {
            "tcp": int(stream.get("tcp_connect_num") or 0),
            "udp": int(stream.get("udp_connect_num") or 0),
        },
        "uptime": uptime,
        "process": 0,
        "message": "",
    }


def collect_report():
    if TOKEN_MODE:
        return collect_report_token()
    return collect_report_password()


def send_basic_info():
    if TOKEN_MODE:
        send_basic_info_token(ik.sysinfo())
    else:
        send_basic_info_password()


def main():
    if not KOMARI_ENDPOINT or not KOMARI_TOKEN:
        raise SystemExit("Environment KOMARI_ENDPOINT / KOMARI_TOKEN is required")

    if TOKEN_MODE:
        # Token 模式：先做一次连通性校验
        while True:
            try:
                si = ik.sysinfo()
                log("iKuai API OK (%s, %s, %s)" % (
                    IKUAI_URL, si.get("hostname", "?"), (si.get("verinfo") or {}).get("version", "?")))
                break
            except Exception as e:
                log("iKuai API error: %s, retry in 10s" % e)
                time.sleep(10)
    else:
        if not IKUAI_USERNAME or not IKUAI_PASSWORD:
            raise SystemExit("IKUAI_API_TOKEN or IKUAI_USERNAME/IKUAI_PASSWORD is required")
        while True:
            try:
                ik.login()
                break
            except IkuaiLoginLocked as e:
                log("iKuai account locked, retry in %ss: %s" % (LOCK_BACKOFF, e))
                time.sleep(LOCK_BACKOFF)
            except Exception as e:
                log("login error: %s, retry in 10s" % e)
                time.sleep(10)

    last_basic = 0.0
    n = 0
    while True:
        n += 1
        try:
            report = collect_report()
            if time.time() - last_basic >= BASIC_INTERVAL:
                send_basic_info()
                last_basic = time.time()
            komari_rpc("agent.report", {"report": report, "ack_event_ids": []}, "r-%d" % n)
        except IkuaiLoginLocked as e:
            log("iKuai account locked, retry in %ss: %s" % (LOCK_BACKOFF, e))
            time.sleep(LOCK_BACKOFF)
        except Exception as e:
            log("collect error: %s" % e)
            traceback.print_exc()
            if not TOKEN_MODE:
                try:
                    ik.login()
                except Exception as e2:
                    log("re-login failed: %s" % e2)
                    time.sleep(10)
        time.sleep(REPORT_INTERVAL)


if __name__ == "__main__":
    main()
