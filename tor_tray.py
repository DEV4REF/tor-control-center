#!/usr/bin/env python3
"""
🧅 Tor Control Center v2
Professional KDE/GNOME system tray — real Tor monitoring & control
Author: tor_tray v2
Requires: python3-pyqt6, requests[socks]

مرکز کنترل Tor — نمایشگر و کنترل‌کنندهٔ واقعی Tor روی سیستم‌تری KDE/GNOME.
شامل: روشن/خاموش‌کردن سرویس Tor، هویت جدید، کیل‌سوییچ، پراکسی شفاف،
مدیریت بریج/ترنسپورت ضدسانسور، و پنل لاگ.
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import base64
import subprocess
import threading
import logging
import webbrowser
from datetime import datetime
from collections import deque
from dataclasses import dataclass
from typing import Optional

# ── Enforce PyQt6 ─────────────────────────────────────────────────────────────
try:
    from PyQt6.QtWidgets import (
        QApplication, QSystemTrayIcon, QMenu, QWidget,
        QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTextEdit, QFrame, QGridLayout, QComboBox, QDialog,
    )
    from PyQt6.QtCore import (
        Qt, QTimer, pyqtSignal, QObject, QPoint,
    )
    from PyQt6.QtGui import (
        QIcon, QPixmap, QPainter, QColor, QFont, QBrush,
        QPen, QAction,
    )
except ImportError:
    print("ERROR: PyQt6 not found.\n  pip3 install PyQt6 --break-system-packages")
    sys.exit(1)

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    print("WARNING: requests not found.  pip3 install requests[socks]")

# ── Config dir / files ────────────────────────────────────────────────────────
CONFIG_DIR   = os.path.join(os.path.expanduser("~"), ".config", "tor-control-center")
CONFIG_FILE  = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE     = os.path.join(CONFIG_DIR, "tor_tray.log")

# ── Logging (console + rotating file) ─────────────────────────────────────────
os.makedirs(CONFIG_DIR, exist_ok=True)
log = logging.getLogger("tor_tray")
log.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter(
    "%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S"
))
log.addHandler(_console)

try:
    from logging.handlers import RotatingFileHandler
    _file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    _file_handler.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    log.addHandler(_file_handler)
except Exception as _e:
    print(f"WARNING: could not set up file logging: {_e}")

# ── Default constants (overridable via ~/.config/tor-control-center/config.json)
_DEFAULTS = {
    "tor_socks_host":   "127.0.0.1",
    "tor_socks_port":   9050,
    "tor_control_port": 9051,
    "tor_trans_port":   9040,
    "tor_dns_port":     5353,
    "tor_check_url":    "https://check.torproject.org/api/ip",
    "geoip_url":        "https://ipapi.co/{ip}/json/",
    "direct_ip_url":    "https://api.ipify.org?format=json",
    "poll_normal_sec":  8,
    "poll_fast_sec":    2,
    "request_timeout":  10,
    "log_maxlen":       300,
}


def _load_config() -> dict:
    """Load user overrides from ~/.config/tor-control-center/config.json, if present.

    (تنظیمات کاربر رو از کانفیگ خارجی می‌خونه، اگه وجود داشته باشه؛ در غیر
    این صورت مقادیر پیش‌فرض استفاده میشه.)
    """
    cfg = dict(_DEFAULTS)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            if isinstance(user_cfg, dict):
                cfg.update({k: v for k, v in user_cfg.items() if k in _DEFAULTS})
        except Exception as e:
            log.warning(f"Failed to read {CONFIG_FILE}: {e} — using defaults")
    return cfg


_CFG = _load_config()

# ── Constants ─────────────────────────────────────────────────────────────────
TOR_SOCKS_HOST    = _CFG["tor_socks_host"]
TOR_SOCKS_PORT    = _CFG["tor_socks_port"]
TOR_CONTROL_PORT  = _CFG["tor_control_port"]
TOR_TRANS_PORT    = _CFG["tor_trans_port"]
TOR_DNS_PORT      = _CFG["tor_dns_port"]

TOR_CHECK_URL     = _CFG["tor_check_url"]
GEOIP_URL         = _CFG["geoip_url"]
DIRECT_IP_URL     = _CFG["direct_ip_url"]

POLL_NORMAL_SEC   = _CFG["poll_normal_sec"]
POLL_FAST_SEC     = _CFG["poll_fast_sec"]
REQUEST_TIMEOUT   = _CFG["request_timeout"]
LOG_MAXLEN        = _CFG["log_maxlen"]

# iptables comment tags used to identify our own rules (for reliable status
# detection across restarts, instead of trusting in-memory UI state).
# (تگ‌هایی که رو قوانین iptables می‌ذاریم تا مطمئن بشیم قوانین خودمون رو
# داریم می‌بینیم، نه یه حدس از وضعیت حافظه‌ای برنامه.)
KS_TAG = "tcc_killswitch"
TP_TAG = "tcc_transproxy"

# ── Palette ───────────────────────────────────────────────────────────────────
P = {
    "bg":        "#0d1117",
    "surface":   "#161b22",
    "surface2":  "#21262d",
    "border":    "#30363d",
    "green":     "#3fb950",
    "purple":    "#a371f7",
    "orange":    "#f0883e",
    "red":       "#f85149",
    "blue":      "#58a6ff",
    "text":      "#e6edf3",
    "muted":     "#8b949e",
    "dim":       "#484f58",
}

# ── State dataclass ───────────────────────────────────────────────────────────
@dataclass
class TorState:
    mode:          str   = "init"       # init | disconnected | connecting | connected | leak
    tor_running:   bool  = False
    socks_up:      bool  = False
    is_tor_exit:   bool  = False
    exit_ip:       str   = "—"
    real_ip:       str   = "—"
    country:       str   = "—"
    country_code:  str   = ""
    isp:           str   = "—"
    latency_ms:    Optional[int] = None
    leak:          bool  = False
    ts:            str   = ""
    error:         str   = ""

    def flag(self) -> str:
        cc = self.country_code
        if len(cc) != 2:
            return "🌐"
        return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)

    def mode_label(self) -> str:
        return {
            "init":         "Initializing…",
            "disconnected": "Disconnected",
            "connecting":   "Building circuit…",
            "connected":    "Connected via Tor",
            "leak":         "IP LEAK DETECTED",
        }.get(self.mode, self.mode.upper())

    def mode_color(self) -> str:
        return {
            "init":         P["muted"],
            "disconnected": P["red"],
            "connecting":   P["orange"],
            "connected":    P["green"],
            "leak":         P["red"],
        }.get(self.mode, P["muted"])


# ══════════════════════════════════════════════════════════════════════════════
#  TorProbe  — all network checks, runs in background thread
# ══════════════════════════════════════════════════════════════════════════════
class TorProbe(QObject):
    state_ready = pyqtSignal(object)   # TorState
    log_line    = pyqtSignal(str, str) # level, message

    def __init__(self) -> None:
        super().__init__()
        self._active  = False
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> None:
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="TorProbe")
        self._thread.start()

    def stop(self) -> None:
        self._active = False

    def probe_now(self) -> None:
        """Trigger an immediate out-of-cycle probe."""
        t = threading.Thread(target=self._single_probe, daemon=True)
        t.start()

    # ── main loop ─────────────────────────────────────────────────────────────
    def _loop(self) -> None:
        while self._active:
            state = self._single_probe()
            interval = POLL_FAST_SEC if state.mode in ("connecting", "init") else POLL_NORMAL_SEC
            time.sleep(interval)

    def _single_probe(self) -> TorState:
        s = TorState(ts=datetime.now().strftime("%H:%M:%S"))
        try:
            s.tor_running = self._service_running()
            s.socks_up    = self._socks_reachable()

            if not s.tor_running and not s.socks_up:
                s.mode = "disconnected"
                self.state_ready.emit(s)
                return s

            if not s.socks_up:
                s.mode = "connecting"
                self.state_ready.emit(s)
                return s

            # Check routing via Tor
            tor_check = self._tor_check()
            if tor_check is None:
                s.mode = "connecting"
                self.state_ready.emit(s)
                return s

            s.exit_ip     = tor_check.get("IP", "—")
            s.is_tor_exit = tor_check.get("IsTor", False)

            # Real IP (direct)
            s.real_ip = self._direct_ip() or "—"

            # Leak detection
            if s.real_ip != "—" and s.exit_ip != "—":
                s.leak = (s.real_ip == s.exit_ip)

            # GeoIP on exit node
            if s.exit_ip != "—":
                geo = self._geoip(s.exit_ip)
                s.country      = geo.get("country", "—")
                s.country_code = geo.get("countryCode", "")
                s.isp          = geo.get("isp") or geo.get("org", "—")

            # Latency
            s.latency_ms = self._latency()

            # Final mode
            if s.leak:
                s.mode = "leak"
                self.log_line.emit("WARN", f"IP LEAK: real={s.real_ip}  exit={s.exit_ip}")
            elif s.is_tor_exit:
                s.mode = "connected"
            else:
                s.mode = "connecting"

        except Exception as exc:
            s.mode  = "disconnected"
            s.error = str(exc)
            log.exception("Probe error")

        self.state_ready.emit(s)
        return s

    # ── checks ────────────────────────────────────────────────────────────────
    @staticmethod
    def _service_running() -> bool:
        # systemctl
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", "tor"],
                timeout=3
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
        # pgrep fallback
        try:
            r = subprocess.run(["pgrep", "-x", "tor"], capture_output=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _socks_reachable() -> bool:
        try:
            with socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=2):
                return True
        except OSError:
            return False

    @staticmethod
    def _tor_check() -> Optional[dict]:
        if not _HAS_REQUESTS:
            return None
        proxies = {
            "http":  f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        }
        try:
            r = requests.get(TOR_CHECK_URL, proxies=proxies, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    @staticmethod
    def _direct_ip() -> Optional[str]:
        if not _HAS_REQUESTS:
            return None
        try:
            r = requests.get(DIRECT_IP_URL, timeout=5)
            r.raise_for_status()
            return r.json().get("ip")
        except Exception:
            return None

    @staticmethod
    def _geoip(ip: str) -> dict:
        """Look up GeoIP for the exit node, routed *through Tor* over HTTPS.

        Previously this hit a plaintext (http://) endpoint directly on the
        clear path — leaking the query to a third party outside Tor, and
        prone to being blocked outright when the kill switch is active
        (since only the Tor process itself is allowed to egress). Routing
        via the SOCKS proxy keeps it consistent with the rest of the app.

        (جست‌وجوی موقعیت جغرافیایی exit node — از داخل خود Tor و روی
        HTTPS، نه مستقیم و plaintext مثل قبل.)
        """
        if not _HAS_REQUESTS:
            return {}
        proxies = {
            "http":  f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        }
        try:
            r = requests.get(GEOIP_URL.format(ip=ip), proxies=proxies, timeout=6)
            r.raise_for_status()
            data = r.json()
            if data.get("error"):
                return {}
            return {
                "country":     data.get("country_name", "—"),
                "countryCode": data.get("country_code", ""),
                "isp":         data.get("org") or data.get("asn") or "—",
            }
        except Exception:
            return {}

    @staticmethod
    def _latency() -> Optional[int]:
        if not _HAS_REQUESTS:
            return None
        proxies = {
            "http":  f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        }
        try:
            t0 = time.monotonic()
            requests.get("https://check.torproject.org/", proxies=proxies, timeout=REQUEST_TIMEOUT)
            return int((time.monotonic() - t0) * 1000)
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  TorControl  — subprocess-based service & firewall control
# ══════════════════════════════════════════════════════════════════════════════
class TorControl:
    """Subprocess-based service & firewall control.

    All privileged operations go through a single narrow helper script
    (`HELPER_PATH`, installed by setup.sh) instead of granting passwordless
    sudo on `iptables`/`ip6tables`/`tee` directly. Those tools accept
    arbitrary arguments, so a blanket `NOPASSWD: /sbin/iptables` rule is
    effectively unrestricted root access via the firewall (flush any
    chain, redirect any traffic, etc). The helper hard-codes the specific
    whitelisted actions this app needs (case-matched, no shell
    interpolation of user input into commands), and sudoers only allows
    that one exact path — a meaningfully smaller trusted surface.

    (کنترل سرویس Tor و فایروال از طریق subprocess. تمام عملیات‌های نیازمند
    دسترسی روت از یه اسکریپت واسط باریک (tcc-helper) رد میشن، نه از طریق
    دسترسی passwordless مستقیم به iptables/ip6tables. این اسکریپت واسط فقط
    همون چند عملیات مشخص و از پیش validate-شده رو انجام میده.)
    """

    HELPER_PATH = "/usr/local/sbin/tcc-helper"

    _tor_user_cache: Optional[str] = None
    _ipv6_available: Optional[bool] = None
    _helper_available: Optional[bool] = None

    @staticmethod
    def _run(*args: str, input_text: Optional[str] = None) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                list(args), capture_output=True, text=True, timeout=15,
                input=input_text,
            )
            out = (r.stdout + r.stderr).strip()
            return r.returncode == 0, out
        except Exception as e:
            return False, str(e)

    @classmethod
    def _helper(cls, *args: str, input_text: Optional[str] = None) -> tuple[bool, str]:
        return cls._run("sudo", cls.HELPER_PATH, *args, input_text=input_text)

    @classmethod
    def helper_available(cls) -> bool:
        if cls._helper_available is None:
            cls._helper_available = os.path.isfile(cls.HELPER_PATH)
            if not cls._helper_available:
                log.warning(
                    f"{cls.HELPER_PATH} not found — run setup.sh to install the "
                    f"privileged helper before using firewall features."
                )
        return cls._helper_available

    @classmethod
    def start(cls)   -> tuple[bool, str]: return cls._helper("tor-start")
    @classmethod
    def stop(cls)    -> tuple[bool, str]: return cls._helper("tor-stop")
    @classmethod
    def restart(cls) -> tuple[bool, str]: return cls._helper("tor-restart")

    # ── Tor system-user detection ────────────────────────────────────────────
    @classmethod
    def tor_user(cls) -> str:
        """Detect which system user Tor runs as.

        Distros disagree: Debian/Ubuntu use 'debian-tor', Arch/Fedora often
        use plain 'tor', some minimal images use '_tor'. Hard-coding
        'debian-tor' meant the kill switch / transparent proxy would
        silently exempt the wrong user (or nobody) on non-Debian systems,
        defeating the whole point of a kill switch.

        (تشخیص یوزر سیستمیِ Tor — چون توزیع‌های مختلف لینوکس اسم متفاوتی
        براش استفاده می‌کنن، هاردکد کردن یه اسم ثابت باعث میشد کیل‌سوییچ
        رو سیستم‌های غیر-Debian درست کار نکنه.)
        """
        if cls._tor_user_cache:
            return cls._tor_user_cache
        for candidate in ("debian-tor", "tor", "_tor"):
            ok, _ = cls._run("id", "-u", candidate)
            if ok:
                cls._tor_user_cache = candidate
                return candidate
        log.warning("Could not detect Tor's system user — defaulting to 'debian-tor'")
        cls._tor_user_cache = "debian-tor"
        return cls._tor_user_cache

    @classmethod
    def _has_ip6tables(cls) -> bool:
        if cls._ipv6_available is None:
            ok, _ = cls._helper("ipv6-available")
            cls._ipv6_available = ok
            if not ok:
                log.warning("ip6tables not available — IPv6 leak protection disabled")
        return cls._ipv6_available

    # ── control port auth ────────────────────────────────────────────────────
    @staticmethod
    def _cookie_auth_hex() -> Optional[str]:
        """Read Tor's control-port auth cookie, if cookie auth is enabled."""
        for path in (
            "/run/tor/control.authcookie",
            "/var/run/tor/control.authcookie",
            "/var/lib/tor/control_auth_cookie",
        ):
            try:
                with open(path, "rb") as f:
                    return f.read().hex()
            except OSError:
                continue
        return None

    @classmethod
    def new_identity(cls) -> tuple[bool, str]:
        """Send NEWNYM via control port, fall back to restart.

        Tries cookie auth first (the default on most distros when
        CookieAuthentication is on); falls back to a blank AUTHENTICATE
        for setups with no auth configured. Previously this only ever sent
        an empty AUTHENTICATE, which silently fails whenever cookie auth is
        enabled (the common case) and always fell through to a disruptive
        full service restart instead of a cheap NEWNYM signal.

        (درخواست هویت جدید (مدار جدید Tor) از طریق control port؛ اگه شکست
        بخوره، به‌عنوان fallback کل سرویس رو ری‌استارت می‌کنه.)
        """
        try:
            s = socket.socket()
            s.settimeout(4)
            s.connect(("127.0.0.1", TOR_CONTROL_PORT))

            cookie_hex = cls._cookie_auth_hex()
            if cookie_hex:
                s.sendall(f'AUTHENTICATE {cookie_hex}\r\n'.encode())
            else:
                s.sendall(b'AUTHENTICATE ""\r\n')
            auth_resp = s.recv(512).decode(errors="replace")
            if "250" not in auth_resp:
                s.close()
                return False, f"Control port auth failed: {auth_resp.strip()}"

            s.sendall(b'SIGNAL NEWNYM\r\nQUIT\r\n')
            resp = s.recv(512).decode(errors="replace")
            s.close()
            if "250" in resp:
                return True, "New circuit requested via control port"
            return False, f"Control port response: {resp}"
        except Exception as e:
            log.warning(f"Control port failed ({e}), falling back to restart")
            return cls.restart()

    # ── kill switch ──────────────────────────────────────────────────────────
    @classmethod
    def killswitch_on(cls) -> tuple[bool, str]:
        """Block all non-Tor outbound traffic (IPv4 + IPv6) and lock DNS.

        IPv6 was previously left completely unfiltered — any host with
        IPv6 connectivity could bypass the "kill switch" entirely over v6.
        The helper now also blocks IPv6 egress, and additionally
        immutable-locks /etc/resolv.conf (`chattr +i`) so nothing on the
        system (NetworkManager, systemd-resolved, a VPN client, etc.) can
        silently repoint DNS away from the loopback resolver while
        protection is meant to be active.

        (کیل‌سوییچ رو روشن می‌کنه: بلاک‌کردن هر ترافیک غیر-Tor روی IPv4 و
        IPv6، به‌علاوه قفل‌کردن DNS تا هیچ سرویسی نتونه resolver رو عوض
        کنه و از این مسیر لو بره.)
        """
        if not cls.helper_available():
            return False, f"Privileged helper missing at {cls.HELPER_PATH} — run setup.sh"
        tor_user = cls.tor_user()
        ok, out = cls._helper("killswitch-on", tor_user)
        if not ok:
            return False, f"helper error: {out}"
        cls._helper("dns-lock")
        v6_note = "" if cls._has_ip6tables() else " WARNING: ip6tables unavailable, IPv6 is NOT protected."
        return True, f"Kill switch ON (tor user: {tor_user}), DNS locked.{v6_note}"

    @classmethod
    def killswitch_off(cls) -> tuple[bool, str]:
        """Remove kill switch rules and unlock DNS."""
        if not cls.helper_available():
            return False, f"Privileged helper missing at {cls.HELPER_PATH} — run setup.sh"
        ok, out = cls._helper("killswitch-off")
        cls._helper("dns-unlock")
        return ok, out or "Kill switch OFF, DNS unlocked."

    @classmethod
    def killswitch_status(cls) -> bool:
        """Query the real firewall state rather than trusting in-memory UI state.

        Without this, a service/system restart clears the actual firewall
        rules while the UI still shows "ON" — the user believes they're
        protected when they aren't.
        """
        if not cls.helper_available():
            return False
        ok, _ = cls._helper("killswitch-status")
        return ok

    # ── transparent proxy ────────────────────────────────────────────────────
    @classmethod
    def transparent_proxy_on(cls) -> tuple[bool, str]:
        """Route all TCP + DNS through Tor transparently (IPv4); block IPv6.

        Tor's TransPort here only handles IPv4. IPv6-capable destinations
        would previously go out directly, unproxied and unblocked. Since
        IPv6 can't be transparently tunnelled through this TransPort setup,
        the helper blocks it outright instead of letting it leak.

        (پراکسی شفاف رو روشن می‌کنه: تمام ترافیک TCP و DNS سیستم از داخل
        Tor رد میشه (فقط IPv4)، و IPv6 برای جلوگیری از لو رفتن بلاک میشه.)
        """
        if not cls.helper_available():
            return False, f"Privileged helper missing at {cls.HELPER_PATH} — run setup.sh"
        tor_user = cls.tor_user()
        ok, out = cls._helper("tp-on", tor_user, str(TOR_DNS_PORT), str(TOR_TRANS_PORT))
        if not ok:
            return False, f"helper error: {out}"
        v6_note = "" if cls._has_ip6tables() else " WARNING: ip6tables unavailable, IPv6 is NOT protected."
        return True, f"Transparent proxy ON — IPv4 tunnelled (tor user: {tor_user}).{v6_note}"

    @classmethod
    def transparent_proxy_off(cls) -> tuple[bool, str]:
        if not cls.helper_available():
            return False, f"Privileged helper missing at {cls.HELPER_PATH} — run setup.sh"
        ok, out = cls._helper("tp-off")
        return ok, out or "Transparent proxy OFF"

    @classmethod
    def transparent_proxy_status(cls) -> bool:
        """Query the real firewall state instead of trusting UI state."""
        if not cls.helper_available():
            return False
        ok, _ = cls._helper("tp-status")
        return ok

    # ── anti-censorship: pluggable transports / bridges ─────────────────────
    PT_BINARIES = {
        "obfs4":      ["obfs4proxy"],
        "meek-azure": ["meek-client"],
        "snowflake":  ["snowflake-client"],
    }

    @classmethod
    def detect_pt_binaries(cls) -> dict:
        """Which pluggable-transport binaries are actually installed.

        Bridges are useless without their transport binary — surfacing
        this up front avoids the confusing failure mode of Tor silently
        refusing to build circuits with no obvious explanation.
        """
        import shutil as _shutil
        found = {}
        for name, bins in cls.PT_BINARIES.items():
            found[name] = next((b for b in bins if _shutil.which(b)), None)
        return found

    @classmethod
    def apply_bridges(cls, transport: str, bridge_lines: list[str]) -> tuple[bool, str]:
        """Write a managed Bridge/ClientTransportPlugin block into torrc and restart Tor.

        Bridge fingerprints/certs are not something this app invents or
        hard-codes — real, current ones must come from
        https://bridges.torproject.org (or `moat`/Tor Browser) and be
        pasted in by the user, since baked-in defaults go stale and a
        wrong hard-coded fingerprint just fails silently.

        (خط‌های Bridge رو داخل torrc می‌نویسه و Tor رو ری‌استارت می‌کنه.
        این برنامه هیچ fingerprint ای رو خودش نمی‌سازه — چون این مقادیر
        دائم تغییر می‌کنن و باید از bridges.torproject.org گرفته بشن.)
        """
        if not cls.helper_available():
            return False, f"Privileged helper missing at {cls.HELPER_PATH} — run setup.sh"
        if not bridge_lines:
            return cls.clear_bridges()

        pt_bin_map = cls.detect_pt_binaries()
        lines = ["UseBridges 1"]
        if transport != "custom":
            binary = pt_bin_map.get(transport)
            if not binary:
                pkg_hint = {
                    "obfs4": "obfs4proxy", "meek-azure": "meek-client", "snowflake": "snowflake-client"
                }.get(transport, transport)
                return False, (f"{pkg_hint} not installed — install it first "
                                f"(see setup.sh / your package manager), then apply bridges again.")
            import shutil as _shutil
            path = _shutil.which(binary)
            lines.append(f"ClientTransportPlugin {transport} exec {path}")

        for raw in bridge_lines:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            lines.append(raw if raw.startswith("Bridge ") else f"Bridge {raw}")

        content = "\n".join(lines)
        b64 = base64.b64encode(content.encode()).decode()
        ok, out = cls._helper("write-bridges", input_text=b64)
        if not ok:
            return False, f"helper error: {out}"
        return True, f"Bridges applied ({transport}, {len(bridge_lines)} line(s)) — Tor restarted"

    @classmethod
    def clear_bridges(cls) -> tuple[bool, str]:
        """Remove the managed bridge block from torrc — back to a direct connection."""
        if not cls.helper_available():
            return False, f"Privileged helper missing at {cls.HELPER_PATH} — run setup.sh"
        ok, out = cls._helper("write-bridges", input_text="")
        if not ok:
            return False, f"helper error: {out}"
        return True, "Bridges cleared — Tor will connect directly, restarted"


# ══════════════════════════════════════════════════════════════════════════════
#  Icons
# ══════════════════════════════════════════════════════════════════════════════
def _make_icon(mode: str, size: int = 22) -> QIcon:
    color_map = {
        "connected":    P["green"],
        "connecting":   P["orange"],
        "disconnected": P["red"],
        "leak":         P["red"],
        "init":         P["muted"],
    }
    color = QColor(color_map.get(mode, P["muted"]))

    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p  = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Ring
    pen = QPen(color, 2.2)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(2, 2, size - 4, size - 4)

    # Inner state
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(color))
    c = size // 2
    if mode == "connected":
        r = size // 5
        p.drawEllipse(c - r, c - r, r * 2, r * 2)
    elif mode == "connecting":
        r = size // 6
        p.drawEllipse(c - r, c - r, r * 2, r * 2)
    elif mode in ("disconnected", "leak"):
        pen2 = QPen(color, 2.5)
        p.setPen(pen2)
        m = size // 4
        p.drawLine(m, m, size - m, size - m)
        p.drawLine(size - m, m, m, size - m)

    p.end()
    return QIcon(px)


# ══════════════════════════════════════════════════════════════════════════════
#  BridgesDialog  — pluggable-transport / anti-censorship bridge management
# ══════════════════════════════════════════════════════════════════════════════
class BridgesDialog(QDialog):
    """Lets the user switch Tor to connect via a bridge + pluggable transport.

    Real bridge lines (with current fingerprints/certs) are NOT hard-coded
    here — they go stale and a wrong baked-in value just fails silently.
    The user fetches current ones from https://bridges.torproject.org (a
    button below opens it) and pastes them in.

    (دیالوگ مدیریت بریج — برای وصل‌شدن به Tor از طریق بریج/ترنسپورت
    ضدسانسور مثل obfs4، meek-azure یا Snowflake. مقادیر بریج رو خود کاربر
    از bridges.torproject.org می‌گیره و اینجا پیست می‌کنه.)
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Bridges / Anti-Censorship")
        self.setFixedSize(420, 460)
        self.setStyleSheet(f"""
            QDialog {{ background: {P['bg']}; }}
            QLabel {{ color: {P['text']}; font-family: 'JetBrains Mono', monospace; font-size: 11px; }}
            QComboBox, QTextEdit {{
                background: {P['surface']}; color: {P['text']};
                border: 1px solid {P['border']}; border-radius: 6px; padding: 4px;
                font-family: 'JetBrains Mono', monospace; font-size: 11px;
            }}
            QPushButton {{
                border-radius: 7px; font-size: 11px; font-weight: 600;
                border: 1px solid {P['border']}; padding: 6px 10px;
                background: {P['surface2']}; color: {P['text']};
            }}
            QPushButton:hover {{ background: {P['border']}; }}
        """)

        v = QVBoxLayout(self)

        info = QLabel(
            "Route Tor through a bridge to hide the fact that you're using Tor "
            "from your ISP/network (useful under DPI-based censorship).\n\n"
            "1. Pick a transport below.\n"
            "2. Get current bridge lines from bridges.torproject.org.\n"
            "3. Paste them (one per line) and click Apply."
        )
        info.setWordWrap(True)
        v.addWidget(info)

        pt_found = TorControl.detect_pt_binaries()
        self._combo = QComboBox()
        for key, label in [
            ("custom", "Direct Bridge line(s) (any transport)"),
            ("obfs4", f"obfs4 {'✓ installed' if pt_found.get('obfs4') else '✗ not installed'}"),
            ("meek-azure", f"meek-azure {'✓ installed' if pt_found.get('meek-azure') else '✗ not installed'}"),
            ("snowflake", f"snowflake {'✓ installed' if pt_found.get('snowflake') else '✗ not installed'}"),
        ]:
            self._combo.addItem(label, userData=key)
        v.addWidget(self._combo)

        open_btn = QPushButton("🌐  Open bridges.torproject.org")
        open_btn.clicked.connect(lambda: webbrowser.open("https://bridges.torproject.org/"))
        v.addWidget(open_btn)

        v.addWidget(QLabel("Bridge line(s):"))
        self._text = QTextEdit()
        self._text.setPlaceholderText(
            "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0\n"
            "(paste one or more lines from bridges.torproject.org)"
        )
        v.addWidget(self._text)

        btn_row = QHBoxLayout()
        apply_btn = QPushButton("✓  Apply")
        apply_btn.clicked.connect(self._apply)
        clear_btn = QPushButton("✕  Clear (direct connection)")
        clear_btn.clicked.connect(self._clear)
        btn_row.addWidget(apply_btn)
        btn_row.addWidget(clear_btn)
        v.addLayout(btn_row)

        self._status = QLabel("")
        self._status.setWordWrap(True)
        v.addWidget(self._status)

    def _apply(self) -> None:
        transport = self._combo.currentData()
        lines = [ln for ln in self._text.toPlainText().splitlines() if ln.strip()]
        if not lines:
            self._status.setText("⚠ No bridge lines entered.")
            return
        ok, out = TorControl.apply_bridges(transport, lines)
        self._status.setText(("✓ " if ok else "✗ ") + out)

    def _clear(self) -> None:
        ok, out = TorControl.clear_bridges()
        self._status.setText(("✓ " if ok else "✗ ") + out)
        if ok:
            self._text.clear()


# ══════════════════════════════════════════════════════════════════════════════
#  Dashboard  — main popup window
# ══════════════════════════════════════════════════════════════════════════════
class Dashboard(QWidget):

    def __init__(self, probe: TorProbe) -> None:
        super().__init__()
        self.probe = probe
        # Query the real firewall state instead of assuming OFF. If the app
        # (or system) restarted while the kill switch / transparent proxy
        # was active, the iptables rules survive but the old code always
        # initialized to False here — showing "protection off" in the UI
        # while the machine was actually still locked down (or vice versa
        # after a manual `iptables -F`).
        # (وضعیت واقعی فایروال رو موقع شروع برنامه می‌خونیم، نه این‌که فرض
        # کنیم خاموشه — چون بعد از ری‌استارت ممکنه قوانین قبلی هنوز فعال
        # باشن.)
        self._ks_on    = TorControl.killswitch_status()
        self._tp_on    = TorControl.transparent_proxy_status()
        self._drag_pos: Optional[QPoint] = None
        self._log_buf: deque[str] = deque(maxlen=LOG_MAXLEN)

        self.setWindowTitle("Tor Control Center")
        self.setFixedSize(460, 600)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._build()
        self._style()
        self._sync_toggle_buttons()

    # ── build ─────────────────────────────────────────────────────────────────
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self._card = QFrame(self)
        self._card.setObjectName("card")
        self._card.setFixedSize(460, 600)
        root.addWidget(self._card)

        lay = QVBoxLayout(self._card)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(10)

        # ── title bar ─────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        onion = QLabel("🧅")
        onion.setFont(QFont("Noto Emoji", 18))
        title = QLabel("Tor Control Center")
        title.setObjectName("title")
        self._close = QPushButton("✕")
        self._close.setObjectName("closeBtn")
        self._close.setFixedSize(24, 24)
        self._close.clicked.connect(self.hide)
        tb.addWidget(onion)
        tb.addSpacing(6)
        tb.addWidget(title)
        tb.addStretch()
        tb.addWidget(self._close)
        lay.addLayout(tb)

        # ── status banner ─────────────────────────────────────────────────────
        banner = QFrame()
        banner.setObjectName("banner")
        banner.setFixedHeight(58)
        bl = QHBoxLayout(banner)
        bl.setContentsMargins(14, 6, 14, 6)

        self._dot   = QLabel("●")
        self._dot.setFont(QFont("Monospace", 18))
        self._mode  = QLabel("Initializing…")
        self._mode.setObjectName("modeLabel")
        self._ts    = QLabel("")
        self._ts.setObjectName("tsLabel")
        self._ts.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        bl.addWidget(self._dot)
        bl.addSpacing(8)
        bl.addWidget(self._mode, 1)
        bl.addWidget(self._ts)
        lay.addWidget(banner)

        # ── info grid ─────────────────────────────────────────────────────────
        grid_frame = QFrame()
        grid_frame.setObjectName("surface")
        grid = QGridLayout(grid_frame)
        grid.setContentsMargins(12, 8, 12, 8)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)

        def row(label: str, r: int) -> QLabel:
            k = QLabel(label)
            k.setObjectName("key")
            v = QLabel("—")
            v.setObjectName("val")
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(k, r, 0)
            grid.addWidget(v, r, 1)
            return v

        self._v_exit    = row("Exit Node",   0)
        self._v_real    = row("Real IP",     1)
        self._v_country = row("Country",     2)
        self._v_isp     = row("ISP / Org",   3)
        self._v_latency = row("Latency",     4)
        self._v_route   = row("Route",       5)
        lay.addWidget(grid_frame)

        # ── controls ──────────────────────────────────────────────────────────
        g = QGridLayout()
        g.setSpacing(7)

        self._b_start   = self._mk_btn("▶  Start",          "green",  self._act_start)
        self._b_stop    = self._mk_btn("■  Stop",           "red",    self._act_stop)
        self._b_restart = self._mk_btn("↺  Restart",        "blue",   self._act_restart)
        self._b_newid   = self._mk_btn("⟳  New Identity",  "purple", self._act_newid)
        self._b_ks      = self._mk_btn("🔒  Kill Switch",   "orange", self._act_ks)
        self._b_tp      = self._mk_btn("⬡  Transparent",   "teal",   self._act_tp)
        self._b_bridges = self._mk_btn("🌉  Bridges",       "dim",    self._open_bridges)
        self._b_probe   = self._mk_btn("⟳  Check Now",     "dim",    self._act_probe)

        g.addWidget(self._b_start,   0, 0)
        g.addWidget(self._b_stop,    0, 1)
        g.addWidget(self._b_restart, 1, 0)
        g.addWidget(self._b_newid,   1, 1)
        g.addWidget(self._b_ks,      2, 0)
        g.addWidget(self._b_tp,      2, 1)
        g.addWidget(self._b_bridges, 3, 0)
        g.addWidget(self._b_probe,   3, 1)
        lay.addLayout(g)

        # ── log ───────────────────────────────────────────────────────────────
        hdr = QLabel("◆  Event Log")
        hdr.setObjectName("sectionHdr")
        lay.addWidget(hdr)

        self._log = QTextEdit()
        self._log.setObjectName("logBox")
        self._log.setReadOnly(True)
        self._log.setFixedHeight(100)
        lay.addWidget(self._log)

        # drag support on card
        self._card.mousePressEvent   = self._mp
        self._card.mouseMoveEvent    = self._mm
        self._card.mouseReleaseEvent = self._mr

    def _mk_btn(self, text: str, variant: str, slot) -> QPushButton:
        b = QPushButton(text)
        b.setObjectName(f"btn_{variant}")
        b.setFixedHeight(34)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.clicked.connect(slot)
        return b

    # ── style ─────────────────────────────────────────────────────────────────
    def _style(self) -> None:
        self.setStyleSheet(f"""
        * {{
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            color: {P['text']};
        }}
        #card {{
            background: {P['bg']};
            border: 1px solid {P['border']};
            border-radius: 14px;
        }}
        #title {{
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        #closeBtn {{
            background: transparent;
            border: none;
            color: {P['muted']};
            font-size: 13px;
            border-radius: 5px;
            padding: 0;
        }}
        #closeBtn:hover {{ background: {P['red']}; color: white; }}

        #banner {{
            background: {P['surface']};
            border: 1px solid {P['border']};
            border-radius: 9px;
        }}
        #modeLabel {{ font-size: 14px; font-weight: 700; }}
        #tsLabel   {{ color: {P['muted']}; font-size: 10px; }}

        #surface {{
            background: {P['surface']};
            border: 1px solid {P['border']};
            border-radius: 9px;
        }}
        #key {{ color: {P['muted']}; font-size: 11px; min-width: 80px; }}
        #val {{ font-size: 12px; font-weight: 600; }}

        #sectionHdr {{
            color: {P['dim']};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }}
        #logBox {{
            background: {P['surface']};
            border: 1px solid {P['border']};
            border-radius: 8px;
            color: {P['muted']};
            font-size: 10px;
            padding: 5px 8px;
        }}

        QPushButton {{
            border-radius: 7px;
            font-size: 11px;
            font-weight: 600;
            border: 1px solid;
            padding: 0 10px;
        }}
        #btn_green  {{ background:#1a3326; color:{P['green']};  border-color:#2d5a40; }}
        #btn_green:hover  {{ background:#23472e; }}
        #btn_red    {{ background:#3b1219; color:{P['red']};    border-color:#6b2228; }}
        #btn_red:hover    {{ background:#4d1820; }}
        #btn_blue   {{ background:#1a2840; color:{P['blue']};   border-color:#2d4a6b; }}
        #btn_blue:hover   {{ background:#233555; }}
        #btn_purple {{ background:#261a40; color:{P['purple']}; border-color:#4a2d6b; }}
        #btn_purple:hover {{ background:#332255; }}
        #btn_orange {{ background:#3b2b12; color:{P['orange']}; border-color:#6b4a20; }}
        #btn_orange:hover {{ background:#4d3818; }}
        #btn_orange_on {{ background:{P['orange']}; color:#111; border-color:{P['orange']}; font-weight:800; }}
        #btn_teal   {{ background:#122830; color:#4ec9b0;       border-color:#206050; }}
        #btn_teal:hover   {{ background:#1a3a40; }}
        #btn_teal_on {{ background:#4ec9b0; color:#0d1117;      border-color:#4ec9b0; font-weight:800; }}
        #btn_dim    {{ background:{P['surface2']}; color:{P['muted']}; border-color:{P['border']}; }}
        #btn_dim:hover    {{ background:{P['border']}; color:{P['text']}; }}
        """)

    # ── state update slot ─────────────────────────────────────────────────────
    def on_state(self, state: TorState) -> None:
        color = state.mode_color()
        self._dot.setStyleSheet(f"color: {color};")
        self._mode.setText(state.mode_label())
        self._mode.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: 700;")
        self._ts.setText(state.ts)

        self._v_exit.setText(state.exit_ip)
        self._v_real.setText(state.real_ip)
        self._v_country.setText(f"{state.flag()}  {state.country}")
        self._v_isp.setText(state.isp)
        self._v_latency.setText(f"{state.latency_ms} ms" if state.latency_ms else "—")

        route_labels = {
            "connected":    f"🟢  TOR  (exit {state.exit_ip})",
            "connecting":   "🟡  TOR  (building circuit)",
            "disconnected": "🔴  DIRECT — not protected",
            "leak":         "🔴  LEAK — real IP exposed",
            "init":         "⬜  Unknown",
        }
        self._v_route.setText(route_labels.get(state.mode, state.mode))

        self._push_log("INFO", f"{state.mode.upper():12s}  exit={state.exit_ip}"
                       + (f"  {state.latency_ms}ms" if state.latency_ms else "")
                       + (f"  [{state.country}]" if state.country != "—" else "")
                       + ("  ⚠ LEAK" if state.leak else ""))

    # ── log ───────────────────────────────────────────────────────────────────
    def _push_log(self, level: str, msg: str) -> None:
        ts    = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {level:4s}  {msg}"
        self._log_buf.append(entry)
        self._log.setPlainText("\n".join(self._log_buf))
        sb = self._log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def log_event(self, level: str, msg: str) -> None:
        self._push_log(level, msg)

    # ── actions ───────────────────────────────────────────────────────────────
    def _act_start(self) -> None:
        self._push_log("INFO", "Starting tor service…")
        ok, out = TorControl.start()
        self._push_log("OK" if ok else "ERR", out or "—")
        if ok:
            QTimer.singleShot(1500, self.probe.probe_now)

    def _act_stop(self) -> None:
        self._push_log("INFO", "Stopping tor service…")
        ok, out = TorControl.stop()
        self._push_log("OK" if ok else "ERR", out or "—")
        if ok:
            QTimer.singleShot(1000, self.probe.probe_now)

    def _act_restart(self) -> None:
        self._push_log("INFO", "Restarting tor service…")
        ok, out = TorControl.restart()
        self._push_log("OK" if ok else "ERR", out or "—")
        if ok:
            QTimer.singleShot(2000, self.probe.probe_now)

    def _act_newid(self) -> None:
        self._push_log("INFO", "Requesting new identity…")
        ok, out = TorControl.new_identity()
        self._push_log("OK" if ok else "ERR", out)
        if ok:
            QTimer.singleShot(3000, self.probe.probe_now)

    def _sync_toggle_buttons(self) -> None:
        """Reflect the (possibly restart-recovered) real state onto the buttons."""
        if self._ks_on:
            self._b_ks.setText("🔓  Kill Switch: ON")
            self._b_ks.setObjectName("btn_orange_on")
        else:
            self._b_ks.setText("🔒  Kill Switch")
            self._b_ks.setObjectName("btn_orange")
        if self._tp_on:
            self._b_tp.setText("⬡  Transparent: ON")
            self._b_tp.setObjectName("btn_teal_on")
        else:
            self._b_tp.setText("⬡  Transparent")
            self._b_tp.setObjectName("btn_teal")
        self._b_ks.setStyleSheet("")
        self._b_tp.setStyleSheet("")
        self._style()

    def _act_ks(self) -> None:
        # Only flip internal/UI state *after* confirming the firewall
        # command actually succeeded. Previously the state flipped first,
        # so a failed iptables call (permission denied, missing binary,
        # etc.) still left the UI claiming the kill switch was ON/OFF while
        # the real firewall rules hadn't changed at all.
        # (وضعیت داخلی رو فقط بعد از تأیید موفقیت واقعی دستور عوض می‌کنیم —
        # نه قبلش — تا UI هیچ‌وقت وضعیت اشتباه نشون نده.)
        target_on = not self._ks_on
        ok, out = TorControl.killswitch_on() if target_on else TorControl.killswitch_off()
        if ok:
            self._ks_on = target_on
        else:
            self._push_log("ERR", f"Kill switch state unchanged — command failed: {out}")
        self._sync_toggle_buttons()
        self._push_log("OK" if ok else "ERR", out)

    def _act_tp(self) -> None:
        target_on = not self._tp_on
        ok, out = TorControl.transparent_proxy_on() if target_on else TorControl.transparent_proxy_off()
        if ok:
            self._tp_on = target_on
        else:
            self._push_log("ERR", f"Transparent proxy state unchanged — command failed: {out}")
        self._sync_toggle_buttons()
        self._push_log("OK" if ok else "ERR", out)

    def _act_probe(self) -> None:
        self._push_log("INFO", "Manual probe triggered…")
        self.probe.probe_now()

    def _open_bridges(self) -> None:
        dlg = BridgesDialog(self)
        dlg.exec()

    # ── drag ─────────────────────────────────────────────────────────────────
    def _mp(self, ev) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = ev.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def _mm(self, ev) -> None:
        if self._drag_pos and ev.buttons() == Qt.MouseButton.LeftButton:
            self.move(ev.globalPosition().toPoint() - self._drag_pos)

    def _mr(self, _) -> None:
        self._drag_pos = None


# ══════════════════════════════════════════════════════════════════════════════
#  SystemTray
# ══════════════════════════════════════════════════════════════════════════════
class TrayIcon(QSystemTrayIcon):

    def __init__(self, dash: Dashboard) -> None:
        super().__init__()
        self._dash = dash
        self.setIcon(_make_icon("init"))
        self.setToolTip("Tor Control Center — initializing")
        self._build_menu()
        self.activated.connect(self._activated)

    def _build_menu(self) -> None:
        m = QMenu()
        m.setStyleSheet(f"""
            QMenu {{
                background: {P['surface']};
                border: 1px solid {P['border']};
                border-radius: 8px;
                padding: 4px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                color: {P['text']};
            }}
            QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
            QMenu::item:selected {{ background: {P['surface2']}; }}
            QMenu::separator {{ height: 1px; background: {P['border']}; margin: 3px 8px; }}
        """)

        def act(label: str, fn) -> QAction:
            a = QAction(label, m)
            a.triggered.connect(fn)
            return a

        m.addAction(act("🖥   Open Dashboard",   self._show))
        m.addSeparator()
        m.addAction(act("▶   Start Tor",         lambda: TorControl.start()))
        m.addAction(act("■   Stop Tor",          lambda: TorControl.stop()))
        m.addAction(act("↺   Restart Tor",       lambda: TorControl.restart()))
        m.addAction(act("⟳   New Identity",      lambda: TorControl.new_identity()))
        m.addSeparator()
        m.addAction(act("✕   Quit",              QApplication.quit))
        self.setContextMenu(m)

    def on_state(self, state: TorState) -> None:
        self.setIcon(_make_icon(state.mode))
        parts = [state.mode_label()]
        if state.exit_ip != "—":
            parts.append(state.exit_ip)
        if state.country != "—":
            parts.append(f"{state.flag()} {state.country}")
        if state.latency_ms:
            parts.append(f"{state.latency_ms}ms")
        if state.leak:
            parts.append("⚠ LEAK")
        self.setToolTip("🧅  " + "  ·  ".join(parts))

    def _activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._show()

    def _show(self) -> None:
        if self._dash.isVisible():
            self._dash.hide()
            return
        geo  = QApplication.primaryScreen().availableGeometry()
        w, h = self._dash.width(), self._dash.height()
        self._dash.move(geo.right() - w - 16, geo.bottom() - h - 52)
        self._dash.show()
        self._dash.raise_()
        self._dash.activateWindow()


# ══════════════════════════════════════════════════════════════════════════════
#  Entry
# ══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("TorControlCenter")
    app.setApplicationVersion("2.0")

    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("ERROR: No system tray found.")
        sys.exit(1)

    if not _HAS_REQUESTS:
        print("WARNING: requests not installed — network checks disabled.")

    probe = TorProbe()
    dash  = Dashboard(probe)
    tray  = TrayIcon(dash)

    probe.state_ready.connect(dash.on_state)
    probe.state_ready.connect(tray.on_state)
    probe.log_line.connect(dash.log_event)

    tray.show()
    probe.start()

    dash.log_event("INFO", "Tor Control Center v2 started")
    if not _HAS_REQUESTS:
        dash.log_event("WARN", "requests not found — install:  pip3 install requests[socks]")
    if dash._ks_on or dash._tp_on:
        dash.log_event(
            "INFO",
            f"Recovered firewall state on startup: "
            f"kill_switch={'ON' if dash._ks_on else 'off'}  "
            f"transparent_proxy={'ON' if dash._tp_on else 'off'}"
        )
    if not TorControl._has_ip6tables():
        dash.log_event("WARN", "ip6tables unavailable on this system — IPv6 traffic is NOT filtered by the kill switch")

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
