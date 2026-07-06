# 🧅 Tor Control Center

A professional system tray application for monitoring and controlling Tor on Linux (KDE/GNOME). Shows real-time connection status, exit node info, latency, and provides one-click controls.

![status](https://img.shields.io/badge/status-stable-brightgreen)
![platform](https://img.shields.io/badge/platform-Linux-blue)
![python](https://img.shields.io/badge/python-3.10%2B-yellow)

---

## Features

- **Real connection check** — verifies actual routing through Tor (via check.torproject.org), not just whether the service is running
- **GeoIP info** — country, ISP/org of the current exit node
- **Latency measurement** — round-trip time through the Tor circuit
- **Leak detection** — compares your direct IP against the Tor exit IP
- **One-click controls** — Start / Stop / Restart Tor, request a New Identity
- **Kill switch** — blocks all non-Tor traffic (IPv4 + IPv6) via iptables/ip6tables if Tor goes down, and locks `/etc/resolv.conf` while active so nothing can silently repoint DNS
- **Transparent proxy toggle** — route all system TCP/DNS traffic through Tor (IPv4 tunnelled, IPv6 blocked to prevent leaks)
- **Bridges / pluggable transports** — obfs4, meek-azure, or Snowflake, for connecting where Tor itself is blocked/fingerprinted by DPI; bridge lines are fetched by you from bridges.torproject.org (never hard-coded, since baked-in ones go stale)
- **System tray integration** — color-coded icon (green/yellow/red) with live tooltip
- **Event log** — rolling log of state changes inside the dashboard, plus a rotating file log at `~/.config/tor-control-center/tor_tray.log`
- **Least-privilege firewall control** — privileged actions go through a single whitelisted helper script (`tcc-helper`), not a blanket `NOPASSWD: iptables` sudoers rule

> **Note on "undetectable"**: no configuration makes Tor traffic provably invisible against a sophisticated, resourced adversary doing deep packet inspection — pluggable transports raise the bar significantly (obfs4 resists protocol fingerprinting, meek/Snowflake hide inside ordinary-looking HTTPS/WebRTC), but treat this as risk reduction, not a guarantee.

---

## Screenshots

*(add your own screenshots here)*

---

## Requirements

- Linux with a system tray (KDE Plasma, GNOME with extension, XFCE, etc.)
- Python 3.10+
- `tor` package
- `PyQt6`
- `requests` with SOCKS support

---

## Installation

```bash
git clone https://github.com/dev4ref/tor-control-center.git
cd tor-control-center
chmod +x setup.sh
./setup.sh
```

The setup script will:

- Install `tor`, `PyQt6`, `requests[socks]`, and `obfs4proxy`
- Remove any previous installation first (old sudoers rule, old helper, old autostart entries) so re-running is always a clean reinstall
- Install a single whitelisted privileged helper (`tcc-helper`) and a sudoers rule scoped to *only* that script — not a blanket rule on `iptables`/`systemctl`
- Copy the script to `~/.local/bin/tor_tray.py`
- Create an autostart entry (tray only — **Tor itself stays off** until you start it manually)
- Create an application launcher entry

> **Note:** Tor is *not* enabled to autostart with the system. The app starts in the tray on login, shows 🔴 disconnected, and you connect manually via the **▶ Start** button. To change this, see [Manual vs Automatic Tor](#manual-vs-automatic-tor) below.

---

## Usage

```bash
python3 ~/.local/bin/tor_tray.py
```

Click the tray icon to open the dashboard. Buttons:

| Button | Action |
|---|---|
| ▶ Start | `systemctl start tor` |
| ■ Stop | `systemctl stop tor` |
| ↺ Restart | `systemctl restart tor` |
| ⟳ New Identity | Requests a new circuit via the Tor control port |
| 🔒 Kill Switch | Toggles iptables rules that block all non-Tor traffic |
| ⬡ Transparent | Toggles system-wide transparent proxying through Tor |
| ⟳ Check Now | Forces an immediate status probe |

---

## Manual vs Automatic Tor

By default, Tor does **not** start with the system — only the tray monitor does.

**To keep it manual (default):**
```bash
sudo systemctl disable tor
```

**To have Tor start automatically with the system:**
```bash
sudo systemctl enable tor
```

---

## New Identity / Control Port

To enable the "New Identity" feature via the control port, add to `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 1
```

Then:
```bash
sudo systemctl restart tor
```

> If the control port isn't configured, "New Identity" falls back to restarting the Tor service.

---

## Transparent Proxy (system-wide tunneling)

The "Transparent" button redirects all outbound TCP and DNS traffic through Tor's `TransPort`/`DNSPort`. For this to work, add to `/etc/tor/torrc`:

```
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
```

Then restart Tor. Toggle the button in the dashboard to enable/disable the iptables redirection rules.

---

## Uninstall

```bash
rm ~/.local/bin/tor_tray.py
rm ~/.config/autostart/tor-control-center.desktop
rm ~/.local/share/applications/tor-control-center.desktop
sudo rm /etc/sudoers.d/tor-control-center
sudo rm /usr/local/sbin/tcc-helper
```

---

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

This tool manages your local Tor daemon and firewall rules. It does not provide anonymity guarantees beyond what Tor itself provides. Review the iptables rules in `tor_tray.py` before relying on the kill switch or transparent proxy for sensitive use cases.

---

## راهنمای فارسی

### معرفی

Tor Control Center یه اپلیکیشن سیستم‌تری برای لینوکس (KDE/GNOME) هست که وضعیت واقعی اتصال Tor رو نشون می‌ده و کنترل کاملش رو در اختیارت می‌ذاره: وضعیت لحظه‌ای اتصال، اطلاعات exit node، تأخیر شبکه، و دکمه‌های یک‌کلیکی برای کنترل.

### امکانات

- **بررسی واقعی اتصال** — از طریق check.torproject.org چک می‌کنه که ترافیک واقعاً از Tor رد می‌شه، نه فقط این‌که سرویس روشنه
- **اطلاعات GeoIP** — کشور و ISP/سازمان مربوط به exit node فعلی
- **اندازه‌گیری تأخیر (Latency)** — زمان رفت‌وبرگشت روی مدار Tor
- **تشخیص لو رفتن (Leak Detection)** — مقایسهٔ IP مستقیم شما با IP خروجی Tor
- **کنترل‌های یک‌کلیکی** — روشن/خاموش/ری‌استارت Tor، درخواست هویت جدید
- **کیل‌سوییچ (Kill Switch)** — با iptables/ip6tables جلوی هر ترافیک غیر-Tor (روی IPv4 و IPv6) رو می‌گیره اگه Tor قطع بشه؛ همچنین DNS رو قفل می‌کنه که هیچی نتونه بی‌سروصدا resolver رو عوض کنه
- **پراکسی شفاف (Transparent Proxy)** — تونل‌کردن کل ترافیک TCP/DNS سیستم از داخل Tor (فقط IPv4؛ IPv6 برای جلوگیری از لو رفتن بلاک میشه)
- **بریج / ترنسپورت‌های ضدسانسور** — پشتیبانی از obfs4، meek-azure و Snowflake برای وصل‌شدن جایی که خود Tor توسط فیلترینگ عمیق (DPI) شناسایی/بلاک میشه؛ خط‌های bridge رو خودت از bridges.torproject.org می‌گیری (این برنامه هیچ‌چیزی رو هاردکد نمی‌کنه چون این مقادیر منقضی میشن)
- **آیکون سیستم‌تری رنگی** — سبز/زرد/قرمز با تول‌تیپ زنده
- **لاگ رویدادها** — لاگ داخل داشبورد + فایل لاگ چرخشی در `~/.config/tor-control-center/tor_tray.log`
- **کنترل فایروال با کمترین دسترسی ممکن (Least Privilege)** — عملیات‌های حساس از طریق یه اسکریپت واسط محدود (`tcc-helper`) انجام میشه، نه یه قانون sudoers باز روی کل `iptables`

> **نکته دربارهٔ «غیرقابل‌شناسایی»**: هیچ تنظیماتی ترافیک Tor رو در برابر یه سانسورچیِ قدرتمند و مجهز به DPI عمیق صد در صد نامرئی نمی‌کنه. ترنسپورت‌های pluggable (به‌خصوص obfs4 و Snowflake/meek) ریسک شناسایی رو به‌شدت کم می‌کنن، ولی این یعنی کاهش ریسک، نه تضمین مطلق.

### نصب

```bash
git clone https://github.com/dev4ref/tor-control-center.git
cd tor-control-center
chmod +x setup.sh
./setup.sh
```

اسکریپت نصب این کارها رو انجام می‌ده:

- نصب `tor`، `PyQt6`، `requests[socks]` و `obfs4proxy`
- **پاک‌کردن هر نصب قبلی** (قانون sudoers قدیمی، هلپر قدیمی، ورودی‌های autostart قدیمی) قبل از نصب مجدد — تا هر بار اجرا، یه نصب کاملاً تمیز باشه
- نصب یه اسکریپت واسط محدود (`tcc-helper`) و یه قانون sudoers که *فقط* به همون یه مسیر دسترسی passwordless می‌ده (نه به `iptables`/`systemctl` مستقیم)
- کپی اسکریپت اصلی به `~/.local/bin/tor_tray.py`
- ساخت ورودی autostart (فقط خود برنامهٔ تری — **خود Tor روشن نمیشه** تا خودت دستی استارتش کنی)
- ساخت میان‌بر اجرا (launcher)

> **نکته:** Tor به‌صورت پیش‌فرض با سیستم بالا نمیاد. برنامه موقع لاگین توی تری با وضعیت 🔴 قطع‌شده باز میشه و باید خودت با دکمهٔ **▶ Start** وصلش کنی.

### چرا سوییچ‌ها با خطای «password is required» فیل می‌کردن؟

اگه قبلاً `setup.sh` رو با `sudo` اجرا کرده باشی (به‌جای کاربر عادی)، یا نسخهٔ قدیمی‌تر اسکریپت اجرا شده باشه، قانون `sudoers` برای کاربر/مسیر اشتباهی نوشته میشه یا اصلاً نوشته نمیشه، و بعد هر دکمه‌ای که به دسترسی روت نیاز داره (کیل‌سوییچ، پراکسی شفاف، حتی Start/Stop) با خطای زیر تو لاگ فیل می‌کنه:

```
sudo: a terminal is required to read the password
sudo: a password is required
```

**راه‌حل:** نسخهٔ فعلی `setup.sh` رو (دوباره) اجرا کن — این نسخه:
1. تشخیص می‌ده اگه با `sudo` اجرا شده باشی و بهت میگه به‌جاش با کاربر عادی اجراش کن
2. قبل از نصب مجدد، هر نصب/تنظیم قبلی رو کامل پاک می‌کنه
3. syntax فایل `sudoers` جدید رو قبل از فعال‌سازی با `visudo -c` چک می‌کنه (تا هرگز یه فایل sudoers خراب جایگزین نشه)
4. در آخر با یه تست واقعی چک می‌کنه که واقعاً دسترسی passwordless کار می‌کنه یا نه، و اگه کار نکرد صریح بهت میگه

```bash
cd tor-control-center
./setup.sh
```

اگه بازم مشکل داشت، یه ترمینال جدید باز کن (کش گروه/sudoers ممکنه stale باشه) و دوباره اجرا کن.

### حذف کامل

```bash
rm ~/.local/bin/tor_tray.py
rm ~/.config/autostart/tor-control-center.desktop
rm ~/.local/share/applications/tor-control-center.desktop
sudo rm /etc/sudoers.d/tor-control-center
sudo rm /usr/local/sbin/tcc-helper
```

### سلب مسئولیت

این ابزار سرویس محلی Tor و قوانین فایروال سیستم شما رو مدیریت می‌کنه. هیچ تضمین ناشناس‌ماندنی فراتر از چیزی که خودِ Tor ارائه می‌ده نمی‌ده. قبل از تکیه‌کردن روی کیل‌سوییچ یا پراکسی شفاف برای موارد حساس، قوانین iptables رو در `scripts/tcc-helper` مرور کن.
