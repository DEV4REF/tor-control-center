#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  Tor Control Center v2 — Setup
#  Ubuntu / Debian / Arch / Fedora
#
#  نصب و راه‌اندازی Tor Control Center — این اسکریپت idempotent هست، یعنی
#  هر بار که اجرا بشه اول نسخه/تنظیمات قبلی رو پاک می‌کنه و از صفر تمیز
#  نصب می‌کنه (تا فایل sudoers یا هلپر قدیمی و ناسازگار باقی نمونه).
# ─────────────────────────────────────────────
set -euo pipefail

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
ok()   { echo -e "${G}[✓]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[✗]${N} $*"; exit 1; }

echo ""
echo "  🧅  Tor Control Center v2 — Setup"
echo "  ──────────────────────────────────"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── real (non-root) user detection ────────────────────────────────────────────
# اگه اسکریپت مستقیم با sudo اجرا بشه، $USER میشه "root" و قانون sudoers
# برای کاربر اشتباه نوشته میشه (و همون چیزیه که باعث خطای "password is
# required" تو لاگ برنامه میشه — چون قانون passwordless برای یوزر واقعی
# دسکتاپ هیچوقت نوشته نشده بوده). این‌جا کاربر واقعی رو تشخیص می‌دیم:
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  REAL_USER="$SUDO_USER"
elif [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  err "این اسکریپت رو مستقیم با sudo اجرا نکن — به‌عنوان کاربر عادی اجرا کن (خودش وقتی لازم باشه sudo می‌زنه). Run this as your normal user, not via sudo."
else
  REAL_USER="$USER"
fi
ok "Installing for user: $REAL_USER"

# ── cleanup any previous install ──────────────────────────────────────────────
# پاک‌کردن هر نسخهٔ قبلی (فایل sudoers، هلپر، سرویس‌های autostart) قبل از
# نصب مجدد — تا هیچ تنظیم قدیمی/ناسازگار (مثلاً قانون sudoers قدیمی که
# مستقیم به iptables دسترسی می‌داد، یا مسیر هلپر قدیمی) باقی نمونه.
ok "Removing any previous installation…"
sudo rm -f /etc/sudoers.d/tor-control-center
sudo rm -f /usr/local/sbin/tcc-helper
rm -f "$HOME/.local/bin/tor_tray.py"
rm -f "$HOME/.config/autostart/tor-control-center.desktop"
rm -f "$HOME/.local/share/applications/tor-control-center.desktop"

# ── package manager ───────────────────────────────────────────────────────────
if   command -v apt-get &>/dev/null; then PM="apt"
elif command -v pacman  &>/dev/null; then PM="pacman"
elif command -v dnf     &>/dev/null; then PM="dnf"
else warn "Unknown package manager — install deps manually."; PM="none"; fi

# ── system packages ───────────────────────────────────────────────────────────
ok "Installing system packages ($PM)…"
case $PM in
  apt)
    sudo apt-get update -qq
    sudo apt-get install -y tor python3-pip \
      python3-pyqt6 python3-requests \
      obfs4proxy >/dev/null 2>&1 || true
    ;;
  pacman)
    sudo pacman -Sy --noconfirm tor python-pyqt6 python-requests obfs4proxy >/dev/null 2>&1 || true
    ;;
  dnf)
    sudo dnf install -y tor python3-PyQt6 python3-requests obfs4 >/dev/null 2>&1 || true
    ;;
esac
warn "snowflake-client / meek-client aren't packaged everywhere — install manually if you plan to use those transports (see README)."

# ── pip packages ──────────────────────────────────────────────────────────────
python3 -c "import PyQt6"   2>/dev/null || {
  warn "PyQt6 not found via system, trying pip…"
  pip3 install PyQt6 --break-system-packages -q
}
python3 -c "import requests" 2>/dev/null || {
  warn "requests not found, installing…"
  pip3 install requests --break-system-packages -q
}
python3 -c "import socks"   2>/dev/null || {
  ok "Installing PySocks (SOCKS5 support)…"
  pip3 install "requests[socks]" --break-system-packages -q
}
ok "Python dependencies ready"

# ── tor service ───────────────────────────────────────────────────────────────
# Do NOT enable autostart — user controls this manually via the app
ok "Tor installed (service left disabled — start via app)"

# ── privileged helper ─────────────────────────────────────────────────────────
# نصب اسکریپت واسط محدود (tcc-helper) — تنها چیزی که sudoers بهش دسترسی
# passwordless میده، نه به iptables/systemctl مستقیم.
HELPER_DEST="/usr/local/sbin/tcc-helper"
ok "Installing privileged helper → $HELPER_DEST…"
sudo install -o root -g root -m 755 "$SCRIPT_DIR/scripts/tcc-helper" "$HELPER_DEST"

# ── sudoers ───────────────────────────────────────────────────────────────────
# Previous versions granted NOPASSWD on the bare iptables/ip6tables binaries,
# which accept arbitrary arguments — effectively unrestricted root via the
# firewall. This grants NOPASSWD on exactly one path: the helper script
# above, which only performs its small set of hard-coded, validated actions.
#
# نکته: قبل از فعال‌کردن فایل sudoers، syntax اونو با visudo -c چک می‌کنیم؛
# یه فایل sudoers خراب می‌تونه کل دسترسی sudo سیستم رو مختل کنه، پس هرگز
# بدون validation نصبش نمی‌کنیم. اگه validation fail بشه، اسکریپت متوقف
# میشه بدون این‌که فایل خراب جایگزین بشه.
SUDOERS="/etc/sudoers.d/tor-control-center"
SUDOERS_TMP="$(mktemp)"
ok "Writing restricted sudoers rule (helper script only, for user: $REAL_USER)…"
cat > "$SUDOERS_TMP" <<RULE
# Tor Control Center — generated by setup.sh
# Grants passwordless root ONLY for the whitelisted helper script, not for
# iptables/ip6tables/systemctl directly.
$REAL_USER ALL=(ALL) NOPASSWD: $HELPER_DEST
RULE

if ! sudo visudo -c -f "$SUDOERS_TMP" >/dev/null 2>&1; then
  rm -f "$SUDOERS_TMP"
  err "Generated sudoers rule failed validation — aborting without touching /etc/sudoers.d. Please report this."
fi

sudo install -o root -g root -m 440 "$SUDOERS_TMP" "$SUDOERS"
rm -f "$SUDOERS_TMP"
ok "Sudoers rule installed and validated"

# ── verify it actually works ─────────────────────────────────────────────────
# تست عملی این‌که واقعاً بدون پسورد کار می‌کنه (با یه اکشن read-only و
# بی‌خطر از خود هلپر) — اگه fail بشه یعنی چیز دیگه‌ای (مثلاً یه فایل
# sudoers دیگه که override می‌کنه) هست که باید دستی بررسی بشه، به‌جای
# این‌که کاربر بعداً وسط استفاده از برنامه غافلگیر بشه.
VERIFY_OUT="$(sudo -n "$HELPER_DEST" ipv6-available 2>&1)" && VERIFY_RC=0 || VERIFY_RC=$?
if [[ "$VERIFY_OUT" == *"password"* || "$VERIFY_OUT" == *"a terminal is required"* ]]; then
  warn "Passwordless sudo for the helper does not seem to be working yet."
  warn "Close and reopen your terminal (group/sudoers caches can be stale) and re-run this script."
  warn "If it still fails, run manually to see the exact sudoers error: sudo visudo -c"
else
  ok "Verified: $HELPER_DEST is callable without a password prompt"
fi

# ── install script ────────────────────────────────────────────────────────────
DEST="$HOME/.local/bin/tor_tray.py"
mkdir -p "$HOME/.local/bin"
cp "$SCRIPT_DIR/tor_tray.py" "$DEST"
chmod +x "$DEST"
ok "Script installed → $DEST"

# ── XDG autostart (KDE / GNOME) ───────────────────────────────────────────────
mkdir -p "$HOME/.config/autostart"
cat > "$HOME/.config/autostart/tor-control-center.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Tor Control Center
Comment=Tor monitor — starts minimized in tray, does not start Tor automatically
Exec=python3 $DEST
Icon=network-vpn
Categories=Network;Security;
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
DESK
ok "Autostart entry created (tray only, Tor stays off)"

# ── app launcher ──────────────────────────────────────────────────────────────
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/tor-control-center.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Tor Control Center
Comment=KDE/GNOME system tray for Tor monitoring and control
Exec=python3 $DEST
Icon=network-vpn
Categories=Network;Security;
Terminal=false
StartupNotify=false
DESK
ok "App launcher created"

# ── torrc hint ────────────────────────────────────────────────────────────────
TORRC="/etc/tor/torrc"
if [[ -f "$TORRC" ]] && ! grep -q "^ControlPort" "$TORRC"; then
  echo ""
  warn "Optional: enable Tor control port for 'New Identity' (cookie auth, no plaintext password):"
  echo "  sudo bash -c 'echo -e \"ControlPort 9051\nCookieAuthentication 1\" >> /etc/tor/torrc'"
  echo "  sudo systemctl restart tor"
fi

echo ""
warn "Bridges / anti-censorship: to use obfs4/meek-azure/snowflake, fetch current"
warn "bridge lines from https://bridges.torproject.org and paste them into the"
warn "app's Bridges panel — see README for details."

echo ""
echo "  ──────────────────────────────────────────────"
ok "Setup complete!"
echo ""
echo "  Start now:    python3 ~/.local/bin/tor_tray.py"
echo "  Auto-starts:  at login (tray only, Tor off)"
echo "  ──────────────────────────────────────────────"
echo ""
