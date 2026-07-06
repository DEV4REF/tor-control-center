# Changelog

## Unreleased — sudoers/cleanup fix (رفع خطای دسترسی روت)

**English:**

- **Fixed**: `setup.sh` now detects if it was invoked via `sudo` (using
  `$SUDO_USER`) instead of blindly using `$USER`, which previously could
  write the sudoers rule for the wrong user ("root") and leave the real
  desktop user without passwordless access — the exact cause of
  `sudo: a password is required` errors showing up in the app's log panel
  for kill switch / transparent proxy / start-stop actions.
- **Fixed**: `setup.sh` is now properly idempotent — it removes any
  previous installation (old sudoers rule, old helper script, old
  autostart/launcher entries) *before* reinstalling, so re-running it
  after a broken or outdated install always results in a clean, consistent
  state instead of layering on top of stale config.
- **Added**: the generated sudoers rule is validated with `visudo -c`
  before being activated, and a live check (`sudo -n tcc-helper
  ipv6-available`) confirms passwordless access actually works, printing a
  clear warning with next steps if it doesn't — instead of failing
  silently later inside the app.

**فارسی:**

- **رفع شد:** `setup.sh` حالا تشخیص می‌ده که آیا مستقیم با `sudo` اجرا
  شده یا نه (به‌جای این‌که کورکورانه از `$USER` استفاده کنه). قبلاً اگه
  اسکریپت با `sudo` اجرا می‌شد، قانون sudoers برای کاربر «root» نوشته
  می‌شد نه کاربر واقعی دسکتاپ — دقیقاً همون چیزی که باعث خطای
  `sudo: a password is required` تو پنل لاگ برنامه (موقع کیل‌سوییچ،
  پراکسی شفاف، و حتی Start/Stop) می‌شد.
- **رفع شد:** `setup.sh` الان واقعاً idempotent هست — قبل از نصب مجدد،
  هر نصب قبلی (قانون sudoers قدیمی، اسکریپت هلپر قدیمی، ورودی‌های
  autostart/launcher قدیمی) رو کامل پاک می‌کنه، تا اجرای دوباره‌ش همیشه
  یه وضعیت تمیز و یکدست بسازه، نه این‌که رو تنظیمات قدیمی/خراب لایه
  بذاره.
- **اضافه شد:** فایل sudoers تولیدشده قبل از فعال‌سازی با `visudo -c`
  اعتبارسنجی میشه، و یه تست واقعی (`sudo -n tcc-helper ipv6-available`)
  چک می‌کنه که دسترسی passwordless واقعاً کار می‌کنه — اگه کار نکرد،
  یه هشدار واضح با مراحل بعدی نشون داده میشه، به‌جای این‌که کاربر بعداً
  وسط استفاده از برنامه غافلگیر بشه.

## Unreleased — anti-censorship & least-privilege pass

### Added

- **Pluggable transports / bridges**: new "Bridges" dialog lets you route Tor
  through obfs4, meek-azure, or Snowflake. Bridge lines are never hard-coded
  (they go stale and get silently rejected) — fetch current ones from
  bridges.torproject.org and paste them in; the app writes a managed block
  into `torrc` and restarts Tor. Detects whether the required transport
  binary (`obfs4proxy`, `meek-client`, `snowflake-client`) is installed and
  tells you plainly if it isn't, instead of a silent circuit-build failure.
- **DNS lock**: while the kill switch is on, `/etc/resolv.conf` is now
  immutable-locked (`chattr +i`) so NetworkManager/systemd-resolved/a VPN
  client can't silently repoint DNS away from the loopback resolver.
  Unlocked automatically when the kill switch is turned off.
- **Least-privilege firewall control**: replaced the old
  `NOPASSWD: /sbin/iptables` sudoers rule — which grants effectively
  unrestricted root, since `iptables` accepts arbitrary arguments — with a
  single narrow helper script (`scripts/tcc-helper`, installed to
  `/usr/local/sbin/tcc-helper`). Sudoers now only allows passwordless
  execution of that one exact path, and the script itself only performs a
  fixed, whitelisted set of validated actions (no shell interpolation of
  user input into commands).

### Notes

- No configuration makes Tor traffic provably undetectable against a
  well-resourced adversary running deep packet inspection. Pluggable
  transports meaningfully raise the bar (obfs4 resists protocol
  fingerprinting; meek/Snowflake hide inside ordinary HTTPS/WebRTC), but
  this is risk reduction, not a guarantee — say so honestly rather than
  oversell it.

## Unreleased — fixes & hardening pass

### Fixed (security-relevant)

- **IPv6 leak**: kill switch and transparent proxy previously only touched
  `iptables` (IPv4). Any host with IPv6 connectivity could bypass both
  features entirely over v6. Now `ip6tables` rules are added alongside the
  IPv4 ones (block all IPv6 egress except loopback) whenever either feature
  is enabled. If `ip6tables` isn't installed, the app now logs an explicit
  warning instead of silently leaving IPv6 unprotected.
- **Hard-coded Tor system user**: the firewall rules assumed Tor always
  runs as `debian-tor`. On distros where it runs as `tor` or `_tor`
  (Arch, Fedora, some minimal images), the exемption rule matched nothing —
  Tor's own traffic would get blocked, or worse, the intended protection
  silently didn't apply as expected. `TorControl.tor_user()` now detects
  the actual user via `id -u <candidate>` at runtime.
- **GeoIP request leaked outside Tor**: the `ip-api.com` lookup was a
  plaintext HTTP request sent directly (not through Tor), which (a) told a
  third party the same exit IP anyway but with no downside avoided, (b)
  would get blocked by the kill switch and throw a needless error, and
  (c) had no transport encryption. It's now routed through the Tor SOCKS
  proxy over HTTPS (`ipapi.co`).
- **Control-port auth almost always failed**: `new_identity()` only ever
  sent a blank `AUTHENTICATE ""`, which fails whenever `CookieAuthentication`
  is enabled (the common default) — meaning "New Identity" silently always
  fell through to a full `systemctl restart tor` instead of a lightweight
  `NEWNYM` signal. Cookie-based auth is now attempted first.

### Fixed (correctness / state)

- **Toggle race condition**: `_act_ks` / `_act_tp` flipped the in-memory
  ON/OFF state *before* checking whether the underlying `iptables` command
  actually succeeded. A failed command (permission denied, missing binary)
  left the UI showing the wrong state. State now only updates after a
  confirmed success.
- **No state recovery on restart**: the app always assumed kill switch /
  transparent proxy were OFF on launch, even if the actual firewall rules
  were still active from a previous session (or vice versa, after a
  manual `iptables -F`). `killswitch_status()` / `transparent_proxy_status()`
  now query the live `iptables` ruleset (via tagged comments) on startup and
  the UI reflects the true state.

### Added

- **External config**: `~/.config/tor-control-center/config.json` (see
  `config.example.json`) lets you override ports/URLs/timeouts without
  touching the source.
- **Rotating file log**: `~/.config/tor-control-center/tor_tray.log`
  (1&nbsp;MB × 3 backups) in addition to the console/UI log, for debugging
  after a crash.
- **CI**: `.github/workflows/lint.yml` runs `ruff check` and a byte-compile
  check on every push/PR.

### Cleanup

- Removed unused imports (`QSizePolicy`, `QThread`, `QSize`, `QFontMetrics`,
  `dataclasses.field`) flagged by `ruff`.
