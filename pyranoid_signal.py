# =============================================================================
#  PyranoidSignal.py  v1.3
#  Monitors active TCP connections or UDP sockets, resolves PID → executable
#  path, checks Authenticode signing status, and logs everything to CSV/JSON.
#
#  Run as Administrator for full PID resolution on all system processes.
#  Dependencies: psutil   (pip install psutil)
#
#  Changes from v1.2:
#    - Startup menu: choose TCP Monitor (1) or UDP Scan (2)
#    - UDP mode: dedicated scan + alert logic for DNS, NetBIOS, LLMNR, mDNS
#      sockets and any unsigned/unknown process holding a UDP socket
# =============================================================================

import os
import csv
import json
import time
import psutil
import subprocess
from datetime import datetime

os.system("")  # Trick tp enable VT100 colour on Windows terminal

# =============================================================================
#  CONFIG — edit this section to suit your lab
# =============================================================================

# Folder where log files are written
LOG_DIR = "tpm_logs"

# "csv" or "json"
LOG_FORMAT = "csv"

# Seconds between connection scans (will fill the .cvs log pretty quick)
POLL_INTERVAL = 10

# Path to the whitelist file.  The file is created from DEFAULT_WHITELIST on
# first run and can be edited at any time — changes are picked up automatically.
WHITELIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist.txt")

# Ports that flag LISTEN sockets — an unexpected process opening one of these
# as a listener is reported even if the signed/whitelisted checks would silence it.
SENSITIVE_LISTEN_PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 4444, 8080]

# UDP ports considered sensitive.  An unexpected process holding any of these
# warrants an alert.  Port 53 = DNS, 123 = NTP, 137/138 = NetBIOS,
# 5353 = mDNS, 5355 = LLMNR.
SENSITIVE_UDP_PORTS = [53, 123, 137, 138, 5353, 5355]

# Process names that are legitimately expected to own UDP port 53 on Windows.
# Anything else touching port 53 is flagged as a potential DNS-tunnel.
DNS_OWNER_PROCS = {"svchost.exe", "system", "dnscache"}

# =============================================================================
#  DEFAULT WHITELIST — written to whitelist.txt on first run only.
#  Edit whitelist.txt directly (or use whitelist_manager.py) going forward.
# =============================================================================

DEFAULT_WHITELIST = [
    "system",
    "system idle process",
    r"c:\python314\python.exe",
    r"c:\windows\explorer.exe",
    r"c:\windows\system32\svchost.exe",
    r"c:\windows\system32\lsass.exe",
    r"c:\windows\system32\services.exe",
    r"c:\windows\system32\wininit.exe",
    r"c:\windows\system32\ntoskrnl.exe",
]

# =============================================================================
#  SETUP
# =============================================================================

os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(
    LOG_DIR, f"tpm_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{LOG_FORMAT}"
)

# Runtime whitelist state — populated by load_whitelist() at startup
_whitelist: set[str] = set()
_whitelist_mtime: float = 0.0

# Caches — avoids redundant subprocess calls and psutil lookups
_signing_cache: dict[str, str] = {}
_seen_connections: set = set()   # TCP
_seen_udp_sockets: set = set()   # UDP

# =============================================================================
#  WHITELIST FILE  MANAGEMENT
# =============================================================================


def _write_default_whitelist() -> None:
    """Create whitelist.txt from DEFAULT_WHITELIST on first run."""
    with open(WHITELIST_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Pyranoid Signal — Whitelist\n")
        f.write("# One executable path per line (lowercase best case, dont yell at me).\n")
        f.write("# Lines starting with # are comments; blank lines are ignored.\n")
        f.write("# Run whitelist_manager.py then pyranoidsignal.py for easy management of this file with a shitty GUI ;)\n\n")
        for entry in DEFAULT_WHITELIST:
            f.write(entry + "\n")
    print(cyan(f"  [Created default whitelist at {WHITELIST_FILE}]"))


def load_whitelist() -> None:
    """
    Load (or reload) the whitelist from WHITELIST_FILE.
    Creates the file from DEFAULT_WHITELIST if it does not exist yet.
    Normalises every entry to lowercase so matching is always case-insensitive.
    """
    global _whitelist, _whitelist_mtime

    if not os.path.exists(WHITELIST_FILE):
        _write_default_whitelist()

    try:
        mtime = os.path.getmtime(WHITELIST_FILE)
        entries: set[str] = set()
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    entries.add(line)
        _whitelist = entries
        _whitelist_mtime = mtime
    except OSError as exc:
        print(yellow(f"  [Warning] Could not read whitelist: {exc}"))


def maybe_reload_whitelist() -> None:
    """Hot-reload whitelist.txt if its modification time has changed."""
    global _whitelist_mtime
    try:
        mtime = os.path.getmtime(WHITELIST_FILE)
    except OSError:
        return
    if mtime != _whitelist_mtime:
        old_count = len(_whitelist)
        load_whitelist()
        delta = len(_whitelist) - old_count
        sign = "+" if delta >= 0 else ""
        print(cyan(f"  [Whitelist reloaded: {len(_whitelist)} entries ({sign}{delta})]"))


# =============================================================================
#  ANSI COLOUR HELPERS
# =============================================================================


def red(s):   return f"\033[38;5;196m{s}\033[0m"
def yellow(s): return f"\033[38;5;220m{s}\033[0m"
def green(s): return f"\033[38;5;156m{s}\033[0m"
def cyan(s):  return f"\033[38;5;117m{s}\033[0m"
def grey(s):  return f"\033[38;5;244m{s}\033[0m"
def bold(s):  return f"\033[1m{s}\033[0m"


# =============================================================================
#  SIGNING CHECK  (Windows Authenticode via PowerShell)
# =============================================================================


def check_signing(exe_path: str) -> str:
    """
    Returns the Authenticode status string for an executable:
    'Valid', 'NotSigned', 'UnknownError', 'HashMismatch', 'CheckFailed', etc.
    Results are cached so PowerShell is only called once per unique path.
    """
    if not exe_path or exe_path in ("Unknown", "AccessDenied", "ProcessGone", "System"):
        return "Unknown"

    key = exe_path.lower()
    if key in _signing_cache:
        return _signing_cache[key]

    try:
        # Escape any single quotes in the path, then use -LiteralPath
        # so spaces and special characters in paths are handled safely.
        safe_path = exe_path.replace("'", "''")
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').Status",
            ],
            capture_output=True,
            text=True,
            timeout=6,
        )
        status = result.stdout.strip() or "Unknown"
    except subprocess.TimeoutExpired:
        status = "Timeout"
    except FileNotFoundError:
        status = "NoPowerShell"
    except Exception:
        status = "CheckFailed"

    _signing_cache[key] = status
    return status


# =============================================================================
#  PROCESS RESOLUTION
# =============================================================================


def get_process_info(pid: int | None) -> dict:
    """
    Resolves a PID to its name, full executable path, and signing status.
    Gracefully handles access-denied and already-dead processes.
    """
    if pid is None:
        return {"pid": None, "name": "Unknown", "exe": "Unknown", "signed": "Unknown"}

    # PID 0 = System Idle Process (kernel placeholder, no real exe)
    if pid == 0:
        return {
            "pid": 0,
            "name": "System Idle Process",
            "exe": "System",
            "signed": "Valid",
        }

    # PID 4 is always the Windows kernel System process — no exe to query
    if pid == 4:
        return {"pid": 4, "name": "System", "exe": "System", "signed": "Valid"}

    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        name = proc.name()
    except psutil.NoSuchProcess:
        return {
            "pid": pid,
            "name": "ProcessGone",
            "exe": "ProcessGone",
            "signed": "Unknown",
        }
    except psutil.AccessDenied:
        # We can still get the name even without admin for some processes
        try:
            name = psutil.Process(pid).name()
        except Exception:
            name = "AccessDenied"
        return {"pid": pid, "name": name, "exe": "AccessDenied", "signed": "Unknown"}

    signed = check_signing(exe)
    return {"pid": pid, "name": name, "exe": exe, "signed": signed}


# =============================================================================
#  HELPERS
# =============================================================================


def fmt_addr(addr) -> str:
    """Safely converts a psutil address namedtuple to 'ip:port' string."""
    if not addr:
        return ""
    return f"{addr.ip}:{addr.port}"


def _is_loopback(addr) -> bool:
    """
    Returns True if the address is a loopback address (IPv4 or IPv6).
    """
    if not addr:
        return False
    ip = addr.ip
    # 127.x.x.x covers the full loopback block; ::1 covers IPv6
    return ip == "::1" or ip.startswith("127.")


def is_whitelisted(exe: str) -> bool:
    return exe.lower() in _whitelist


def is_alert_port(conn) -> bool:
    """True if either end of the connection touches a known sensitive port."""
    if not conn.laddr:
        return False
    local_hit = conn.laddr.port in SENSITIVE_LISTEN_PORTS
    remote_hit = hasattr(conn, 'raddr') and conn.raddr and conn.raddr.port in SENSITIVE_LISTEN_PORTS
    return bool(local_hit or remote_hit)

def _is_private_ip(ip: str) -> bool:
    """
    Returns True for RFC 1918 / link-local addresses.
    Connections to LAN IPs are lower-priority than public-internet ones,
    so callers can use this to tune alert severity.
    """
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("169.254.")
        or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
    )


# =============================================================================
#  LOG ENTRY  BUILD + WRITE
# =============================================================================

COMMON_LOG_FIELDS = [
    "timestamp",
    "pid",
    "process",
    "exe_path",
    "signed",
    "local_addr",
    "remote_addr",
    "status",
    "whitelisted",
    "alert_port",
    "alert",
    "is_private_ip",
    "alert_reason",
]

def write_log(entry: dict):
    """Unified logging for both TCP and UDP entries."""
    if LOG_FORMAT == "csv":
        file_exists = os.path.exists(LOG_FILE)
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=COMMON_LOG_FIELDS, extrasaction='ignore')
            if not file_exists:
                writer.writeheader()
            writer.writerow(entry)
    else:  # json
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

def should_alert(proc: dict, conn) -> tuple[bool, str]:
    """
    Decides whether a connection warrants terminal output and returns a
    human-readable reason string alongside the boolean.

    Alert conditions:
      1. Unsigned AND not whitelisted AND not loopback
      2. ESTABLISHED AND not whitelisted AND not loopback
      3. CLOSE_WAIT / FIN_WAIT AND not whitelisted AND not loopback (try to catch some sneaky fuckers if we didnt see it active maybe we can catch the close)
      4. LISTEN on a sensitive port AND not whitelisted
      
      Note: the world is your oyster mix and match the rules how you think they should be.

    Signed + whitelisted = fully silent. this is bliss, cause when you see something in the terminal you know something aint right.
    """
    whitelisted = is_whitelisted(proc["exe"])
    unsigned    = proc["signed"] != "Valid"
    established = conn.status == "ESTABLISHED"
    is_closing  = conn.status in ("CLOSE_WAIT",) or conn.status.startswith("FIN_WAIT")
    is_listen   = conn.status == "LISTEN"
    is_home     = _is_loopback(conn.laddr) or _is_loopback(conn.raddr)

    if is_listen and not whitelisted and conn.laddr and conn.laddr.port in SENSITIVE_LISTEN_PORTS:
        return True, "UNEXPECTED LISTENER"
    if unsigned and not whitelisted and not is_home:
        return True, "UNSIGNED + UNKNOWN"
    if established and not whitelisted and not is_home:
        return True, "ESTABLISHED UNKNOWN"
    if is_closing and not whitelisted and not is_home:
        return True, "CLOSING UNKNOWN"
    return False, ""


def build_entry(conn, proc: dict) -> dict:
    alert, reason = should_alert(proc, conn)
    return {
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
        "pid":         proc["pid"],
        "process":     proc["name"],
        "exe_path":    proc["exe"],
        "signed":      proc["signed"],
        "local_addr":  fmt_addr(conn.laddr),
        "remote_addr": fmt_addr(conn.raddr),
        "status":      conn.status,
        "whitelisted": is_whitelisted(proc["exe"]),
        "alert_port":  is_alert_port(conn),
        "alert":       alert,
        "is_private_ip": _is_private_ip(conn.raddr.ip) if conn.raddr and conn.raddr.ip else False,
        "alert_reason": reason,
    }

# =============================================================================
#  TERMINAL OUTPUT
# =============================================================================


def print_entry(entry: dict):
    ts   = grey(entry["timestamp"])
    pid  = cyan(str(entry["pid"]))
    proc = yellow(entry["process"])
    laddr = entry["local_addr"]
    raddr = entry["remote_addr"] if entry["remote_addr"] else grey("—")
    # Lowercase so the path can be pasted directly into whitelist.txt if youre so inclined to build it that way
    exe  = entry["exe_path"].lower()

    # I think we should also get the hash and monitor if that changes next version maybe
    if entry["signed"] == "Valid":
        sig_label = green("Signed ✔")
    elif entry["signed"] == "NotSigned":
        sig_label = red("NOT Signed ✘")
    else:
        sig_label = yellow(f"Sig: {entry['signed']}")

    wl_label = (
        green("Whitelisted ✔") if entry["whitelisted"] else red("NOT Whitelisted ✘")
    )

    reason = entry.get("alert_reason", "")
    if reason == "UNEXPECTED LISTENER":
        alert_tag = f"  {bold(red('⚠ UNEXPECTED LISTENER'))}"
    elif reason == "UNSIGNED + UNKNOWN":
        alert_tag = f"  {bold(red('⚠ UNSIGNED + UNKNOWN'))}"
    elif reason in ("ESTABLISHED UNKNOWN", "CLOSING UNKNOWN"):
        alert_tag = f"  {bold(yellow('⚡Unknown Connection'))}" #vibecoded give away -- ChatGPT, Claude, Gemini and Sophist :) they didnt think this thing up. 
    else:
        alert_tag = ""

    print(f"    {ts}  PID {pid}  {proc}{alert_tag}")
    print(f"    {laddr}  →  {raddr}  [{grey(entry['status'])}]")
    print(f"    {cyan(exe)}")
    print(f"    {sig_label}  |  {wl_label}")
    print()

def _run_monitor_loop(kind: str, build_func, print_func, seen_cache: set):
    """Generic engine to handle the polling logic for both TCP and UDP."""
    while True:
        maybe_reload_whitelist()

        try:
            connections = psutil.net_connections(kind=kind)
        except psutil.AccessDenied:
            print(red("  [Access Denied] — run as Administrator for full visibility"))
            time.sleep(POLL_INTERVAL)
            continue

        # Prune stale connections
        current_keys = set()
        for conn in connections:
            if kind == "tcp" and conn.status == "TIME_WAIT":
                continue
            key = (conn.pid, fmt_addr(conn.laddr), fmt_addr(getattr(conn, 'raddr', None)), getattr(conn, 'status', 'UDP'))
            current_keys.add(key)
        
        seen_cache.intersection_update(current_keys)

        for conn in connections:
            if kind == "tcp" and conn.status == "TIME_WAIT":
                continue

            conn_key = (conn.pid, fmt_addr(conn.laddr), fmt_addr(getattr(conn, 'raddr', None)), getattr(conn, 'status', 'UDP'))
            if conn_key in seen_cache:
                continue
            
            seen_cache.add(conn_key)
            proc = get_process_info(conn.pid)
            entry = build_func(conn, proc)

            write_log(entry)
            if entry["alert"]:
                print_func(entry)

        time.sleep(POLL_INTERVAL)

# =============================================================================
#  MAIN MONITOR LOOP
# =============================================================================
def monitor():
    # Load whitelist before printing the banner so the count is correct
    load_whitelist()

    print(yellow(bold("\n  ╔══════════════════════════════════════╗")))
    print(yellow(bold("  ║      Pyranoid Signal v1.3             ║")))
    print(yellow(bold("  ╚══════════════════════════════════════╝\n")))
    print(f"  Log file       : {cyan(LOG_FILE)}")
    print(f"  Log format     : {cyan(LOG_FORMAT.upper())}")
    print(f"  Whitelist file : {cyan(WHITELIST_FILE)}")
    print(f"  Whitelist      : {cyan(str(len(_whitelist)))} entries (hot-reloads on change)")
    print(f"  Listen ports   : {yellow(str(SENSITIVE_LISTEN_PORTS))}")
    print(f"  Poll interval  : {cyan(str(POLL_INTERVAL))}s")
    print(f"\n  {grey('Alerts: unexpected listener | unsigned+unknown | established unknown | closing unknown.')}")
    print(f"  {grey('Signed + whitelisted connections are silent.  All connections are logged.')}")
    print(f"  {grey('Run whitelist_manager.py to add executables to the whitelist via GUI.')}")
    print(f"\n  {grey('Ctrl+C to stop')}")
    print("  " + "─" * 66 + "\n")
    
    _run_monitor_loop("tcp", build_entry, print_entry, _seen_connections)

# =============================================================================
#  UDP  SCAN
# =============================================================================
def should_alert_udp(proc: dict, conn) -> tuple[bool, str]:
    """
    Alert tiers for UDP sockets:

      HIGH  — Port 53 owned by a process that isn't svchost/system/dnscache.
               Classic DNS-tunnelling indicator.
      HIGH  — Unsigned + not whitelisted on any sensitive UDP port.
      MED   — NetBIOS / LLMNR / mDNS port from a non-system process.
               Responder-style attacks rely on these.
      MED   — Any unsigned + non-whitelisted process with a UDP socket.
      LOW   — Non-whitelisted but signed: logged quietly, not printed.
      SILENT — Whitelisted: no output, no log noise.
    """
    whitelisted  = is_whitelisted(proc["exe"])
    name_lower   = proc["name"].lower()
    unsigned     = proc["signed"] != "Valid"
    port         = conn.laddr.port if conn.laddr else 0
    is_home      = _is_loopback(conn.laddr)

    if whitelisted:
        return False, ""

    # ── HIGH: DNS socket held by unexpected process ───────────────────────
    if port == 53 and name_lower not in DNS_OWNER_PROCS:
        return True, "DNS SOCKET — UNEXPECTED OWNER"

    # ── HIGH: unsigned process on any sensitive UDP port ──────────────────
    if unsigned and port in SENSITIVE_UDP_PORTS and not is_home:
        return True, "UNSIGNED ON SENSITIVE UDP PORT"

    # ── MED: known-risky port from any non-system process ─────────────────
    if port in (137, 138, 5353, 5355) and not is_home:
        return True, "NETBIOS / LLMNR / MDNS SOCKET"

    # ── MED: unsigned process on any UDP socket ───────────────────────────
    if unsigned and not is_home:
        return True, "UNSIGNED UDP SOCKET"

    return False, ""


def build_entry_udp(conn, proc: dict) -> dict:
    alert, reason = should_alert_udp(proc, conn)
    return {
        "timestamp":    datetime.now().isoformat(timespec="seconds"),
        "pid":          proc["pid"],
        "process":      proc["name"],
        "exe_path":     proc["exe"],
        "signed":       proc["signed"],
        "local_addr":   fmt_addr(conn.laddr),
        "remote_addr":  "",
        "status":       "UDP",
        "whitelisted":  is_whitelisted(proc["exe"]),
        "alert_port":   is_alert_port(conn),
        "alert":        alert,
        "is_private_ip": _is_private_ip(conn.laddr.ip) if conn.laddr and conn.laddr.ip else False,
        "alert_reason": reason,
    }

def print_entry_udp(entry: dict) -> None:
    ts    = grey(entry["timestamp"])
    pid   = cyan(str(entry["pid"]))
    proc  = yellow(entry["process"])
    laddr = entry["local_addr"]
    exe   = entry["exe_path"].lower()
    reason = entry.get("alert_reason", "")

    if entry["signed"] == "Valid":
        sig_label = green("Signed ✔")
    elif entry["signed"] == "NotSigned":
        sig_label = red("NOT Signed ✘")
    else:
        sig_label = yellow(f"Sig: {entry['signed']}")

    wl_label = (
        green("Whitelisted ✔") if entry["whitelisted"] else red("NOT Whitelisted ✘")
    )

    if "DNS" in reason:
        alert_tag = f"  {bold(red('⚠  ' + reason))}"
    elif "UNSIGNED" in reason:
        alert_tag = f"  {bold(red('⚠  ' + reason))}"
    else:
        alert_tag = f"  {bold(yellow('⚡  ' + reason))}"

    print(f"  {ts}  PID {pid}  {proc} [UDP]{alert_tag}")
    print(f"    socket  {laddr}")
    print(f"    {cyan(exe)}")
    print(f"    {sig_label}  |  {wl_label}")
    print()


def monitor_udp() -> None:
    load_whitelist()

    print(green(bold("\n  ╔══════════════════════════════════════╗")))
    print(green(bold("  ║        Pyranoid Signal v1.3          ║")))
    print(green(bold("  ║           UDP Scan Mode              ║")))
    print(green(bold("  ╚══════════════════════════════════════╝\n")))
    print(f"  Log file          : {cyan(LOG_FILE)}")
    print(f"  Log format        : {cyan(LOG_FORMAT.upper())}")
    print(f"  Whitelist file    : {cyan(WHITELIST_FILE)}")
    print(f"  Whitelist         : {cyan(str(len(_whitelist)))} entries (hot-reloads on change)")
    print(f"  Sensitive UDP ports: {yellow(str(SENSITIVE_UDP_PORTS))}")
    print(f"  Poll interval     : {cyan(str(POLL_INTERVAL))}s")
    print(f"\n  {grey('Alerts: DNS socket from unexpected owner | unsigned on sensitive port')}")
    print(f"  {grey('         NetBIOS/LLMNR/mDNS from non-system | unsigned on any UDP socket.')}")
    print(f"  {grey('Signed + whitelisted sockets are silent.  All sockets are logged.')}")
    print(f"\n  {grey('Ctrl+C to stop')}")
    print("  " + "─" * 66 + "\n")
    
    _run_monitor_loop("udp", build_entry_udp, print_entry_udp, _seen_udp_sockets)

# =============================================================================
#  STARTUP MENU
# =============================================================================


def show_menu() -> int:
    """
    Print the mode-selection menu and return the user's choice (1 or 2).
    Loops until valid input is received.
    """
    print(green(bold("\n  ╔══════════════════════════════════════╗")))
    print(green(bold("  ║        Pyranoid Signal v1.3          ║")))
    print(green(bold("  ╚══════════════════════════════════════╝\n")))
    print(f"  {cyan('Select a mode:')}\n")
    print(f"    {bold(cyan('[1]'))}  {green('TCP Monitor')}  —  track all active TCP connections,")
    print(f"         alert on unknown/unsigned processes and unexpected listeners")
    print()
    print(f"    {bold(cyan('[2]'))}  {yellow('UDP Scan')}    —  inspect all open UDP sockets,")
    print(f"         alert on DNS-tunnel indicators, NetBIOS/LLMNR/mDNS exposure,")
    print(f"         and unsigned processes holding UDP sockets")
    print()

    while True:
        try:
            raw = input(f"  {grey('Enter choice [1/2]: ')}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(0)
        if raw in ("1", "2"):
            return int(raw)
        print(f"  {cyan('Please enter 1 or 2.')}")


if __name__ == "__main__":
    try:
        choice = show_menu()
        if choice == 1:
            monitor()
        else:
            monitor_udp()
    except KeyboardInterrupt:
        print(green("\n  Monitor stopped. Logs saved to: ") + cyan(LOG_FILE) + "\n")
# this was fun to make, the dashboard is pretty slick too google search the exe and whois ipv4 remote_addr only for now :\