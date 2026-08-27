"""Observable discrimination (ADR-0030).

Classifies an observable value as `discriminating` — it narrows the field to this
report — or `ubiquitous` — it appears in the overwhelming majority of intrusion
reports and therefore carries no ranking signal.

Document frequency cannot do this job: measured on the live store it keeps
`certutil` (df=15), `ping` (10), `tasklist` (7) and `netstat` (9), and strips
`api.telegram.org` (60). It cuts the wrong way because it measures rarity in the
RULE corpus, which is simply not the property being asked about.

Contract: this module never raises. Any malformed input falls back to UBIQUITOUS.
"""
from __future__ import annotations

DISCRIMINATING: str = "discriminating"
UBIQUITOUS: str = "ubiquitous"

#: Binaries that ship with the operating system, plus the LOLBAS set. A report
#: mentioning `certutil` is not thereby distinguishable from any other intrusion
#: report, so a rule matching on it has corroborated nothing. Stored as bare
#: stems, lowercase, without extension -- `_stem` normalises before lookup.
UBIQUITOUS_BINARIES: frozenset[str] = frozenset({
    # Windows: LOLBAS and shipped system binaries
    "at", "atbroker", "attrib", "bcdedit", "bitsadmin", "bootcfg", "cacls",
    "calc", "certreq", "certutil", "change", "chcp", "chkdsk", "cipher", "cmd",
    "cmdkey", "cmdl32", "cmstp", "colorcpl", "comp", "compact",
    "computerdefaults", "conhost", "control", "csc", "cscript", "csvde",
    "dataexchangehost", "defrag", "desktopimgdownldr", "dfsvc", "diantz",
    "diskshadow", "dllhost", "dnscmd", "driverquery", "dsacls", "dsget",
    "dsquery", "esentutl", "eventvwr", "expand", "explorer", "extexport",
    "extrac32", "findstr", "finger", "fltmc", "forfiles", "format", "fsutil",
    "gpresult", "gpscript", "gpupdate", "hh", "ie4uinit", "ieexec", "iexpress",
    "infdefaultinstall", "installutil", "ipconfig", "jsc", "klist", "ldifde",
    "lsass", "magnify", "makecab", "mavinject", "mmc", "mofcomp", "mpcmdrun",
    "msbuild", "msconfig", "msdt", "mshta", "msiexec", "narrator", "nbtstat",
    "net", "net1", "netsh", "netstat", "nltest", "nslookup", "odbcconf",
    "openwith", "osk", "pcalua", "pcwrun", "pktmon", "pnputil",
    "presentationhost", "logoff", "msg", "mstsc", "qwinsta", "rwinsta",
    "tskill", "waitfor", "where", "wusa",
    "print", "printbrm", "psr", "pwsh", "quser", "query", "rasautou", "reg",
    "regasm", "regedit", "regini", "regsvcs", "regsvr32", "replace",
    "robocopy", "route", "rpcping", "runas", "rundll32", "runonce",
    "runscripthelper", "sc", "schtasks", "scriptrunner", "sdclt",
    "sdiagnhost", "services", "sethc", "setx", "shutdown", "spoolsv",
    "svchost", "syncappvpublishingserver", "systeminfo", "takeown",
    "taskhostw", "taskkill", "tasklist", "tracert", "ttdinject", "tttracer",
    "typeperf", "utilman", "vbc", "verclsid", "vssadmin", "wab", "wbadmin",
    "wevtutil", "winlogon", "winrm", "winrs", "wmic", "wmiprvse", "wscript",
    "wsreset", "wuauclt", "xcopy", "xwizard",
    # Cross-platform shells, interpreters and network clients
    "bash", "csh", "curl", "dash", "ftp", "ksh", "perl", "php", "ping",
    "powershell", "python", "python2", "python3", "ruby", "scp", "sftp", "sh",
    "ssh", "tar", "telnet", "wget", "wsl", "zsh",
    # Unix: coreutils and standard administration
    "apt", "apt-get", "arp", "awk", "base32", "base64", "busybox", "bzip2",
    "cat", "chattr", "chmod", "chown", "chroot", "cp", "crontab", "cut", "dd",
    "df", "dig", "dmesg", "dnf", "docker", "du", "echo", "env", "expr",
    "find", "gawk", "gcc", "gdb", "getent", "gpg", "grep", "groupadd",
    "gzip", "head", "hostname", "iconv", "id", "ifconfig", "insmod", "ip",
    "iptables", "journalctl", "kill", "killall", "last", "ld", "ldconfig",
    "less", "ln", "ls", "lsmod", "lsof", "make", "md5sum", "mkdir", "mknod",
    "modprobe", "more", "mount", "mv", "nice", "nohup", "nsenter", "od",
    "openssl", "passwd", "pkexec", "pkill", "ps", "rm", "rpm", "rsync",
    "sed", "service", "setcap", "sha1sum", "sha256sum", "sort", "ss",
    "ssh-keygen", "strace", "su", "sudo", "systemctl", "systemd", "tail",
    "tee", "tmux", "top", "touch", "tr", "traceroute", "umount", "uname",
    "uniq", "unzip", "useradd", "usermod", "vi", "vim", "w", "wall", "watch",
    "wc", "which", "who", "whoami", "xargs", "xxd", "yum", "zip",
    # macOS
    "codesign", "csrutil", "defaults", "ditto", "dscl", "hdiutil",
    "installer", "launchctl", "mdfind", "mdls", "networksetup", "open",
    "osascript", "plutil", "security", "softwareupdate", "spctl", "sw_vers",
    "system_profiler", "xattr", "xcode-select",
})

#: Whole values that are standard system locations. Only an EXACT match counts:
#: a payload dropped in %TEMP% keeps its discriminating power, so a path PREFIX
#: must never demote a filename. `/etc/passwd` is kept as an observable by
#: ADR-0014 on purpose; this stops it from corroborating.
UBIQUITOUS_EXACT_PATHS: frozenset[str] = frozenset({
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group", "/etc/sudoers",
    "/etc/crontab", "/etc/resolv.conf", "/etc/fstab", "/etc/issue",
    "/dev/null", "/dev/tcp", "/dev/udp", "/dev/zero", "/dev/random",
    "/proc/self", "/proc/version", "/proc/cpuinfo", "/proc/mounts",
    "/tmp", "/var/tmp", "/var/log", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
    "/var/log/secure", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog",
    "/var/log/cron", "/var/log/maillog", "/var/log/kern.log",
    "/var/log/boot.log", "/var/log/audit/audit.log", "/var/log/dmesg",
    "/root/.ssh/authorized_keys", "/root/.bash_history",
    "c:/windows/system32", "c:/windows/syswow64", "c:/windows/temp",
    "c:/program files", "c:/program files (x86)", "c:/users/public",
    "%temp%", "%tmp%", "%appdata%", "%localappdata%", "%programdata%",
    "%systemroot%", "%windir%", "%userprofile%", "%programfiles%",
})

#: Standard OS files, as BARE NAMES. `observables_from_entities` emits both the
#: full path and its basename, so `/etc/shadow` arrives twice — once as a path
#: this module already classifies, and once as `shadow`, which is neither a
#: binary nor a path and so escaped the check entirely. Measured on the Cisco
#: SD-WAN report: `shadow` and `auth.log` were the ONLY thing admitting 10 of the
#: 10 rules the panel served, including `Simple keyword detection rule for cat`.
#: Both the basename and its extension-stripped stem are tested, so `auth.log`
#: and `auth`-style spellings are both covered.
UBIQUITOUS_SYSTEM_FILES: frozenset[str] = frozenset({
    # Unix account, auth and system configuration
    "passwd", "shadow", "group", "gshadow", "sudoers", "hosts", "hostname",
    "resolv.conf", "fstab", "issue", "motd", "crontab", "profile", "bashrc",
    "bash_history", "zsh_history", "bash_profile", "bash_logout", "netrc",
    # Unix logs — every intrusion report names them; they identify no campaign
    "auth.log", "authlog", "syslog", "messages", "secure", "wtmp", "btmp",
    "lastlog", "utmp", "dmesg", "boot.log", "cron", "maillog", "faillog",
    "audit.log", "kern.log", "daemon.log", "sulog",
    # SSH material — a credential-access target, not an identity
    "authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", "ssh_config", "sshd_config",
    # Windows credential stores and answer files
    "sam", "ntds.dit", "system.hive", "security.hive", "software.hive",
    "unattend.xml", "sysprep.inf", "sysprep.xml", "groups.xml",
})

#: Registry prefixes every persistence report touches. Matched as a PREFIX,
#: because the value carries a trailing value name that varies per campaign
#: while the key itself is the ubiquitous part.
UBIQUITOUS_REGISTRY_PREFIXES: tuple[str, ...] = (
    "hklm/software/microsoft/windows/currentversion/run",
    "hkcu/software/microsoft/windows/currentversion/run",
    "hklm/software/microsoft/windows nt/currentversion/winlogon",
    "hklm/system/currentcontrolset/services",
    "hklm/software/microsoft/windows nt/currentversion/image file execution options",
    "hkcu/software/microsoft/windows/currentversion/explorer/run",
)

#: Free-mail, cloud and developer hosts. A report naming an attacker's Gmail
#: address is describing something specific -- but the observable pipeline
#: reduces that address to `gmail.com`, which is not. Abused-service endpoints
#: that DO narrow the field (`api.telegram.org`, `t.me`, `pastebin.com`,
#: `discord.com`) are deliberately ABSENT: only a subset of campaigns use them,
#: so they must keep corroborating.
UBIQUITOUS_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "google.com", "googleapis.com",
    "gstatic.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "office.com", "office365.com", "sharepoint.com", "onedrive.com",
    "microsoft.com", "windows.net", "azurewebsites.net", "azure.com",
    "yahoo.com", "aol.com", "icloud.com", "apple.com", "me.com",
    "protonmail.com", "proton.me", "tutanota.com", "zoho.com", "gmx.com",
    "mail.ru", "yandex.ru", "yandex.com", "qq.com", "163.com",
    "amazon.com", "amazonaws.com", "cloudflare.com", "akamai.net",
    "akamaiedge.net", "fastly.net", "digitalocean.com",
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "instagram.com", "wikipedia.org", "w3.org", "mozilla.org",
    "localhost", "example.com", "example.org", "test.com",
})

#: Addresses that are infrastructure, not indicators: public resolvers and
#: wildcard/broadcast forms. RFC1918 ranges are NOT here -- an internal pivot
#: target is real incident content (ADR-0014).
UBIQUITOUS_IPS: frozenset[str] = frozenset({
    "0.0.0.0", "255.255.255.255", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "77.88.8.8", "114.114.114.114",
})

#: Built-in principals. A rule matching on `SYSTEM` has corroborated nothing.
UBIQUITOUS_USERS: frozenset[str] = frozenset({
    "administrator", "admin", "root", "system", "guest", "localsystem",
    "nt authority/system", "nt authority/local service",
    "nt authority/network service", "local service", "network service",
    "everyone", "users", "authenticated users", "domain admins",
    "domain users", "administrators",
})

#: Category words that extraction routinely emits as malware or tool NAMES.
#: ADR-0025 measured `Wiper` (38 rules) and `Solar` (56 rules, three unrelated
#: products sharing a prefix) promoted to full coverage this way. They name a
#: class of thing, never an identity, so they must not corroborate. The real
#: fix is upstream in extraction; this is the stopgap that stops them scoring.
UBIQUITOUS_CATEGORY_WORDS: frozenset[str] = frozenset({
    "wiper", "stealer", "infostealer", "loader", "dropper", "backdoor",
    "rat", "ransomware", "trojan", "worm", "botnet", "keylogger",
    "downloader", "webshell", "shell", "rootkit", "bootkit", "miner",
    "cryptominer", "malware", "implant", "beacon", "payload", "shellcode",
    "exploit", "vulnerability", "threat", "actor", "campaign", "cluster",
    "phishing", "spearphishing", "smishing", "vishing", "adware", "spyware",
    "wiperware", "scareware", "cryptor", "packer", "obfuscator", "injector",
    "atomic", "solar", "generic", "unknown", "unnamed", "suspicious",
    "windows", "linux", "macos", "android", "ios", "unix", "office",
    "javascript", "vbscript", "jscript", "dotnet", "java", "node", "nodejs",
})


def _stem(value: str) -> str:
    """Extract the basename without directory or extension, lowercased."""
    if not value:
        return ""
    # Normalize separators
    v = value.replace("\\", "/")
    # Get basename
    parts = v.split("/")
    base = parts[-1]
    if not base:
        return ""
    # Remove one extension if it is 1-4 alphanumeric chars
    if "." in base:
        name, ext = base.rsplit(".", 1)
        if 1 <= len(ext) <= 4 and ext.isalnum():
            base = name
    return base.lower()


def _host(value: str) -> str:
    """Extract the host from a URL or domain, lowercased, without schema/port/path."""
    if not value:
        return ""
    v = value.lower()
    # Remove schema
    if "://" in v:
        v = v.split("://", 1)[1]
    # Cut at leftmost delimiter among /, ?, #
    for delim in ["/", "?", "#"]:
        if delim in v:
            v = v.split(delim, 1)[0]
    # Remove userinfo
    if "@" in v:
        v = v.rsplit("@", 1)[-1]
    # Remove port
    if ":" in v:
        v = v.split(":", 1)[0]
    return v


def _registrable(host: str) -> str:
    """Return the last two labels of a hostname."""
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def discrimination(obs_class: str, value: str) -> str:
    """Classify one observable value. Returns DISCRIMINATING or UBIQUITOUS."""
    # Check value validity first
    if not isinstance(value, str) or not value.strip():
        return UBIQUITOUS

    v = value.strip().lower().replace("\\", "/")

    # Check class validity
    if not isinstance(obs_class, str):
        return DISCRIMINATING

    obs_class = obs_class.lower()

    if obs_class == "hash":
        return DISCRIMINATING
    elif obs_class == "cve":
        return DISCRIMINATING
    elif obs_class == "port":
        return UBIQUITOUS
    elif obs_class == "ip":
        return UBIQUITOUS if v in UBIQUITOUS_IPS else DISCRIMINATING
    elif obs_class in ("domain", "url"):
        h = _host(v)
        if h in UBIQUITOUS_DOMAINS or _registrable(h) in UBIQUITOUS_DOMAINS:
            return UBIQUITOUS
        return DISCRIMINATING
    elif obs_class == "user":
        return UBIQUITOUS if v in UBIQUITOUS_USERS else DISCRIMINATING
    elif obs_class == "registry":
        for prefix in UBIQUITOUS_REGISTRY_PREFIXES:
            if v.startswith(prefix):
                return UBIQUITOUS
        return DISCRIMINATING
    elif obs_class in ("file", "image"):
        if v in UBIQUITOUS_EXACT_PATHS:
            return UBIQUITOUS
        if _stem(v) in UBIQUITOUS_BINARIES:
            return UBIQUITOUS
        # The basename arrives as its own observable alongside the full path,
        # so it must be checked too — `shadow` as well as `/etc/shadow`.
        base = v.rsplit("/", 1)[-1]
        if base in UBIQUITOUS_SYSTEM_FILES or _stem(v) in UBIQUITOUS_SYSTEM_FILES:
            return UBIQUITOUS
        return DISCRIMINATING
    elif obs_class == "name":
        stem = _stem(v)
        if stem in UBIQUITOUS_BINARIES or stem in UBIQUITOUS_CATEGORY_WORDS:
            return UBIQUITOUS
        return DISCRIMINATING
    else:
        return DISCRIMINATING


def is_ubiquitous(obs_class: str, value: str) -> bool:
    """True when `value` carries no ranking signal for its class."""
    return discrimination(obs_class, value) == UBIQUITOUS
