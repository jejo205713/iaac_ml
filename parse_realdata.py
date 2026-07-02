#!/usr/bin/env python3
"""Parse the v3 REAL-data haul (agents' downloads) into labeled seeds/*.jsonl.

Key design decision (fixes the RECON<->BENIGN confusion, ml_build.md weak spot #1):
label by the COMMAND STRING itself, consistently across every source. The model can
only see the string, so the label must be a function of the string — `find / -perm
-4000` -> RECON, `find . -name '*.py'` -> BENIGN. Bare ambiguous dual-use (`whoami`,
bare `netstat`) defaults to BENIGN: the safe, low-false-positive choice (product rule #1).

Every row is is_synthetic=FALSE — this is the real-telemetry-adjacent injection that
addresses the "0% real data" gap. reviewed_by='heuristic-v3' flags them for the
spot-check pass (high-loss surfacing + boundary sampling) before they're fully trusted.
"""
import os, re, json, csv, html, collections
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DD = os.path.join(HERE, "datasets")
SEEDS = os.path.join(HERE, "seeds")
LABELS = {"BENIGN", "ADMIN", "RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION"}

# ---------------------------------------------------------------- cleaning
PROMPT_RE = re.compile(r'^[\w.\-]+@[\w.\-]+:[^\$#]*[\$#]\s*')   # user@host:/path$ cmd
TLDR_DEFAULTS = {
    "file": "file.txt", "path": "/path/to/file", "path/to/file": "/path/to/file",
    "path/to/directory": "/path/to/dir", "directory": "dir", "dir": "dir",
    "protocol": "tcp", "port": "8080", "host": "example.com", "hostname": "host",
    "ip": "10.0.0.1", "user": "user", "username": "user", "pattern": "pattern",
    "command": "cmd", "pid": "1234", "package": "pkg", "url": "http://example.com",
}
def _tldr_ph(m):
    inner = m.group(1).strip()
    return TLDR_DEFAULTS.get(inner, re.sub(r'[^\w./-]', '', inner.split("|")[0]) or "x")
TLDR_PH_RE = re.compile(r'\{\{(.*?)\}\}')

def clean(cmd):
    if not cmd:
        return None
    c = html.unescape(str(cmd)).strip()
    c = TLDR_PH_RE.sub(_tldr_ph, c)              # tldr {{placeholder}} -> concrete
    c = PROMPT_RE.sub('', c).strip()             # strip shell prompt prefix
    c = c.strip('`').strip()                     # strip stray backticks
    if c.startswith("$ ") or c.startswith("# "):
        c = c[2:].strip()
    # reject junk: empty, too short, prose (no command-ish token), pure placeholder
    if len(re.sub(r'\s', '', c)) < 3:
        return None
    if c.lower() in {"alias", "true", "false", "exit", "clear"}:
        return None
    if not re.match(r'^[\w./~\-]', c):           # must start command-like
        return None
    if len(c) > 400:
        return None
    if re.search(r'<[a-z][\w .\-]*>', c, re.I):   # <placeholder> template junk
        return None
    # reject English prose that leaked into a command field (capitalized sentence)
    if re.match(r'^[A-Z][a-z]+\s', c) and not c.startswith('/') and '=' not in c.split()[0]:
        return None
    return c

# ---------------------------------------------------------------- labeler (LFs)
# ordered priority: high-confidence UNSAFE > RECON > ADMIN > BENIGN
UNSAFE = [
    (r'(bash|sh|nc|ncat|python\d?|perl|ruby|php)\b.*(-c|-e|/dev/tcp|reverse|>&|0>&1|pty|socket)', "EXPLOIT"),
    (r'\brm\s+-[rf]{1,2}\b.*(/|\*)', "EXPLOIT"),
    (r':\(\)\s*\{.*\|.*&\s*\}\s*;', "EXPLOIT"),                      # fork bomb
    (r'\b(mkfs|dd)\b.*(/dev/[sh]d|of=/dev/)', "EXPLOIT"),
    (r'(curl|wget).*(\||;)\s*(bash|sh|python)', "EXPLOIT"),
    (r'\b(chmod|chown)\s+(4755|u\+s|\+s)\b', "PERSISTENCE"),        # setuid backdoor
    (r'(crontab\s+.*(curl|wget|/tmp/|base64)|echo.*>>?\s*/etc/cron)', "PERSISTENCE"),
    (r'(>>?\s*~?/.ssh/authorized_keys|echo.*ssh-rsa.*authorized_keys)', "PERSISTENCE"),
    (r'/etc/systemd/system/.*\.service.*(curl|wget|/tmp)', "PERSISTENCE"),
    (r'(curl|wget|nc)\b.*(-d|--data|POST|/dev/tcp).*(\$\(|passwd|shadow|token|secret)', "EXFILTRATION"),
    (r'(aws\s+s3|scp|rsync)\b.*(secret|\.env|id_rsa|/etc/)', "EXFILTRATION"),
]
RECON = [
    r'\b(cat|less|more|head|tail|strings|grep|awk|sed)\b[^|;]*\b/etc/(passwd|shadow|sudoers|group|gshadow)\b',
    r'\bcat\b[^|;]*/proc/(version|self/environ)\b',
    r'\bfind\b[^|;]*-perm\b[^|;]*(4000|2000|-u\+s|-g\+s|/[0-9]{3,4})',
    r'\bfind\b[^|;]*-perm\b[^|;]*-0[0-7]{3}',
    r'\bfind\b[^|;]*\b(id_rsa|id_dsa|\.pem|authorized_keys|\.kube|\.aws)\b',
    r'\bgetcap\b\s+-r',
    r'\bsudo\s+-n?\s*-?l\b',                                        # sudo -l enum
    r'\b(enum4linux|linpeas|linenum|lse\.sh|pspy|unix-privesc-check|smbmap)\b',
    r'\b(showmount|rpcinfo|ldapsearch)\b',
    r'\bgrep\b[^|;]*-r[a-z]*\b[^|;]*(password|passwd|secret|api[_-]?key|BEGIN.*PRIVATE)',
    r'\b(whoami|id|uname|hostname|hostnamectl)\b.*&&.*\b(whoami|id|uname|hostname|w|last)\b',  # enum chain
    r'\bcat\b[^|;]*(\.bash_history|\.mysql_history)\b',
    r'\bnmap\b',
]
ADMIN = [
    r'\bsudo\b',
    r'\b(systemctl|service|journalctl|systemd-\w+)\b',
    r'\b(apt|apt-get|yum|dnf|pacman|zypper|dpkg|snap|rpm)\b',
    r'\b(docker|docker-compose|podman|kubectl|helm|containerd|nerdctl)\b',
    r'\b(useradd|usermod|userdel|groupadd|groupmod|passwd|chpasswd|adduser|deluser)\b',
    r'\b(iptables|nft| nft|ufw|firewall-cmd|firewalld)\b',
    r'\b(mount|umount|mkfs|fdisk|parted|lvm|lvcreate|vgcreate|pvcreate|mdadm|cryptsetup)\b',
    r'\b(modprobe|insmod|rmmod|sysctl|dmesg|update-grub|grub-\w+|mkinitramfs|dracut)\b',
    r'\b(crontab|systemd-run|timedatectl|hostnamectl|localectl|update-alternatives)\b',
    r'\b(nginx|apache2|apachectl|httpd|mysqld?|postgres\w*|redis-\w+|named)\b',
    r'\b(rsync|tar)\b.*(backup|/etc|/var|/home)',
    r'\bchmod\b.*-R\b', r'\bchown\b.*-R\b',
    r'\b(ansible|ansible-playbook|terraform|puppet|chef|salt)\b',
    r'\b(pip\d?|npm|gem|cargo)\s+install\b.*-g\b',
    r'\bmake\s+install\b',
]
def _any(pats, c): return any(re.search(p, c, re.I) for p in pats)

def label(c):
    for pat, cls in UNSAFE:
        if re.search(pat, c, re.I):
            return cls
    if _any(RECON, c):
        return "RECON"
    if _any(ADMIN, c):
        return "ADMIN"
    return "BENIGN"

def family_id(c):
    toks = re.findall(r'[A-Za-z0-9_./-]+', c)
    base = os.path.basename(toks[0]) if toks else "misc"
    sub = toks[1] if len(toks) > 1 and re.match(r'^[a-z-]+$', toks[1]) else ""
    return re.sub(r'[^a-z0-9]+', '-', f"{base}-{sub}".lower()).strip('-') or "misc"

def rec(cmd, source):
    c = clean(cmd)
    if not c:
        return None
    return {"command": c, "expected": label(c), "source": source, "technique": None,
            "is_synthetic": False, "is_obfuscated": False,
            "family_id": family_id(c), "reviewed_by": "heuristic-v3"}

# ---------------------------------------------------------------- extractors
def j(path):
    return json.load(open(path))

def extract():
    out = []  # (rows, source)
    def add(rows, src):
        rs = [r for r in (rec(x, src) for x in rows) if r]
        out.append((rs, src)); print(f"  {src:26s} raw->{len(rs)}")

    P = lambda *a: os.path.join(DD, *a)
    # NL->bash / real command corpora (command in a specific field)
    if os.path.exists(P("cli-commands-explained")):
        f = [x for x in os.listdir(P("cli-commands-explained")) if x.endswith(".json")][0]
        add([r.get("code") for r in j(P("cli-commands-explained", f))], "real_commandlinefu_cc0")
    if os.path.exists(P("romit-linuxcommands", "Processed.csv")):
        with open(P("romit-linuxcommands", "Processed.csv")) as fh:
            add([r["cmd"] for r in csv.DictReader(fh) if r.get("cmd")], "real_romit_mit")
    if os.path.exists(P("mecha-linux-command", "linuxcommands.json")):
        add([r.get("output") for r in j(P("mecha-linux-command", "linuxcommands.json"))], "real_mecha_apache")
    pq = P("bash-command-6k", "data")
    if os.path.exists(pq):
        f = [x for x in os.listdir(pq) if x.endswith(".parquet")][0]
        df = pd.read_parquet(os.path.join(pq, f))
        col = "completion" if "completion" in df.columns else df.columns[-1]
        add(df[col].dropna().tolist(), "real_bash6k_apache")
    if os.path.exists(P("bash-commands", "dataset.json")):
        add([r.get("response") for r in j(P("bash-commands", "dataset.json"))], "real_aelhalili_mit")
    if os.path.exists(P("linux-terminal-commands")):
        f = [x for x in os.listdir(P("linux-terminal-commands")) if x.endswith(".jsonl")][0]
        rows = []
        for l in open(P("linux-terminal-commands", f)):
            if not l.strip():
                continue
            try:
                rows.append(json.loads(l)["command"])
            except (json.JSONDecodeError, KeyError):
                m = re.search(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)"', l)
                if m:
                    rows.append(m.group(1))
        add(rows, "real_darkknight_mit")
    if os.path.exists(P("linux-commands-mrheinen", "ds.json")):
        add([r.get("input") for r in j(P("linux-commands-mrheinen", "ds.json"))], "real_mrheinen_apache")
    if os.path.exists(P("unix-commands-harpomaxx")):
        f = [x for x in os.listdir(P("unix-commands-harpomaxx")) if x.endswith(".json")][0]
        add([r.get("input") for r in j(P("unix-commands-harpomaxx", f))], "real_harpomaxx_ccby")
    # tldr: only linux + common pages (skip osx/windows/android/... — not our target OS)
    rows = []
    for sub in ("common", "linux"):
        d = P("tldr", "pages", sub)
        if not os.path.exists(d):
            continue
        for fn in os.listdir(d):
            if fn.endswith(".md"):
                for line in open(os.path.join(d, fn)):
                    m = re.match(r'^`(.+)`\s*$', line.strip())
                    if m:
                        rows.append(m.group(1))
    if rows:
        add(rows, "real_tldr_ccby")
    # RECON-side enumeration scripts
    if os.path.exists(P("linenum", "LinEnum.sh")):
        rows = re.findall(r'`([^`]+)`', open(P("linenum", "LinEnum.sh")).read())
        add(rows, "real_linenum_mit")
    if os.path.exists(P("linuxprivchecker", "linuxprivchecker.py")):
        rows = re.findall(r'"cmd"\s*:\s*"([^"]+)"', open(P("linuxprivchecker", "linuxprivchecker.py")).read())
        add(rows, "real_privchecker_mit")
    return out

def main():
    print("parsing v3 real-data haul ->")
    groups = extract()
    dist = collections.Counter()
    total, quarantined = 0, 0
    SAFE_TRAIN = {"BENIGN", "ADMIN", "RECON"}   # trust heuristic only for these
    qf = open(os.path.join(HERE, "_quarantine_realdata_unsafe.jsonl"), "w")
    for rows, src in groups:
        # dedup within source by normalized command
        seen, uniq = set(), []
        for r in rows:
            k = re.sub(r'\s+', ' ', r["command"]).strip().lower()
            if k not in seen:
                seen.add(k); uniq.append(r)
        with open(os.path.join(SEEDS, src + ".jsonl"), "w") as fh:
            for r in uniq:
                # attack labels heuristically inferred on BENIGN corpora are untrusted:
                # quarantine (not trained) — real attack data comes from curated sources.
                if r["expected"] not in SAFE_TRAIN:
                    qf.write(json.dumps(r) + "\n"); quarantined += 1; continue
                fh.write(json.dumps(r) + "\n")
                dist[r["expected"]] += 1; total += 1
    qf.close()
    print(f"\nwrote {total} REAL train rows across {len(groups)} sources "
          f"({quarantined} unsafe-heuristic rows quarantined, not trained)")
    for k in sorted(dist):
        print(f"  {k:14s} {dist[k]}")

if __name__ == "__main__":
    main()
