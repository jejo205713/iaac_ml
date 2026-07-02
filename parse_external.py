#!/usr/bin/env python3
"""Parse cloned external attack/benign sources into the §15.0 seed schema.

Sources (in ~/projects/ml/datasets, cloned separately):
  - Atomic Red Team (MIT)      -> auto-labeled by MITRE tactic  -> seeds/ext_atomic.jsonl
  - Reverse-shell zip (Kaggle) -> EXPLOIT                        -> seeds/ext_revshell.jsonl
  - Kaggle LINUX_TERMINAL      -> BENIGN/ADMIN by category       -> seeds/ext_kaggle_linux.jsonl
  - GTFOBins (GPL-3.0)         -> QUARANTINED (license risk)     -> ../_quarantine_GPL/ext_gtfobins.jsonl

Strings only; nothing is executed. GTFOBins is written to a separate quarantine
dir and NOT into seeds/ — GPL-3.0 is a derived-labels risk for a commercial
product; merge it only after a licensing decision.
"""
import os, re, json, glob, yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "seeds")
DSROOT = "/home/knightofnull/projects/ml/datasets"
QUAR = os.path.join(HERE, "..", "_quarantine_GPL")
os.makedirs(QUAR, exist_ok=True)

# ---- Atomic tactic -> our class (priority: higher wins on duplicate command) ----
TACTIC2CLASS = {
    "persistence": "PERSISTENCE",
    "exfiltration": "EXFILTRATION", "command-and-control": "EXFILTRATION",
    "collection": "EXFILTRATION", "credential-access": "EXFILTRATION",
    "discovery": "RECON", "reconnaissance": "RECON",
    "execution": "EXPLOIT", "privilege-escalation": "EXPLOIT", "impact": "EXPLOIT",
    "lateral-movement": "EXPLOIT", "initial-access": "EXPLOIT", "stealth": "EXPLOIT",
    "defense-impairment": "EXPLOIT", "defense-evasion": "EXPLOIT",
    "resource-development": "EXPLOIT",
}
PRIORITY = {"PERSISTENCE": 4, "EXFILTRATION": 3, "RECON": 2, "EXPLOIT": 1}


def write(path, rows):
    with open(path, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def subst_args(cmd, args):
    for name, spec in (args or {}).items():
        default = "" if not isinstance(spec, dict) else spec.get("default", "")
        cmd = cmd.replace("#{%s}" % name, str(default))
    return cmd


def parse_atomic():
    idx = os.path.join(DSROOT, "atomic-red-team/atomics/Indexes/linux-index.yaml")
    d = yaml.safe_load(open(idx))
    best = {}  # command -> (class, tid)
    for tactic, techs in d.items():
        cls = TACTIC2CLASS.get(tactic, "EXPLOIT")
        for tid, info in (techs or {}).items():
            for t in (info.get("atomic_tests") or []):
                plats = t.get("supported_platforms") or []
                ex = t.get("executor") or {}
                if "linux" not in plats or ex.get("name") not in ("sh", "bash"):
                    continue
                cmd = (ex.get("command") or "").strip()
                if not cmd:
                    continue
                cmd = subst_args(cmd, t.get("input_arguments"))[:4096].strip()
                if not cmd:
                    continue
                if cmd not in best or PRIORITY[cls] > PRIORITY[best[cmd][0]]:
                    best[cmd] = (cls, tid)
    rows = [{"command": c, "expected": cls, "source": "atomic-red-team",
             "technique": tid, "is_synthetic": False, "is_obfuscated": False,
             "family_id": f"atomic-{tid}", "reviewed_by": None}
            for c, (cls, tid) in best.items()]
    return rows


def parse_revshell():
    f = os.path.join(DSROOT, "revshell_zip", "Reverseshell_payloads_dataset.jsonl")
    linux_langs = {"bash", "sh", "netcat", "python", "python3", "perl", "php",
                   "ruby", "awk", "socat", "telnet", "lua", "nodejs", "node",
                   "groovy", "openssl", "ncat"}
    rows = []
    for l in open(f):
        l = l.strip()
        if not l:
            continue
        try:
            r = json.loads(l)
        except Exception:
            continue
        lang = (r.get("language") or "").lower()
        plat = (r.get("platform") or "").lower()
        if plat and plat != "linux" and lang not in linux_langs:
            continue
        if lang in ("powershell",) and plat == "windows":
            continue
        cmd = (r.get("payload") or "").strip()[:4096]
        if not cmd:
            continue
        rows.append({"command": cmd, "expected": "EXPLOIT", "source": "kaggle-revshell",
                     "technique": "T1059", "is_synthetic": False,
                     "is_obfuscated": bool(r.get("obfuscated", False)),
                     "family_id": f"revshell-{lang or 'misc'}", "reviewed_by": None})
    return rows


CATMAP = {  # Kaggle LINUX_TERMINAL category -> BENIGN/ADMIN
    "Navigation": "BENIGN", "Viewing": "BENIGN", "File Management": "BENIGN",
    "System Info": "BENIGN", "Editor": "BENIGN", "Process": "BENIGN",
    "Networking": "ADMIN", "Permissions": "ADMIN", "User Management": "ADMIN",
    "Package Management": "ADMIN",
}
# dual-use commands that the category mislabels — force safe only if clearly benign
DUALUSE = re.compile(r"\b(dd|mkfs|mknod|nc|ncat|/dev/tcp|shred)\b")


def parse_kaggle_linux():
    f = "/home/knightofnull/Downloads/LINUX_TERMINAL_COMMANDS.jsonl"
    if not os.path.exists(f):
        return []
    rows = []
    for l in open(f):
        l = l.strip()
        if not l:
            continue
        try:
            r = json.loads(l)
        except Exception:
            continue
        cmd = (r.get("command") or "").strip()[:4096]
        cat = r.get("category", "")
        if not cmd:
            continue
        cls = CATMAP.get(cat, "ADMIN")
        # skip dual-use rows that need human adjudication rather than mislabel them safe
        if DUALUSE.search(cmd):
            continue
        rows.append({"command": cmd, "expected": cls, "source": "kaggle-linux-terminal",
                     "technique": None, "is_synthetic": False, "is_obfuscated": False,
                     "family_id": f"kaggle-{cat.lower().replace(' ', '-')}",
                     "reviewed_by": None})
    return rows


FUNC2CLASS = {
    "file-read": "RECON", "file-upload": "EXFILTRATION",
}  # everything else in GTFOBins -> EXPLOIT


def parse_gtfobins():
    rows = []
    for path in glob.glob(os.path.join(DSROOT, "gtfobins", "_gtfobins", "*")):
        binname = os.path.basename(path).replace(".md", "")
        txt = open(path, errors="ignore").read()
        # GTFOBins files are pure YAML front-matter after a single leading '---'
        parts = txt.split("---", 1)
        if len(parts) < 2:
            continue
        try:
            fm = yaml.safe_load(parts[1])
        except Exception:
            continue
        if not isinstance(fm, dict):
            continue
        for func, entries in (fm.get("functions") or {}).items():
            cls = FUNC2CLASS.get(func, "EXPLOIT")
            for e in (entries or []):
                code = (e.get("code") or "").strip()[:4096] if isinstance(e, dict) else ""
                if not code:
                    continue
                rows.append({"command": code, "expected": cls, "source": "gtfobins",
                             "technique": None, "is_synthetic": False, "is_obfuscated": False,
                             "family_id": f"gtfobins-{binname}-{func}",
                             "reviewed_by": None, "license": "GPL-3.0"})
    return rows


INTENT2CLASS = {
    "NETWORK_SCAN": "RECON", "VULNERABILITY_AUDIT": "RECON",
    "DIRECTORY_BRUTEFORCE": "RECON", "SERVICE_ENUMERATION": "RECON",
    "PASSIVE_RECON": "RECON", "PASSWORD_ATTACK": "EXPLOIT", "EXPLOITATION": "EXPLOIT",
}  # REJECTED / AMBIGUOUS intentionally dropped


def parse_pentest():
    import csv
    f = os.path.join(DSROOT, "pentest_zip", "pentest-command-generation-dataset.csv")
    if not os.path.exists(f):
        return []
    rows = []
    for r in csv.DictReader(open(f)):
        cls = INTENT2CLASS.get((r.get("intent") or "").strip().upper())
        if not cls:
            continue
        cmd = (r.get("expected_command") or "").strip()[:4096]
        if not cmd or "<" in cmd and ">" in cmd:  # skip unfilled placeholder templates
            if "<" in cmd:
                continue
        if not cmd:
            continue
        tool = (r.get("expected_tool") or "misc").strip().lower()
        rows.append({"command": cmd, "expected": cls, "source": "kaggle-pentest",
                     "technique": None, "is_synthetic": False, "is_obfuscated": False,
                     "family_id": f"pentest-{cls.lower()}-{tool}", "reviewed_by": None})
    return rows


def parse_caldera():
    """MITRE Caldera stockpile abilities (Apache-2.0): linux sh/bash command,
    labeled by ATT&CK tactic. Fills lateral-movement / collection / C2 / exfil."""
    rows, seen = [], set()
    for path in glob.glob(os.path.join(DSROOT, "stockpile", "data", "abilities", "*", "*.yml")):
        try:
            docs = yaml.safe_load(open(path))
        except Exception:
            continue
        for ab in (docs or []):
            cls = TACTIC2CLASS.get((ab.get("tactic") or "").lower(), "EXPLOIT")
            tid = (ab.get("technique") or {}).get("attack_id")
            lin = (ab.get("platforms") or {}).get("linux") or {}
            for ex in ("sh", "bash"):
                blk = lin.get(ex)
                if not isinstance(blk, dict):
                    continue
                cmd = blk.get("command") or ""
                cmd = re.sub(r"#\{[^}]+\}", "X", cmd)      # strip Caldera fact placeholders
                cmd = re.sub(r"\s+", " ", cmd).strip()[:4096]
                if not cmd or cmd in seen:
                    continue
                seen.add(cmd)
                rows.append({"command": cmd, "expected": cls, "source": "caldera",
                             "technique": tid, "is_synthetic": False, "is_obfuscated": False,
                             "family_id": f"caldera-{tid or ab.get('id')}", "reviewed_by": None})
    return rows


def parse_privesc():
    f = os.path.join(DSROOT, "privesc_zip", "linux_window_priv_escalation_datatset.jsonl")
    if not os.path.exists(f):
        return []
    ENUM = re.compile(r"\bfind\b|getcap|sudo -l|\bcat \b|\bls \b|\bgrep\b|\buname\b|lsof|\bps \b|"
                      r"\bstat \b|\bmount\b|printenv|\benv\b|dpkg |rpm -qa|readlink|/proc/|\bwhich \b|\bid\b")
    PERSIST = re.compile(r"crontab|>>\s*/etc/cron|/etc/systemd|authorized_keys|"
                         r">>\s*/etc/(passwd|sudoers)|useradd|chmod \+s|chmod u\+s")
    rows = []
    for l in open(f):
        l = l.strip()
        if not l:
            continue
        try:
            r = json.loads(l)
        except Exception:
            continue
        if str(r.get("platform", "")).lower() != "linux":
            continue
        cmd = (r.get("command") or "").strip()[:4096]
        if not cmd:
            continue
        c = cmd.lower()
        tech = (r.get("mapped_technique") or "")
        if PERSIST.search(c) or tech[:5] in ("T1556", "T1053", "T1543"):
            cls = "PERSISTENCE"
        elif ENUM.search(c):
            cls = "RECON"
        elif tech[:5] in ("T1552", "T1003"):
            cls = "EXFILTRATION"
        else:
            cls = "EXPLOIT"
        cat = (r.get("category") or "misc").lower().replace(" ", "-")
        rows.append({"command": cmd, "expected": cls, "source": "kaggle-privesc",
                     "technique": tech or None, "is_synthetic": False, "is_obfuscated": False,
                     "family_id": f"privesc-{cat}", "reviewed_by": None})
    return rows


def summarize(name, rows):
    import collections
    c = collections.Counter(r["expected"] for r in rows)
    print(f"{name}: {len(rows)} rows  " + " ".join(f"{k}={c[k]}" for k in sorted(c)))


def main():
    atomic = parse_atomic()
    revshell = parse_revshell()
    kaggle = parse_kaggle_linux()
    pentest = parse_pentest()
    privesc = parse_privesc()
    caldera = parse_caldera()
    gtfo = parse_gtfobins()

    write(os.path.join(SEEDS, "ext_atomic.jsonl"), atomic)
    write(os.path.join(SEEDS, "ext_revshell.jsonl"), revshell)
    write(os.path.join(SEEDS, "ext_kaggle_linux.jsonl"), kaggle)
    write(os.path.join(SEEDS, "ext_pentest.jsonl"), pentest)
    write(os.path.join(SEEDS, "ext_privesc.jsonl"), privesc)
    write(os.path.join(SEEDS, "ext_caldera.jsonl"), caldera)
    write(os.path.join(SEEDS, "ext_gtfobins.jsonl"), gtfo)  # license cleared by owner

    print("=== parsed (MIT/clean -> seeds/) ===")
    summarize("atomic-red-team", atomic)
    summarize("kaggle-revshell ", revshell)
    summarize("kaggle-linux    ", kaggle)
    summarize("kaggle-pentest  ", pentest)
    summarize("kaggle-privesc  ", privesc)
    summarize("caldera         ", caldera)
    summarize("gtfobins(GPL ok)", gtfo)


if __name__ == "__main__":
    main()
