# Forgotten


![Forgotten](/images/Forgotten/forgotten.png)

**Forgotten** est une **box Linux de difficulté Easy** centrée sur une application web **LimeSurvey** exposée sur le port 80. Après énumération, on trouve une installation **LimeSurvey** nécessitant une configuration, ce qui permet de **déployer un plugin contenant un reverse shell PHP** pour obtenir un accès initial sur le conteneur Docker qui héberge l’application. À l’intérieur du conteneur, une **variable d’environnement exposent le mot de passe de l’utilisateur LimeSurvey**, ce qui permet de **se connecter via SSH directement à l’hôte avec ces identifiants**. Pour l’**escalade de privilèges**, j'abuse **du partage entre le conteneur et l’hôte** est utilisée afin d’obtenir un accès root sur la machine.

# Énumération
## Nmap

Le scan révèle 2 ports ouverts.
- 22 pour le service SSH sur une machine Ubuntu
- 80 pour le service HTTP faisant tourner un service Apache
```bash
Forgotten ➤ nmap -sT -sVC --min-rate 2000 -vvv -p- 10.129.146.197
--SNIP--
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 28c7f196f9536411f87055680be53c22 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMIbLmW6I3vlf8QRrAaFLhH3Ao7CFIvqPPmQG0Z14i0SlPfX9IZobRkjLOB0ncKb5oQ/0SXLnU60rnUe+7Xe6BU=
|   256 0243d2ba4e87de7772ce5afa865c0df4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICGL/2c6HVh+6F9RbNsZpoYJ2jv4C8SGqtskv0GGuU2P
80/tcp open  http    syn-ack Apache httpd 2.4.56
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP - TCP 80
### Site

Je n'ai pas la permission d'accéder à la page principale.
![](/images/Forgotten/Forgotten-1.png)

### feroxbuster

J'énumère alors les répertoires.
```bash
Forgotten ➤ feroxbuster -w `fzf-wordlists` -u "http://10.129.146.197"
--SNIP--
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      317c http://10.129.146.197/survey => http://10.129.146.197/survey/
302      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      324c http://10.129.146.197/survey/themes => http://10.129.146.197/survey/themes/
301      GET        9l       28w      325c http://10.129.146.197/survey/modules => http://10.129.146.197/survey/modules/
301      GET        9l       28w      323c http://10.129.146.197/survey/admin => http://10.129.146.197/survey/admin/
301      GET        9l       28w      324c http://10.129.146.197/survey/assets => http://10.129.146.197/survey/assets/
301      GET        9l       28w      324c http://10.129.146.197/survey/upload => http://10.129.146.197/survey/upload/
```
J'ai accès à un répertoire `/survey`.

### LimeSurvey

Je m'y rends et je vois qu'il s'agit d'une application [LimeSurvey](https://www.limesurvey.org/fr), un logiciel d'enquête statistiques et d'évaluation en ligne.
![](/images/Forgotten/Forgotten-2.png)
Je vois qu'il s'agit de la page d'installation de LimeSurvey. Je clique donc sur **Start Installation** pour continuer le processus d'installation.

Il s'agit de **LimeSurvey 6.3.7**. En recherchant sur Google `limesurvey 6.3.7 exploit`, cette version est vulnerable à un RCE via upload de fichier. Cet article de [INE](https://ine.com/blog/cve-2021-44967-limesurvey-rce) en parle.
![](/images/Forgotten/Forgotten-3.png)
Mais il faut que je connecte afin de l'exploiter. Je continue alors le processus d'installation.

Là, je dois mettre une configuration MySQL à utilisé. Je vais créer une configuration **MariaDB** sur ma machine et y mettre ses informations sur ce formulaire.
![](/images/Forgotten/Forgotten-4.png)


Premièrement je modifie la ligne suivante dans le fichier `/etc/mysql/mariadb.conf.d/50-server.cnf` afin de recevoir des connexions depuis n'importe qu'elle port de ma machine. 
```bash
bind-address            = 0.0.0.0
```
Je fais cela pour que MariaDB puisse utiliser le port **tun0**, port du VPN de Hackthebox.

Ensuite je démarre le service **mariadb**.
```bash
sudo systemctl enable mariadb && sudo systemctl start mariadb 
```

Je me connecte, je crée une base de données *forgotten*, un utilisateur *z3rodol* et un mot de passe *Password123*. Je donne aussi tous les privilèges sur la base de données à *z3rodol*.
```mysql
sudo mariadb
CREATE DATABASE forgotten CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'z3rodol'@'%' IDENTIFIED BY 'Password123';
GRANT ALL PRIVILEGES ON forgotten.* TO 'z3rodol'@'%';
quit;
```
![](/images/Forgotten/Forgotten-10.png)

Un fois la base de données configurée, je remplis les informations dans le formulaire et je continue.
![](/images/Forgotten/Forgotten-9.png)

Ce message indique que la base de données n'existe pas et donc sera créée.
![](/images/Forgotten/Forgotten-8.png)

Une fois la créée, j'arrive sur la page de paramètres de l'administrateur de l'application.
![](/images/Forgotten/Forgotten-11.png)
Ne pouvant pas voir le mot de passe, je le modifie alors.

Je clique alors sur **Administration** pour terminer le processus d'installation de LimeSurvey.
![](/images/Forgotten/Forgotten-12.png)

Je suis redirigé alors sur la page de connexion de l'application où je me connecte avec les identifiants admin précédemment modifiés.
![](/images/Forgotten/Forgotten-14.png)

J'arrive alors sur la page d'administration de LimeSurvey.
![](/images/Forgotten/Forgotten-15.png)

# Accès initial
## CVE-2021-44967

Je peux maintenant exploiter cette vulnérabilité expliquée sur cet article de [INE](https://ine.com/blog/cve-2021-44967-limesurvey-rce). Je trouve ce [POC](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE) dont je clone le repo.
![](/images/Forgotten/Forgotten-33.png)

Je n'aurai besoin ici que des fichiers `config.xml` et `php-rev.php` vu que je compte l'exploiter manuellement. Premièrement, je modifie un peu le fichier config.xml pour y ajouter des versions compatibles. La version de `LimeSurvey` ici est la **6.3.7** donc je mettrai une compatibilité jusqu'à la version 7.
![](/images/Forgotten/Forgotten-16.png)

Ensuite le fichier `php-rev.php`, je modifie l'adresse IP pour qu'elle soit celle du VPN de hackthebox ainsi que le port d'écoute. Il s'agit d'un simple reverse shell PHP de [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell)
![](/images/Forgotten/Forgotten-17.png)

Je me rends alors dans **Configuration > Plugins**.
![](/images/Forgotten/Forgotten-18.png)

Puis je clique sur **Upload & Install** afin d'uploader mon fichier zip.
![](/images/Forgotten/Forgotten-19.png)

Je clique sur **Install** pour terminer l'installation du plugin.
![](/images/Forgotten/Forgotten-20.png)

Je vérifie l'installation du plugin.
![](/images/Forgotten/Forgotten-21.png)

## Shell

Ensuite, je démarre mon listener.
```bash
penelope -p 9001
```

Puis je me rends sur la page suivante pour déclencher l'exécution du reverse shell.
```txt
http://10.129.42.192/survey/upload/plugins/Y1LD1R1M/php-rev.php
```

J'obtiens alors un shell dans un docker en tant que l'utilisateur `limesvc`.
![](/images/Forgotten/Forgotten-22.png)
Ce dernier est membre du groupe `sudo`.

# Mouvement latéral
## Énumération 

Il me faut le mot de passe de `limesvc`.
![](/images/Forgotten/Forgotten-23.png)

En regardant les variables d'environnement avec la commande **env**, je trouve un mot de passe.
![](/images/Forgotten/Forgotten-24.png)

## Connexion root sur docker

Ce mot de passe est bien valide et me permet d'obtenir un shell en tant que root.
![](/images/Forgotten/Forgotten-25.png)

## SSH

Ce mot de passe permet d'obtenir un shell SSH sur la machine en tant que l'utilisateur **limesvc**.
![](/images/Forgotten/Forgotten-26.png)

# Escalade de privilèges 
## Docker escape

Dans le répertoire **/opt** se trouve un dossier **limesurvey**.
![](/images/Forgotten/Forgotten-27.png)

Il contient tous les fichiers de configuration de LimeSurvey.
![](/images/Forgotten/Forgotten-28.png)

Je vois dans le répertoire **/var/www/html/survey** du docker se trouve ces mêmes fichiers.
![](/images/Forgotten/Forgotten-29.png)
Peut-être que le répertoire **/opt/limesurvey** de la machine est monté sur le docker. 

Je crée un fichier dans le  répertoire **/var/www/html/survey du docker**.
```bash
echo "Je suis ici" > monfichier.txt
```

Je vois qu'il se trouve aussi dans le répertoire **/opt/limesurvey** de la machine.
![](/images/Forgotten/Forgotten-30.png)
Je vois aussi qu'il appartient à l'utilisateur root. Donc les fichiers créés dans le répertoire **/var/www/html/survey** du docker se retrouvent dans le répertoire **/opt/limesurvey** de la machine avec les permissions root.

## Shell

Je fais alors une copie du **bash** dans le répertoire **/var/www/html/survey** du docker avec toutes les permissions.
```bash
cp /bin/bash rootme
chmod 4777 rootme
```
![](/images/Forgotten/Forgotten-31.png)

Je l'utilise alors sur la machine afin d'avoir un shell root.
```bash
./rootme -p
```
![](/images/Forgotten/Forgotten-32.png)

