---
title: VulnEscape
date: 2026-03-14 10:28:41
categories: ["Machines", "Hackthebox"]
tags: ["Easy", "Windows", "Kiosk Mode", "UAC Bypass"]
image: vulnescape.png
comments: false
---

VulnEscape est une machine Windows de difficulté Facile qui propose le service Bureau à distance (Remote Desktop Server) fonctionnant sur son port par défaut. Les utilisateurs peuvent se connecter à la machine via RDP et se connecter en tant que **KioskUser0** sans mot de passe. L'environnement cible est restreint, cependant, en exploitant le schéma `file://` dans **Microsoft Edge**, les utilisateurs peuvent naviguer dans le système de fichiers. Une exploitation plus poussée permet de contourner les restrictions du système et d'ouvrir une fenêtre PowerShell. L'énumération du système de fichiers révèle un dossier contenant un profil pour une application appelée Remote Desktop Plus. Ce profil peut être chargé dans l'application et le mot de passe qu'il contient peut être extrait. Le mot de passe extrait peut ensuite être utilisé pour démarrer une session en tant qu'utilisateur admin, et un contournement supplémentaire du Contrôle de Compte Utilisateur (UAC) permet de lire le flag racine.

# Recon
## TCP Scan

Je commence l'énumération de la machine avec un scan TCP complet. Il n'y a que le port `RDP` qui est ouvert.
```js
╭─root at exegol-htb in /workspace/VulnEscape
╰─○ nmap 10.129.193.207 --min-rate 10000 -p- -vv
--SNIP--
PORT     STATE SERVICE       REASON
3389/tcp open  ms-wbt-server syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.49 seconds
           Raw packets sent: 131078 (5.767MB) | Rcvd: 10 (440B)
           
╭─root at exegol-htb in /workspace/VulnEscape
╰─○ nmap 10.129.193.207 -p 3389 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-08 22:17 CEST
Nmap scan report for 10.129.193.207
Host is up (0.049s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Escape
| Not valid before: 2025-04-10T06:20:36
|_Not valid after:  2025-10-10T06:20:36
| rdp-ntlm-info:
|   Target_Name: ESCAPE
|   NetBIOS_Domain_Name: ESCAPE
|   NetBIOS_Computer_Name: ESCAPE
|   DNS_Domain_Name: Escape
|   DNS_Computer_Name: Escape
|   Product_Version: 10.0.19041
|_  System_Time: 2025-07-08T20:17:20+00:00
|_ssl-date: 2025-07-08T20:17:25+00:00; +1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Initial Access
## RDP as KioskUser0

J'initie une connexion sans identifiants. Cela est possible grâce à l'option `-sec-nla`. J'ai alors un message me disant de me connecter en tant que l'utilisateur `KioskUser0`. 
Après une petite recherche j'apprends que l'utilisateur `KioskUser` ou `KioskUser0` est un utilisateur spécial qui est créé automatiquement lorsqu'on active le **mode Kiosque**. Ce mode permet de verrouiller un ordinateur pour n'exécuter que des applications et paramètres spécifiques.
```js
xfreerdp /cert-ignore /v:10.129.234.51 /dynamic-resolution -clipboard -sec-nla
```
![](1.png)

Je me connecte alors en tant que `KioskUser0` sans fournir de mot de passe.
![](2.png)

J'arrive sur une page d'accueil de Windows qui montre bien qu'on est sur un système en coréen.
![](3.png)

En cliquant sur la touche **Windows** de mon clavier, je peux afficher le menu Démarrer.
![](VulnEscape-1.png)

Je recherche alors **Edge** afin de l'ouvrir.
![](VulnEscape-2.png)

Là il suffit de suivre les étapes de première ouverture de Microsoft Edge. C'est à dire accepter ou non les conditions.
![](VulnEscape-3.png)

Une fois terminé j'ai une session en tant que Profile 1.
![](VulnEscape-4.png)

Le raccourci **CTRL + J**, me permet d'afficher tous les téléchargements. Il n'y en a aucun, mais en cliquant sur l'icone de dossier cela me permet d'ouvrir l'explorateur de fichiers.
![](VulnEscape-5.png)

Je coche l'option d'affichage des extensions de fichiers ainsi que celle d'affichage des fichiers cachés.
![](VulnEscape-6.png)

Lorsque j'essaie d'accéder au répertoire personnel de KioskUser0 (**C:\Users\KioskUser0**), j'ai un message d'erreur disant que l'accès a été bloqué par mon organisation.
![](VulnEscape-7.png)

Par contre je peux y accéder depuis Microsoft Edge avec l'option suivante :
```js
file://C:\Users\KioskUser0
```
![](VulnEscape-8.png)

Le répertoire `C:\Users\KioskUser0\Desktop` contient le flag.
![](4.png)

Il suffit de cliquer dessus pour afficher le contenu.
![](VulnEscape-9.png)

# Privilege escalation
## Recon 

Dans le répertoire `C:\Users`, se trouve le répertoire personnel de l'utilisateur `admin`.
![](VulnEscape-10.png)

Sauf qu'il est vide.
![](VulnEscape-11.png)

À la racine se trouve un répertoire `_admin`.
![](VulnEscape-12.png)

Le dossier `C:/_admin` contient plusieurs fichiers.
![](VulnEscape-13.png)

Le fichier `C:\_admin\profiles.xml` contient des identifiants de l'utilisateur `admin` pour l'application `Remote Desktop Plus`.
![](VulnEscape-14.png)

## Get admin's password

L'exécutable de l'application se trouve dans le dossier `C:/Program Files (x86)/Remote/Desktop/Plus/`
![](VulnEscape-15.png)

Je clique dessus ce qui le télécharge.
![](VulnEscape-16.png)

Mais lorsque je lance l'exécutable, j'ai ce message d'erreur me disant que : **cette action a été annulée en raison de restrictions système. Veuillez contacter votre administrateur système**.
![](VulnEscape-17.png)

Jusque là je vois que je ne peux démarrer que l'exécutable `msedge.exe` de Microsoft Edge. S'il s'agit d'une restriction par nom qui est effectuer il me suffit de modifier le nom de l'exécutable en `msegde.exe`.
![](VulnEscape-18.png)

Et bingo!! Il démarre bien.
![](VulnEscape-19.png)

Je me rends dans **Manages profiles** afin d'importer le profile trouvé précédemment.
![](VulnEscape-20.png)

Malheureusement l'appli n'a pas les droits d'accès au répertoire `C:\_admin`
![](VulnEscape-21.png)

Dans le répertoire `C:/Windows/System32/` se trouve l'exécutable du CMD que je télécharge.
![](VulnEscape-22.png)

Je renomme le `cmd.exe` en `msedge.exe` et lui aussi démarre.
![](VulnEscape-29.png)

Je copie alors le `profile.xml` dans le répertoire `C:\Users\KioskUser0\Downloads\`.
```js
copy C:\_admin\profiles.xml C:\Users\KioskUser0\Downloads\
```
![](VulnEscape-23.png)

Je peux alors bien importer le profile.
![](VulnEscape-24.png)

Je clique sur `Edit` afin d'éditer le profile. Je vois alors que je ne peux pas copier le mot de passe.
![](VulnEscape-25.png)

En recherchant sur google alors comment déchiffrer ce mot de passe, je trouve ce [GitHub](https://gist.github.com/jsundin/da2330884cd2a195c3f39fb72d0814f7) qui permet de craquer ce hash.
![](VulnEscape-26.png)

## Attempt RDP as admin

J'initie une connexion RDP en tant que l'utilisateur **admin**.
```js
xfreerdp /cert-ignore /v:10.129.4.58 /u:admin /p:Twisting3021 /dynamic-resolution +clipboard
```
![](VulnEscape-27.png)

La connexion ne s'établie pas et j'ai ce message.
![](VulnEscape-38.png)

Avec Claude je traduis le message reçu. L'utilisateur **admin** ne serait pas membre du groupe `Remote Desktop Users`, groupe permettant un accès par RDP à une machine Windows.
![](VulnEscape-28.png)

Je vois bien que admin n'est pas membre du groupe `Remote Desktop Users`.
![](VulnEscape-30.png)

Il tout de même possible d'avoir un shell depuis ma session RDP avec `runas`.
```js
runas /user:admin cmd
```
![](VulnEscape-37.png)

J'obtiens bien alors un shell en tant que l'utilisateur **admin**.
![](VulnEscape-31.png)

Sauf que je n'ai pas un shell avec les pleins droits admin. Car `runas` n'a pas été lancé avec le UAC. Ce message qui demande si on veut lancer le cmd avec des droits administrateurs.
![](VulnEscape-32.png)

## Trigger UAC

Après une petite recherche sur le bypass de UAC avec `runas`, je tombe sur cet article de [Infosecwriteups](https://infosecwriteups.com/bypassing-uac-1ba99a173b30) qui explique qu'il est possible de déclencher (pas un bypass dans ce cas) la fenêtre UAC avec la commande suivante :
```js
Start-Process powershell -Verb runAs
```
![](VulnEscape-33.png)

Cela affiche bien le panneau me demandant si je veux obtenir un shell tant qu'administrateur. Je choisis alors la première option.
![](VulnEscape-34.png)

Et là j'ai un shell avec tous les privilèges administrateur.
![](VulnEscape-35.png)

Je peux alors récupérer le flag root.
![](VulnEscape-36.png)
