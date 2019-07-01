import * as tls from 'tls';

import * as ocsp from '../index';

describe('proper OCSP requests', () => {
    test('for letsencrypt.org (RSA good)', done => {
        const cert = `-----BEGIN CERTIFICATE-----
MIIHMjCCBhqgAwIBAgISA+HOLAMk+cqTQX/IiG+H80hXMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA1MDMyMTEwMjZaFw0x
OTA4MDEyMTEwMjZaMB4xHDAaBgNVBAMTE3d3dy5sZXRzZW5jcnlwdC5vcmcwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCiJVoMxjBUFBa/qCfgulvNK8kP
9HcXYlgOi7K81iUQW6Pe8aGVfTD7e3HpWKFGR9BgKUL+3K9s1Ig5L0VkzGh1JPfi
+Ug+9oEq2Cy7hDDQwV0hEmORyv1dm2Q9UTh2D6L564YD0JxtYxJrWRrKTprrK1jQ
ogsHKWa1NGDOI1w2zvGNUF6XsRme8dJwC4SNUiNiScovQ2R9w6OafQNs+7CbgDgA
KmPa/xSnK14x9pXeim2RS8GObJunPxBRaOyfRHwO6WIvxE89G2ZQFQBi8MK1Q28y
sVKm5R9/y4AH5eGuedGCOyXUTu9pdHreqcaYNSDgaIh8lLacJ4AJhYwpYrDNAgMB
AAGjggQ8MIIEODAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFMuUbU8b5LCmNdHbve0D
mMr0c724MB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUF
BwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZy8wggHxBgNVHREEggHoMIIB5IIbY2VydC5pbnQteDEubGV0c2VuY3J5
cHQub3JnghtjZXJ0LmludC14Mi5sZXRzZW5jcnlwdC5vcmeCG2NlcnQuaW50LXgz
LmxldHNlbmNyeXB0Lm9yZ4IbY2VydC5pbnQteDQubGV0c2VuY3J5cHQub3Jnghxj
ZXJ0LnJvb3QteDEubGV0c2VuY3J5cHQub3Jngh9jZXJ0LnN0YWdpbmcteDEubGV0
c2VuY3J5cHQub3Jngh9jZXJ0LnN0Zy1pbnQteDEubGV0c2VuY3J5cHQub3JngiBj
ZXJ0LnN0Zy1yb290LXgxLmxldHNlbmNyeXB0Lm9yZ4ISY3AubGV0c2VuY3J5cHQu
b3JnghpjcC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZ4ITY3BzLmxldHNlbmNyeXB0
Lm9yZ4IbY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3Jnghtjcmwucm9vdC14MS5s
ZXRzZW5jcnlwdC5vcmeCD2xldHNlbmNyeXB0Lm9yZ4IWb3JpZ2luLmxldHNlbmNy
eXB0Lm9yZ4IXb3JpZ2luMi5sZXRzZW5jcnlwdC5vcmeCFnN0YXR1cy5sZXRzZW5j
cnlwdC5vcmeCE3d3dy5sZXRzZW5jcnlwdC5vcmcwTAYDVR0gBEUwQzAIBgZngQwB
AgEwNwYLKwYBBAGC3xMBAQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRz
ZW5jcnlwdC5vcmcwggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgDiaUuuJujpQAno
hhu2O4PUPuf+dIj7pI8okwGd3fHb/gAAAWp/v6MgAAAEAwBHMEUCIGrZoFnKmmYt
Omx+B0sKmyRBbeiSJQwGFYDETJswjpVAAiEA0BkcBEGR/r6787vEDHwuhCmOuavs
7YybVaoj8lmVx1YAdQApPFGWVMg5ZbqqUPxYB9S3b79Yeily3KTDDPTlRUf0eAAA
AWp/v6U0AAAEAwBGMEQCIFIxbMPE6RDnputd6t3Z1lthJ2vWRjIxNkPw5BkhlVOj
AiB4rr/jnUUdquBrNbL2jUghUktMi59oIGFv6HSgXVkweDANBgkqhkiG9w0BAQsF
AAOCAQEAUzzOcatp5xJBPnSm5Wa/d7JAM8fV/LBvAmLTdNb0Udk4w3QXdTMCN06K
EooTZFoOBe2ae1SIbqDDFFW19OEt0veSlLdJGE7CZgTW7mxdvERXuhhKw4dYtSmd
YOz/ukuNt/xaQxOD2B+4NRYkmr1kxvApZVOJSCduLXmYCw7EFWNXAojeeuDT3dOG
/9/GpOFVOywu7JpgvZwUgeymSU206Z7igxVvCTFN9Hwl2ddeXqT061efa4a9v62H
75sbpxaBKztrZMJdWukmtuyND1MV2+zhVUF6he87nVtrpzmvyfwCdnCH+N7h2LlB
cJLo338k0DUgi+b4PSIxUQIn5NBTGg==
-----END CERTIFICATE-----`;

        const issuer = `-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----`;
        ocsp.getRevocationStatusAsyncForTesting(
            cert,
            issuer,
            'Host=ocsp.int-x3.letsencrypt.org',
            'http://letsencrypt.org',
            // 'http://ocsp.int-x3.letsencrypt.org',
            (err, response) => {
                expect(err).toBeNull();
                expect(response).toMatchObject({
                    status: 0,
                    statusStr: ocsp.CertificateStatus.Good,
                    reason: 0,
                    reasonStr: ocsp.RevokedStatus.Unspecified,
                });
                done();
            }
        );
    });

    test('for revoked.badssl.com (RSA revoked)', done => {
        const cert = `-----BEGIN CERTIFICATE-----
MIIGoTCCBYmgAwIBAgIQAa8e+91erglSMgsk/mtVaDANBgkqhkiG9w0BAQsFADBN
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTYwOTAyMDAwMDAwWhcN
MTkwOTExMTIwMDAwWjBtMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTEVMBMGA1UEBxMMV2FsbnV0IENyZWVrMRUwEwYDVQQKEwxMdWNhcyBHYXJyb24x
GzAZBgNVBAMTEnJldm9rZWQuYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMcxZeRVz2mQn24f2GoTfnS/EzpUZA90JD3cYLinRQG3yGoD
rGRKZfB8gYGDCtndMSCCSKYzY+4rdOq05sccsl7kKDp6PSAZA7cVP0/JJuy3y79I
bl80cFbEhsfjUpohMy8QE/MlDB6UNS7o0NG1oHdAkS7puvj/TvX78noEp+bGzj8P
EBgyyAa8FbO+aax1fUKgjC7DrOEgTx42nJouov15gLZi+MCyA6kpUMzVJYozXuB4
ExjAgBcJlb2i/pIVByB6gc7bDoEpidTI7LOzeQ7yziXn7r4hfa8ME5Qp3jWaHtiE
GFpcGpSCzpph1p3s+O6tPwlbc+yim/rcYvFYH30CAwEAAaOCA1swggNXMB8GA1Ud
IwQYMBaAFA+AYRyCMWHVLyjnjUY4tCzhxtniMB0GA1UdDgQWBBT0SH0HRRoyB5CR
rAW4n6kR8H4RNjAdBgNVHREEFjAUghJyZXZva2VkLmJhZHNzbC5jb20wDgYDVR0P
AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8E
ZDBiMC+gLaArhilodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc1
LmNybDAvoC2gK4YpaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1n
NS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0
cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgMwfAYIKwYBBQUHAQEE
cDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYB
BQUHMAKGOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJT
ZWN1cmVTZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADCCAX4GCisGAQQB1nkCBAIE
ggFuBIIBagFoAHUApLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BAAAAFW
7KE32gAABAMARjBEAiA/bKj1xHwBTMNaKCdQR2PZrOG+Lb+HeMs6gJckdM0W9wIg
cf+TorVUfn9TRX9ZWmAYIVyrfR8IslSgs8SIpYPSY1UAdwBo9pj4H2SCvjqM7rko
HUz8cVFdZ5PURNEKZ6y7T0/7xAAAAVbsoTehAAAEAwBIMEYCIQD+WZciTGwPOQXZ
5Mp+O9OzRxthcrY6T9byo1dJSE9qbQIhAI8UGzwbiaMdcOzU1xG8+Qs8YKyMhHMk
aw43blN/nX80AHYAVhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0AAAFW
7KE4fwAABAMARzBFAiAOv1NZFwzsZgxeh7uPX7Z2hvJc/LyoucDfvBo77hHy0AIh
AIclOeQymUjKIBsTlh3DLJhrG8DM5WcivZIU6WjNlYIyMA0GCSqGSIb3DQEBCwUA
A4IBAQBaoEmIrWAfCFNM2bjc9UBBre/IewE7E3BEmfZcI0b3Osh9ySGtOklFgh5d
Ox6bago+YS32sZl0L5H51fGfrnQmizynjL4o/qw7cK4IVnGsVXxAiQItYSr9VHK/
GlxwGZAVpHagf1YcwfCNXpk9g0FUaOViwVqiZIwBZHojuT+/Is8fwEeAH5TV8jCE
+wcC+lugugkEmE7zJVZMxH7gJ9joMo+zPFqSS8B3LbDlrh+vHX8hnGUmvgy66A3B
0me0uTPRSu78uK8DW8g+vPoJnQTOPqa1xHQ7MXrzLEKzx3PbqnUujYqeeTO+17YU
myare54Us1XmS7uGlBF0AjW0UnCb
-----END CERTIFICATE-----`;

        const issuer = `-----BEGIN CERTIFICATE-----
MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1
oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD
QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh
xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB
CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl
5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA
8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC
2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit
c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0
j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz
-----END CERTIFICATE-----`;
        ocsp.getRevocationStatusAsyncForTesting(
            cert,
            issuer,
            'Host=ocsp.digicert.com',
            'http://ocsp.digicert.com',
            (err, response) => {
                expect(err).toBeNull();
                expect(response).toMatchObject({
                    status: 1,
                    statusStr: ocsp.CertificateStatus.Revoked,
                    reason: -1,
                    reasonStr: ocsp.RevokedStatus.UnknownStatus,
                });
                done();
            }
        );
    });

    test('for wikipedia.org (ECDSA good)', done => {
        const cert = `-----BEGIN CERTIFICATE-----
MIIIMTCCBxmgAwIBAgIMFkDF1F0uxNlMfXxqMA0GCSqGSIb3DQEBCwUAMGYxCzAJ
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTwwOgYDVQQDEzNH
bG9iYWxTaWduIE9yZ2FuaXphdGlvbiBWYWxpZGF0aW9uIENBIC0gU0hBMjU2IC0g
RzIwHhcNMTgxMTA4MjEyMTA0WhcNMTkxMTIyMDc1OTU5WjB5MQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEj
MCEGA1UEChMaV2lraW1lZGlhIEZvdW5kYXRpb24sIEluYy4xGDAWBgNVBAMMDyou
d2lraXBlZGlhLm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGd1rS7GauMx
J15BmViShjVMjwQJNjjw+OUhnIaqE5QF/q6c/LIvVh4N3473a7J52JcfmlfCrXvD
thHzaZNEneKjggWVMIIFkTAOBgNVHQ8BAf8EBAMCA4gwgaAGCCsGAQUFBwEBBIGT
MIGQME0GCCsGAQUFBzAChkFodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2Nh
Y2VydC9nc29yZ2FuaXphdGlvbnZhbHNoYTJnMnIxLmNydDA/BggrBgEFBQcwAYYz
aHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzb3JnYW5pemF0aW9udmFsc2hh
MmcyMFYGA1UdIARPME0wQQYJKwYBBAGgMgEUMDQwMgYIKwYBBQUHAgEWJmh0dHBz
Oi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAgGBmeBDAECAjAJBgNV
HRMEAjAAMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5j
b20vZ3MvZ3Nvcmdhbml6YXRpb252YWxzaGEyZzIuY3JsMIICxQYDVR0RBIICvDCC
AriCDyoud2lraXBlZGlhLm9yZ4INd2lraW1lZGlhLm9yZ4INbWVkaWF3aWtpLm9y
Z4INd2lraWJvb2tzLm9yZ4IMd2lraWRhdGEub3Jnggx3aWtpbmV3cy5vcmeCDXdp
a2lxdW90ZS5vcmeCDndpa2lzb3VyY2Uub3Jngg93aWtpdmVyc2l0eS5vcmeCDndp
a2l2b3lhZ2Uub3Jngg53aWt0aW9uYXJ5Lm9yZ4IXd2lraW1lZGlhZm91bmRhdGlv
bi5vcmeCBncud2lraYISd21mdXNlcmNvbnRlbnQub3JnghEqLm0ud2lraXBlZGlh
Lm9yZ4IPKi53aWtpbWVkaWEub3JnghEqLm0ud2lraW1lZGlhLm9yZ4IWKi5wbGFu
ZXQud2lraW1lZGlhLm9yZ4IPKi5tZWRpYXdpa2kub3JnghEqLm0ubWVkaWF3aWtp
Lm9yZ4IPKi53aWtpYm9va3Mub3JnghEqLm0ud2lraWJvb2tzLm9yZ4IOKi53aWtp
ZGF0YS5vcmeCECoubS53aWtpZGF0YS5vcmeCDioud2lraW5ld3Mub3JnghAqLm0u
d2lraW5ld3Mub3Jngg8qLndpa2lxdW90ZS5vcmeCESoubS53aWtpcXVvdGUub3Jn
ghAqLndpa2lzb3VyY2Uub3JnghIqLm0ud2lraXNvdXJjZS5vcmeCESoud2lraXZl
cnNpdHkub3JnghMqLm0ud2lraXZlcnNpdHkub3JnghAqLndpa2l2b3lhZ2Uub3Jn
ghIqLm0ud2lraXZveWFnZS5vcmeCECoud2lrdGlvbmFyeS5vcmeCEioubS53aWt0
aW9uYXJ5Lm9yZ4IZKi53aWtpbWVkaWFmb3VuZGF0aW9uLm9yZ4IUKi53bWZ1c2Vy
Y29udGVudC5vcmeCDXdpa2lwZWRpYS5vcmcwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMB0GA1UdDgQWBBSt4NNfC33t2i98DfZjjYpZGMJsijAfBgNVHSME
GDAWgBSW3mHxvRwWKVMcwMx9O4MAQOYafDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA
8AB2AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABZvUzN/YAAAQD
AEcwRQIgBATdvSzbd5NwGdtkmJ5SEvEPn6A8hgAsk6GSP6hzWcgCIQDKfHQNtObs
/hHPfLgXsVkcnHIbjlNwmWeiukGtGHZFMgB2AG9Tdqwx8DEZ2JkApFEV/3cVHBHZ
AsEAKQaNsgiaN9kTAAABZvUzN8cAAAQDAEcwRQIgYalEnXtd/fPhjq9SXPoSPRha
MmeDs0IMN5o5Y6QTKfUCIQClR1uj+B56K4tGh/mws4qugG1qSD9zfvmx8roKik3H
HDANBgkqhkiG9w0BAQsFAAOCAQEAUEJyg/AZo+owG5J/LIk8EIDnyOcanmfgvdjM
g8KnpBvh8l3Wb4HmOudluJhIeIbCUMwzEzSGqYQQ78n4wtjLaLwaDgL4WzHOVec2
k+rbfmPT6MUCtdlz1PK5/WY9JQyQq6vy+tm3a6Wijy6M8U/TdrJubK5X03SFfRb0
pDuFdr2fnkctLRnyCb1w0XHwGXjEcGm1LY42YKwdvbj3WIqumeSEuG4MZtquW6NU
RKELSil03G/hRHRAHHGx3zXes/jJcpH2GPX9eY9B+R1oHmCE2QF5Y/Bh+uNA2+2I
uj/6UJAOw/Z/8+qZcnLWWnK2Dwzc34C/AUD+Wb71oUcr60+pPg==
-----END CERTIFICATE-----`;

        const issuer = `-----BEGIN CERTIFICATE-----
MIIEYjCCA0qgAwIBAgILBAAAAAABMYnGRMkwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTEwODAyMTAwMDAwWhcNMjIwODAy
MTAwMDAwWjBmMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1z
YTE8MDoGA1UEAxMzR2xvYmFsU2lnbiBPcmdhbml6YXRpb24gVmFsaWRhdGlvbiBD
QSAtIFNIQTI1NiAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
xw5sPyOTf8xwpZ0gww5TP37ATsKYScpH1SPvAzSFdMijAi5GXAt9yYidT4vw+Jxs
jFU127/ys+r741bnSkbZEyLKNtWbwajjlkOT8gy85vnm6JnIY0h4f1c2aRoZHVrR
1H3CnNR/4YASrnrqiOpX2MoKCjoSSaJiGXoNJPc367RzknsFI5sStc7rKd+kFAK5
AaXUppxDZIje+H7+4/Ue5f7co6jkZjHZTCXpGLmJWQmu6Z0cbTcPSh41ICjir9Qh
iwHERa1uK2OrkmthCk0g7XO6fM7+FrXbn4Dw1ots2Qh5Sk94ZdqSvL41+bPE+SeA
Tv+WUuYCIOEHc+ldK72y8QIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJbeYfG9HBYpUxzAzH07gwBA5hp8
MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzA2BgNVHR8ELzAtMCugKaAnhiVodHRw
Oi8vY3JsLmdsb2JhbHNpZ24ubmV0L3Jvb3QtcjMuY3JsMD4GCCsGAQUFBwEBBDIw
MDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
MzAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDANBgkqhkiG9w0BAQsF
AAOCAQEAugYpwLQZjCERwJQRnrs91NVDQPafuyULI2i1Gvf6VGTMKxP5IfBEreHo
FVjb7v3bok3MGI8Nmm3DawGhMfCNvABAzDlfh2FRbfSV6uoVNT5AhcBi1aE0/niq
qLJaOfM3Qfuc6D5xSlvr+GlYoeDGk3fpumeS62VYkHBzQn2v9CMmeReq+qS7meVE
b2WB58rrVcj0ticRIXSUvGu3dGIpxM2uR/LmQlt4hgVhy5CqeYnfBH6xJnBLjUAf
hHvA+wfmyLdOkfQ1A+3o60EQF0m0YsinLPLhTI8DLPMWN11n8aQ5eUmjwF3MVfkh
gA/7zuIpalhQ6abX6xwyNrVip8H65g==
-----END CERTIFICATE-----`;
        ocsp.getRevocationStatusAsyncForTesting(
            cert,
            issuer,
            'Host=ocsp2.globalsign.com',
            'http://ocsp2.globalsign.com/gsorganizationvalsha2g2',
            (err, response) => {
                expect(err).toBeNull();
                expect(response).toMatchObject({
                    status: 0,
                    statusStr: ocsp.CertificateStatus.Good,
                    reason: 0,
                    reasonStr: ocsp.RevokedStatus.Unspecified,
                });
                done();
            }
        );
    });

    test('for dashlane.com (long certificate chain)', done => {
        const tlsOptions: tls.ConnectionOptions = {
            host: 'dashlane.com',
            servername: 'dashlane.com',
            port: 443,
        };
        const socket = tls.connect(tlsOptions);
        socket.on('secureConnect', () => {
            const socketCertificate = socket.getPeerCertificate(true);
            ocsp.getRevocationStatusAsync(
                socketCertificate,
                (err, response) => {
                    expect(err).toBeNull();
                    expect(response).toMatchObject({
                        status: 0,
                        statusStr: ocsp.CertificateStatus.Good,
                        reason: 0,
                        reasonStr: ocsp.RevokedStatus.Unspecified,
                    });
                    socket.removeAllListeners();
                    socket.end();
                    socket.destroy();
                    done();
                }
            );
        });
    });

    test('for incomplete-chain.badssl.com', done => {
        const tlsOptions: tls.ConnectionOptions = {
            host: 'incomplete-chain.badssl.com',
            servername: 'incomplete-chain.badssl.com',
            port: 443,
            rejectUnauthorized: false,
        };
        const socket = tls.connect(tlsOptions);
        socket.on('secureConnect', () => {
            const socketCertificate = socket.getPeerCertificate(true);
            ocsp.getRevocationStatusAsync(
                socketCertificate,
                (err, response) => {
                    expect(err).toEqual(
                        new Error('Missing issuer certificate')
                    );
                    expect(response).toBeUndefined();
                    socket.removeAllListeners();
                    socket.end();
                    socket.destroy();
                    done();
                }
            );
        });
    });
});

describe('wrong OCSP requests', () => {
    test('Error parsing URL', done => {
        ocsp.getRevocationStatusAsyncForTesting(
            '',
            '',
            '',
            '',
            (err, response) => {
                expect(err).toBe('Error parsing URL');
                done();
            }
        );
    });
    test('Wrong issuer', done => {
        ocsp.getRevocationStatusAsyncForTesting(
            '',
            '',
            '',
            'http://ocsp.sca1b.amazontrust.com',
            (err, response) => {
                expect(err).toBe('Unable to load issuer certificate');
                done();
            }
        );
    });
    test('Wrong cert', done => {
        ocsp.getRevocationStatusAsyncForTesting(
            '',
            `-----BEGIN CERTIFICATE-----
MIIFdzCCBF+gAwIBAgIQCXekOMYr/qbDSHzhdAH7szANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xODA5MjEwMDAwMDBaFw0xOTEwMjEx
MjAwMDBaMBgxFjAUBgNVBAMTDWRhdGFkb2docS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7VnIMiWl89z1CDASb90CGd8321Jzm7bqYjmx/uJtw
gt/gArDxQxJ5ldisumsjirKSegBpzncRuC4fnDf/vaT0sYpYFPOcL1zJ7eKq+V03
AIh2rGpskUtbW2waUz0pbW5fyxZ7fC1LD4TYLu4TT5O4XV33st+O5nfWdXq6dIgU
5I9ZLmzuc8MQFHQbIVgM2QAtJq/uLYayLLySJeKZ2T90uQDj8orUlTDJf65D7Yy3
fsI9WfjuWaTIPsmhMFlRUZQZf5FnvxxFE5DrmnIwi05+JMhJcETGymQkfulZNkmI
550VfB9M8YRRlBQ1bOKAZ+3kcZN7nzzIM7aLRayMojpLAgMBAAGjggKNMIICiTAf
BgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUsaUEh5Aj
d5mYgl+LbR1RyaVD8RUwKwYDVR0RBCQwIoINZGF0YWRvZ2hxLmNvbYIRd3d3LmRh
dGFkb2docS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnNjYTFiLmFt
YXpvbnRydXN0LmNvbS9zY2ExYi5jcmwwIAYDVR0gBBkwFzALBglghkgBhv1sAQIw
CAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0cDovL29j
c3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRwOi8vY3J0
LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0TAQH/BAIwADCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AKS5CZC0GFgUh7sTosxncAo8NZgE+Rvf
uON3zQ7IDdwQAAABZfmDRsQAAAQDAEcwRQIgGcTtvqH9JEgMumjNBAoGRz1VfyCX
3YpOPd1rphjqM48CIQCfNhGbS+r1u4tkcoAjdBD//BSo5niTOK43eSac628XtgB3
AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABZfmDR5kAAAQDAEgw
RgIhALqkVYFm/KUD0u+zUQbYuk7u0Ks87ctWvL6GG7VhSmRhAiEAwdMHSWLdEj9K
grKkDoPPz9HNaNkzroVh2cdBswwT3swwDQYJKoZIhvcNAQELBQADggEBADCTjA9g
Ldhcn2wMf80SHdWoXaREmZhsMhETLDfOEU7sp5pNfBNdHpzAQtd2Et/Px5V3XhJI
4zxc8FGHksAPQ/7esOvtgbkLqVw8d1hdz0Zy9VJ3DGWMU1QeHXQZd9mJzOLyx+10
EZNDMX+x5ZxGLJURxru5uNCCoMzVZBNYOt77W3Vre1UL3lMVoeaN5KoKJtltya6Y
0yebuvcfCCAZg791WYpupSVq5Z2tQbl5le9CFoWYnU5qL1pG9iprM/bQoDNV+tkW
lszJxb8EfsdWlTq9MriACO4CK8AEBvs48zdWqLRzJoS2uh1dFOCXHK3hcymQVVh0
6+xpb0/W0HZmE7c=
-----END CERTIFICATE-----`,
            '',
            'http://ocsp.sca1b.amazontrust.com',
            (err, response) => {
                expect(err).toBe('Unable to load certificate');
                done();
            }
        );
    });

    test('Missing = in header key=value', done => {
        ocsp.getRevocationStatusAsyncForTesting(
            `-----BEGIN CERTIFICATE-----
MIIFdzCCBF+gAwIBAgIQCXekOMYr/qbDSHzhdAH7szANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xODA5MjEwMDAwMDBaFw0xOTEwMjEx
MjAwMDBaMBgxFjAUBgNVBAMTDWRhdGFkb2docS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7VnIMiWl89z1CDASb90CGd8321Jzm7bqYjmx/uJtw
gt/gArDxQxJ5ldisumsjirKSegBpzncRuC4fnDf/vaT0sYpYFPOcL1zJ7eKq+V03
AIh2rGpskUtbW2waUz0pbW5fyxZ7fC1LD4TYLu4TT5O4XV33st+O5nfWdXq6dIgU
5I9ZLmzuc8MQFHQbIVgM2QAtJq/uLYayLLySJeKZ2T90uQDj8orUlTDJf65D7Yy3
fsI9WfjuWaTIPsmhMFlRUZQZf5FnvxxFE5DrmnIwi05+JMhJcETGymQkfulZNkmI
550VfB9M8YRRlBQ1bOKAZ+3kcZN7nzzIM7aLRayMojpLAgMBAAGjggKNMIICiTAf
BgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUsaUEh5Aj
d5mYgl+LbR1RyaVD8RUwKwYDVR0RBCQwIoINZGF0YWRvZ2hxLmNvbYIRd3d3LmRh
dGFkb2docS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnNjYTFiLmFt
YXpvbnRydXN0LmNvbS9zY2ExYi5jcmwwIAYDVR0gBBkwFzALBglghkgBhv1sAQIw
CAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0cDovL29j
c3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRwOi8vY3J0
LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0TAQH/BAIwADCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AKS5CZC0GFgUh7sTosxncAo8NZgE+Rvf
uON3zQ7IDdwQAAABZfmDRsQAAAQDAEcwRQIgGcTtvqH9JEgMumjNBAoGRz1VfyCX
3YpOPd1rphjqM48CIQCfNhGbS+r1u4tkcoAjdBD//BSo5niTOK43eSac628XtgB3
AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABZfmDR5kAAAQDAEgw
RgIhALqkVYFm/KUD0u+zUQbYuk7u0Ks87ctWvL6GG7VhSmRhAiEAwdMHSWLdEj9K
grKkDoPPz9HNaNkzroVh2cdBswwT3swwDQYJKoZIhvcNAQELBQADggEBADCTjA9g
Ldhcn2wMf80SHdWoXaREmZhsMhETLDfOEU7sp5pNfBNdHpzAQtd2Et/Px5V3XhJI
4zxc8FGHksAPQ/7esOvtgbkLqVw8d1hdz0Zy9VJ3DGWMU1QeHXQZd9mJzOLyx+10
EZNDMX+x5ZxGLJURxru5uNCCoMzVZBNYOt77W3Vre1UL3lMVoeaN5KoKJtltya6Y
0yebuvcfCCAZg791WYpupSVq5Z2tQbl5le9CFoWYnU5qL1pG9iprM/bQoDNV+tkW
lszJxb8EfsdWlTq9MriACO4CK8AEBvs48zdWqLRzJoS2uh1dFOCXHK3hcymQVVh0
6+xpb0/W0HZmE7c=
-----END CERTIFICATE-----`,
            `-----BEGIN CERTIFICATE-----
MIIFdzCCBF+gAwIBAgIQCXekOMYr/qbDSHzhdAH7szANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xODA5MjEwMDAwMDBaFw0xOTEwMjEx
MjAwMDBaMBgxFjAUBgNVBAMTDWRhdGFkb2docS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7VnIMiWl89z1CDASb90CGd8321Jzm7bqYjmx/uJtw
gt/gArDxQxJ5ldisumsjirKSegBpzncRuC4fnDf/vaT0sYpYFPOcL1zJ7eKq+V03
AIh2rGpskUtbW2waUz0pbW5fyxZ7fC1LD4TYLu4TT5O4XV33st+O5nfWdXq6dIgU
5I9ZLmzuc8MQFHQbIVgM2QAtJq/uLYayLLySJeKZ2T90uQDj8orUlTDJf65D7Yy3
fsI9WfjuWaTIPsmhMFlRUZQZf5FnvxxFE5DrmnIwi05+JMhJcETGymQkfulZNkmI
550VfB9M8YRRlBQ1bOKAZ+3kcZN7nzzIM7aLRayMojpLAgMBAAGjggKNMIICiTAf
BgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUsaUEh5Aj
d5mYgl+LbR1RyaVD8RUwKwYDVR0RBCQwIoINZGF0YWRvZ2hxLmNvbYIRd3d3LmRh
dGFkb2docS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnNjYTFiLmFt
YXpvbnRydXN0LmNvbS9zY2ExYi5jcmwwIAYDVR0gBBkwFzALBglghkgBhv1sAQIw
CAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0cDovL29j
c3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRwOi8vY3J0
LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0TAQH/BAIwADCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AKS5CZC0GFgUh7sTosxncAo8NZgE+Rvf
uON3zQ7IDdwQAAABZfmDRsQAAAQDAEcwRQIgGcTtvqH9JEgMumjNBAoGRz1VfyCX
3YpOPd1rphjqM48CIQCfNhGbS+r1u4tkcoAjdBD//BSo5niTOK43eSac628XtgB3
AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABZfmDR5kAAAQDAEgw
RgIhALqkVYFm/KUD0u+zUQbYuk7u0Ks87ctWvL6GG7VhSmRhAiEAwdMHSWLdEj9K
grKkDoPPz9HNaNkzroVh2cdBswwT3swwDQYJKoZIhvcNAQELBQADggEBADCTjA9g
Ldhcn2wMf80SHdWoXaREmZhsMhETLDfOEU7sp5pNfBNdHpzAQtd2Et/Px5V3XhJI
4zxc8FGHksAPQ/7esOvtgbkLqVw8d1hdz0Zy9VJ3DGWMU1QeHXQZd9mJzOLyx+10
EZNDMX+x5ZxGLJURxru5uNCCoMzVZBNYOt77W3Vre1UL3lMVoeaN5KoKJtltya6Y
0yebuvcfCCAZg791WYpupSVq5Z2tQbl5le9CFoWYnU5qL1pG9iprM/bQoDNV+tkW
lszJxb8EfsdWlTq9MriACO4CK8AEBvs48zdWqLRzJoS2uh1dFOCXHK3hcymQVVh0
6+xpb0/W0HZmE7c=
-----END CERTIFICATE-----`,
            '',
            'http://ocsp.sca1b.amazontrust.com',
            (err, response) => {
                expect(err).toBe('Missing = in header key=value');
                done();
            }
        );
    });

    test('Invalid header', done => {
        ocsp.getRevocationStatusAsyncForTesting(
            `-----BEGIN CERTIFICATE-----
MIIFdzCCBF+gAwIBAgIQCXekOMYr/qbDSHzhdAH7szANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xODA5MjEwMDAwMDBaFw0xOTEwMjEx
MjAwMDBaMBgxFjAUBgNVBAMTDWRhdGFkb2docS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7VnIMiWl89z1CDASb90CGd8321Jzm7bqYjmx/uJtw
gt/gArDxQxJ5ldisumsjirKSegBpzncRuC4fnDf/vaT0sYpYFPOcL1zJ7eKq+V03
AIh2rGpskUtbW2waUz0pbW5fyxZ7fC1LD4TYLu4TT5O4XV33st+O5nfWdXq6dIgU
5I9ZLmzuc8MQFHQbIVgM2QAtJq/uLYayLLySJeKZ2T90uQDj8orUlTDJf65D7Yy3
fsI9WfjuWaTIPsmhMFlRUZQZf5FnvxxFE5DrmnIwi05+JMhJcETGymQkfulZNkmI
550VfB9M8YRRlBQ1bOKAZ+3kcZN7nzzIM7aLRayMojpLAgMBAAGjggKNMIICiTAf
BgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUsaUEh5Aj
d5mYgl+LbR1RyaVD8RUwKwYDVR0RBCQwIoINZGF0YWRvZ2hxLmNvbYIRd3d3LmRh
dGFkb2docS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnNjYTFiLmFt
YXpvbnRydXN0LmNvbS9zY2ExYi5jcmwwIAYDVR0gBBkwFzALBglghkgBhv1sAQIw
CAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0cDovL29j
c3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRwOi8vY3J0
LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0TAQH/BAIwADCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AKS5CZC0GFgUh7sTosxncAo8NZgE+Rvf
uON3zQ7IDdwQAAABZfmDRsQAAAQDAEcwRQIgGcTtvqH9JEgMumjNBAoGRz1VfyCX
3YpOPd1rphjqM48CIQCfNhGbS+r1u4tkcoAjdBD//BSo5niTOK43eSac628XtgB3
AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABZfmDR5kAAAQDAEgw
RgIhALqkVYFm/KUD0u+zUQbYuk7u0Ks87ctWvL6GG7VhSmRhAiEAwdMHSWLdEj9K
grKkDoPPz9HNaNkzroVh2cdBswwT3swwDQYJKoZIhvcNAQELBQADggEBADCTjA9g
Ldhcn2wMf80SHdWoXaREmZhsMhETLDfOEU7sp5pNfBNdHpzAQtd2Et/Px5V3XhJI
4zxc8FGHksAPQ/7esOvtgbkLqVw8d1hdz0Zy9VJ3DGWMU1QeHXQZd9mJzOLyx+10
EZNDMX+x5ZxGLJURxru5uNCCoMzVZBNYOt77W3Vre1UL3lMVoeaN5KoKJtltya6Y
0yebuvcfCCAZg791WYpupSVq5Z2tQbl5le9CFoWYnU5qL1pG9iprM/bQoDNV+tkW
lszJxb8EfsdWlTq9MriACO4CK8AEBvs48zdWqLRzJoS2uh1dFOCXHK3hcymQVVh0
6+xpb0/W0HZmE7c=
-----END CERTIFICATE-----`,
            `-----BEGIN CERTIFICATE-----
MIIFdzCCBF+gAwIBAgIQCXekOMYr/qbDSHzhdAH7szANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0xODA5MjEwMDAwMDBaFw0xOTEwMjEx
MjAwMDBaMBgxFjAUBgNVBAMTDWRhdGFkb2docS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7VnIMiWl89z1CDASb90CGd8321Jzm7bqYjmx/uJtw
gt/gArDxQxJ5ldisumsjirKSegBpzncRuC4fnDf/vaT0sYpYFPOcL1zJ7eKq+V03
AIh2rGpskUtbW2waUz0pbW5fyxZ7fC1LD4TYLu4TT5O4XV33st+O5nfWdXq6dIgU
5I9ZLmzuc8MQFHQbIVgM2QAtJq/uLYayLLySJeKZ2T90uQDj8orUlTDJf65D7Yy3
fsI9WfjuWaTIPsmhMFlRUZQZf5FnvxxFE5DrmnIwi05+JMhJcETGymQkfulZNkmI
550VfB9M8YRRlBQ1bOKAZ+3kcZN7nzzIM7aLRayMojpLAgMBAAGjggKNMIICiTAf
BgNVHSMEGDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUsaUEh5Aj
d5mYgl+LbR1RyaVD8RUwKwYDVR0RBCQwIoINZGF0YWRvZ2hxLmNvbYIRd3d3LmRh
dGFkb2docS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnNjYTFiLmFt
YXpvbnRydXN0LmNvbS9zY2ExYi5jcmwwIAYDVR0gBBkwFzALBglghkgBhv1sAQIw
CAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0cDovL29j
c3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRwOi8vY3J0
LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0TAQH/BAIwADCC
AQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2AKS5CZC0GFgUh7sTosxncAo8NZgE+Rvf
uON3zQ7IDdwQAAABZfmDRsQAAAQDAEcwRQIgGcTtvqH9JEgMumjNBAoGRz1VfyCX
3YpOPd1rphjqM48CIQCfNhGbS+r1u4tkcoAjdBD//BSo5niTOK43eSac628XtgB3
AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABZfmDR5kAAAQDAEgw
RgIhALqkVYFm/KUD0u+zUQbYuk7u0Ks87ctWvL6GG7VhSmRhAiEAwdMHSWLdEj9K
grKkDoPPz9HNaNkzroVh2cdBswwT3swwDQYJKoZIhvcNAQELBQADggEBADCTjA9g
Ldhcn2wMf80SHdWoXaREmZhsMhETLDfOEU7sp5pNfBNdHpzAQtd2Et/Px5V3XhJI
4zxc8FGHksAPQ/7esOvtgbkLqVw8d1hdz0Zy9VJ3DGWMU1QeHXQZd9mJzOLyx+10
EZNDMX+x5ZxGLJURxru5uNCCoMzVZBNYOt77W3Vre1UL3lMVoeaN5KoKJtltya6Y
0yebuvcfCCAZg791WYpupSVq5Z2tQbl5le9CFoWYnU5qL1pG9iprM/bQoDNV+tkW
lszJxb8EfsdWlTq9MriACO4CK8AEBvs48zdWqLRzJoS2uh1dFOCXHK3hcymQVVh0
6+xpb0/W0HZmE7c=
-----END CERTIFICATE-----`,
            '=',
            'http://ocsp.sca1b.amazontrust.com',
            (err, response) => {
                expect(err).toBe('Error querying OCSP responder');
                done();
            }
        );
    });
});
