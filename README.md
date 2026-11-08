# XiPKI PKIX

ASN.1 structures (including CMS, CMP and SCEP), certificates, signers and verifiers for Java.

Part of the code is taken from [xipki/xipki](https://github.com/xipki/xipki). The ASN.1
layer (`pkix-asn1`) is new and is built on the `codec` module of
[xipki/xicrypto](https://github.com/xipki/xicrypto), not on BouncyCastle.

## Modules

| Module       | Artifact                    | Description |
|--------------|-----------------------------|-------------|
| `pkix-util`  | `org.xipki.pkix:pkix-util`  | Common utilities: configuration (`FileOrBinary`, `FileOrValue`, `KeystoreConf`, `Validity`), I/O helpers, PEM encoding, and password handling (PBE, OBF, password resolvers and callbacks). |
| `pkix-asn1`  | `org.xipki.pkix:pkix-asn1`  | ASN.1 structures for PKIX and related standards. |
| `pkix`       | `org.xipki.pkix:pkix`       | Higher-level PKIX API: X.509 certificates and CRLs, PKCS#11 and PKCS#12 key stores, signers and signature verifiers. |

`pkix` depends on `pkix-asn1` and `pkix-util`; both of those depend only on
`org.xipki.crypto:codec`.

### pkix-asn1 packages

All packages are under `org.xipki.asn1`.

| Package     | Content |
|-------------|---------|
| `x509`      | X.509 certificates, CRLs and extensions (RFC 5280), qualified certificates (RFC 3039) |
| `x500`      | Names and directory attributes |
| `cert`      | Additional certificate extensions: CT logs (RFC 6962), TLS features (RFC 7633), hardware module name (RFC 4108), Microsoft certificate template, SmtpUTF8Mailbox, ... |
| `cms`,      | Cryptographic Message Syntax (RFC 5652, RFC 5753, RFC 6211, RFC 9629 KEMRecipientInfo) |
| `cmp`       | Certificate Management Protocol (RFC 4210, RFC 9810) |
| `crmf`      | Certificate Request Message Format (RFC 4211, RFC 2875) |
| `ocsp`      | Online Certificate Status Protocol (RFC 6960) |
| `pkcs10`    | Certification requests |
| `pkcs12`    | PKCS#12 (RFC 7292) |
| `est`       | Enrollment over Secure Transport (RFC 7030) |
| `scep`      | SCEP structures |
| `ess`       | ESS ContentHints |
| `smime`     | S/MIME capabilities |
| `rpki`      | IP address and AS identifier extensions |
| `stir`      | STIR / TNAuthList (RFC 8226) |
| `tcg`       | TCG platform certificate structures |
| `spdm`      | DMTF SPDM certificate extensions |
| `ccc`       | Car Connectivity Consortium (Digital Key) certificate extensions |
| `util`      | Helpers (e.g. RFC 4514 string representation) |

## Requirements

- Java 11 or later
- Maven 3

## Build

```sh
mvn clean install
```

Skip the tests with `-DskipTests`. The `release` profile additionally signs the artifacts and
builds Javadoc jars:

```sh
mvn clean deploy -Prelease
```

## Usage

```xml
<dependency>
  <groupId>org.xipki.pkix</groupId>
  <artifactId>pkix</artifactId>
  <version>7.0.0-SNAPSHOT</version>
</dependency>
```

Use `pkix-asn1` alone if you only need the ASN.1 structures.

## License

[Apache License 2.0](LICENSE)
