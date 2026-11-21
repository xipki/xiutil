// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.codec.util.Args;

/**
 * Key Usage enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum KeyUsage {

  digitalSignature(org.xipki.asn1.x509.KeyUsage.digitalSignature,
      C509KeyUsage.DIGITAL_SIGNATURE),
  contentCommitment(org.xipki.asn1.x509.KeyUsage.nonRepudiation,
      C509KeyUsage.CONTENT_COMMITMENT, "nonRepudiation"),
  keyEncipherment(org.xipki.asn1.x509.KeyUsage.keyEncipherment,
      C509KeyUsage.KEY_ENCIPHERMENT),
  dataEncipherment(org.xipki.asn1.x509.KeyUsage.dataEncipherment,
      C509KeyUsage.DATA_ENCIPHERMENT),
  keyAgreement(org.xipki.asn1.x509.KeyUsage.keyAgreement,
      C509KeyUsage.KEY_AGREEMENT),
  keyCertSign(org.xipki.asn1.x509.KeyUsage.keyCertSign,
      C509KeyUsage.KEY_CERT_SIGN),
  cRLSign(org.xipki.asn1.x509.KeyUsage.cRLSign,
      C509KeyUsage.CRL_SIGN),
  encipherOnly(org.xipki.asn1.x509.KeyUsage.encipherOnly,
      C509KeyUsage.ENCIPHER_ONLY),
  decipherOnly(org.xipki.asn1.x509.KeyUsage.decipherOnly,
      C509KeyUsage.DECIPHER_ONLY);

  private final org.xipki.asn1.x509.KeyUsage asn1;

  private final C509KeyUsage c509;

  private final String[] names;

  KeyUsage(org.xipki.asn1.x509.KeyUsage asn1, C509KeyUsage c509, String... aliases) {
    this.asn1 = asn1;
    this.c509 = c509;
    int len = aliases == null ? 1 : 1 + aliases.length;
    this.names = new String[len];
    this.names[0] = name();
    if (len > 1) {
      System.arraycopy(aliases, 0, names, 1, len - 1);
    }
  }

  public org.xipki.asn1.x509.KeyUsage asn1() {
    return asn1;
  }

  public C509KeyUsage c509() {
    return c509;
  }

  public String getName() {
    return names[0];
  }

  public static KeyUsage getKeyUsage(String usage) {
    String u = Args.notNull(usage, "usage").trim();

    for (KeyUsage ku : KeyUsage.values()) {
      for (String name : ku.names) {
        if (name.equalsIgnoreCase(u)) {
          return ku;
        }
      }
    }

    throw new IllegalArgumentException("invalid KeyUsage " + usage);
  }

}
