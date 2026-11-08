// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.codec.util.Args;

/**
 * Key Usage enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum KeyUsage {

  digitalSignature(org.xipki.asn1.x509.KeyUsage.digitalSignature),
  contentCommitment(org.xipki.asn1.x509.KeyUsage.nonRepudiation, "nonRepudiation"),
  keyEncipherment(org.xipki.asn1.x509.KeyUsage.keyEncipherment),
  dataEncipherment(org.xipki.asn1.x509.KeyUsage.dataEncipherment),
  keyAgreement(org.xipki.asn1.x509.KeyUsage.keyAgreement),
  keyCertSign(org.xipki.asn1.x509.KeyUsage.keyCertSign),
  cRLSign(org.xipki.asn1.x509.KeyUsage.cRLSign),
  encipherOnly(org.xipki.asn1.x509.KeyUsage.encipherOnly),
  decipherOnly(org.xipki.asn1.x509.KeyUsage.decipherOnly);

  private final org.xipki.asn1.x509.KeyUsage asn1;

  private final String[] names;

  KeyUsage(org.xipki.asn1.x509.KeyUsage asn1, String... aliases) {
    this.asn1 = asn1;
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
