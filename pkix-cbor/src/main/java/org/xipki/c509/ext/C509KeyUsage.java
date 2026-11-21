// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

/**
 * The key usage extension.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509KeyUsage extends C509BitFlagsExtnValue {

  public static final C509KeyUsage DIGITAL_SIGNATURE = new C509KeyUsage(1);
  public static final C509KeyUsage CONTENT_COMMITMENT = new C509KeyUsage(1 << 1);
  public static final C509KeyUsage KEY_ENCIPHERMENT = new C509KeyUsage(1 << 2);
  public static final C509KeyUsage DATA_ENCIPHERMENT = new C509KeyUsage(1 << 3);
  public static final C509KeyUsage KEY_AGREEMENT = new C509KeyUsage(1 << 4);
  public static final C509KeyUsage KEY_CERT_SIGN = new C509KeyUsage(1 << 5);
  public static final C509KeyUsage CRL_SIGN = new C509KeyUsage(1 << 6);
  public static final C509KeyUsage ENCIPHER_ONLY = new C509KeyUsage(1 << 7);
  public static final C509KeyUsage DECIPHER_ONLY = new C509KeyUsage(1 << 8);

  private static final String[] NAMES = {"digitalSignature", "contentCommitment",
      "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
      "encipherOnly", "decipherOnly"};

  public C509KeyUsage(int bits) {
    super(bits);
  }

  /**
   * Combines masks such as {@link #DIGITAL_SIGNATURE}.
   */
  public static C509KeyUsage of(int... masks) {
    return new C509KeyUsage(combine(masks, false));
  }

  /**
   * Combines masks such as {@link #DIGITAL_SIGNATURE}.
   */
  public static C509KeyUsage of(C509KeyUsage... usages) {
    int[] masks = new int[usages.length];
    for (int i = 0; i < masks.length; i++) {
      masks[i] = usages[i].bits();
    }

    return new C509KeyUsage(combine(masks, false));
  }

  /**
   * Combines bit indexes as defined in RFC 5280 (0 = digitalSignature).
   */
  public static C509KeyUsage ofBitIndexes(int... indexes) {
    return new C509KeyUsage(combine(indexes, true));
  }

  public static C509KeyUsage read(CborDecoder in) throws CodecException {
    return new C509KeyUsage(in.readInt());
  }

  public boolean hasUsage(C509KeyUsage usage) {
    return has(usage.bits());
  }

  @Override
  protected String[] bitNames() {
    return NAMES;
  }

  @Override
  public String label() {
    return "Key Usage";
  }

}
