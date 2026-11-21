// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

/**
 * The ReasonFlags of a CRL distribution point.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ReasonFlags extends C509BitFlagsExtnValue {

  public static final int UNUSED = 1;
  public static final int KEY_COMPROMISE = 1 << 1;
  public static final int CA_COMPROMISE = 1 << 2;
  public static final int AFFILIATION_CHANGED = 1 << 3;
  public static final int SUPERSEDED = 1 << 4;
  public static final int CESSATION_OF_OPERATION = 1 << 5;
  public static final int CERTIFICATE_HOLD = 1 << 6;
  public static final int PRIVILEGE_WITHDRAWN = 1 << 7;
  public static final int AA_COMPROMISE = 1 << 8;

  private static final String[] NAMES = {"unused", "keyCompromise", "cACompromise",
      "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold",
      "privilegeWithdrawn", "aACompromise"};

  public C509ReasonFlags(int bits) {
    super(bits);
  }

  public static C509ReasonFlags of(int... masks) {
    return new C509ReasonFlags(combine(masks, false));
  }

  public static C509ReasonFlags read(CborDecoder in) throws CodecException {
    return new C509ReasonFlags(in.readInt());
  }

  @Override
  protected String[] bitNames() {
    return NAMES;
  }

  @Override
  public String label() {
    return "Reason Flags";
  }

}
