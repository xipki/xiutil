// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Enumerated;
import org.xipki.codec.asn1.Enumerated;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * The CRLReason enumeration.
 * <pre>
 * CRLReason ::= ENUMERATED {
 *  unspecified             (0),
 *  keyCompromise           (1),
 *  cACompromise            (2),
 *  affiliationChanged      (3),
 *  superseded              (4),
 *  cessationOfOperation    (5),
 *  certificateHold         (6),
 *  removeFromCRL           (8),
 *  privilegeWithdrawn      (9),
 *  aACompromise           (10)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CRLReason extends Enumerated {

  private static final Hashtable<Integer, CRLReason> table = new Hashtable<>();

  public static final CRLReason unspecified = getInstance(0);
  public static final CRLReason keyCompromise = getInstance(1);
  public static final CRLReason cACompromise = getInstance(2);
  public static final CRLReason affiliationChanged = getInstance(3);
  public static final CRLReason superseded = getInstance(4);
  public static final CRLReason cessationOfOperation = getInstance(5);
  public static final CRLReason certificateHold = getInstance(6);
  // 7 -> unknown
  public static final CRLReason removeFromCRL = getInstance(8);
  public static final CRLReason privilegeWithdrawn = getInstance(9);
  public static final CRLReason aACompromise = getInstance(10);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(10);
    valueNameMap.put(0, "unspecified");
    valueNameMap.put(1, "keyCompromise");
    valueNameMap.put(2, "cACompromise");
    valueNameMap.put(3, "affiliationChanged");
    valueNameMap.put(4, "superseded");
    valueNameMap.put(5, "cessationOfOperation");
    valueNameMap.put(6, "certificateHold");
    valueNameMap.put(8, "removeFromCRL");
    valueNameMap.put(9, "privilegeWithdrawn");
    valueNameMap.put(10, "aACompromise");
  }

  private CRLReason(int reason) {
    super(Args.notNegative(reason, "reason"));
  }

  @Override
  protected String getTitle() {
    return "CRLReason";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static CRLReason fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static CRLReason fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static CRLReason getInstance(int value) {
    // 100 shall be enough for the future extension.
    Args.range(value, "value", 0, 100);
    CRLReason r = table.get(value);
    if (r == null) {
      r = new CRLReason(value);
      table.put(value, r);
    }
    return r;
  }

}
