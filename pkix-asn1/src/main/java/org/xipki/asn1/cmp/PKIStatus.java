// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.util.ToStringUtil;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * PKIStatus ::= INTEGER {
 *          accepted               (0),
 *          grantedWithMods        (1),
 *          rejection              (2),
 *          waiting                (3),
 *          revocationWarning      (4),
 *          revocationNotification (5),
 *          keyUpdateWarning       (6)
 *      }
 *
 * @author Lijun Liao (xipki)
 */
public class PKIStatus extends Asn1Encodable {

  private static final Hashtable<Integer, PKIStatus> table = new Hashtable<>();

  private static final Map<Integer, String> valueNameMap = new HashMap<>(7);

  public static final PKIStatus accepted = init(0, "accepted");
  public static final PKIStatus grantedWithMods = init(1, "grantedWithMods");
  public static final PKIStatus rejection = init(2, "rejection");
  public static final PKIStatus waiting = init(3, "waiting");
  public static final PKIStatus revocationWarning = init(4, "revocationWarning");
  public static final PKIStatus revocationNotification = init(5, "revocationNotification");
  public static final PKIStatus keyUpdateWarning = init(6, "keyUpdateWarning");

  private final int value;

  private static PKIStatus init(int code, String name) {
    valueNameMap.put(code, name);
    PKIStatus r = new PKIStatus(code);
    table.put(code, r);
    return r;
  }

  private PKIStatus(int value) {
    this.value = value;
  }

  public int value() {
    return value;
  }

  /**
   * Returns the name of the status, or {@code null} if the value has no name.
   * @return the name of the status.
   */
  public String name() {
    return valueNameMap.get(value);
  }

  @Override
  public int hashCode() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }

    if (!(o instanceof PKIStatus)) {
      return false;
    }

    return ((PKIStatus) o).value == value;
  }

  public static PKIStatus getInstance(int value) {
    PKIStatus r = table.get(value);
    return r == null ? new PKIStatus(value) : r;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Integer(value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    String name = name();
    return ToStringUtil.appendIndent(buf, indentLevel,
        (name != null) ? name : Integer.toString(value));
  }

}
