// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Enumerated;
import org.xipki.codec.asn1.Enumerated;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * The AttributeStatus enumeration.
 * <pre>
 * AttributeStatus ::= ENUMERATED {
 *     added    (0),
 *     modified (1),
 *     removed  (2)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeStatus extends Enumerated {

  private static final Hashtable<Integer, AttributeStatus> table = new Hashtable<>();

  public static final AttributeStatus added = getInstance(0);
  public static final AttributeStatus modified = getInstance(1);
  public static final AttributeStatus removed = getInstance(2);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(3);
    valueNameMap.put(0, "added");
    valueNameMap.put(1, "modified");
    valueNameMap.put(2, "removed");
  }

  private AttributeStatus(int status) {
    super(Args.notNegative(status, "status"));
  }

  @Override
  protected String getTitle() {
    return "AttributeStatus";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static AttributeStatus fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static AttributeStatus fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static AttributeStatus getInstance(int value) {
    AttributeStatus r = table.get(value);
    if (r == null) {
      r = new AttributeStatus(value);
      table.put(value, r);
    }
    return r;
  }

}
