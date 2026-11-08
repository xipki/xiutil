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
 * The StrengthOfFunction enumeration.
 * <pre>
 * StrengthOfFunction ::= ENUMERATED {
 *     basic  (0),
 *     medium (1),
 *     high   (2)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class StrengthOfFunction extends Enumerated {

  private static final Hashtable<Integer, StrengthOfFunction> table = new Hashtable<>();

  public static final StrengthOfFunction basic = getInstance(0);
  public static final StrengthOfFunction medium = getInstance(1);
  public static final StrengthOfFunction high = getInstance(2);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(3);
    valueNameMap.put(0, "basic");
    valueNameMap.put(1, "medium");
    valueNameMap.put(2, "high");
  }

  private StrengthOfFunction(int level) {
    super(Args.notNegative(level, "level"));
  }

  @Override
  protected String getTitle() {
    return "StrengthOfFunction";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static StrengthOfFunction fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static StrengthOfFunction fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static StrengthOfFunction getInstance(int value) {
    StrengthOfFunction r = table.get(value);
    if (r == null) {
      r = new StrengthOfFunction(value);
      table.put(value, r);
    }
    return r;
  }

}
