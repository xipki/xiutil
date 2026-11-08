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
 * The EvaluationAssuranceLevel enumeration.
 * <pre>
 * SecurityLevel ::= ENUMERATED {
 *     level1 (1),
 *     level2 (2),
 *     level3 (3),
 *     level4 (4)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityLevel extends Enumerated {

  private static final Hashtable<Integer, SecurityLevel> table = new Hashtable<>();

  public static final SecurityLevel level1 = getInstance(1);
  public static final SecurityLevel level2 = getInstance(2);
  public static final SecurityLevel level3 = getInstance(3);
  public static final SecurityLevel level4 = getInstance(4);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(4);
    for (int i = 1; i < 4; i++) {
      valueNameMap.put(i, "level" + i);
    }
  }

  private SecurityLevel(int level) {
    super(Args.notNegative(level, "level"));
  }

  @Override
  protected String getTitle() {
    return "SecurityLevel";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static SecurityLevel fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static SecurityLevel fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static SecurityLevel getInstance(int value) {
    SecurityLevel r = table.get(value);
    if (r == null) {
      r = new SecurityLevel(value);
      table.put(value, r);
    }
    return r;
  }

}
