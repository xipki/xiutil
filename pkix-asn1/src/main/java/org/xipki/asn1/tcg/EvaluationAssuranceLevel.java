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
 * EvaluationAssuranceLevel ::= ENUMERATED {
 *     level1 (1),
 *     level2 (2),
 *     level3 (3),
 *     level4 (4),
 *     level5 (5),
 *     level6 (6),
 *     level7 (7)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EvaluationAssuranceLevel extends Enumerated {

  private static final Hashtable<Integer, EvaluationAssuranceLevel> table = new Hashtable<>();

  public static final EvaluationAssuranceLevel level1 = getInstance(1);
  public static final EvaluationAssuranceLevel level2 = getInstance(2);
  public static final EvaluationAssuranceLevel level3 = getInstance(3);
  public static final EvaluationAssuranceLevel level4 = getInstance(4);
  public static final EvaluationAssuranceLevel level5 = getInstance(5);
  public static final EvaluationAssuranceLevel level6 = getInstance(6);
  public static final EvaluationAssuranceLevel level7 = getInstance(7);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(7);
    for (int i = 1; i < 7; i++) {
      valueNameMap.put(i, "level" + i);
    }
  }

  private EvaluationAssuranceLevel(int level) {
    super(Args.notNegative(level, "level"));
  }

  @Override
  protected String getTitle() {
    return "EvaluationAssuranceLevel";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static EvaluationAssuranceLevel fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static EvaluationAssuranceLevel fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static EvaluationAssuranceLevel getInstance(int value) {
    EvaluationAssuranceLevel r = table.get(value);
    if (r == null) {
      r = new EvaluationAssuranceLevel(value);
      table.put(value, r);
    }
    return r;
  }

}
