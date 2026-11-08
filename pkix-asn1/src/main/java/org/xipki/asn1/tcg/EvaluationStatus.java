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
 * The EvaluationStatus enumeration.
 * <pre>
 * EvaluationStatus ::= ENUMERATED {
 *     designedToMeet       (0),
 *     evaluationInProgress (1),
 *     evaluationCompleted  (2)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EvaluationStatus extends Enumerated {

  private static final Hashtable<Integer, EvaluationStatus> table = new Hashtable<>();

  public static final EvaluationStatus designedToMeet = getInstance(0);
  public static final EvaluationStatus evaluationInProgress = getInstance(1);
  public static final EvaluationStatus evaluationCompleted = getInstance(2);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(3);
    valueNameMap.put(0, "designedToMeet");
    valueNameMap.put(1, "evaluationInProgress");
    valueNameMap.put(2, "evaluationCompleted");
  }

  private EvaluationStatus(int status) {
    super(Args.notNegative(status, "status"));
  }

  @Override
  protected String getTitle() {
    return "EvaluationStatus";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static EvaluationStatus fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static EvaluationStatus fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static EvaluationStatus getInstance(int value) {
    EvaluationStatus r = table.get(value);
    if (r == null) {
      r = new EvaluationStatus(value);
      table.put(value, r);
    }
    return r;
  }

}
