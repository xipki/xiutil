// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Enumerated;
import org.xipki.codec.asn1.Enumerated;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * OCSP RFC 2560, RFC 6960
 * <p>
 * The OCSPResponseStatus enumeration.
 * <pre>
 * OCSPResponseStatus ::= ENUMERATED {
 *     successful            (0),  --Response has valid confirmations
 *     malformedRequest      (1),  --Illegal confirmation request
 *     internalError         (2),  --Internal error in issuer
 *     tryLater              (3),  --Try again later
 *                                 --(4) is not used
 *     sigRequired           (5),  --Must sign the request
 *     unauthorized          (6)   --Request unauthorized
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OCSPResponseStatus extends Enumerated {

  private static final Hashtable<Integer, OCSPResponseStatus> table = new Hashtable<>();

  public static final OCSPResponseStatus SUCCESSFUL = getInstance(0);
  public static final OCSPResponseStatus MALFORMED_REQUEST = getInstance(1);
  public static final OCSPResponseStatus INTERNAL_ERROR = getInstance(2);
  public static final OCSPResponseStatus TRY_LATER = getInstance(3);
  public static final OCSPResponseStatus SIG_REQUIRED = getInstance(5);
  public static final OCSPResponseStatus UNAUTHORIZED = getInstance(6);

  private static final Map<Integer, String> valueNameMap;

  static {
    valueNameMap = new HashMap<>(6);
    valueNameMap.put(0, "successful");
    valueNameMap.put(1, "malformedRequest");
    valueNameMap.put(2, "internalError");
    valueNameMap.put(3, "tryLater");
    valueNameMap.put(5, "sigRequired");
    valueNameMap.put(6, "unauthorized");
  }

  private OCSPResponseStatus(int status) {
    super(Args.notNegative(status, "status"));
  }

  @Override
  protected String getTitle() {
    return "OCSPResponseStatus";
  }

  @Override
  public String getEnumeratedName() {
    String name = valueNameMap.get(enumerated.getValue());
    return name == null ? "N/A" : name;
  }

  public static OCSPResponseStatus fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Enumerated.fromEncoded(encoded));
  }

  public static OCSPResponseStatus fromAsn1(Asn1Enumerated asn1) {
    return getInstance(Args.notNull(asn1, "asn1").getValue());
  }

  public static OCSPResponseStatus getInstance(int value) {
    OCSPResponseStatus r = table.get(value);
    if (r == null) {
      r = new OCSPResponseStatus(value);
      table.put(value, r);
    }
    return r;
  }

}
