// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.nio.charset.StandardCharsets;

/**
 * The OCSP single request extension TN Query of draft-ietf-stir-certificates-ocsp, carrying the
 * telephone number to be checked (draft-liao-cose-c509-revocation-01, Section 7.5.2.13):
 * <pre>
 * TNQuery = text .size (1..15)
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TNQuery extends C509ExtnValue {

  private final String telephoneNumber;

  /**
   * @param telephoneNumber the telephone number, 1 to 15 bytes in UTF-8.
   */
  public C509TNQuery(String telephoneNumber) {
    Args.notNull(telephoneNumber, "telephoneNumber");
    int len = telephoneNumber.getBytes(StandardCharsets.UTF_8).length;
    if (len < 1 || len > 15) {
      throw new IllegalArgumentException("telephoneNumber must have 1 to 15 bytes, not " + len);
    }
    this.telephoneNumber = telephoneNumber;
  }

  public String telephoneNumber() {
    return telephoneNumber;
  }

  public static C509TNQuery read(CborDecoder in) throws CodecException {
    String text = in.readTextString();
    try {
      return new C509TNQuery(text);
    } catch (IllegalArgumentException e) {
      throw new CodecException("TNQuery: " + e.getMessage(), e);
    }
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeTextString(telephoneNumber);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(telephoneNumber);
  }

  @Override
  public String label() {
    return "TN Query";
  }

}
