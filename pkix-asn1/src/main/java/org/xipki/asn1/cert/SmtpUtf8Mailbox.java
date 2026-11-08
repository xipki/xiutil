// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cert;

import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.DerivedUtf8String;
import org.xipki.codec.exception.CodecException;

/**
 * @author Lijun Liao (xipki)
 */
public class SmtpUtf8Mailbox extends DerivedUtf8String {

  @Override
  protected void checkValue(Asn1Utf8String value) throws CodecException {
    String text = value.getString();
    boolean withNonAscii = false;
    for (int i = 0; i < text.length(); i++) {
      int c = text.charAt(i);
      if (c > 127) {
        withNonAscii = true;
        break;
      }
    }

    if (!withNonAscii) {
      throw new CodecException("smtpUTF8Mailbox shall not contain ASCII-only mailbox");
    }
  }

  public SmtpUtf8Mailbox(Asn1Utf8String value) throws CodecException {
    super(value);
  }

  public SmtpUtf8Mailbox(String value) throws CodecException {
    super(value);
  }

}
