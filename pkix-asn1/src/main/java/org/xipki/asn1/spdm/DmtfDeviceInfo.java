// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.spdm;

import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.DerivedUtf8String;
import org.xipki.codec.exception.CodecException;

/**
 * @author Lijun Liao (xipki)
 */
public class DmtfDeviceInfo extends DerivedUtf8String {

  public DmtfDeviceInfo(Asn1Utf8String value) throws CodecException {
    super(value);
  }

  public DmtfDeviceInfo(String value) throws CodecException {
    super(value);
  }

  @Override
  protected void checkValue(Asn1Utf8String value) throws CodecException {
    String str = value.getString();
    int[] indexes = new int[3];
    int j = 0;
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (c == ':') {
        if (j > 2) {
          throw new CodecException("invalid DMTF_device_info: '" + str + "'");
        }
        indexes[j++] = i;
      }
    }

    if (j != 2) {
      throw new CodecException("invalid DMTF_device_info: '" + str + "'");
    }

    if (indexes[0] + 1 == indexes[1] || indexes[1] + 1 == indexes[2]) {
      throw new CodecException("invalid DMTF_device_info: '" + str + "'");
    }
  }

}
