// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RecipientInfos extends RecipientInfo.Set1 {

  public RecipientInfos(RecipientInfo... entries) {
    super(entries);
  }

  public RecipientInfos(List<RecipientInfo> entries) {
    super(entries);
  }

  protected RecipientInfos(Asn1Set set) throws CodecException {
    super(set);
  }

  public static RecipientInfos fromAsn1(Asn1Set set) throws CodecException {
    return new RecipientInfos(set);
  }

  public boolean hasPwri() {
    for (RecipientInfo m : entries) {
      if (m.hasPwri()) {
        return true;
      }
    }
    return false;
  }

  public boolean hasOri() {
    for (RecipientInfo m : entries) {
      if (m.hasOri()) {
        return true;
      }
    }
    return false;
  }

  public boolean allWithVersion(int version) {
    for (RecipientInfo m : entries) {
      if (!m.getVersion().hasValue(version)) {
        return false;
      }
    }
    return true;
  }

}
