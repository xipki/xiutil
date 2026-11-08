// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * SignerInfos ::= SET OF SignerInfo
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SignerInfos extends SignerInfo.Set0 {

  public SignerInfos(SignerInfo... entries) {
    super(entries);
  }

  public SignerInfos(List<SignerInfo> entries) {
    super(entries.toArray(new SignerInfo[0]));
  }

  protected SignerInfos(Asn1Set set) throws CodecException {
    super(set);
  }

  public static SignerInfos fromAsn1(Asn1Set set) throws CodecException {
    return new SignerInfos(set);
  }

  public boolean hasSignerInfoVersion(int version) {
    for (SignerInfo signerInfo : entries) {
      if (signerInfo.getVersion().hasValue(version)) {
        return true;
      }
    }
    return false;
  }

}
