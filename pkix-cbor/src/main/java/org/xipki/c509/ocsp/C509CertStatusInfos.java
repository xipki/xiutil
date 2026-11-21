// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.util.List;

/**
 * The non-empty list of {@link C509CertStatusInfo}s answered in a C509 OCSP response for one
 * issuer, accessible by position or by serial number.
 *
 * @author Lijun Liao (xipki)
 */
public class C509CertStatusInfos {

  private final List<C509CertStatusInfo> infos;

  public C509CertStatusInfos(List<C509CertStatusInfo> infos) {
    this.infos = Args.notEmptyAndNoNullElements(infos, "infos");
  }

  public C509CertStatusInfos(C509CertStatusInfo info) {
    this.infos = List.of(Args.notNull(info, "info"));
  }

  public int size() {
    return infos.size();
  }

  public C509CertStatusInfo getStatusAt(int index) {
    return infos.get(index);
  }

  public C509CertStatusInfo getStatusForSerialNumber(BigInteger serialNumber) {
    for (C509CertStatusInfo info : infos) {
      if (info.serialNumber().equals(serialNumber)) {
        return info;
      }
    }
    return null;
  }

}
