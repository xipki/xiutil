package org.xipki.c509.ocsp;

import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.util.List;

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
