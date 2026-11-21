// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.sign.C509SignedBody;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.List;

/**
 * TBSCertList: the CRL header followed by the revocation groups (a flat array of five
 * elements per group). A single blank group is encoded as CBOR null.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TBSCertList extends C509SignedBody {

  private static final int GROUP_WIDTH = 5;

  private final C509CRLInfoData header;

  private final List<C509PerIssuerRevokedCerts> groups;

  /**
   * @param groups the revocation groups; an empty list stands for a single blank group.
   */
  public C509TBSCertList(C509CRLInfoData header, List<C509PerIssuerRevokedCerts> groups) {
    this.header = Args.notNull(header, "header");
    List<C509PerIssuerRevokedCerts> list = C509Cbor.frozen(groups, "groups");
    this.groups = list.isEmpty() ? List.of(C509PerIssuerRevokedCerts.BLANK) : list;
  }

  public C509CRLInfoData header() {
    return header;
  }

  public List<C509PerIssuerRevokedCerts> groups() {
    return groups;
  }

  private boolean hasNoGroups() {
    return groups.size() == 1 && groups.get(0).isBlank();
  }

  @Override
  public int signatureAlgorithm() {
    return header.signatureAlgorithm();
  }

  @Override
  protected int fieldCount() {
    return C509CRLInfoData.FIELD_COUNT + 1;
  }

  static C509TBSCertList read(CborDecoder in) throws CodecException {
    C509CRLInfoData header = C509CRLInfoData.read(in);
    List<C509PerIssuerRevokedCerts> groups = C509Cbor.orNull(in,
        x -> C509Cbor.readGroups(x, GROUP_WIDTH, "revocation groups",
            C509PerIssuerRevokedCerts::read));
    return new C509TBSCertList(header, groups == null ? List.of() : groups);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    header.encode(out);
    if (hasNoGroups()) {
      out.writeNull();
    } else {
      C509Cbor.writeGroups(out, GROUP_WIDTH, groups);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    out.inline(header);
    if (hasNoGroups()) {
      out.line("no revoked certificates");
    } else {
      out.items("revocation groups", groups);
    }
  }

}
