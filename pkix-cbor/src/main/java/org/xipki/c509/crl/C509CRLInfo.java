// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.time.Instant;

/**
 * C509CRLInfo: the CRL header alone, as one array.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CRLInfo extends C509CborItem {

  private final C509CRLInfoData header;

  public C509CRLInfo(C509CRLInfoData header) {
    this.header = Args.notNull(header, "header");
  }

  public static C509CRLInfo fromCRL(C509CertificateList crl) {
    return new C509CRLInfo(crl.header());
  }

  public C509CRLInfoData header() {
    return header;
  }

  public int signatureAlgorithm() {
    return header.signatureAlgorithm();
  }

  public C509NameVariant authority() {
    return header.authority();
  }

  public byte[] authorityKeyId() {
    return header.authorityKeyId();
  }

  public long crlNumber() {
    return header.crlNumber();
  }

  public Instant thisUpdate() {
    return header.thisUpdate();
  }

  public Instant nextUpdate() {
    return header.nextUpdate();
  }

  public Long baseCrlNumber() {
    return header.baseCrlNumber();
  }

  public boolean isDelta() {
    return header.isDelta();
  }

  public C509Extensions extensions() {
    return header.extensions();
  }

  public static C509CRLInfo read(CborDecoder in) throws CodecException {
    in.readArrayLength(C509CRLInfoData.FIELD_COUNT);
    return new C509CRLInfo(C509CRLInfoData.read(in));
  }

  public static C509CRLInfo parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509CRLInfo::read);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(C509CRLInfoData.FIELD_COUNT);
    header.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.inline(header);
  }

}
