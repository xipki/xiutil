// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.c509.sign.C509Signed;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * A C509 certificate revocation list.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertificateList extends C509Signed<C509TBSCertList> {

  public C509CertificateList(C509TBSCertList body, SignatureValue signature) {
    super(body, signature);
  }

  public static C509CertificateList read(CborDecoder in) throws CodecException {
    in.readArrayLength(C509CRLInfoData.FIELD_COUNT + 2);
    C509TBSCertList body = C509TBSCertList.read(in);
    return new C509CertificateList(body, readSignature(in, body));
  }

  public static C509CertificateList parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509CertificateList::read);
  }

  public C509CRLInfoData header() {
    return body().header();
  }

  public C509NameVariant authority() {
    return header().authority();
  }

  public byte[] authorityKeyId() {
    return header().authorityKeyId();
  }

  public long crlNumber() {
    return header().crlNumber();
  }

  public Instant thisUpdate() {
    return header().thisUpdate();
  }

  public Instant nextUpdate() {
    return header().nextUpdate();
  }

  public Long baseCrlNumber() {
    return header().baseCrlNumber();
  }

  public boolean isDelta() {
    return header().isDelta();
  }

  public C509Extensions extensions() {
    return header().extensions();
  }

  @Override
  protected String getTitle() {
    return "C509CertificateList";
  }

}
