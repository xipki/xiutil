// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.cert;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.sign.C509Signed;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.time.Instant;

/**
 * A C509 certificate.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Certificate extends C509Signed<C509TBSCertificate> {

  public C509Certificate(C509TBSCertificate body, SignatureValue signature) {
    super(body, signature);
  }

  public static C509Certificate read(CborDecoder in) throws CodecException {
    in.readArrayLength(11);
    C509TBSCertificate body = C509TBSCertificate.read(in);
    return new C509Certificate(body, readSignature(in, body));
  }

  public static C509Certificate parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509Certificate::read);
  }

  public BigInteger serialNumber() {
    return body().serialNumber();
  }

  public C509Name issuer() {
    return body().issuer();
  }

  public C509Name subject() {
    return body().subject();
  }

  public boolean isSelfSigned() {
    return body().isSelfSigned();
  }

  public Instant notBefore() {
    return body().notBefore();
  }

  public Instant notAfter() {
    return body().notAfter();
  }

  public boolean isValidAt(Instant time) {
    return !time.isBefore(notBefore()) && !time.isAfter(notAfter());
  }

  public int type() {
    return body().type();
  }

  public C509SubjectPublicKey subjectPublicKey() {
    return body().subjectPublicKey();
  }

  public C509Extension getExtension(long extensionId) {
    return body().getExtension(extensionId);
  }

  public C509Extensions extensions() {
    return body().extensions();
  }

  public <T extends C509ExtnValue> T extension(long id, Class<T> type) {
    return extensions().valueOf(id, type);
  }

  @Override
  protected String getTitle() {
    return "C509 Certificate";
  }

}
