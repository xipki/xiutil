// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csr;

import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509Attributes;
import org.xipki.c509.attr.C509ChallengePassword;
import org.xipki.c509.attr.C509ExtensionRequest;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.c509.sign.C509Signed;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * A C509 certification request, signed with the key it requests a certificate for.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertificationRequest extends C509Signed<C509TBSCertificationRequest> {

  public C509CertificationRequest(C509TBSCertificationRequest body, SignatureValue signature) {
    super(body, signature);
  }

  public static C509CertificationRequest read(CborDecoder in) throws CodecException {
    in.readArrayLength(7);
    C509TBSCertificationRequest body = C509TBSCertificationRequest.read(in);
    return new C509CertificationRequest(body, readSignature(in, body));
  }

  public static C509CertificationRequest parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509CertificationRequest::read);
  }

  /** The challenge password, or null. */
  public String challengePassword() {
    C509ChallengePassword v = body().attributes().firstValue(ConstAttributeType.challengePassword,
        C509ChallengePassword.class);
    return v == null ? null : v.password();
  }

  /** The requested extensions, or null. */
  public C509Extensions requestedExtensions() {
    C509ExtensionRequest v = body().attributes().firstValue(ConstAttributeType.extensionRequest,
        C509ExtensionRequest.class);
    return v == null ? null : v.extensions();
  }

  public int type() {
    return body().type();
  }

  public C509Name subject() {
    return body().subject();
  }

  public C509SubjectPublicKey subjectPublicKey() {
    return body().subjectPublicKey();
  }

  public C509Attributes attributes() {
    return body().attributes();
  }

  public List<C509Attribute> getAttribute(long attributeType) {
    return body().getAttribute(attributeType);
  }

  public C509Attribute getFirstAttribute(long attributeType) {
    return body().getFirstAttribute(attributeType);
  }

  @Override
  protected String getTitle() {
    return "C509 Certification Request";
  }

}
