// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csr;

import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509Attributes;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.c509.sign.C509SignedBody;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.List;

/**
 * TBSCertificateRequest.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TBSCertificationRequest extends C509SignedBody {

  public static final int TYPE_NATIVE = 2;

  public static final int TYPE_RECODED_X509 = 3;

  private final int type;

  private final int signatureAlgorithm;

  private final C509Name subject;

  private final C509SubjectPublicKey subjectPublicKey;

  private final C509Attributes attributes;

  public C509TBSCertificationRequest(
      int type, int signatureAlgorithm, C509Name subject,
      C509SubjectPublicKey subjectPublicKey, C509Attributes attributes) {
    if (type != TYPE_NATIVE && type != TYPE_RECODED_X509) {
      throw new IllegalArgumentException("invalid request type " + type);
    }
    this.type = type;
    this.signatureAlgorithm = signatureAlgorithm;
    this.subject = Args.notNull(subject, "subject");
    this.subjectPublicKey = Args.notNull(subjectPublicKey, "subjectPublicKey");
    this.attributes = Args.notNull(attributes, "attributes");
  }

  public int type() {
    return type;
  }

  @Override
  public int signatureAlgorithm() {
    return signatureAlgorithm;
  }

  public C509Name subject() {
    return subject;
  }

  public C509SubjectPublicKey subjectPublicKey() {
    return subjectPublicKey;
  }

  public C509Attributes attributes() {
    return attributes;
  }

  public List<C509Attribute> getAttribute(long attributeType) {
    return attributes.all(attributeType);
  }

  public C509Attribute getFirstAttribute(long attributeType) {
    return attributes.first(attributeType);
  }

  @Override
  protected int fieldCount() {
    return 6;
  }

  public static C509TBSCertificationRequest read(CborDecoder in) throws CodecException {
    int type = in.readInt();
    int sigAlg = in.readInt();
    C509Name subject = C509Name.read(in);
    C509SubjectPublicKey key = C509SubjectPublicKey.read(in);
    return new C509TBSCertificationRequest(type, sigAlg, subject, key, C509Attributes.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(type);
    out.writeInt(signatureAlgorithm);
    subject.encode(out);
    subjectPublicKey.encode(out);
    attributes.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("type", type)
        .kv("signature algorithm", ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm))
        .kv("subject", subject.getNameText())
        .external("public key", subjectPublicKey)
        .item("attributes", attributes);
  }

}
