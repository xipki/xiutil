// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.cert;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.c509.sign.C509SignedBody;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * TBSCertificate. Self-signed certificates omit the issuer (CBOR null); a certificate without
 * expiry omits notAfter (CBOR null, meaning 9999-12-31T23:59:59Z).
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TBSCertificate extends C509SignedBody {

  /** Natively signed C509 certificate. */
  public static final int TYPE_NATIVE = 2;

  /** Re-encoded X.509 certificate. */
  public static final int TYPE_RECODED_X509 = 3;

  public static final Instant NO_EXPIRY = Instant.ofEpochSecond(253402300799L);

  private final int type;

  private final BigInteger serialNumber;

  private final int signatureAlgorithm;

  private final C509Name issuer;

  private final Instant notBefore;

  private final Instant notAfter;

  private final C509Name subject;

  private final C509SubjectPublicKey subjectPublicKey;

  private final C509Extensions extensions;

  /**
   * @param issuer   the issuer; null or equal to the subject for self-signed certificates.
   * @param notAfter the end of validity; null for no expiry.
   */
  public C509TBSCertificate(
      int type, BigInteger serialNumber, int signatureAlgorithm,
      C509Name issuer, C509Name subject, Instant notBefore, Instant notAfter,
      C509SubjectPublicKey subjectPublicKey, C509Extensions extensions) {
    this.type = Args.among(type, "certificate type", TYPE_NATIVE);

    if (Args.notNull(serialNumber, "serialNumber").signum() < 0) {
      throw new IllegalArgumentException("negative serialNumber");
    }
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.signatureAlgorithm = signatureAlgorithm;
    this.subject = Args.notNull(subject, "subject");
    this.issuer = issuer == null ? subject : issuer;
    this.notBefore = Args.notNull(notBefore, "notBefore").truncatedTo(ChronoUnit.SECONDS);

    Instant end;
    if (notAfter == null) {
      end = NO_EXPIRY;
    } else if (notAfter.isAfter(NO_EXPIRY)) {
      end = NO_EXPIRY;
    } else {
      end = notAfter.truncatedTo(ChronoUnit.SECONDS);
    }

    if (this.notBefore.isAfter(end)) {
      throw new IllegalArgumentException("notBefore is after notAfter");
    }
    this.notAfter = end;
    this.subjectPublicKey = Args.notNull(subjectPublicKey, "subjectPublicKey");
    this.extensions = Args.notNull(extensions, "extensions");
  }

  public int type() {
    return type;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  @Override
  public int signatureAlgorithm() {
    return signatureAlgorithm;
  }

  /** The issuer; equals the subject for self-signed certificates. */
  public C509Name issuer() {
    return issuer == null ? subject : issuer;
  }

  public C509Name subject() {
    return subject;
  }

  public boolean isSelfSigned() {
    return issuer.equals(subject);
  }

  public Instant notBefore() {
    return notBefore;
  }

  public Instant notAfter() {
    return notAfter;
  }

  private boolean expires() {
    return notAfter.isBefore(NO_EXPIRY);
  }

  public C509SubjectPublicKey subjectPublicKey() {
    return subjectPublicKey;
  }

  public C509Extension getExtension(long extensionId) {
    return extensions == null ? null : extensions.get(extensionId);
  }

  public C509Extensions extensions() {
    return extensions;
  }

  @Override
  protected int fieldCount() {
    // the public key contributes two fields: algorithm and key
    return 10;
  }

  public static C509TBSCertificate read(CborDecoder in) throws CodecException {
    int type = in.readInt();
    BigInteger serial = in.readUnwrappedBigInt();
    int sigAlg = in.readInt();
    C509Name issuer = C509Cbor.orNull(in, C509Name::read);
    Instant notBefore = Instant.ofEpochSecond(in.readLong());
    Long notAfter = C509Cbor.orNull(in, CborDecoder::readLong);
    C509Name subject = C509Name.read(in);
    C509SubjectPublicKey key = C509SubjectPublicKey.read(in);
    return new C509TBSCertificate(type, serial, sigAlg, issuer, subject, notBefore,
        notAfter == null ? null : Instant.ofEpochSecond(notAfter), key, C509Extensions.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(type);
    out.writeUnwrappedBiguint(serialNumber);
    out.writeInt(signatureAlgorithm);
    out.writeObject(isSelfSigned() ? null : issuer);
    out.writeUnwrappedTime(notBefore);
    if (expires()) {
      out.writeUnwrappedTime(notAfter);
    } else {
      out.writeNull();
    }
    subject.encode(out);
    subjectPublicKey.encode(out);
    extensions.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("type", type)
        .number("serial number", serialNumber)
        .kv("signature algorithm", ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm))
        .kv("issuer", issuer.getNameText())
        .kv("subject", subject.getNameText())
        .kv("not before", notBefore)
        .kv("not after", expires() ? notAfter : "no expiry")
        .external("public key", subjectPublicKey)
        .item("extensions", extensions);
  }

}
