// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 *  CertTemplate ::= SEQUENCE {
 *      version      [0] Version               OPTIONAL,
 *      serialNumber [1] INTEGER               OPTIONAL,
 *      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 *      issuer       [3] Name                  OPTIONAL,
 *      validity     [4] OptionalValidity      OPTIONAL,
 *      subject      [5] Name                  OPTIONAL,
 *      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
 *      issuerUID    [7] UniqueIdentifier      OPTIONAL,
 *      subjectUID   [8] UniqueIdentifier      OPTIONAL,
 *      extensions   [9] Extensions            OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertTemplate extends Asn1Encodable {

  private static final int tag0_version      = 0;
  private static final int tag1_serialNumber = 1;
  private static final int tag2_signingAlg   = 2;
  private static final int tag3_issuer       = 3;
  private static final int tag4_validity     = 4;
  private static final int tag5_subject      = 5;
  private static final int tag6_publicKey    = 6;
  private static final int tag7_issuerUID    = 7;
  private static final int tag8_subjectUID   = 8;
  private static final int tag9_extensions   = 9;

  private Asn1Integer version;
  private Asn1Integer serialNumber;
  private AlgorithmIdentifier signingAlg;
  private X500Name issuer;
  private OptionalValidity validity;
  private X500Name subject;
  private SubjectPublicKeyInfo publicKey;
  private Asn1BitString issuerUID;
  private Asn1BitString subjectUID;
  private Extensions extensions;

  public static CertTemplate fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 10);
    int index = 0;

    CertTemplate r = new CertTemplate();
    Asn1Integer version = seq.isNotTaggedAt(index, tag0_version) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);
    r.setVersion(version);

    Asn1Integer serialNumber = seq.isNotTaggedAt(index, tag1_serialNumber) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);
    r.setSerialNumber(serialNumber);

    AlgorithmIdentifier signingAlg = seq.isNotTaggedAt(index, tag2_signingAlg) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    r.setSigningAlg(signingAlg);

    // CHOICE -> Explicit
    X500Name issuer = seq.isNotTaggedAt(index, tag3_issuer) ? null
            : X500Name.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    r.setIssuer(issuer);

    OptionalValidity validity = seq.isNotTaggedAt(index, tag4_validity) ? null
            : OptionalValidity.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    r.setValidity(validity);

    // CHOICE -> Explicit
    X500Name subject = seq.isNotTaggedAt(index, tag5_subject) ? null
            : X500Name.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    r.setSubject(subject);

    SubjectPublicKeyInfo publicKey = seq.isNotTaggedAt(index, tag6_publicKey) ? null
            : SubjectPublicKeyInfo.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    r.setPublicKey(publicKey);

    Asn1BitString issuerUID = seq.isNotTaggedAt(index, tag7_issuerUID) ? null
            : seq.getBitStringTaggedAt(index++, false);
    r.setIssuerUID(issuerUID);

    Asn1BitString subjectUID = seq.isNotTaggedAt(index, tag8_subjectUID) ? null
            : seq.getBitStringTaggedAt(index++, false);
    r.setSubjectUID(subjectUID);

    Extensions extensions = seq.isNotTaggedAt(index, tag9_extensions) ? null
            : Extensions.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    r.setExtensions(extensions);

    Asn1Util.checkSequenceEnd(index, size);

    return r;
  }

  public void setVersion(int version) {
    this.version = new Asn1Integer(version);
  }

  public void setVersion(Asn1Integer version) {
    this.version = version;
  }

  public void setSerialNumber(Asn1Integer serialNumber) {
    this.serialNumber = serialNumber;
  }

  public void setSigningAlg(AlgorithmIdentifier signingAlg) {
    this.signingAlg = signingAlg;
  }

  public void setIssuer(X500Name issuer) {
    this.issuer = issuer;
  }

  public void setValidity(OptionalValidity validity) {
    this.validity = validity;
  }

  public void setSubject(X500Name subject) {
    this.subject = subject;
  }

  public void setPublicKey(SubjectPublicKeyInfo publicKey) {
    this.publicKey = publicKey;
  }

  public void setIssuerUID(Asn1BitString issuerUID) {
    this.issuerUID = issuerUID;
  }

  public void setSubjectUID(Asn1BitString subjectUID) {
    this.subjectUID = subjectUID;
  }

  public void setExtensions(Extensions extensions) {
    this.extensions = extensions;
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public Asn1Integer getSerialNumber() {
    return serialNumber;
  }

  public AlgorithmIdentifier getSigningAlg() {
    return signingAlg;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public OptionalValidity getValidity() {
    return validity;
  }

  public X500Name getSubject() {
    return subject;
  }

  public SubjectPublicKeyInfo getPublicKey() {
    return publicKey;
  }

  public Asn1BitString getIssuerUID() {
    return issuerUID;
  }

  public Asn1BitString getSubjectUID() {
    return subjectUID;
  }

  public Extensions getExtensions() {
    return extensions;
  }

  public Integer version() {
    return Asn1Util.fromAsn1Int(version);
  }

  public BigInteger serialNumber() {
    return Asn1Util.fromAsn1(serialNumber);
  }

  public byte[] issuerUID() {
    return Asn1Util.fromAsn1(issuerUID);
  }

  public byte[] subjectUID() {
    return Asn1Util.fromAsn1(subjectUID);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    List<Asn1Encodable> v = new ArrayList<>(10);
    addOptional(v, false, tag0_version,      version);
    addOptional(v, false, tag1_serialNumber, serialNumber);
    addOptional(v, false, tag2_signingAlg,   signingAlg);
    addOptional(v, true,  tag3_issuer,     issuer);
    addOptional(v, false, tag4_validity,   validity);
    addOptional(v, true,  tag5_subject,    subject);
    addOptional(v, false, tag6_publicKey,  publicKey);
    addOptional(v, false, tag7_issuerUID,  issuerUID);
    addOptional(v, false, tag8_subjectUID, subjectUID);
    addOptional(v, false, tag9_extensions, extensions);
    return new Asn1Sequence(v);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (version != null) {
      version.toStringNoLineSep(buf, indentLevel, "version", true);
    }

    if (serialNumber != null) {
      serialNumber.toStringNoLineSep(buf, indentLevel, "serialNumber", true);
    }

    if (signingAlg != null) {
      signingAlg.toStringWithLineSep(buf, indentLevel, "signingAlg", true);
    }

    if (issuer != null) {
      issuer.toStringNoLineSep(buf, indentLevel, "issuer", true);
    }

    if (validity != null) {
      validity.toStringWithLineSep(buf, indentLevel, "validity", true);
    }

    if (subject != null) {
      subject.toStringNoLineSep(buf, indentLevel, "subject", true);
    }

    if (publicKey != null) {
      publicKey.toStringWithLineSep(buf, indentLevel, "publicKey", true);
    }

    if (issuerUID != null) {
      issuerUID.toStringWithLineSep(buf, indentLevel, "issuerUID", true);
    }

    if (subjectUID != null) {
      subjectUID.toStringWithLineSep(buf, indentLevel, "subjectUID", true);
    }

    if (extensions != null) {
      extensions.toStringWithLineSep(buf, indentLevel, "extensions", true);
    }

    return deleteLastNewLine(buf);
  }

  private static void addOptional(List<Asn1Encodable> v, boolean explicit,
                                  int tagNo, Asn1Encodable value) {
    if (value != null) {
      v.add(new Asn1TaggedObject(explicit, tagNo, value));
    }
  }
}
