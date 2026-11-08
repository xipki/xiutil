// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.time.Instant;

/**
 * The TBSCertificate object.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  EXPLICIT Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] EXPLICIT Extensions OPTIONAL
 *      }
 *
 * UniqueIdentifier  ::=  BIT STRING
 * </pre>
 * <p>
 * Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
 * will parse them, but you really shouldn't be creating new ones.
 *
 * @author Lijun Liao (xipki)
 */
public class TBSCertificate extends Asn1Encodable {

  public static class V3Generator {

    private Asn1Integer serialNumber;
    private AlgorithmIdentifier signature;
    private X500Name issuer;
    private Instant startDate;
    private Instant endDate;
    private X500Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private Extensions extensions;

    public V3Generator() {
    }

    public void setSerialNumber(Asn1Integer  serialNumber) {
      this.serialNumber = serialNumber;
    }

    public void setSignature(AlgorithmIdentifier signature) {
      this.signature = signature;
    }

    public void setIssuer(X500Name issuer) {
      this.issuer = issuer;
    }

    public void setStartDate(Instant startDate) {
      this.startDate = startDate;
    }

    public void setEndDate(Instant endDate) {
      this.endDate = endDate;
    }

    public void setSubject(X500Name subject) {
      this.subject = subject;
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo pubKeyInfo) {
      this.subjectPublicKeyInfo = pubKeyInfo;
    }

    public void setExtensions(Extensions extensions) {
      this.extensions = extensions;
    }

    public TBSCertificate generateTBSCertificate() {
      Validity validity = new Validity(startDate, endDate);
      return new TBSCertificate(2, serialNumber, signature, issuer, validity, subject,
          subjectPublicKeyInfo, extensions);
    }

  }

  private final Asn1Integer          version;
  private final Asn1Integer          serialNumber;
  private final AlgorithmIdentifier  signature;
  private final X500Name             issuer;
  private final Validity             validity;
  private final X500Name             subject;
  private final SubjectPublicKeyInfo subjectPublicKeyInfo;
  private final Asn1BitString        issuerUniqueID;
  private final Asn1BitString        subjectUniqueID;
  private final Extensions           extensions;

  public TBSCertificate(
      int version, Asn1Integer serialNumber, AlgorithmIdentifier signature,
      X500Name issuer, Validity validity, X500Name subject,
      SubjectPublicKeyInfo subjectPublicKeyInfo, Extensions extensions) {
    this.version = new Asn1Integer(Args.range(version, "version", 0, 2));
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.signature = Args.notNull(signature, "signature");
    this.issuer = Args.notNull(issuer, "issuer");
    if (issuer.size() == 0) {
      throw new IllegalArgumentException("certificate issuer is an empty distinguished name");
    }

    this.validity = Args.notNull(validity, "validity");
    this.subject = Args.notNull(subject, "subject");
    this.subjectPublicKeyInfo = Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");

    if (version < 2) {
      if (extensions != null) {
        throw new IllegalArgumentException("extensions is not allowed in version " + version);
      }
    }

    this.extensions = extensions;
    this.issuerUniqueID = null;
    this.subjectUniqueID = null;
  }

  public static TBSCertificate fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeMin(seq, "seq", 6);
    int index = 0;

    // version
    Asn1Integer bn = seq.isNotTaggedAt(index, 0) ? Asn1Integer.ZERO
        : seq.getNonNegativeIntegerTaggedAt(index++, true);

    int version = bn.intValueExact();
    if (!(version == 0 || version == 1 || version == 2)) {
      throw new CodecException("invalid version " + version);
    }

    Asn1Integer serialNumber = seq.getNonNegativeIntegerAt(index++);
    AlgorithmIdentifier signature = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index++));
    X500Name issuer = X500Name.fromAsn1(seq.getSequenceAt(index++));
    // RFC 5280 sec. 4.1.2.4: certificate issuer MUST be a non-empty DN.
    if (issuer.size() == 0) {
      throw new CodecException("certificate issuer is an empty distinguished name");
    }

    Validity validity = Validity.fromAsn1(seq.getSequenceAt(index++));
    X500Name subject  = X500Name.fromAsn1(seq.getSequenceAt(index++));
    SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.fromAsn1(seq.getSequenceAt(index++));

    Asn1BitString issuerUniqueID = seq.isNotTaggedAt(index, 1) ? null
        : seq.getBitStringTaggedAt(index++, false);

    Asn1BitString subjectUniqueID = seq.isNotTaggedAt(index, 2) ? null
        : seq.getBitStringTaggedAt(index++, false);

    Extensions extensions = seq.isNotTaggedAt(index, 3) ? null
        : Extensions.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    if (issuerUniqueID != null && version == 0) {
      throw new CodecException("issuerUniqueID is present but not allowed");
    }

    if (subjectUniqueID != null && version == 0) {
      throw new CodecException("subjectUniqueID is present but not allowed");
    }

    if (extensions != null && version < 2) {
      throw new CodecException("extensions is present but not allowed");
    }

    Asn1Util.checkSequenceEnd(index, size);

    return new TBSCertificate(version, serialNumber, signature, issuer, validity, subject,
        subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions);
  }

  private TBSCertificate(
      int version, Asn1Integer serialNumber, AlgorithmIdentifier signature, X500Name issuer,
      Validity validity, X500Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo,
      Asn1BitString issuerUniqueID, Asn1BitString subjectUniqueID, Extensions extensions) {
    this.version = new Asn1Integer(version);
    this.serialNumber = serialNumber;
    this.signature = signature;
    this.issuer = issuer;
    this.validity = validity;
    this.subject = subject;
    this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    this.issuerUniqueID = issuerUniqueID;
    this.subjectUniqueID = subjectUniqueID;
    this.extensions = extensions;
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public Asn1Integer getSerialNumber() {
    return serialNumber;
  }

  public AlgorithmIdentifier getSignature() {
    return signature;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public Validity getValidity() {
    return validity;
  }

  public Time getNotBefore() {
    return validity.getNotBefore();
  }

  public Time getNotAfter() {
    return validity.getNotAfter();
  }

  public X500Name getSubject() {
    return subject;
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

  public Asn1BitString getIssuerUniqueID() {
    return issuerUniqueID;
  }

  public Asn1BitString getSubjectUniqueID() {
    return subjectUniqueID;
  }

  public Extensions getExtensions() {
    return extensions;
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return extensions == null ? null : extensions.getExtension(extensionId);
  }

  public void expandDetails() throws CodecException {
    if (extensions == null) {
      return;
    }

    for (Extension extn : extensions.getEntries()) {
      extn.parseValue();
    }
  }

  public int version() {
    return version.intValueExact();
  }

  public BigInteger serialNumber() {
    return serialNumber.getValue();
  }

  public Instant notBefore() {
    return validity.notBefore();
  }

  public Instant notAfter() {
    return validity.notAfter();
  }

  public byte[] issuerUniqueID() {
    return Asn1Util.fromAsn1(issuerUniqueID);
  }

  public byte[] subjectUniqueID() {
    return Asn1Util.fromAsn1(subjectUniqueID);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    Asn1TaggedObject asn1Version = version.hasValue(0) ? null
        : Asn1TaggedObject.newExplicit(0, version);
    return Asn1Sequence.buildIgnoreNull(
        asn1Version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo,
        (issuerUniqueID == null) ? null : Asn1TaggedObject.newImplicit(1, issuerUniqueID),
        (subjectUniqueID == null) ? null : Asn1TaggedObject.newImplicit(2, subjectUniqueID),
        (extensions == null) ? null : Asn1TaggedObject.newExplicit(3, extensions));
  }

  @Override
  protected String getTitle() {
    return "TBSCertificate";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    serialNumber.toStringNoLineSep(buf, indentLevel, "serialNumber", true);
    signature.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    issuer.toStringNoLineSep(buf, indentLevel, "issuer", true);
    validity.toString(buf, indentLevel).append("\n");
    subject.toStringNoLineSep(buf, indentLevel, "subject", true);
    subjectPublicKeyInfo.toStringWithLineSep(buf, indentLevel, "subjectPublicKeyInfo", true);

    if (issuerUniqueID != null) {
      issuerUniqueID.toStringNoLineSep(buf, indentLevel, "issuerUniqueID", true);
    }

    if (subjectUniqueID != null) {
      subjectUniqueID.toStringNoLineSep(buf, indentLevel, "subjectUniqueID", true);
    }

    if (extensions != null) {
      extensions.toStringWithLineSep(buf, indentLevel, "extensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
