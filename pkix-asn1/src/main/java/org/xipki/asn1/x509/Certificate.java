// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.GenerationException;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * An X509Certificate structure.
 * <pre>
 *  Certificate ::= SEQUENCE {
 *      tbsCertificate          TBSCertificate,
 *      signatureAlgorithm      AlgorithmIdentifier,
 *      signature               BIT STRING
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Certificate extends Asn1Encodable {

  /**
   * Produce an X.509 Version 3 certificate.
   */
  public static class V3CertBuilder {

    private final TBSCertificate.V3Generator tbsGen;
    private final Extensions.Generator extGenerator;

    public V3CertBuilder(
        X500Name issuer, BigInteger serial, Instant notBefore, Instant notAfter,
        X500Name subject, SubjectPublicKeyInfo publicKeyInfo) {
      Args.notNull(issuer, "issuer");
      Args.notNull(serial, "serial");
      Args.notNull(notBefore, "notBefore");
      Args.notNull(notAfter, "notAfter");
      Args.notNull(subject, "subject");
      Args.notNull(publicKeyInfo, "publicKeyInfo");

      tbsGen = new TBSCertificate.V3Generator();
      tbsGen.setSerialNumber(new Asn1Integer(serial));
      tbsGen.setIssuer(issuer);
      tbsGen.setStartDate(notBefore);
      tbsGen.setEndDate(notAfter);
      tbsGen.setSubject(subject);
      tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
      extGenerator = new Extensions.Generator();
    }

    public boolean hasExtensions() {
      return extGenerator.hasExtensions();
    }

    public boolean hasExtension(Asn1Oid oid) {
      return extGenerator.hasExtension(oid);
    }

    public Extension getExtension(Asn1Oid oid) {
      return extGenerator.getExtension(oid);
    }

    public V3CertBuilder addExtension(Extension extension) throws GenerationException {
      extGenerator.addExtension(Args.notNull(extension, "extension"));
      return this;
    }

    public V3CertBuilder replaceExtension(Extension extension){
      extGenerator.replaceExtension(Args.notNull(extension, "extension"));
      return this;
    }

    public V3CertBuilder removeExtension(Asn1Oid oid) {
      extGenerator.removeExtension(oid);
      return this;
    }

    public Certificate build(ContentSigner signer) throws GenerationException {
      AlgorithmIdentifier sigAlgID = signer.getAlgorithmIdentifier();
      tbsGen.setSignature(sigAlgID);

      try {
        if (extGenerator.hasExtensions()) {
          tbsGen.setExtensions(extGenerator.build());
        }
        TBSCertificate tbsCert = tbsGen.generateTBSCertificate();
        byte[] signature = signer.atomicSign(tbsCert.getEncoded());
        return new Certificate(tbsCert, sigAlgID, new Asn1BitString(signature));
      } catch (SignatureException | CodecException e) {
        throw new GenerationException("cannot produce certificate signature", e);
      }
    }
  }
  /**
   * SEQUENCE OF Certificate
   */
  public static class Seq0 extends AbstractSeq0<Certificate> {

    public Seq0(Certificate... entries) {
      super(entries);
    }

    public Seq0(List<Certificate> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected Certificate newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Certificate.fromAsn1(coll.getSequenceAt(index));
    }

  }

  /**
   * SEQUENCE SIZE (1..MAX) OF Certificate
   */
  public static class Seq1 extends AbstractSeq1<Certificate> {

    public Seq1(Certificate... entries) {
      super(entries);
    }

    public Seq1(List<Certificate> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected Certificate newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Certificate.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final TBSCertificate tbsCertificate;
  private final AlgorithmIdentifier signatureAlgorithm;
  private final Asn1BitString signature;

  public static Certificate fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static Certificate fromJceCert(X509Certificate cert) throws CertificateEncodingException {
    try {
      return fromEncoded(cert.getEncoded());
    } catch (CodecException e) {
      throw new CertificateEncodingException(e);
    }
  }

  public static Certificate fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    TBSCertificate tbsCert = TBSCertificate.fromAsn1(seq.getSequenceAt(0));
    AlgorithmIdentifier sigAlgId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    Asn1BitString sig = seq.getBitStringAt(2);
    return new Certificate(tbsCert, sigAlgId, sig);
  }

  public Certificate(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId,
                     Asn1BitString signature) {
    this.tbsCertificate = Args.notNull(tbsCert, "tbsCert");
    this.signatureAlgorithm = Args.notNull(sigAlgId, "sigAlgId");
    this.signature = Args.notNull(signature, "signature");
  }

  public TBSCertificate getTBSCertificate() {
    return tbsCertificate;
  }

  public Asn1Integer getVersion() {
    return tbsCertificate.getVersion();
  }

  public Time getNotBefore() {
    return tbsCertificate.getNotBefore();
  }

  public Time getNotAfter() {
    return tbsCertificate.getNotAfter();
  }

  public X500Name getIssuer() {
    return tbsCertificate.getIssuer();
  }

  public X500Name getSubject() {
    return tbsCertificate.getSubject();
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return tbsCertificate.getSubjectPublicKeyInfo();
  }

  public Validity getValidity() {
    return tbsCertificate.getValidity();
  }

  public Extensions getExtensions() {
    return tbsCertificate.getExtensions();
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  public Asn1BitString getSignature() {
    return signature;
  }

  public Asn1Integer getSerialNumber() {
    return tbsCertificate.getSerialNumber();
  }

  public Asn1BitString getIssuerUniqueID() {
    return tbsCertificate.getIssuerUniqueID();
  }

  public Asn1BitString getSubjectUniqueID() {
    return tbsCertificate.getSubjectUniqueID();
  }

  public int version() {
    return tbsCertificate.version();
  }

  public BigInteger serialNumber() {
    return tbsCertificate.serialNumber();
  }

  public Instant notBefore() {
    return tbsCertificate.notBefore();
  }

  public Instant notAfter() {
    return tbsCertificate.notAfter();
  }

  public byte[] issuerUniqueID() {
    return tbsCertificate.issuerUniqueID();
  }

  public byte[] subjectUniqueID() {
    return tbsCertificate.subjectUniqueID();
  }

  public byte[] signature() {
    return signature.getAlignedOctets();
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return tbsCertificate.getExtension(extensionId);
  }

  public boolean isValidOn(Instant time) {
    long t = time.getEpochSecond();
    return t >= notBefore().getEpochSecond() && t <= notAfter().getEpochSecond();
  }

  public void expandDetails() throws CodecException {
    tbsCertificate.expandDetails();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(tbsCertificate, signatureAlgorithm, signature);
  }

  public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
      throws SignatureException {
    if (!tbsCertificate.getSignature().equals(signatureAlgorithm)) {
      return false;
    }

    ContentVerifier verifier;
    try {
      verifier = verifierProvider.get(signatureAlgorithm);
    } catch (GenerationException e) {
      throw new SignatureException(e.getMessage(), e);
    }
    return verifier.atomicVerify(tbsCertificate.getEncoded(), signature.getOctets());
  }

  @Override
  public int hashCode() {
    return tbsCertificate.hashCode() * 31 * 31 +
        signatureAlgorithm.hashCode() * 31 + signature.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof Certificate)) {
      return false;
    }

    Certificate b = (Certificate) obj;
    return tbsCertificate.equals(b.tbsCertificate)
        && signatureAlgorithm.equals(b.signatureAlgorithm)
        && signature.equals(b.signature);
  }

  @Override
  protected String getTitle() {
    return "Certificate";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    tbsCertificate.toStringWithLineSep(buf, indentLevel, "tbsCertificate", true);
    signatureAlgorithm.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    return signature.toStringWithLineSep(buf, indentLevel, "Signature");
  }

}
