// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs10;

import org.xipki.asn1.cms.AttributesGenerator;
import org.xipki.asn1.x500.DirectoryString;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.SignatureException;

/**
 * PKCS10 Certification request object.
 * <pre>
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo  CertificationRequestInfo,
 *   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature                 BIT STRING
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertificationRequest extends Asn1Encodable {

public static class CsrBuilder {

  private final SubjectPublicKeyInfo publicKeyInfo;
  private final X500Name subject;
  private final AttributesGenerator attrsGenerator = new AttributesGenerator();

  public CsrBuilder(X500Name subject, SubjectPublicKeyInfo publicKeyInfo) {
    this.subject = Args.notNull(subject, "subject");
    this.publicKeyInfo = Args.notNull(publicKeyInfo, "publicKeyInfo");
  }

  public CsrBuilder setAttribute(Attribute attr) throws GenerationException {
    Asn1Oid attrType = attr.getAttrType();
    if (attrsGenerator.hasAttribute(attrType)) {
      throw new GenerationException("Attribute " + attrType + " is already set");
    }

    attrsGenerator.addAttribute(attr);
    return this;
  }

  public CertificationRequest build(ContentSigner signer) throws SignatureException {
    CertificationRequestInfo info = new CertificationRequestInfo(subject, publicKeyInfo,
        attrsGenerator.buildSet0());
    byte[] signature = signer.atomicSign(info.getEncoded());
    return new CertificationRequest(info, signer.getAlgorithmIdentifier(), signature);
  }

}

  private final CertificationRequestInfo requestInfo;
  private final AlgorithmIdentifier algorithm;
  private final Asn1BitString signature;

  public CertificationRequest(CertificationRequestInfo requestInfo,
                              AlgorithmIdentifier algorithm, Asn1BitString signature) {
    this.requestInfo = Args.notNull(requestInfo, "requestInfo");
    this.algorithm = Args.notNull(algorithm, "algorithm");
    this.signature = Args.notNull(signature, "signature");
  }

  public CertificationRequest(CertificationRequestInfo requestInfo,
                              AlgorithmIdentifier algorithm, byte[] signature) {
    this(requestInfo, algorithm, Asn1Util.toBitString(signature));
  }

  public static CertificationRequest fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertificationRequest fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    CertificationRequestInfo requestInfo = CertificationRequestInfo.fromAsn1(seq.getSequenceAt(0));
    AlgorithmIdentifier algorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    Asn1BitString signature = seq.getBitStringAt(2);
    return new CertificationRequest(requestInfo, algorithm, signature);
  }

  public Asn1Integer getVersion() {
    return requestInfo.getVersion();
  }

  public X500Name getSubject() {
    return requestInfo.getSubject();
  }

  public SubjectPublicKeyInfo getSubjectPKInfo() {
    return requestInfo.getSubjectPKInfo();
  }

  public Attribute.Set0 getAttributes() {
    return requestInfo.getAttributes();
  }

  public int version() {
    return requestInfo.version();
  }

  public Attribute getAttribute(Asn1Oid attributeType) {
    return requestInfo.getAttribute(attributeType);
  }

  public CertificationRequestInfo getCertificationRequestInfo() {
    return requestInfo;
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return algorithm;
  }

  public Extensions getExtensionRequest() {
    Attribute attr = getAttribute(AttributeOIDs.pkcs9_at_extensionRequest);
    return attr == null ? null : attr.getExtensionRequest();
  }

  public DirectoryString getChallengePassword() {
    Attribute attr = getAttribute(AttributeOIDs.pkcs9_at_challengePassword);
    return attr == null ? null : attr.getChallengePassword();
  }

  public String challengePassword() {
    Attribute attr = getAttribute(AttributeOIDs.pkcs9_at_challengePassword);
    return attr == null ? null : attr.challengePassword();
  }

  public Asn1BitString getSignature() {
    return signature;
  }

  public byte[] signature() {
    return signature.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(requestInfo, algorithm, signature);
  }

  public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
      throws SignatureException {
    ContentVerifier verifier;
    try {
      verifier = verifierProvider.get(algorithm);
    } catch (GenerationException e) {
      throw new SignatureException(e.getMessage(), e);
    }
    return verifier.atomicVerify(requestInfo.getEncoded(), signature.getOctets());
  }

  @Override
  public int hashCode() {
    return requestInfo.hashCode() * 31 * 31 + algorithm.hashCode() * 31 + signature.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof CertificationRequest)) {
      return false;
    }

    CertificationRequest b = (CertificationRequest) obj;
    return requestInfo.equals(b.requestInfo)
        && algorithm.equals(b.algorithm)
        && signature.equals(b.signature);
  }

  @Override
  protected String getTitle() {
    return "CertificationRequest";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    requestInfo.toStringWithLineSep(buf, indentLevel, "CertificationRequest", true);
    algorithm.toStringNoLineSep(buf, indentLevel, "Algorithm", true);
    return signature.toStringNoLineSep(buf, indentLevel, "Signature");
  }

}
