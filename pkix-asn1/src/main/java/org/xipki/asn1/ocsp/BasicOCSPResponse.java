// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.Extension;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.SignatureException;
import java.time.Instant;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * BasicOCSPResponse       ::= SEQUENCE {
 *    tbsResponseData      ResponseData,
 *    signatureAlgorithm   AlgorithmIdentifier,
 *    signature            BIT STRING,
 *    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class BasicOCSPResponse extends Asn1Encodable {

  private final ResponseData tbsResponseData;
  private final AlgorithmIdentifier signatureAlgorithm;
  private final Asn1BitString signature;
  private final Certificate.Seq0 certs;

  public BasicOCSPResponse(ResponseData tbsResponseData, AlgorithmIdentifier signatureAlgorithm,
                           Asn1BitString signature, Certificate.Seq0 certs) {
    this.tbsResponseData = Args.notNull(tbsResponseData, "tbsResponseData");
    this.signatureAlgorithm = Args.notNull(signatureAlgorithm, "signatureAlgorithm");
    this.signature = Args.notNull(signature, "signature");
    this.certs = certs;
  }

  public static BasicOCSPResponse fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static BasicOCSPResponse fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 4);
    ResponseData tbsResponseData = ResponseData.fromAsn1(seq.getSequenceAt(0));
    AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    Asn1BitString signature = seq.getBitStringAt(2);
    Certificate.Seq0 certs = (size == 3) ? null
        : Certificate.Seq0.fromAsn1(seq.getTaggedAt(3, 0).getExplicitSequenceBase());
    return new BasicOCSPResponse(tbsResponseData, signatureAlgorithm, signature, certs);
  }

  public ResponseData getTbsResponseData() {
    return tbsResponseData;
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  public Asn1BitString getSignature() {
    return signature;
  }

  public Certificate.Seq0 getCerts() {
    return certs;
  }

  public byte[] signature() {
    return signature.getAlignedOctets();
  }

  public ResponderID getResponderID() {
    return tbsResponseData.getResponderID();
  }

  public SingleResponse.Seq0 getResponses() {
    return tbsResponseData.getResponses();
  }

  public Instant producedAt() {
    return tbsResponseData.producedAt();
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return tbsResponseData.getExtension(extensionId);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(tbsResponseData, signatureAlgorithm, signature,
        certs == null ? null : Asn1TaggedObject.newExplicit(0, certs));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    tbsResponseData.toStringWithLineSep(buf, indentLevel, "tbsResponseData", true);
    signatureAlgorithm.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    signature.toStringWithLineSep(buf, indentLevel, "signature", true);

    if (certs != null) {
      certs.toStringWithLineSep(buf, indentLevel, "certs", true);
    }

    return deleteLastNewLine(buf);
  }

  public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
      throws SignatureException {
    ContentVerifier verifier;
    try {
      verifier = verifierProvider.get(signatureAlgorithm);
    } catch (GenerationException e) {
      throw new SignatureException(e.getMessage(), e);
    }
    return verifier.atomicVerify(tbsResponseData.getEncoded(), signature.getAlignedOctets());
  }

}
