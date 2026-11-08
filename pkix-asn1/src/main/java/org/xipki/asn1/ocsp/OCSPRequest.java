// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.SignatureException;
import java.util.List;

/**
 * <pre>
 * OCSPRequest     ::=     SEQUENCE {
 *     tbsRequest              TBSRequest,
 *     optionalSignature   [0] EXPLICIT Signature OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OCSPRequest extends Asn1Encodable {

  private final TBSRequest tbsRequest;
  private final Signature optionalSignature;

  public OCSPRequest(TBSRequest tbsRequest, Signature optionalSignature) {
    this.tbsRequest = Args.notNull(tbsRequest, "tbsRequest");
    this.optionalSignature = optionalSignature;
  }

  public static OCSPRequest fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static OCSPRequest fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    TBSRequest tbsRequest = TBSRequest.fromAsn1(seq.getSequenceAt(0));
    Signature optionalSignature = (size == 1) ? null
        : Signature.fromAsn1(seq.getTaggedAt(1, 0).getExplicitSequenceBase());
    return new OCSPRequest(tbsRequest, optionalSignature);
  }

  public TBSRequest getTbsRequest() {
    return tbsRequest;
  }

  public Signature getOptionalSignature() {
    return optionalSignature;
  }

  public List<Certificate> getCertificates() {
    if (optionalSignature != null) {
      Certificate.Seq0 seq0 = optionalSignature.getCerts();
      return seq0 == null ? null : seq0.getEntries();
    }
    return null;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(tbsRequest,
        (optionalSignature == null ? null
            : Asn1TaggedObject.newExplicit(0, optionalSignature)));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    tbsRequest.toStringWithLineSep(buf, indentLevel, "tbsRequest", true);

    if (optionalSignature != null) {
      optionalSignature.toStringWithLineSep(buf, indentLevel, "optionalSignature", true);
    }

    return deleteLastNewLine(buf);
  }

  public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
      throws SignatureException {
    if (optionalSignature == null) {
      throw new SignatureException("attempt to verify signature on unsigned object");
    }

    ContentVerifier verifier;
    try {
      verifier = verifierProvider.get(optionalSignature.getSignatureAlgorithm());
    } catch (GenerationException e) {
      throw new SignatureException(e.getMessage(), e);
    }
    return verifier.atomicVerify(tbsRequest.getEncoded(), optionalSignature.signature());
  }

}
