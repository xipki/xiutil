// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 2315 (PKCS#7):
 * <pre>
 *  SignerInfo ::= SEQUENCE {
 *      version Version,
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
 *  }
 *
 *  Attributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *  EncryptedDigest ::= OCTET STRING
 *
 *  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 *  DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * </pre>
 * <a href="https://tools.ietf.org/html/rfc5652#section-5.3">RFC 5652</a>:
 * Signature container per Signer, see {@link SignerIdentifier}.
 * <pre>
 * SignerInfo ::= SEQUENCE {
 *     version            CMSVersion,
 *     sid                SignerIdentifier,
 *     digestAlgorithm    DigestAlgorithmIdentifier,
 *     signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
 *     signatureAlgorithm SignatureAlgorithmIdentifier,
 *     signature          SignatureValue,
 *     unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL
 * }
 *
 * -- {@link SignerIdentifier} referenced certificates are at containing
 * -- {@link SignedData} certificates element.
 *
 * SignerIdentifier ::= CHOICE {
 *     issuerAndSerialNumber {@link IssuerAndSerialNumber},
 *     subjectKeyIdentifier  [0] SubjectKeyIdentifier }
 *
 * SignedAttributes   ::= SET SIZE (1..MAX) OF Attribute
 * UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * Attribute ::= SEQUENCE {
 *     attrType   OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue }
 *
 * AttributeValue ::= ANY
 *
 * SignatureValue ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SignerInfo extends Asn1Encodable {

  public static class Set0 extends AbstractSet0<SignerInfo> {

    public Set0(SignerInfo... entries) {
      super(entries);
    }

    public Set0(List<SignerInfo> entries) {
      super(entries);
    }

    protected Set0(Asn1Set set) throws CodecException {
      super(set);
    }

    public static Set0 fromAsn1(Asn1Set set) throws CodecException {
      return new Set0(set);
    }

    @Override
    protected SignerInfo newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return SignerInfo.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Integer version;
  private final SignerIdentifier sid;
  private final AlgorithmIdentifier digestAlgorithm;
  private final Attributes signedAttributes;
  private final AlgorithmIdentifier signatureAlgorithm;
  private final Asn1OctetString signature;
  private final Attributes unsignedAttributes;

  public SignerInfo(SignerIdentifier sid, AlgorithmIdentifier digestAlgorithm,
                    Attributes signedAttributes, AlgorithmIdentifier signatureAlgorithm,
                    Asn1OctetString signature, Attributes unsignedAttributes) {
    this((Args.notNull(sid, "sid").getSubjectKeyIdentifier() != null)
        ? Asn1Integer.THREE : Asn1Integer.ONE,
      sid, digestAlgorithm, signedAttributes, signatureAlgorithm, signature, unsignedAttributes);
  }

  public SignerInfo(Asn1Integer version, SignerIdentifier sid, AlgorithmIdentifier digestAlgorithm,
                    Attributes signedAttributes, AlgorithmIdentifier signatureAlgorithm,
                    Asn1OctetString signature, Attributes unsignedAttributes) {
    this.sid = Args.notNull(sid, "sid");
    this.version = Args.notNull(version, "version");
    this.digestAlgorithm = Args.notNull(digestAlgorithm, "digestAlgorithm");
    this.signedAttributes = signedAttributes;
    this.signatureAlgorithm = Args.notNull(signatureAlgorithm, "signatureAlgorithm");
    this.signature = Args.notNull(signature, "signature");
    this.unsignedAttributes = unsignedAttributes;
  }

  public static SignerInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 5, 7);

    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    SignerIdentifier sid = SignerIdentifier.fromAsn1(seq.getObjectAt(1));
    AlgorithmIdentifier digestAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(2));

    //  *     signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
    // *     signatureAlgorithm SignatureAlgorithmIdentifier,
    // *     signature          SignatureValue,
    // *     unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL
    int index = 3;
    Attributes signedAttributes = seq.isNotTaggedAt(index, 0) ? null
        : Attributes.fromAsn1(seq.getSetTaggedAt(index++, false));
    AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.fromSequenceElement(seq, index++);
    Asn1OctetString signature = seq.getOctetStringAt(index++);
    Attributes unsignedAttributes = seq.isNotTaggedAt(index, 1) ? null
        : Attributes.fromAsn1(seq.getSetTaggedAt(index++, false));
    Asn1Util.checkSequenceEnd(index, size);

    return new SignerInfo(version, sid, digestAlgorithm, signedAttributes,
        signatureAlgorithm, signature, unsignedAttributes);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public SignerIdentifier getSID() {
    return sid;
  }

  public IssuerAndSerialNumber getIssuerAndSerialNumber() {
    return sid.getIssuerAndSerialNumber();
  }

  public Asn1OctetString getSubjectKeyIdentifier() {
    return sid.getSubjectKeyIdentifier();
  }

  public Attributes getSignedAttributes() {
    return signedAttributes;
  }

  @Deprecated
  public Attributes getAuthenticatedAttributes() {
    return signedAttributes;
  }

  public AlgorithmIdentifier getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public Asn1OctetString getSignature() {
    return signature;
  }

  @Deprecated
  public Asn1OctetString getEncryptedDigest() {
    return signature;
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  @Deprecated
  public AlgorithmIdentifier getDigestEncryptionAlgorithm() {
    return signatureAlgorithm;
  }

  public Attributes getUnsignedAttributes() {
    return unsignedAttributes;
  }

  @Deprecated
  public Attribute.Set1 getUnauthenticatedAttributes() {
    return unsignedAttributes;
  }

  public int version() {
    return version.intValueExact();
  }

  public byte[] subjectKeyIdentifier() {
    return sid.subjectKeyIdentifier();
  }

  public byte[] signature() {
    return signature.getOctets();
  }

  /**
   * Produce an object suitable for an ASN1OutputStream.
   */
  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, sid, digestAlgorithm,
        (signedAttributes == null) ? null : Asn1TaggedObject.newImplicit(0, signedAttributes),
        signatureAlgorithm, signature,
        (unsignedAttributes == null) ? null : Asn1TaggedObject.newImplicit(1, unsignedAttributes));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    sid.toStringWithLineSep(buf, indentLevel, "sid", true);
    digestAlgorithm.toStringWithLineSep(buf, indentLevel, "digestAlgorithm", true);

    if (signedAttributes != null) {
      signedAttributes.toStringWithLineSep(buf, indentLevel, "signedAttributes", true);
    }

    signatureAlgorithm.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    signature.toStringWithLineSep(buf, indentLevel, "signature", true);

    if (unsignedAttributes != null) {
      unsignedAttributes.toStringWithLineSep(buf, indentLevel, "unsignedAttributes", true);
    }

    return deleteLastNewLine(buf);
  }
}
