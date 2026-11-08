// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * ISIS-MTT PROFILE:
 * <p>
 * The responder may include this extension in a response to send the hash of
 * the requested certificate to the responder. This hash is cryptographically
 * bound to the certificate and serves as evidence that the certificate is
 * known to the responder (i.e. it has been issued and is present in the
 * directory).
 *
 * Hence, this extension is a means to provide a positive statement of
 * availability as described in T8.[8]. As explained in T13.[1], clients may
 * rely on this information to be able to validate signatures after the expiry
 * of the corresponding certificate. Hence, clients MUST support this
 * extension. If a positive statement of availability is to be delivered, this
 * extension syntax and OID MUST be used.
 *
 * <pre>
 * CertHash ::= SEQUENCE {
 *     hashAlgorithm    AlgorithmIdentifier,
 *     certificateHash  OCTET STRING
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertHash extends Asn1Encodable {

  private final AlgorithmIdentifier hashAlgorithm;
  private final Asn1OctetString certificateHash;

  public static CertHash fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertHash fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier hashAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1OctetString certificateHash = seq.getOctetStringAt(1);
    return new CertHash(hashAlgorithm, certificateHash);
  }

  public CertHash(AlgorithmIdentifier hashAlgorithm, byte[] certificateHash) {
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.certificateHash = new Asn1OctetString(Args.notEmpty(certificateHash, "certificateHash"));
  }

  public CertHash(AlgorithmIdentifier hashAlgorithm, Asn1OctetString certificateHash) {
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.certificateHash = Args.notNull(certificateHash, "certificateHash");
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public Asn1OctetString getCertificateHash() {
    return certificateHash;
  }

  public byte[] certificateHash() {
    return certificateHash.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(hashAlgorithm, certificateHash);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    hashAlgorithm.toStringWithLineSep(buf, indentLevel, "hashAlgorithm", true);
    certificateHash.toStringWithLineSep(buf, indentLevel, "certificateHash", true);

    return deleteLastNewLine(buf);
  }

}
