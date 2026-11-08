
package org.xipki.asn1.x509;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.exception.OperatorException;

import java.math.BigInteger;
import java.security.SignatureException;
import java.time.Instant;
import java.util.List;

/**
 * PKIX RFC-2459
 *
 * The X.509 v2 CRL syntax is as follows.  For signature calculation,
 * the data that is to be signed is ASN.1 DER encoded.
 *
 * <pre>
 * CertificateList  ::=  SEQUENCE  {
 *     tbsCertList          TBSCertList,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateList extends Asn1Encodable {

  /**
   * Produce an X.509 Version 2 CRL.
   */
  public static class V2CRLBuilder {

    private final TBSCertList.V2Generator tbsGen;
    private final Extensions.Generator extGenerator;

    public V2CRLBuilder(X500Name issuer, Instant thisUpdate) {
      tbsGen = new TBSCertList.V2Generator();
      extGenerator = new Extensions.Generator();
      tbsGen.setIssuer(issuer);
      tbsGen.setThisUpdate(thisUpdate);
    }

    public V2CRLBuilder setNextUpdate(Instant date) {
      tbsGen.setNextUpdate(date);
      return this;
    }

    public V2CRLBuilder addCRLEntry(
        BigInteger certSerial, Instant revocationDate, CRLReason reason) throws CodecException {
      tbsGen.addCRLEntry(certSerial, revocationDate, reason);
      return this;
    }

    public V2CRLBuilder addCRLEntry(
        BigInteger certSerial, Instant revocationDate, CRLReason reason, Instant invalidityDate)
        throws CodecException {
      tbsGen.addCRLEntry(certSerial, revocationDate, reason, invalidityDate);
      return this;
    }

    public V2CRLBuilder addCRLEntry(
        BigInteger certSerial, Instant revocationDate, Extensions extensions) {
      tbsGen.addCRLEntry(certSerial, revocationDate, extensions);
      return this;
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

    public V2CRLBuilder addExtension(Extension extension) throws GenerationException {
      extGenerator.addExtension(Args.notNull(extension, "extension"));
      return this;
    }

    public V2CRLBuilder replaceExtension(Extension extension){
      extGenerator.replaceExtension(Args.notNull(extension, "extension"));
      return this;
    }

    public V2CRLBuilder removeExtension(Asn1Oid oid) {
      extGenerator.removeExtension(oid);
      return this;
    }

    public CertificateList build(ContentSigner signer) {
      AlgorithmIdentifier sigAlgID = signer.getAlgorithmIdentifier();
      tbsGen.setSignature(sigAlgID);

      try {
        if (extGenerator.hasExtensions()) {
          tbsGen.setExtensions(extGenerator.build());
        }
        TBSCertList tbsCertList = tbsGen.generateTBSCertList();
        byte[] signature = signer.atomicSign(tbsCertList.getEncoded());
        return new CertificateList(tbsCertList, sigAlgID, new Asn1BitString(signature));
      } catch (SignatureException | CodecException e) {
        throw new IllegalArgumentException("cannot produce CRL signature", e);
      }
    }

  }

  /**
   * SEQUENCE OF CertificateList
   */
  public static class Seq0 extends AbstractSeq0<CertificateList> {

    public Seq0(CertificateList... entries) {
      super(entries);
    }

    public Seq0(List<CertificateList> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected CertificateList newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return CertificateList.fromAsn1(coll.getSequenceAt(index));
    }

  }

  /**
   * SEQUENCE SIZE (1..MAX) OF CertificateList
   */
  public static class Seq1 extends AbstractSeq1<CertificateList> {

    public Seq1(CertificateList... entries) {
      super(entries);
    }

    public Seq1(List<CertificateList> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected CertificateList newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return CertificateList.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final TBSCertList tbsCertList;
  private final AlgorithmIdentifier signatureAlgorithm;
  private final Asn1BitString signatureValue;

  public static CertificateList fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertificateList fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    TBSCertList tbsCertList = TBSCertList.fromAsn1(seq.getSequenceAt(0));
    AlgorithmIdentifier sigAlgId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    Asn1BitString sig = seq.getBitStringAt(2);
    return new CertificateList(tbsCertList, sigAlgId, sig);
  }

  public CertificateList(TBSCertList tbsCertList, AlgorithmIdentifier sigAlgId, Asn1BitString sig) {
    this.tbsCertList = Args.notNull(tbsCertList, "tbsCertList");
    this.signatureAlgorithm = Args.notNull(sigAlgId, "sigAlgId");
    this.signatureValue = Args.notNull(sig, "sig");
  }

  public TBSCertList getTBSCertList() {
    return tbsCertList;
  }

  public List<CRLEntry> getRevokedCertificates() throws CodecException {
    return tbsCertList.getRevokedCertificates();
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  public Asn1BitString getSignature() {
    return signatureValue;
  }

  public Asn1Integer getVersion() {
    return tbsCertList.getVersion();
  }

  public X500Name getIssuer() {
    return tbsCertList.getIssuer();
  }

  public Time getThisUpdate() {
    return tbsCertList.getThisUpdate();
  }

  public Time getNextUpdate() {
    return tbsCertList.getNextUpdate();
  }

  public int version() {
    return tbsCertList.version();
  }

  public Instant thisUpdate() {
    return tbsCertList.thisUpdate();
  }

  public Instant nextUpdate() {
    return tbsCertList.nextUpdate();
  }

  public byte[] signature() {
    return signatureValue.getAlignedOctets();
  }

  public Extensions getExtensions() {
    return tbsCertList.getExtensions();
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return tbsCertList.getExtension(extensionId);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(tbsCertList, signatureAlgorithm, signatureValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    tbsCertList.toStringWithLineSep(buf, indentLevel, "tbsCertList", true);
    signatureAlgorithm.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    signatureValue.toStringWithLineSep(buf, indentLevel, "signatureValue", true);

    return deleteLastNewLine(buf);
  }

  public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
      throws OperatorException {
    try {
      ContentVerifier verifier = verifierProvider.get(tbsCertList.getSignature());
      return verifier.atomicVerify(tbsCertList.getEncoded(), signatureValue.getAlignedOctets());
    } catch (Exception e) {
      throw new OperatorException("unable to process signature: " + e.getMessage(), e);
    }
  }

}
