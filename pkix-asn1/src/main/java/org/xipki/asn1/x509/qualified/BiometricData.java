// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The BiometricData object.
 * <pre>
 * BiometricData  ::=  SEQUENCE {
 *       typeOfBiometricData  TypeOfBiometricData,
 *       hashAlgorithm        AlgorithmIdentifier,
 *       biometricDataHash    OCTET STRING,
 *       sourceDataUri        IA5String OPTIONAL  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class BiometricData extends Asn1Encodable {

  /**
   * SEQUENCE OF BiometricData
   */
  public static class Seq0 extends AbstractSeq0<BiometricData> {

    public Seq0(BiometricData... entries) {
      super(entries);
    }

    public Seq0(List<BiometricData> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected BiometricData newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return BiometricData.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final TypeOfBiometricData typeOfBiometricData;
  private final AlgorithmIdentifier hashAlgorithm;
  private final Asn1OctetString biometricDataHash;
  private final Asn1IA5String sourceDataUri;

  public static BiometricData fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static BiometricData fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 4);
    // typeOfBiometricData
    TypeOfBiometricData typeOfBiometricData = TypeOfBiometricData.fromAsn1(seq.getObjectAt(0));
    // hashAlgorithm
    AlgorithmIdentifier hashAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    // biometricDataHash
    Asn1OctetString biometricDataHash = seq.getOctetStringAt(2);

    int index = 3;
    // sourceDataUri
    Asn1IA5String sourceDataUri = seq.notHasIA5String(index) ? null : seq.getIA5StringAt(index++);
    Asn1Util.checkSequenceEnd(index, size);

    return new BiometricData(typeOfBiometricData, hashAlgorithm, biometricDataHash, sourceDataUri);
  }

  public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm,
                       Asn1OctetString biometricDataHash, Asn1IA5String sourceDataUri) {
    this.typeOfBiometricData = Args.notNull(typeOfBiometricData, "typeOfBiometricData");
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.biometricDataHash = Args.notNull(biometricDataHash, "biometricDataHash");
    this.sourceDataUri = sourceDataUri;
  }

  public BiometricData(TypeOfBiometricData typeOfBiometricData,
                       AlgorithmIdentifier hashAlgorithm, Asn1OctetString biometricDataHash) {
    this(typeOfBiometricData, hashAlgorithm, biometricDataHash, null);
  }

  public TypeOfBiometricData getTypeOfBiometricData() {
    return typeOfBiometricData;
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public Asn1OctetString getBiometricDataHash() {
    return biometricDataHash;
  }

  public Asn1IA5String getSourceDataUriIA5() {
    return sourceDataUri;
  }

  public byte[] biometricDataHash() {
    return biometricDataHash.getOctets();
  }

  public String sourceDataUriIA5() {
    return Asn1Util.fromAsn1(sourceDataUri);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(typeOfBiometricData, hashAlgorithm,
        biometricDataHash, sourceDataUri);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    typeOfBiometricData.toStringNoLineSep(buf, indentLevel, "typeOfBiometricData", true);
    hashAlgorithm.toStringWithLineSep(buf, indentLevel, "hashAlgorithm", true);
    biometricDataHash.toStringWithLineSep(buf, indentLevel, "biometricDataHash", true);
    if (sourceDataUri != null) {
      sourceDataUri.toStringNoLineSep(buf, indentLevel, "sourceDataUri", true);
    }
    return deleteLastNewLine(buf);
  }
}
