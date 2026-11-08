// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Utf8StringSeq;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimPermittedValues ::= SEQUENCE {
 *    claim      JWTClaimName,
 *    permitted  SEQUENCE SIZE (1..MAX) OF UTF8String
 * }
 *
 * JWTClaimName ::= IA5String
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimPermittedValues extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<JWTClaimPermittedValues> {

    public Seq1(JWTClaimPermittedValues... entries) {
      super(entries);
    }

    public Seq1(List<JWTClaimPermittedValues> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected JWTClaimPermittedValues newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return JWTClaimPermittedValues.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1IA5String claim;

  private final Utf8StringSeq permitted;

  public static JWTClaimPermittedValues fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1IA5String claim = seq.getIA5StringAt(0);
    Utf8StringSeq permitted = Utf8StringSeq.fromAsn1(1, seq.getSequenceAt(1));
    return new JWTClaimPermittedValues(claim, permitted);
  }

  public JWTClaimPermittedValues(Asn1IA5String claim, Utf8StringSeq permitted) {
    this.claim = Args.notNull(claim, "claim");
    this.permitted = Args.notNull(permitted, "permitted");
  }

  public JWTClaimPermittedValues(String claim, List<String> permitted) {
    this.claim = new Asn1IA5String(Args.notNull(claim, "claim"));
    Args.notEmpty(permitted, "permitted");
    this.permitted = new Utf8StringSeq(1, permitted.toArray(new String[0]));
  }

  public Asn1IA5String getClaim() {
    return claim;
  }

  public Utf8StringSeq getPermitted() {
    return permitted;
  }

  public String claim() {
    return claim.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(claim, permitted);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    claim.toStringNoLineSep(buf, indentLevel, "claim", true);
    permitted.toStringWithLineSep(buf, indentLevel, "permitted", true);

    return deleteLastNewLine(buf);
  }

}
