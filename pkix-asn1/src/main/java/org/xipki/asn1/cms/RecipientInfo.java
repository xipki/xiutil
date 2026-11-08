// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSet0;
import org.xipki.codec.asn1.AbstractSet1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * RecipientInfo ::= CHOICE {
 *     ktri      KeyTransRecipientInfo,
 *     kari  [1] KeyAgreeRecipientInfo,
 *     kekri [2] KEKRecipientInfo,
 *     pwri  [3] PasswordRecipientInfo,
 *     ori   [4] OtherRecipientInfo }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RecipientInfo extends Asn1Encodable {

  public static class Set1 extends AbstractSet1<RecipientInfo> {

    public Set1(RecipientInfo... entries) {
      super(entries);
    }

    public Set1(List<RecipientInfo> entries) {
      super(entries);
    }

    protected Set1(Asn1Set set) throws CodecException {
      super(set);
    }

    public static Set1 fromAsn1(Asn1Set set) throws CodecException {
      return new Set1(set);
    }

    @Override
    protected RecipientInfo newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return RecipientInfo.fromAsn1(coll.getObjectAt(index));
    }
  }

  public static class Set0 extends AbstractSet0<RecipientInfo> {

    public Set0(RecipientInfo... entries) {
      super(entries);
    }

    public Set0(List<RecipientInfo> entries) {
      super(entries);
    }

    private Set0(Asn1Set set) throws CodecException {
      super(set);
    }

    public static Set0 fromAsn1(Asn1Set set) throws CodecException {
      return new Set0(set);
    }

    @Override
    protected RecipientInfo newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return RecipientInfo.fromAsn1(coll.getObjectAt(index));
    }
  }

  private final KeyTransRecipientInfo ktri;

  private final KeyAgreeRecipientInfo kari;

  private final KEKRecipientInfo kekri;

  private final PasswordRecipientInfo pwri;

  private final OtherRecipientInfo ori;

  private RecipientInfo(KeyTransRecipientInfo ktri, KeyAgreeRecipientInfo kari,
                        KEKRecipientInfo kekri, PasswordRecipientInfo pwri,
                        OtherRecipientInfo ori) {
    this.ktri = ktri;
    this.kari = kari;
    this.kekri = kekri;
    this.pwri = pwri;
    this.ori = ori;
  }

  public static RecipientInfo ofKtri(KeyTransRecipientInfo ktri) {
    return new RecipientInfo(Args.notNull(ktri, "ktri"), null, null, null, null);
  }

  public static RecipientInfo ofKari(KeyAgreeRecipientInfo kari) {
    return new RecipientInfo(null, Args.notNull(kari, "kari"), null, null, null);
  }

  public static RecipientInfo ofKekri(KEKRecipientInfo kekri) {
    return new RecipientInfo(null, null, Args.notNull(kekri, "kekri"), null, null);
  }

  public static RecipientInfo ofPwri(PasswordRecipientInfo pwri) {
    return new RecipientInfo(null, null, null, Args.notNull(pwri, "pwri"), null);
  }

  public static RecipientInfo ofOri(OtherRecipientInfo ori) {
    return new RecipientInfo(null, null, null, null, Args.notNull(ori, "ori"));
  }

  public Asn1Integer getVersion() {
    return ktri != null ? ktri.getVersion()
        : kari  != null ? kari.getVersion()
        : kekri != null ? kekri.getVersion()
        : pwri  != null ? pwri.getVersion() : null;
  }

  public boolean hasKtri() {
    return ktri != null;
  }

  public boolean hasKari() {
    return kari != null;
  }

  public boolean hasKetri() {
    return kekri != null;
  }

  public boolean hasPwri() {
    return pwri != null;
  }

  public boolean hasOri() {
    return ori != null;
  }

  public static RecipientInfo fromAsn1(Asn1Primitive asn1) throws CodecException {
    if (asn1 instanceof Asn1Sequence) {
      return ofKtri(KeyTransRecipientInfo.fromAsn1((Asn1Sequence) asn1));
    } else if (asn1 instanceof Asn1TaggedObject) {
      Asn1TaggedObject t = (Asn1TaggedObject) asn1;
      int tagNo = t.getTagNo();
      if (tagNo == 1) {
        return ofKari(KeyAgreeRecipientInfo.fromAsn1(t.getImplicitSequenceBase()));
      } else if (tagNo == 2) {
        return ofKekri(KEKRecipientInfo.fromAsn1(t.getImplicitSequenceBase()));
      } else if (tagNo == 3) {
        return ofPwri(PasswordRecipientInfo.fromAsn1(t.getImplicitSequenceBase()));
      } else if (tagNo == 4) {
        return ofOri(OtherRecipientInfo.fromAsn1(t.getImplicitSequenceBase()));
      } else {
        throw new CodecException("unknown tag number " + tagNo);
      }
    } else {
      throw new CodecException("unknown asn1 type");
    }
  }

  public KeyTransRecipientInfo getKtri() {
    return ktri;
  }

  public KeyAgreeRecipientInfo getKari() {
    return kari;
  }

  public KEKRecipientInfo getKekri() {
    return kekri;
  }

  public PasswordRecipientInfo getPwri() {
    return pwri;
  }

  public OtherRecipientInfo getOri() {
    return ori;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return ktri != null ? ktri.toAsn1Primitive()
        : kari  != null ? Asn1TaggedObject.newImplicit(1, kari)
        : kekri != null ? Asn1TaggedObject.newImplicit(2, kekri)
        : pwri  != null ? Asn1TaggedObject.newImplicit(3, pwri)
        : Asn1TaggedObject.newImplicit(4, ori);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (ktri != null) {
      return ktri.toStringWithLineSep(buf, indentLevel, "ktri");
    }

    if (kari != null) {
      return kari.toStringWithLineSep(buf, indentLevel, "kari");
    }

    if (kekri != null) {
      return kekri.toStringWithLineSep(buf, indentLevel, "kekri");
    }

    if (pwri != null) {
      return pwri.toStringWithLineSep(buf, indentLevel, "pwri");
    }

    return ori.toStringWithLineSep(buf, indentLevel, "ori");
  }
}
