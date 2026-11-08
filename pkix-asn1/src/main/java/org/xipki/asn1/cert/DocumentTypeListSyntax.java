// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.cert;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.PrintableStringSet;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * MRTD:
 * <pre>
 * DocumentTypeList EXTENSION ::= {
 *     SYNTAX     DocumentTypeListSyntax
 *     IDENTIFIED BY id-icao-mrtd-security-extensions-documentTypeList }
 *
 * DocumentTypeListSyntax ::= SEQUENCE {
 *     version     DocumentTypeListVersion,
 *     docTypeList SET OF DocumentType }
 *
 * DocumentTypeListVersion ::= INTEGER {v0(0)}
 * -- Document Type as contained in MRZ, e.g. “P” or “ID” where a
 * -- single letter denotes all document types starting with that letter
 *
 * DocumentType ::= PrintableString(SIZE(1..2))
 *
 * id-icao-mrtd-security-extensions-documentTypeList OBJECT
 *     IDENTIFIER ::= {id-icao-mrtd-security-extensions 2}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class DocumentTypeListSyntax extends Asn1Encodable {

  private final PrintableStringSet docTypeList;

  public DocumentTypeListSyntax(PrintableStringSet docTypeList) {
    this.docTypeList = Args.notNull(docTypeList, "docTypeList");
    Args.min(docTypeList.size(), "docTypeList.size", 1);
  }

  public DocumentTypeListSyntax(List<String> docTypeList) {
    Args.notNull(docTypeList, "docTypeList");
    for (String m : docTypeList) {
      if (m == null || (m.length() != 1 && m.length() != 2)) {
        throw new IllegalArgumentException("invalid docType '" + m + "'");
      }
    }

    this.docTypeList = new PrintableStringSet(0, docTypeList.toArray(new String[0]));
  }

  public static DocumentTypeListSyntax fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    if (!version.hasValue(0)) {
      throw new IllegalArgumentException("invalid version " + version);
    }
    PrintableStringSet docTypeList = new PrintableStringSet(1, seq.getSetAt(1));
    return new DocumentTypeListSyntax(docTypeList);
  }

  public PrintableStringSet docTypeList() {
    return docTypeList;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(Asn1Integer.ZERO, docTypeList);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    Asn1Integer.ZERO.toStringNoLineSep(buf, indentLevel, "version", true);
    return docTypeList.toStringWithLineSep(buf, indentLevel, "docTypeList", false);
  }
}
