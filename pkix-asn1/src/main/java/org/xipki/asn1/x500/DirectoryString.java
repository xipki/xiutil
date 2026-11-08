// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x500;

import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.Asn1BmpString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Currently only printableString and utf8String are supported.
 *
 * <pre>
 * DirectoryString ::= CHOICE {
 *     teletexString    TeletexString (SIZE (1..MAX)),
 *     printableString  PrintableString (SIZE (1..MAX)),
 *     universalString  UniversalString (SIZE (1..MAX)),
 *     utf8String       UTF8String (SIZE (1..MAX)),
 *     bmpString        BMPString (SIZE (1..MAX)) }
 * </pre>
 * Wo do not support teletexString and universalString since it is not used
 * in the target environment PKIX.
 *
 * @author Lijun Liao (xipki)
 */
public class DirectoryString extends Asn1Encodable {

  private final AbstractAsn1String string;

  public static DirectoryString fromAsn1(Asn1Primitive asn1) throws CodecException {
    if (asn1 instanceof Asn1PrintableString) {
      return new DirectoryString((Asn1PrintableString) asn1);
    } else if (asn1 instanceof Asn1Utf8String) {
      return new DirectoryString((Asn1Utf8String) asn1);
    } else if (asn1 instanceof Asn1BmpString) {
      return new DirectoryString((Asn1BmpString) asn1);
    } else {
      throw new CodecException("unsupported ASN.1 type");
    }
  }

  public DirectoryString(Asn1PrintableString string) {
    this.string = Args.notNull(string, "string");
  }

  public DirectoryString(Asn1Utf8String string) {
    this.string = Args.notNull(string, "string");
  }

  public DirectoryString(Asn1BmpString string) {
    this.string = Args.notNull(string, "string");
  }

  public DirectoryString(String string) {
    this.string = new Asn1Utf8String(Args.notNull(string, "string"));
  }

  public AbstractAsn1String getString() {
    return string;
  }

  public String string() {
    return string.getString();
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return string;
  }

  @Override
  public int hashCode() {
    return string.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof DirectoryString)) {
      return false;
    }

    DirectoryString b = (DirectoryString) obj;
    return string.equals(b.string);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return string.toString(buf, indentLevel);
  }

}
