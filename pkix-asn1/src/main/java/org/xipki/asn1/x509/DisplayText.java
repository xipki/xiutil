
package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.Asn1BmpString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1VisibleString;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <code>DisplayText</code> class, used in
 * <code>CertificatePolicies</code> X509 V3 extensions (in policy qualifiers).
 *
 * <p>It stores a string in a chosen encoding.
 * <pre>
 * DisplayText ::= CHOICE {
 *      ia5String        IA5String      (SIZE (1..200)),
 *      visibleString    VisibleString  (SIZE (1..200)),
 *      bmpString        BMPString      (SIZE (1..200)),
 *      utf8String       UTF8String     (SIZE (1..200)) }
 * </pre>
 * RFC 6818 (updating RFC 5280) for the explicitText: conforming CAs SHOULD use the UTF8String;
 * the VisibleString and the BMPString are acceptable; the IA5String MUST NOT be used.
 *
 * @author Lijun Liao (xipki)
 */
public class DisplayText extends Asn1Encodable {

  public enum ContentType {
    IA5String,
    VisibleString,
    BMPString,
    UTF8String
  }

  private final AbstractAsn1String content;

  private DisplayText(AbstractAsn1String content) {
    this.content = Args.notNull(content, "content");
  }

  public DisplayText(ContentType type, String text) {
    Args.notNull(type, "type");
    Args.notNull(text, "text");
    Args.max(text.length(), "text length", 200);

    if (type == ContentType.IA5String) {
      content = new Asn1IA5String(text);
    } else if (type == ContentType.UTF8String) {
      content = new Asn1Utf8String(text);
    } else if (type == ContentType.VisibleString) {
      content = new Asn1VisibleString(text);
    } else {
      // case BMPString:
      content = new Asn1BmpString(text);
    }
  }

  public DisplayText(String text) {
    this(ContentType.UTF8String, text);
  }

  public static DisplayText fromAsn1(AbstractAsn1String text) {
    Args.notNull(text, "text");
    if (text instanceof Asn1IA5String
        || text instanceof Asn1VisibleString
        || text instanceof Asn1Utf8String
        || text instanceof Asn1BmpString) {
      return new DisplayText(text);
    } else {
      throw new IllegalArgumentException("unknown STRING type in DisplayText");
    }
  }

  public static DisplayText getInstance(Asn1TaggedObject obj, boolean explicit)
      throws CodecException {
    if (!explicit) {
      throw new IllegalArgumentException("choice item must be explicitly tagged");
    }

    Asn1Primitive base = obj.getExplicitBase();
    if (!(base instanceof AbstractAsn1String)) {
      throw new CodecException("DisplayText is not a supported string type");
    }
    return DisplayText.fromAsn1((AbstractAsn1String) base);
  }

  public AbstractAsn1String getString() {
    return content;
  }

  public String string() {
    return content.getString();
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return content;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return content.toString(buf, indentLevel);
  }

}
