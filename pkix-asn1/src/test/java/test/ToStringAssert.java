// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;

/**
 * Checks of {@link Asn1Encodable#toString()}.
 *
 * @author Lijun Liao (xipki)
 */
class ToStringAssert {

  private ToStringAssert() {
  }

  /**
   * Asserts that the object can be printed, and is not printed as the generic dump of
   * {@link Asn1Encodable#toAsn1Primitive()}.
   * @param name the name in the assertion messages.
   * @param obj the object.
   * @return the text.
   */
  static String assertPrintable(String name, Asn1Encodable obj) {
    String text;
    try {
      text = obj.toString();
    } catch (RuntimeException e) {
      throw new AssertionError(name + ": toString() failed: " + e, e);
    }

    Assert.assertFalse(name + ": empty toString()", text.trim().isEmpty());

    // only the classes of asn1 and of org.xipki.codec.asn1.crypto (codec)
    // are checked, no ASN.1 primitives.
    boolean inScope = Certificate.class.getProtectionDomain().getCodeSource()
        .equals(obj.getClass().getProtectionDomain().getCodeSource())
        || obj.getClass().getName().startsWith("org.xipki.codec.asn1.crypto.");
    if (obj instanceof Asn1Primitive || !inScope) {
      return text;
    }

    String generic = obj.toAsn1Primitive().toString(new StringBuilder(), 0).toString();
    String own = obj.toString(new StringBuilder(), 0).toString();
    Assert.assertNotEquals(name + ": printed as generic ASN.1 dump", generic, own);
    return text;
  }

  /**
   * Asserts that the text of the object contains each of the given field names.
   * @param name the name in the assertion messages.
   * @param obj the object.
   * @param fieldNames the expected field names.
   */
  static void assertFields(String name, Asn1Encodable obj, String... fieldNames) {
    String text = assertPrintable(name, obj);
    for (String fieldName : fieldNames) {
      Assert.assertTrue(name + ": missing field '" + fieldName + "' in\n" + text,
          text.contains(fieldName + ":"));
    }
  }

}
