// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.attr.C509AttrValue;
import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509RawAttrValue;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * Tests the registration of attribute value classes outside the package org.xipki.c509.attr.
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeRegistrationTest {

  private static final long CUSTOM_TYPE = 990001;

  private static final long UNREGISTERED_TYPE = 990002;

  /** A custom attribute value: a text string. */
  public static final class CustomValue extends C509AttrValue {

    private final String text;

    public CustomValue(String text) {
      this.text = text;
    }

    public String text() {
      return text;
    }

    public static CustomValue read(CborDecoder in) throws CodecException {
      return new CustomValue(in.readTextString());
    }

    @Override
    protected void writeTo(CborEncoder out) throws CodecException {
      out.writeTextString(text);
    }

    @Override
    protected void render(C509TextTree out) {
      out.line(text);
    }

    @Override
    public String label() {
      return "Custom";
    }

  }

  static {
    ConstAttributeType.register(CUSTOM_TYPE, "customAttr");
    C509Attribute.register(CustomValue.class, CustomValue::read, CUSTOM_TYPE);
  }

  @Test
  public void registeredTypeDecodesToItsClass() throws Exception {
    byte[] encoded = new C509Attribute(CUSTOM_TYPE, new CustomValue("hello")).getEncoded();
    C509Attribute decoded = C509Cbor.parse(encoded, C509Attribute::read);
    Assert.assertEquals("hello", decoded.value(CustomValue.class).text());
    Assert.assertEquals("customAttr", ConstAttributeType.name(CUSTOM_TYPE));
  }

  @Test
  public void foreignValueIsConvertedToRegisteredClass() throws Exception {
    byte[] encoded = new C509Attribute(CUSTOM_TYPE, new CustomValue("x")).value().getEncoded();
    C509RawAttrValue raw = C509Cbor.parse(encoded, C509RawAttrValue::read);
    C509Attribute attr = new C509Attribute(CUSTOM_TYPE, raw);
    Assert.assertEquals(CustomValue.class, attr.value().getClass());
  }

  @Test
  public void unregisteredTypeDecodesToRaw() throws Exception {
    byte[] encoded = new C509Attribute(UNREGISTERED_TYPE, new CustomValue("raw")).getEncoded();
    C509Attribute decoded = C509Cbor.parse(encoded, C509Attribute::read);
    Assert.assertEquals(C509RawAttrValue.class, decoded.value().getClass());
  }

  @Test
  public void duplicateRegistrationIsRejected() {
    Assert.assertThrows(IllegalStateException.class,
        () -> C509Attribute.register(CustomValue.class, CustomValue::read, CUSTOM_TYPE));
    // built-in type: none of the given types is registered
    Assert.assertThrows(IllegalStateException.class,
        () -> C509Attribute.register(CustomValue.class, CustomValue::read,
            990003, ConstAttributeType.gender));
    C509Attribute.register(CustomValue.class, CustomValue::read, 990003);
  }

}
