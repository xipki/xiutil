// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * Tests the registration of general name value classes outside the package org.xipki.c509.name.
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralNameRegistrationTest {

  private static final int CUSTOM_TAG = 900;

  private static final int UNREGISTERED_TAG = 901;

  /** A custom general name value: [ text, int ]. */
  public static final class CustomValue extends C509CborItem {

    private final String text;

    private final long number;

    public CustomValue(String text, long number) {
      this.text = text;
      this.number = number;
    }

    public String text() {
      return text;
    }

    public long number() {
      return number;
    }

    public static CustomValue read(CborDecoder in) throws CodecException {
      in.readArrayLength(2);
      return new CustomValue(in.readTextString(), in.readLong());
    }

    @Override
    protected void writeTo(CborEncoder out) throws CodecException {
      out.writeArrayStart(2);
      out.writeTextString(text);
      out.writeLong(number);
    }

    @Override
    protected void render(C509TextTree out) {
      out.kv("text", text).kv("number", number);
    }

  }

  static {
    ConstGeneralNameTag.register(CUSTOM_TAG, "customName");
    C509GeneralName.register(CustomValue.class, CustomValue::read, CUSTOM_TAG);
  }

  private static C509GeneralName roundTrip(C509GeneralName name) throws CodecException {
    return C509Cbor.parse(name.getEncoded(), C509GeneralName::read);
  }

  @Test
  public void registeredTagDecodesToItsClass() throws Exception {
    C509GeneralName decoded = roundTrip(C509GeneralName.of(CUSTOM_TAG, new CustomValue("a", 5)));
    Assert.assertEquals(CUSTOM_TAG, decoded.tag());
    CustomValue v = decoded.custom(CustomValue.class);
    Assert.assertEquals("a", v.text());
    Assert.assertEquals(5, v.number());
    Assert.assertNull(decoded.raw());
    Assert.assertFalse(decoded.toString().isEmpty());
  }

  @Test
  public void rawValueOfRegisteredTagIsConverted() throws Exception {
    CborEncodedItem raw = CborEncodedItem.getInstance(new CustomValue("b", 6).getEncoded());
    C509GeneralName name = C509GeneralName.raw(CUSTOM_TAG, raw);
    Assert.assertEquals("b", name.custom(CustomValue.class).text());
    Assert.assertEquals(name, C509GeneralName.of(CUSTOM_TAG, new CustomValue("b", 6)));

    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509GeneralName.raw(CUSTOM_TAG, CborEncodedItem.ofData("not an array")));
  }

  @Test
  public void unregisteredTagStaysRaw() throws Exception {
    C509GeneralName name = C509GeneralName.raw(UNREGISTERED_TAG, CborEncodedItem.ofData("x"));
    C509GeneralName decoded = roundTrip(name);
    Assert.assertNotNull(decoded.raw());
    Assert.assertNull(decoded.custom());
    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509GeneralName.of(UNREGISTERED_TAG, new CustomValue("c", 1)));
  }

  @Test
  public void invalidRegistrationsAreRejected() {
    Assert.assertThrows(IllegalStateException.class,
        () -> C509GeneralName.register(CustomValue.class, CustomValue::read, CUSTOM_TAG));
    // tag with a dedicated shape: none of the given tags is registered
    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509GeneralName.register(CustomValue.class, CustomValue::read,
            902, ConstGeneralNameTag.dNSName));
    C509GeneralName.register(CustomValue.class, CustomValue::read, 902);
  }

}
