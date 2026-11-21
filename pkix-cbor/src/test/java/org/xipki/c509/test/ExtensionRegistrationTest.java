// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509NullExtnValue;
import org.xipki.c509.ext.C509RawExtnValue;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * Tests the registration of extension value classes outside the package org.xipki.c509.ext.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtensionRegistrationTest {

  private static final long CUSTOM_ID = 990001;

  private static final long NULLABLE_ID = 990002;

  private static final long ALWAYS_NULL_ID = 990003;

  private static final long UNREGISTERED_ID = 990004;

  /** A custom extension value: an integer. */
  public static final class CustomValue extends C509ExtnValue {

    private final long number;

    public CustomValue(long number) {
      this.number = number;
    }

    public long number() {
      return number;
    }

    public static CustomValue read(CborDecoder in) throws CodecException {
      return new CustomValue(in.readLong());
    }

    @Override
    protected void writeTo(CborEncoder out) throws CodecException {
      out.writeLong(number);
    }

    @Override
    protected void render(C509TextTree out) {
      out.line(Long.toString(number));
    }

    @Override
    public String label() {
      return "Custom";
    }

  }

  static {
    ConstExtensionId.register(CUSTOM_ID, "customExtn");
    C509Extension.register(CustomValue.class, CustomValue::read, CUSTOM_ID);
    C509Extension.registerNullable(CustomValue.class, CustomValue::read, NULLABLE_ID);
    C509Extension.registerAlwaysNull(ALWAYS_NULL_ID);
  }

  private static C509Extension roundTrip(C509Extension extn) throws CodecException {
    return C509Cbor.parse(extn.getEncoded(), C509Extension::read);
  }

  @Test
  public void registeredIdDecodesToItsClass() throws Exception {
    C509Extension decoded = roundTrip(C509Extension.critical(CUSTOM_ID, new CustomValue(42)));
    Assert.assertTrue(decoded.isCritical());
    Assert.assertEquals(42, decoded.value(CustomValue.class).number());
    Assert.assertEquals("customExtn", ConstExtensionId.name(CUSTOM_ID));
  }

  @Test
  public void nullableId() throws Exception {
    Assert.assertEquals(7, roundTrip(C509Extension.nonCritical(NULLABLE_ID, new CustomValue(7)))
        .value(CustomValue.class).number());
    Assert.assertSame(C509NullExtnValue.INSTANCE,
        roundTrip(C509Extension.nonCritical(NULLABLE_ID, C509NullExtnValue.INSTANCE)).value());
  }

  @Test
  public void alwaysNullId() throws Exception {
    Assert.assertSame(C509NullExtnValue.INSTANCE,
        roundTrip(C509Extension.nonCritical(ALWAYS_NULL_ID, C509NullExtnValue.INSTANCE)).value());
    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509Extension.nonCritical(ALWAYS_NULL_ID, new CustomValue(1)));
  }

  @Test
  public void unregisteredIdDecodesToRaw() throws Exception {
    C509Extension decoded = roundTrip(C509Extension.nonCritical(UNREGISTERED_ID,
        new CustomValue(1)));
    Assert.assertEquals(C509RawExtnValue.class, decoded.value().getClass());
  }

  @Test
  public void invalidRegistrationsAreRejected() {
    Assert.assertThrows(IllegalStateException.class,
        () -> C509Extension.register(CustomValue.class, CustomValue::read, CUSTOM_ID));
    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509Extension.register(CustomValue.class, CustomValue::read, 0));
    // built-in ID: none of the given IDs is registered
    Assert.assertThrows(IllegalStateException.class,
        () -> C509Extension.register(CustomValue.class, CustomValue::read,
            990005, ConstExtensionId.keyUsage));
    C509Extension.register(CustomValue.class, CustomValue::read, 990005);
  }

}
