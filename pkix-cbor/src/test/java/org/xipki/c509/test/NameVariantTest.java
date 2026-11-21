// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.c509.registry.ConstCertificateType;
import org.xipki.codec.Hex;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.exception.CodecException;

/**
 * Tests for {@link C509NameVariant}.
 *
 * @author Lijun Liao (xipki)
 */
public class NameVariantTest {

  // SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "A" } } }
  private static final byte[] DER_NAME = Hex.decode("300c310a300806035504030c0141");

  @Test
  public void x509() throws Exception {
    C509NameVariant v = C509NameVariant.ofX509(DER_NAME);
    Assert.assertEquals("8200" + "4e" + Hex.encode(DER_NAME), Hex.encode(v.getEncoded()));
    C509NameVariant v2 = roundTrip(v);
    Assert.assertArrayEquals(DER_NAME, v2.x509Name());
    Assert.assertNull(v2.c509Name());
  }

  @Test
  public void c509() throws Exception {
    C509Name name = new C509Name("CN=Test");
    C509NameVariant v = roundTrip(C509NameVariant.ofC509(name));
    Assert.assertEquals(ConstCertificateType.c509, v.type());
    Assert.assertEquals(name, v.c509Name());
    Assert.assertNull(v.x509Name());
  }

  @Test
  public void otherType() throws Exception {
    C509NameVariant v = roundTrip(C509NameVariant.of(5, "text"));
    Assert.assertEquals(5, v.type());
    Assert.assertEquals("text", v.raw().data());
    Assert.assertSame(v.raw(), v.value());

    // {2: "b", 1: "a"}: original encoding kept
    String hex = "8205a2026162016161";
    Assert.assertEquals(hex, Hex.encode(read(Hex.decode(hex)).getEncoded()));
  }

  @Test
  public void rawPublicKeyTypeIsOther() throws Exception {
    // [2, h'01']: type 2 (RawPublicKey) has no dedicated encoding, original encoding kept
    String hex = "82024101";
    C509NameVariant v = read(Hex.decode(hex));
    Assert.assertEquals(ConstCertificateType.rawPublicKey, v.type());
    Assert.assertNotNull(v.raw());
    Assert.assertNull(v.x509Name());
    Assert.assertEquals(hex, Hex.encode(v.getEncoded()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void typeOutOfRange() {
    C509NameVariant.of(256, "text");
  }

  @Test(expected = CodecException.class)
  public void wrongValueForType4() throws Exception {
    // [4, 5]
    read(Hex.decode("820405"));
  }

  private static C509NameVariant roundTrip(C509NameVariant v) throws Exception {
    C509NameVariant v2 = read(v.getEncoded());
    Assert.assertEquals(v, v2);
    return v2;
  }

  private static C509NameVariant read(byte[] encoded) throws CodecException {
    try (ByteArrayCborDecoder in = new ByteArrayCborDecoder(encoded)) {
      return C509NameVariant.read(in);
    }
  }

}
