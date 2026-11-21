// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509RawAttrValue;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509RawExtnValue;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.Hex;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborMap;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Values of unregistered extensions and attributes: built from generic CBOR data with maps
 * sorted deterministically, and decoded in their original encoding.
 *
 * @author Lijun Liao (xipki)
 */
public class GenericValueTest {

  private static final long UNREGISTERED_EXTENSION = 1000;

  private static final long UNREGISTERED_ATTRIBUTE = 1000;

  /** {"z": [1, {2: h'02', 1: h'01'}], 3: "c", -1: true}, keys in non-deterministic order. */
  private static Map<Object, Object> unsortedValue() {
    Map<Object, Object> inner = new LinkedHashMap<>();
    inner.put(2, new byte[] {2});
    inner.put(1, new byte[] {1});
    Map<Object, Object> outer = new LinkedHashMap<>();
    outer.put("z", List.of(1, inner));
    outer.put(3, "c");
    outer.put(-1, true);
    return outer;
  }

  /** The same value as {@link #unsortedValue()}, with the keys inserted in another order. */
  private static Map<Object, Object> otherOrderValue() {
    Map<Object, Object> inner = new LinkedHashMap<>();
    inner.put(1, new byte[] {1});
    inner.put(2, new byte[] {2});
    Map<Object, Object> outer = new LinkedHashMap<>();
    outer.put(-1, true);
    outer.put(3, "c");
    outer.put("z", List.of(1, inner));
    return outer;
  }

  @Test
  public void extensionValue() throws Exception {
    C509RawExtnValue a = new C509RawExtnValue(unsortedValue());
    C509RawExtnValue b = new C509RawExtnValue(otherOrderValue());
    Assert.assertEquals(a, b);
    Assert.assertArrayEquals(a.getEncoded(), b.getEncoded());
    Assert.assertTrue(a.data() instanceof CborMap);
    Assert.assertEquals("{3: \"c\", -1: true, \"z\": [1, {1: h'01', 2: h'02'}]}",
        CborMap.toDiagnostic(a.data()));
    Assert.assertTrue(a.toString().contains("h'01'"));

    C509RawExtnValue copy = Fixtures.roundTrip(a, C509RawExtnValue::read);
    Assert.assertEquals(a, copy);
  }

  @Test
  public void attributeValue() throws Exception {
    C509RawAttrValue a = new C509RawAttrValue(unsortedValue());
    C509RawAttrValue b = new C509RawAttrValue(otherOrderValue());
    Assert.assertEquals(a, b);
    Assert.assertArrayEquals(a.getEncoded(), b.getEncoded());
    Fixtures.roundTrip(a, C509RawAttrValue::read);
  }

  @Test
  public void unmodifiable() throws Exception {
    Map<?, ?> data = (Map<?, ?>) new C509RawExtnValue(unsortedValue()).data();
    Assert.assertThrows(UnsupportedOperationException.class, data::clear);
    List<?> list = (List<?>) data.get("z");
    Assert.assertThrows(UnsupportedOperationException.class, () -> list.remove(0));
    Map<?, ?> inner = (Map<?, ?>) list.get(1);
    Assert.assertThrows(UnsupportedOperationException.class, () -> inner.remove(1));
  }

  @Test
  public void duplicateKeys() {
    Map<Object, Object> map = new LinkedHashMap<>();
    map.put(1, "a");
    map.put(1L, "b");
    Assert.assertThrows(IllegalArgumentException.class, () -> new C509RawExtnValue(map));
  }

  /**
   * The signature is verified over the re-encoded body of the decoded certificate, which must
   * therefore be identical to the signed one.
   */
  @Test
  public void certificateWithUnregisteredExtension() throws Exception {
    C509KeyPair key = TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1);
    C509Certificate cert = Fixtures.issue(key, null, new C509Name("CN=generic"),
        key.subjectPublicKey(), null, b -> b.extension(C509Extension.nonCritical(
            UNREGISTERED_EXTENSION, new C509RawExtnValue(unsortedValue()))));

    C509Certificate copy = C509Certificate.parse(cert.getEncoded());
    Assert.assertEquals(new C509RawExtnValue(otherOrderValue()),
        copy.extensions().get(UNREGISTERED_EXTENSION).value());
  }

  @Test
  public void requestWithUnregisteredAttribute() throws Exception {
    C509KeyPair key = TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1);
    C509CertificationRequest csr = Fixtures.request(key, new C509Name("CN=generic"),
        b -> b.attribute(new C509Attribute(UNREGISTERED_ATTRIBUTE,
            new C509RawAttrValue(unsortedValue()))));
    Assert.assertEquals(new C509RawAttrValue(otherOrderValue()),
        csr.attributes().first(UNREGISTERED_ATTRIBUTE).value());
  }

  @Test
  public void originalEncodingKept() throws Exception {
    // {2: "b", 1: "a"}: keys not in deterministic order
    String hex = "a2026162016161";
    C509RawExtnValue extn = C509RawExtnValue.read(new ByteArrayCborDecoder(Hex.decode(hex)));
    Assert.assertEquals(hex, Hex.encode(extn.getEncoded()));
    Assert.assertEquals("{1: \"a\", 2: \"b\"}", extn.raw().toDiagnostic());
    Assert.assertNotEquals(new C509RawExtnValue(extn.data()), extn);

    C509RawAttrValue attr = C509RawAttrValue.read(new ByteArrayCborDecoder(Hex.decode(hex)));
    Assert.assertEquals(hex, Hex.encode(attr.getEncoded()));

    // indefinite-length array: cannot be decoded as generic data, but kept
    String indef = "9f0102ff";
    C509RawExtnValue v = C509RawExtnValue.read(new ByteArrayCborDecoder(Hex.decode(indef)));
    Assert.assertEquals(indef, Hex.encode(v.getEncoded()));
    Assert.assertTrue(v.toString().contains(indef));
  }

}
