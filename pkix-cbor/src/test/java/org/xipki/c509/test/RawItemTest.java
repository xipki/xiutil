// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.key.C509PrivateKey;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.c509.registry.ConstPrivateKeyType;
import org.xipki.codec.Hex;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * Values of unregistered ids and types, kept as {@link CborEncodedItem} in their original encoding.
 *
 * @author Lijun Liao (xipki)
 */
public class RawItemTest {

  /** {2: "b", 1: "a"}: keys not in deterministic order. */
  private static final String UNSORTED = "a2026162016161";

  @Test
  public void rawItem() throws Exception {
    CborEncodedItem item = C509Cbor.parse(Hex.decode(UNSORTED), CborDecoder::readEncodedItem);
    Assert.assertEquals(UNSORTED, Hex.encode(item.getEncoded()));
    Assert.assertTrue(item.type().isMap());
    Assert.assertEquals("{1: \"a\", 2: \"b\"}", item.toDiagnostic());

    // built from generic data: deterministic encoding
    CborEncodedItem built = CborEncodedItem.ofData(item.data());
    Assert.assertEquals("a2016161026162", Hex.encode(built.getEncoded()));
    Assert.assertNotEquals(item, built);
    Assert.assertEquals(built, CborEncodedItem.ofData(item.data()));
    Assert.assertSame(built, CborEncodedItem.ofData(built));
  }

  @Test
  public void generalName() throws Exception {
    // tag 3 (x400Address) has no dedicated shape
    String hex = "03" + UNSORTED;
    C509GeneralName name = C509Cbor.parse(Hex.decode(hex), C509GeneralName::read);
    Assert.assertEquals(3, name.tag());
    Assert.assertNotNull(name.raw());
    Assert.assertNull(name.text());
    Assert.assertEquals(hex, Hex.encode(name.getEncoded()));
    Assert.assertTrue(name.toString().contains("{1: \"a\", 2: \"b\"}"));

    Assert.assertEquals(name, C509GeneralName.raw(3, name.raw()));
    Assert.assertNull(C509GeneralName.dns("example.com").raw());
    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509GeneralName.raw(ConstGeneralNameTag.dNSName, CborEncodedItem.ofData("x")));
  }

  @Test
  public void privateKey() throws Exception {
    // [2, 1, {2: "b", 1: "a"}]: type 2 is not registered
    String hex = "830201" + UNSORTED;
    C509PrivateKey key = C509PrivateKey.parse(Hex.decode(hex));
    Assert.assertEquals(2, key.type());
    Assert.assertTrue(key.privateKey() instanceof CborEncodedItem);
    Assert.assertEquals(hex, Hex.encode(key.getEncoded()));
    Assert.assertFalse(key.toString().contains("\"a\""));

    C509PrivateKey built = C509PrivateKey.ofRaw(2, 1, (CborEncodedItem) key.privateKey());
    Assert.assertEquals(key, built);
    // non-map values allowed for unregistered types
    C509PrivateKey list = C509PrivateKey.ofRaw(2, 1, CborEncodedItem.ofData(List.of(1, 2)));
    Assert.assertEquals(list, C509PrivateKey.parse(list.getEncoded()));

    Assert.assertThrows(IllegalArgumentException.class,
        () -> C509PrivateKey.ofRaw(ConstPrivateKeyType.coseKey, 1, CborEncodedItem.ofData(1)));
    // coseKey still requires a map
    Assert.assertThrows(CodecException.class,
        () -> C509PrivateKey.parse(Hex.decode("83010101")));
  }

}
