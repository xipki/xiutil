// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.ext.C509AcceptableResponseTypes;
import org.xipki.c509.ext.C509ExpiredCertsOnCRL;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509PreferredSignatureAlgorithm;
import org.xipki.c509.ext.C509PreferredSignatureAlgorithms;
import org.xipki.c509.ext.C509TNQuery;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;
import java.util.List;

/**
 * The extensions defined in draft-liao-cose-c509-revocation-01: expiredCertsOnCRL, Acceptable
 * Response Types, Preferred Signature Algorithms and TN Query.
 *
 * @author Lijun Liao (xipki)
 */
public class RevocationExtensionsTest {

  /** Encodes the extension in an Extensions array, decodes it and checks the value class. */
  private static <T> T roundTrip(long id, C509ExtnValue value, Class<T> clazz)
      throws Exception {
    C509Extensions exts = C509Extensions.of(C509Extension.nonCritical(id, value));
    C509Extensions copy = Fixtures.roundTrip(exts, C509Extensions::read);
    Assert.assertEquals(exts, copy);
    Assert.assertFalse(copy.toString().isEmpty());
    return clazz.cast(copy.get(id).value());
  }

  @Test
  public void expiredCertsOnCRL() throws Exception {
    Instant since = Instant.ofEpochSecond(1_700_000_000L);
    C509ExpiredCertsOnCRL v = roundTrip(ConstExtensionId.expiredCertsOnCRL,
        new C509ExpiredCertsOnCRL(since), C509ExpiredCertsOnCRL.class);
    Assert.assertEquals(since, v.since());

    Assert.assertThrows(IllegalArgumentException.class,
        () -> new C509ExpiredCertsOnCRL(Instant.ofEpochSecond(-1)));
    // -1
    Assert.assertThrows(CodecException.class,
        () -> C509Cbor.parse(Hex.decode("20"), C509ExpiredCertsOnCRL::read));
  }

  @Test
  public void acceptableResponseTypes() throws Exception {
    C509AcceptableResponseTypes v = roundTrip(ConstExtensionId.acceptableOcspResponseTypes,
        new C509AcceptableResponseTypes(2, 1), C509AcceptableResponseTypes.class);
    Assert.assertArrayEquals(new int[] {2, 1}, v.types());
    Assert.assertThrows(IllegalArgumentException.class, C509AcceptableResponseTypes::new);
  }

  @Test
  public void preferredSignatureAlgorithms() throws Exception {
    C509PreferredSignatureAlgorithms value = C509PreferredSignatureAlgorithms.of(
        // pubKeyAlgIdentifiers: null
        new C509PreferredSignatureAlgorithm(ConstSignatureAlgorithm.ed25519),
        // a single IntAlgorithmIdentifier
        new C509PreferredSignatureAlgorithm(ConstSignatureAlgorithm.ecdsa_with_SHA256,
            ConstPublicKeyAlgorithm.ec_secp256r1),
        // [ 2* IntAlgorithmIdentifier ]
        new C509PreferredSignatureAlgorithm(ConstSignatureAlgorithm.ecdsa_with_SHA384,
            ConstPublicKeyAlgorithm.ec_secp384r1, ConstPublicKeyAlgorithm.ec_brainpoolP384r1));
    C509PreferredSignatureAlgorithms v = roundTrip(ConstExtensionId.ocsp_pref_sig_algs, value,
        C509PreferredSignatureAlgorithms.class);
    Assert.assertEquals(3, v.entries().size());
    Assert.assertNull(v.entries().get(0).keyAlgorithms());
    Assert.assertArrayEquals(new int[] {ConstPublicKeyAlgorithm.ec_secp256r1},
        v.entries().get(1).keyAlgorithms());

    // the CDDL group is inlined: [12, null, ...], not [[12, null], ...]
    byte[] encoded = value.getEncoded();
    Assert.assertEquals((byte) 0x86, encoded[0]);

    Assert.assertThrows(IllegalArgumentException.class,
        () -> new C509PreferredSignatureAlgorithms(List.of()));
    // []: at least one entry
    Assert.assertThrows(CodecException.class,
        () -> C509Cbor.parse(Hex.decode("80"), C509PreferredSignatureAlgorithms::read));
    // [12, [1]]: a single public key algorithm must be an integer, not an array
    Assert.assertThrows(CodecException.class,
        () -> C509Cbor.parse(Hex.decode("820c8101"), C509PreferredSignatureAlgorithms::read));
  }

  @Test
  public void tnQuery() throws Exception {
    C509TNQuery v = roundTrip(ConstExtensionId.ocsp_stir_tn, new C509TNQuery("12025551234"),
        C509TNQuery.class);
    Assert.assertEquals("12025551234", v.telephoneNumber());
    Assert.assertEquals("TNQuery", ConstExtensionId.name(ConstExtensionId.ocsp_stir_tn));

    new C509TNQuery("123456789012345");
    Assert.assertThrows(IllegalArgumentException.class, () -> new C509TNQuery(""));
    Assert.assertThrows(IllegalArgumentException.class,
        () -> new C509TNQuery("1234567890123456"));
    // "": empty text
    Assert.assertThrows(CodecException.class,
        () -> C509Cbor.parse(Hex.decode("60"), C509TNQuery::read));
  }

}
