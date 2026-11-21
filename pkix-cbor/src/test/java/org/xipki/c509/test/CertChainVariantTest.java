// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.ocsp.C509CertChainVariant;
import org.xipki.c509.registry.ConstCertificateType;
import org.xipki.codec.Hex;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * Tests for {@link C509CertChainVariant}. The C509 type is covered by the golden vectors.
 *
 * @author Lijun Liao (xipki)
 */
public class CertChainVariantTest {

  private static final byte[] CERT1 = Hex.decode("3003020101");

  private static final byte[] CERT2 = Hex.decode("3003020102");

  @Test
  public void x509SingleCert() throws Exception {
    // COSE_X509 with one certificate: a byte string, not an array
    C509CertChainVariant v = C509CertChainVariant.ofX509(List.of(CERT1));
    Assert.assertEquals("8200" + "45" + Hex.encode(CERT1), Hex.encode(v.getEncoded()));
    C509CertChainVariant v2 = roundTrip(v);
    Assert.assertEquals(ConstCertificateType.x509, v2.type());
    Assert.assertEquals(1, v2.x509().size());
    Assert.assertArrayEquals(CERT1, v2.x509().get(0));
    Assert.assertNull(v2.c509());
  }

  @Test
  public void x509MultipleCerts() throws Exception {
    C509CertChainVariant v = C509CertChainVariant.ofX509(List.of(CERT1, CERT2));
    Assert.assertEquals("8200" + "82" + "45" + Hex.encode(CERT1) + "45" + Hex.encode(CERT2),
        Hex.encode(v.getEncoded()));
    C509CertChainVariant v2 = roundTrip(v);
    Assert.assertEquals(2, v2.x509().size());
    Assert.assertArrayEquals(CERT2, v2.x509().get(1));
  }

  @Test
  public void otherType() throws Exception {
    // [5, [h'01', h'02']]: original encoding kept
    String hex = "8205824101" + "4102";
    C509CertChainVariant v = read(Hex.decode(hex));
    Assert.assertEquals(5, v.type());
    Assert.assertNotNull(v.raw());
    Assert.assertEquals(hex, Hex.encode(v.getEncoded()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void dedicatedTypeViaOfOther() {
    C509CertChainVariant.ofOther(ConstCertificateType.c509, "text");
  }

  @Test(expected = CodecException.class)
  public void typeOutOfRange() throws Exception {
    read(Hex.decode("821901004101"));
  }

  @Test
  public void rawPublicKeyTypeIsOther() throws Exception {
    // [2, h'01']: type 2 (RawPublicKey) has no dedicated encoding, original encoding kept
    String hex = "82024101";
    C509CertChainVariant v = read(Hex.decode(hex));
    Assert.assertEquals(ConstCertificateType.rawPublicKey, v.type());
    Assert.assertNotNull(v.raw());
    Assert.assertNull(v.x509());
    Assert.assertEquals(hex, Hex.encode(v.getEncoded()));
    Assert.assertEquals(v, C509CertChainVariant.ofOther(ConstCertificateType.rawPublicKey,
        v.raw()));
  }

  private static C509CertChainVariant roundTrip(C509CertChainVariant v) throws Exception {
    C509CertChainVariant v2 = read(v.getEncoded());
    Assert.assertEquals(v, v2);
    return v2;
  }

  private static C509CertChainVariant read(byte[] encoded) throws CodecException {
    return C509CertChainVariant.read(new ByteArrayCborDecoder(encoded));
  }

}
