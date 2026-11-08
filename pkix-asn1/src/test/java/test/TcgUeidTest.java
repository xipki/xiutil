// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x509.Extension;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

/**
 * Test of the TCG DICE UEID extension: TcgUeid ::= SEQUENCE { ueid OCTET STRING }.
 *
 * @author Lijun Liao (xipki)
 */
public class TcgUeidTest {

  // Extension { tcg-dice-Ueid, extnValue = DER(SEQUENCE { OCTET STRING 12121212 }) }
  private static final String EXTN = "3012060667810505040404083006040412121212";

  @Test
  public void testEncodeAndParse() throws Exception {
    byte[] ueid = Hex.decode("12121212");
    Extension extn = Extension.ofTcgDiceUeid(false, ueid);
    Assert.assertEquals(EXTN, Hex.encode(extn.getEncoded()));

    Extension parsed = Extension.fromAsn1(Asn1Sequence.fromEncoded(Hex.decode(EXTN)));
    Assert.assertArrayEquals(ueid, parsed.tcgDiceUeid());
  }

  @Test
  public void testBareOctetStringRejected() {
    // the former, non-conformant encoding: extnValue = DER(OCTET STRING 12121212)
    Assert.assertThrows(CodecException.class,
        () -> Extension.fromAsn1(
            Asn1Sequence.fromEncoded(Hex.decode("301006066781050504040406040412121212"))));
  }

}
