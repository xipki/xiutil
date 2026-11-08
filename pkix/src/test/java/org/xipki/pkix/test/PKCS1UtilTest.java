// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.crypto.core.Pkcs1Util;
import org.xipki.util.misc.RandomUtil;

/**
 * Test for {@link Pkcs1Util}.
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS1UtilTest {

  @Test
  public void testMgf1PssEncodeDecode() throws XiSecurityException {
    HashAlgo ha = HashAlgo.SHA256;
    byte[] mHash = ha.hash("hello world".getBytes());
    int modulusBits = 2048;
    int sLen = ha.length();
    byte[] em = Pkcs1Util.EMSA_PSS_ENCODE(ha, mHash, ha, sLen, modulusBits, RandomUtil.random());
    boolean valid = Pkcs1Util.EMSA_PSS_DECODE(ha, mHash, em, sLen, modulusBits);
    Assert.assertTrue("PSS encode-then-decode", valid);
  }

  @Test
  public void testShakePssEncodeDecode() throws XiSecurityException {
    HashAlgo ha = HashAlgo.SHAKE128;
    byte[] mHash = ha.hash("hello world".getBytes());
    int modulusBits = 2048;
    int sLen = ha.length();
    byte[] em = Pkcs1Util.EMSA_PSS_ENCODE(ha, mHash, ha, sLen, modulusBits, RandomUtil.random());
    boolean valid = Pkcs1Util.EMSA_PSS_DECODE(ha, mHash, em, sLen, modulusBits);
    Assert.assertTrue("PSS encode-then-decode", valid);
  }

}
