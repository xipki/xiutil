// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.misc;

import org.xipki.crypto.api.CryptoApiFactory;

import java.security.SecureRandom;

/**
 * Random Util. The random numbers come from the crypto backend
 * ({@link org.xipki.crypto.api.CryptoApi#getSecureRandom()}).
 *
 * @author Lijun Liao (xipki)
 */
public class RandomUtil {

  public static SecureRandom random() {
    return CryptoApiFactory.get().getSecureRandom();
  }

  public static long nextLong() {
    return random().nextLong();
  }

  public static int nextInt() {
    return random().nextInt();
  }

  public static int nextInt(int bound) {
    return random().nextInt(bound);
  }

  public static byte[] nextBytes(int num) {
    byte[] bytes = new byte[num];
    random().nextBytes(bytes);
    return bytes;
  }

}
