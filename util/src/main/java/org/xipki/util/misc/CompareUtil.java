// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.misc;

import java.util.Arrays;
import java.util.Objects;

/**
 * Compare Util.
 *
 * @author Lijun Liao (xipki)
 */
public class CompareUtil {

  private CompareUtil() {
  }

  public static boolean areEqual(byte[] a1, int a1Pos, byte[] a2, int a2Pos, int len) {
    return Arrays.equals(a1, a1Pos, a1Pos + len, a2, a2Pos, a2Pos + len);
  }

  public static boolean equals(Object a, Object b) {
    return Objects.deepEquals(a, b);
  }

  public static boolean contains(int[] array, int value) {
    for (int v : array) {
      if (v == value) return true;
    }
    return false;
  }

  public static boolean contains(long[] array, long value) {
    for (long v : array) {
      if (v == value) return true;
    }
    return false;
  }

}
