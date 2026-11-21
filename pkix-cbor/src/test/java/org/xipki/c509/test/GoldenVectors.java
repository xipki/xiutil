// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.xipki.codec.Hex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Loads the reference encodings from {@code c509-golden.txt}: lines of {@code name=hex}.
 *
 * @author Lijun Liao (xipki)
 */
final class GoldenVectors {

  private static final Map<String, byte[]> VECTORS = load();

  private GoldenVectors() {
  }

  private static Map<String, byte[]> load() {
    Map<String, byte[]> map = new LinkedHashMap<>();
    try (InputStream is = GoldenVectors.class.getResourceAsStream("/c509-golden.txt");
         BufferedReader r = new BufferedReader(
             new InputStreamReader(is, StandardCharsets.US_ASCII))) {
      String line;
      while ((line = r.readLine()) != null) {
        int eq = line.indexOf('=');
        if (eq > 0) {
          map.put(line.substring(0, eq), Hex.decode(line.substring(eq + 1).trim()));
        }
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return map;
  }

  static byte[] get(String name) {
    byte[] v = VECTORS.get(name);
    if (v == null) {
      throw new IllegalArgumentException("no golden vector " + name);
    }
    return v.clone();
  }

  static Map<String, byte[]> all() {
    return VECTORS;
  }

}
