// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.LongFunction;

/**
 * A two-way table between the integer codes of one C509 registry and their names.
 * <p>
 * Lookups by name ignore case, spaces, dashes and underscores, so that e.g. {@code x_y},
 * {@code xy} and {@code x-y} are the same name; the decimal code itself is accepted as a name as
 * well. The names are the registered names and the names of the constants of the registry class.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstRegistry {

  public static final ConstRegistry SIGNATURE_ALGORITHM = new ConstRegistry("signature algorithm",
      code -> ConstSignatureAlgorithm.name(narrow(code)),
      text -> toLong(ConstSignatureAlgorithm.code(text)));

  public static final ConstRegistry PUBLIC_KEY_ALGORITHM = new ConstRegistry("public key algorithm",
      code -> ConstPublicKeyAlgorithm.name(narrow(code)),
      text -> toLong(ConstPublicKeyAlgorithm.code(text)));

  public static final ConstRegistry HASH_ALGORITHM = new ConstRegistry("hash algorithm",
      code -> ConstHashAlgorithm.name(narrow(code)),
      text -> toLong(ConstHashAlgorithm.code(text)));

  public static final ConstRegistry RDN_ATTRIBUTE = new ConstRegistry("RDN attribute",
      ConstRDNAttributeType::name, ConstRDNAttributeType::code);

  private static final String UNKNOWN = "unknown";

  private final String kind;

  private final Map<Long, String> names = new ConcurrentHashMap<>();

  private final Map<String, Long> codesByAlias = new ConcurrentHashMap<>();

  private final LongFunction<String> external;

  /** Resolves the names of an external registry, or {@code null}. */
  private final Function<String, Long> externalCodeOf;

  ConstRegistry(String kind) {
    this.kind = kind;
    this.external = null;
    this.externalCodeOf = null;
  }

  private ConstRegistry(String kind, LongFunction<String> external,
                        Function<String, Long> externalCodeOf) {
    this.kind = kind;
    this.external = external;
    this.externalCodeOf = externalCodeOf;
  }

  private static Long toLong(Integer code) {
    return code == null ? null : code.longValue();
  }

  /**
   * Adds the names of the {@code public static final long} and {@code int} constants of the
   * class as names of their codes.
   *
   * @throws IllegalStateException if a name is already used for another code.
   */
  ConstRegistry withConstants(Class<?> clazz) {
    for (Field field : clazz.getFields()) {
      int mod = field.getModifiers();
      Class<?> type = field.getType();
      if ((type == long.class || type == int.class)
          && Modifier.isStatic(mod) && Modifier.isFinal(mod)) {
        long code;
        try {
          code = field.getLong(null);
        } catch (IllegalAccessException ex) {
          throw new IllegalStateException(ex);
        }

        Long prev = codesByAlias.putIfAbsent(canonical(field.getName()), code);
        if (prev != null && prev != code) {
          throw new IllegalStateException(kind + ": name " + field.getName() + " of code "
              + code + " is already used by code " + prev);
        }
      }
    }
    return this;
  }

  /**
   * Returns the canonical form of a name: case, spaces, dashes and underscores are ignored.
   */
  static String canonicalName(String text) {
    return canonical(text);
  }

  ConstRegistry put(long code, String name, String... aliases) {
    if (names.putIfAbsent(code, name) != null) {
      throw new IllegalStateException(kind + ": duplicate code " + code);
    }
    alias(name, code);
    for (String a : aliases) {
      alias(a, code);
    }
    return this;
  }

  private void alias(String alias, long code) {
    if (codesByAlias.putIfAbsent(canonical(alias), code) != null) {
      throw new IllegalStateException(kind + ": duplicate alias " + alias);
    }
  }

  private static String canonical(String text) {
    StringBuilder sb = new StringBuilder(text.length());
    for (char c : text.toCharArray()) {
      if (c != ' ' && c != '-' && c != '_') {
        sb.append(c);
      }
    }
    return sb.toString().toUpperCase(Locale.ROOT);
  }

  private static int narrow(long code) {
    if (code < Integer.MIN_VALUE || code > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("not a 32-bit code: " + code);
    }
    return (int) code;
  }

  public String kind() {
    return kind;
  }

  public String nameOf(long code) {
    String name = (external != null) ? external.apply(code) : names.get(code);
    return name == null ? UNKNOWN : name;
  }

  public boolean isKnown(long code) {
    return !UNKNOWN.equals(nameOf(code));
  }

  /**
   * Returns {@code "name (code)"}.
   */
  public String describe(long code) {
    return nameOf(code) + " (" + code + ")";
  }

  /**
   * Resolves a name, alias or decimal code.
   *
   * @return the code, or {@code null} if the text is not known.
   */
  public Long codeOf(String nameOrCode) {
    String text = nameOrCode.trim();
    Long code = codesByAlias.get(canonical(text));
    if (code != null) {
      return code;
    }
    if (externalCodeOf != null) {
      return externalCodeOf.apply(text);
    }
    try {
      long numeric = Long.parseLong(text);
      return (external != null || names.containsKey(numeric)) ? numeric : null;
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /**
   * Resolves a name, alias or decimal code to a 32-bit code.
   *
   * @return the code, or {@code null} if the text is not known.
   * @throws IllegalArgumentException if the code does not fit in an {@code int}.
   */
  public Integer intCodeOf(String nameOrCode) {
    Long code = codeOf(nameOrCode);
    return code == null ? null : narrow(code);
  }

}
