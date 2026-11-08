// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.AbstractCollection;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.DerivedBitString;
import org.xipki.codec.asn1.DerivedInteger;
import org.xipki.codec.asn1.DerivedOctetString;
import org.xipki.codec.asn1.DerivedUtf8String;
import org.xipki.codec.asn1.Enumerated;
import org.xipki.codec.asn1.FlagsBitString;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Every {@link Asn1Encodable} of asn1, except those extending {@code Derived*},
 * {@link AbstractCollection}, {@link Asn1Primitive}, {@link Enumerated} and
 * {@link FlagsBitString}, must implement {@code toString(StringBuilder, int)}, or inherit it
 * from a class of asn1.
 *
 * @author Lijun Liao (xipki)
 */
public class ToStringCoverageTest {

  private static final Class<?>[] EXCLUDED_BASES = {AbstractCollection.class,
      Asn1Primitive.class, Enumerated.class, FlagsBitString.class, DerivedBitString.class,
      DerivedInteger.class, DerivedOctetString.class, DerivedUtf8String.class};

  @Test
  public void testAllClassesHaveToString() throws Exception {
    CodeSource xiasn1 = Certificate.class.getProtectionDomain().getCodeSource();
    List<String> missing = new ArrayList<>();
    int checked = 0;

    for (String className : classNames(xiasn1)) {
      Class<?> clazz = Class.forName(className, false, getClass().getClassLoader());
      if (!Asn1Encodable.class.isAssignableFrom(clazz) || isExcluded(clazz)) {
        continue;
      }

      checked++;
      if (!hasOwnToString(clazz, xiasn1)) {
        missing.add(className);
      }
    }

    Assert.assertTrue("no classes checked", checked > 100);
    Assert.assertTrue("classes without toString(StringBuilder, int):\n"
        + String.join("\n", missing), missing.isEmpty());
  }

  private static boolean isExcluded(Class<?> clazz) {
    for (Class<?> base : EXCLUDED_BASES) {
      if (base.isAssignableFrom(clazz)) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasOwnToString(Class<?> clazz, CodeSource xiasn1) {
    for (Class<?> c = clazz; c != Asn1Encodable.class; c = c.getSuperclass()) {
      if (!xiasn1.equals(c.getProtectionDomain().getCodeSource())) {
        return false;
      }

      try {
        c.getDeclaredMethod("toString", StringBuilder.class, int.class);
        return true;
      } catch (NoSuchMethodException e) {
        // check the superclass
      }
    }
    return false;
  }

  private static List<String> classNames(CodeSource codeSource)
      throws IOException, URISyntaxException {
    Path root = Paths.get(codeSource.getLocation().toURI());
    Assert.assertTrue("asn1 classes must be a directory: " + root, Files.isDirectory(root));

    List<String> names = new ArrayList<>();
    try (Stream<Path> paths = Files.walk(root)) {
      paths.filter(p -> p.toString().endsWith(".class"))
          .map(p -> root.relativize(p).toString())
          .filter(n -> !n.endsWith("package-info.class"))
          .forEach(n -> names.add(n.substring(0, n.length() - ".class".length())
              .replace('/', '.').replace('\\', '.')));
    }
    return names;
  }

}
