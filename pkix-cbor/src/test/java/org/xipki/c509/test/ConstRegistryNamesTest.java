// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.registry.ConstAccessMethod;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.c509.registry.ConstCertificatePolicy;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.c509.registry.ConstPolicyQualifier;
import org.xipki.c509.registry.ConstPrivateKeyType;
import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Locale;

/**
 * The names of all C509 registries: every constant is found by its name in the forms x_y, xy
 * and x-y, in any case.
 *
 * @author Lijun Liao (xipki)
 */
public class ConstRegistryNamesTest {

  private static final Class<?>[] REGISTRIES = {
      ConstAccessMethod.class, ConstAttributeType.class, ConstCertificatePolicy.class,
      ConstExtendedKeyUsage.class, ConstExtensionId.class, ConstGeneralNameTag.class,
      ConstPolicyQualifier.class, ConstPrivateKeyType.class, ConstRDNAttributeType.class};

  @Test
  public void allConstantsByName() throws Exception {
    for (Class<?> clazz : REGISTRIES) {
      Method code = clazz.getMethod("code", String.class);
      int n = 0;
      for (Field field : constants(clazz)) {
        n++;
        long expected = field.getLong(null);
        for (String name : variants(field.getName())) {
          Number actual = (Number) code.invoke(null, name);
          Assert.assertNotNull(clazz.getSimpleName() + ": " + name, actual);
          Assert.assertEquals(clazz.getSimpleName() + ": " + name, expected, actual.longValue());
        }
      }
      Assert.assertTrue(clazz.getSimpleName() + " has constants", n > 0);
    }
  }

  @Test
  public void algorithmRegistriesByName() throws Exception {
    assertRegistry(ConstRegistry.PUBLIC_KEY_ALGORITHM, ConstPublicKeyAlgorithm.class);
    assertRegistry(ConstRegistry.SIGNATURE_ALGORITHM, ConstSignatureAlgorithm.class);
    assertRegistry(ConstRegistry.HASH_ALGORITHM, ConstHashAlgorithm.class);
    assertRegistry(ConstRegistry.RDN_ATTRIBUTE, ConstRDNAttributeType.class);
  }

  @Test
  public void examples() {
    // constant name, registered name and code
    Assert.assertEquals(Long.valueOf(ConstCertificatePolicy.ipAddr_asNumber),
        ConstCertificatePolicy.code("ipaddr-asnumber"));
    Assert.assertEquals(Long.valueOf(ConstCertificatePolicy.ipAddr_asNumber),
        ConstCertificatePolicy.code("rpki-ipAddr-asNumber"));
    Assert.assertEquals(Long.valueOf(ConstExtensionId.subjectAltName),
        ConstExtensionId.code("subject_alt_name"));
    Assert.assertEquals(Long.valueOf(1),
        ConstRegistry.PUBLIC_KEY_ALGORITHM.codeOf("ec-secp256r1"));
    Assert.assertEquals(Long.valueOf(ConstRDNAttributeType.organizationalUnit),
        ConstRDNAttributeType.code("organizational_unit"));
    Assert.assertNull(ConstRegistry.PUBLIC_KEY_ALGORITHM.codeOf("no_such_algorithm"));
    Assert.assertNull(ConstExtensionId.code("no-such-extension"));
  }

  private static void assertRegistry(ConstRegistry registry, Class<?> clazz) throws Exception {
    for (Field field : constants(clazz)) {
      long expected = field.getLong(null);
      for (String name : variants(field.getName())) {
        Assert.assertEquals(registry.kind() + ": " + name, Long.valueOf(expected),
            registry.codeOf(name));
      }
    }
  }

  private static Iterable<Field> constants(Class<?> clazz) {
    java.util.List<Field> ret = new java.util.ArrayList<>();
    for (Field field : clazz.getFields()) {
      int mod = field.getModifiers();
      Class<?> type = field.getType();
      if ((type == long.class || type == int.class)
          && Modifier.isStatic(mod) && Modifier.isFinal(mod)) {
        ret.add(field);
      }
    }
    return ret;
  }

  /** The name with the separators '_', '' and '-', in the original and in other cases. */
  private static String[] variants(String name) {
    String noSep = name.replace("_", "").replace("-", "");
    String dash = name.replace('_', '-');
    String underscore = name.replace('-', '_');
    return new String[] {underscore, noSep, dash, underscore.toLowerCase(Locale.ROOT),
        noSep.toUpperCase(Locale.ROOT)};
  }

}
