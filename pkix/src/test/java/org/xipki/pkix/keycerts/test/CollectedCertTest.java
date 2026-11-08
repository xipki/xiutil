// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.keycerts.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x509.Certificate;
import org.xipki.pkix.util.X509Util;
import org.xipki.codec.util.IoUtil;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Lijun Liao (xipki)
 */
public class CollectedCertTest {

  @Test
  public void certTest() throws Exception {
    for (Path path : listFiles("/keycerts", "crt")) {
      try {
        byte[] encoded = IoUtil.read(path.toFile());
        encoded = X509Util.toDerEncoded(encoded);
        Certificate cert = Certificate.fromEncoded(encoded);
        System.out.println(cert);
      } catch (Exception e) {
        //System.err.println("error loading " + path + ": " + e.getMessage());
        throw new Exception("error loading " + path, e);
      }
    }
  }

  static List<Path> listFiles(String path, String extension) throws Exception {
    URL url = CollectedCertTest.class.getResource(path);
    Assert.assertNotNull("URL " + path, url);
    Path dir = Paths.get(url.toURI());

    try (Stream<Path> paths = Files.walk(dir)) {
      return paths.filter(Files::isRegularFile)
          .filter(p -> p.getFileName().toString().endsWith("." + extension))
          .collect(Collectors.toList());
    }
  }

}
