// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.servlet;

import jakarta.servlet.ServletException;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Tests the resolution of the context parameter xipki.basedir.
 *
 * @author Lijun Liao (xipki)
 */
public class BasedirTest {

  private static Path newContainerBase() throws IOException {
    Path base = Files.createTempDirectory("xipki-container-base");
    Files.createDirectories(base.resolve("xipki"));
    return base;
  }

  private static String canonical(Path path) throws IOException {
    return path.toFile().getCanonicalPath();
  }

  @Test
  public void relativeValueIsResolvedAgainstEachKnownContainer() throws Exception {
    for (String property : ServletFilter.CONTAINER_BASE_PROPERTIES) {
      Path base = newContainerBase();
      String basedir = ServletFilter.resolveBasedir("xipki",
          Map.of(property, base.toString())::get);
      Assert.assertEquals(property, canonical(base.resolve("xipki")), basedir);
    }
  }

  @Test
  public void firstKnownContainerWins() throws Exception {
    Path tomcat = newContainerBase();
    Path wildfly = newContainerBase();
    String basedir = ServletFilter.resolveBasedir("xipki", Map.of(
        "jboss.server.base.dir", wildfly.toString(),
        "catalina.base", tomcat.toString())::get);
    Assert.assertEquals(canonical(tomcat.resolve("xipki")), basedir);
  }

  @Test
  public void absoluteValueIgnoresContainer() throws Exception {
    Path dir = Files.createTempDirectory("xipki-absolute");
    Assert.assertEquals(canonical(dir),
        ServletFilter.resolveBasedir(" " + dir + " ", name -> null));
  }

  @Test
  public void relativeValueInUnknownContainerIsRejected() {
    ServletException ex = Assert.assertThrows(ServletException.class,
        () -> ServletFilter.resolveBasedir("xipki", name -> null));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("use an absolute path"));
  }

  @Test
  public void unresolvedPlaceholderIsRejected() {
    ServletException ex = Assert.assertThrows(ServletException.class,
        () -> ServletFilter.resolveBasedir("${catalina.base}/xipki", name -> null));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains("unresolved placeholder"));
  }

  @Test
  public void missingOrNonExistingDirectoryIsRejected() throws Exception {
    Assert.assertThrows(ServletException.class,
        () -> ServletFilter.resolveBasedir(null, name -> null));
    Assert.assertThrows(ServletException.class,
        () -> ServletFilter.resolveBasedir("  ", name -> null));

    Path base = Files.createTempDirectory("xipki-container-base"); // without xipki/
    Assert.assertThrows(ServletException.class,
        () -> ServletFilter.resolveBasedir("xipki", Map.of("catalina.base", base.toString())::get));
    Assert.assertThrows(ServletException.class,
        () -> ServletFilter.resolveBasedir(base + File.separator + "missing", name -> null));
  }

}
