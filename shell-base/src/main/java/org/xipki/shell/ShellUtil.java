// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Shell Util.
 *
 * @author Lijun Liao (xipki)
 */
public class ShellUtil {

  private static final String SHELL_HOME = "org.xipki.shell.home";

  /**
   * Resolves a required path under the configured shell home.
   *
   * @param relativePath path relative to shell home
   * @return normalized absolute path string
   * @throws IllegalStateException if the path escapes shell home or does not exist as a file
   */
  public static String resolveRequired(String relativePath) {
    Path baseDir = shellHome();
    Path path = baseDir.resolve(relativePath).normalize();
    if (!path.startsWith(baseDir)) {
      throw new IllegalStateException("config path escapes shell home: " + relativePath);
    }
    if (!path.toFile().isFile()) {
      throw new IllegalStateException("required config file not found: " + path);
    }
    return path.toString();
  }

  /**
   * Resolves an optional path under the configured shell home.
   *
   * @param relativePath path relative to shell home
   * @return normalized absolute path string
   * @throws IOException if the path escapes shell home
   */
  public static String resolveOptional(String relativePath) throws IOException {
    Path baseDir = shellHome();
    Path path = baseDir.resolve(relativePath).normalize();
    if (!path.startsWith(baseDir)) {
      throw new IOException("config path escapes shell home: " + relativePath);
    }
    return path.toString();
  }

  /**
   * Returns the shell home directory used for bundled configuration and scripts.
   *
   * @return normalized absolute shell home path
   */
  public static Path shellHome() {
    String shellHome = System.getProperty(SHELL_HOME);
    if (shellHome == null || shellHome.isBlank()) {
      return Paths.get("").toAbsolutePath().normalize();
    }
    return Paths.get(shellHome).toAbsolutePath().normalize();
  }

  public static boolean isBlank(String str) {
    return str == null || str.isEmpty();
  }

  public static boolean isNotBlank(String str) {
    return str != null && !str.isEmpty();
  }

  public static boolean orEqualsIgnoreCase(String str, String... tokens) {
    if (str == null) {
      return false;
    }

    for (String token : tokens) {
      if (str.equalsIgnoreCase(token)) {
        return true;
      }
    }
    return false;
  }

  public static boolean startsWithIgnoreCase(String str, String prefix) {
    return str.length() >= prefix.length()
        && prefix.equalsIgnoreCase(str.substring(0, prefix.length()));
  }

  /**
   * Replaces a leading {@code ~} by the user home directory.
   *
   * @param path the path, must not be blank
   * @return the expanded path
   */
  public static String expandFilepath(String path) {
    if (isBlank(path)) {
      throw new IllegalArgumentException("path must not be blank");
    }
    return path.startsWith("~") ? System.getProperty("user.home") + path.substring(1) : path;
  }

  public static void mkdirs(File dir) throws IOException {
    if (dir.exists()) {
      if (!dir.isDirectory()) {
        throw new IOException("Path " + dir.getPath() + " exists but is not a directory");
      }
    } else if (!dir.mkdirs()) {
      throw new IOException("Could not mkdirs for " + dir.getPath());
    }
  }

  /**
   * Logs the message and the exception at ERROR level, with the calling class, method and
   * line; the stack trace is logged at ERROR for runtime exceptions, otherwise at DEBUG.
   *
   * @param log the logger
   * @param th the exception
   * @param msg the message
   */
  public static void logError(Logger log, Throwable th, String msg) {
    if (!log.isErrorEnabled()) {
      return;
    }

    StackTraceElement[] traces = Thread.currentThread().getStackTrace();
    if (traces.length > 2) {
      StackTraceElement trace = traces[2];
      log.error("({}.{} {}) {}, {}: {}", trace.getClassName(),
          trace.getMethodName(), trace.getLineNumber(), msg,
          th.getClass().getName(), th.getMessage());
    } else {
      log.error("{}, {}: {}", msg, th.getClass().getName(), th.getMessage());
    }

    if (th instanceof RuntimeException) {
      log.error(msg, th);
    } else {
      log.debug(msg, th);
    }
  }

  private ShellUtil() {
  }

}
