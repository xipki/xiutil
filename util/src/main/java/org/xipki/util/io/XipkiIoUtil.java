// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.io;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.IoUtil;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;

/**
 * Io Util.
 *
 * @author Lijun Liao (xipki)
 */
public class XipkiIoUtil {

  private static final Logger LOG = LoggerFactory.getLogger(XipkiIoUtil.class);

  private XipkiIoUtil() {
  }

  public static void closeQuietly(Closeable closable) {
    if (closable == null) {
      return;
    }
    try {
      closable.close();
    } catch (Throwable th) {
      LOG.error("could not close closable: {}", th.getMessage());
    }
  }

  public static byte[] read(String fileName, boolean prependBaseDir) throws IOException {
    return IoUtil.read(expandFilepath(fileName, prependBaseDir));
  }

  public static byte[] read(File file, boolean prependBaseDir) throws IOException {
    return IoUtil.read(expandFilepath(file, prependBaseDir));
  }

  /**
   * Read all bytes from the input stream and close the stream.
   * The specified stream is closed after this method returns.
   * @param in the input stream.
   * @return the byte array contained in the input stream.
   * @throws IOException if error occurs while reading the bytes.
   */
  public static byte[] readAllBytesAndClose(InputStream in) throws IOException {
    try (in) {
      return IoUtil.readAllBytes(in);
    } catch (IOException ex) {
      LOG.error("could not close stream: {}", ex.getMessage());
      throw ex;
    }
  }

  public static void save(String fileName, byte[] encoded, boolean prependBaseDir)
      throws IOException {
    save(new File(fileName), encoded, prependBaseDir);
  }

  public static void save(File file, byte[] content, boolean prependBaseDir)
      throws IOException {
    IoUtil.save(expandFilepath(file, prependBaseDir), content);
  }

  public static boolean deleteFile(String path, boolean prependBaseDir) {
    return deleteFile(new File(path), prependBaseDir);
  }

  public static boolean deleteFile(File file, boolean prependBaseDir) {
    return IoUtil.deleteFile(expandFilepath(file, prependBaseDir));
  }

  public static boolean deleteDir(File dir) {
    return deleteDir(dir, false);
  }

  public static boolean deleteDir(File dir, boolean prependBaseDir) {
    dir = expandFilepath(dir, prependBaseDir);
    try {
      IoUtil.deleteDirectory(dir);
      return true;
    } catch (IOException e) {
      LOG.error("error deleting dir {}", dir);
      if (LOG.isDebugEnabled()) {
        LOG.debug("error deleting dir {}", dir, e);
      }
      return false;
    }
  }

  public static String expandFilepath(String path, boolean prependBaseDir) {
    String expandedPath = IoUtil.expandFilepath(path);
    if (!prependBaseDir || XipkiBaseDir.basedir() == null
        || IoUtil.isAbsolutePath(expandedPath)) {
      return expandedPath;
    }

    return Paths.get(XipkiBaseDir.basedir(), expandedPath).toString();
  }

  public static File expandFilepath(File file, boolean prependBaseDir) {
    String path = file.getPath();
    String expandedPath = expandFilepath(path, prependBaseDir);
    return path.equals(expandedPath) ? file : new File(expandedPath);
  }

  public static String detectPath(String path) {
    File file = new File(path);
    file = expandFilepath(file, false);
    if (!file.exists()) {
      File file2 = expandFilepath(file, true);
      if (file2.exists()) {
        file = file2;
      }
    }

    try {
      return file.getCanonicalPath();
    } catch (IOException ex) {
      return path;
    }
  }

}
