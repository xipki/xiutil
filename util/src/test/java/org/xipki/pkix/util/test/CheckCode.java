// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util.test;

import org.xipki.codec.util.IoUtil;

import java.io.BufferedReader;
import java.io.File;
import java.nio.file.Files;
import java.util.StringTokenizer;

/**
 * Canonicalize the text files.
 *
 * @author Lijun Liao (xipki)
 */
public class CheckCode {

  private final String baseDir;

  private final int baseDirLen;

  private CheckCode(String baseDir) {
    baseDir = IoUtil.expandFilepath(baseDir);
    this.baseDir = baseDir.endsWith(File.separator) ? baseDir : baseDir + File.separator;
    this.baseDirLen = this.baseDir.length();
  }

  public static void main(String[] args) {
    for (String arg : args) {
      try {
        System.out.println("Canonicalize dir " + arg);
        CheckCode canonicalizer = new CheckCode(arg);
        canonicalizer.checkWarnings();
      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }
  }

  private void checkWarnings() throws Exception {
    int n = checkWarningsInDir(new File(baseDir), true);
    System.out.println("# Files with warnings: " + n);
  }

  private int checkWarningsInDir(File dir, boolean root) throws Exception {
    if (!root) {
      // skip git submodules
      if (new File(dir, ".git").exists()) {
        return 0;
      }
    }

    File[] files = dir.listFiles();
    if (files == null) {
      return 0;
    }

    int n = 0;
    for (File file : files) {
      if (file.isDirectory()) {
        if (!file.getName().equals("target") && !file.getName().equals("tbd")) {
          n += checkWarningsInDir(file, false);
        }
      } else {
        String filename = file.getName();
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1) ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          if (checkWarningsInFile(file)) {
            n++;
          }
        }
      }
    }

    return n;
  } // method checkWarningsInDir

  private boolean checkWarningsInFile(File file) throws Exception {
    if (file.getName().equals("package-info.java")) {
      return false;
    }

    BufferedReader reader = Files.newBufferedReader(file.toPath());

    boolean bo = false;

    try {
      String line0;
      while ((line0 = reader.readLine()) != null) {
        String line = line0.trim();

        if (!line.startsWith("*")) {
          continue;
        }

        line = line.substring(1).trim();

        StringTokenizer tokenizer = new StringTokenizer(line, " ");
        if (tokenizer.countTokens() < 2) {
          continue;
        }

        while (tokenizer.hasMoreTokens()) {
          String t1 = tokenizer.nextToken();
          if (!tokenizer.hasMoreTokens()) {
            break;
          }

          String t2 = tokenizer.nextToken();

          if (t1.equalsIgnoreCase(t2)) {
            bo = true;
            System.out.println(line0);
            break;
          }
        }
      } // end while
    } finally {
      reader.close();
    }

    boolean withWarnings = false;
    if (bo) {
      System.out.println("Please check file " + file.getPath().substring(baseDirLen));
      withWarnings = true;
    }

    return withWarnings;
  } // method checkWarningsInFile

}
