// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.UserInterruptException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;

/**
 * Shared base for concrete commands.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ShellBaseCommand implements Runnable {

  private static final Logger LOG = LoggerFactory.getLogger(ShellBaseCommand.class);

  private static final SecureRandom RANDOM = new SecureRandom();

  @Spec
  protected CommandSpec spec;

  protected PrintWriter out() {
    return spec.commandLine().getOut();
  }

  protected void println(String text) {
    out().println(text);
    out().flush();
  }

  /**
   * Reads a secret (e.g. a password) from the console without echo, or from stdin if no console
   * is available.
   *
   * @param prompt the prompt, null for "Password"
   * @return the entered characters, null at the end of input
   * @throws IOException if reading fails
   */
  protected char[] readSecret(String prompt) throws IOException {
    String effectivePrompt = prompt == null ? "Password" : prompt;
    Console console = System.console();
    if (console != null) {
      return console.readPassword("%s: ", effectivePrompt);
    }

    out().print(effectivePrompt + ": ");
    out().flush();
    String line = new BufferedReader(new InputStreamReader(System.in)).readLine();
    return line == null ? null : line.toCharArray();
  }

  protected boolean confirmAction(String prompt) throws IOException {
    String answer = readPrompt(prompt + " (yes/no): ");
    return ShellUtil.orEqualsIgnoreCase(answer, "yes", "y");
  }

  protected String readPrompt(String prompt) throws IOException {
    String tmpPrompt = prompt;
    if (ShellUtil.isNotBlank(prompt) && !prompt.endsWith(" ")) {
      tmpPrompt += " ";
    }

    LineReader reader = PicocliShell.activeLineReader();
    if (reader != null) {
      Object historyDisabledVar = reader.getVariable(LineReader.DISABLE_HISTORY);
      try {
        reader.setVariable(LineReader.DISABLE_HISTORY, Boolean.TRUE);
        return reader.readLine(tmpPrompt);
      } catch (UserInterruptException | EndOfFileException ex) {
        throw new IOException("interrupted", ex);
      } finally {
        if (historyDisabledVar != null) {
          reader.setVariable(LineReader.DISABLE_HISTORY, historyDisabledVar);
        } else {
          reader.getVariables().remove(LineReader.DISABLE_HISTORY);
        }
      }
    }

    out().print(tmpPrompt);
    out().flush();
    return new BufferedReader(new InputStreamReader(System.in)).readLine();
  }

  protected void saveVerbose(String promptPrefix, String file, byte[] content)
      throws IOException {
    saveVerbose(promptPrefix, Paths.get(file), content);
  }

  protected void saveVerbose(String promptPrefix, Path file, byte[] content) throws IOException {
    File saveTo = new File(ShellUtil.expandFilepath(file.toString()));

    if (saveTo.exists()) {
      try {
        boolean bo = true;
        while (saveTo.exists()) {
          String answer;
          if (bo) {
            answer = readPrompt("A file named '" + saveTo.getPath()
                + "' already exists. Do you want to replace it [Yes/No]? ");
          } else {
            answer = readPrompt("Please answer with Yer or No: ");
          }

          if (answer == null) {
            throw new IOException("interrupted");
          }

          if (ShellUtil.orEqualsIgnoreCase(answer, "yes", "y")) {
            break;
          } else if (ShellUtil.orEqualsIgnoreCase(answer, "no", "n")) {
            bo = true;
            saveTo = promptSaveTarget();
          } else {
            bo = false;
          }
        }
      } catch (IOException ex) {
        ShellUtil.logError(LOG, ex, "could not save file");
        saveTo = new File("tmp-" + randomHex(6));
      }
    }

    int tries = 2;
    while (true) {
      try {
        tries--;
        save(saveTo, content);
        break;
      } catch (IOException ex) {
        println("ERROR: " + ex.getMessage());
        if (tries > 0) {
          try {
            saveTo = promptSaveTarget();
          } catch (IOException ex2) {
            ShellUtil.logError(LOG, ex2, "could not save to file");
            saveTo = new File("tmp-" + randomHex(6));
          }
        } else if (tries == 0) {
          saveTo = new File("tmp-" + randomHex(6));
        } else {
          ShellUtil.logError(LOG, ex, "could not save to file");
          throw new IOException("could not save to file", ex);
        }
      }
    }

    String tmpPromptPrefix = ShellUtil.isBlank(promptPrefix) ? "saved to file" : promptPrefix;
    println(tmpPromptPrefix + " " + saveTo.getPath());
  }

  private File promptSaveTarget() throws IOException {
    while (true) {
      String newFn = readPrompt("Enter new path to save to ... ");
      if (ShellUtil.isNotBlank(newFn)) {
        return new File(newFn);
      }
    }
  }

  protected void save(File file, byte[] content) throws IOException {
    File tmpFile = new File(ShellUtil.expandFilepath(file.getPath()));
    File parent = tmpFile.getParentFile();
    if (parent != null) {
      ShellUtil.mkdirs(parent);
    }

    try (InputStream is = new ByteArrayInputStream(content)) {
      Files.copy(is, tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
  }

  protected BigInteger toBigInt(String text) {
    return toBigInt(text, null);
  }

  protected BigInteger toBigInt(String text, Boolean hex) {
    String value = text.trim();
    if (ShellUtil.startsWithIgnoreCase(value, "0x")) {
      return new BigInteger(value.substring(2), 16);
    }
    return Boolean.TRUE.equals(hex) ? new BigInteger(value, 16) : new BigInteger(value);
  }

  private static String randomHex(int numOfBytes) {
    byte[] bytes = new byte[numOfBytes];
    RANDOM.nextBytes(bytes);
    StringBuilder sb = new StringBuilder(2 * numOfBytes);
    for (byte b : bytes) {
      sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
    }
    return sb.toString();
  }

}
