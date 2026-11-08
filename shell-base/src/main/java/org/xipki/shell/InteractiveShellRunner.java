// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.history.DefaultHistory;
import org.jline.terminal.Terminal;
import org.jline.utils.InfoCmp.Capability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.time.Instant;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Runs the interactive shell loop, including terminal setup, history, prompts, and startup output.
 *
 * @author Lijun Liao (xipki)
 */
class InteractiveShellRunner {

  private static final Logger LOG = LoggerFactory.getLogger(InteractiveShellRunner.class);

  private final PicocliShell shell;

  InteractiveShellRunner(PicocliShell shell) {
    this.shell = shell;
  }

  int run(String[] args, Terminal terminal) {
    shell.helpSupport().stripVersionOptions(shell.commandLine().getCommandSpec());
    shell.helpSupport().flattenQualifiedNames(shell.commandLine().getCommandSpec());
    if (args != null && args.length > 0) {
      if (isHelpRequest(args)) {
        shell.helpSupport().printDetachedUsage(shell.helpSupport().resolveCommandSpec(args));
        return 0;
      }
      return shell.commandLine().execute(args);
    }
    runInteractive(terminal);
    return 0;
  }

  void runInteractive(Terminal terminal) {
    LineReader reader = LineReaderBuilder.builder()
        .terminal(terminal)
        .parser(shell.parser())
        .history(new ShellHistorySupport.MaskingHistory())
        .highlighter(ShellCommandStyler.highlighter())
        .completer(new ShellCompleter(shell.commandLine().getCommandSpec()))
        .build();
    Path historyFile = resolveHistoryFile();
    try {
      Path parent = historyFile.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
    } catch (IOException ex) {
      throw new RuntimeException("could not create history directory for " + historyFile, ex);
    }
    reader.setVariable(LineReader.HISTORY_FILE, historyFile);

    boolean startupMessagePrinted = false;
    while (shell.isRunning()) {
      try {
        shell.activateTerminal(terminal, reader);
        if (!startupMessagePrinted) {
          prepareFreshLine(terminal);
          printStartupMessage();
          startupMessagePrinted = true;
        }
        String line = readInteractiveCommand(reader);
        shell.executeLine(line);
      } catch (UserInterruptException ex) {
        shell.out().println("^C");
        shell.out().flush();
      } catch (EndOfFileException ex) {
        shell.out().println();
        shell.out().flush();
        break;
      } finally {
        shell.deactivateTerminal();
      }
    }
  }

  void clearScreen() {
    shell.out().print("\033[H\033[2J");
    shell.out().flush();
    Terminal activeTerminal = PicocliShell.activeTerminal();
    if (activeTerminal != null) {
      prepareFreshLine(activeTerminal);
    }
    printStartupMessage();
  }

  private static boolean isHelpRequest(String[] args) {
    for (String arg : args) {
      if ("-h".equals(arg) || "--help".equals(arg)) {
        return true;
      }
    }
    return false;
  }

  private Path resolveHistoryFile() {
    String commandName = shell.commandLine().getCommandName();
    String fileName = commandName + ".history";
    return Paths.get(System.getProperty("user.home"), ".xipki", fileName);
  }

  private void printWelcome() {
    String commandName = shell.commandLine().getCommandName();
    String version = determineVersion();
    shell.out().println("Welcome to " + commandName + " " + version);
    shell.out().flush();
  }

  private void printStartupMessage() {
    printWelcome();
    shell.out().println("Type 'help' for commands, 'exit' to quit.");
    shell.out().flush();
  }

  private static void prepareFreshLine(Terminal terminal) {
    terminal.puts(Capability.carriage_return);
    terminal.puts(Capability.clr_eol);
    terminal.flush();
  }

  private String determineVersion() {
    Class<?> rootClass = shell.commandLine().getCommandSpec().userObject().getClass();

    Package pkg = rootClass.getPackage();
    if (pkg != null) {
      String version = pkg.getImplementationVersion();
      if (ShellUtil.isNotBlank(version)) {
        return version;
      }
    }

    String version = versionFromPomProperties(rootClass, shell.commandLine().getCommandName());
    return ShellUtil.isNotBlank(version) ? version : "unknown";
  }

  /**
   * Reads the version from META-INF/maven/&lt;groupId&gt;/&lt;artifactId&gt;/pom.properties, with
   * any groupId, in the jar containing the given class.
   */
  private static String versionFromPomProperties(Class<?> clazz, String artifactId) {
    CodeSource codeSource = clazz.getProtectionDomain().getCodeSource();
    if (codeSource == null || codeSource.getLocation() == null) {
      return null;
    }

    String prefix = "META-INF/maven/";
    String suffix = "/" + artifactId + "/pom.properties";
    try {
      Path path = Paths.get(codeSource.getLocation().toURI());
      if (!Files.isRegularFile(path)) {
        return null;
      }

      try (JarFile jar = new JarFile(path.toFile())) {
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
          JarEntry entry = entries.nextElement();
          String name = entry.getName();
          if (!name.startsWith(prefix) || !name.endsWith(suffix)
              || name.length() <= prefix.length() + suffix.length()
              || name.indexOf('/', prefix.length()) != name.length() - suffix.length()) {
            continue;
          }

          try (InputStream in = jar.getInputStream(entry)) {
            Properties props = new Properties();
            props.load(in);
            return props.getProperty("version");
          }
        }
      }
    } catch (IOException | URISyntaxException | IllegalArgumentException ex) {
      LOG.debug("could not read version of {} from {}", artifactId, codeSource.getLocation(), ex);
    }
    return null;
  }

  private String readInteractiveCommand(LineReader reader) {
    StringBuilder command = new StringBuilder();
    String currentPrompt = shell.prompt();
    while (true) {
      String line = reader.readLine(currentPrompt);
      if (command.length() > 0) {
        appendInteractiveContinuation(command, line);
      } else {
        command.append(line);
      }

      if (!ShellCommandExecutor.endsWithContinuation(command.toString())) {
        return command.toString();
      }

      String merged = ShellCommandExecutor.removeContinuation(command.toString()).stripTrailing();
      command.setLength(0);
      command.append(merged);
      currentPrompt = "> ";
    }
  }

  private static void appendInteractiveContinuation(StringBuilder command, String line) {
    String trimmed = line == null ? "" : line.trim();
    if (trimmed.isEmpty()) {
      return;
    }

    if (command.length() > 0 && !Character.isWhitespace(command.charAt(command.length() - 1))) {
      command.append(' ');
    }
    command.append(trimmed);
  }

  /**
   * History helpers for masking sensitive shell input before it is persisted.
   *
   * @author Lijun Liao (xipki)
   */
  static final class ShellHistorySupport {

    private static final Set<String> MASKED_OPTIONS = Set.of("--password", "--pin");

    private ShellHistorySupport() {
    }

    static String maskSensitiveHistoryValues(String line) {
      if (ShellUtil.isBlank(line)) {
        return line;
      }

      char[] chars = line.toCharArray();
      int i = 0;
      while (i < chars.length) {
        i = skipWhitespace(chars, i);
        if (i >= chars.length) {
          break;
        }

        int tokenEnd = findTokenEnd(chars, i);
        String token = new String(chars, i, tokenEnd - i);

        int eqIndex = token.indexOf('=');
        if (eqIndex > 0) {
          String option = token.substring(0, eqIndex);
          if (MASKED_OPTIONS.contains(option)) {
            String valueToken = token.substring(eqIndex + 1);
            if (!isVariableReference(valueToken)) {
              maskRange(chars, i + eqIndex + 1, tokenEnd);
            }
          }
        } else if (MASKED_OPTIONS.contains(token)) {
          int valueStart = skipWhitespace(chars, tokenEnd);
          if (valueStart < chars.length) {
            int valueEnd = findTokenEnd(chars, valueStart);
            String valueToken = new String(chars, valueStart, valueEnd - valueStart);
            if (!isVariableReference(valueToken)) {
              maskRange(chars, valueStart, valueEnd);
            }
            tokenEnd = valueEnd;
          }
        }

        i = tokenEnd;
      }

      return new String(chars);
    }

    private static int skipWhitespace(char[] chars, int start) {
      int i = start;
      while (i < chars.length && Character.isWhitespace(chars[i])) {
        i++;
      }
      return i;
    }

    private static int findTokenEnd(char[] chars, int start) {
      int i = start;
      boolean inSingle = false;
      boolean inDouble = false;
      while (i < chars.length) {
        char ch = chars[i];
        if (ch == '\'' && !inDouble) {
          inSingle = !inSingle;
        } else if (ch == '"' && !inSingle) {
          inDouble = !inDouble;
        } else if (Character.isWhitespace(ch) && !inSingle && !inDouble) {
          break;
        }
        i++;
      }
      return i;
    }

    private static boolean isVariableReference(String token) {
      String value = token == null ? "" : token.trim();
      if (ShellVariableSupport.isSimpleQuotedLiteral(value)) {
        value = value.substring(1, value.length() - 1);
      }
      return value.startsWith("$");
    }

    private static void maskRange(char[] chars, int start, int end) {
      if (start >= end) {
        return;
      }

      if (end - start >= 2) {
        char first = chars[start];
        char last = chars[end - 1];
        if ((first == '"' || first == '\'') && first == last) {
          for (int i = start + 1; i < end - 1; i++) {
            chars[i] = '*';
          }
          return;
        }
      }

      for (int i = start; i < end; i++) {
        chars[i] = '*';
      }
    }

    static class MaskingHistory extends DefaultHistory {

      @Override
      public void add(Instant time, String line) {
        super.add(time, maskSensitiveHistoryValues(line));
      }
    }

  }

}
