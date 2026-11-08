// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.junit.Assert;
import org.junit.Test;
import picocli.CommandLine.Command;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Tests of {@link PicocliShell#executeLine(String)}.
 *
 * @author Lijun Liao (xipki)
 */
public class PicocliShellExecuteLineTest {

  @Command(name = "root",
      subcommands = {MissingClassCommand.class, OutOfMemoryCommand.class, OkCommand.class})
  static class RootCommand extends ShellBaseCommand {

    @Override
    public void run() {
    }

  }

  @Command(name = "missing-class")
  static class MissingClassCommand extends ShellBaseCommand {

    @Override
    public void run() {
      throw new NoClassDefFoundError("org/h2/tools/Server");
    }

  }

  @Command(name = "oom")
  static class OutOfMemoryCommand extends ShellBaseCommand {

    @Override
    public void run() {
      throw new OutOfMemoryError("test");
    }

  }

  @Command(name = "ok")
  static class OkCommand extends ShellBaseCommand {

    @Override
    public void run() {
      println("ok-output");
    }

  }

  @Test
  public void missingClassDoesNotTerminateShell() {
    StringWriter sw = new StringWriter();
    PicocliShell shell = new PicocliShell("test> ", new RootCommand(), new PrintWriter(sw));

    Assert.assertEquals(1, shell.executeLine("missing-class"));
    Assert.assertTrue(sw.toString(), sw.toString().contains("org/h2/tools/Server"));

    // the shell is still usable
    Assert.assertEquals(0, shell.executeLine("ok"));
  }

  @Test
  public void otherErrorsAreNotCaught() {
    PicocliShell shell = new PicocliShell("test> ", new RootCommand(),
        new PrintWriter(new StringWriter()));
    try {
      shell.executeLine("oom");
      Assert.fail("expected OutOfMemoryError");
    } catch (OutOfMemoryError ex) {
      // expected
    }
  }

}
