// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.xi;

import org.junit.Assert;
import org.junit.Test;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Tests for the command wait-server.
 *
 * @author Lijun Liao (xipki)
 */
public class WaitServerTest {

  @Test
  public void testStoppedOnClosedPort() throws Exception {
    int port;
    try (ServerSocket serverSocket = new ServerSocket(0)) {
      port = serverSocket.getLocalPort();
    }

    Assert.assertEquals(0, execute("--stopped", "--timeout", "5", Integer.toString(port)));
  }

  @Test
  public void testUpOnClosedPortTimesOut() throws Exception {
    int port;
    try (ServerSocket serverSocket = new ServerSocket(0)) {
      port = serverSocket.getLocalPort();
    }

    Assert.assertNotEquals(0, execute("--timeout", "1", Integer.toString(port)));
  }

  @Test
  public void testUpHttp() throws Exception {
    try (ServerSocket serverSocket = new ServerSocket(0)) {
      Thread server = new Thread(() -> {
        try (Socket socket = serverSocket.accept()) {
          socket.getInputStream().read();
          socket.getOutputStream().write(
              "HTTP/1.0 200 OK\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        } catch (IOException ex) {
          // ignore
        }
      });
      server.start();

      Assert.assertEquals(0,
          execute("--timeout", "5", Integer.toString(serverSocket.getLocalPort())));
      server.join(5000);
    }
  }

  @Test
  public void testUpTlsServerAnswers() throws Exception {
    // the server closes the connection during the handshake, as with a TLS alert.
    try (ServerSocket serverSocket = new ServerSocket(0)) {
      Thread server = new Thread(() -> {
        try (Socket socket = serverSocket.accept()) {
          socket.getInputStream().read();
        } catch (IOException ex) {
          // ignore
        }
      });
      server.start();

      Assert.assertEquals(0,
          execute("--tls", "--timeout", "5", Integer.toString(serverSocket.getLocalPort())));
      server.join(5000);
    }
  }

  @Test
  public void testPortOpenButNotAccepting() throws Exception {
    // the port is bound, but the connections are not accepted, e.g. Tomcat while deploying.
    try (ServerSocket serverSocket = new ServerSocket(0)) {
      String port = Integer.toString(serverSocket.getLocalPort());
      Assert.assertNotEquals(0, execute("--timeout", "1", port));
      Assert.assertNotEquals(0, execute("--tls", "--timeout", "1", port));
      Assert.assertNotEquals(0, execute("--stopped", "--timeout", "1", port));
    }
  }

  private static int execute(String... args) {
    CommandLine commandLine = new CommandLine(new XiCommands.WaitServer());
    commandLine.setOut(new PrintWriter(new StringWriter(), true));
    commandLine.setErr(new PrintWriter(new StringWriter(), true));
    return commandLine.execute(args);
  }
}
