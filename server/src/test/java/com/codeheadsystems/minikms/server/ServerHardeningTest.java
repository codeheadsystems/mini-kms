package com.codeheadsystems.minikms.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minikms.auth.AllowAllPolicy;
import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.kms.KmsService;
import com.codeheadsystems.minikms.master.Argon2Settings;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Behavioral tests for the connection-exhaustion hardening (idle-timeout watchdog
 * and concurrent-connection cap). Each boots a real server on an ephemeral
 * loopback port and drives it with raw sockets.
 */
class ServerHardeningTest {

  @TempDir
  Path tempDir;

  private KmsServer boot(final String... extraFlags) {
    final LocalKeyring keyring = LocalKeyring.bootstrap(
        tempDir.resolve("keystore.json"), "pw".toCharArray(), new Argon2Settings(2048, 1, 1));
    final KmsRequestHandler handler = new KmsRequestHandler(
        new KmsService(keyring), keyring,
        new ApiTokenAuthenticator("data"), new ApiTokenAuthenticator("admin"), new AllowAllPolicy());
    final String[] base = {"--tcp-port", "0", "--no-unix"};
    final String[] flags = new String[base.length + extraFlags.length];
    System.arraycopy(base, 0, flags, 0, base.length);
    System.arraycopy(extraFlags, 0, flags, base.length, extraFlags.length);
    try {
      final KmsServer server = new KmsServer(ServerConfig.resolve(flags, Map.of()), handler);
      server.start();
      return server;
    } catch (final Exception e) {
      throw new IllegalStateException("failed to boot test server", e);
    }
  }

  @Test
  void idleConnectionIsClosedByTheWatchdog() throws Exception {
    final KmsServer server = boot("--idle-timeout-ms", "400");
    try {
      try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress("127.0.0.1", server.boundTcpPort()));
        socket.setSoTimeout(5000);
        final long startNanos = System.nanoTime();
        final int eof = socket.getInputStream().read(); // blocks until the server idle-closes us
        final long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
        assertEquals(-1, eof, "an idle connection should be closed by the server");
        assertTrue(elapsedMs >= 300, "should not be closed before the idle timeout (was " + elapsedMs + "ms)");
        assertTrue(elapsedMs < 4000, "should be closed around the idle timeout (was " + elapsedMs + "ms)");
      }
    } finally {
      server.close();
    }
  }

  @Test
  void connectionsBeyondTheLimitAreRejected() throws Exception {
    final KmsServer server = boot("--max-connections", "1", "--idle-timeout-ms", "30000");
    try {
      final int port = server.boundTcpPort();
      try (Socket first = new Socket()) {
        first.connect(new InetSocketAddress("127.0.0.1", port));
        Thread.sleep(300); // let the accept loop take the single permit
        try (Socket second = new Socket()) {
          second.connect(new InetSocketAddress("127.0.0.1", port));
          second.setSoTimeout(5000);
          assertEquals(-1, second.getInputStream().read(),
              "a connection beyond the limit should be closed immediately");
        }
      }
    } finally {
      server.close();
    }
  }

  @Test
  void aFreedSlotAcceptsNewConnections() throws Exception {
    final KmsServer server = boot("--max-connections", "1", "--idle-timeout-ms", "400");
    try {
      final int port = server.boundTcpPort();
      // First connection takes the only slot, then is dropped by the idle watchdog, freeing it.
      try (Socket first = new Socket()) {
        first.connect(new InetSocketAddress("127.0.0.1", port));
        first.setSoTimeout(5000);
        assertEquals(-1, first.getInputStream().read()); // idle-closed, permit released
      }
      // A later connection now succeeds (stays open past the accept) and is itself idle-closed.
      try (Socket later = new Socket()) {
        later.connect(new InetSocketAddress("127.0.0.1", port));
        later.setSoTimeout(5000);
        assertEquals(-1, later.getInputStream().read());
      }
    } finally {
      server.close();
    }
  }
}
