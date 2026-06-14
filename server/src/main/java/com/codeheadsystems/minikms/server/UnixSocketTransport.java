package com.codeheadsystems.minikms.server;

import java.io.Closeable;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;

/**
 * A Unix domain socket listener using Java 21's native
 * {@link StandardProtocolFamily#UNIX} support.
 *
 * <p>Unix sockets are filesystem objects, so access is governed by file
 * permissions. We create the parent directory as owner-only (0700) and tighten
 * the socket file itself to owner read/write (0600) immediately after bind, so
 * only the owning user can connect. (The shared API token still applies as well.)
 *
 * <p>A stale socket file from a previous unclean shutdown is removed before bind.
 */
final class UnixSocketTransport implements Closeable {

  private static final Logger LOG = System.getLogger(UnixSocketTransport.class.getName());

  private static final Set<PosixFilePermission> DIR_OWNER_ONLY = EnumSet.of(
      PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
  private static final Set<PosixFilePermission> FILE_OWNER_ONLY = EnumSet.of(
      PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private final Path path;
  private final ServerSocketChannel channel;
  private final ExecutorService executor;
  private final ConnectionHandlerFactory factory;
  private final Semaphore connectionLimiter;
  private volatile boolean running;
  private Thread acceptThread;

  UnixSocketTransport(final Path path, final ExecutorService executor, final ConnectionHandlerFactory factory,
                      final Semaphore connectionLimiter) throws IOException {
    this.path = path.toAbsolutePath();
    this.executor = executor;
    this.factory = factory;
    this.connectionLimiter = connectionLimiter;
    prepareDirectory(this.path);
    Files.deleteIfExists(this.path);
    this.channel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
    this.channel.bind(UnixDomainSocketAddress.of(this.path));
    restrictSocketFile(this.path);
  }

  /** Begin accepting connections on a background daemon thread. */
  void start() {
    running = true;
    acceptThread = new Thread(this::acceptLoop, "minikms-unix-accept");
    acceptThread.setDaemon(true);
    acceptThread.start();
    LOG.log(Level.INFO, "listening on unix:{0}", path);
  }

  /** @return the socket path. */
  Path path() {
    return path;
  }

  private void acceptLoop() {
    while (running) {
      final SocketChannel client;
      try {
        client = channel.accept();
      } catch (final IOException e) {
        if (running) {
          LOG.log(Level.WARNING, () -> "unix accept failed: " + e.getMessage());
        }
        return;
      }
      if (!connectionLimiter.tryAcquire()) {
        LOG.log(Level.WARNING, "connection limit reached; rejecting unix client");
        closeQuietly(client);
        continue;
      }
      try {
        executor.execute(factory.create(
            Channels.newInputStream(client), Channels.newOutputStream(client), "unix", client,
            connectionLimiter::release));
      } catch (final RuntimeException e) {
        connectionLimiter.release(); // acquired above, but the handler never took ownership
        LOG.log(Level.WARNING, () -> "failed to start handler: " + e.getMessage());
        closeQuietly(client);
      }
    }
  }

  private static void prepareDirectory(final Path socketPath) throws IOException {
    final Path parent = socketPath.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
      trySetPermissions(parent, DIR_OWNER_ONLY);
    }
  }

  private static void restrictSocketFile(final Path socketPath) {
    trySetPermissions(socketPath, FILE_OWNER_ONLY);
  }

  private static void trySetPermissions(final Path target, final Set<PosixFilePermission> perms) {
    try {
      Files.setPosixFilePermissions(target, perms);
    } catch (final UnsupportedOperationException | IOException ignored) {
      // Non-POSIX filesystem: best effort.
    }
  }

  private static void closeQuietly(final SocketChannel client) {
    try {
      client.close();
    } catch (final IOException ignored) {
      // best effort
    }
  }

  @Override
  public void close() throws IOException {
    running = false;
    channel.close();
    if (acceptThread != null) {
      acceptThread.interrupt();
    }
    Files.deleteIfExists(path);
  }
}
