package com.codeheadsystems.minikms.server;

import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.protocol.ProtocolCodec;
import java.io.Closeable;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;

/**
 * The socket daemon: binds the enabled transports and dispatches each connection
 * to a virtual thread.
 *
 * <p>Concurrency uses Java 21 virtual threads (one per connection), which suits
 * the blocking, I/O-bound nature of the protocol and scales to many idle clients
 * cheaply. The same {@link KmsRequestHandler} (and therefore the same single
 * master key) backs every connection on both transports.
 *
 * <p>Lifecycle: construct, {@link #start()}, then {@link #close()} to stop. The
 * caller is responsible for closing the {@code MasterKeyProvider} behind the
 * handler to zero the master key.
 */
public final class KmsServer implements Closeable {

  private static final Logger LOG = System.getLogger(KmsServer.class.getName());

  private final ServerConfig config;
  private final ConnectionHandlerFactory factory;
  private final ExecutorService executor;
  private final ScheduledThreadPoolExecutor idleWatchdog;
  private final Semaphore connectionLimiter;
  private TcpTransport tcpTransport;
  private UnixSocketTransport unixTransport;

  /**
   * @param config         the resolved configuration.
   * @param requestHandler the transport-agnostic request handler.
   */
  public KmsServer(final ServerConfig config, final KmsRequestHandler requestHandler) {
    this.config = config;
    this.connectionLimiter = new Semaphore(config.maxConnections());
    this.idleWatchdog = new ScheduledThreadPoolExecutor(1, runnable -> {
      final Thread thread = new Thread(runnable, "minikms-idle-watchdog");
      thread.setDaemon(true);
      return thread;
    });
    // Cancelled timeouts (the common case: a request arrived in time) are purged immediately,
    // so the watchdog queue cannot grow with one stale entry per served request.
    this.idleWatchdog.setRemoveOnCancelPolicy(true);
    this.factory = new ConnectionHandlerFactory(new ProtocolCodec(), requestHandler,
        config.maxFrameBytes(), idleWatchdog, config.idleTimeoutMillis());
    this.executor = Executors.newVirtualThreadPerTaskExecutor();
  }

  /**
   * Bind and start accepting on all enabled transports.
   *
   * @throws IOException if a socket cannot be bound.
   */
  public void start() throws IOException {
    if (config.tcpEnabled()) {
      tcpTransport = new TcpTransport(config.tcpPort(), executor, factory, connectionLimiter);
      tcpTransport.start();
    }
    if (config.unixEnabled()) {
      unixTransport = new UnixSocketTransport(config.unixSocketPath(), executor, factory, connectionLimiter);
      unixTransport.start();
    }
  }

  /** @return the actual bound TCP port, or -1 if TCP is disabled. Useful with ephemeral (port 0). */
  public int boundTcpPort() {
    return tcpTransport != null ? tcpTransport.boundPort() : -1;
  }

  @Override
  public void close() {
    closeQuietly(tcpTransport, "tcp");
    closeQuietly(unixTransport, "unix");
    executor.shutdownNow();
    idleWatchdog.shutdownNow();
    LOG.log(Level.INFO, "server stopped");
  }

  private static void closeQuietly(final Closeable closeable, final String name) {
    if (closeable == null) {
      return;
    }
    try {
      closeable.close();
    } catch (final IOException e) {
      LOG.log(Level.WARNING, () -> "error closing " + name + " transport: " + e.getMessage());
    }
  }
}
