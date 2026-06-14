package com.codeheadsystems.minikms.server;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;

/**
 * A TCP listener bound to loopback only (127.0.0.1).
 *
 * <p>Binding to {@link InetAddress#getLoopbackAddress()} means the socket is not
 * reachable from other hosts — only processes on this machine can connect. The
 * shared API token still authenticates every request; the loopback bind is
 * defense in depth, not the sole control.
 *
 * <p>Each accepted connection is handed to the shared executor; the accept loop
 * itself runs on a dedicated daemon thread.
 */
final class TcpTransport implements Closeable {

  private static final Logger LOG = System.getLogger(TcpTransport.class.getName());

  private final ServerSocket serverSocket;
  private final ExecutorService executor;
  private final ConnectionHandlerFactory factory;
  private final Semaphore connectionLimiter;
  private volatile boolean running;
  private Thread acceptThread;

  TcpTransport(final int port, final ExecutorService executor, final ConnectionHandlerFactory factory,
               final Semaphore connectionLimiter) throws IOException {
    this.executor = executor;
    this.factory = factory;
    this.connectionLimiter = connectionLimiter;
    this.serverSocket = new ServerSocket();
    this.serverSocket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
  }

  /** Begin accepting connections on a background daemon thread. */
  void start() {
    running = true;
    acceptThread = new Thread(this::acceptLoop, "minikms-tcp-accept");
    acceptThread.setDaemon(true);
    acceptThread.start();
    LOG.log(Level.INFO, "listening on tcp://{0}", describe());
  }

  /** @return the bound address (resolves the actual port when an ephemeral port was requested). */
  String describe() {
    return InetAddress.getLoopbackAddress().getHostAddress() + ":" + serverSocket.getLocalPort();
  }

  /** @return the actual bound port. */
  int boundPort() {
    return serverSocket.getLocalPort();
  }

  private void acceptLoop() {
    while (running) {
      final Socket socket;
      try {
        socket = serverSocket.accept();
      } catch (final IOException e) {
        if (running) {
          LOG.log(Level.WARNING, () -> "tcp accept failed: " + e.getMessage());
        }
        return;
      }
      if (!connectionLimiter.tryAcquire()) {
        LOG.log(Level.WARNING, () -> "connection limit reached; rejecting " + socket.getRemoteSocketAddress());
        closeQuietly(socket);
        continue;
      }
      try {
        final String peer = "tcp:" + socket.getRemoteSocketAddress();
        executor.execute(factory.create(socket.getInputStream(), socket.getOutputStream(), peer, socket,
            connectionLimiter::release));
      } catch (final IOException | RuntimeException e) {
        connectionLimiter.release(); // acquired above, but the handler never took ownership
        LOG.log(Level.WARNING, () -> "failed to start handler: " + e.getMessage());
        closeQuietly(socket);
      }
    }
  }

  private static void closeQuietly(final Socket socket) {
    try {
      socket.close();
    } catch (final IOException ignored) {
      // best effort
    }
  }

  @Override
  public void close() throws IOException {
    running = false;
    serverSocket.close();
    if (acceptThread != null) {
      acceptThread.interrupt();
    }
  }
}
