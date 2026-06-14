package com.codeheadsystems.minikms.server;

import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.protocol.ProtocolCodec;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Builds a {@link ConnectionHandler} for an accepted connection. Shared by both
 * transports so TCP and Unix connections are serviced identically — including the
 * idle-timeout watchdog and the per-connection permit release.
 */
final class ConnectionHandlerFactory {

  private final ProtocolCodec codec;
  private final KmsRequestHandler requestHandler;
  private final int maxFrameBytes;
  private final ScheduledExecutorService idleWatchdog;
  private final long idleTimeoutMillis;

  ConnectionHandlerFactory(final ProtocolCodec codec, final KmsRequestHandler requestHandler,
                           final int maxFrameBytes, final ScheduledExecutorService idleWatchdog,
                           final long idleTimeoutMillis) {
    this.codec = codec;
    this.requestHandler = requestHandler;
    this.maxFrameBytes = maxFrameBytes;
    this.idleWatchdog = idleWatchdog;
    this.idleTimeoutMillis = idleTimeoutMillis;
  }

  ConnectionHandler create(final InputStream in, final OutputStream out, final String peer,
                           final AutoCloseable closeable, final Runnable onClose) {
    return new ConnectionHandler(in, out, peer, closeable, codec, requestHandler, maxFrameBytes,
        idleWatchdog, idleTimeoutMillis, onClose);
  }
}
