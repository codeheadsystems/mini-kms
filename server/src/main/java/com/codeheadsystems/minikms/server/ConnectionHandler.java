package com.codeheadsystems.minikms.server;

import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.protocol.ErrorCode;
import com.codeheadsystems.minikms.protocol.KmsRequest;
import com.codeheadsystems.minikms.protocol.KmsResponse;
import com.codeheadsystems.minikms.protocol.ProtocolCodec;
import com.codeheadsystems.minikms.protocol.ProtocolException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Services one accepted connection: a request/response loop over a single socket.
 *
 * <p>The same handler backs both transports — it only sees an {@link InputStream}
 * and {@link OutputStream}, so TCP and Unix connections are handled identically.
 * It reads bounded newline-delimited frames, decodes each to a {@link KmsRequest},
 * dispatches to the transport-agnostic {@link KmsRequestHandler}, and writes one
 * JSON response line back. Connections are persistent: multiple requests may flow
 * over one connection until the client closes it.
 *
 * <p>Logging never includes request/response bodies, tokens, or key material —
 * only coarse lifecycle and error categories.
 *
 * <p>Each read of the next request is guarded by an idle-timeout watchdog: a
 * client that connects and then stalls (sending nothing, or one byte at a time)
 * is forcibly disconnected after {@code idleTimeoutMillis} rather than pinning the
 * thread forever. The permit acquired for this connection by the transport is
 * released exactly once, via {@code onClose}, when the loop ends.
 */
final class ConnectionHandler implements Runnable {

  private static final Logger LOG = System.getLogger(ConnectionHandler.class.getName());

  private final InputStream in;
  private final OutputStream out;
  private final String peer;
  private final AutoCloseable closeable;
  private final ProtocolCodec codec;
  private final KmsRequestHandler requestHandler;
  private final int maxFrameBytes;
  private final ScheduledExecutorService idleWatchdog;
  private final long idleTimeoutMillis;
  private final Runnable onClose;

  ConnectionHandler(final InputStream in, final OutputStream out, final String peer,
                    final AutoCloseable closeable, final ProtocolCodec codec,
                    final KmsRequestHandler requestHandler, final int maxFrameBytes,
                    final ScheduledExecutorService idleWatchdog, final long idleTimeoutMillis,
                    final Runnable onClose) {
    this.in = in;
    this.out = out;
    this.peer = peer;
    this.closeable = closeable;
    this.codec = codec;
    this.requestHandler = requestHandler;
    this.maxFrameBytes = maxFrameBytes;
    this.idleWatchdog = idleWatchdog;
    this.idleTimeoutMillis = idleTimeoutMillis;
    this.onClose = onClose;
  }

  @Override
  public void run() {
    final BoundedLineReader reader = new BoundedLineReader(in, maxFrameBytes);
    try {
      byte[] line;
      while ((line = readNext(reader)) != null) {
        if (line.length == 0) {
          continue; // tolerate blank keep-alive lines
        }
        final KmsResponse response = process(line);
        writeResponse(response);
      }
    } catch (final FrameTooLargeException e) {
      tryWrite(KmsResponse.error(ErrorCode.FRAME_TOO_LARGE, "request too large"));
      LOG.log(Level.WARNING, "closing {0}: frame exceeded limit", peer);
    } catch (final IOException e) {
      LOG.log(Level.DEBUG, () -> "connection " + peer + " ended: " + e.getMessage());
    } finally {
      close();
      onClose.run(); // release this connection's permit exactly once
    }
  }

  /**
   * Read the next request line, force-closing the connection if it stalls longer
   * than the idle timeout. Closing the socket from the watchdog thread unblocks
   * the in-progress read with an {@link IOException}, which ends the loop.
   */
  private byte[] readNext(final BoundedLineReader reader) throws IOException {
    final ScheduledFuture<?> timeout =
        idleWatchdog.schedule(this::closeForIdleTimeout, idleTimeoutMillis, TimeUnit.MILLISECONDS);
    try {
      return reader.readLine();
    } finally {
      timeout.cancel(false);
    }
  }

  private void closeForIdleTimeout() {
    LOG.log(Level.DEBUG, "closing {0}: idle timeout", peer);
    close();
  }

  private KmsResponse process(final byte[] line) {
    final String json = new String(line, StandardCharsets.UTF_8);
    final KmsRequest request;
    try {
      request = codec.decodeRequest(json);
    } catch (final ProtocolException e) {
      return KmsResponse.error(ErrorCode.INVALID_REQUEST, e.getMessage());
    }
    return requestHandler.handle(request);
  }

  private void writeResponse(final KmsResponse response) throws IOException {
    final byte[] bytes = (codec.encodeResponse(response) + "\n").getBytes(StandardCharsets.UTF_8);
    out.write(bytes);
    out.flush();
  }

  private void tryWrite(final KmsResponse response) {
    try {
      writeResponse(response);
    } catch (final IOException ignored) {
      // Best effort: the client may already be gone.
    }
  }

  private void close() {
    try {
      closeable.close();
    } catch (final Exception ignored) {
      // nothing actionable on close failure
    }
  }
}
