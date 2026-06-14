package com.codeheadsystems.minikms.server;

import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.protocol.ProtocolCodec;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Builds a {@link ConnectionHandler} for an accepted connection. Shared by both
 * transports so TCP and Unix connections are serviced identically.
 */
final class ConnectionHandlerFactory {

  private final ProtocolCodec codec;
  private final KmsRequestHandler requestHandler;
  private final int maxFrameBytes;

  ConnectionHandlerFactory(final ProtocolCodec codec, final KmsRequestHandler requestHandler,
                           final int maxFrameBytes) {
    this.codec = codec;
    this.requestHandler = requestHandler;
    this.maxFrameBytes = maxFrameBytes;
  }

  ConnectionHandler create(final InputStream in, final OutputStream out, final String peer,
                           final AutoCloseable closeable) {
    return new ConnectionHandler(in, out, peer, closeable, codec, requestHandler, maxFrameBytes);
  }
}
