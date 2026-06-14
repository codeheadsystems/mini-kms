package com.codeheadsystems.minikms.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads newline-delimited frames from a stream with a hard size cap.
 *
 * <p>The protocol is one JSON object per line. A hostile or buggy client could
 * send an enormous line (or never send a newline) to exhaust server memory; this
 * reader bounds each frame to {@code maxFrameBytes} and raises
 * {@link FrameTooLargeException} once that is exceeded, rather than buffering
 * without limit. Both {@code \n} and {@code \r\n} line endings are accepted.
 */
final class BoundedLineReader {

  private final InputStream in;
  private final int maxFrameBytes;

  BoundedLineReader(final InputStream in, final int maxFrameBytes) {
    this.in = in;
    this.maxFrameBytes = maxFrameBytes;
  }

  /**
   * Read the next line (without its terminator).
   *
   * @return the line bytes, or {@code null} at end of stream.
   * @throws IOException             on stream failure.
   * @throws FrameTooLargeException  if the line exceeds the configured limit.
   */
  byte[] readLine() throws IOException {
    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int read;
    boolean any = false;
    while ((read = in.read()) != -1) {
      any = true;
      if (read == '\n') {
        return trimTrailingCarriageReturn(buffer);
      }
      if (buffer.size() >= maxFrameBytes) {
        throw new FrameTooLargeException(maxFrameBytes);
      }
      buffer.write(read);
    }
    if (!any) {
      return null;
    }
    // Stream ended without a trailing newline: return what we have.
    return trimTrailingCarriageReturn(buffer);
  }

  private static byte[] trimTrailingCarriageReturn(final ByteArrayOutputStream buffer) {
    final byte[] bytes = buffer.toByteArray();
    if (bytes.length > 0 && bytes[bytes.length - 1] == '\r') {
      final byte[] trimmed = new byte[bytes.length - 1];
      System.arraycopy(bytes, 0, trimmed, 0, trimmed.length);
      return trimmed;
    }
    return bytes;
  }
}
