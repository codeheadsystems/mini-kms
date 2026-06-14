package com.codeheadsystems.minikms.client;

import com.codeheadsystems.minikms.kms.DataKey;
import com.codeheadsystems.minikms.protocol.KeyGroupView;
import com.codeheadsystems.minikms.protocol.KmsRequest;
import com.codeheadsystems.minikms.protocol.KmsResponse;
import com.codeheadsystems.minikms.protocol.ProtocolCodec;
import com.codeheadsystems.minikms.protocol.RequestType;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

/**
 * A small, reusable client for the mini-kms protocol, covering both planes.
 *
 * <p>Open one with {@link #connectTcp}/{@link #connectUnix}, passing the token the
 * server expects for the operations you intend to call: the <b>API token</b> for
 * data-plane calls, or the <b>admin token</b> for control-plane calls. The server
 * routes by request type, so a client simply carries whichever token it was given.
 *
 * <p>{@link AutoCloseable}; one persistent connection; intended for a single
 * thread at a time. Binary fields are base64 on the wire and handled for you.
 */
public final class KmsClient implements Closeable {

  private final OutputStream out;
  private final BufferedReader reader;
  private final Closeable underlying;
  private final ProtocolCodec codec = new ProtocolCodec();
  private final String token;

  private KmsClient(final InputStream in, final OutputStream out, final Closeable underlying,
                    final String token) {
    this.out = out;
    this.reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
    this.underlying = underlying;
    this.token = token;
  }

  /** Connect over loopback TCP. */
  public static KmsClient connectTcp(final String host, final int port, final String token) {
    try {
      final Socket socket = new Socket();
      socket.connect(new InetSocketAddress(host, port));
      return new KmsClient(socket.getInputStream(), socket.getOutputStream(), socket, token);
    } catch (final IOException e) {
      throw new KmsClientException("failed to connect to tcp://" + host + ":" + port, e);
    }
  }

  /** Connect over a Unix domain socket. */
  public static KmsClient connectUnix(final Path path, final String token) {
    try {
      final SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX);
      channel.connect(UnixDomainSocketAddress.of(path.toAbsolutePath()));
      return new KmsClient(Channels.newInputStream(channel), Channels.newOutputStream(channel),
          channel, token);
    } catch (final IOException e) {
      throw new KmsClientException("failed to connect to unix:" + path, e);
    }
  }

  // ---- DATA PLANE ----

  /** @return whether the server answered Health with ok. */
  public boolean health() {
    return exchange(KmsRequest.health(token)).isOk();
  }

  /** Generate a data key under the default key group. */
  public DataKey generateDataKey(final byte[] aad) {
    return generateDataKey(null, aad);
  }

  /**
   * Generate a data key under a named key group.
   *
   * @param keyId the key group (null → default).
   * @param aad   optional encryption context.
   * @return plaintext + wrapped DEK.
   */
  public DataKey generateDataKey(final String keyId, final byte[] aad) {
    final KmsResponse response = exchange(KmsRequest.generateDataKey(token, keyId, encode(aad)));
    return new DataKey(decode(response.plaintextDataKey()), decode(response.wrappedDataKey()));
  }

  /** Encrypt a small blob under the default key group. */
  public byte[] encrypt(final byte[] plaintext, final byte[] aad) {
    return encrypt(null, plaintext, aad);
  }

  /**
   * Encrypt a small blob under a named key group.
   *
   * @param keyId     the key group (null → default).
   * @param plaintext the data.
   * @param aad       optional encryption context.
   * @return the serialized ciphertext.
   */
  public byte[] encrypt(final String keyId, final byte[] plaintext, final byte[] aad) {
    final KmsResponse response = exchange(KmsRequest.encrypt(token, keyId, encode(plaintext), encode(aad)));
    return decode(response.ciphertext());
  }

  /** Decrypt a blob or unwrap a data key (key group + version are read from the blob). */
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad) {
    final KmsResponse response = exchange(KmsRequest.decrypt(token, encode(ciphertext), encode(aad)));
    return decode(response.plaintext());
  }

  /**
   * Re-encrypt a blob onto a destination group's active version (server-side; the
   * plaintext is never exposed).
   *
   * @param destKeyId  the destination key group (null → default).
   * @param ciphertext the existing blob.
   * @param aad        the encryption context.
   * @return the re-encrypted blob.
   */
  public byte[] reEncrypt(final String destKeyId, final byte[] ciphertext, final byte[] aad) {
    final KmsResponse response =
        exchange(KmsRequest.reEncrypt(token, destKeyId, encode(ciphertext), encode(aad)));
    return decode(response.ciphertext());
  }

  // ---- CONTROL PLANE (requires the admin token) ----

  /** Create a new key group. */
  public KeyGroupView createKeyGroup(final String keyId) {
    return exchange(KmsRequest.createKeyGroup(token, keyId)).keyGroup();
  }

  /** Rotate a key group (mint a new active version). */
  public KeyGroupView rotateKeyGroup(final String keyId) {
    return exchange(KmsRequest.rotateKeyGroup(token, keyId)).keyGroup();
  }

  /** @return all key groups and their versions. */
  public List<KeyGroupView> listKeyGroups() {
    return exchange(KmsRequest.listKeyGroups(token)).keyGroups();
  }

  /** Disable a non-active version. */
  public void disableVersion(final String keyId, final long version) {
    exchange(KmsRequest.versionOp(RequestType.DISABLE_VERSION, token, keyId, version));
  }

  /** Re-enable a disabled version. */
  public void enableVersion(final String keyId, final long version) {
    exchange(KmsRequest.versionOp(RequestType.ENABLE_VERSION, token, keyId, version));
  }

  /** Destroy a non-active version's key material (irreversible). */
  public void destroyVersion(final String keyId, final long version) {
    exchange(KmsRequest.versionOp(RequestType.DESTROY_VERSION, token, keyId, version));
  }

  // ---- internals ----

  private KmsResponse exchange(final KmsRequest request) {
    final KmsResponse response = sendAndReceive(request);
    if (!response.isOk()) {
      throw new KmsClientException(response.errorCode(),
          "server error" + (response.message() != null ? ": " + response.message() : ""));
    }
    return response;
  }

  private KmsResponse sendAndReceive(final KmsRequest request) {
    try {
      out.write((codec.encodeRequest(request) + "\n").getBytes(StandardCharsets.UTF_8));
      out.flush();
      final String line = reader.readLine();
      if (line == null) {
        throw new KmsClientException("server closed the connection without responding", null);
      }
      return codec.decodeResponse(line);
    } catch (final IOException e) {
      throw new KmsClientException("transport failure", e);
    }
  }

  private static String encode(final byte[] bytes) {
    return bytes == null ? null : Base64.getEncoder().encodeToString(bytes);
  }

  private static byte[] decode(final String base64) {
    if (base64 == null) {
      throw new KmsClientException(null, "server response missing expected field");
    }
    return Base64.getDecoder().decode(base64);
  }

  @Override
  public void close() {
    try {
      underlying.close();
    } catch (final IOException ignored) {
      // best effort
    }
  }
}
