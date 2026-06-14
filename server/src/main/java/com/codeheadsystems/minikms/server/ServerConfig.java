package com.codeheadsystems.minikms.server;

import com.codeheadsystems.minikms.master.Argon2Settings;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Resolved server configuration: where to listen, where the keystore lives, and
 * framing limits. Values come from CLI flags (highest priority), then environment
 * variables, then sensible per-user defaults.
 *
 * <p>Secrets are deliberately NOT stored here as plaintext config: the passphrase
 * is read separately and transiently, and the API token is resolved from its
 * source by {@link ServerMain} and handed straight to the authenticator.
 *
 * <p>Recognized flags / env vars:
 * <pre>
 *   --tcp-port N        MINIKMS_TCP_PORT        loopback TCP port (0 = ephemeral; default 9123)
 *   --unix-socket PATH  MINIKMS_UNIX_SOCKET     Unix domain socket path
 *   --keystore PATH     MINIKMS_KEYSTORE        keystore metadata file path
 *   --token-file PATH       MINIKMS_API_TOKEN_FILE   file holding the API token (alt: MINIKMS_API_TOKEN env)
 *   --admin-token-file PATH MINIKMS_ADMIN_TOKEN_FILE file holding the admin token (alt: MINIKMS_ADMIN_TOKEN env)
 *   --max-frame-bytes N     MINIKMS_MAX_FRAME_BYTES  per-request size limit (default 1 MiB)
 *   --idle-timeout-ms N     MINIKMS_IDLE_TIMEOUT_MS  drop a connection idle/stalled this long (default 30000)
 *   --max-connections N     MINIKMS_MAX_CONNECTIONS  cap on concurrent connections (default 256)
 *   --no-tcp                                         disable the TCP listener
 *   --no-unix                                        disable the Unix listener
 * </pre>
 *
 * <p>Token-file paths are config (not secrets); the token values are read by
 * {@link ServerMain} from {@code MINIKMS_API_TOKEN} / {@code MINIKMS_ADMIN_TOKEN}
 * or those files — never from a flag. The API token guards the data plane; the
 * separate admin token guards the control plane (key management).
 */
public final class ServerConfig {

  /** Default loopback TCP port. */
  public static final int DEFAULT_TCP_PORT = 9123;

  /** Default request frame limit: 1 MiB. */
  public static final int DEFAULT_MAX_FRAME_BYTES = 1024 * 1024;

  /** Default idle/stall timeout per connection: 30 seconds. */
  public static final int DEFAULT_IDLE_TIMEOUT_MILLIS = 30_000;

  /** Default cap on concurrent connections across all transports. */
  public static final int DEFAULT_MAX_CONNECTIONS = 256;

  private final boolean tcpEnabled;
  private final int tcpPort;
  private final boolean unixEnabled;
  private final Path unixSocketPath;
  private final Path keystorePath;
  private final Path tokenFilePath;
  private final Path adminTokenFilePath;
  private final int maxFrameBytes;
  private final int idleTimeoutMillis;
  private final int maxConnections;
  private final Argon2Settings argonSettings;

  ServerConfig(final boolean tcpEnabled, final int tcpPort, final boolean unixEnabled,
               final Path unixSocketPath, final Path keystorePath, final Path tokenFilePath,
               final Path adminTokenFilePath, final int maxFrameBytes, final int idleTimeoutMillis,
               final int maxConnections, final Argon2Settings argonSettings) {
    this.tcpEnabled = tcpEnabled;
    this.tcpPort = tcpPort;
    this.unixEnabled = unixEnabled;
    this.unixSocketPath = unixSocketPath;
    this.keystorePath = keystorePath;
    this.tokenFilePath = tokenFilePath;
    this.adminTokenFilePath = adminTokenFilePath;
    this.maxFrameBytes = maxFrameBytes;
    this.idleTimeoutMillis = idleTimeoutMillis;
    this.maxConnections = maxConnections;
    this.argonSettings = argonSettings;
  }

  /**
   * Resolve configuration from CLI args and the process environment.
   *
   * @param args the raw CLI arguments.
   * @param env  the environment (injectable for testing; usually {@code System.getenv()}).
   * @return the resolved configuration.
   */
  public static ServerConfig resolve(final String[] args, final Map<String, String> env) {
    final Path dataDir = defaultDataDir(env);

    boolean tcpEnabled = true;
    boolean unixEnabled = true;
    Integer tcpPort = envInt(env, "MINIKMS_TCP_PORT");
    String unixSocket = env.get("MINIKMS_UNIX_SOCKET");
    String keystore = env.get("MINIKMS_KEYSTORE");
    String tokenFile = env.get("MINIKMS_API_TOKEN_FILE");
    String adminTokenFile = env.get("MINIKMS_ADMIN_TOKEN_FILE");
    Integer maxFrame = envInt(env, "MINIKMS_MAX_FRAME_BYTES");
    Integer idleTimeout = envInt(env, "MINIKMS_IDLE_TIMEOUT_MS");
    Integer maxConnections = envInt(env, "MINIKMS_MAX_CONNECTIONS");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--tcp-port" -> tcpPort = Integer.parseInt(requireValue(args, ++i, arg));
        case "--unix-socket" -> unixSocket = requireValue(args, ++i, arg);
        case "--keystore" -> keystore = requireValue(args, ++i, arg);
        case "--token-file" -> tokenFile = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--max-frame-bytes" -> maxFrame = Integer.parseInt(requireValue(args, ++i, arg));
        case "--idle-timeout-ms" -> idleTimeout = Integer.parseInt(requireValue(args, ++i, arg));
        case "--max-connections" -> maxConnections = Integer.parseInt(requireValue(args, ++i, arg));
        case "--no-tcp" -> tcpEnabled = false;
        case "--no-unix" -> unixEnabled = false;
        default -> throw new IllegalArgumentException("unknown argument: " + arg);
      }
    }

    final Path unixPath = unixSocket != null ? Paths.get(unixSocket) : dataDir.resolve("kms.sock");
    final Path keystorePath = keystore != null ? Paths.get(keystore) : dataDir.resolve("keystore.json");
    final Path tokenFilePath = tokenFile != null ? Paths.get(tokenFile) : null;
    final Path adminTokenFilePath = adminTokenFile != null ? Paths.get(adminTokenFile) : null;

    if (!tcpEnabled && !unixEnabled) {
      throw new IllegalArgumentException("at least one of TCP or Unix transports must be enabled");
    }

    final int resolvedIdleTimeout = idleTimeout != null ? idleTimeout : DEFAULT_IDLE_TIMEOUT_MILLIS;
    if (resolvedIdleTimeout < 1) {
      throw new IllegalArgumentException("idle timeout must be at least 1 ms");
    }
    final int resolvedMaxConnections = maxConnections != null ? maxConnections : DEFAULT_MAX_CONNECTIONS;
    if (resolvedMaxConnections < 1) {
      throw new IllegalArgumentException("max connections must be at least 1");
    }

    return new ServerConfig(
        tcpEnabled,
        tcpPort != null ? tcpPort : DEFAULT_TCP_PORT,
        unixEnabled,
        unixPath,
        keystorePath,
        tokenFilePath,
        adminTokenFilePath,
        maxFrame != null ? maxFrame : DEFAULT_MAX_FRAME_BYTES,
        resolvedIdleTimeout,
        resolvedMaxConnections,
        Argon2Settings.defaults());
  }

  private static Path defaultDataDir(final Map<String, String> env) {
    final String xdg = env.get("XDG_DATA_HOME");
    if (xdg != null && !xdg.isBlank()) {
      return Paths.get(xdg, "mini-kms");
    }
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-kms");
  }

  private static Integer envInt(final Map<String, String> env, final String key) {
    final String value = env.get(key);
    return value == null ? null : Integer.valueOf(value.trim());
  }

  private static String requireValue(final String[] args, final int index, final String flag) {
    if (index >= args.length) {
      throw new IllegalArgumentException("flag " + flag + " requires a value");
    }
    return args[index];
  }

  /** @return whether the loopback TCP listener is enabled. */
  public boolean tcpEnabled() {
    return tcpEnabled;
  }

  /** @return the loopback TCP port (0 means an ephemeral port is chosen). */
  public int tcpPort() {
    return tcpPort;
  }

  /** @return whether the Unix domain socket listener is enabled. */
  public boolean unixEnabled() {
    return unixEnabled;
  }

  /** @return the Unix domain socket path. */
  public Path unixSocketPath() {
    return unixSocketPath;
  }

  /** @return the keystore metadata file path. */
  public Path keystorePath() {
    return keystorePath;
  }

  /** @return the file to read the API token from, or {@code null} if unset (env is then required). */
  public Path tokenFilePath() {
    return tokenFilePath;
  }

  /** @return the file to read the admin token from, or {@code null} if unset (env is then required). */
  public Path adminTokenFilePath() {
    return adminTokenFilePath;
  }

  /** @return the maximum bytes accepted for a single request line. */
  public int maxFrameBytes() {
    return maxFrameBytes;
  }

  /** @return how long a connection may stall waiting to send a request before it is dropped (ms). */
  public int idleTimeoutMillis() {
    return idleTimeoutMillis;
  }

  /** @return the maximum number of concurrent connections across all transports. */
  public int maxConnections() {
    return maxConnections;
  }

  /** @return the Argon2 parameters used when initializing a new keystore. */
  public Argon2Settings argonSettings() {
    return argonSettings;
  }
}
