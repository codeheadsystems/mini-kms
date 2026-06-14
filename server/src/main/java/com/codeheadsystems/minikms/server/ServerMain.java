package com.codeheadsystems.minikms.server;

import com.codeheadsystems.minikms.auth.AllowAllPolicy;
import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.kms.KmsService;
import com.codeheadsystems.minikms.master.WrongPassphraseException;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * Server entry point.
 *
 * <p>Startup sequence:
 * <ol>
 *   <li>Resolve {@link ServerConfig} from flags + environment.</li>
 *   <li>Resolve the <b>API token</b> (data plane) and <b>admin token</b> (control
 *       plane) from env vars or token files — never plaintext CLI args.</li>
 *   <li>Read the passphrase without echoing ({@link Console#readPassword}), with a
 *       {@code MINIKMS_PASSPHRASE} fallback for automation.</li>
 *   <li>Bootstrap the {@link LocalKeyring}: initialize a new keystore (with a
 *       {@code default} key group) on first run, or validate the passphrase
 *       against an existing one (fail fast on mismatch).</li>
 *   <li>Bind the transports and serve until interrupted; a shutdown hook zeros the
 *       root key and every KEK.</li>
 * </ol>
 */
public final class ServerMain {

  /** Env var carrying the data-plane API token. */
  static final String ENV_API_TOKEN = "MINIKMS_API_TOKEN";
  /** Env var carrying the control-plane admin token. */
  static final String ENV_ADMIN_TOKEN = "MINIKMS_ADMIN_TOKEN";
  /** Env var carrying the passphrase (automation fallback for the no-echo prompt). */
  static final String ENV_PASSPHRASE = "MINIKMS_PASSPHRASE";

  private ServerMain() {
  }

  /** @param args CLI arguments (see {@link ServerConfig}). */
  public static void main(final String[] args) {
    try {
      run(args, System.getenv());
    } catch (final WrongPassphraseException e) {
      System.err.println("Startup aborted: " + e.getMessage());
      System.exit(2);
    } catch (final IllegalArgumentException | IllegalStateException e) {
      System.err.println("Configuration error: " + e.getMessage());
      System.exit(64);
    } catch (final IOException e) {
      System.err.println("I/O error: " + e.getMessage());
      System.exit(74);
    }
  }

  private static void run(final String[] args, final Map<String, String> env) throws IOException {
    final ServerConfig config = ServerConfig.resolve(args, env);
    final String apiToken = resolveToken(env, ENV_API_TOKEN, config.tokenFilePath(),
        "data-plane API token", "--token-file");
    final String adminToken = resolveToken(env, ENV_ADMIN_TOKEN, config.adminTokenFilePath(),
        "control-plane admin token", "--admin-token-file");
    final char[] passphrase = readPassphrase(env);

    final LocalKeyring keyring;
    try {
      keyring = LocalKeyring.bootstrap(config.keystorePath(), passphrase, config.argonSettings());
    } finally {
      Arrays.fill(passphrase, '\0');
    }

    // The one keyring backs both planes: data via KmsService, control via KeyringManager.
    final KmsRequestHandler requestHandler = new KmsRequestHandler(
        new KmsService(keyring),
        keyring,
        new ApiTokenAuthenticator(apiToken),
        new ApiTokenAuthenticator(adminToken),
        new AllowAllPolicy());
    final KmsServer server = new KmsServer(config, requestHandler);

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.close();
      keyring.close(); // zero the root key and every KEK
      shutdown.countDown();
    }, "minikms-shutdown"));

    server.start();
    System.out.println("mini-kms is running. Press Ctrl-C to stop.");
    awaitShutdown(shutdown);
  }

  private static void awaitShutdown(final CountDownLatch shutdown) {
    try {
      shutdown.await();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** Resolve a token from its env var or a token file; required. */
  private static String resolveToken(final Map<String, String> env, final String envVar,
                                     final Path tokenFile, final String what, final String flag)
      throws IOException {
    final String fromEnv = env.get(envVar);
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }
    if (tokenFile != null) {
      final String fromFile = Files.readString(tokenFile, StandardCharsets.UTF_8).strip();
      if (!fromFile.isEmpty()) {
        return fromFile;
      }
    }
    throw new IllegalStateException("no " + what + " configured: set " + envVar + " or provide " + flag);
  }

  /** Read the passphrase without echoing; fall back to env for non-interactive automation. */
  private static char[] readPassphrase(final Map<String, String> env) {
    final Console console = System.console();
    if (console != null) {
      final char[] entered = console.readPassword("Keystore passphrase: ");
      if (entered != null && entered.length > 0) {
        return entered;
      }
      throw new IllegalStateException("empty passphrase");
    }
    final String fromEnv = env.get(ENV_PASSPHRASE);
    if (fromEnv != null && !fromEnv.isEmpty()) {
      return fromEnv.toCharArray();
    }
    throw new IllegalStateException(
        "no interactive console available; set " + ENV_PASSPHRASE + " for automation");
  }
}
