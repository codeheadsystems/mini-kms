package com.codeheadsystems.minikms.client;

import com.codeheadsystems.minikms.keyring.RootKeyRotation;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.protocol.KeyGroupView;
import java.io.Console;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The mini-kms CONTROL PLANE CLI (key management).
 *
 * <p>Kept separate from the data-plane {@code client} CLI to make the plane split
 * obvious and to use the <b>admin token</b> rather than the API token.
 *
 * <pre>
 * kms-admin [--tcp HOST:PORT | --unix PATH] [--admin-token-file PATH] &lt;command&gt; [options]
 *
 *   Online (talks to the running server with the admin token from MINIKMS_ADMIN_TOKEN
 *   or --admin-token-file):
 *     list-keys
 *     create-key      --key GROUP
 *     rotate-key      --key GROUP
 *     disable-version --key GROUP --version N
 *     enable-version  --key GROUP --version N
 *     destroy-version --key GROUP --version N    (irreversible)
 *
 *   Offline (operates directly on the keystore file; run with the server stopped;
 *   prompts for passphrases with no echo — never over the network):
 *     change-passphrase --keystore PATH
 * </pre>
 */
public final class KeyringAdminMain {

  /** Env var holding the admin token. */
  static final String ENV_ADMIN_TOKEN = "MINIKMS_ADMIN_TOKEN";
  /** Env var holding the current passphrase (automation fallback). */
  static final String ENV_PASSPHRASE = "MINIKMS_PASSPHRASE";
  /** Env var holding the new passphrase (automation fallback). */
  static final String ENV_NEW_PASSPHRASE = "MINIKMS_NEW_PASSPHRASE";

  private KeyringAdminMain() {
  }

  /** @param args CLI arguments. */
  public static void main(final String[] args) {
    try {
      System.exit(run(args, System.getenv()));
    } catch (final UsageException e) {
      System.err.println("error: " + e.getMessage());
      System.err.println();
      System.err.println(USAGE);
      System.exit(64);
    } catch (final KmsClientException e) {
      System.err.println("error: " + e.getMessage());
      System.exit(1);
    }
  }

  static int run(final String[] args, final Map<String, String> env) {
    final ArgCursor cursor = new ArgCursor(args);
    String tcp = null;
    String unix = null;
    Path adminTokenFile = null;
    String command = null;
    while (cursor.hasNext()) {
      final String arg = cursor.peek();
      if (!arg.startsWith("--")) {
        command = cursor.next();
        break;
      }
      switch (cursor.next()) {
        case "--tcp" -> tcp = cursor.value("--tcp");
        case "--unix" -> unix = cursor.value("--unix");
        case "--admin-token-file" -> adminTokenFile = Path.of(cursor.value("--admin-token-file"));
        case "--help", "-h" -> {
          System.out.println(USAGE);
          return 0;
        }
        default -> throw new UsageException("unknown global option: " + arg);
      }
    }
    if (command == null) {
      throw new UsageException("no command given");
    }

    // change-passphrase is offline: it never connects and never touches a token.
    if (command.equals("change-passphrase")) {
      return changePassphrase(cursor, env);
    }
    return online(command, cursor, env, tcp, unix, adminTokenFile);
  }

  // ---- online control-plane commands ----

  private static int online(final String command, final ArgCursor cursor, final Map<String, String> env,
                            final String tcp, final String unix, final Path adminTokenFile) {
    final Opts opts = Opts.parse(cursor);
    final String token = AdminToken.resolve(env, adminTokenFile);
    try (KmsClient client = Connections.connect(tcp, unix, token)) {
      return switch (command) {
        case "list-keys" -> listKeys(client);
        case "create-key" -> printGroup("created", client.createKeyGroup(opts.requireKey()));
        case "rotate-key" -> printGroup("rotated", client.rotateKeyGroup(opts.requireKey()));
        case "disable-version" -> {
          client.disableVersion(opts.requireKey(), opts.requireVersion());
          yield announce("disabled", opts);
        }
        case "enable-version" -> {
          client.enableVersion(opts.requireKey(), opts.requireVersion());
          yield announce("enabled", opts);
        }
        case "destroy-version" -> {
          client.destroyVersion(opts.requireKey(), opts.requireVersion());
          yield announce("destroyed", opts);
        }
        default -> throw new UsageException("unknown command: " + command);
      };
    }
  }

  private static int listKeys(final KmsClient client) {
    final List<KeyGroupView> groups = client.listKeyGroups();
    if (groups.isEmpty()) {
      System.out.println("(no key groups)");
      return 0;
    }
    for (final KeyGroupView group : groups) {
      System.out.println("key group: " + group.keyId() + "  (active version " + group.activeVersion() + ")");
      group.versions().forEach(v ->
          System.out.printf("    v%-3d %-10s created %ds epoch%n", v.version(), v.status(), v.createdAtEpochSec()));
    }
    return 0;
  }

  private static int printGroup(final String verb, final KeyGroupView group) {
    System.out.println(verb + " key group " + group.keyId() + "; active version is now v" + group.activeVersion());
    return 0;
  }

  private static int announce(final String verb, final Opts opts) {
    System.out.println(opts.requireKey() + " v" + opts.requireVersion() + " " + verb);
    return 0;
  }

  // ---- offline root/passphrase rotation ----

  private static int changePassphrase(final ArgCursor cursor, final Map<String, String> env) {
    Path keystore = null;
    while (cursor.hasNext()) {
      if (cursor.next().equals("--keystore")) {
        keystore = Path.of(cursor.value("--keystore"));
      } else {
        throw new UsageException("unknown option: " + cursor.last());
      }
    }
    if (keystore == null) {
      throw new UsageException("--keystore is required for change-passphrase");
    }
    final char[] oldPass = readPassphrase(env, ENV_PASSPHRASE, "Current passphrase: ");
    final char[] newPass = readPassphrase(env, ENV_NEW_PASSPHRASE, "New passphrase: ");
    try {
      RootKeyRotation.changePassphrase(keystore, oldPass, newPass, Argon2Settings.defaults());
      System.out.println("passphrase changed; keyring re-wrapped under a new root key "
          + "(no key ids or ciphertexts affected)");
      return 0;
    } finally {
      Arrays.fill(oldPass, '\0');
      Arrays.fill(newPass, '\0');
    }
  }

  private static char[] readPassphrase(final Map<String, String> env, final String envVar, final String prompt) {
    final Console console = System.console();
    if (console != null) {
      final char[] entered = console.readPassword(prompt);
      if (entered != null && entered.length > 0) {
        return entered;
      }
      throw new UsageException("empty passphrase");
    }
    final String fromEnv = env.get(envVar);
    if (fromEnv != null && !fromEnv.isEmpty()) {
      return fromEnv.toCharArray();
    }
    throw new UsageException("no interactive console; set " + envVar + " for automation");
  }

  /** Resolves the admin token from env or a file. */
  private static final class AdminToken {
    static String resolve(final Map<String, String> env, final Path file) {
      final String fromEnv = env.get(ENV_ADMIN_TOKEN);
      if (fromEnv != null && !fromEnv.isBlank()) {
        return fromEnv.trim();
      }
      if (file != null) {
        try {
          final String fromFile = java.nio.file.Files.readString(file).strip();
          if (!fromFile.isEmpty()) {
            return fromFile;
          }
        } catch (final java.io.IOException e) {
          throw new UsageException("cannot read admin token file: " + e.getMessage());
        }
      }
      throw new UsageException("no admin token: set " + ENV_ADMIN_TOKEN + " or pass --admin-token-file");
    }
  }

  /** Command options (--key/--version). */
  private record Opts(String key, Long version) {
    static Opts parse(final ArgCursor cursor) {
      String key = null;
      Long version = null;
      while (cursor.hasNext()) {
        switch (cursor.next()) {
          case "--key" -> key = cursor.value("--key");
          case "--version" -> version = Long.parseLong(cursor.value("--version"));
          default -> throw new UsageException("unknown option: " + cursor.last());
        }
      }
      return new Opts(key, version);
    }

    String requireKey() {
      if (key == null) {
        throw new UsageException("--key GROUP is required");
      }
      return key;
    }

    long requireVersion() {
      if (version == null) {
        throw new UsageException("--version N is required");
      }
      return version;
    }
  }

  /** Minimal positional cursor (shared shape with the data CLI). */
  private static final class ArgCursor {
    private final List<String> args;
    private int index;
    private String last;

    ArgCursor(final String[] args) {
      this.args = List.of(args);
    }

    boolean hasNext() {
      return index < args.size();
    }

    String peek() {
      return args.get(index);
    }

    String next() {
      return last = args.get(index++);
    }

    String last() {
      return last;
    }

    String value(final String flag) {
      if (index >= args.size()) {
        throw new UsageException(flag + " requires a value");
      }
      return args.get(index++);
    }
  }

  /** Thrown for CLI misuse; mapped to exit 64. */
  private static final class UsageException extends RuntimeException {
    UsageException(final String message) {
      super(message);
    }
  }

  private static final String USAGE = """
      kms-admin [--tcp HOST:PORT | --unix PATH] [--admin-token-file PATH] <command> [options]

        Online (admin token from MINIKMS_ADMIN_TOKEN or --admin-token-file):
          list-keys
          create-key      --key GROUP
          rotate-key      --key GROUP
          disable-version --key GROUP --version N
          enable-version  --key GROUP --version N
          destroy-version --key GROUP --version N

        Offline (server stopped; prompts for passphrases, no echo):
          change-passphrase --keystore PATH
      """;
}
