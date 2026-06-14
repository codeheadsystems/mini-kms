package com.codeheadsystems.minikms.client;

import com.codeheadsystems.minikms.kms.DataKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The mini-kms demonstration CLI.
 *
 * <p>Usage:
 * <pre>
 *   mini-kms-client [--tcp HOST:PORT | --unix PATH] [--token-file PATH] &lt;command&gt; [options]
 *
 * Connection (default --tcp 127.0.0.1:9123); token from MINIKMS_API_TOKEN or --token-file.
 *
 * Commands (data plane; uses MINIKMS_API_TOKEN):
 *   health
 *   generate-data-key [--key GROUP] [--aad STR]
 *   encrypt      --in PATH | --text STR  [--out PATH] [--key GROUP] [--aad STR]   (small blob)
 *   decrypt      --in PATH               [--out PATH]               [--aad STR]
 *   encrypt-file --in PATH  --out PATH               [--key GROUP]  [--aad STR]   (envelope)
 *   decrypt-file --in PATH  --out PATH                              [--aad STR]
 *   reencrypt    --in PATH  --out PATH   --key GROUP                [--aad STR]   (to GROUP's active version)
 *
 * --key names a key group (default "default"). For control-plane key management
 * (rotate, list, etc.) use the separate {@code kms-admin} CLI.
 * </pre>
 */
public final class ClientMain {

  /** Env var holding the API token. */
  static final String ENV_API_TOKEN = "MINIKMS_API_TOKEN";

  private ClientMain() {
  }

  /**
   * @param args CLI arguments.
   */
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
    } catch (final IOException e) {
      System.err.println("i/o error: " + e.getMessage());
      System.exit(74);
    }
  }

  static int run(final String[] args, final Map<String, String> env) throws IOException {
    final ArgParser parser = new ArgParser(args);

    // Connection options come before the command.
    String tcp = null;
    String unix = null;
    Path tokenFile = null;
    String command = null;
    while (parser.hasNext()) {
      final String arg = parser.peek();
      if (!arg.startsWith("--")) {
        command = parser.next();
        break;
      }
      switch (parser.next()) {
        case "--tcp" -> tcp = parser.value("--tcp");
        case "--unix" -> unix = parser.value("--unix");
        case "--token-file" -> tokenFile = Path.of(parser.value("--token-file"));
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

    final String token = resolveToken(env, tokenFile);
    try (KmsClient client = Connections.connect(tcp, unix, token)) {
      return dispatch(command, parser, client);
    }
  }

  private static int dispatch(final String command, final ArgParser parser, final KmsClient client)
      throws IOException {
    return switch (command) {
      case "health" -> doHealth(client);
      case "generate-data-key" -> doGenerateDataKey(parser, client);
      case "encrypt" -> doEncrypt(parser, client);
      case "decrypt" -> doDecrypt(parser, client);
      case "encrypt-file" -> doEncryptFile(parser, client);
      case "decrypt-file" -> doDecryptFile(parser, client);
      case "reencrypt" -> doReEncrypt(parser, client);
      default -> throw new UsageException("unknown command: " + command);
    };
  }

  private static int doHealth(final KmsClient client) {
    final boolean ok = client.health();
    System.out.println(ok ? "ok" : "unhealthy");
    return ok ? 0 : 1;
  }

  private static int doGenerateDataKey(final ArgParser parser, final KmsClient client) {
    final Options opts = Options.parse(parser);
    final DataKey dataKey = client.generateDataKey(opts.key(), opts.aad());
    System.out.println("plaintextDataKey: " + base64(dataKey.plaintext()));
    System.out.println("wrappedDataKey:   " + base64(dataKey.wrapped()));
    return 0;
  }

  private static int doEncrypt(final ArgParser parser, final KmsClient client) throws IOException {
    final Options opts = Options.parse(parser);
    final byte[] plaintext = opts.readInputOrText();
    final byte[] ciphertext = client.encrypt(opts.key(), plaintext, opts.aad());
    writeOutputOrPrintBase64(opts, ciphertext);
    return 0;
  }

  private static int doDecrypt(final ArgParser parser, final KmsClient client) throws IOException {
    final Options opts = Options.parse(parser);
    final byte[] ciphertext = opts.readInputOrText();
    final byte[] plaintext = client.decrypt(ciphertext, opts.aad());
    if (opts.out() != null) {
      Files.write(opts.out(), plaintext);
    } else {
      System.out.write(plaintext);
      System.out.flush();
    }
    return 0;
  }

  private static int doEncryptFile(final ArgParser parser, final KmsClient client) throws IOException {
    final Options opts = Options.parse(parser);
    final byte[] plaintext = Files.readAllBytes(opts.requireIn());
    final byte[] container = new EnvelopeFileService(client).encrypt(opts.key(), plaintext, opts.aad());
    Files.write(opts.requireOut(), container);
    System.out.println("encrypted " + opts.in() + " -> " + opts.out());
    return 0;
  }

  private static int doReEncrypt(final ArgParser parser, final KmsClient client) throws IOException {
    final Options opts = Options.parse(parser);
    if (opts.key() == null) {
      throw new UsageException("--key (destination group) is required for reencrypt");
    }
    final byte[] ciphertext = Files.readAllBytes(opts.requireIn());
    final byte[] rewrapped = client.reEncrypt(opts.key(), ciphertext, opts.aad());
    Files.write(opts.requireOut(), rewrapped);
    System.out.println("re-encrypted " + opts.in() + " -> " + opts.out() + " under group " + opts.key());
    return 0;
  }

  private static int doDecryptFile(final ArgParser parser, final KmsClient client) throws IOException {
    final Options opts = Options.parse(parser);
    final byte[] container = Files.readAllBytes(opts.requireIn());
    final byte[] plaintext = new EnvelopeFileService(client).decrypt(container, opts.aad());
    Files.write(opts.requireOut(), plaintext);
    System.out.println("decrypted " + opts.in() + " -> " + opts.out());
    return 0;
  }

  private static void writeOutputOrPrintBase64(final Options opts, final byte[] bytes) throws IOException {
    if (opts.out() != null) {
      Files.write(opts.out(), bytes);
    } else {
      System.out.println(base64(bytes));
    }
  }

  private static String resolveToken(final Map<String, String> env, final Path tokenFile)
      throws IOException {
    final String fromEnv = env.get(ENV_API_TOKEN);
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }
    if (tokenFile != null) {
      final String fromFile = Files.readString(tokenFile, StandardCharsets.UTF_8).strip();
      if (!fromFile.isEmpty()) {
        return fromFile;
      }
    }
    throw new UsageException("no API token: set " + ENV_API_TOKEN + " or pass --token-file");
  }

  private static String base64(final byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  /** Per-command options (--in/--out/--text/--key/--aad). */
  private record Options(Path in, Path out, String text, String key, byte[] aad) {

    static Options parse(final ArgParser parser) {
      Path in = null;
      Path out = null;
      String text = null;
      String key = null;
      byte[] aad = null;
      while (parser.hasNext()) {
        switch (parser.next()) {
          case "--in" -> in = Path.of(parser.value("--in"));
          case "--out" -> out = Path.of(parser.value("--out"));
          case "--text" -> text = parser.value("--text");
          case "--key" -> key = parser.value("--key");
          case "--aad" -> aad = parser.value("--aad").getBytes(StandardCharsets.UTF_8);
          default -> throw new UsageException("unknown option: " + parser.last());
        }
      }
      return new Options(in, out, text, key, aad);
    }

    byte[] readInputOrText() throws IOException {
      if (text != null) {
        return text.getBytes(StandardCharsets.UTF_8);
      }
      return Files.readAllBytes(requireIn());
    }

    Path requireIn() {
      if (in == null) {
        throw new UsageException("--in is required");
      }
      return in;
    }

    Path requireOut() {
      if (out == null) {
        throw new UsageException("--out is required");
      }
      return out;
    }
  }

  /** Minimal positional argument cursor. */
  private static final class ArgParser {
    private final List<String> args;
    private int index;
    private String last;

    ArgParser(final String[] args) {
      this.args = new ArrayList<>(List.of(args));
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

  /** Thrown for any CLI misuse; mapped to exit code 64. */
  private static final class UsageException extends RuntimeException {
    UsageException(final String message) {
      super(message);
    }
  }

  private static final String USAGE = """
      mini-kms-client [--tcp HOST:PORT | --unix PATH] [--token-file PATH] <command> [options]

        Connection defaults to --tcp 127.0.0.1:9123.
        API token is read from MINIKMS_API_TOKEN or --token-file.

      Commands (data plane):
        health
        generate-data-key [--key GROUP] [--aad STR]
        encrypt      --in PATH | --text STR  [--out PATH] [--key GROUP] [--aad STR]
        decrypt      --in PATH               [--out PATH]               [--aad STR]
        encrypt-file --in PATH  --out PATH               [--key GROUP]  [--aad STR]
        decrypt-file --in PATH  --out PATH                              [--aad STR]
        reencrypt    --in PATH  --out PATH   --key GROUP                [--aad STR]

      For key management (rotate/list/create/disable/destroy) use the kms-admin CLI.
      """;
}
