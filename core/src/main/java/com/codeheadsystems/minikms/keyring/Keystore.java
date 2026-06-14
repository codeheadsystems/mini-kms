package com.codeheadsystems.minikms.keyring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * Reads and writes the {@link KeystoreMetadata} JSON file.
 *
 * <p>The file contains no plaintext keys, but is still written owner-only (0600)
 * on POSIX systems. Writes are atomic (temp file + move) so a crash never leaves
 * a half-written keyring.
 */
public final class Keystore {

  private static final ObjectMapper MAPPER = new ObjectMapper()
      .enable(SerializationFeature.INDENT_OUTPUT);

  private static final Set<PosixFilePermission> OWNER_ONLY =
      EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private Keystore() {
  }

  /** @return whether the keystore file exists. */
  public static boolean exists(final Path path) {
    return Files.isRegularFile(path);
  }

  /** Load and parse the keystore metadata file. */
  public static KeystoreMetadata load(final Path path) {
    try {
      return MAPPER.readValue(Files.readAllBytes(path), KeystoreMetadata.class);
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to read keystore metadata at " + path, e);
    }
  }

  /** Atomically write the keystore metadata file with owner-only permissions. */
  public static void save(final Path path, final KeystoreMetadata metadata) {
    try {
      final Path parent = path.toAbsolutePath().getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      final byte[] json = MAPPER.writeValueAsBytes(metadata);
      final Path tmp = Files.createTempFile(parent, ".keystore", ".tmp");
      try {
        Files.write(tmp, json);
        restrictPermissions(tmp);
        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
      } finally {
        Files.deleteIfExists(tmp);
      }
      restrictPermissions(path);
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to write keystore metadata at " + path, e);
    }
  }

  private static void restrictPermissions(final Path path) {
    try {
      Files.setPosixFilePermissions(path, OWNER_ONLY);
    } catch (final UnsupportedOperationException | IOException ignored) {
      // Non-POSIX filesystem: best effort.
    }
  }
}
